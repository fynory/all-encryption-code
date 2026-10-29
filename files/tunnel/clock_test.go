package main

import (
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"
)

// fakeClock is a clock the tests move by hand: Advance sets the time forward and runs every timer that came due, each in its own goroutine (as
// time.AfterFunc does), in the order of their moments. A timer asked for a moment that is already past runs at once. Nothing else in the node reads
// it: socket deadlines stay on the real clock.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
	fired  int // timers run so far (a test waits for them)
}

type fakeTimer struct {
	when    time.Time
	f       func()
	stopped bool
	done    bool
}

func newFakeClock() *fakeClock { return &fakeClock{now: time.Now()} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) AfterFunc(d time.Duration, f func()) func() bool {
	c.mu.Lock()
	t := &fakeTimer{when: c.now.Add(d), f: f}
	if d <= 0 {
		t.done = true
		c.fired++
		c.mu.Unlock()
		go f()
		return func() bool { return false }
	}
	c.timers = append(c.timers, t)
	c.mu.Unlock()
	return func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		was := !t.stopped && !t.done
		t.stopped = true
		return was
	}
}

// Advance moves the clock forward by d and runs what came due.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	var due []*fakeTimer
	rest := c.timers[:0]
	for _, t := range c.timers {
		switch {
		case t.stopped || t.done:
		case !t.when.After(c.now):
			t.done = true
			c.fired++
			due = append(due, t)
		default:
			rest = append(rest, t)
		}
	}
	c.timers = rest
	c.mu.Unlock()
	sort.SliceStable(due, func(i, j int) bool { return due[i].when.Before(due[j].when) })
	for _, t := range due {
		go t.f()
	}
}

// pending is the number of timers waiting.
func (c *fakeClock) pending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, t := range c.timers {
		if !t.stopped && !t.done {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------------------------------------------------------- the helpers of clock.go

func TestClock_TheFakeClockRunsDueTimersInOrderStopsOnRequestAndRunsAPastOneAtOnce(t *testing.T) {
	c := newFakeClock()
	var mu sync.Mutex
	var order []string
	note := func(s string) func() { return func() { mu.Lock(); order = append(order, s); mu.Unlock() } }
	c.AfterFunc(20*time.Second, note("b"))
	c.AfterFunc(10*time.Second, note("a"))
	stopped := c.AfterFunc(15*time.Second, note("stopped"))
	c.AfterFunc(40*time.Second, note("later"))
	if !stopped() {
		t.Fatal("a pending timer was not stopped")
	}
	if stopped() {
		t.Fatal("a timer was stopped twice")
	}
	c.Advance(25 * time.Second)
	eventually(t, "the two due timers", time.Second, func() bool { mu.Lock(); defer mu.Unlock(); return len(order) == 2 })
	if c.pending() != 1 {
		t.Fatalf("pending %d", c.pending())
	}
	c.AfterFunc(-time.Second, note("past")) // a moment already gone runs at once
	eventually(t, "a past timer", time.Second, func() bool { mu.Lock(); defer mu.Unlock(); return len(order) == 3 })
	mu.Lock()
	defer mu.Unlock()
	if order[0] != "a" && order[0] != "b" || order[2] != "past" {
		t.Fatalf("order %v", order)
	}
}

func TestClock_SleepEndsWithTheClockOrWithTheContext(t *testing.T) {
	c := newFakeClock()
	clk := newClock(c.Now, c.AfterFunc)
	done := make(chan bool, 1)
	go func() { done <- clk.sleep(context.Background(), time.Minute) }()
	eventually(t, "the sleeper", time.Second, func() bool { return c.pending() == 1 })
	c.Advance(time.Minute)
	if !<-done {
		t.Fatal("a sleep that ran to its end reported that it was cut")
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { done <- clk.sleep(ctx, time.Hour) }()
	eventually(t, "the sleeper", time.Second, func() bool { return c.pending() == 1 })
	cancel()
	if <-done {
		t.Fatal("a cancelled sleep reported that it ran to its end")
	}
	if c.pending() != 0 {
		t.Fatal("a cancelled sleep left its timer behind")
	}
	if clk.sleep(ctx, time.Second) {
		t.Fatal("a sleep started with a cancelled context")
	}
}

func TestClock_BackoffDoublesFromThePolicysMinimumToItsMaximumAndJitterStaysInItsBand(t *testing.T) {
	want := []time.Duration{1, 2, 4, 8, 16, 32, 60, 60}
	for i, w := range want {
		if got := backoff(i + 1); got != w*time.Second {
			t.Errorf("backoff(%d) = %s, want %s", i+1, got, w*time.Second)
		}
	}
	if backoff(0) != secs(policyData.Timing.BackoffMinS) || backoff(1000) != secs(policyData.Timing.BackoffMaxS) {
		t.Fatal("backoff out of its bounds")
	}
	for i := 0; i < 500; i++ {
		if got := jitter(100*time.Second, 10); got < 90*time.Second || got > 110*time.Second {
			t.Fatalf("jitter %s", got)
		}
	}
	if jitter(time.Second, 0) != time.Second || jitter(0, 10) != 0 {
		t.Fatal("jitter of nothing")
	}
}

func TestHealth_AnAnswerOfAnyKindIsReachabilityAndDownNeedsAFailureAfterItAndQuiet(t *testing.T) {
	var h cpHealth
	now := time.Now()
	if h.down(now, time.Second) {
		t.Fatal("down before anything was seen")
	}
	h.record(now, nil)
	h.record(now.Add(time.Second), &ControlError{Status: 402, Code: codeLicenseInactive}) // a refusal is an answer
	h.record(now.Add(2*time.Second), &ControlError{Status: 404, Code: "not_enrolled"})
	if h.down(now.Add(time.Hour), time.Second) {
		t.Fatal("a control plane that said no is down")
	}
	for name, err := range map[string]error{"a 503": &ControlError{Status: 503, Code: "end_to_end_unavailable"}, "a 429": &ControlError{Status: 429, Code: "busy"},
		"a timeout": context.DeadlineExceeded, "a transport error": errors.New("connection refused"), "an unreadable answer": &ControlError{Status: 502, Code: "bad_response"}} {
		var g cpHealth
		g.record(now, nil)
		g.record(now.Add(time.Second), err)
		if g.down(now.Add(2*time.Second), time.Minute) {
			t.Errorf("%s: down before the quiet period", name)
		}
		if !g.down(now.Add(2*time.Minute), time.Minute) {
			t.Errorf("%s: not down after the quiet period", name)
		}
		g.record(now.Add(3*time.Minute), nil)
		if g.down(now.Add(10*time.Minute), time.Minute) {
			t.Errorf("%s: still down after an answer", name)
		}
	}
}

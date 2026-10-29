package main

import (
	"context"
	"math/rand/v2"
	"time"
)

// clock is the node's source of time. Production uses the real one; the tests that cover hours (an outage of two hours, a grace of fifteen minutes,
// a JWKS that goes stale) drive their own by hand, so nothing in the node reads the wall clock for a decision except through it. Socket deadlines are
// not decisions of that kind: they stay on the real clock.
type clock struct {
	now       func() time.Time
	afterFunc func(d time.Duration, f func()) (stop func() bool)
}

func newClock(now func() time.Time, afterFunc func(d time.Duration, f func()) func() bool) clock {
	if now == nil {
		now = time.Now
	}
	if afterFunc == nil {
		afterFunc = func(d time.Duration, f func()) func() bool { return time.AfterFunc(d, f).Stop }
	}
	return clock{now: now, afterFunc: afterFunc}
}

func (c clock) Now() time.Time { return c.now() }

// AfterFunc runs f once, d from now on this clock, in its own goroutine. The returned function stops it and reports whether it did so in time.
func (c clock) AfterFunc(d time.Duration, f func()) (stop func() bool) {
	return c.afterFunc(max(d, 0), f)
}

// sleep waits d on this clock; it reports false when ctx ended first.
func (c clock) sleep(ctx context.Context, d time.Duration) bool {
	if ctx.Err() != nil {
		return false
	}
	done := make(chan struct{})
	stop := c.AfterFunc(d, func() { close(done) })
	defer stop()
	select {
	case <-done:
		return true
	case <-ctx.Done():
		return false
	}
}

// jitter spreads d by up to +/- pct percent, so that a fleet of nodes or a loop restarted together does not stay in step.
func jitter(d time.Duration, pct int) time.Duration {
	if pct <= 0 || d <= 0 {
		return d
	}
	span := int64(d) * int64(pct) / 100
	return d + time.Duration(rand.Int64N(2*span+1)-span)
}

// backoff is the delay after the n-th failure in a row (n from 1): the policy's minimum, doubled each time, up to its maximum.
func backoff(n int) time.Duration {
	d := secs(policyData.Timing.BackoffMinS)
	limit := secs(policyData.Timing.BackoffMaxS)
	for i := 1; i < n && d < limit; i++ {
		d *= 2
	}
	return min(d, limit)
}

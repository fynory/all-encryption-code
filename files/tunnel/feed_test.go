package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The feed consumer: what the control plane says the node must stop serving, applied within the deadline, once, in order.

// scriptedFeed is a feed the tests write by hand. By default it answers like the control plane's: the events after the cursor, in order, with the head
// as the next cursor; a test overrides what it answers to feed the node duplicates, disorder and nonsense.
type scriptedFeed struct {
	mu     sync.Mutex
	events []FeedEvent
	head   int64
	fail   error
	custom func(since int64) FeedAnswer
	cursor []int64 // the cursor of every poll
	block  chan struct{}
}

func (f *scriptedFeed) push(events ...FeedEvent) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range events {
		if e.Epoch == 0 {
			f.head++
			e.Epoch = f.head
		}
		f.head = max(f.head, e.Epoch)
		f.events = append(f.events, e)
	}
}

func (f *scriptedFeed) set(custom func(since int64) FeedAnswer) {
	f.mu.Lock()
	f.custom = custom
	f.mu.Unlock()
}

func (f *scriptedFeed) polls() []int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int64(nil), f.cursor...)
}

func (f *scriptedFeed) Feed(ctx context.Context, since int64, wait time.Duration) (FeedAnswer, error) {
	f.mu.Lock()
	f.cursor = append(f.cursor, since)
	fail, custom, block := f.fail, f.custom, f.block
	f.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return FeedAnswer{}, ctx.Err()
		}
	}
	if fail != nil {
		return FeedAnswer{}, fail
	}
	if custom != nil {
		return custom(since), nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	answer := FeedAnswer{Epoch: f.head, ServerTime: time.Now().Unix()}
	for _, e := range f.events {
		if e.Epoch > since {
			answer.Events = append(answer.Events, e)
		}
	}
	return answer, nil
}

func (e *testEnv) event(kind string, d *testDevice) FeedEvent {
	ev := FeedEvent{Type: kind, At: e.now().Unix()}
	if d != nil {
		ev.DeviceID, ev.Label = d.id, d.label
	}
	return ev
}

// withFeed is a node on the real clock whose feed is f, polled every 20 ms.
func withFeed(t *testing.T, f *scriptedFeed) *testEnv {
	return newTestEnv(t, func(c *Config) {
		c.Feed = f
		c.FeedPoll = 20 * time.Millisecond
	})
}

// streamOpen opens a client stream of d and sends one request over it, leaving the connection open.
func streamOpen(t *testing.T, e *testEnv, d *testDevice) *tlsClient {
	t.Helper()
	c, err := e.clientTLS(d)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := postOver(c, d.host, []byte("hello")); err != nil || string(resp) != "echo:hello" {
		t.Fatalf("a stream of %s: %q %v", d.host, resp, err)
	}
	return &tlsClient{Conn: c}
}

type tlsClient struct{ net.Conn }

// dead reports whether the node cut the stream within timeout.
func (c *tlsClient) dead(timeout time.Duration) bool {
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1)
	_, err := c.Read(buf)
	if err == nil {
		return false
	}
	var ne net.Error
	return !(errors.As(err, &ne) && ne.Timeout())
}

// ---------------------------------------------------------------------------------------------------------------------------- the deadline

func TestFeed_ARevokeClosesTheControlConnectionAndTheStreamsWithinTheApplyDeadline(t *testing.T) {
	if policyData.Timing.FeedPollS != 15 || policyData.Timing.FeedApplyDeadlineS != 20 {
		t.Fatalf("the plan says a poll every 15 s and an apply within 20 s: policy %d and %d", policyData.Timing.FeedPollS, policyData.Timing.FeedApplyDeadlineS)
	}
	clk := newFakeClock()
	e, cp := httpNode(t, clk, nil)
	d, bystander := e.newDevice(), e.newDevice()
	dc, bc := e.connectOK(d), e.connectOK(bystander)
	ds := dc.serve(nil)
	bs := bc.serve(nil)
	stream := streamOpen(t, e, d)
	other := streamOpen(t, e, bystander)
	defer other.Close()

	cp.addEvent("revoke", d)
	// Virtual time passes second by second; the node must have acted before the deadline.
	elapsed := 0
	for ; elapsed <= policyData.Timing.FeedApplyDeadlineS; elapsed++ {
		if !e.srv.Online(d.host) {
			break
		}
		clk.Advance(time.Second)
		time.Sleep(15 * time.Millisecond)
	}
	if elapsed > policyData.Timing.FeedApplyDeadlineS {
		t.Fatalf("the node had not applied the revoke after %d s", elapsed)
	}
	eventually(t, "CLOSE revoked", 2*time.Second, func() bool { return containsLine(ds.otherLines(), "CLOSE revoked") })
	<-ds.done
	if !stream.dead(2 * time.Second) {
		t.Fatal("the stream of a revoked device is still open")
	}
	// nothing else was touched
	if !e.srv.Online(bystander.host) || other.dead(100*time.Millisecond) || len(bs.otherLines()) != 0 {
		t.Fatalf("another device was affected: lines %q", bs.otherLines())
	}
	// and it is not served again: the control plane would refuse its next HELLO
	e.cp.set(d.id, nil)
	if _, err := e.clientTLS(d); err == nil {
		t.Fatal("a client reached a revoked device")
	}
}

func TestFeed_ALongPollDeliversARevokeTheMomentItHappens(t *testing.T) {
	e, cp := httpNode(t, nil, nil)
	cp.mu.Lock()
	cp.hold = 10 * time.Second
	cp.mu.Unlock()
	d := e.newDevice()
	dc := e.connectOK(d)
	ds := dc.serve(nil)
	stream := streamOpen(t, e, d)
	eventually(t, "a held poll", 3*time.Second, func() bool {
		for _, c := range cp.feedCalls() {
			if c.wait == int64(policyData.Timing.FeedPollS) {
				return true
			}
		}
		return false
	})
	started := time.Now()
	cp.addEvent("revoke", d)
	eventually(t, "CLOSE revoked", 3*time.Second, func() bool { return containsLine(ds.otherLines(), "CLOSE revoked") })
	if took := time.Since(started); took > 2*time.Second {
		t.Fatalf("a held poll delivered the revoke after %s", took)
	}
	if !stream.dead(2 * time.Second) {
		t.Fatal("stream alive")
	}
	// The poll the node signed: the exact URL, the cursor and the hold.
	for _, c := range cp.feedCalls() {
		if !strings.HasPrefix(c.url, "/v1/tunnel/feed?since=") {
			t.Errorf("feed URL %q", c.url)
		}
	}
	first := cp.feedCalls()[0]
	if first.since != 0 || first.wait != 0 {
		t.Fatalf("the catch-up poll is the first, from the start and without a hold: %+v", first)
	}
}

func TestFeed_PollsOncePerPeriodAndAdvancesItsCursor(t *testing.T) {
	clk := newFakeClock()
	e, cp := httpNode(t, clk, nil)
	d := e.newDevice()
	_ = e.connectOK(d)
	// the catch-up poll, then the first long poll right after it (a control plane that does not hold it answers at once)
	eventually(t, "the catch-up and the first long poll", 3*time.Second, func() bool { return len(cp.feedCalls()) == 2 })
	time.Sleep(50 * time.Millisecond)
	if n := len(cp.feedCalls()); n != 2 {
		t.Fatalf("the node polled %d times without a period passing", n)
	}
	other := &testDevice{id: randomHex(16), label: label20()}
	cp.addEvent("revoke", other) // nobody here: the cursor still moves
	step := func(want int) {
		t.Helper()
		for i := 0; i < 20 && len(cp.feedCalls()) < want; i++ {
			clk.Advance(time.Second)
			time.Sleep(15 * time.Millisecond)
		}
		if n := len(cp.feedCalls()); n != want {
			t.Fatalf("%d polls, want %d", n, want)
		}
	}
	step(4) // the poll that brings the event, and the long poll that follows it at once
	step(5)
	calls := cp.feedCalls()
	wantSince := []int64{0, 0, 0, 1, 1}
	for i, c := range calls {
		if c.since != wantSince[i] {
			t.Errorf("poll %d asked since=%d, want %d", i, c.since, wantSince[i])
		}
		wantWait := int64(policyData.Timing.FeedPollS)
		if i == 0 {
			wantWait = 0
		}
		if c.wait != wantWait {
			t.Errorf("poll %d asked wait=%d, want %d", i, c.wait, wantWait)
		}
	}
}

// ---------------------------------------------------------------------------------------------------------------------------- what each event does

func TestFeed_RevokeReleaseAndLicenseEndCloseTheConnectionAndKillTheStreams(t *testing.T) {
	for kind, want := range map[string]string{feedRevoke: "CLOSE revoked", feedRelease: "CLOSE released", feedLicenseEnd: "CLOSE revoked"} {
		t.Run(kind, func(t *testing.T) {
			f := &scriptedFeed{}
			e := withFeed(t, f)
			d := e.newDevice()
			dc := e.connectOK(d)
			ds := dc.serve(nil)
			stream := streamOpen(t, e, d)
			f.push(e.event(kind, d))
			eventually(t, want, 3*time.Second, func() bool { return containsLine(ds.otherLines(), want) })
			if !stream.dead(2 * time.Second) {
				t.Fatal("the stream is still open")
			}
			eventually(t, "the host unbound", 2*time.Second, func() bool { return !e.srv.Online(d.host) })
			e.waitIdle()
		})
	}
}

func TestFeed_AStreamOfAHostWhoseConnectionIsAlreadyGoneIsStillKilled(t *testing.T) {
	f := &scriptedFeed{}
	e := withFeed(t, f)
	d := e.newDevice()
	dc := e.connectOK(d)
	_ = dc.serve(nil)
	stream := streamOpen(t, e, d)
	_ = dc.c.Close() // the device's control connection drops, its data connection and the client's stream are still there
	eventually(t, "the control connection gone", 2*time.Second, func() bool { return e.srv.routes.controls(d.label) == nil })
	if stream.dead(100 * time.Millisecond) {
		t.Fatal("a stream was cut because the control connection dropped: it keeps to its own limits")
	}
	f.push(e.event(feedRevoke, d))
	if !stream.dead(3 * time.Second) {
		t.Fatal("the revoke did not reach a stream that outlived its control connection")
	}
}

func TestFeed_APauseStopsNewStreamsKillsTheOnesInFlightAndForwardsTheSignedStatement(t *testing.T) {
	const pausedStatement = "eyJhbGciOiJFZERTQSJ9.eyJzdGF0ZSI6InBhdXNlZCJ9.c2lnbmF0dXJl"
	const resumedStatement = "eyJhbGciOiJFZERTQSJ9.eyJzdGF0ZSI6InJlc3VtZWQifQ.c2lnbmF0dXJl"
	f := &scriptedFeed{}
	e := withFeed(t, f)
	d := e.newDevice()
	dc := e.connectOK(d)
	ds := dc.serve(nil)
	stream := streamOpen(t, e, d)

	answer := func(status, access string) {
		e.cp.set(d.id, &devicePlan{host: d.host, answer: func(int) AuthorizeResponse {
			now := e.now()
			return AuthorizeResponse{DeviceID: d.id, Label: d.label, Host: d.host, Status: status, Plan: "paid", ValidUntil: now.Unix() + 3600, ServerTime: now.Unix(),
				Policy: okPolicy{20, 45, 1800, 14400, 300}, Nodes: []any{}, Access: access}
		}})
	}
	answer(statusPaused, pausedStatement)
	f.push(e.event(feedPause, d))
	eventually(t, "the signed statement of the pause", 3*time.Second, func() bool { return containsLine(ds.otherLines(), "STATEMENT "+pausedStatement) })
	if !stream.dead(2 * time.Second) {
		t.Fatal("a stream of a paused device survived the pause")
	}
	if e.srv.Online(d.host) {
		t.Fatal("a paused device is online")
	}
	if _, err := e.clientTLS(d); err == nil {
		t.Fatal("a client got a stream of a paused device")
	}
	if !dc.try0() {
		t.Fatal("the control connection of a paused device must stay (the resume arrives as a statement)")
	}
	if n := e.cp.callsFor(d.id, "renew"); n != 1 {
		t.Fatalf("one refresh was expected, the control plane saw %d", n)
	}

	answer(statusActive, resumedStatement)
	f.push(e.event(feedResume, d))
	eventually(t, "the statement of the resume", 3*time.Second, func() bool { return containsLine(ds.otherLines(), "STATEMENT "+resumedStatement) })
	eventually(t, "streams again", 2*time.Second, func() bool { return e.srv.Online(d.host) })
	c, err := e.clientTLS(d)
	if err != nil {
		t.Fatalf("a client after the resume: %v", err)
	}
	_ = c.Close()
	e.checkTranscript()
}

// try0 reports whether the device's connection is still up: nothing closed it.
func (dc *devConn) try0() bool {
	select {
	case _, ok := <-dc.feed:
		return ok
	case <-time.After(150 * time.Millisecond):
		return true
	}
}

func TestFeed_APausedConnectionStaysPausedUntilTheControlPlaneAnswers(t *testing.T) {
	f := &scriptedFeed{}
	e := withFeed(t, f)
	d := e.newDevice()
	dc := e.connectOK(d)
	ds := dc.serve(nil)

	// the control plane cannot be asked right now
	e.cp.set(d.id, &devicePlan{host: d.host, err: &ControlError{Status: 503, Code: "end_to_end_unavailable"}})
	f.push(e.event(feedPause, d))
	eventually(t, "paused locally, without waiting for an answer", 3*time.Second, func() bool { return !e.srv.Online(d.host) })
	f.push(e.event(feedResume, d))
	time.Sleep(300 * time.Millisecond)
	if e.srv.Online(d.host) {
		t.Fatal("the node lifted a pause by itself, with no answer from the control plane")
	}
	// the answer comes: the pause is lifted
	e.cp.set(d.id, &devicePlan{host: d.host, validFor: time.Hour})
	eventually(t, "the refresh after the control plane is back", 6*time.Second, func() bool { return e.srv.Online(d.host) })
	if e.cp.callsFor(d.id, "renew") < 2 {
		t.Fatal("the node did not try again")
	}
	_ = ds
}

func TestFeed_AResumeThatTheControlPlaneRefusesCutsTheConnection(t *testing.T) {
	f := &scriptedFeed{}
	e := withFeed(t, f)
	d := e.newDevice()
	dc := e.connectOK(d)
	ds := dc.serve(nil)
	e.cp.set(d.id, &devicePlan{host: d.host, err: &ControlError{Status: 402, Code: codeLicenseInactive}})
	f.push(e.event(feedResume, d))
	eventually(t, "CLOSE revoked", 3*time.Second, func() bool { return containsLine(ds.otherLines(), "CLOSE revoked") })
}

func TestFeed_TheKillSwitchClosesEverythingAndNobodyIsServedUntilItIsCleared(t *testing.T) {
	f := &scriptedFeed{}
	e := withFeed(t, f)
	a, b := e.newDevice(), e.newDevice()
	ca, cb := e.connectOK(a), e.connectOK(b)
	da, db := ca.serve(nil), cb.serve(nil)
	sa := streamOpen(t, e, a)
	sb := streamOpen(t, e, b)

	f.push(FeedEvent{Type: feedKill, At: e.now().Unix()})
	for _, ds := range []*devServer{da, db} {
		ds := ds
		eventually(t, "CLOSE killed", 3*time.Second, func() bool { return containsLine(ds.otherLines(), "CLOSE killed") })
	}
	if !sa.dead(2*time.Second) || !sb.dead(2*time.Second) {
		t.Fatal("a stream survived the kill switch")
	}
	calls := len(e.cp.callLog())
	c := e.connect(a)
	line := c.hello(func() string { return e.session(a, nil) }, func(s, n string) string { return e.proof(a, s, n, nil) })
	if line != "ERR control_unavailable" {
		t.Fatalf("a HELLO while the switch is on: %q", line)
	}
	if len(e.cp.callLog()) != calls {
		t.Fatal("the node asked the control plane about a device while the kill switch is on")
	}

	f.push(FeedEvent{Type: feedKillClear, At: e.now().Unix()})
	eventually(t, "served again", 3*time.Second, func() bool {
		cc := e.connect(a)
		l := cc.hello(func() string { return e.session(a, nil) }, func(s, n string) string { return e.proof(a, s, n, nil) })
		return strings.HasPrefix(l, "OK ")
	})
}

func TestFeed_TheKillSwitchSeenInAnAuthorizeAnswerIsTheSameAsTheEvent(t *testing.T) {
	e := newTestEnv(t, nil)
	a, b := e.newDevice(), e.newDevice()
	ca := e.connectOK(a)
	da := ca.serve(nil)
	e.cp.set(b.id, &devicePlan{host: b.host, answer: func(int) AuthorizeResponse {
		now := e.now()
		return AuthorizeResponse{DeviceID: b.id, Label: b.label, Host: b.host, Status: statusActive, Plan: "paid", ValidUntil: now.Unix() + 3600, ServerTime: now.Unix(),
			Policy: okPolicy{20, 45, 1800, 14400, 300}, Nodes: []any{}, E2EKill: true}
	}})
	cb := e.connect(b)
	if line := cb.hello(func() string { return e.session(b, nil) }, func(s, n string) string { return e.proof(b, s, n, nil) }); line != "ERR control_unavailable" {
		t.Fatalf("a HELLO answered with the kill flag: %q", line)
	}
	eventually(t, "the other device told", 3*time.Second, func() bool { return containsLine(da.otherLines(), "CLOSE killed") })
}

// ---------------------------------------------------------------------------------------------------------------------------- order, duplicates, stale events

func TestFeed_DuplicatesAreAppliedOnceAndAnEventAtOrBelowTheCursorIsDropped(t *testing.T) {
	f := &scriptedFeed{}
	e := withFeed(t, f)
	d := e.newDevice()
	dc := e.connectOK(d)
	ds := dc.serve(nil)

	resume := e.event(feedResume, d)
	resume.Epoch = 5
	f.set(func(since int64) FeedAnswer {
		a := FeedAnswer{Epoch: 5, ServerTime: time.Now().Unix()}
		// the same event three times in one answer, and again in every answer after it: a feed that does not honor the cursor
		a.Events = []FeedEvent{resume, resume, resume}
		return a
	})
	eventually(t, "the polls", 3*time.Second, func() bool { return len(f.polls()) >= 6 })
	if n := e.cp.callsFor(d.id, "renew"); n != 1 {
		t.Fatalf("the same event was applied %d times", n)
	}
	// an older epoch than the cursor changes nothing, even when it is a revoke
	old := e.event(feedRevoke, d)
	old.Epoch = 3
	f.set(func(since int64) FeedAnswer {
		return FeedAnswer{Epoch: 5, ServerTime: time.Now().Unix(), Events: []FeedEvent{old}}
	})
	time.Sleep(200 * time.Millisecond)
	if !e.srv.Online(d.host) || containsLine(ds.otherLines(), "CLOSE revoked") {
		t.Fatal("an event below the cursor was applied")
	}
	// the cursor moved to the head and never back
	last := int64(-1)
	for _, c := range f.polls() {
		if c < last {
			t.Fatalf("the cursor went back: %v", f.polls())
		}
		last = c
	}
}

func TestFeed_AnAnswerOutOfOrderIsAppliedInEpochOrder(t *testing.T) {
	f := &scriptedFeed{}
	e := withFeed(t, f)
	d := e.newDevice()
	dc := e.connectOK(d)
	ds := dc.serve(nil)

	// delivered as [resume 8, pause 7]: in order that is a pause and then a resume, so the device ends up served; as delivered it would end paused.
	pause, resume := e.event(feedPause, d), e.event(feedResume, d)
	pause.Epoch, resume.Epoch = 7, 8
	var delivered atomic.Bool
	f.set(func(since int64) FeedAnswer {
		if since >= 8 {
			return FeedAnswer{Epoch: 8, ServerTime: time.Now().Unix()}
		}
		delivered.Store(true)
		return FeedAnswer{Epoch: 8, ServerTime: time.Now().Unix(), Events: []FeedEvent{resume, pause}}
	})
	eventually(t, "the answer delivered", 3*time.Second, delivered.Load)
	// both events produced a refresh and, whatever the interleaving, the control plane's last answer (active) is the state
	eventually(t, "refreshed", 3*time.Second, func() bool { return e.cp.callsFor(d.id, "renew") >= 1 })
	eventually(t, "served", 3*time.Second, func() bool { return e.srv.Online(d.host) })
	if containsLine(ds.otherLines(), "CLOSE revoked") {
		t.Fatal("closed")
	}
	if got := f.polls(); got[len(got)-1] != 8 {
		t.Fatalf("the cursor must be the highest epoch seen: %v", got)
	}
}

func TestFeed_AnEventOlderThanTheLastAnswerForAConnectionIsAlreadyInThatAnswer(t *testing.T) {
	f := &scriptedFeed{}
	e := withFeed(t, f)
	d := e.newDevice()
	dc := e.connectOK(d)
	ds := dc.serve(nil)
	// The device's license was ended and renewed: the revoke is from before the connection's own authorize, and is replayed (a node that restarted
	// replays the feed from the start). The connection must not be cut by it.
	stale := e.event(feedRevoke, d)
	stale.At = e.now().Unix() - 120
	f.push(stale)
	time.Sleep(300 * time.Millisecond)
	if !e.srv.Online(d.host) || containsLine(ds.otherLines(), "CLOSE revoked") {
		t.Fatal("a revoke older than the connection's last answer cut it")
	}
	// a revoke from now is not stale
	f.push(e.event(feedRevoke, d))
	eventually(t, "CLOSE revoked", 3*time.Second, func() bool { return containsLine(ds.otherLines(), "CLOSE revoked") })
}

func TestFeed_UnreadableEventsAreSkippedAndTheRestOfTheAnswerIsStillApplied(t *testing.T) {
	d := &testDevice{id: randomHex(16), label: label20()}
	good := map[string]any{"epoch": 4, "type": "revoke", "device_id": d.id, "label": d.label, "at": 1793000000}
	doc := map[string]any{"ok": true, "v": 1, "epoch": 4, "server_time": 1793000000, "events": []any{
		map[string]any{"epoch": 1, "type": "teleport", "device_id": d.id, "label": d.label, "at": 1793000000},      // a type this node does not know
		map[string]any{"epoch": 2, "type": "revoke", "device_id": "not-an-id", "label": d.label, "at": 1793000000}, // a malformed device id
		map[string]any{"epoch": 3, "type": "kill", "device_id": d.id, "label": nil, "at": 1793000000},              // a global event that names a device
		map[string]any{"epoch": 0, "type": "revoke", "device_id": d.id, "label": d.label, "at": 1793000000},        // epoch 0
		map[string]any{"epoch": 5, "type": "revoke", "device_id": d.id, "label": "UPPERCASELABELUPPERCA", "at": 1}, // a bad label
		good,
	}}
	answer, err := parseFeedAnswer([]byte(canonicalJSON(doc)))
	if err != nil {
		t.Fatal(err)
	}
	if len(answer.Events) != 1 || answer.Events[0].Epoch != 4 || answer.Skipped != 5 {
		t.Fatalf("events %+v skipped %d", answer.Events, answer.Skipped)
	}
	// the envelope is read strictly: a node does not act on an answer it cannot make sense of
	for name, bad := range map[string]string{
		"not ok":          `{"ok":false,"v":1,"epoch":1,"server_time":1793000000,"events":[]}`,
		"another version": `{"ok":true,"v":2,"epoch":1,"server_time":1793000000,"events":[]}`,
		"no events":       `{"ok":true,"v":1,"epoch":1,"server_time":1793000000}`,
		"a negative head": `{"ok":true,"v":1,"epoch":-1,"server_time":1793000000,"events":[]}`,
		"a repeated key":  `{"ok":true,"ok":true,"v":1,"epoch":1,"server_time":1793000000,"events":[]}`,
		"reset not bool":  `{"ok":true,"v":1,"epoch":1,"server_time":1793000000,"events":[],"reset":"yes"}`,
	} {
		if _, err := parseFeedAnswer([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestFeed_AResetClosesEveryTunnelAndTheCursorFollowsTheAnswer(t *testing.T) {
	f := &scriptedFeed{}
	e := withFeed(t, f)
	a, b := e.newDevice(), e.newDevice()
	ca, cb := e.connectOK(a), e.connectOK(b)
	da, db := ca.serve(nil), cb.serve(nil)
	sa := streamOpen(t, e, a)
	f.set(func(since int64) FeedAnswer {
		if since < 40 {
			return FeedAnswer{Epoch: 40, Reset: true, ServerTime: time.Now().Unix()}
		}
		return FeedAnswer{Epoch: since, ServerTime: time.Now().Unix()}
	})
	for _, ds := range []*devServer{da, db} {
		ds := ds
		eventually(t, "CLOSE after a reset", 3*time.Second, func() bool { return containsLine(ds.otherLines(), "CLOSE expired") })
	}
	if !sa.dead(2 * time.Second) {
		t.Fatal("a stream survived a reset")
	}
	eventually(t, "the cursor at the answer's epoch", 3*time.Second, func() bool {
		p := f.polls()
		return p[len(p)-1] == 40
	})
	// the devices reconnect and are authorized again: nothing is held against them
	if line := e.connect(a).hello(func() string { return e.session(a, nil) }, func(s, n string) string { return e.proof(a, s, n, nil) }); !strings.HasPrefix(line, "OK ") {
		t.Fatalf("a device after a reset: %q", line)
	}
}

func TestFeed_AnAnswerBehindTheCursorIsNotActedOn(t *testing.T) {
	f := &scriptedFeed{}
	e := withFeed(t, f)
	d := e.newDevice()
	dc := e.connectOK(d)
	ds := dc.serve(nil)
	f.set(func(since int64) FeedAnswer {
		if since == 0 {
			return FeedAnswer{Epoch: 10, ServerTime: time.Now().Unix()}
		}
		// the control plane (or a cache in front of it) says the head is 3 although the node has seen 10, and brings a revoke with it
		ev := e.event(feedRevoke, d)
		ev.Epoch = 3
		return FeedAnswer{Epoch: 3, ServerTime: time.Now().Unix(), Events: []FeedEvent{ev}}
	})
	time.Sleep(300 * time.Millisecond)
	if !e.srv.Online(d.host) || containsLine(ds.otherLines(), "CLOSE revoked") {
		t.Fatal("an answer behind the cursor was acted on")
	}
	for _, c := range f.polls() {
		if c != 0 && c != 10 {
			t.Fatalf("the cursor moved to %d on a bad answer: %v", c, f.polls())
		}
	}
}

// ---------------------------------------------------------------------------------------------------------------------------- the feed is down, the node is starting

func TestFeed_AFeedThatIsDownDoesNotCutAnythingAndIsHeardAgainWithinOnePollPeriod(t *testing.T) {
	clk := newFakeClock()
	e, cp := httpNode(t, clk, nil)
	d := e.newDevice()
	dc := e.connectOK(d)
	ds := dc.serve(nil)
	stream := streamOpen(t, e, d)

	cp.setDown(503)
	cp.addEvent("revoke", d)  // happens while the node cannot hear it
	for i := 0; i < 20; i++ { // five minutes of failing polls, in 15 s steps
		clk.Advance(15 * time.Second)
		time.Sleep(10 * time.Millisecond)
	}
	if !e.srv.Online(d.host) || stream.dead(50*time.Millisecond) || containsLine(ds.otherLines(), "CLOSE revoked") {
		t.Fatal("the node cut a device because its feed is unreachable: what is authenticated goes on until valid_until")
	}
	failed := cp.callCount(feedPath)
	if failed < 5 {
		t.Fatalf("the node polled %d times in five minutes of failure", failed)
	}
	cp.setDown(0)
	elapsed := 0
	for ; elapsed <= policyData.Timing.FeedApplyDeadlineS; elapsed++ {
		if !e.srv.Online(d.host) {
			break
		}
		clk.Advance(time.Second)
		time.Sleep(15 * time.Millisecond)
	}
	if elapsed > policyData.Timing.FeedApplyDeadlineS {
		t.Fatalf("the revoke was not applied within %d s of the feed coming back", elapsed)
	}
}

func TestFeed_TheFirstAnswerIsAppliedBeforeTheNodeAcceptsAnyone(t *testing.T) {
	f := &scriptedFeed{}
	f.push(FeedEvent{Type: feedKill, At: time.Now().Unix()}) // the switch was on while the node was down
	e := withFeed(t, f)
	a := e.newDevice()
	c := e.connect(a)
	if line := c.hello(func() string { return e.session(a, nil) }, func(s, n string) string { return e.proof(a, s, n, nil) }); line != "ERR control_unavailable" {
		t.Fatalf("a device accepted before the node knew the kill switch was on: %q", line)
	}
	if e.cp.callsFor(a.id, "") != 0 {
		t.Fatal("authorize was asked while the kill switch was on")
	}
}

func TestFeed_ALateFeedDoesNotKeepTheNodeFromStarting(t *testing.T) {
	f := &scriptedFeed{block: make(chan struct{})}
	started := time.Now()
	e := newTestEnv(t, func(c *Config) {
		c.Feed = f
		c.FeedPoll = 20 * time.Millisecond
		c.FeedStartWait = 250 * time.Millisecond
	})
	if took := time.Since(started); took > 3*time.Second {
		t.Fatalf("the node took %s to start with a feed that does not answer", took)
	}
	d := e.newDevice()
	_ = e.connectOK(d)
	close(f.block)
}

func TestFeed_AFailingFeedIsRetriedWithinThePollPeriodNotTheBackoffCap(t *testing.T) {
	// The backoff after repeated failures reaches a minute in the policy; the feed must not wait that long to hear a revoke once it is back.
	if backoff(20) <= secs(policyData.Timing.FeedPollS) {
		t.Fatal("this test needs a backoff longer than the poll period")
	}
	f := &scriptedFeed{fail: errors.New("down")}
	clk := newFakeClock()
	e := newEnv(t, clk, func(e *testEnv, c *Config) { c.Feed = f })
	_ = e
	for i := 0; i < 25; i++ {
		clk.Advance(5 * time.Second)
		time.Sleep(5 * time.Millisecond)
	}
	n := len(f.polls())
	f.mu.Lock()
	f.fail = nil
	f.mu.Unlock()
	for i := 0; i < 5; i++ {
		clk.Advance(5 * time.Second)
		time.Sleep(10 * time.Millisecond)
	}
	if len(f.polls()) <= n {
		t.Fatalf("no poll within 25 s after the feed recovered (%d polls)", n)
	}
}

func TestFeed_MoreThanAThousandEventsArePagedAtOnceAndTheCursorStopsAtTheLastEventGiven(t *testing.T) {
	f := &scriptedFeed{}
	nobody := &testDevice{id: randomHex(16), label: label20()}
	for i := 0; i < 1500; i++ {
		f.push(FeedEvent{Type: feedRevoke, DeviceID: nobody.id, Label: nobody.label, At: time.Now().Unix()})
	}
	// the control plane's answers: at most 1000 events, and `epoch` is where the cursor goes next (the last event given, not the head)
	f.set(func(since int64) FeedAnswer {
		a := FeedAnswer{ServerTime: time.Now().Unix()}
		for e := since + 1; e <= 1500 && len(a.Events) < 1000; e++ {
			a.Events = append(a.Events, FeedEvent{Epoch: e, Type: feedRevoke, DeviceID: nobody.id, Label: nobody.label, At: time.Now().Unix()})
		}
		a.Epoch = 1500
		if len(a.Events) == 1000 && since+1000 < 1500 {
			a.Epoch = since + 1000
		}
		return a
	})
	clk := newFakeClock()
	_ = newEnv(t, clk, func(_ *testEnv, c *Config) { c.Feed = f })
	eventually(t, "every page", 3*time.Second, func() bool { return len(f.polls()) >= 3 })
	// no clock moved: the pages followed each other at once, and only the empty poll after them waits for a period
	if got := f.polls(); got[0] != 0 || got[1] != 1000 || got[2] != 1500 || len(got) != 3 {
		t.Fatalf("the cursor went %v, want [0 1000 1500]", got)
	}
}

// ---------------------------------------------------------------------------------------------------------------------------- events during authorize

// gateAnswer makes the control plane's `from`-th answer for d (1 = the first) decide at once and arrive only when release is called: the verdict is
// from before whatever the feed says in between. Later answers are not held and carry laterStatus.
func (e *testEnv) gateAnswer(d *testDevice, from int, laterStatus string) (decided <-chan struct{}, release func()) {
	dec, rel := make(chan struct{}), make(chan struct{})
	var once sync.Once
	release = func() { once.Do(func() { close(rel) }) }
	e.t.Cleanup(release)
	e.cp.set(d.id, &devicePlan{host: d.host, answer: func(n int) AuthorizeResponse {
		now := e.now()
		status := statusActive
		if n > from {
			status = laterStatus
		}
		resp := AuthorizeResponse{DeviceID: d.id, Label: d.label, Host: d.host, Status: status, Plan: "paid", ValidUntil: now.Unix() + 3600, ServerTime: now.Unix(),
			Policy: okPolicy{20, 45, 1800, 14400, 300}, Nodes: []any{}}
		if n == from {
			close(dec)
			<-rel
		}
		return resp
	}})
	return dec, release
}

// applied waits until the node's feed cursor has passed epoch: the event is applied.
func (f *scriptedFeed) applied(t *testing.T, epoch int64) {
	t.Helper()
	eventually(t, "the event applied", 3*time.Second, func() bool {
		for _, c := range f.polls() {
			if c >= epoch {
				return true
			}
		}
		return false
	})
}

func TestFeed_ACutThatIsAppliedWhileAHelloWaitsForTheControlPlaneIsNotLost(t *testing.T) {
	for kind, want := range map[string]string{feedRevoke: "ERR device_revoked", feedRelease: "ERR device_revoked", feedLicenseEnd: "ERR license_inactive"} {
		t.Run(kind, func(t *testing.T) {
			f := &scriptedFeed{}
			e := withFeed(t, f)
			d := e.newDevice()
			decided, release := e.gateAnswer(d, 1, statusActive)
			hello := e.helloAsync(d)
			<-decided
			f.push(e.event(kind, d))
			f.applied(t, 1)
			release()
			select {
			case line := <-hello:
				if line != want {
					t.Fatalf("the HELLO whose answer the %s overtook was answered %q, want %q", kind, line, want)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("no answer")
			}
			time.Sleep(100 * time.Millisecond)
			if e.srv.Online(d.host) {
				t.Fatal("a device cut while it was authorizing is online")
			}
			e.checkTranscript()
		})
	}
}

func TestFeed_AnEventThatDoesNotConcernAHelloWaitingForTheControlPlaneLeavesItAlone(t *testing.T) {
	f := &scriptedFeed{}
	e := withFeed(t, f)
	d, other := e.newDevice(), e.newDevice()
	decided, release := e.gateAnswer(d, 1, statusActive)
	hello := e.helloAsync(d)
	<-decided
	f.push(e.event(feedRevoke, other)) // another device
	old := e.event(feedRevoke, d)      // this one, but from before the answer: the answer already knew it
	old.At = e.now().Unix() - 60
	f.push(old)
	f.applied(t, 2)
	release()
	select {
	case line := <-hello:
		if !strings.HasPrefix(line, "OK ") {
			t.Fatalf("the HELLO was answered %q", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no answer")
	}
	if !e.srv.Online(d.host) {
		t.Fatal("the device is not online")
	}
	e.checkTranscript()
}

func TestFeed_APauseThatIsAppliedWhileAHelloWaitsForTheControlPlaneHoldsAndIsRefreshed(t *testing.T) {
	f := &scriptedFeed{}
	e := withFeed(t, f)
	d := e.newDevice()
	decided, release := e.gateAnswer(d, 1, statusPaused)
	hello := e.helloAsync(d)
	<-decided
	f.push(e.event(feedPause, d))
	f.applied(t, 1)
	release()
	select {
	case line := <-hello:
		if !strings.HasPrefix(line, "OK ") {
			t.Fatalf("the HELLO was answered %q", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no answer")
	}
	if e.srv.Online(d.host) {
		t.Fatal("a device paused while it was authorizing is served")
	}
	eventually(t, "the control plane asked again", 3*time.Second, func() bool { return e.cp.callsFor(d.id, "renew") >= 1 })
	time.Sleep(100 * time.Millisecond)
	if e.srv.Online(d.host) {
		t.Fatal("the refresh, which says paused, lifted the pause")
	}
}

func TestFeed_APauseAppliedWhileARenewWaitsForTheControlPlaneIsNotWrittenOverByItsAnswer(t *testing.T) {
	f := &scriptedFeed{}
	e := withFeed(t, f)
	d := e.newDevice()
	dc := e.connectOK(d)
	decided, release := e.gateAnswer(d, 2, statusPaused) // the HELLO was the first call; plain plan afterwards
	e.cp.set(d.id, e.cp.plans[d.id])
	renewed := make(chan string, 1)
	go func() {
		dc.session = e.session(d, nil)
		dc.send("RENEW " + dc.session)
		line, err := dc.try(5 * time.Second)
		if err != nil || !strings.HasPrefix(line, "CHALLENGE ") {
			renewed <- "no challenge: " + line
			return
		}
		m, _ := parseLine(line, dirN2D)
		dc.send("PROOF " + e.proof(d, dc.session, m.str("nonce"), nil))
		line, _ = dc.try(5 * time.Second)
		renewed <- line
	}()
	<-decided
	f.push(e.event(feedPause, d))
	f.applied(t, 1)
	release()
	select {
	case line := <-renewed:
		if !strings.HasPrefix(line, "OK ") {
			t.Fatalf("the RENEW was answered %q", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no answer")
	}
	if e.srv.Online(d.host) {
		t.Fatal("the RENEW's answer, decided before the pause, lifted it")
	}
}

func TestFeed_TheKillSwitchThatGoesOnWhileAHelloWaitsForTheControlPlaneDoesNotServeIt(t *testing.T) {
	f := &scriptedFeed{}
	e := withFeed(t, f)
	d := e.newDevice()
	decided, release := e.gateAnswer(d, 1, statusActive)
	hello := e.helloAsync(d)
	<-decided
	f.push(e.event(feedKill, nil))
	f.applied(t, 1)
	release()
	select {
	case line := <-hello:
		if strings.HasPrefix(line, "OK ") {
			t.Fatalf("the HELLO was answered %q with the kill switch on", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no answer")
	}
	if e.srv.Online(d.host) {
		t.Fatal("a device is online with the kill switch on")
	}
}

func TestFeed_AResetThatIsAppliedWhileAHelloWaitsForTheControlPlaneDoesNotServeItEither(t *testing.T) {
	f := &scriptedFeed{}
	e := withFeed(t, f)
	d := e.newDevice()
	decided, release := e.gateAnswer(d, 1, statusActive)
	var reset atomic.Bool
	f.set(func(since int64) FeedAnswer {
		if !reset.Swap(true) {
			return FeedAnswer{Reset: true, Epoch: 7, ServerTime: time.Now().Unix()}
		}
		return FeedAnswer{Epoch: 7, ServerTime: time.Now().Unix()}
	})
	hello := e.helloAsync(d)
	<-decided
	time.Sleep(300 * time.Millisecond) // the reset is applied by the first polls
	release()
	select {
	case line := <-hello:
		if strings.HasPrefix(line, "OK ") {
			t.Fatalf("a HELLO overtaken by a reset was answered %q", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no answer")
	}
	if e.srv.Online(d.host) {
		t.Fatal("a device is online after the reset overtook its authorization")
	}
}

func TestFeed_ARefreshAfterShutdownStartsNothing(t *testing.T) {
	f := &scriptedFeed{}
	e := withFeed(t, f)
	d := e.newDevice()
	e.connectOK(d)
	cc, _ := e.srv.routes.lookup(d.host)
	e.srv.Shutdown(time.Second)
	e.srv.refreshAsync(cc)
	cc.mu.Lock()
	running := cc.refreshing
	cc.mu.Unlock()
	if running {
		t.Fatal("a refresh was started on a node that has ended")
	}
}

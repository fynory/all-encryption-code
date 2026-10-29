package main

import (
	"strings"
	"testing"
	"time"
)

// The gated thin pipe (gated.go): a device that is gated is served only a little, counted by the node on every status the control plane gives.

func TestGated_DayUsageCountsAdmitsAndRollsAtMidnight(t *testing.T) {
	now := time.Date(2026, 10, 26, 23, 59, 0, 0, time.UTC)
	u := &dayUsage{day: now.Unix() / 86400}
	for i := 0; i < 3; i++ {
		if ok, why := u.admit(now, 1000, 3); !ok {
			t.Fatalf("stream %d: %s", i, why)
		}
	}
	if ok, why := u.admit(now, 1000, 3); ok || why != "gated_streams" {
		t.Fatalf("the fourth stream: %v %q", ok, why)
	}
	if got := u.charge(now, 600, 1000); got != 600 {
		t.Fatalf("%d", got)
	}
	if got := u.charge(now, 600, 1000); got != 400 {
		t.Fatalf("the edge gives %d, want the 400 that are left", got)
	}
	if got := u.charge(now, 1, 1000); got != 0 {
		t.Fatalf("after the edge %d", got)
	}
	u2 := &dayUsage{day: now.Unix() / 86400, bytes: 1000}
	if ok, why := u2.admit(now, 1000, 3); ok || why != "gated_bytes" {
		t.Fatalf("a stream with no byte budget left: %v %q", ok, why)
	}
	next := now.Add(2 * time.Minute) // past midnight UTC
	if ok, _ := u.admit(next, 1000, 3); !ok {
		t.Fatal("the new day did not reset the stream count")
	}
	if got := u.charge(next, 700, 1000); got != 700 {
		t.Fatalf("the new day did not reset the bytes: %d", got)
	}
}

func TestGated_SweepKeepsWhatIsHeldOrUsedToday(t *testing.T) {
	fc := newFakeClock()
	g := newGateTable(newClock(fc.Now, fc.AfterFunc))
	held := g.acquire("held.example")
	used := g.acquire("used.example")
	used.charge(fc.Now(), 10, 1000)
	g.release(used)
	idle := g.acquire("idle.example")
	g.release(idle)
	g.Sweep()
	if g.size() != 2 {
		t.Fatalf("%d records after the sweep, want the held one and the used one", g.size())
	}
	fc.Advance(25 * time.Hour)
	g.Sweep()
	if g.size() != 1 {
		t.Fatalf("%d records a day later, want only the held one", g.size())
	}
	g.release(held)
	g.Sweep()
	if g.size() != 0 {
		t.Fatalf("%d", g.size())
	}
}

func gatedEnv(t *testing.T, budget int64, streams int) *testEnv {
	return newTestEnv(t, func(c *Config) { c.GatedBytesPerDay, c.GatedStreamsPerDay = budget, streams })
}

func (e *testEnv) gatedBytes(d *testDevice) int64 {
	e.srv.gates.mu.Lock()
	u := e.srv.gates.byHost[d.host]
	e.srv.gates.mu.Unlock()
	if u == nil {
		return 0
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.bytes
}

func TestGated_ADeviceStopsAtItsByteBudgetAndTheStreamIsCutThere(t *testing.T) {
	const budget = 60_000
	e := gatedEnv(t, budget, 200)
	d := e.newDevice()
	e.plan(d).status, e.plan(d).plan, e.plan(d).validFor = statusGated, "trial", 100*time.Hour // (the test moves the node's clock a day)
	dc := e.connectOK(d)
	if body, _ := dc.ok["body"].(map[string]any); body["status"] != "gated" {
		t.Fatalf("the OK says %v", dc.ok)
	}
	dc.serve(nil)
	c, err := e.clientTLS(d)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if resp, err := postOver(c, d.host, []byte("a thin pipe is enough for a card")); err != nil || string(resp) != "echo:a thin pipe is enough for a card" {
		t.Fatalf("a small exchange of a gated device: %q %v", resp, err)
	}
	if _, err := postOver(c, d.host, make([]byte, 400_000)); err == nil {
		t.Fatal("a body far past the budget went through")
	}
	e.waitIdle()
	if got := e.gatedBytes(d); got != budget {
		t.Fatalf("the node counted %d bytes, want exactly the budget %d", got, budget)
	}
	up, down := e.metricValue(`all_tunnel_bytes_total{direction="up"}`), e.metricValue(`all_tunnel_bytes_total{direction="down"}`)
	if up+down != budget {
		t.Fatalf("%d bytes crossed the node (up %d, down %d), want exactly %d", up+down, up, down, budget)
	}
	if e.metricValue(`all_tunnel_gated_cut_total`) != 1 || e.metricValue(`all_tunnel_stream_closed_total{reason="gated_bytes"}`) != 1 {
		t.Fatalf("metrics:\n%s", e.srv.renderMetrics())
	}
	if e.logs.Count(`"reason":"gated_bytes"`) < 1 {
		t.Fatalf("logs:\n%s", e.logs.String())
	}
	// a new stream the same day gets nothing: the byte budget is spent
	if _, err := e.clientTLS(d); err == nil {
		t.Fatal("a stream was admitted with the day's bytes spent")
	}
	if e.rejected("gated_bytes") != 1 {
		t.Fatalf("counted %d", e.rejected("gated_bytes"))
	}
	// reconnecting does not buy a new budget
	dc.c.Close()
	dc2 := e.connectOK(d)
	dc2.serve(nil)
	if _, err := e.clientTLS(d); err == nil {
		t.Fatal("a reconnected device got a fresh budget")
	}
	// midnight does
	e.offsetNS.Add(int64(24 * time.Hour))
	c3, err := e.clientTLS(d)
	if err != nil {
		t.Fatalf("the next day: %v", err)
	}
	defer c3.Close()
	if resp, err := postOver(c3, d.host, []byte("tomorrow")); err != nil || string(resp) != "echo:tomorrow" {
		t.Fatalf("%q %v", resp, err)
	}
	e.checkTranscript()
}

func TestGated_AtMostTheDaysNumberOfStreams(t *testing.T) {
	e := gatedEnv(t, 50<<20, 3)
	d := e.newDevice()
	e.plan(d).status, e.plan(d).plan = statusGated, "trial"
	dc := e.connectOK(d)
	dc.serve(nil)
	for i := 0; i < 3; i++ {
		c, err := e.clientTLS(d)
		if err != nil {
			t.Fatalf("stream %d: %v", i, err)
		}
		if _, err := postOver(c, d.host, []byte("x")); err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	if _, err := e.clientTLS(d); err == nil || !strings.Contains(err.Error(), "internal error") {
		t.Fatalf("the fourth stream of the day: %v", err)
	}
	if e.rejected("gated_streams") != 1 {
		t.Fatalf("counted %d", e.rejected("gated_streams"))
	}
	// a device that is not gated is not counted at all
	other := e.newDevice()
	oc := e.connectOK(other)
	oc.serve(nil)
	for i := 0; i < 6; i++ {
		c, err := e.clientTLS(other)
		if err != nil {
			t.Fatalf("an active device, stream %d: %v", i, err)
		}
		c.Close()
	}
}

func TestGated_ADeviceThatBecomesGatedAtARenewIsHeldToTheBudgetOnTheStreamsAlreadyOpen(t *testing.T) {
	const budget = 80_000
	e := gatedEnv(t, budget, 200)
	d := e.newDevice()
	dc := e.connectOK(d) // active, paid: the trial is still on
	dc.serve(nil)
	c, err := e.clientTLS(d)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// far more than the budget goes through while the device is active
	for i := 0; i < 3; i++ {
		if resp, err := postOver(c, d.host, make([]byte, 100_000)); err != nil || len(resp) != 100_005 {
			t.Fatalf("an active device's exchange %d: %d bytes, %v", i, len(resp), err)
		}
	}
	if e.gatedBytes(d) != 0 {
		t.Fatalf("an active device was counted: %d", e.gatedBytes(d))
	}
	// the trial ends: the control plane says gated at the next RENEW, and the node holds the open stream to the budget from there on
	e.plan(d).status, e.plan(d).plan = statusGated, "trial"
	dc.drainFeed()
	if r := dc.renew(); !strings.HasPrefix(r, "OK ") || !strings.Contains(r, `"status":"gated"`) {
		t.Fatalf("renew: %q", r)
	}
	if resp, err := postOver(c, d.host, []byte("a card")); err != nil || string(resp) != "echo:a card" {
		t.Fatalf("a small exchange after the RENEW: %q %v", resp, err)
	}
	if _, err := postOver(c, d.host, make([]byte, 300_000)); err == nil {
		t.Fatal("the stream that was already open went past the budget after the device became gated")
	}
	e.waitIdle()
	if got := e.gatedBytes(d); got != budget {
		t.Fatalf("counted %d, want exactly %d", got, budget)
	}
	// and back to active at the next RENEW: nothing is counted or cut any more, what was used stays on the day's record
	e.plan(d).status, e.plan(d).plan = statusActive, "paid"
	if r := dc.renew(); !strings.HasPrefix(r, "OK ") || !strings.Contains(r, `"status":"active"`) {
		t.Fatalf("renew: %q", r)
	}
	c2, err := e.clientTLS(d)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if resp, err := postOver(c2, d.host, make([]byte, 200_000)); err != nil || len(resp) != 200_005 {
		t.Fatalf("a device that is active again: %d bytes, %v", len(resp), err)
	}
	if e.gatedBytes(d) != budget {
		t.Fatalf("an active device was counted again: %d", e.gatedBytes(d))
	}
	e.checkTranscript()
}

func TestGated_AFeedRefreshThatMakesTheHostGatedAlsoHoldsItsStreams(t *testing.T) {
	const budget = 70_000
	e, cp := httpNode(t, nil, func(c *Config) { c.GatedBytesPerDay = budget })
	cp.mu.Lock()
	cp.hold = 10 * time.Second
	cp.mu.Unlock()
	d := e.newDevice()
	dc := e.connectOK(d)
	dc.serve(nil)
	c, err := e.clientTLS(d)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := postOver(c, d.host, make([]byte, 100_000)); err != nil {
		t.Fatalf("while active: %v", err)
	}
	// a resume event after the control plane turned the device gated (the node asks authorize again, outside any RENEW of the device)
	e.plan(d).status, e.plan(d).plan = statusGated, "trial"
	cp.addEvent("resume", d)
	eventually(t, "the refresh asked authorize again", 5*time.Second, func() bool { return e.cp.callsFor(d.id, "renew") >= 1 })
	eventually(t, "the host is gated", 5*time.Second, func() bool {
		cc, he := e.srv.routes.lookup(d.host)
		return cc != nil && he.gated.Load()
	})
	if _, err := postOver(c, d.host, make([]byte, 300_000)); err == nil {
		t.Fatal("the stream was not held to the budget after the refresh")
	}
	e.waitIdle()
	if got := e.gatedBytes(d); got != budget {
		t.Fatalf("counted %d, want %d", got, budget)
	}
}

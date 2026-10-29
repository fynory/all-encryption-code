package main

import (
	"strings"
	"testing"
	"time"
)

// What a node does when its control plane does not answer (the design plan, section 5): what is already authenticated goes on until
// valid_until, a paid device gets 15 minutes more, a trial or a gated device gets none, and nothing new is admitted without a good authorize. Every
// test runs the whole stack (HTTPS client, JWKS cache, feed) against a fake control plane on a clock the test moves by hand.

// pass moves the node's clock forward by d in steps of at most step, giving the node's timers and loops a moment after each.
func (e *testEnv) pass(d, step time.Duration) {
	for d > 0 {
		s := min(d, step)
		e.clk.Advance(s)
		time.Sleep(12 * time.Millisecond)
		d -= s
	}
}

// outageDevice is a device with its connection up, its read loop running and a stream of a client open on it.
type outageDevice struct {
	d      *testDevice
	conn   *devConn
	ds     *devServer
	stream *tlsClient
}

func connectWithStream(t *testing.T, e *testEnv, plan devicePlan) *outageDevice {
	t.Helper()
	d := e.newDeviceNoPlan()
	plan.host = d.host
	e.cp.set(d.id, &plan)
	dc := e.connectOK(d)
	ds := dc.serve(nil)
	return &outageDevice{d: d, conn: dc, ds: ds, stream: streamOpen(t, e, d)}
}

// validUntil is the moment the OK gave the connection.
func (o *outageDevice) validUntil() time.Time {
	return time.Unix(int64(o.conn.ok["body"].(map[string]any)["valid_until"].(float64)), 0)
}

func (o *outageDevice) closed(want string) bool { return containsLine(o.ds.otherLines(), want) }

func (o *outageDevice) renewFails(t *testing.T) {
	t.Helper()
	if line := o.conn.renew(); line != "ERR control_unavailable" {
		t.Fatalf("a RENEW while the control plane is down: %q", line)
	}
}

func TestOutage_ADownControlPlaneFor14MinutesKeepsPaidTunnelsAndRefusesNewAttaches(t *testing.T) {
	clk := newFakeClock()
	e, cp := httpNode(t, clk, nil)
	paid := connectWithStream(t, e, devicePlan{validFor: 4 * time.Hour})

	cp.setDown(503)
	e.pass(14*time.Minute, time.Minute)

	// the paid tunnel and its stream are untouched, and the host still serves new clients
	if !e.srv.Online(paid.d.host) || paid.stream.dead(50*time.Millisecond) || paid.closed("CLOSE") {
		t.Fatal("a paid tunnel did not survive 14 minutes of a down control plane")
	}
	if c, err := e.clientTLS(paid.d); err != nil {
		t.Fatalf("a client of a device that is authenticated: %v", err)
	} else {
		_ = c.Close()
	}
	// a NEW attach needs a good authorize: it is refused with a word that says "try later", and nothing was relayed
	newcomer := e.newDevice()
	conn := e.connect(newcomer)
	line := conn.hello(func() string { return e.session(newcomer, nil) }, func(s, n string) string { return e.proof(newcomer, s, n, nil) })
	if line != "ERR control_unavailable" {
		t.Fatalf("a new attach during the outage: %q", line)
	}
	if e.srv.Online(newcomer.host) {
		t.Fatal("a device that nothing authorized is served")
	}
	// and the same device that was already attached may RENEW later, when the control plane is back; until then its renewals keep the connection
	paid.renewFails(t)
	if !e.srv.Online(paid.d.host) {
		t.Fatal("a refused RENEW closed the connection")
	}
	cp.setDown(0)
	clk.Advance(2 * time.Second)
	if line := e.connect(newcomer).hello(func() string { return e.session(newcomer, nil) }, func(s, n string) string { return e.proof(newcomer, s, n, nil) }); !strings.HasPrefix(line, "OK ") {
		t.Fatalf("a new attach once the control plane is back: %q", line)
	}
	if r := paid.conn.renew(); !strings.HasPrefix(r, "OK ") {
		t.Fatalf("renew after the outage: %q", r)
	}
}

func TestOutage_ATrialAndAGatedTunnelAreNotExtended(t *testing.T) {
	clk := newFakeClock()
	e, cp := httpNode(t, clk, nil)
	trial := connectWithStream(t, e, devicePlan{plan: "trial", validFor: 15 * time.Minute})
	gated := connectWithStream(t, e, devicePlan{status: statusGated, plan: "trial", validFor: 15 * time.Minute})
	if gated.conn.ok["body"].(map[string]any)["status"] != "gated" {
		t.Fatalf("OK %v", gated.conn.ok)
	}

	cp.setDown(503)
	e.pass(10*time.Minute, time.Minute) // the moment a device renews: valid_until minus 5 minutes
	trial.renewFails(t)
	gated.renewFails(t)
	// gated opens streams like any other device: the card is served by the device
	if c, err := e.clientTLS(gated.d); err != nil {
		t.Fatalf("a client of a gated device: %v", err)
	} else {
		_ = c.Close()
	}

	// five minutes later the grants are over, the control plane still down: no grace for either
	e.pass(5*time.Minute+2*time.Second, 30*time.Second)
	for name, o := range map[string]*outageDevice{"trial": trial, "gated": gated} {
		o := o
		eventually(t, name+" CLOSE expired", 3*time.Second, func() bool { return o.closed("CLOSE expired") })
		if !o.stream.dead(2 * time.Second) {
			t.Errorf("%s: the stream outlived the grant", name)
		}
		if e.srv.Online(o.d.host) {
			t.Errorf("%s: still online", name)
		}
	}
}

func TestOutage_APaidTunnelOutlivesItsValidUntilByTheGraceAndNotOneSecondMore(t *testing.T) {
	if policyData.Authorization.GracePaidS != 900 {
		t.Fatalf("the plan says 15 minutes of grace, the policy says %d s", policyData.Authorization.GracePaidS)
	}
	clk := newFakeClock()
	e, cp := httpNode(t, clk, nil)
	paid := connectWithStream(t, e, devicePlan{validFor: 15 * time.Minute})
	validUntil := paid.validUntil()

	cp.setDown(503)
	e.pass(10*time.Minute, time.Minute)
	paid.renewFails(t)
	e.pass(validUntil.Sub(e.now())+time.Second, 30*time.Second)

	// past valid_until: the connection and its stream live (grace), but no NEW stream is opened
	if paid.closed("CLOSE") || paid.stream.dead(50*time.Millisecond) {
		t.Fatal("a paid tunnel was cut at valid_until although the control plane is down")
	}
	if e.srv.Online(paid.d.host) {
		t.Fatal("a stream may be opened after valid_until")
	}
	if _, err := e.clientTLS(paid.d); err == nil {
		t.Fatal("a new client got a stream after valid_until")
	}
	if !strings.Contains(e.logs.String(), `"msg":"control_grace"`) {
		t.Fatal("the grace is not logged")
	}
	// (the contracts' transcript checker has no notion of the grace, so this test does not run it; the rule it enforces, no OPEN at or after
	// valid_until, is the two refusals above)

	// just before the grace ends it still lives
	e.pass(validUntil.Add(policyDataGrace()).Sub(e.now())-10*time.Second, 30*time.Second)
	if paid.closed("CLOSE") || paid.stream.dead(50*time.Millisecond) {
		t.Fatal("cut before the grace was over")
	}
	// and when it is over, the connection and the streams are closed
	e.pass(20*time.Second, 5*time.Second)
	eventually(t, "CLOSE expired", 3*time.Second, func() bool { return paid.closed("CLOSE expired") })
	if !paid.stream.dead(2 * time.Second) {
		t.Fatal("the stream outlived the grace")
	}
}

func policyDataGrace() time.Duration { return secs(policyData.Authorization.GracePaidS) }

func TestOutage_APaidDeviceTheControlPlaneRefusedGetsNoGrace(t *testing.T) {
	clk := newFakeClock()
	e, _ := httpNode(t, clk, nil)
	// The control plane is UP and says no: a license that ended. The paid plan does not matter, there is nothing to be graceful about.
	refused := connectWithStream(t, e, devicePlan{validFor: 15 * time.Minute})
	e.pass(10*time.Minute, time.Minute)
	e.cp.set(refused.d.id, &devicePlan{host: refused.d.host, err: &ControlError{Status: 402, Code: codeLicenseInactive}})
	if r := refused.conn.renew(); r != "ERR license_inactive" {
		t.Fatalf("%q", r)
	}
	e.pass(5*time.Minute+2*time.Second, 30*time.Second)
	eventually(t, "CLOSE expired", 3*time.Second, func() bool { return refused.closed("CLOSE expired") })
	if !refused.stream.dead(2 * time.Second) {
		t.Fatal("the stream outlived the grant of a device the control plane refused")
	}
	if strings.Contains(e.logs.String(), `"msg":"control_grace"`) {
		t.Fatal("a grace was given while the control plane was answering")
	}
}

func TestOutage_ADeviceWhoseOwnRenewalHadNoAnswerGetsTheGraceEvenWhileTheRestOfTheControlPlaneWorks(t *testing.T) {
	// "subscription_verification_unavailable": the control plane is up but cannot tell whether the subscription is paid. Nothing is granted, and a
	// paying device's connection is not cut for it.
	clk := newFakeClock()
	e, _ := httpNode(t, clk, nil)
	o := connectWithStream(t, e, devicePlan{validFor: 15 * time.Minute})
	validUntil := o.validUntil()
	e.pass(10*time.Minute, time.Minute)
	e.cp.set(o.d.id, &devicePlan{host: o.d.host, err: &ControlError{Status: 503, Code: "subscription_verification_unavailable"}})
	o.renewFails(t)
	e.pass(validUntil.Sub(e.now())+time.Second, 30*time.Second)
	if o.closed("CLOSE") || o.stream.dead(50*time.Millisecond) {
		t.Fatal("a paying device was cut because the subscription could not be verified")
	}
	e.pass(policyDataGrace(), time.Minute)
	eventually(t, "CLOSE expired", 3*time.Second, func() bool { return o.closed("CLOSE expired") })
}

func TestOutage_ARenewInsideTheGraceEndsItAndTheNewGrantIsTheControlPlanes(t *testing.T) {
	clk := newFakeClock()
	e, cp := httpNode(t, clk, nil)
	o := connectWithStream(t, e, devicePlan{validFor: 15 * time.Minute})
	validUntil := o.validUntil()
	cp.setDown(503)
	e.pass(10*time.Minute, time.Minute)
	o.renewFails(t)
	e.pass(validUntil.Sub(e.now())+time.Minute, 30*time.Second) // a minute into the grace
	if o.closed("CLOSE") {
		t.Fatal("closed inside the grace")
	}
	// the control plane is back: the next RENEW works, and the connection has a new valid_until with no grace attached
	cp.setDown(0)
	clk.Advance(2 * time.Second)
	if r := o.conn.renew(); !strings.HasPrefix(r, "OK ") {
		t.Fatalf("renew inside the grace: %q", r)
	}
	if !e.srv.Online(o.d.host) {
		t.Fatal("not served after the renewal")
	}
	// the old end of the grace passes: nothing happens (the new grant is a minute longer than that)
	e.pass(o.validUntil().Add(policyDataGrace()).Sub(e.now())+10*time.Second, 30*time.Second)
	if o.closed("CLOSE") || o.stream.dead(50*time.Millisecond) || !e.srv.Online(o.d.host) {
		t.Fatal("the old grace closed a connection that was renewed")
	}
	e.checkTranscript()
}

func TestOutage_APaidTunnelSurvivesATwoHourControlPlaneOutage(t *testing.T) {
	clk := newFakeClock()
	e, cp := httpNode(t, clk, nil)
	paid := connectWithStream(t, e, devicePlan{validFor: 4 * time.Hour})
	other := connectWithStream(t, e, devicePlan{validFor: 4 * time.Hour})
	validUntil := paid.validUntil()

	cp.setDown(503)
	e.pass(2*time.Hour, 5*time.Minute)

	for name, o := range map[string]*outageDevice{"first": paid, "second": other} {
		if !e.srv.Online(o.d.host) || o.closed("CLOSE") || o.stream.dead(50*time.Millisecond) {
			t.Fatalf("%s: a paid tunnel did not survive two hours of a down control plane", name)
		}
		if c, err := e.clientTLS(o.d); err != nil {
			t.Fatalf("%s: a new client during the outage: %v", name, err)
		} else {
			_ = c.Close()
		}
	}
	// by now the node no longer vouches for the control plane's keys (30 minutes), so even a good session is refused as "try later"
	newcomer := e.newDevice()
	if line := e.connect(newcomer).hello(func() string { return e.session(newcomer, nil) }, func(s, n string) string { return e.proof(newcomer, s, n, nil) }); line != "ERR control_unavailable" {
		t.Fatalf("a new attach after two hours of outage: %q", line)
	}

	// the control plane comes back: the connection renews when it is due, and gets a fresh four hours
	cp.setDown(0)
	e.pass(validUntil.Add(-5*time.Minute).Sub(e.now()), 20*time.Minute)
	if r := paid.conn.renew(); !strings.HasPrefix(r, "OK ") {
		t.Fatalf("renew after the outage: %q", r)
	}
	e.pass(30*time.Minute, 10*time.Minute) // past the old valid_until
	if !e.srv.Online(paid.d.host) || paid.closed("CLOSE") {
		t.Fatal("the renewed connection was closed at the old valid_until")
	}
	e.checkTranscript()
}

func TestGated_ATrialThatEndsBecomesGatedAtItsRenewalWithoutAnyEvent(t *testing.T) {
	clk := newFakeClock()
	e, _ := httpNode(t, clk, nil)
	o := connectWithStream(t, e, devicePlan{plan: "trial", validFor: 15 * time.Minute})
	if o.conn.ok["body"].(map[string]any)["status"] != "active" {
		t.Fatalf("OK %v", o.conn.ok)
	}
	e.pass(10*time.Minute, time.Minute)
	// the trial ended: the control plane now says gated (and never beyond its cutoff)
	e.cp.set(o.d.id, &devicePlan{host: o.d.host, status: statusGated, plan: "trial", validFor: 15 * time.Minute})
	r := o.conn.renew()
	if !strings.HasPrefix(r, "OK ") || !strings.Contains(r, `"status":"gated"`) {
		t.Fatalf("renew of a trial that ended: %q", r)
	}
	if c, err := e.clientTLS(o.d); err != nil {
		t.Fatalf("a gated device serves streams (the card is the device's): %v", err)
	} else {
		_ = c.Close()
	}
	// and it is not extended by anything the node thinks: with the control plane down at the next end, it closes
	e.cpDownThrough(15 * time.Minute)
	eventually(t, "CLOSE expired", 3*time.Second, func() bool { return o.closed("CLOSE expired") })
	e.checkTranscript()
}

// cpDownThrough takes the control plane down (every call of the node answers 503) and lets d pass.
func (e *testEnv) cpDownThrough(d time.Duration) {
	e.cp.mu.Lock()
	for _, p := range e.cp.plans {
		p.err = &ControlError{Status: 503, Code: "end_to_end_unavailable"}
	}
	e.cp.mu.Unlock()
	e.pass(d+2*time.Second, time.Minute)
}

func TestOutage_APaidDeviceTheControlPlaneRefusedGetsNoGraceWhenTheControlPlaneGoesDownLater(t *testing.T) {
	clk := newFakeClock()
	e, cp := httpNode(t, clk, nil)
	o := connectWithStream(t, e, devicePlan{validFor: 15 * time.Minute})
	validUntil := o.validUntil()
	e.pass(2*time.Minute, time.Minute)
	e.cp.set(o.d.id, &devicePlan{host: o.d.host, err: &ControlError{Status: 402, Code: codeLicenseInactive}})
	if r := o.conn.renew(); r != "ERR license_inactive" {
		t.Fatalf("%q", r)
	}
	// the whole control plane goes down afterwards: the node cannot tell one device from another, but it has been told no for this one
	cp.setDown(503)
	e.pass(validUntil.Sub(e.now())+2*time.Second, time.Minute)
	eventually(t, "CLOSE expired", 3*time.Second, func() bool { return o.closed("CLOSE expired") })
	if strings.Contains(e.logs.String(), `"msg":"control_grace"`) {
		t.Fatal("a device the control plane refused was given the grace")
	}
}

func TestOutage_ARenewTheNodeItselfCouldNotSendIsNotTheControlPlaneBeingDown(t *testing.T) {
	// The node's own queue for authorize is full: the control plane was never asked, and answers everyone else. The device gets no grace for it.
	clk := newFakeClock()
	e, _ := httpNode(t, clk, func(c *Config) { c.MaxUnauth = 1 })
	o := connectWithStream(t, e, devicePlan{validFor: 15 * time.Minute})
	validUntil := o.validUntil()
	e.pass(2*time.Minute, time.Minute)

	slow := e.newDevice()
	e.cp.set(slow.id, &devicePlan{host: slow.host, validFor: time.Hour, delay: 2 * time.Second})
	hello := e.helloAsync(slow)
	eventually(t, "the other device's authorize in flight", 3*time.Second, func() bool { return e.cp.callsFor(slow.id, "hello") == 1 })
	o.renewFails(t)
	if n := e.cp.callsFor(o.d.id, "renew"); n != 0 {
		t.Fatalf("the control plane was asked %d times: the queue was not full", n)
	}
	<-hello
	e.pass(validUntil.Sub(e.now())+2*time.Second, time.Minute)
	eventually(t, "CLOSE expired", 3*time.Second, func() bool { return o.closed("CLOSE expired") })
	if strings.Contains(e.logs.String(), `"msg":"control_grace"`) {
		t.Fatal("a RENEW that never left the node was taken for a control plane that does not answer")
	}
}

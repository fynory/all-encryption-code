package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

// A paid device whose RENEW is refused only because the node cannot read the control plane's keys (they are older than the policy's window: the control plane is away) is
// a device the control plane did not answer: it gets the grace, as a device whose authorize call failed does. Before, the connection closed at valid_until (the chaos suite's
// real-device outage case): the node refused the session without recording that the control plane was down.
func TestOutage_ARenewRefusedBecauseTheKeysAreStaleStillEarnsThePaidGrace(t *testing.T) {
	clk := newFakeClock()
	// the node's own record of failed authorize calls must not be what gives the grace here (no authorize call is made: the session is refused before one): with it out of the way,
	// only the refusal itself can say that the control plane is away
	e, cp := httpNode(t, clk, func(c *Config) { c.DownQuiet = 1000 * time.Hour })
	o := connectWithStream(t, e, devicePlan{validFor: 3 * time.Hour})
	validUntil := o.validUntil()
	cp.setDown(503)
	e.pass(31*time.Minute, time.Minute) // the node's set of keys is now older than the window it may vouch for

	_, newPriv, _ := ed25519.GenerateKey(rand.Reader)
	const newKID = "cp-rotated-while-away"
	o.conn.session = e.sessionSignedBy(newPriv, o.d, func(h, c map[string]any) { h["kid"] = newKID })
	o.conn.send("RENEW " + o.conn.session)
	if line := o.conn.recv(); line != "ERR control_unavailable" {
		t.Fatalf("a RENEW with a key the node cannot vouch for: %q", line)
	}
	if !strings.Contains(e.logs.String(), `"reason":"unknown_kid"`) {
		t.Fatal("the refusal was not the stale-keys one")
	}

	e.pass(validUntil.Sub(e.now())+time.Second, 30*time.Second)
	if o.closed("CLOSE") || o.stream.dead(50*time.Millisecond) {
		t.Fatal("a paid device was cut at valid_until although the control plane was away")
	}
	if !strings.Contains(e.logs.String(), `"msg":"control_grace"`) {
		t.Fatal("no grace was given")
	}
	e.pass(policyDataGrace(), time.Minute)
	eventually(t, "CLOSE expired once the grace is over", 3*time.Second, func() bool { return o.closed("CLOSE expired") })
}

func TestOutage_AHelloRefusedBecauseTheKeysAreStaleGivesNoGraceToAnythingBecauseThereIsNoConnectionYet(t *testing.T) {
	clk := newFakeClock()
	e, cp := httpNode(t, clk, nil)
	cp.setDown(503)
	e.pass(31*time.Minute, time.Minute)
	d := e.newDevice()
	_, newPriv, _ := ed25519.GenerateKey(rand.Reader)
	line := e.connect(d).hello(func() string {
		return e.sessionSignedBy(newPriv, d, func(h, c map[string]any) { h["kid"] = "cp-unknown" })
	}, func(s, n string) string { return e.proof(d, s, n, nil) })
	if line != "ERR control_unavailable" {
		t.Fatalf("a HELLO on stale keys: %q", line)
	}
	if strings.Contains(e.logs.String(), `"msg":"control_grace"`) {
		t.Fatal("a grace for a connection that never existed")
	}
}

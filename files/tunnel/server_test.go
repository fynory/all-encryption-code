package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ------------------------------------------------------------------------------------------------------------------------------------
// The handshake and the label binding
// ------------------------------------------------------------------------------------------------------------------------------------

func TestHello_OKRelaysWhatTheControlPlaneDecided(t *testing.T) {
	e := newTestEnv(t, nil)
	// valid_until is relayed exactly as the control plane gave it, never trimmed by the node: paid 14400 s, running trial 900 s, gated 900 s
	for name, tc := range map[string]struct {
		validFor time.Duration
		status   string
		plan     string
	}{
		"paid":                            {secs(ctPolInt("authorization.valid_until_paid_s")), statusActive, "paid"},
		"trial":                           {secs(ctPolInt("authorization.valid_until_trial_s")), statusActive, "trial"},
		"gated":                           {secs(ctPolInt("authorization.valid_until_gated_s")), statusGated, "trial"},
		"a trial that ends in 90 seconds": {90 * time.Second, statusActive, "trial"},
	} {
		d := e.newDevice()
		*e.plan(d) = devicePlan{host: d.host, validFor: tc.validFor, status: tc.status, plan: tc.plan}
		before := e.now().Unix()
		dc := e.connectOK(d)
		after := e.now().Unix()
		body := dc.ok["body"].(map[string]any)
		if body["host"] != d.host || body["node"] != testNodeID || body["status"] != tc.status {
			t.Fatalf("%s: OK body %v", name, body)
		}
		until := int64(body["valid_until"].(float64))
		if until < before+int64(tc.validFor/time.Second) || until > after+int64(tc.validFor/time.Second) {
			t.Fatalf("%s: valid_until %d, want about %d", name, until, before+int64(tc.validFor/time.Second))
		}
		calls := e.cp.callLog()
		last := calls[len(calls)-1]
		if last.DeviceID != d.id || last.Reason != "hello" || last.Node != testNodeID {
			t.Fatalf("%s: authorize call %+v", name, last)
		}
		// the windows are the policy's own
		pol := body["policy"].(map[string]any)
		if pol["dead_peer_s"] != float64(ctPolInt("timing.dead_peer_s")) || pol["renew_before_valid_until_s"] != float64(ctPolInt("timing.renew_before_valid_until_s")) {
			t.Fatalf("%s: policy block %v", name, pol)
		}
	}
	e.checkTranscript()
}

func TestLabelBinding_ASessionOfOneDeviceNeverBringsUpTheHostOfAnother(t *testing.T) {
	e := newTestEnv(t, nil)
	a, b := e.newDevice(), e.newDevice()
	sessionA := e.session(a, nil)

	attempts := map[string]string{
		"host as a third field":     "HELLO 2 " + sessionA + " " + b.host,
		"host in the version slot":  "HELLO " + b.host + " " + sessionA,
		"host before the session":   "HELLO 2 " + b.host + " " + sessionA,
		"label as an extra field":   "HELLO 2 " + sessionA + " " + b.label,
		"a host command":            "HOST " + b.host,
		"a session for another key": "HELLO 2 " + e.sessionSignedBy(b.key, b, nil),
	}
	for name, line := range attempts {
		dc := e.connect(a)
		dc.send(line)
		reply := dc.recv()
		if !strings.HasPrefix(reply, "ERR ") {
			t.Fatalf("%s: answered %q", name, reply)
		}
		dc.expectClosed(2 * time.Second)
	}
	// a proof that names B, or is signed by B's key, for A's session
	for name, mutate := range map[string]func(h, c map[string]any){
		"proof of B's subject": func(h, c map[string]any) { c["sub"] = b.id },
		"proof with B's key": func(h, c map[string]any) {
			h["jwk"] = map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64Encode(b.key.Public().(ed25519.PublicKey))}
		},
		"proof with a host claim": func(h, c map[string]any) { c["host"] = b.host; c["sub"] = b.id },
	} {
		dc := e.connect(a)
		reply := dc.hello(func() string { return sessionA }, func(s, n string) string { return e.proof(a, s, n, mutate) })
		if !strings.HasPrefix(reply, "ERR ") {
			t.Fatalf("%s: answered %q", name, reply)
		}
		dc.expectClosed(2 * time.Second)
	}
	if n := len(e.cp.callLog()); n != 0 {
		t.Fatalf("the control plane was asked %d times about a session that never proved itself", n)
	}
	if e.srv.Online(b.host) || e.srv.Online(a.host) {
		t.Fatal("a host is up although no device authenticated")
	}

	// A, honestly: a valid session that carries extra claims naming B's host still binds only A's own host
	dc := e.connect(a)
	reply := dc.hello(
		func() string {
			return e.session(a, func(h, c map[string]any) { c["host"] = b.host; c["label"] = b.label; c["hostname"] = b.host })
		},
		func(s, n string) string { return e.proof(a, s, n, nil) })
	if m, err := parseLine(reply, dirN2D); err != nil || m.str("verb") != "OK" || m["body"].(map[string]any)["host"] != a.host {
		t.Fatalf("A's handshake: %q", reply)
	}
	dsA := dc.serve(nil)
	if !e.srv.Online(a.host) || e.srv.Online(b.host) {
		t.Fatal("the node serves the wrong host")
	}
	// a client of B's host while only A is connected: refused with an alert, A is never asked to open anything
	if _, err := e.clientTLS(b); err == nil {
		t.Fatal("a client of B's host got a TLS session")
	}
	time.Sleep(100 * time.Millisecond)
	if dsA.openCount() != 0 {
		t.Fatal("A was asked to open a stream for B's host")
	}
	c, err := e.clientTLS(a)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := postOver(c, a.host, []byte("hi")); err != nil || string(resp) != "echo:hi" {
		t.Fatalf("A's own host: %q %v", resp, err)
	}
	_ = c.Close()
	e.checkTranscript()
}

func TestLabelBinding_AHostIsNeverGivenToTwoDevices(t *testing.T) {
	e := newTestEnv(t, nil)
	a, b := e.newDevice(), e.newDevice()
	// a control plane that (wrongly) answers the same host for two devices: the first holds it, the second is refused
	e.plan(b).host = a.host
	dcA := e.connectOK(a)
	dsA := dcA.serve(nil)

	dcB := e.connect(b)
	reply := dcB.hello(func() string { return e.session(b, nil) }, func(s, n string) string { return e.proof(b, s, n, nil) })
	if reply != "ERR auth" {
		t.Fatalf("second device for the same host: %q", reply)
	}
	dcB.expectClosed(2 * time.Second)

	// traffic for the host still reaches A
	c, err := e.clientTLS(a)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := postOver(c, a.host, []byte("still-a")); err != nil || string(resp) != "echo:still-a" {
		t.Fatalf("%q %v", resp, err)
	}
	_ = c.Close()
	if dsA.openCount() != 1 {
		t.Fatalf("A got %d opens", dsA.openCount())
	}
	e.checkTranscript()
}

func TestLabelBinding_ARenewThatChangesTheHostClosesTheConnection(t *testing.T) {
	e := newTestEnv(t, nil)
	d := e.newDevice()
	dc := e.connectOK(d)
	// the control plane now says this device owns another host (its label was retired): the old host must stop being served at once
	e.plan(d).host = label20() + "." + testZone
	reply := dc.renew()
	_ = reply
	lines := append([]string{reply}, dc.expectClosed(2*time.Second)...)
	if !containsLine(lines, "CLOSE revoked") {
		t.Fatalf("lines after the renew: %q", lines)
	}
	eventually(t, "old host unbound", 2*time.Second, func() bool { return !e.srv.Online(d.host) })
}

func containsLine(lines []string, want string) bool {
	for _, l := range lines {
		if l == want {
			return true
		}
	}
	return false
}

// ------------------------------------------------------------------------------------------------------------------------------------
// Proofs, sessions and what is refused
// ------------------------------------------------------------------------------------------------------------------------------------

func TestAuth_ExpiredWrongAudienceWrongKidReplayedAndWrongHTUAreRefused(t *testing.T) {
	e := newTestEnv(t, nil)
	d := e.newDevice()
	_, rogue, _ := ed25519.GenerateKey(rand.Reader)
	other := e.newDevice()
	otherSession := e.session(other, nil)

	type tc struct {
		name    string
		session func() string
		proof   func(session, nonce string) string
		want    string // the ERR line
	}
	goodSession := func() string { return e.session(d, nil) }
	goodProof := func(s, n string) string { return e.proof(d, s, n, nil) }
	proofWith := func(mutate func(h, c map[string]any)) func(s, n string) string {
		return func(s, n string) string { return e.proof(d, s, n, mutate) }
	}
	sessionWith := func(mutate func(h, c map[string]any)) func() string {
		return func() string { return e.session(d, mutate) }
	}
	cases := []tc{
		{"expired session", sessionWith(func(h, c map[string]any) { c["iat"], c["exp"] = e.now().Unix()-400, e.now().Unix()-100 }), goodProof, "ERR auth"},
		{"wrong lifetime", sessionWith(func(h, c map[string]any) { c["exp"] = c["iat"].(int64) + 3000 }), goodProof, "ERR auth"},
		{"audience all-relay", sessionWith(func(h, c map[string]any) { c["aud"] = "all-relay" }), goodProof, "ERR auth"},
		{"audience all-control", sessionWith(func(h, c map[string]any) { c["aud"] = "all-control" }), goodProof, "ERR auth"},
		{"no audience", sessionWith(func(h, c map[string]any) { delete(c, "aud") }), goodProof, "ERR auth"},
		{"wrong kid", sessionWith(func(h, c map[string]any) { h["kid"] = "cp-unknown" }), goodProof, "ERR auth"},
		{"signed by a forger", func() string { return e.sessionSignedBy(rogue, d, nil) }, goodProof, "ERR auth"},
		{"alg none", func() string {
			s := e.session(d, nil)
			parts := strings.Split(s, ".")
			return b64Encode([]byte(`{"alg":"none","typ":"device-session","kid":"`+testKID+`"}`)) + "." + parts[1] + "."
		}, goodProof, "ERR bad_hello"}, // no signature segment: not even the shape of a token
		{"alg none with a signature part", func() string {
			s := e.session(d, nil)
			parts := strings.Split(s, ".")
			return b64Encode([]byte(`{"alg":"none","typ":"device-session","kid":"`+testKID+`"}`)) + "." + parts[1] + "." + parts[2]
		}, goodProof, "ERR auth"},
		{"alg HS256", sessionWith(func(h, c map[string]any) { h["alg"] = "HS256" }), goodProof, "ERR auth"},
		{"wrong issuer", sessionWith(func(h, c map[string]any) { c["iss"] = "https://evil.example" }), goodProof, "ERR auth"},
		{"ver 1", sessionWith(func(h, c map[string]any) { c["ver"] = 1 }), goodProof, "ERR auth"},
		{"a clock far ahead", sessionWith(func(h, c map[string]any) { c["iat"], c["exp"] = e.now().Unix()+120, e.now().Unix()+420 }), goodProof, "ERR clock_skew"},

		{"proof for another node's URL", goodSession, proofWith(func(h, c map[string]any) {
			c["htu"] = "https://t2.nodes.all-e2e.test" + policyData.Protocol.ProofHTUPath
		}), "ERR bad_proof"},
		{"proof with a port in the URL", goodSession, proofWith(func(h, c map[string]any) {
			c["htu"] = "https://" + testNodeHost + ":8443" + policyData.Protocol.ProofHTUPath
		}), "ERR bad_proof"},
		{"proof for the node's host and another path", goodSession, proofWith(func(h, c map[string]any) { c["htu"] = "https://" + testNodeHost + "/" }), "ERR bad_proof"},
		{"proof with another nonce", goodSession, proofWith(func(h, c map[string]any) { c["nonce"] = "AAAAAAAAAAAAAAAAAAAAAA" }), "ERR bad_proof"},
		{"proof for another session", goodSession, proofWith(func(h, c map[string]any) { c["ath"] = sha256B64([]byte(otherSession)) }), "ERR bad_proof"},
		{"stale proof", goodSession, proofWith(func(h, c map[string]any) { c["iat"] = e.now().Unix() - 200 }), "ERR clock_skew"},
		{"proof from the future", goodSession, proofWith(func(h, c map[string]any) { c["iat"] = e.now().Unix() + 200 }), "ERR clock_skew"},
		{"proof with POST", goodSession, proofWith(func(h, c map[string]any) { c["htm"] = "POST" }), "ERR bad_proof"},
		{"proof for the relay audience", goodSession, proofWith(func(h, c map[string]any) { c["aud"] = "all-relay" }), "ERR auth"},
		{"proof of another subject", goodSession, proofWith(func(h, c map[string]any) { c["sub"] = other.id }), "ERR bad_proof"},
		{"proof signed by another key", goodSession, func(s, n string) string { return e.proof(other, s, n, func(h, c map[string]any) { c["sub"] = d.id }) }, "ERR bad_proof"},
		{"proof with a private part in the jwk", goodSession, proofWith(func(h, c map[string]any) { h["jwk"].(map[string]any)["d"] = "AAAA" }), "ERR bad_hello"},
		{"proof of the wrong type", goodSession, proofWith(func(h, c map[string]any) { h["typ"] = "JWT" }), "ERR bad_proof"},
		{"proof without a jti", goodSession, proofWith(func(h, c map[string]any) { delete(c, "jti") }), "ERR bad_proof"},
		{"proof that is not a token", goodSession, func(s, n string) string { return "AAAA.BBBB.CCCC" }, "ERR bad_hello"},
	}
	for _, c := range cases {
		dc := e.connect(d)
		reply := dc.hello(c.session, c.proof)
		if reply != c.want {
			t.Errorf("%s: answered %q, want %q", c.name, reply, c.want)
		}
		dc.expectClosed(2 * time.Second)
		if e.srv.Online(d.host) {
			t.Fatalf("%s: the host is up", c.name)
		}
	}
	if n := len(e.cp.callLog()); n != 0 {
		t.Fatalf("authorize was called %d times for refused sessions and proofs", n)
	}

	// replay: the very proof jti of an accepted handshake is refused on another connection, with a fresh nonce
	var spent string
	dc := e.connect(d)
	reply := dc.hello(goodSession, func(s, n string) string {
		p := e.proof(d, s, n, nil)
		spent = p
		return p
	})
	if !strings.HasPrefix(reply, "OK ") {
		t.Fatalf("baseline handshake: %q", reply)
	}
	_ = dc.c.Close()
	jti := jtiOf(t, spent)
	dc = e.connect(d)
	reply = dc.hello(goodSession, func(s, n string) string { return e.proof(d, s, n, func(h, c map[string]any) { c["jti"] = jti }) })
	if reply != "ERR bad_proof" {
		t.Fatalf("replayed proof jti: %q", reply)
	}
	// the same proof text on a connection whose nonce differs fails on the nonce, and a session jti is NOT single use: a cached session reconnects
	session := e.session(d, nil)
	for i := 0; i < 2; i++ {
		dc = e.connect(d)
		reply = dc.hello(func() string { return session }, goodProof)
		if !strings.HasPrefix(reply, "OK ") {
			t.Fatalf("a cached session must reconnect (round %d): %q", i, reply)
		}
		_ = dc.c.Close()
	}
	e.checkTranscript()
}

func jtiOf(t *testing.T, token string) string {
	t.Helper()
	j, err := splitJWS(token, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	return j.claims["jti"].(string)
}

func TestAuth_ClockSkewWindowIsConfigurable(t *testing.T) {
	ahead := func(e *testEnv, d *testDevice, by int64) string {
		dc := e.connect(d)
		return dc.hello(
			func() string {
				return e.session(d, func(h, c map[string]any) { c["iat"], c["exp"] = e.now().Unix()+by, e.now().Unix()+by+300 })
			},
			func(s, n string) string {
				return e.proof(d, s, n, func(h, c map[string]any) { c["iat"] = e.now().Unix() + by })
			})
	}
	e := newTestEnv(t, nil) // the policy's own window: a few seconds
	d := e.newDevice()
	if r := ahead(e, d, 3); !strings.HasPrefix(r, "OK ") {
		t.Fatalf("a device clock 3 s fast: %q", r)
	}
	if r := ahead(e, d, 30); r != "ERR clock_skew" {
		t.Fatalf("a device clock 30 s fast: %q", r)
	}
	// a device whose clock is slow still authenticates while its tokens are fresh
	dc := e.connect(d)
	r := dc.hello(
		func() string {
			return e.session(d, func(h, c map[string]any) { c["iat"], c["exp"] = e.now().Unix()-20, e.now().Unix()+280 })
		},
		func(s, n string) string {
			return e.proof(d, s, n, func(h, c map[string]any) { c["iat"] = e.now().Unix() - 20 })
		})
	if !strings.HasPrefix(r, "OK ") {
		t.Fatalf("a device clock 20 s slow: %q", r)
	}

	wide := newTestEnv(t, func(c *Config) { c.ClockSkew = 20 * time.Second })
	dw := wide.newDevice()
	if r := ahead(wide, dw, 15); !strings.HasPrefix(r, "OK ") {
		t.Fatalf("a device clock 15 s fast inside a 20 s window: %q", r)
	}
	if r := ahead(wide, dw, 25); r != "ERR clock_skew" {
		t.Fatalf("a device clock 25 s fast outside a 20 s window: %q", r)
	}

	// the window cannot be opened beyond the policy's maximum
	cfg := DefaultConfig()
	cfg.NodeID, cfg.NodeHost, cfg.Keys, cfg.Control = testNodeID, testNodeHost, e.keys, e.cp
	cfg.CertSource = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, nil }
	cfg.ClockSkew = secs(policyData.Authorization.NodeSkewMaxS) + time.Second
	if _, err := NewServer(cfg); err == nil {
		t.Fatal("a skew window beyond the policy's maximum was accepted")
	}
}

func TestAuth_ControlPlaneRefusalsBecomeClosedWords(t *testing.T) {
	e := newTestEnv(t, func(c *Config) { c.AuthorizeTimeout = 400 * time.Millisecond })
	d := e.newDevice()
	label := label20()
	for name, tc := range map[string]struct {
		plan devicePlan
		want string
	}{
		"license ended":      {devicePlan{err: &ControlError{Status: 402, Code: "license_inactive"}}, "ERR license_inactive"},
		"device revoked":     {devicePlan{err: &ControlError{Status: 401, Code: "device_revoked"}}, "ERR device_revoked"},
		"unknown 4xx":        {devicePlan{err: &ControlError{Status: 404, Code: "not_enrolled"}}, "ERR auth"},
		"control plane 503":  {devicePlan{err: &ControlError{Status: 503, Code: "subscription_verification_unavailable"}}, "ERR control_unavailable"},
		"too many 429":       {devicePlan{err: &ControlError{Status: 429, Code: "busy"}}, "ERR control_unavailable"},
		"transport failure":  {devicePlan{err: fmt.Errorf("connection refused")}, "ERR control_unavailable"},
		"too slow":           {devicePlan{delay: 3 * time.Second, host: d.host, validFor: time.Hour}, "ERR control_unavailable"},
		"grant already over": {devicePlan{host: d.host, validFor: -5 * time.Second}, "ERR auth"},
		"answer for another device": {devicePlan{answer: func(int) AuthorizeResponse {
			return AuthorizeResponse{DeviceID: randomHex(16), Label: label, Host: label + "." + testZone, Status: "active", Plan: "paid", ValidUntil: e.now().Unix() + 600,
				ServerTime: e.now().Unix(), Policy: okPolicy{20, 45, 1800, 14400, 300}}
		}}, "ERR control_unavailable"},
		"answer with a host that is not a device host": {devicePlan{answer: func(int) AuthorizeResponse {
			return AuthorizeResponse{DeviceID: d.id, Label: "evil", Host: "evil.example.com", Status: "active", Plan: "paid", ValidUntil: e.now().Unix() + 600,
				ServerTime: e.now().Unix(), Policy: okPolicy{20, 45, 1800, 14400, 300}}
		}}, "ERR control_unavailable"},
	} {
		plan := tc.plan
		if plan.host == "" && plan.err == nil && plan.answer == nil {
			plan.host = d.host
		}
		e.cp.set(d.id, &plan)
		dc := e.connect(d)
		reply := dc.hello(func() string { return e.session(d, nil) }, func(s, n string) string { return e.proof(d, s, n, nil) })
		if reply != tc.want {
			t.Errorf("%s: %q, want %q", name, reply, tc.want)
		}
		dc.expectClosed(2 * time.Second)
		if e.srv.Online(d.host) {
			t.Fatalf("%s: the host is up", name)
		}
	}
	e.checkTranscript()
}

// ------------------------------------------------------------------------------------------------------------------------------------
// The lifetime: valid_until, RENEW, replacement
// ------------------------------------------------------------------------------------------------------------------------------------

func TestLifetime_WithoutRenewalTheConnectionClosesAtValidUntil(t *testing.T) {
	e := newTestEnv(t, nil)
	d := e.newDevice()
	e.plan(d).validFor = 2 * time.Second
	dc := e.connectOK(d)
	ds := dc.serve(nil)
	until := int64(dc.ok["body"].(map[string]any)["valid_until"].(float64))

	c, err := e.clientTLS(d)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := postOver(c, d.host, []byte("before")); err != nil || string(resp) != "echo:before" {
		t.Fatalf("%q %v", resp, err)
	}
	_ = c.Close()

	eventually(t, "CLOSE expired", 4*time.Second, func() bool { return containsLine(ds.otherLines(), "CLOSE expired") })
	if now := e.now().Unix(); now < until {
		t.Fatalf("closed at %d, before valid_until %d", now, until)
	}
	<-ds.done
	if e.srv.Online(d.host) {
		t.Fatal("the host is still up after valid_until")
	}
	if _, err := e.clientTLS(d); err == nil {
		t.Fatal("a client got through after valid_until")
	}
	e.checkTranscript()
}

func TestLifetime_RenewExtendsTheConnectionAndCallsAuthorizeAgain(t *testing.T) {
	e := newTestEnv(t, nil)
	d := e.newDevice()
	e.plan(d).validFor = 2 * time.Second
	dc := e.connectOK(d)
	firstUntil := int64(dc.ok["body"].(map[string]any)["valid_until"].(float64))

	// the control plane's answer for the renewal is longer, and the trial turned into the paywall: gated
	e.plan(d).validFor, e.plan(d).status, e.plan(d).plan = 5*time.Second, statusGated, "trial"
	reply := dc.renew()
	m, err := parseLine(reply, dirN2D)
	if err != nil || m.str("verb") != "OK" {
		t.Fatalf("RENEW answered %q", reply)
	}
	body := m["body"].(map[string]any)
	if int64(body["valid_until"].(float64)) <= firstUntil || body["status"] != "gated" {
		t.Fatalf("renewed body %v (first valid_until %d)", body, firstUntil)
	}
	// the renewal called authorize again, with its own session's jti and the reason renew
	if e.cp.callsFor(d.id, "hello") != 1 || e.cp.callsFor(d.id, "renew") != 1 {
		t.Fatalf("authorize calls: %+v", e.cp.callLog())
	}
	if last := e.cp.callLog()[1]; last.SessionJTI != jtiOf(t, dc.session) || last.Reason != "renew" {
		t.Fatalf("the renew call %+v", last)
	}

	// past the FIRST valid_until the connection is still there and serves (gated still opens streams)
	ds := dc.serve(nil)
	time.Sleep(time.Until(time.Unix(firstUntil, 0)) + 500*time.Millisecond)
	if !e.srv.Online(d.host) {
		t.Fatal("the renewed connection ended at the old valid_until")
	}
	c, err := e.clientTLS(d)
	if err != nil {
		t.Fatalf("a client after the old valid_until: %v", err)
	}
	if resp, err := postOver(c, d.host, []byte("renewed")); err != nil || string(resp) != "echo:renewed" {
		t.Fatalf("%q %v", resp, err)
	}
	_ = c.Close()
	// and without a second renewal it ends at the NEW valid_until
	eventually(t, "CLOSE expired after the renewal", 8*time.Second, func() bool { return containsLine(ds.otherLines(), "CLOSE expired") })
	if now := e.now().Unix(); now < int64(body["valid_until"].(float64)) {
		t.Fatalf("closed at %d, before the renewed valid_until %v", now, body["valid_until"])
	}
	e.checkTranscript()
}

func TestLifetime_ARefusedRenewKeepsTheConnectionAndItsOldValidUntil(t *testing.T) {
	e := newTestEnv(t, nil)
	d := e.newDevice()
	other := e.newDevice()
	e.plan(d).validFor = 3 * time.Second
	dc := e.connectOK(d)
	ds := dc.serve(nil)
	_ = ds

	// the control plane refuses the renewal
	e.plan(d).err = &ControlError{Status: 402, Code: "license_inactive"}
	if r := dc.renew(); r != "ERR license_inactive" {
		t.Fatalf("refused RENEW answered %q", r)
	}
	e.plan(d).err = nil
	// a RENEW with the session of another device
	dc.send("RENEW " + e.session(other, nil))
	if r := dc.recv(); r != "ERR auth" {
		t.Fatalf("RENEW of another subject: %q", r)
	}
	// a RENEW whose proof is bad
	dc.send("RENEW " + e.session(d, nil))
	if line := dc.recv(); !strings.HasPrefix(line, "CHALLENGE ") {
		t.Fatalf("%q", line)
	}
	dc.send("PROOF AAAA.BBBB.CCCC")
	if r := dc.recv(); !strings.HasPrefix(r, "ERR ") {
		t.Fatalf("%q", r)
	}
	// a session that is expired
	dc.send("RENEW " + e.session(d, func(h, c map[string]any) { c["iat"], c["exp"] = e.now().Unix()-400, e.now().Unix()-100 }))
	if r := dc.recv(); r != "ERR auth" {
		t.Fatalf("%q", r)
	}
	// the connection is alive and answers PING: nothing above extended or ended it
	dc.send("PING")
	deadline := time.Now().Add(2 * time.Second)
	for !containsLine(ds.otherLines(), "PONG") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !e.srv.Online(d.host) {
		t.Fatal("a refused RENEW ended the connection")
	}
	eventually(t, "CLOSE expired at the OLD valid_until", 5*time.Second, func() bool { return containsLine(ds.otherLines(), "CLOSE expired") })
	e.checkTranscript()
}

func TestLifetime_ARenewThatNeverGetsItsProofIsDroppedNotTheConnection(t *testing.T) {
	e := newTestEnv(t, func(c *Config) { c.FirstLineTimeout = 400 * time.Millisecond })
	d := e.newDevice()
	dc := e.connectOK(d)
	dc.send("RENEW " + e.session(d, nil))
	if line := dc.recv(); !strings.HasPrefix(line, "CHALLENGE ") {
		t.Fatalf("%q", line)
	}
	time.Sleep(900 * time.Millisecond)
	// the abandoned exchange's PROOF finds no nonce; a fresh RENEW works
	dc.send("PING")
	if line := dc.recv(); line != "PONG" {
		t.Fatalf("%q", line)
	}
	if r := dc.renew(); !strings.HasPrefix(r, "OK ") {
		t.Fatalf("a new RENEW after the abandoned one: %q", r)
	}
}

func TestLifetime_ASecondHelloOfTheSameSubjectReplacesTheFirst(t *testing.T) {
	e := newTestEnv(t, nil)
	d := e.newDevice()
	first := e.connectOK(d)
	dsFirst := first.serve(nil)

	// a stream that is open on the first connection when it is replaced keeps running
	c, err := e.clientTLS(d)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := postOver(c, d.host, []byte("one")); err != nil || string(resp) != "echo:one" {
		t.Fatalf("%q %v", resp, err)
	}
	if dsFirst.openCount() != 1 {
		t.Fatalf("first opens %d", dsFirst.openCount())
	}

	second := e.connectOK(d)
	dsSecond := second.serve(nil)
	eventually(t, "CLOSE replaced on the first connection", 3*time.Second, func() bool { return containsLine(dsFirst.otherLines(), "CLOSE replaced") })
	<-dsFirst.done

	if resp, err := postOver(c, d.host, []byte("two")); err != nil || string(resp) != "echo:two" {
		t.Fatalf("the open stream after the replacement: %q %v", resp, err)
	}
	_ = c.Close()
	c2, err := e.clientTLS(d)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := postOver(c2, d.host, []byte("three")); err != nil || string(resp) != "echo:three" {
		t.Fatalf("%q %v", resp, err)
	}
	_ = c2.Close()
	if dsSecond.openCount() != 1 || dsFirst.openCount() != 1 {
		t.Fatalf("opens: first %d second %d", dsFirst.openCount(), dsSecond.openCount())
	}
	e.checkTranscript()
}

func TestLifetime_ManyConcurrentHellosOfOneSubjectLeaveExactlyOneConnection(t *testing.T) {
	e := newTestEnv(t, nil)
	d := e.newDevice()
	const n = 24
	var wg sync.WaitGroup
	conns := make([]*devConn, n)
	var failures atomic.Int32
	for i := 0; i < n; i++ {
		c, err := e.dialNode()
		if err != nil {
			t.Fatal(err)
		}
		conns[i] = &devConn{t: t, e: e, d: d, c: c, br: bufio.NewReader(c)}
		t.Cleanup(func() { _ = c.Close() })
	}
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(dc *devConn) {
			defer wg.Done()
			dc.session = e.session(d, nil)
			fmt.Fprintf(dc.c, "HELLO 2 %s\n", dc.session)
			line, err := dc.br.ReadString('\n')
			if err != nil || !strings.HasPrefix(line, "CHALLENGE ") {
				t.Logf("challenge: %q %v", line, err)
				failures.Add(1)
				return
			}
			fmt.Fprintf(dc.c, "PROOF %s\n", e.proof(d, dc.session, strings.TrimSpace(strings.TrimPrefix(line, "CHALLENGE ")), nil))
			if line, err = dc.br.ReadString('\n'); err != nil || !strings.HasPrefix(line, "OK ") {
				t.Logf("ok: %q %v", line, err)
				failures.Add(1)
			}
		}(conns[i])
	}
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatalf("%d handshakes failed", failures.Load())
	}
	// exactly one connection is left open; every other one was told it was replaced
	open := 0
	for _, dc := range conns {
		_ = dc.c.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		line, err := dc.br.ReadString('\n')
		if err == nil && line == "CLOSE replaced\n" {
			continue
		}
		open++
	}
	if open != 1 {
		t.Fatalf("%d connections left open", open)
	}
	if !e.srv.Online(d.host) {
		t.Fatal("the host is not served by the survivor")
	}
	e.srv.routes.mu.Lock()
	if len(e.srv.routes.bySub) != 1 || len(e.srv.routes.byHost) != 1 {
		t.Errorf("the table holds %d subjects and %d hosts", len(e.srv.routes.bySub), len(e.srv.routes.byHost))
	}
	e.srv.routes.mu.Unlock()
	e.checkTranscript()
}

func TestLifetime_APausedDeviceKeepsItsConnectionButOpensNothing(t *testing.T) {
	e := newTestEnv(t, nil)
	d := e.newDevice()
	e.plan(d).status = statusPaused
	dc := e.connectOK(d)
	ds := dc.serve(nil)
	if dc.ok["body"].(map[string]any)["status"] != "paused" {
		t.Fatalf("%v", dc.ok)
	}
	if _, err := e.clientTLS(d); err == nil {
		t.Fatal("a client got a stream of a paused device")
	}
	time.Sleep(100 * time.Millisecond)
	if ds.openCount() != 0 {
		t.Fatal("a paused device was asked to open a stream")
	}
	// resumed: the renewal says active and streams flow again, on the same connection
	e.plan(d).status = statusActive
	r := dc.renew()
	if !strings.HasPrefix(r, "OK ") {
		t.Fatalf("%q", r)
	}
	c, err := e.clientTLS(d)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	e.checkTranscript()
}

func TestLifetime_ADeadPeerIsDroppedAndAPingKeepsItAlive(t *testing.T) {
	e := newTestEnv(t, func(c *Config) { c.DeadPeer = 600 * time.Millisecond })
	d := e.newDevice()
	dc := e.connectOK(d)
	for i := 0; i < 4; i++ {
		time.Sleep(250 * time.Millisecond)
		dc.send("PING")
		if line := dc.recv(); line != "PONG" {
			t.Fatalf("%q", line)
		}
	}
	if !e.srv.Online(d.host) {
		t.Fatal("a pinging device was dropped")
	}
	lines := dc.expectClosed(3 * time.Second)
	if !containsLine(lines, "CLOSE idle") {
		t.Fatalf("lines before the close: %q", lines)
	}
	eventually(t, "host unbound", time.Second, func() bool { return !e.srv.Online(d.host) })
}

// ------------------------------------------------------------------------------------------------------------------------------------
// ATTACH
// ------------------------------------------------------------------------------------------------------------------------------------

// openOne makes a client arrive and returns its OPEN line, parsed; the client's goroutine ends when done is closed or the handshake gives up.
func openOne(t *testing.T, e *testEnv, d *testDevice, dc *devConn) (message, chan<- struct{}) {
	t.Helper()
	stop := make(chan struct{})
	go func() {
		c, err := e.clientTLS(d)
		if err == nil {
			<-stop
			_ = c.Close()
		}
	}()
	line := dc.recv()
	m, err := parseLine(line, dirN2D)
	if err != nil || m.str("verb") != "OPEN" {
		t.Fatalf("expected an OPEN, got %q", line)
	}
	return m, stop
}

func attachLine(id, secret string) string { return "ATTACH " + id + " " + secret }

func TestAttach_AWrongOrReusedSecretFailsAndTheRightOneWorksOnce(t *testing.T) {
	e := newTestEnv(t, nil)
	d := e.newDevice()
	dc := e.connectOK(d)
	open, stop := openOne(t, e, d, dc)
	defer close(stop)
	id, secret := open.str("stream_id"), open.str("secret")

	rawAttach := func(line string) (reply string, closed bool) {
		c, err := e.dialNode()
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		fmt.Fprintf(c, "%s\n", line)
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		br := bufio.NewReader(c)
		b, _ := br.ReadString('\n')
		_, err = br.ReadByte() // the node closes after an ERR
		return strings.TrimSpace(b), err != nil
	}
	wrong := secret[:len(secret)-1] + map[bool]string{true: "B", false: "A"}[secret[len(secret)-1] == 'A']
	if r, closed := rawAttach(attachLine(id, wrong)); r != "ERR auth" || !closed {
		t.Fatalf("wrong secret: %q closed=%v", r, closed)
	}
	if r, _ := rawAttach(attachLine(id, strings.Repeat("A", 43))); r != "ERR auth" {
		t.Fatalf("zero secret: %q", r)
	}
	// a wrong secret does not consume the stream: the right one still works
	c, err := e.dialNode()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "%s\n", attachLine(id, secret))
	// success has no reply: the next byte is the client's ClientHello (a TLS handshake record)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	first := make([]byte, 1)
	if _, err := io.ReadFull(c, first); err != nil || first[0] != 0x16 {
		t.Fatalf("after a good ATTACH the stream's first byte is % x, err %v", first, err)
	}
	// used: the same id and secret again is an unknown stream
	if r, closed := rawAttach(attachLine(id, secret)); r != "ERR unknown_stream" || !closed {
		t.Fatalf("reused secret: %q", r)
	}
	if r, _ := rawAttach(attachLine(randomHex(16), secret)); r != "ERR unknown_stream" {
		t.Fatalf("unknown id: %q", r)
	}
	for _, bad := range []string{"ATTACH", "ATTACH " + id, "ATTACH " + strings.ToUpper(id) + " " + secret, "ATTACH " + id + " short", "ATTACH " + id + " " + secret + " extra"} {
		if r, _ := rawAttach(bad); r != "ERR bad_attach" && r != "ERR bad_command" {
			t.Errorf("%q answered %q", bad, r)
		}
	}
	e.checkTranscript()
}

func TestAttach_AfterTheTimeoutTheStreamIsGone(t *testing.T) {
	e := newTestEnv(t, func(c *Config) { c.AttachTimeout = 300 * time.Millisecond })
	d := e.newDevice()
	dc := e.connectOK(d)
	open, stop := openOne(t, e, d, dc)
	defer close(stop)
	time.Sleep(700 * time.Millisecond)
	c, err := e.dialNode()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "%s\n", attachLine(open.str("stream_id"), open.str("secret")))
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if b, _ := bufio.NewReader(c).ReadString('\n'); strings.TrimSpace(b) != "ERR unknown_stream" {
		t.Fatalf("attach after the timeout: %q", b)
	}
	e.waitIdle()
	// (no transcript check here: the checker judges a late ATTACH by the policy's attach window, this node runs a shorter one)
}

func TestAttach_EveryStreamGetsItsOwnIdAndSecret(t *testing.T) {
	e := newTestEnv(t, nil)
	d := e.newDevice()
	dc := e.connectOK(d)
	ds := dc.serve(func(c net.Conn) { time.Sleep(50 * time.Millisecond) })
	for i := 0; i < 40; i++ {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", e.httpsAddr, &tls.Config{ServerName: d.host, InsecureSkipVerify: true})
		if c != nil {
			_ = c.Close()
		}
		_ = err
	}
	eventually(t, "40 opens", 5*time.Second, func() bool { return ds.openCount() >= 40 })
	ids, secrets := map[string]bool{}, map[string]bool{}
	for _, m := range ds.openList() {
		ids[m.str("stream_id")], secrets[m.str("secret")] = true, true
		if !reStreamID.MatchString(m.str("stream_id")) || !reSecret.MatchString(m.str("secret")) {
			t.Fatalf("OPEN %v", m)
		}
	}
	if len(ids) != 40 || len(secrets) != 40 {
		t.Fatalf("%d distinct ids, %d distinct secrets for 40 streams", len(ids), len(secrets))
	}
}

// ------------------------------------------------------------------------------------------------------------------------------------
// OPEN only after a complete, well-formed ClientHello
// ------------------------------------------------------------------------------------------------------------------------------------

// helloOf builds a ClientHello for host with a padding extension of pad bytes, as records of at most recordSize payload bytes.
func helloOf(host string, pad, recordSize int) []byte {
	ext := sniExt(host)
	if pad > 0 {
		ext = append(append([]byte{0, 21, byte(pad >> 8), byte(pad)}, make([]byte, pad)...), ext...)
	}
	var body []byte
	body = append(body, 3, 3)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	body = append(body, 0, 2, 0x13, 0x01)
	body = append(body, 1, 0)
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	hs := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	var out []byte
	for len(hs) > 0 {
		k := min(recordSize, len(hs))
		out = append(out, 22, 3, 1, byte(k>>8), byte(k))
		out = append(out, hs[:k]...)
		hs = hs[k:]
	}
	return out
}

// sendRaw opens a connection, writes b in pieces of size (0 = at once) and returns it.
func sendRaw(t *testing.T, e *testEnv, b []byte, size int) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", e.httpsAddr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	var w net.Conn = c
	if size > 0 {
		w = chunkConn{Conn: c, size: size, delay: time.Millisecond}
	}
	_, _ = w.Write(b)
	return c
}

func TestClientHello_NothingThatIsNotACompleteWellFormedHelloProducesAnOpen(t *testing.T) {
	e := newTestEnv(t, func(c *Config) { c.HelloTimeout = 400 * time.Millisecond })
	d := e.newDevice()
	dc := e.connectOK(d)
	ds := dc.serve(nil)
	ds.noAttach = true
	full := helloOf(d.host, 0, 16000)

	t.Run("truncated at every interesting length", func(t *testing.T) {
		for _, n := range []int{1, 2, 3, 4, 5, 6, 9, 20, 43, 44, len(full) / 2, len(full) - 1} {
			c := sendRaw(t, e, full[:n], 0)
			_ = c.Close() // the client goes away mid-hello
		}
	})
	t.Run("stalls half way", func(t *testing.T) {
		c := sendRaw(t, e, full[:len(full)/2], 0)
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		start := time.Now()
		if n, err := c.Read(make([]byte, 1)); n != 0 || err == nil {
			t.Fatalf("n=%d err=%v", n, err)
		}
		if time.Since(start) > 2*time.Second {
			t.Fatal("the hello deadline is not enforced")
		}
	})
	t.Run("a hello whose record length lies", func(t *testing.T) {
		lie := append([]byte(nil), full...)
		lie[3], lie[4] = 0xff, 0xff
		sendRaw(t, e, lie, 0)
	})
	t.Run("a handshake that is not a ClientHello", func(t *testing.T) {
		notHello := append([]byte(nil), full...)
		notHello[5] = 2
		sendRaw(t, e, notHello, 0)
	})
	t.Run("not TLS at all", func(t *testing.T) {
		sendRaw(t, e, []byte("GET / HTTP/1.1\r\nHost: "+d.host+"\r\n\r\n"), 0)
	})
	t.Run("no SNI", func(t *testing.T) {
		sendRaw(t, e, realHello(t, ""), 0)
	})
	t.Run("an address as the name", func(t *testing.T) {
		sendRaw(t, e, buildHello(sniExt("192.0.2.3"), true), 0)
	})
	t.Run("another host", func(t *testing.T) {
		sendRaw(t, e, helloOf(label20()+"."+testZone, 0, 16000), 0)
	})
	t.Run("a name with an underscore, a double dot, a space", func(t *testing.T) {
		for _, name := range []string{"a_b." + testZone, "a..b." + testZone, "a b." + testZone, d.label + "." + testZone + ".."} {
			sendRaw(t, e, helloOf(name, 0, 16000), 0)
		}
	})
	time.Sleep(900 * time.Millisecond)
	if n := ds.openCount(); n != 0 {
		t.Fatalf("%d OPEN lines for hellos that were not complete and well formed", n)
	}
	// teeth: the same bytes, whole, do produce one
	sendRaw(t, e, full, 0)
	eventually(t, "the OPEN of the complete hello", 3*time.Second, func() bool { return ds.openCount() == 1 })
	e.checkTranscript()
}

func TestClientHello_FragmentedHugeCasedAndDottedHellosAreServed(t *testing.T) {
	e := newTestEnv(t, nil)
	d := e.newDevice()
	dc := e.connectOK(d)
	ds := dc.serve(nil)
	ds.noAttach = true

	variants := map[string][]byte{
		"split in 100 byte records":              helloOf(d.host, 0, 100),
		"in 7 byte records":                      helloOf(d.host, 0, 7),
		"64 KB":                                  helloOf(d.host, 65000, 16384),
		"upper case":                             helloOf(strings.ToUpper(d.host), 0, 16000),
		"mixed case":                             helloOf(strings.ToUpper(d.label[:5])+d.label[5:]+"."+strings.ToUpper(testZone[:3])+testZone[3:], 0, 16000),
		"trailing dot":                           helloOf(d.host+".", 0, 16000),
		"a real client's hello":                  realHello(t, d.host),
		"a client hello offering X25519MLKEM768": captureClientHello(t, &tls.Config{ServerName: d.host, InsecureSkipVerify: true, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519}}),
	}
	want := 0
	for name, hello := range variants {
		_ = name
		want++
		sendRaw(t, e, hello, 0)
	}
	eventually(t, "an OPEN per variant", 5*time.Second, func() bool { return ds.openCount() == want })
	// arriving one byte at a time (over a pipe so the pieces really are separate reads)
	sendRaw(t, e, helloOf(d.host, 0, 16000), 1)
	eventually(t, "the byte-by-byte hello", 10*time.Second, func() bool { return ds.openCount() == want+1 })
	e.checkTranscript()
}

func TestClientHello_ThePeerAddressAndTheClassTravelInTheOpen(t *testing.T) {
	cases := map[string]struct {
		classify func(netip.Addr, string) string
		want     string
	}{
		"no classifier":       {nil, "anon"},
		"openai":              {func(netip.Addr, string) string { return "openai" }, "openai"},
		"hint":                {func(netip.Addr, string) string { return "hint" }, "hint"},
		"a class that is not": {func(netip.Addr, string) string { return "vip" }, "anon"},
	}
	for name, tc := range cases {
		var seenPeer atomic.Value
		e := newTestEnv(t, func(c *Config) {
			if tc.classify != nil {
				c.Classify = func(peer netip.Addr, host string) string {
					seenPeer.Store(peer.String() + " " + host)
					return tc.classify(peer, host)
				}
			}
		})
		d := e.newDevice()
		dc := e.connectOK(d)
		ds := dc.serve(nil)
		ds.noAttach = true
		sendRaw(t, e, helloOf(d.host, 0, 16000), 0)
		eventually(t, name+": the OPEN", 3*time.Second, func() bool { return ds.openCount() == 1 })
		open := ds.openList()[0]
		if open.str("peer_ip") != "127.0.0.1" || open.str("class") != tc.want {
			t.Errorf("%s: OPEN %v", name, open)
		}
		if tc.classify != nil && seenPeer.Load() != "127.0.0.1 "+d.host {
			t.Errorf("%s: the classifier was asked about %v", name, seenPeer.Load())
		}
		e.checkTranscript()
	}
}

// ------------------------------------------------------------------------------------------------------------------------------------
// Port 80 and the listeners
// ------------------------------------------------------------------------------------------------------------------------------------

func acmeGet(t *testing.T, e *testEnv, method, path, host string) string {
	t.Helper()
	return rawExchange(t, e.httpAddr, method+" "+path+" HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n")
}

func TestPort80_ServesOnlyTheNodesOwnACMEWebroot(t *testing.T) {
	webroot := t.TempDir()
	dir := filepath.Join(webroot, ".well-known", "acme-challenge")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(dir, "tok_OK-1"), []byte("tok_OK-1.thumbprint"), 0o644))
	must(os.WriteFile(filepath.Join(dir, "huge"), bytes.Repeat([]byte("x"), 9000), 0o644))
	outside := filepath.Join(t.TempDir(), "secret")
	must(os.WriteFile(outside, []byte("not for the internet"), 0o644))
	must(os.Symlink(outside, filepath.Join(dir, "linked")))
	must(os.WriteFile(filepath.Join(webroot, "private.txt"), []byte("private"), 0o644))

	e := newTestEnv(t, func(c *Config) { c.ACMEWebroot = webroot })
	d := e.newDevice()
	dc := e.connectOK(d)
	ds := dc.serve(nil)
	ds.noAttach = true

	if out := acmeGet(t, e, "GET", "/.well-known/acme-challenge/tok_OK-1", testNodeHost); !strings.HasPrefix(out, "HTTP/1.1 200 OK") || !strings.HasSuffix(out, "tok_OK-1.thumbprint") {
		t.Fatalf("the node's own challenge: %q", out)
	}
	if out := acmeGet(t, e, "GET", "/.well-known/acme-challenge/tok_OK-1", strings.ToUpper(testNodeHost)+":80"); !strings.HasPrefix(out, "HTTP/1.1 200 OK") {
		t.Fatalf("the node's own name, upper case with a port: %q", out)
	}
	if out := acmeGet(t, e, "HEAD", "/.well-known/acme-challenge/tok_OK-1", testNodeHost); !strings.HasPrefix(out, "HTTP/1.1 200 OK") || strings.Contains(out, "thumbprint") {
		t.Fatalf("HEAD: %q", out)
	}
	for name, req := range map[string][2]string{
		"a device's host":          {"/.well-known/acme-challenge/tok_OK-1", d.host},
		"another host":             {"/.well-known/acme-challenge/tok_OK-1", "example.com"},
		"no such token":            {"/.well-known/acme-challenge/nope", testNodeHost},
		"the webroot itself":       {"/", testNodeHost},
		"a file outside the path":  {"/private.txt", testNodeHost},
		"traversal":                {"/.well-known/acme-challenge/../../private.txt", testNodeHost},
		"encoded traversal":        {"/.well-known/acme-challenge/%2e%2e/private.txt", testNodeHost},
		"a query":                  {"/.well-known/acme-challenge/tok_OK-1?x=1", testNodeHost},
		"a file that is too large": {"/.well-known/acme-challenge/huge", testNodeHost},
		"a symlink":                {"/.well-known/acme-challenge/linked", testNodeHost},
		"a metrics path":           {"/metrics", testNodeHost},
		"healthz":                  {"/healthz", testNodeHost},
	} {
		if out := acmeGet(t, e, "GET", req[0], req[1]); !strings.HasPrefix(out, "HTTP/1.1 404 ") || strings.Contains(out, "thumbprint") || strings.Contains(out, "private") || strings.Contains(out, "internet") {
			t.Errorf("%s: %q", name, out)
		}
	}
	if out := acmeGet(t, e, "POST", "/.well-known/acme-challenge/tok_OK-1", testNodeHost); !strings.HasPrefix(out, "HTTP/1.1 404 ") {
		t.Errorf("POST: %q", out)
	}
	if out := rawExchange(t, e.httpAddr, "GET /.well-known/acme-challenge/tok_OK-1 HTTP/1.0\r\n\r\n"); out != "" && !strings.HasPrefix(out, "HTTP/1.1 404 ") {
		t.Errorf("no Host: %q", out)
	}
	time.Sleep(100 * time.Millisecond)
	if ds.openCount() != 0 {
		t.Fatal("port 80 asked a device to open a stream: it must never reach one")
	}
}

func TestPort80_WithoutAWebrootEverythingIs404(t *testing.T) {
	e := newTestEnv(t, nil)
	if out := acmeGet(t, e, "GET", "/.well-known/acme-challenge/anything", testNodeHost); !strings.HasPrefix(out, "HTTP/1.1 404 ") {
		t.Fatalf("%q", out)
	}
}

func TestListeners_ThereIsNoPort8443AndNoSelfSignedPin(t *testing.T) {
	e := newTestEnv(t, nil)
	if e.srv.httpsLn == nil || e.srv.httpLn == nil {
		t.Fatal("the two listeners are not up")
	}
	// the node holds exactly two listeners (the field set of the server says it: no control listener exists)
	typ := reflect.TypeOf(e.srv).Elem()
	for i := 0; i < typ.NumField(); i++ {
		if name := typ.Field(i).Name; strings.Contains(strings.ToLower(name), "ctrlln") || strings.Contains(strings.ToLower(name), "controlln") {
			t.Fatalf("the server has a control listener field %s", name)
		}
	}
	cfgType := reflect.TypeOf(Config{})
	for i := 0; i < cfgType.NumField(); i++ {
		if name := cfgType.Field(i).Name; strings.Contains(name, "ControlAddr") || strings.Contains(name, "StateDir") || strings.Contains(name, "Devices") {
			t.Fatalf("Config still has %s", name)
		}
	}
	// nothing in the sources speaks of :8443, a device token or a pinned fingerprint any more
	files, _ := filepath.Glob("*.go")
	forbidden := regexp.MustCompile(`8443|ControlAddr|control_cert_sha256|server\.fingerprint|loadOrCreateServerCert|checkToken`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(f)
		if loc := forbidden.FindIndex(b); loc != nil {
			t.Errorf("%s still mentions %q", f, b[loc[0]:loc[1]])
		}
	}
}

// ------------------------------------------------------------------------------------------------------------------------------------
// The device's connection to the node's own name
// ------------------------------------------------------------------------------------------------------------------------------------

func TestOwnName_OnlyAllTunnel2OverTLS13AndOnlyHelloOrAttach(t *testing.T) {
	e := newTestEnv(t, nil)

	reply := func(line string) string {
		c, err := e.dialNode()
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_, _ = io.WriteString(c, line+"\n")
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		b, _ := bufio.NewReader(c).ReadString('\n')
		return strings.TrimSpace(b)
	}
	for line, want := range map[string]string{
		"hello 2 AAAA.BBBB.CCCC":       "ERR bad_command",
		"PING":                         "ERR bad_command",
		"PROOF not-a-token":            "ERR bad_command", // a malformed PROOF/RENEW as the FIRST line is not HELLO or ATTACH (contract section 2)
		"PROOF AAAA.BBBB.CCCC":         "ERR bad_command",
		"PROOF":                        "ERR bad_command",
		"RENEW not-a-token":            "ERR bad_command",
		"RENEW AAAA.BBBB.CCCC":         "ERR bad_command",
		"OPEN " + randomHex(16):        "ERR bad_command",
		"HELLO 3 AAAA.BBBB.CCCC":       "ERR unsupported_version",
		"HELLO 1 AAAA.BBBB.CCCC":       "ERR unsupported_version",
		"HELLO two AAAA.BBBB.CCCC":     "ERR bad_command",
		"HELLO 2":                      "ERR bad_command",
		"HELLO 2 not-a-token":          "ERR bad_hello",
		"HELLO 2 AAAA.BBBB.CCCC extra": "ERR bad_command",
		"HELLO  2 AAAA.BBBB.CCCC":      "ERR bad_command",
		"HELLO 2 AAAA.BBBB.CCCC\r":     "ERR bad_command",
		"GET / HTTP/1.1":               "ERR bad_command",
		"ATTACH":                       "ERR bad_command",
		"ATTACH short short":           "ERR bad_attach",
		strings.Repeat("A", 9000):      "ERR line_too_long",
		"HELLO 2 " + strings.Repeat("A", 5000) + ".B.C": "ERR bad_hello",
	} {
		if got := reply(line); got != want {
			t.Errorf("%.40q: %q, want %q", line, got, want)
		}
	}

	dial := func(cfg *tls.Config) error {
		cfg.ServerName, cfg.RootCAs = testNodeHost, e.nodePool
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", e.httpsAddr, cfg)
		if err == nil {
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err = c.Read(make([]byte, 1)) // the node closes: it does not talk to a client that did not offer the protocol
			_ = c.Close()
		}
		return err
	}
	if err := dial(&tls.Config{NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS13}); err == nil {
		t.Error("a client offering only h2 got a session")
	}
	if err := dial(&tls.Config{NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS13}); err == nil {
		t.Error("a client offering only http/1.1 stayed")
	}
	if err := dial(&tls.Config{MinVersion: tls.VersionTLS13}); err == nil {
		t.Error("a client offering no ALPN stayed")
	}
	if err := dial(&tls.Config{NextProtos: []string{policyData.Protocol.ALPN}, MaxVersion: tls.VersionTLS12}); err == nil {
		t.Error("a TLS 1.2 client got a session")
	}
	// ... and the one that speaks the protocol is not hurt by the refusals
	d := e.newDevice()
	_ = e.connectOK(d)
}

func TestOwnName_UnauthenticatedConnectionsAreCapped(t *testing.T) {
	e := newTestEnv(t, func(c *Config) {
		c.MaxUnauth = 4
		c.FirstLineTimeout = 700 * time.Millisecond
		c.HelloTimeout = 700 * time.Millisecond
	})
	var held []net.Conn
	for i := 0; i < 4; i++ {
		c, err := net.Dial("tcp", e.httpsAddr)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
		defer c.Close()
	}
	time.Sleep(150 * time.Millisecond)
	// the fifth is turned away without a byte
	c, err := net.Dial("tcp", e.httpsAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := c.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("n=%d err=%v", n, err)
	}
	// once the held ones time out, the node serves again
	time.Sleep(900 * time.Millisecond)
	d := e.newDevice()
	_ = e.connectOK(d)
	_ = held
}

// A control plane that is slow to answer must not starve what the node does without it: a device that proved itself is no longer an
// unauthenticated connection, so the clients (and the ATTACHes) of devices that are already connected go on.
func TestOwnName_SlowAuthorizeDoesNotStarveClientsOfConnectedDevices(t *testing.T) {
	e := newTestEnv(t, func(c *Config) { c.MaxUnauth = 4 })
	d := e.newDevice()
	dc := e.connectOK(d)
	_ = dc.serve(nil)

	var pending []<-chan string
	for i := 0; i < 4; i++ {
		slow := e.newDevice()
		e.plan(slow).delay = 2 * time.Second
		pending = append(pending, e.helloAsync(slow))
	}
	eventually(t, "the slow authorize calls are in flight", 3*time.Second, func() bool { return len(e.cp.callLog()) >= 5 })

	// a client of the connected device is served at once (its stream's ATTACH goes through the same gate)
	c, err := e.clientTLS(d)
	if err != nil {
		t.Fatalf("a client of a connected device was turned away while authorize was slow: %v", err)
	}
	defer c.Close()
	if resp, err := postOver(c, d.host, []byte("hello")); err != nil || !bytes.Contains(resp, []byte("hello")) {
		t.Fatalf("resp=%q err=%v", resp, err)
	}
	for _, p := range pending {
		if got := <-p; !strings.HasPrefix(got, "OK ") {
			t.Fatalf("a slow device ended with %q", got)
		}
	}
	e.checkTranscript()
}

// At most AuthorizeMax calls to the control plane run at once; the ones that wait for a turn are bounded too, and beyond that the device is told
// control_unavailable.
func TestAuthorize_ConcurrencyAndTheWaitingAreBounded(t *testing.T) {
	e := newTestEnv(t, func(c *Config) { c.AuthorizeMax = 2 })
	var pending []<-chan string
	for i := 0; i < 6; i++ {
		d := e.newDevice()
		e.plan(d).delay = 300 * time.Millisecond
		pending = append(pending, e.helloAsync(d))
	}
	for _, p := range pending {
		if got := <-p; !strings.HasPrefix(got, "OK ") {
			t.Fatalf("%q", got)
		}
	}
	e.cp.mu.Lock()
	most := e.cp.maxInflight
	e.cp.mu.Unlock()
	if most != 2 {
		t.Fatalf("%d authorize calls at once, want exactly the limit of 2", most)
	}

	full := newTestEnv(t, func(c *Config) { c.AuthorizeMax, c.MaxUnauth = 1, 2 })
	pending = nil
	for i := 0; i < 3; i++ {
		d := full.newDevice()
		full.plan(d).delay = time.Second
		pending = append(pending, full.helloAsync(d))
	}
	ok, refused := 0, 0
	for _, p := range pending {
		switch got := <-p; {
		case strings.HasPrefix(got, "OK "):
			ok++
		case got == "ERR control_unavailable":
			refused++
		default:
			t.Fatalf("%q", got)
		}
	}
	if ok != 2 || refused != 1 {
		t.Fatalf("%d OK and %d refused, want 2 and 1", ok, refused)
	}
}

// What the node records of two connections of one subject is in the order it routed them: the OK is recorded under the routing table's lock.
func TestRoutes_ActivationIsRecordedUnderTheTableLock(t *testing.T) {
	rt := newRouteTable()
	a := &ctrl{}
	underLock := false
	if _, err := rt.activate(a, "sub", "h.example", func() {
		if rt.mu.TryLock() {
			rt.mu.Unlock()
			return
		}
		underLock = true
	}); err != nil || !underLock {
		t.Fatalf("err=%v, recorded under the lock: %v", err, underLock)
	}
	if _, err := rt.activate(&ctrl{}, "other", "h.example", func() { t.Error("recorded a refused activation") }); err != errHostTaken {
		t.Fatalf("err=%v", err)
	}
}

func TestHint_AddressesReachTheHookAndABadHintClosesTheConnection(t *testing.T) {
	type hint struct {
		host  string
		addrs []netip.Addr
	}
	got := make(chan hint, 4)
	e := newTestEnv(t, func(c *Config) { c.OnHint = func(host string, addrs []netip.Addr) { got <- hint{host, addrs} } })
	d := e.newDevice()
	dc := e.connectOK(d)
	dc.send("HINT 203.0.113.9 2001:db8::7")
	select {
	case h := <-got:
		if h.host != d.host || len(h.addrs) != 2 || h.addrs[0].String() != "203.0.113.9" || h.addrs[1].String() != "2001:db8::7" {
			t.Fatalf("%+v", h)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no hint")
	}
	dc.send("HINT 203.0.113.9 not-an-ip")
	if r := dc.recv(); r != "ERR bad_command" {
		t.Fatalf("%q", r)
	}
	dc.expectClosed(2 * time.Second)
	e.checkTranscript()
}

// ------------------------------------------------------------------------------------------------------------------------------------
// helpers shared by the splice tests
// ------------------------------------------------------------------------------------------------------------------------------------

func fingerprintOf(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func TestLifetime_ARenewFloodIsBusyNotAStreamOfAuthorizeCalls(t *testing.T) {
	e := newTestEnv(t, func(c *Config) { c.MinRenewGap = 700 * time.Millisecond })
	d := e.newDevice()
	dc := e.connectOK(d)
	if r := dc.renew(); !strings.HasPrefix(r, "OK ") {
		t.Fatalf("first renew: %q", r)
	}
	for i := 0; i < 5; i++ {
		dc.send("RENEW " + e.session(d, nil))
		if r := dc.recv(); r != "ERR busy" {
			t.Fatalf("a renew right after another: %q", r)
		}
	}
	if n := e.cp.callsFor(d.id, "renew"); n != 1 {
		t.Fatalf("the flood reached the control plane %d times", n)
	}
	time.Sleep(800 * time.Millisecond)
	if r := dc.renew(); !strings.HasPrefix(r, "OK ") {
		t.Fatalf("a renew after the gap: %q", r)
	}
	if !e.srv.Online(d.host) {
		t.Fatal("the connection did not survive the flood")
	}
}

func TestClientHello_ADualStackListenerSeesAnIPv4ClientAsIPv4(t *testing.T) {
	e := newTestEnv(t, func(c *Config) { c.HTTPSAddr = "[::]:0" })
	d := e.newDevice()
	dc := e.connectOK(d)
	ds := dc.serve(nil)
	ds.noAttach = true
	port := e.srv.HTTPSAddr()[strings.LastIndex(e.srv.HTTPSAddr(), ":")+1:]
	e.httpsAddr = "127.0.0.1:" + port
	sendRaw(t, e, helloOf(d.host, 0, 16000), 0)
	eventually(t, "the OPEN", 3*time.Second, func() bool { return ds.openCount() == 1 })
	if ip := ds.openList()[0].str("peer_ip"); ip != "127.0.0.1" {
		t.Fatalf("peer_ip %q: an IPv4 client must not be written as an IPv4-mapped IPv6 address", ip)
	}
	e.checkTranscript()
}

func TestAuth_AKeyRotationOfTheControlPlaneIsFollowedAndARevokedKeyIsNotTrusted(t *testing.T) {
	e := newTestEnv(t, nil)
	d := e.newDevice()
	oldKey := e.cpKey
	oldPub := oldKey.Public().(ed25519.PublicKey)
	newPub, newPriv, _ := ed25519.GenerateKey(rand.Reader)

	handshake := func(signer ed25519.PrivateKey, kid string) string {
		dc := e.connect(d)
		return dc.hello(
			func() string { return e.sessionSignedBy(signer, d, func(h, c map[string]any) { h["kid"] = kid }) },
			func(s, n string) string { return e.proof(d, s, n, nil) })
	}
	if r := handshake(oldKey, testKID); !strings.HasPrefix(r, "OK ") {
		t.Fatalf("before the rotation: %q", r)
	}
	// both keys are published during a rotation
	e.keys.Set(StaticKeys{testKID: oldPub, "cp-test-2": newPub})
	if r := handshake(newPriv, "cp-test-2"); !strings.HasPrefix(r, "OK ") {
		t.Fatalf("the new key during the rotation: %q", r)
	}
	if r := handshake(oldKey, testKID); !strings.HasPrefix(r, "OK ") {
		t.Fatalf("the old key during the rotation: %q", r)
	}
	// the old key is withdrawn: its sessions are refused, the new key's are not
	e.keys.Set(StaticKeys{"cp-test-2": newPub})
	if r := handshake(oldKey, testKID); r != "ERR auth" {
		t.Fatalf("a withdrawn key: %q", r)
	}
	if r := handshake(newPriv, "cp-test-2"); !strings.HasPrefix(r, "OK ") {
		t.Fatalf("the new key after the old one was withdrawn: %q", r)
	}
	// a key source that vouches for nothing (stale beyond its window) refuses every session
	e.keys.Set(nil)
	if r := handshake(newPriv, "cp-test-2"); r != "ERR auth" {
		t.Fatalf("an empty key set: %q", r)
	}
}

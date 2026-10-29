package main

import (
	"strings"
	"testing"
	"time"
)

// STATEMENT: the control plane's signed access statement, forwarded as it is, right after the OK, before any stream can be opened on the connection.

const testStatement = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRldmljZS1hY2Nlc3MifQ.eyJzZXEiOjEyMzQ1fQ.c2lnbmF0dXJlLXNpZ25hdHVyZS1zaWduYXR1cmUtc2lnbmF0dXJl"

func statementPlan(e *testEnv, d *testDevice, access string) *devicePlan {
	return &devicePlan{host: d.host, answer: func(int) AuthorizeResponse {
		now := e.now()
		return AuthorizeResponse{DeviceID: d.id, Label: d.label, Host: d.host, Status: statusActive, Plan: "paid", ValidUntil: now.Unix() + 3600, ServerTime: now.Unix(),
			Policy: okPolicy{20, 45, 1800, 14400, 300}, Nodes: []any{}, Access: access}
	}}
}

func TestStatement_IsForwardedUnchangedRightAfterTheOKOfAHelloAndOfARenew(t *testing.T) {
	e := newTestEnv(t, nil)
	d := e.newDeviceNoPlan()
	e.cp.set(d.id, statementPlan(e, d, testStatement))
	dc := e.connect(d)
	dc.session = e.session(d, nil)
	dc.send("HELLO 2 " + dc.session)
	m, _ := parseLine(dc.recv(), dirN2D)
	dc.send("PROOF " + e.proof(d, dc.session, m.str("nonce"), nil))
	if line := dc.recv(); !strings.HasPrefix(line, "OK ") {
		t.Fatalf("%q", line)
	}
	if line := dc.recv(); line != "STATEMENT "+testStatement {
		t.Fatalf("the line after the OK: %q", line)
	}
	// a client stream opened now reaches a device that has the statement already: the OPEN comes after it
	ds := dc.serve(nil)
	c, err := e.clientTLS(d)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if ds.openCount() != 1 {
		t.Fatalf("opens %d", ds.openCount())
	}

	// and at every RENEW, with the control plane's newer statement
	const newer = "eyJhbGciOiJFZERTQSJ9.eyJzZXEiOjEyMzQ2fQ.c2lnbmF0dXJl"
	e.cp.set(d.id, statementPlan(e, d, newer))
	if r := dc.renew(); !strings.HasPrefix(r, "OK ") {
		t.Fatalf("%q", r)
	}
	eventually(t, "the newer statement", 2*time.Second, func() bool { return containsLine(ds.otherLines(), "STATEMENT "+newer) })
	e.checkTranscript()
}

func TestStatement_NoStatementNoLineAndABadOneIsDroppedNeverRelayedNeverAPanic(t *testing.T) {
	e := newTestEnv(t, nil)
	for name, access := range map[string]string{
		"none":          "",
		"not a jws":     "this is not a token",
		"two segments":  "aaaa.bbbb",
		"too long":      strings.Repeat("a", policyData.Protocol.StatementLineMaxBytes) + ".b.c",
		"a space in it": "aaaa.bb bb.cccc",
	} {
		d := e.newDeviceNoPlan()
		e.cp.set(d.id, statementPlan(e, d, access))
		dc := e.connectOK(d)
		ds := dc.serve(nil)
		time.Sleep(60 * time.Millisecond)
		for _, line := range ds.otherLines() {
			if strings.HasPrefix(line, "STATEMENT") {
				t.Errorf("%s: forwarded %.40q", name, line)
			}
		}
		if !e.srv.Online(d.host) {
			t.Errorf("%s: the connection did not come up", name)
		}
	}
	// the longest line the grammar allows is forwarded
	d := e.newDeviceNoPlan()
	longest := strings.Repeat("a", policyData.Protocol.StatementLineMaxBytes-len("STATEMENT ")-1-4) + ".b.c"
	if statementLine(longest) == "" {
		t.Fatal("the longest statement the grammar allows was refused")
	}
	e.cp.set(d.id, statementPlan(e, d, longest))
	dc := e.connectOK(d)
	ds := dc.serve(nil)
	eventually(t, "the longest statement", 3*time.Second, func() bool { return containsLine(ds.otherLines(), "STATEMENT "+longest) })
}

func TestStatement_AnAccessTheControlPlaneSendsThatTheGrammarRefusesIsABadAnswerOverHTTP(t *testing.T) {
	bad := `{"ok":true,"v":1,"device_id":"` + randomHex(16) + `","label":"` + label20() + `","host":"x","status":"active","plan":"paid","valid_until":1793000000,"server_time":1793000000,` +
		`"policy":{"ping_interval_s":20,"dead_peer_s":45,"stream_idle_s":1800,"stream_max_age_s":14400,"renew_before_valid_until_s":300},"nodes":[],"access":"not a jws"}`
	if _, err := parseAuthorizeResponse([]byte(bad)); err == nil {
		t.Fatal("an answer with a statement that is not a JWS was accepted")
	}
}

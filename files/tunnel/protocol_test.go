package main

// ALL 2.0, WP05: the node's own protocol code (policy.go, proto.go, auth.go, jwks.go) against the contracts' golden vectors. The Go reference verifier of
// WP01 (contracts_verify_test.go) and the node are two independent implementations; each vector must get the same verdict and the same error word from
// both. Vectors "nobody has seen" run the same way: ALL_CONTRACT_VECTORS_DIR points ctVectors at a set made with another salt.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// tunnel/policy.json is the node's PROJECTION of contracts/policy.json (the contract lint table `copies`: the contract generator's sync writes it): only the sections the node
// reads, each one as it is in the table. So the test compares section by section, and the sections the node's code reads must all be there.
func TestPolicyCopyIsTheNodesProjectionOfTheContracts(t *testing.T) {
	want, err := os.ReadFile(filepath.Join(ctContracts, "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	var full, mine map[string]any
	if err := json.Unmarshal(want, &full); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(policyJSON, &mine); err != nil {
		t.Fatal(err)
	}
	for _, section := range []string{"protocol", "timing", "node_limits", "authorization", "gated", "identity", "jwks", "enums"} {
		if _, ok := mine[section]; !ok {
			t.Errorf("tunnel/policy.json has no %q section: the node reads it (the contract lint table `copies`, then the contract generator's sync)", section)
		}
	}
	for name, section := range mine {
		if name == "$comment" || name == "provisional" {
			continue
		}
		whole, ok := full[name]
		if !ok {
			t.Errorf("section %q of tunnel/policy.json is not in contracts/policy.json", name)
			continue
		}
		mineMap, mineIsMap := section.(map[string]any)
		wholeMap, _ := whole.(map[string]any)
		if !mineIsMap {
			if !reflect.DeepEqual(section, whole) {
				t.Errorf("%s of tunnel/policy.json differs from contracts/policy.json: run the contract generator's sync", name)
			}
			continue
		}
		for key, value := range mineMap {
			if !reflect.DeepEqual(value, wholeMap[key]) {
				t.Errorf("%s.%s of tunnel/policy.json differs from contracts/policy.json: run the contract generator's sync", name, key)
			}
		}
	}
}

func TestPolicyDefaultsOfTheNodeAreThePolicysNumbers(t *testing.T) {
	cfg := DefaultConfig()
	for name, got := range map[string]time.Duration{
		"HelloTimeout": cfg.HelloTimeout, "AttachTimeout": cfg.AttachTimeout, "FirstLineTimeout": cfg.FirstLineTimeout, "DeadPeer": cfg.DeadPeer,
		"StreamIdle": cfg.StreamIdle, "StreamMaxAge": cfg.StreamMaxAge, "HalfCloseTimeout": cfg.HalfCloseTimeout, "ClockSkew": cfg.ClockSkew, "MinRenewGap": cfg.MinRenewGap,
	} {
		want := map[string]string{
			"HelloTimeout": "node_limits.client_hello_deadline_s", "AttachTimeout": "protocol.attach_timeout_s", "FirstLineTimeout": "protocol.first_line_timeout_s",
			"DeadPeer": "timing.dead_peer_s", "StreamIdle": "timing.stream_idle_s", "StreamMaxAge": "timing.stream_max_age_s",
			"HalfCloseTimeout": "timing.half_close_s", "ClockSkew": "authorization.node_skew_s", "MinRenewGap": "timing.backoff_min_s",
		}[name]
		if got != time.Duration(ctPolInt(want))*time.Second {
			t.Errorf("%s = %s, policy %s = %d", name, got, want, ctPolInt(want))
		}
	}
	if cfg.MaxStreams != ctPolInt("node_limits.global_streams_max") || cfg.MaxStreamsPerHost != ctPolInt("node_limits.label_streams_max") ||
		cfg.MaxUnauth != ctPolInt("node_limits.max_unauthenticated_control") || cfg.AuthorizeMax != ctPolInt("authorization.authorize_max_concurrent") {
		t.Errorf("limits %d %d %d %d", cfg.MaxStreams, cfg.MaxStreamsPerHost, cfg.MaxUnauth, cfg.AuthorizeMax)
	}
}

func TestWireVectorsGetTheSameVerdictFromTheNode(t *testing.T) {
	for _, v := range ctList(t, ctVectors(t, "lines.json"), "lines") {
		line, direction := v["line"].(string), v["dir"].(string)
		parsed, err := parseLine(line, direction)
		if v["ok"] == true {
			if err != nil {
				t.Errorf("%v: %v", v["id"], err)
				continue
			}
			if !ctEqual(map[string]any(parsed), v["parsed"]) {
				t.Errorf("%v: parsed %v, want %v", v["id"], parsed, v["parsed"])
			}
			if v["canonical"] == true && formatLine(parsed) != line {
				t.Errorf("%v: canonical form %q, want %q", v["id"], formatLine(parsed), line)
			}
			continue
		}
		if err == nil {
			t.Errorf("%v: accepted %q", v["id"], truncate(line))
			continue
		}
		if code := errCode(err); code != v["error"] {
			t.Errorf("%v: error %q, want %q", v["id"], code, v["error"])
		}
		for _, suffix := range []string{"\n", "\x00", "\r"} {
			if _, err := parseLine(line+suffix, direction); err == nil {
				t.Errorf("%v: accepted with suffix %q", v["id"], suffix)
			}
		}
	}
}

func TestAddressVectorsGetTheSameVerdictFromTheNode(t *testing.T) {
	for _, v := range ctList(t, ctVectors(t, "lines.json"), "ips") {
		if got := validIP(v["value"].(string)); got != (v["ok"] == true) {
			t.Errorf("%v: %q gave %v", v["id"], v["value"], got)
		}
	}
}

func TestLabelAndHostVectorsGetTheSameVerdictFromTheNode(t *testing.T) {
	doc := ctVectors(t, "labels.json")
	for _, v := range ctList(t, doc, "labels") {
		if got := reLabel.MatchString(v["value"].(string)); got != (v["ok"] == true) {
			t.Errorf("%v: label %q gave %v", v["id"], v["value"], got)
		}
	}
	for _, v := range ctList(t, doc, "fqdns") {
		if got := validFQDN(v["value"].(string)); got != (v["ok"] == true) && v["zones"] == nil {
			t.Errorf("%v: host %q gave %v", v["id"], v["value"], got)
		}
	}
}

// nodeKeys turns the verifier's kid -> x map into the node's key set.
func nodeKeys(t *testing.T, doc any) StaticKeys {
	t.Helper()
	keys := StaticKeys{}
	m, code := ctParseJWKS(doc)
	if code != "" {
		t.Fatalf("jwks: %s", code)
	}
	for kid, x := range m {
		key, ok := publicKeyX(x)
		if !ok {
			t.Fatalf("key %s", kid)
		}
		keys[kid] = key
	}
	return keys
}

func verdictOf(err error) map[string]any {
	if err != nil {
		return map[string]any{"ok": false, "error": tokenWord(err)}
	}
	return map[string]any{"ok": true}
}

func atSeconds(s float64) time.Time { return time.Unix(0, int64(s*1e9)) }

func TestSessionVectorsGetTheSameVerdictFromTheNode(t *testing.T) {
	for _, v := range ctList(t, ctVectors(t, "tokens.json"), "sessions") {
		ctx := v["ctx"].(map[string]any)
		token, isString := v["token"].(string)
		var err error
		if !isString {
			err = tokFail(tokMalformed)
		} else {
			_, err = verifySession(token, atSeconds(ctx["now"].(float64)), nodeKeys(t, ctx["jwks"]), time.Duration(ctx["skew"].(float64))*time.Second)
		}
		ctCheckVerdict(t, v, verdictOf(err))
	}
}

func TestProofVectorsGetTheSameVerdictFromTheNode(t *testing.T) {
	for _, v := range ctList(t, ctVectors(t, "tokens.json"), "proofs") {
		ctx := v["ctx"].(map[string]any)
		now, skew := atSeconds(ctx["now"].(float64)), time.Duration(ctx["skew"].(float64))*time.Second
		sessionToken := ctx["session"].(string)
		session, err := verifySession(sessionToken, now, nodeKeys(t, ctx["jwks"]), skew)
		if err != nil {
			t.Fatalf("%v: session %v", v["id"], err)
		}
		pc, err := verifyProof(v["proof"].(string), now, sessionToken, session, ctx["nonce"].(string), ctx["htu"].(string), skew)
		if err == nil {
			// the replay check belongs to the caller: spend against the vector's set of used jtis
			cache := newReplayCache(16)
			for _, id := range ctStrings(ctx["seen"]) {
				cache.spend(id, pc.IssuedAt, now, skew)
			}
			if !cache.spend(pc.JTI, pc.IssuedAt, now, skew) {
				err = tokFail(tokReplayedJTI)
			}
		}
		ctCheckVerdict(t, v, verdictOf(err))
	}
}

func TestKeySetVectorsGetTheSameVerdictFromTheNode(t *testing.T) {
	for _, v := range ctList(t, ctVectors(t, "tokens.json"), "key_sets") {
		if v["kind"] != "jwks" {
			continue
		}
		_, err := ParseJWKS([]byte(canonicalJSON(v["doc"])))
		got := map[string]any{"ok": true}
		if err != nil {
			got = map[string]any{"ok": false, "error": err.Error()}
		}
		ctCheckVerdict(t, v, got)
	}
}

func TestOKBodyBoundsTheWindowsToThePolicy(t *testing.T) {
	big := okPolicy{PingIntervalS: 86400, DeadPeerS: 86400, StreamIdleS: 86400, StreamMaxAgeS: 86400, RenewBeforeValidUntilS: 86400}
	got := boundWindows(big)
	want := okPolicy{int64(ctPolInt("timing.ping_interval_s")), int64(ctPolInt("timing.dead_peer_s")), int64(ctPolInt("timing.stream_idle_s")),
		int64(ctPolInt("timing.stream_max_age_s")), int64(ctPolInt("timing.renew_before_valid_until_s"))}
	if got != want {
		t.Fatalf("bounded %+v, want %+v", got, want)
	}
	small := okPolicy{PingIntervalS: 5, DeadPeerS: 9, StreamIdleS: 30, StreamMaxAgeS: 60, RenewBeforeValidUntilS: 10}
	if boundWindows(small) != small {
		t.Fatalf("a window below the policy's must stay as it is: %+v", boundWindows(small))
	}
	line := okBody{Node: "t1", Host: strings.Repeat("a", 20) + "." + testZone, Status: statusActive, ValidUntil: 1798766600, ServerTime: 1798761600, Policy: got}.line()
	if m, err := parseLine(line, dirN2D); err != nil || formatLine(m) != line {
		t.Fatalf("the OK line is not canonical: %q %v", line, err)
	}
}

func TestAuthorizeAnswerIsCheckedBeforeItIsRelayed(t *testing.T) {
	req := AuthorizeRequest{DeviceID: randomHex(16), SessionJTI: randomHex(12), Reason: "hello", Node: "t1"}
	label := label20()
	good := AuthorizeResponse{DeviceID: req.DeviceID, Label: label, Host: label + "." + testZone, Status: statusActive, Plan: "paid", ValidUntil: 1798766600,
		ServerTime: 1798761600, Policy: okPolicy{20, 45, 1800, 14400, 300}}
	if err := checkAuthorize(good, req); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(a *AuthorizeResponse){
		"another device":     func(a *AuthorizeResponse) { a.DeviceID = randomHex(16) },
		"host without label": func(a *AuthorizeResponse) { a.Host = "evil." + testZone },
		"host of another":    func(a *AuthorizeResponse) { a.Host = label20() + "." + testZone },
		"two labels deep":    func(a *AuthorizeResponse) { a.Host = "x." + a.Host },
		"unknown status":     func(a *AuthorizeResponse) { a.Status = "free" },
		"unknown plan":       func(a *AuthorizeResponse) { a.Plan = "lifetime" },
		"no valid_until":     func(a *AuthorizeResponse) { a.ValidUntil = 0 },
		"window of a week":   func(a *AuthorizeResponse) { a.Policy.DeadPeerS = 7 * 86400 },
		"zero window":        func(a *AuthorizeResponse) { a.Policy.PingIntervalS = 0 },
		"upper case host":    func(a *AuthorizeResponse) { a.Host = strings.ToUpper(a.Host) },
		"trailing dot host":  func(a *AuthorizeResponse) { a.Host += "." },
		"label not base32":   func(a *AuthorizeResponse) { a.Label = strings.Repeat("0", 20); a.Host = a.Label + "." + testZone },
	} {
		a := good
		mutate(&a)
		if checkAuthorize(a, req) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestReplayCacheRefusesAReusedJTIForTheProofsLifeAndIsBounded(t *testing.T) {
	now := time.Unix(1798766600, 0)
	skew := 5 * time.Second
	c := newReplayCache(3)
	if !c.spend("jti-aaaaaaaaaaaaaaaa", now.Unix(), now, skew) || c.spend("jti-aaaaaaaaaaaaaaaa", now.Unix(), now, skew) {
		t.Fatal("a jti is single use")
	}
	// after the proof can no longer verify (its TTL plus the skew) the jti is forgotten and the cache makes room
	later := now.Add(secs(ctPolInt("authorization.proof_ttl_s")) + skew + time.Second)
	if !c.spend("jti-aaaaaaaaaaaaaaaa", later.Unix(), later, skew) {
		t.Fatal("a forgotten jti is spendable again")
	}
	// full of live entries: a new proof is refused, never admitted unchecked
	c = newReplayCache(2)
	for _, id := range []string{"jti-1aaaaaaaaaaaaaaa", "jti-2aaaaaaaaaaaaaaa"} {
		if !c.spend(id, now.Unix(), now, skew) {
			t.Fatal(id)
		}
	}
	if c.spend("jti-3aaaaaaaaaaaaaaa", now.Unix(), now, skew) {
		t.Fatal("a full cache admitted a proof")
	}
	if !c.spend("jti-3aaaaaaaaaaaaaaa", later.Unix(), later, skew) {
		t.Fatal("expired entries must free the room")
	}
	if c.size() != 1 {
		t.Fatalf("size %d", c.size())
	}
}

func FuzzParseLine(f *testing.F) {
	for _, v := range []string{"HELLO 2 a.b.c", "PROOF a.b.c", "PING", "PONG", "HINT 192.0.2.4 ::1", "CLOSE", "CLOSE expired", "ERR auth", "CHALLENGE AAAAAAAAAAAAAAAAAAAAAA",
		"ATTACH 00000000000000000000000000000000 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "DRAIN 20", "OK {}", "OPEN x y z w"} {
		f.Add(v, true)
		f.Add(v, false)
	}
	f.Fuzz(func(t *testing.T, line string, toNode bool) {
		dir := dirN2D
		if toNode {
			dir = dirD2N
		}
		m, err := parseLine(line, dir)
		if err != nil {
			if code := errCode(err); !inList(policyData.Protocol.ErrorCodes, code) {
				t.Fatalf("%q: error word %q is not a protocol code", line, code)
			}
			return
		}
		// what the node accepts, it can write again unchanged in its canonical form, and that form parses to the same message
		if canonical := formatLine(m); canonical != "" {
			again, err := parseLine(canonical, dir)
			if err != nil || !ctEqual(map[string]any(again), map[string]any(m)) {
				t.Fatalf("%q: canonical %q reparses to %v (%v)", line, canonical, again, err)
			}
		}
	})
}

func FuzzTokens(f *testing.F) {
	doc, err := ctLoadFile(filepath.Join(ctVectorsDir(), "tokens.json"))
	if err != nil {
		f.Fatal(err)
	}
	for _, item := range doc.(map[string]any)["sessions"].([]any) {
		if s, ok := item.(map[string]any)["token"].(string); ok {
			f.Add(s)
		}
	}
	for _, item := range doc.(map[string]any)["proofs"].([]any) {
		f.Add(item.(map[string]any)["proof"].(string))
	}
	keys := StaticKeys{}
	f.Fuzz(func(t *testing.T, token string) {
		// no token, however broken, may panic the verifiers; a token no key signed never verifies
		if _, err := verifySession(token, time.Unix(1798766600, 0), keys, 5*time.Second); err == nil {
			t.Fatalf("a session verified against an empty key set: %q", token)
		}
		_, _ = splitJWS(token, 1<<16)
		_, _ = verifyProof(token, time.Unix(1798766600, 0), "a.b.c", &SessionClaims{KeyX: strings.Repeat("A", 43)}, "n", "h", 5*time.Second)
	})
}

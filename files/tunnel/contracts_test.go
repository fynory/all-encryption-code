package main

// ALL 2.0, WP01: the Go side of the contract tests. The golden vectors of contracts/vectors/ are the spec: this file runs every one of them
// through the Go reference verifier (contracts_verify_test.go) and demands the same verdict, and the same error word, as the Python and
// TypeScript verifiers. The node written by WP05 and WP06 is tested against the same functions and files; nothing here is node code.

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// ctVectorsDir is contracts/vectors, or the folder ALL_CONTRACT_VECTORS_DIR names (vectors made with another salt: nobody has seen them).
func ctVectorsDir() string {
	if dir := os.Getenv("ALL_CONTRACT_VECTORS_DIR"); dir != "" {
		return dir
	}
	return filepath.Join(ctContracts, "vectors")
}

func ctVectors(t *testing.T, name string) map[string]any {
	t.Helper()
	value, err := ctLoadFile(filepath.Join(ctVectorsDir(), name))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return value.(map[string]any)
}

func ctList(t *testing.T, doc map[string]any, key string) []map[string]any {
	t.Helper()
	items, ok := doc[key].([]any)
	if !ok || len(items) == 0 {
		t.Fatalf("no vectors under %q", key)
	}
	out := make([]map[string]any, len(items))
	for i, item := range items {
		out[i] = item.(map[string]any)
	}
	return out
}

func ctVerdict(r ctResult) map[string]any {
	if r.ok {
		return map[string]any{"ok": true}
	}
	return map[string]any{"ok": false, "error": r.err}
}

func ctCheckVerdict(t *testing.T, vector map[string]any, got map[string]any) {
	t.Helper()
	if !ctEqual(got, vector["expect"]) {
		t.Errorf("%s: got %v, want %v", vector["id"], got, vector["expect"])
	}
}

func ctStrings(value any) []string {
	var out []string
	for _, item := range value.([]any) {
		out = append(out, item.(string))
	}
	return out
}

func TestContractsPolicyHoldsThePlansNumbers(t *testing.T) {
	want := map[string]int{
		"timing.stream_idle_s": 1800, "timing.stream_max_age_s": 14400, "timing.ping_interval_s": 20, "timing.dead_peer_s": 45,
		"authorization.valid_until_paid_s": 14400, "authorization.valid_until_trial_s": 900, "authorization.valid_until_gated_s": 900,
		"authorization.grace_paid_s": 900, "authorization.access_ttl_paid_s": 14400, "authorization.access_ttl_trial_s": 600,
		"timing.drain_quiet_s": 1200, "pairing.window_s": 600, "budget.classes.paid": 20, "budget.classes.trial": 12, "budget.classes.flex": 8,
		"gated.bytes_per_day": 10 * 1024 * 1024, "gated.streams_per_day": 200, "gated.cutoff_days": 14, "identity.label_length": 20,
		"timing.renew_before_valid_until_s": 300, "jwks.max_keys": 16, "node_limits.label_streams_max": 64, "node_limits.client_hello_deadline_s": 5,
		"authorization.session_ttl_s": 300, "authorization.proof_ttl_s": 60, "authorization.node_assertion_ttl_s": 60, "protocol.version": 2,
	}
	for key, value := range want {
		if got := ctPolInt(key); got != value {
			t.Errorf("policy %s = %d, want %d", key, got, value)
		}
	}
	if ctPolStr("protocol.alpn") != "all-tunnel/2" {
		t.Errorf("alpn = %s", ctPolStr("protocol.alpn"))
	}
}

func TestContractsLabelPatternComesFromThePolicyOnly(t *testing.T) {
	// the schema, the policy and the compiled verifier pattern are one text; this file never types the pattern itself
	label := ctPolStr("identity.label_regex")
	defs := ctSchemaSet.docs["common.schema.json"].(map[string]any)["$defs"].(map[string]any)
	if defs["label"].(map[string]any)["pattern"] != label || ctLabelRE.String() != label {
		t.Fatalf("label pattern differs: policy %q schema %v compiled %q", label, defs["label"], ctLabelRE.String())
	}
	if alphabet := ctPolStr("identity.label_alphabet"); len(alphabet) != 32 {
		t.Errorf("alphabet %q", alphabet)
	}
	// the detector a node builds for its own addresses accepts exactly the labels of the vectors
	detector := ctHostPattern("devices.all-e2e.test")
	for _, v := range ctList(t, ctVectors(t, "labels.json"), "labels") {
		got := detector.MatchString(v["value"].(string) + ".devices.all-e2e.test")
		if got != (v["ok"] == true) {
			t.Errorf("%v: detector says %v", v["id"], got)
		}
	}
}

func TestContractsSchemaConstantsEqualThePolicy(t *testing.T) {
	defs := ctSchemaSet.docs["common.schema.json"].(map[string]any)["$defs"].(map[string]any)
	pattern := func(name string) any { return defs[name].(map[string]any)["pattern"] }
	for name, key := range map[string]string{"label": "identity.label_regex", "fqdn": "identity.fqdn_regex", "device_id": "identity.device_id_regex",
		"stream_id": "identity.stream_id_regex", "attach_secret": "identity.attach_secret_regex", "nonce": "identity.nonce_regex", "jti": "identity.jti_regex",
		"kid": "identity.kid_regex"} {
		if pattern(name) != ctPolStr(key) {
			t.Errorf("schema %s pattern differs from policy %s", name, key)
		}
	}
	for name, key := range map[string]string{"error_code": "protocol.error_codes", "close_reason": "protocol.close_reasons", "source_class": "protocol.source_classes",
		"authorize_status": "enums.authorize_status", "budget_class": "enums.budget_class"} {
		if !reflect.DeepEqual(ctStrings(defs[name].(map[string]any)["enum"]), ctPolStrings(key)) {
			t.Errorf("schema %s enum differs from policy %s", name, key)
		}
	}
	grammar := ctGrammar["types"].(map[string]any)
	for _, kind := range []string{"stream_id", "attach_secret", "nonce"} {
		if grammar[kind].(map[string]any)["pattern"] != pattern(kind) {
			t.Errorf("grammar type %s differs from the schema", kind)
		}
	}
}

func TestContractsLabelVectors(t *testing.T) {
	doc := ctVectors(t, "labels.json")
	for _, v := range ctList(t, doc, "labels") {
		if got := ctLabelOK(v["value"].(string)); got != (v["ok"] == true) {
			t.Errorf("%v: label %q gave %v", v["id"], v["value"], got)
		}
	}
	for _, v := range ctList(t, doc, "fqdns") {
		var zones []string
		if z, ok := v["zones"]; ok {
			zones = ctStrings(z)
		}
		if got := ctFQDNOK(v["value"].(string), zones); got != (v["ok"] == true) {
			t.Errorf("%v: host %q gave %v", v["id"], v["value"], got)
		}
	}
}

func TestContractsAddressVectors(t *testing.T) {
	for _, v := range ctList(t, ctVectors(t, "lines.json"), "ips") {
		if got := ctValidIP(v["value"].(string)); got != (v["ok"] == true) {
			t.Errorf("%v: %q gave %v", v["id"], v["value"], got)
		}
	}
}

func TestContractsLineVectors(t *testing.T) {
	for _, v := range ctList(t, ctVectors(t, "lines.json"), "lines") {
		line, direction := v["line"].(string), v["dir"].(string)
		parsed, err := ctParseLine(line, direction)
		if v["ok"] == true {
			if err != nil {
				t.Errorf("%v: %v", v["id"], err)
				continue
			}
			if !ctEqual(parsed, v["parsed"]) {
				t.Errorf("%v: parsed %v, want %v", v["id"], parsed, v["parsed"])
			}
			if v["canonical"] == true {
				if again, err := ctFormatLine(parsed); err != nil || again != line {
					t.Errorf("%v: canonical form %q (%v), want %q", v["id"], again, err, line)
				}
			}
			continue
		}
		if err == nil {
			t.Errorf("%v: accepted %q", v["id"], truncate(line))
			continue
		}
		if code := err.(*ctProtoErr).code; code != v["error"] {
			t.Errorf("%v: error %q, want %q", v["id"], code, v["error"])
		}
		for _, suffix := range []string{"\n", "\x00", "\r"} {
			if _, err := ctParseLine(line+suffix, direction); err == nil {
				t.Errorf("%v: accepted with suffix %q", v["id"], suffix)
			}
		}
	}
}

func truncate(s string) string {
	if len(s) > 80 {
		return s[:80] + "..."
	}
	return s
}

func TestContractsBodyVectors(t *testing.T) {
	doc := ctVectors(t, "bodies.json")
	for _, v := range ctList(t, doc, "bodies") {
		errs := ctSchemaSet.validate(v["schema"].(string), v["body"])
		if (len(errs) == 0) != (v["ok"] == true) {
			t.Errorf("%v: errors %v", v["id"], errs)
		}
	}
	for _, v := range ctList(t, doc, "feeds") {
		errs := ctCheckFeed(v["body"], v["since"].(float64))
		if (len(errs) == 0) != (v["ok"] == true) {
			t.Errorf("%v: errors %v", v["id"], errs)
		}
	}
}

func TestContractsSessionVectors(t *testing.T) {
	for _, v := range ctList(t, ctVectors(t, "tokens.json"), "sessions") {
		ctx := v["ctx"].(map[string]any)
		keys, code := ctParseJWKS(ctx["jwks"])
		if code != "" {
			t.Fatalf("%v: %s", v["id"], code)
		}
		token, _ := v["token"].(string) // a null token is "not a string": malformed
		var got ctResult
		if _, isString := v["token"].(string); !isString {
			got = ctFail("malformed_token")
		} else {
			got = ctVerifySession(token, ctx["now"].(float64), ctx["audience"].(string), keys, ctx["skew"].(float64))
		}
		ctCheckVerdict(t, v, ctVerdict(got))
	}
}

func TestContractsProofVectors(t *testing.T) {
	for _, v := range ctList(t, ctVectors(t, "tokens.json"), "proofs") {
		ctx := v["ctx"].(map[string]any)
		keys, _ := ctParseJWKS(ctx["jwks"])
		now, skew := ctx["now"].(float64), ctx["skew"].(float64)
		session := ctVerifySession(ctx["session"].(string), now, ctPolStr("identity.aud_tunnel"), keys, skew)
		if !session.ok {
			t.Fatalf("%v: session %s", v["id"], session.err)
		}
		seen := map[string]bool{}
		for _, id := range ctStrings(ctx["seen"]) {
			seen[id] = true
		}
		got := ctVerifyProof(v["proof"].(string), now, ctx["session"].(string), session.claims, ctx["nonce"].(string), ctx["htu"].(string), skew, seen)
		ctCheckVerdict(t, v, ctVerdict(got))
	}
}

func TestContractsNodeAssertionVectors(t *testing.T) {
	for _, v := range ctList(t, ctVectors(t, "tokens.json"), "assertions") {
		ctx := v["ctx"].(map[string]any)
		keys, code := ctParseNodeKeys(ctx["node_keys"])
		if code != "" {
			t.Fatalf("%v: %s", v["id"], code)
		}
		seen := map[string]bool{}
		for _, id := range ctStrings(ctx["seen"]) {
			seen[id] = true
		}
		got := ctVerifyNodeAssertion(v["assertion"].(string), ctx["now"].(float64), keys, ctx["method"].(string), ctx["url"].(string), []byte(ctx["body"].(string)),
			ctx["skew"].(float64), seen)
		ctCheckVerdict(t, v, ctVerdict(got))
	}
}

func TestContractsStatementVectors(t *testing.T) {
	for _, v := range ctList(t, ctVectors(t, "tokens.json"), "statements") {
		ctx := v["ctx"].(map[string]any)
		keys, _ := ctParseJWKS(ctx["jwks"])
		got := ctVerifyStatement(v["statement"].(string), ctx["now"].(float64), keys, ctx["device_id"].(string), ctx["last_seq"].(float64))
		ctCheckVerdict(t, v, ctVerdict(got))
	}
}

func TestContractsSurfaceVectors(t *testing.T) {
	for _, v := range ctList(t, ctVectors(t, "tokens.json"), "surface") {
		switch v["kind"] {
		case "challenge":
			ctCheckVerdict(t, v, ctVerdict(ctVerifySurfaceChallenge(v["secret"].(string), v["nonce"].(string), v["mac"].(string))))
		case "proof":
			ctCheckVerdict(t, v, ctVerdict(ctVerifySurfaceProof(v["secret"].(string), v["nonce"].(string), int(v["pid"].(float64)), int(v["port"].(float64)), v["proof"].(string))))
		default:
			if got := ctIdentityRequest(v["host"].(string), int(v["port"].(float64)), v["nonce"].(string), v["mac"].(string)); got != v["text"] {
				t.Errorf("%v: request %q, want %q", v["id"], got, v["text"])
			}
		}
	}
}

func TestContractsKeySetVectors(t *testing.T) {
	for _, v := range ctList(t, ctVectors(t, "tokens.json"), "key_sets") {
		var code string
		if v["kind"] == "jwks" {
			_, code = ctParseJWKS(v["doc"])
		} else {
			_, code = ctParseNodeKeys(v["doc"])
		}
		got := map[string]any{"ok": true}
		if code != "" {
			got = map[string]any{"ok": false, "error": code}
		}
		ctCheckVerdict(t, v, got)
	}
}

func TestContractsTranscriptVectors(t *testing.T) {
	for _, v := range ctList(t, ctVectors(t, "transcripts.json"), "transcripts") {
		violation := ctCheckTranscript(v)
		expect := v["expect"].(map[string]any)
		if (violation == "") != (expect["ok"] == true) || (violation != "" && violation != expect["violation"]) {
			t.Errorf("%v: violation %q, want %v", v["id"], violation, expect)
		}
	}
}

// TestContractsGoNodeDoesWhatTheGoldenTranscriptsSay runs the scripted inputs of every golden transcript through an independent Go node
// (the twin of contracts/fake_node.py) and demands the very outputs Python produced: two implementations, one behaviour.
func TestContractsGoNodeDoesWhatTheGoldenTranscriptsSay(t *testing.T) {
	replayed := 0
	for _, v := range ctList(t, ctVectors(t, "transcripts.json"), "transcripts") {
		if v["replay"] != true {
			continue
		}
		replayed++
		inputs, golden := ctSplitTranscript(v["events"].([]any))
		node := ctNewNodeSim(v["ctx"].(map[string]any))
		var produced []map[string]any
		for _, input := range inputs {
			produced = append(produced, node.handle(input)...)
		}
		if len(produced) != len(golden) {
			t.Errorf("%v: %d outputs, want %d", v["id"], len(produced), len(golden))
			continue
		}
		for i := range golden {
			if !ctEqual(toAny(produced[i]), toAny(golden[i])) {
				t.Errorf("%v: output %d is %v, want %v", v["id"], i, produced[i], golden[i])
				break
			}
		}
	}
	if replayed < 8 {
		t.Errorf("only %d replayable transcripts", replayed)
	}
}

func toAny(m map[string]any) any { return m }

func TestContractsEveryTruncationOfAGoodTokenIsRefused(t *testing.T) {
	tokens := ctVectors(t, "tokens.json")
	var vector map[string]any
	for _, v := range ctList(t, tokens, "proofs") {
		if v["id"] == "proof.ok.baseline" {
			vector = v
		}
	}
	ctx := vector["ctx"].(map[string]any)
	keys, _ := ctParseJWKS(ctx["jwks"])
	session := ctx["session"].(string)
	claims := ctVerifySession(session, ctx["now"].(float64), "all-tunnel", keys, 5).claims
	for _, token := range []string{session, vector["proof"].(string)} {
		for cut := 0; cut < len(token)-1; cut += 7 {
			if ctVerifySession(token[:cut], ctx["now"].(float64), "all-tunnel", keys, 5).ok {
				t.Fatalf("truncated session accepted at %d", cut)
			}
			if ctVerifyProof(token[:cut], ctx["now"].(float64), session, claims, ctx["nonce"].(string), ctx["htu"].(string), 5, map[string]bool{}).ok {
				t.Fatalf("truncated proof accepted at %d", cut)
			}
		}
		for i := 0; i < len(token); i += 11 {
			flipped := token[:i] + map[bool]string{true: "B", false: "A"}[token[i] == 'A'] + token[i+1:]
			if strings.Count(flipped, ".") == 2 && ctVerifySession(flipped, ctx["now"].(float64), "all-tunnel", keys, 5).ok && flipped != token {
				t.Fatalf("corrupted session accepted at %d", i)
			}
		}
	}
}

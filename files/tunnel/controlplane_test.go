package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The real control-plane client against a fake control plane over HTTPS that authenticates the node with the contracts' own verifier.

func TestControlPlane_AuthorizeCarriesOneAssertionBoundToTheRequestAndNothingElse(t *testing.T) {
	e, cp := httpNode(t, nil, nil)
	d := e.newDevice()
	hc := cp.control()
	resp, err := hc.Authorize(context.Background(), AuthorizeRequest{DeviceID: d.id, SessionJTI: randomHex(12), Reason: "hello", Node: testNodeID})
	if err != nil {
		t.Fatal(err)
	}
	if resp.DeviceID != d.id || resp.Host != d.host || resp.Status != statusActive || resp.Plan != "paid" || resp.ValidUntil <= e.now().Unix() {
		t.Fatalf("answer %+v", resp)
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if len(cp.bodies) != 1 || len(cp.headers) < 1 || cp.refused != 0 {
		t.Fatalf("authenticated %d requests (%d authorize), refused %d", len(cp.headers), len(cp.bodies), cp.refused)
	}
	// The assertion is the node's ONLY credential, on authorize and on the feed alike: no bearer, no cookie, no shared secret, no commerce key.
	for _, h := range cp.headers {
		if h.Get("x-all-node-assertion") == "" {
			t.Error("a request without its assertion was authenticated")
		}
		for name := range h {
			switch strings.ToLower(name) {
			case "x-all-node-assertion", "content-type", "accept", "user-agent", "content-length", "accept-encoding":
			default:
				t.Errorf("a request of the node carries the header %s", name)
			}
		}
	}
}

func TestControlPlane_AnAssertionServesOneRequestOnly(t *testing.T) {
	_, cp := httpNode(t, nil, nil)
	hc := cp.control()
	body := []byte(`{"v":1}`)
	token := hc.assertion("POST", "https://"+cp.srv.Listener.Addr().String()+authorizePath, body)
	cp.mu.Lock()
	keys := cp.nodeKeys
	cp.mu.Unlock()
	url := "https://" + cp.srv.Listener.Addr().String() + authorizePath
	seen := map[string]bool{}
	first := ctVerifyNodeAssertion(token, epochSeconds(time.Now()), keys, "POST", url, body, 5, seen)
	if !first.ok {
		t.Fatalf("assertion refused: %s", first.err)
	}
	seen[first.jti] = true
	if r := ctVerifyNodeAssertion(token, epochSeconds(time.Now()), keys, "POST", url, body, 5, seen); r.err != "replayed_jti" {
		t.Fatalf("a replayed assertion: %s", r.err)
	}
	// bound to the method, the URL and the exact body bytes
	if r := ctVerifyNodeAssertion(token, epochSeconds(time.Now()), keys, "GET", url, body, 5, map[string]bool{}); r.err != "wrong_htm" {
		t.Fatalf("another method: %s", r.err)
	}
	if r := ctVerifyNodeAssertion(token, epochSeconds(time.Now()), keys, "POST", url+"?x=1", body, 5, map[string]bool{}); r.err != "wrong_htu" {
		t.Fatalf("another URL: %s", r.err)
	}
	if r := ctVerifyNodeAssertion(token, epochSeconds(time.Now()), keys, "POST", url, []byte(`{"v":2}`), 5, map[string]bool{}); r.err != "wrong_body_hash" {
		t.Fatalf("another body: %s", r.err)
	}
	// 60 s, no more
	if r := ctVerifyNodeAssertion(token, epochSeconds(time.Now().Add(61*time.Second)), keys, "POST", url, body, 5, map[string]bool{}); r.err != "expired" {
		t.Fatalf("an old assertion: %s", r.err)
	}
	// every call mints a new one (a retry is a new request)
	if again := hc.assertion("POST", url, body); again == token {
		t.Fatal("two assertions are the same token")
	}
}

func TestControlPlane_ABadNodeSignatureIsRefusedByTheControlPlaneAndTheDeviceIsTurnedAway(t *testing.T) {
	e, cp := httpNode(t, nil, nil)
	d := e.newDevice()

	_, rogueKey, _ := ed25519.GenerateKey(rand.Reader)
	for name, hc := range map[string]*HTTPControl{
		"a key the control plane does not know": func() *HTTPControl {
			c, err := NewHTTPControl(HTTPControlConfig{BaseURL: cp.url(), NodeID: testNodeID, KID: cp.nodeKID, Key: rogueKey, Client: cp.srv.Client()})
			if err != nil {
				t.Fatal(err)
			}
			return c
		}(),
		"a kid it does not know": func() *HTTPControl {
			c, err := NewHTTPControl(HTTPControlConfig{BaseURL: cp.url(), NodeID: testNodeID, KID: "node-t1-revoked", Key: cp.nodeKey, Client: cp.srv.Client()})
			if err != nil {
				t.Fatal(err)
			}
			return c
		}(),
		"another node's id": func() *HTTPControl {
			c, err := NewHTTPControl(HTTPControlConfig{BaseURL: cp.url(), NodeID: "t2", KID: cp.nodeKID, Key: cp.nodeKey, Client: cp.srv.Client()})
			if err != nil {
				t.Fatal(err)
			}
			return c
		}(),
		"a clock a minute off": func() *HTTPControl {
			c, err := NewHTTPControl(HTTPControlConfig{BaseURL: cp.url(), NodeID: testNodeID, KID: cp.nodeKID, Key: cp.nodeKey, Client: cp.srv.Client(),
				Now: func() time.Time { return e.now().Add(-2 * time.Minute) }})
			if err != nil {
				t.Fatal(err)
			}
			return c
		}(),
	} {
		_, err := hc.Authorize(context.Background(), AuthorizeRequest{DeviceID: d.id, SessionJTI: randomHex(12), Reason: "hello", Node: testNodeID})
		ce, ok := err.(*ControlError)
		if !ok || ce.Status != 401 || ce.Code != "unauthorized" {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := hc.Feed(context.Background(), 0, 0); err == nil {
			t.Errorf("%s: the feed answered", name)
		}
	}
	if e.cp.callsFor(d.id, "") != 0 {
		t.Fatal("the control plane decided something for a request it could not authenticate")
	}

	// A node whose key was revoked (its kid removed from TUNNEL_NODE_KEYS) cannot authorize anyone: the device is turned away with a closed word.
	cp.mu.Lock()
	delete(cp.nodeKeys, cp.nodeKID)
	cp.mu.Unlock()
	dc := e.connect(d)
	line := dc.hello(func() string { return e.session(d, nil) }, func(s, n string) string { return e.proof(d, s, n, nil) })
	if line != "ERR control_unavailable" {
		t.Fatalf("a device behind a node the control plane refuses must be told to try later, not that it is wrong: %q", line)
	}
	dc.expectClosed(2 * time.Second)
	if e.srv.Online(d.host) {
		t.Fatal("the host is served although nothing authorized it")
	}
}

func TestControlPlane_TheNodeHoldsNoSecretButItsOwnKey(t *testing.T) {
	// The production binary's whole configuration surface: one key file, no shared secret, no token, no commerce key.
	bin := productionBinary(t)
	out, _ := exec.Command(bin, "-h").CombinedOutput()
	help := strings.ToLower(string(out))
	for _, word := range []string{"secret", "token", "hmac", "commerce", "password", "bearer", "api-key", "apikey"} {
		if strings.Contains(help, word) {
			t.Errorf("the node's flags mention %q:\n%s", word, out)
		}
	}
	if !strings.Contains(help, "-node-key-file") {
		t.Fatalf("no node key flag:\n%s", out)
	}
	for _, name := range []string{"TUNNEL_COMMERCE_KEY", "TUNNEL_SECRET", "TUNNEL_TOKEN", "COMMERCE_HMAC_KEY"} {
		if strings.Contains(string(out), name) {
			t.Errorf("the node reads %s", name)
		}
	}
}

func TestControlPlane_ErrorsAreClosedWordsAndNeverTextFromTheNetwork(t *testing.T) {
	e, cp := httpNode(t, nil, nil)
	d := e.newDevice()
	hc := cp.control()
	ask := func() error {
		_, err := hc.Authorize(context.Background(), AuthorizeRequest{DeviceID: d.id, SessionJTI: randomHex(12), Reason: "renew", Node: testNodeID})
		return err
	}
	code := func(err error) (int, string) {
		ce, ok := err.(*ControlError)
		if !ok {
			return 0, err.Error()
		}
		return ce.Status, ce.Code
	}

	e.cp.set(d.id, &devicePlan{host: d.host, err: &ControlError{Status: 402, Code: codeLicenseInactive}})
	if st, w := code(ask()); st != 402 || w != codeLicenseInactive {
		t.Errorf("402: %d %s", st, w)
	}
	e.cp.set(d.id, &devicePlan{host: d.host, err: &ControlError{Status: 401, Code: codeDeviceRevoked}})
	if st, w := code(ask()); st != 401 || w != codeDeviceRevoked {
		t.Errorf("401: %d %s", st, w)
	}
	cp.setDown(503)
	if st, w := code(ask()); st != 503 || w != "end_to_end_unavailable" || errForControl(ask()) != codeControlUnavailable {
		t.Errorf("503: %d %s", st, w)
	}
	cp.setDown(0)

	// A control plane that answers with something that is not an error body: bad_response, whatever the text says.
	for name, serve := range map[string]http.HandlerFunc{
		"html": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(502)
			_, _ = w.Write([]byte("<html>Bad gateway: secret-detail</html>"))
		},
		"text word": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(500)
			_, _ = w.Write([]byte(`{"ok":false,"error":"Not A Word!"}`))
		},
		"200 junk": func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"ok":true}`)) },
		"200 other device": func(w http.ResponseWriter, r *http.Request) {
			a := AuthorizeResponse{DeviceID: randomHex(16), Label: label20(), Status: statusActive, Plan: "paid"}
			a.Host = a.Label + "." + testZone
			a.ValidUntil, a.ServerTime = e.now().Unix()+3600, e.now().Unix()
			a.Policy = okPolicy{20, 45, 1800, 14400, 300}
			_, _ = w.Write([]byte(canonicalJSON(a.toMap())))
		},
		"too large": func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(bytes.Repeat([]byte("x"), maxControlBody+10))
		},
	} {
		srv := httptest.NewTLSServer(serve)
		other, err := NewHTTPControl(HTTPControlConfig{BaseURL: srv.URL, NodeID: testNodeID, KID: cp.nodeKID, Key: cp.nodeKey, Client: srv.Client()})
		if err != nil {
			t.Fatal(err)
		}
		_, aerr := other.Authorize(context.Background(), AuthorizeRequest{DeviceID: d.id, SessionJTI: randomHex(12), Reason: "hello", Node: testNodeID})
		srv.Close()
		if aerr == nil {
			// the answer for another device parses; the node's own check (checkAuthorize) is what refuses it, below
			if name != "200 other device" {
				t.Errorf("%s: accepted", name)
			}
			continue
		}
		if ce, ok := aerr.(*ControlError); ok && strings.Contains(ce.Code, "secret") {
			t.Errorf("%s: text from the network became a word: %q", name, ce.Code)
		}
		if errForControl(aerr) != codeControlUnavailable && name != "text word" {
			t.Errorf("%s: %q", name, errForControl(aerr))
		}
	}
}

func TestControlPlane_ARedirectIsNeverFollowed(t *testing.T) {
	e, cp := httpNode(t, nil, nil)
	d := e.newDevice()
	var landed atomic.Int64
	elsewhere := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		landed.Add(1)
		_, _ = w.Write([]byte("{}"))
	}))
	defer elsewhere.Close()
	cp.mu.Lock()
	cp.redirect = elsewhere.URL + authorizePath
	cp.mu.Unlock()
	_, err := cp.control().Authorize(context.Background(), AuthorizeRequest{DeviceID: d.id, SessionJTI: randomHex(12), Reason: "hello", Node: testNodeID})
	if err == nil || landed.Load() != 0 {
		t.Fatalf("a redirect was followed: err=%v landed=%d", err, landed.Load())
	}
}

func TestControlPlane_AnAnswerThatIsNotWhatWasAskedIsNeverRelayed(t *testing.T) {
	// The control plane answers for another device: the node refuses to relay it (checkAuthorize) and the device is told control_unavailable.
	e, _ := httpNode(t, nil, nil)
	d := e.newDevice()
	e.cp.set(d.id, &devicePlan{host: d.host, answer: func(int) AuthorizeResponse {
		a := AuthorizeResponse{DeviceID: randomHex(16), Label: label20(), Status: statusActive, Plan: "paid", Nodes: []any{}}
		a.Host = a.Label + "." + testZone
		a.ValidUntil, a.ServerTime = e.now().Unix()+3600, e.now().Unix()
		a.Policy = okPolicy{20, 45, 1800, 14400, 300}
		return a
	}})
	dc := e.connect(d)
	line := dc.hello(func() string { return e.session(d, nil) }, func(s, n string) string { return e.proof(d, s, n, nil) })
	if line != "ERR control_unavailable" || e.srv.Online(d.host) {
		t.Fatalf("an answer for another device: %q", line)
	}
}

func TestControlPlane_TheHostNeverComesFromTheRequest(t *testing.T) {
	e, cp := httpNode(t, nil, nil)
	d := e.newDevice()
	if _, err := cp.control().Authorize(context.Background(), AuthorizeRequest{DeviceID: d.id, SessionJTI: randomHex(12), Reason: "hello", Node: testNodeID}); err != nil {
		t.Fatal(err)
	}
	cp.mu.Lock()
	bodies := append([][]byte(nil), cp.bodies...)
	cp.mu.Unlock()
	if len(bodies) != 1 {
		t.Fatalf("bodies %d", len(bodies))
	}
	doc, perr := parseJSON(string(bodies[0]))
	if perr != nil {
		t.Fatal(perr)
	}
	m := doc.(map[string]any)
	if len(m) != 5 || m["host"] != nil || m["label"] != nil {
		t.Fatalf("the authorize body %s", bodies[0])
	}
	if errs := ctSchemaSet.validate("authorize-request.schema.json", doc); len(errs) > 0 {
		t.Fatalf("not an authorize-request: %v", errs)
	}
}

func TestControlPlane_ConfigurationIsValidated(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	good := HTTPControlConfig{BaseURL: "https://api.example.test", NodeID: "t1", KID: "k1", Key: priv}
	if _, err := NewHTTPControl(good); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*HTTPControlConfig){
		"plain http":      func(c *HTTPControlConfig) { c.BaseURL = "http://api.example.test" },
		"a path":          func(c *HTTPControlConfig) { c.BaseURL = "https://api.example.test/v1" },
		"credentials":     func(c *HTTPControlConfig) { c.BaseURL = "https://user:pw" + "@api.example.test" },
		"a query":         func(c *HTTPControlConfig) { c.BaseURL = "https://api.example.test?x=1" },
		"no host":         func(c *HTTPControlConfig) { c.BaseURL = "https://" },
		"bad node id":     func(c *HTTPControlConfig) { c.NodeID = "T1" },
		"bad kid":         func(c *HTTPControlConfig) { c.KID = "" },
		"no key":          func(c *HTTPControlConfig) { c.Key = nil },
		"a short key":     func(c *HTTPControlConfig) { c.Key = priv[:10] },
		"garbage":         func(c *HTTPControlConfig) { c.BaseURL = "::not a url" },
		"another scheme":  func(c *HTTPControlConfig) { c.BaseURL = "ftp://api.example.test" },
		"whitespace host": func(c *HTTPControlConfig) { c.BaseURL = "https://api example.test" },
	} {
		c := good
		mutate(&c)
		if _, err := NewHTTPControl(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// the port 443 is not part of the URL the control plane's runtime sees
	c := good
	c.BaseURL = "https://api.example.test:443"
	hc, err := NewHTTPControl(c)
	if err != nil || hc.hostHTU != "api.example.test" {
		t.Fatalf("hostHTU %q err %v", hc.hostHTU, err)
	}
	c.BaseURL = "https://api.example.test:8443"
	if hc, _ = NewHTTPControl(c); hc.hostHTU != "api.example.test:8443" {
		t.Fatalf("hostHTU %q", hc.hostHTU)
	}
}

func TestNodeKey_FileRulesAndTheEntryThatRegistersIt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node.key")
	key, err := GenerateNodeKey(path)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	if _, err := GenerateNodeKey(path); err == nil {
		t.Fatal("a key was overwritten")
	}
	loaded, err := LoadNodeKey(path)
	if err != nil || !loaded.Equal(key) {
		t.Fatalf("load: %v", err)
	}
	// a key that others can read is refused, as ssh refuses it
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadNodeKey(path); err == nil {
		t.Fatal("a world-readable key was accepted")
	}
	// systemd's credential copy is 0440 with an ACL for the unit's user: accepted only inside $CREDENTIALS_DIRECTORY, and never world-readable
	if err := os.Chmod(path, 0o440); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadNodeKey(path); err == nil {
		t.Fatal("a group-readable key outside the credentials directory was accepted")
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	if loaded, err := LoadNodeKey(path); err != nil || !loaded.Equal(key) {
		t.Fatalf("the systemd credential copy was refused: %v", err)
	}
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadNodeKey(path); err == nil {
		t.Fatal("a world-readable key in the credentials directory was accepted")
	}
	t.Setenv("CREDENTIALS_DIRECTORY", filepath.Join(dir, "elsewhere"))
	if err := os.Chmod(path, 0o440); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadNodeKey(path); err == nil {
		t.Fatal("a group-readable key outside the credentials directory was accepted")
	}
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	_ = os.Chmod(path, 0o600)
	for name, content := range map[string]string{"garbage": "not pem", "a certificate": "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"} {
		bad := filepath.Join(dir, name)
		if err := os.WriteFile(bad, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadNodeKey(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := LoadNodeKey(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("a missing key was accepted")
	}

	// the entry is a valid TUNNEL_NODE_KEYS document of the contracts, for exactly this key
	entry := NodeKeysEntry("t1", "node-t1-1", key)
	doc, perr := parseJSON(entry)
	if perr != nil {
		t.Fatal(perr)
	}
	keys, word := ctParseNodeKeys(doc)
	if word != "" || keys["node-t1-1"].node != "t1" || keys["node-t1-1"].x != b64Encode(key.Public().(ed25519.PublicKey)) {
		t.Fatalf("entry %s -> %v %q", entry, keys, word)
	}
	var round map[string]any
	if json.Unmarshal([]byte(entry), &round) != nil {
		t.Fatal("entry is not JSON")
	}
}

func TestProductionBinary_InitPrintsTheRegistrationEntryAndRefusesWithoutAKey(t *testing.T) {
	bin := productionBinary(t)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "node.key")
	run := func(args ...string) (string, int) {
		cmd := exec.Command(bin, args...)
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		err := cmd.Run()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
		return out.String() + errb.String(), code
	}
	out, code := run("-node-id", "t1", "-node-kid", "node-t1-1", "-node-key-file", keyPath, "-node-key-init")
	if code != 0 {
		t.Fatalf("init: %d %s", code, out)
	}
	doc, err := parseJSON(strings.TrimSpace(out))
	if err != nil {
		t.Fatalf("init printed %q", out)
	}
	if _, word := ctParseNodeKeys(doc); word != "" {
		t.Fatalf("init printed an entry the contracts refuse: %s", word)
	}
	if out2, code := run("-node-id", "t1", "-node-kid", "node-t1-1", "-node-key-file", keyPath, "-node-key-print"); code != 0 || strings.TrimSpace(out2) != strings.TrimSpace(out) {
		t.Fatalf("print: %d %q", code, out2)
	}
	if _, code := run("-node-id", "t1", "-node-kid", "node-t1-1", "-node-key-file", keyPath, "-node-key-init"); code == 0 {
		t.Fatal("init overwrote the key")
	}
	if out, code := run("-node-id", "t1", "-node-host", testNodeHost); code == 0 || !strings.Contains(out, "signing key") {
		t.Fatalf("without a key: %d %s", code, out)
	}
	if out, code := run("-node-id", "t1", "-node-host", testNodeHost, "-node-key-file", keyPath, "-node-kid", "node-t1-1", "-control-url", "http://plain.example.test"); code == 0 || !strings.Contains(out, "https") {
		t.Fatalf("plain http control plane: %d %s", code, out)
	}
}

// ---------------------------------------------------------------------------------------------------------------------------- authorize concurrency over HTTP

func TestControlPlane_AuthorizeNeverRunsMoreThanFiftyAtOnceOverHTTP(t *testing.T) {
	if policyData.Authorization.AuthorizeMaxConcur != 50 {
		t.Fatalf("the plan says 50 concurrent authorizations, the policy says %d", policyData.Authorization.AuthorizeMaxConcur)
	}
	e, cp := httpNode(t, nil, func(c *Config) { c.HelloTimeout, c.FirstLineTimeout = 10*time.Second, 20*time.Second })
	cp.mu.Lock()
	cp.delay = 80 * time.Millisecond
	cp.mu.Unlock()
	const devices = 160
	var all []*testDevice
	for i := 0; i < devices; i++ {
		all = append(all, e.newDevice())
	}
	var connected atomic.Int64
	var wg sync.WaitGroup
	for _, d := range all {
		wg.Add(1)
		go func(d *testDevice) {
			defer wg.Done()
			// (a burst this size can overflow the listener's backlog: a device that is reset tries again, as one does)
			for attempt := 0; attempt < 40; attempt++ {
				line := helloOnce(e, d)
				if strings.HasPrefix(line, "OK ") {
					connected.Add(1)
					return
				}
				if line != "ERR control_unavailable" && !strings.HasPrefix(line, "unreachable") {
					t.Errorf("a device was refused: %q", line)
					return
				}
				time.Sleep(time.Duration(20+attempt*5) * time.Millisecond)
			}
		}(d)
	}
	wg.Wait()
	if connected.Load() != devices {
		t.Fatalf("%d of %d connected", connected.Load(), devices)
	}
	if peak := cp.maxInflight(); peak > 50 || peak < 2 {
		t.Fatalf("the control plane saw %d authorizations at once; the node's bound is 50", peak)
	}
}

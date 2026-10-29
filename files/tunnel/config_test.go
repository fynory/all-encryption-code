package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestConfig_RefusesWhatTheNodeCannotRunSafely(t *testing.T) {
	e := newTestEnv(t, nil)
	good := func() Config {
		cfg := DefaultConfig()
		cfg.NodeID, cfg.NodeHost, cfg.Keys, cfg.Control = testNodeID, testNodeHost, e.keys, e.cp
		cfg.CertSource = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, nil }
		return cfg
	}
	cfg := good()
	if _, err := NewServer(cfg); err != nil {
		t.Fatalf("the baseline configuration: %v", err)
	}
	for name, mutate := range map[string]func(*Config){
		"no node id":                      func(c *Config) { c.NodeID = "" },
		"a node id with a capital":        func(c *Config) { c.NodeID = "T1" },
		"a node id of 17 characters":      func(c *Config) { c.NodeID = strings.Repeat("a", 17) },
		"no node host":                    func(c *Config) { c.NodeHost = "" },
		"a node host with a capital":      func(c *Config) { c.NodeHost = "T1.nodes.all-e2e.test" },
		"a node host with a trailing dot": func(c *Config) { c.NodeHost = testNodeHost + "." },
		"a node host that is an address":  func(c *Config) { c.NodeHost = "192.0.2.1" },
		"a node host that is a device host": func(c *Config) {
			c.NodeHost = label20() + "." + testZone
		},
		"no certificate source": func(c *Config) { c.CertSource = nil },
		"no key source":         func(c *Config) { c.Keys = nil },
		"no control plane":      func(c *Config) { c.Control = nil },
		"port zero":             func(c *Config) { c.PublicPort = 0 },
		"port 70000":            func(c *Config) { c.PublicPort = 70000 },
		"a negative skew":       func(c *Config) { c.ClockSkew = -time.Second },
		"no stream limit":       func(c *Config) { c.MaxStreams = 0 },
		// WP06: nothing the policy bounds may be configured beyond it
		"a grace longer than the policy's":         func(c *Config) { c.Grace = secs(policyData.Authorization.GracePaidS) + time.Second },
		"a negative grace":                         func(c *Config) { c.Grace = -time.Second },
		"a feed polled less often than the policy": func(c *Config) { c.Feed, c.FeedPoll = &scriptedFeed{}, secs(policyData.Timing.FeedPollS)+time.Second },
		"a feed polled in no time":                 func(c *Config) { c.Feed, c.FeedPoll = &scriptedFeed{}, 0 },
		"a negative drain":                         func(c *Config) { c.DrainQuiet = -time.Second },
		"a drain of two days":                      func(c *Config) { c.DrainQuiet = 48 * time.Hour },
	} {
		cfg := good()
		mutate(&cfg)
		if _, err := NewServer(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// a configuration with the public listener off needs no own name or certificate
	cfg = good()
	cfg.HTTPSAddr, cfg.NodeHost, cfg.CertSource = "", "", nil
	if _, err := NewServer(cfg); err != nil {
		t.Errorf("no public listener: %v", err)
	}
}

func TestRun_TheProductionBuildNeedsItsSigningKeyAndTheOld11FlagsAreGone(t *testing.T) {
	var out, errb bytes.Buffer
	if rc := run([]string{"-version"}, &out, &errb); rc != 0 || !strings.HasPrefix(out.String(), "all-tunnel ") {
		t.Fatalf("-version: %d %q %q", rc, out.String(), errb.String())
	}
	errb.Reset()
	// without its signing key (or, in the test node's build, without its fakes) the node does not start: it never runs without verifying anyone
	if rc := run([]string{"-node-id", "t1", "-node-host", testNodeHost}, io.Discard, &errb); rc != 1 ||
		(!strings.Contains(errb.String(), "signing key") && !strings.Contains(errb.String(), "needs -test-jwks")) {
		t.Fatalf("no backend configured: %d %q", rc, errb.String())
	}
	if rc := run([]string{"-no-such-flag"}, io.Discard, io.Discard); rc != 2 {
		t.Fatalf("unknown flag: %d", rc)
	}
	if rc := run([]string{"-log-level", "loud"}, io.Discard, io.Discard); rc != 2 {
		t.Fatalf("bad log level: %d", rc)
	}
	for _, old := range []string{"-control-addr", "-state-dir", "-token-file", "-devices-file", "-host", "-gen-token"} {
		if rc := run([]string{old, "x"}, io.Discard, io.Discard); rc != 2 {
			t.Errorf("the 1.1 flag %s is still accepted (exit %d)", old, rc)
		}
	}
}

func TestFileCert_ReloadsWhenTheFilesChangeAndKeepsTheOneThatWorks(t *testing.T) {
	dir := t.TempDir()
	write := func(name string) {
		_, cert := makeCA(t, name)
		certPEM, keyPEM := pemOf(t, cert)
		if err := os.WriteFile(filepath.Join(dir, "c.pem"), certPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "k.pem"), keyPEM, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("one.example.test")
	fc, err := newCertReloader(filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem"), "", clock{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	fc.lookGap = 0 // the files are looked at on every call, so the test does not wait for the gap
	first, _ := fc.get(nil)
	again, _ := fc.get(nil)
	if first != again {
		t.Fatal("an unchanged file was parsed again")
	}
	time.Sleep(20 * time.Millisecond)
	write("two.example.test")
	second, err := fc.get(nil)
	if err != nil || fingerprintOf(second.Certificate[0]) == fingerprintOf(first.Certificate[0]) {
		t.Fatalf("a renewed certificate was not picked up: %v", err)
	}
	// a half-written renewal does not take the node down: the working certificate stays
	if err := os.WriteFile(filepath.Join(dir, "c.pem"), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	kept, err := fc.get(nil)
	if err != nil || kept != second {
		t.Fatalf("a failed reload must keep the certificate that works: %v", err)
	}
	if _, err := newCertReloader(filepath.Join(dir, "missing"), filepath.Join(dir, "k.pem"), "", clock{}, nil); err == nil {
		t.Fatal("a node cannot start without its certificate")
	}
}

// ------------------------------------------------------------------------------------------------------------------------------------
// The test-node binary (ALL_TEST_NODE_BIN)
// ------------------------------------------------------------------------------------------------------------------------------------

var (
	testNodeOnce sync.Once
	testNodePath string
	testNodeErr  error
)

// testNodeBinary is the binary the device's tests run against: ALL_TEST_NODE_BIN when set, otherwise this package built with -tags testnode.
func testNodeBinary(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("ALL_TEST_NODE_BIN"); p != "" {
		return p
	}
	testNodeOnce.Do(func() {
		goBin, err := exec.LookPath("go")
		if err != nil {
			if _, serr := os.Stat("/opt/homebrew/bin/go"); serr != nil {
				testNodeErr = err
				return
			}
			goBin = "/opt/homebrew/bin/go"
		}
		dir, err := os.MkdirTemp("", "all-tunnel-testnode-*")
		if err != nil {
			testNodeErr = err
			return
		}
		testNodePath = filepath.Join(dir, "all-tunnel-testnode")
		out, err := exec.Command(goBin, "build", "-tags", "testnode", "-o", testNodePath, ".").CombinedOutput()
		if err != nil {
			testNodeErr = &exec.ExitError{Stderr: out}
			t.Logf("go build: %s", out)
		}
	})
	if testNodeErr != nil {
		t.Skipf("cannot build the test node: %v", testNodeErr)
	}
	return testNodePath
}

var (
	prodBinOnce sync.Once
	prodBinPath string
	prodBinErr  error
)

// productionBinary is this package built the way it is deployed (no test tags): the node a device really meets.
func productionBinary(t *testing.T) string {
	t.Helper()
	prodBinOnce.Do(func() {
		goBin, err := exec.LookPath("go")
		if err != nil {
			if _, serr := os.Stat("/opt/homebrew/bin/go"); serr != nil {
				prodBinErr = err
				return
			}
			goBin = "/opt/homebrew/bin/go"
		}
		dir, err := os.MkdirTemp("", "all-tunnel-prod-*")
		if err != nil {
			prodBinErr = err
			return
		}
		prodBinPath = filepath.Join(dir, "all-tunnel")
		if out, err := exec.Command(goBin, "build", "-o", prodBinPath, ".").CombinedOutput(); err != nil {
			prodBinErr = &exec.ExitError{Stderr: out}
			t.Logf("go build: %s", out)
		}
	})
	if prodBinErr != nil {
		t.Skipf("cannot build the production node: %v", prodBinErr)
	}
	return prodBinPath
}

func TestMain(m *testing.M) {
	code := m.Run()
	if testNodePath != "" {
		_ = os.RemoveAll(filepath.Dir(testNodePath))
	}
	if prodBinPath != "" {
		_ = os.RemoveAll(filepath.Dir(prodBinPath))
	}
	os.Exit(code)
}

func jwksFile(t *testing.T, path, kid string, pub ed25519.PublicKey) {
	t.Helper()
	doc := map[string]any{"keys": []any{map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64Encode(pub), "kid": kid, "alg": "EdDSA", "use": "sig", "key_ops": []any{"verify"}}}}
	if err := os.WriteFile(path, []byte(canonicalJSON(doc)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeControl(t *testing.T, path string, devices map[string]any) {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"devices": devices})
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// TestTestNodeBinary_RunsTheRealProtocolAgainstAFileDrivenControlPlane starts the test-node program, plays a device against it and a client of
// the device, changes the fake control plane while it runs and stops it with SIGTERM.
func TestTestNodeBinary_RunsTheRealProtocolAgainstAFileDrivenControlPlane(t *testing.T) {
	bin := testNodeBinary(t)
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	jwks, control, calls, certOut := filepath.Join(dir, "jwks.json"), filepath.Join(dir, "control.json"), filepath.Join(dir, "calls.jsonl"), filepath.Join(dir, "node.pem")
	jwksFile(t, jwks, testKID, pub)

	e := &testEnv{t: t, cpKey: priv, tapByID: map[string]*bytes.Buffer{}}
	e.srv = &Server{nodeURL: nodeProofURL(testNodeHost, 443)}
	d := e.newDeviceNoPlan()
	writeControl(t, control, map[string]any{d.id: map[string]any{"host": d.host, "status": "active", "plan": "paid", "valid_for_s": 60}})

	cmd := exec.Command(bin, "-https-addr", "127.0.0.1:0", "-http-addr", "127.0.0.1:0", "-node-id", testNodeID, "-node-host", testNodeHost,
		"-test-jwks", jwks, "-test-control", control, "-test-calls", calls, "-test-cert-out", certOut, "-log-level", "info")
	stdout, _ := cmd.StdoutPipe()
	var logs syncBuf
	cmd.Stderr = &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	ready := make(chan map[string]any, 1)
	go func() {
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil {
			ready <- m
		}
	}()
	var info map[string]any
	select {
	case info = <-ready:
	case <-time.After(20 * time.Second):
		t.Fatalf("the test node did not announce itself:\n%s", logs.String())
	}
	if info["ready"] != true || info["node_id"] != testNodeID || info["node_host"] != testNodeHost {
		t.Fatalf("ready line %v", info)
	}
	e.httpsAddr, e.httpAddr = info["https"].(string), info["http"].(string)
	certPEM, err := os.ReadFile(certOut)
	if err != nil {
		t.Fatal(err)
	}
	e.nodePool = x509.NewCertPool()
	if !e.nodePool.AppendCertsFromPEM(certPEM) {
		t.Fatal("the node's certificate file is not PEM")
	}

	dc := e.connectOK(d)
	if body := dc.ok["body"].(map[string]any); body["host"] != d.host || body["status"] != "active" {
		t.Fatalf("OK %v", body)
	}
	ds := dc.serve(nil)
	c, err := e.clientTLS(d)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := postOver(c, d.host, []byte("via-binary-"+marker)); err != nil || string(resp) != "echo:via-binary-"+marker {
		t.Fatalf("resp=%q err=%v\nlogs:\n%s", resp, err, logs.String())
	}
	_ = c.Close()

	// the file is read again at every authorize: this renewal is refused, the next one answers gated
	writeControl(t, control, map[string]any{d.id: map[string]any{"host": d.host, "error": map[string]any{"status": 402, "code": "license_inactive"}}})
	if r := dc.renew(); r != "ERR license_inactive" {
		t.Fatalf("renew with the control plane refusing: %q", r)
	}
	writeControl(t, control, map[string]any{d.id: map[string]any{"host": d.host, "status": "gated", "plan": "trial", "valid_for_s": 900}})
	if r := dc.renew(); r != "ERR busy" { // the production gap between two RENEWs
		t.Fatalf("a renew right after another: %q", r)
	}
	time.Sleep(1200 * time.Millisecond)
	if r := dc.renew(); !strings.HasPrefix(r, "OK ") || !strings.Contains(r, `"status":"gated"`) {
		t.Fatalf("renew answering gated: %q", r)
	}
	// a device the file does not know is refused
	stranger := e.newDeviceNoPlan()
	sc := e.connect(stranger)
	if r := sc.hello(func() string { return e.session(stranger, nil) }, func(s, n string) string { return e.proof(stranger, s, n, nil) }); r != "ERR device_revoked" {
		t.Fatalf("unknown device: %q", r)
	}
	// every authorize was logged with its reason
	raw, _ := os.ReadFile(calls)
	if n := strings.Count(string(raw), `"reason":"renew"`); n != 2 || strings.Count(string(raw), `"reason":"hello"`) != 2 {
		t.Fatalf("calls file:\n%s", raw)
	}
	// ACME path through the binary: only the node's own name, and nothing without a webroot
	if out := acmeGet(t, e, "GET", "/.well-known/acme-challenge/anything", testNodeHost); !strings.HasPrefix(out, "HTTP/1.1 404") {
		t.Fatalf("acme: %q", out)
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-exited:
		if err != nil {
			t.Fatalf("exit: %v\nlogs:\n%s", err, logs.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("did not exit on SIGTERM\nlogs:\n%s", logs.String())
	}
	<-ds.done
	// SIGTERM drains (WP06): the device is told to prefer the other node, and the node closes once its streams are gone
	if !containsLine(ds.otherLines(), "DRAIN "+strconv.Itoa(policyData.Timing.DrainQuietS)) || !containsLine(ds.otherLines(), "CLOSE drain") {
		t.Fatalf("the device was not told the node is draining: %q", ds.otherLines())
	}
	out := logs.String()
	for _, want := range []string{`"msg":"draining"`, `"msg":"drained"`, `"msg":"control_up"`, `"msg":"stream_close"`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in logs", want)
		}
	}
	for name, secret := range map[string]string{"marker": marker, "host": d.host, "device id": d.id, "session": dc.session} {
		if strings.Contains(out, secret) {
			t.Fatalf("the process logs name the %s", name)
		}
	}
}

func TestTestNodeBinary_RefusesToStartWithoutItsFakesOrWithABadConfiguration(t *testing.T) {
	bin := testNodeBinary(t)
	run := func(args ...string) (string, int) {
		cmd := exec.Command(bin, args...)
		var out bytes.Buffer
		cmd.Stderr, cmd.Stdout = &out, &out
		err := cmd.Run()
		if ee, ok := err.(*exec.ExitError); ok {
			return out.String(), ee.ExitCode()
		}
		return out.String(), 0
	}
	dir := t.TempDir()
	jwks, control := filepath.Join(dir, "j.json"), filepath.Join(dir, "c.json")
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	jwksFile(t, jwks, testKID, pub)
	writeControl(t, control, map[string]any{})
	base := []string{"-https-addr", "127.0.0.1:0", "-http-addr", "127.0.0.1:0", "-node-id", testNodeID, "-node-host", testNodeHost}
	for name, tc := range map[string]struct {
		args []string
		want string
		rc   int
	}{
		"no fakes":        {base, "needs -test-jwks and -test-control", 1},
		"skew too wide":   {append(append([]string{}, base...), "-test-jwks", jwks, "-test-control", control, "-clock-skew", "999"), "clock skew", 1},
		"bad node id":     {[]string{"-node-id", "T1", "-node-host", testNodeHost, "-test-jwks", jwks, "-test-control", control}, "node id", 1},
		"version":         {[]string{"-version"}, "all-tunnel", 0},
		"unknown flag":    {[]string{"-bogus"}, "flag provided but not defined", 2},
		"the old 1.1 pin": {[]string{"-control-addr", ":8443"}, "flag provided but not defined", 2},
	} {
		out, rc := run(tc.args...)
		if rc != tc.rc || !strings.Contains(out, tc.want) {
			t.Errorf("%s: exit %d, output %q", name, rc, out)
		}
	}
}

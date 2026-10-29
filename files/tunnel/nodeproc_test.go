package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// nodeProc is the test-node binary running as a process, with a device the fake control plane knows.
type nodeProc struct {
	e       *testEnv
	d       *testDevice
	cmd     *exec.Cmd
	exited  chan error
	logs    *syncBuf
	control string
	feed    string
	ready   map[string]any // the node's ready line
}

// launchTestNode starts the test node with one paid device (valid for validFor seconds) and the extra flags, and waits for its ready line.
func launchTestNode(t *testing.T, validFor int, extra ...string) *nodeProc {
	t.Helper()
	bin := testNodeBinary(t)
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	jwks, control, certOut := filepath.Join(dir, "jwks.json"), filepath.Join(dir, "control.json"), filepath.Join(dir, "node.pem")
	jwksFile(t, jwks, testKID, pub)
	e := &testEnv{t: t, cpKey: priv, tapByID: map[string]*bytes.Buffer{}}
	e.srv = &Server{nodeURL: nodeProofURL(testNodeHost, 443)}
	d := e.newDeviceNoPlan()
	writeControl(t, control, map[string]any{d.id: map[string]any{"host": d.host, "status": "active", "plan": "paid", "valid_for_s": validFor}})
	args := append([]string{"-https-addr", "127.0.0.1:0", "-http-addr", "127.0.0.1:0", "-node-id", testNodeID, "-node-host", testNodeHost,
		"-test-jwks", jwks, "-test-control", control, "-test-cert-out", certOut, "-log-level", "info"}, extra...)
	cmd := exec.Command(bin, args...)
	stdout, _ := cmd.StdoutPipe()
	p := &nodeProc{e: e, d: d, cmd: cmd, exited: make(chan error, 1), logs: &syncBuf{}, control: control}
	cmd.Stderr = p.logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { p.exited <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	ready := make(chan map[string]any, 1)
	go func() {
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil {
			ready <- m
		}
	}()
	select {
	case info := <-ready:
		e.httpsAddr = info["https"].(string)
		p.ready = info
	case <-time.After(20 * time.Second):
		t.Fatalf("the test node did not announce itself:\n%s", p.logs.String())
	}
	certPEM, err := os.ReadFile(certOut)
	if err != nil {
		t.Fatal(err)
	}
	e.nodePool = x509.NewCertPool()
	e.nodePool.AppendCertsFromPEM(certPEM)
	return p
}

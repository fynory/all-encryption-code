package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// marker is a recognizable plaintext. If it ever shows up in a buffer the node touched while splicing a TLS stream, the node could read content.
const marker = "MARKER-9f3a1c-PLAINTEXT-MUST-NOT-LEAK-7b2e"

const (
	testZone     = "devices.all-e2e.test"
	testNodeHost = "t1.nodes.all-e2e.test"
	testNodeID   = "t1"
	testKID      = "cp-test-1"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (s *syncBuf) Count(sub string) int { return strings.Count(s.String(), sub) }

// makeCA returns a CA pool and a leaf certificate for names, signed by it: this is what a DEVICE owns (the node never has the key), and what the
// node itself holds for its own name.
func makeCA(t testing.TB, names ...string) (*x509.CertPool, tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     names,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return pool, tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
}

// ---------------------------------------------------------------------------------------------------------------------------- control plane fake

// devicePlan is what the fake control plane answers for one device.
type devicePlan struct {
	host     string
	status   string // active (default), gated or paused
	plan     string // paid (default) or trial
	validFor time.Duration
	err      error                         // refuse instead of answering
	delay    time.Duration                 // answer late
	answer   func(n int) AuthorizeResponse // overrides everything, n is the call number of this device (1 = first)
}

type fakeControl struct {
	env *testEnv

	mu    sync.Mutex
	plans map[string]*devicePlan
	calls []AuthorizeRequest
	count map[string]int

	inflight, maxInflight int // calls being answered now, and the most there ever were at once
}

func (f *fakeControl) set(deviceID string, p *devicePlan) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.plans[deviceID] = p
}

func (f *fakeControl) callLog() []AuthorizeRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]AuthorizeRequest(nil), f.calls...)
}

func (f *fakeControl) callsFor(deviceID, reason string) int {
	n := 0
	for _, c := range f.callLog() {
		if c.DeviceID == deviceID && (reason == "" || c.Reason == reason) {
			n++
		}
	}
	return n
}

func (f *fakeControl) Authorize(ctx context.Context, req AuthorizeRequest) (AuthorizeResponse, error) {
	f.mu.Lock()
	f.calls = append(f.calls, req)
	f.count[req.DeviceID]++
	n := f.count[req.DeviceID]
	p := f.plans[req.DeviceID]
	f.inflight++
	f.maxInflight = max(f.maxInflight, f.inflight)
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.inflight--
		f.mu.Unlock()
	}()
	if p == nil {
		return AuthorizeResponse{}, &ControlError{Status: 401, Code: codeDeviceRevoked}
	}
	if p.delay > 0 {
		select {
		case <-time.After(p.delay):
		case <-ctx.Done():
			return AuthorizeResponse{}, ctx.Err()
		}
	}
	if p.err != nil {
		return AuthorizeResponse{}, p.err
	}
	if p.answer != nil {
		return p.answer(n), nil
	}
	now := f.env.now()
	status, plan := p.status, p.plan
	if status == "" {
		status = statusActive
	}
	if plan == "" {
		plan = "paid"
	}
	label, _, _ := strings.Cut(p.host, ".")
	t := policyData.Timing
	return AuthorizeResponse{
		DeviceID: req.DeviceID, Label: label, Host: p.host, Status: status, Plan: plan,
		ValidUntil: now.Unix() + int64(p.validFor/time.Second), ServerTime: now.Unix(),
		Policy: okPolicy{int64(t.PingIntervalS), int64(t.DeadPeerS), int64(t.StreamIdleS), int64(t.StreamMaxAgeS), int64(t.RenewBeforeValidUntilS)},
		Nodes:  []any{},
	}, nil
}

// ---------------------------------------------------------------------------------------------------------------------------- the environment

// testDevice is a device the tests play: an id, the Ed25519 key its sessions are bound to, and (for the clients that reach it) the TLS certificate
// it holds for its host.
type testDevice struct {
	id, label, host string
	key             ed25519.PrivateKey
	pool            *x509.CertPool
	cert            tls.Certificate
}

type testEnv struct {
	t        *testing.T
	srv      *Server
	logs     *syncBuf
	cp       *fakeControl
	keys     *SwapKeys
	cpKey    ed25519.PrivateKey
	nodePool *x509.CertPool

	httpsAddr, httpAddr string

	vip      *virtualIPs  // when set, connections made with vip.dial come from the addresses the test chose (hardening tests)
	offsetNS atomic.Int64 // the node's clock is the real one plus this
	clk      *fakeClock   // when set, the node's clock and timers are this one and the tests move it by hand

	tapMu   sync.Mutex
	tapAll  bytes.Buffer
	tapByID map[string]*bytes.Buffer

	traceMu sync.Mutex
	events  []any
	seq     int
}

func (e *testEnv) now() time.Time {
	if e.clk != nil {
		return e.clk.Now()
	}
	return time.Now().Add(time.Duration(e.offsetNS.Load()))
}

// newTestEnv starts a node (loopback, ephemeral ports) with a fake control plane and a key set whose private half the tests hold.
func newTestEnv(t *testing.T, mutate func(*Config)) *testEnv {
	return newEnv(t, nil, func(_ *testEnv, cfg *Config) {
		if mutate != nil {
			mutate(cfg)
		}
	})
}

// newClockEnv is newTestEnv on a clock the test moves by hand: every lifetime the node decides (valid_until, the grace, the feed's pace, the quiet
// period of a drain) follows it, so hours pass in an instant.
func newClockEnv(t *testing.T, mutate func(*Config)) *testEnv {
	return newEnv(t, newFakeClock(), func(_ *testEnv, cfg *Config) {
		if mutate != nil {
			mutate(cfg)
		}
	})
}

// newEnv builds the node; mutate gets the environment (its fake control plane, its keys, its clock) and the configuration before the node starts.
func newEnv(t *testing.T, clk *fakeClock, mutate func(*testEnv, *Config)) *testEnv {
	t.Helper()
	e := &testEnv{t: t, clk: clk, logs: &syncBuf{}, tapByID: map[string]*bytes.Buffer{}}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	e.cpKey = priv
	e.keys = NewSwapKeys(StaticKeys{testKID: pub})
	e.cp = &fakeControl{env: e, plans: map[string]*devicePlan{}, count: map[string]int{}}
	pool, nodeCert := makeCA(t, testNodeHost)
	e.nodePool = pool

	cfg := DefaultConfig()
	cfg.HTTPSAddr, cfg.HTTPAddr = "127.0.0.1:0", "127.0.0.1:0"
	cfg.NodeID, cfg.NodeHost = testNodeID, testNodeHost
	cfg.CertSource = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &nodeCert, nil }
	cfg.Keys, cfg.Control = e.keys, e.cp
	cfg.Now = e.now
	if clk != nil {
		cfg.AfterFunc = clk.AfterFunc
	}
	cfg.MinRenewGap = 0 // tests renew in quick succession; the test of the gap sets its own
	// Every test client and device comes from loopback: one source. The per-source limits (limits_test.go gives its own) would make a crowd of devices
	// in a test look like one attacker, so they are out of the way here.
	cfg.PerIPConcurrent, cfg.PerIPNewPerS = 1<<20, 1<<20
	cfg.UnknownSNIPerIP, cfg.LabelNewPerS, cfg.LabelNewBurst = 1<<20, 1<<20, 1<<20
	cfg.LabelAnonSlice = cfg.MaxStreamsPerHost // and every test client is anonymous: the slices have their own tests
	cfg.HelloTimeout = 2 * time.Second
	cfg.AttachTimeout = 3 * time.Second
	cfg.FirstLineTimeout = 3 * time.Second
	cfg.StreamIdle = 20 * time.Second
	cfg.StreamMaxAge = time.Minute
	cfg.HalfCloseTimeout = 5 * time.Second
	cfg.ACMETimeout = 5 * time.Second
	cfg.Logger = slog.New(slog.NewJSONHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg.tap = func(id, dir string, p []byte) {
		e.tapMu.Lock()
		defer e.tapMu.Unlock()
		e.tapAll.Write(p)
		b := e.tapByID[id]
		if b == nil {
			b = &bytes.Buffer{}
			e.tapByID[id] = b
		}
		b.Write(p)
	}
	cfg.trace = func(ev map[string]any) {
		// the checker reads JSON values: numbers are float64, whatever the node used
		parsed, err := parseJSON(canonicalJSON(ev))
		if err != nil {
			panic(err)
		}
		e.traceMu.Lock()
		e.events = append(e.events, parsed)
		e.traceMu.Unlock()
	}
	if mutate != nil {
		mutate(e, &cfg)
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	e.srv = srv
	e.httpsAddr, e.httpAddr = srv.HTTPSAddr(), srv.HTTPAddr()
	t.Cleanup(func() { srv.Shutdown(2 * time.Second) })
	return e
}

func (e *testEnv) tapped(id string) []byte {
	e.tapMu.Lock()
	defer e.tapMu.Unlock()
	if b := e.tapByID[id]; b != nil {
		return append([]byte(nil), b.Bytes()...)
	}
	return nil
}

func (e *testEnv) tappedAll() []byte {
	e.tapMu.Lock()
	defer e.tapMu.Unlock()
	return append([]byte(nil), e.tapAll.Bytes()...)
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// label20 is a label of the contracts' alphabet.
func label20() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

// newDevice makes a device and tells the fake control plane about it (host under the test zone, paid, valid for an hour unless changed).
func (e *testEnv) newDevice() *testDevice {
	d := e.newDeviceNoPlan()
	e.cp.set(d.id, &devicePlan{host: d.host, validFor: time.Hour})
	return d
}

// newDeviceNoPlan makes a device the control plane has not been told about.
func (e *testEnv) newDeviceNoPlan() *testDevice {
	e.t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		e.t.Fatal(err)
	}
	d := &testDevice{id: randomHex(16), label: label20(), key: priv}
	d.host = d.label + "." + testZone
	d.pool, d.cert = makeCA(e.t, d.host)
	return d
}

func (e *testEnv) plan(d *testDevice) *devicePlan {
	e.cp.mu.Lock()
	defer e.cp.mu.Unlock()
	return e.cp.plans[d.id]
}

// ---------------------------------------------------------------------------------------------------------------------------- tokens

func signJWS(key ed25519.PrivateKey, header, claims map[string]any) string {
	h := b64Encode([]byte(canonicalJSON(header)))
	c := b64Encode([]byte(canonicalJSON(claims)))
	input := h + "." + c
	return input + "." + b64Encode(ed25519.Sign(key, []byte(input)))
}

// session mints a device session for d as the control plane would (aud all-tunnel, 300 s). mutate changes the claims or the header before signing.
func (e *testEnv) session(d *testDevice, mutate func(header, claims map[string]any)) string {
	return e.sessionSignedBy(e.cpKey, d, mutate)
}

// sessionSignedBy is session signed with another key (a forger's).
func (e *testEnv) sessionSignedBy(signer ed25519.PrivateKey, d *testDevice, mutate func(header, claims map[string]any)) string {
	iat := e.now().Unix()
	pub := d.key.Public().(ed25519.PublicKey)
	header := map[string]any{"alg": "EdDSA", "typ": "device-session", "kid": testKID}
	claims := map[string]any{
		"typ": "device-session", "ver": 2, "iss": policyData.Identity.Issuer, "aud": policyData.Identity.AudTunnel, "sub": d.id,
		"iat": iat, "exp": iat + int64(policyData.Authorization.SessionTTLS), "jti": randomHex(12), "generation": 1,
		"cnf": map[string]any{"jwk": map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64Encode(pub)}},
	}
	if mutate != nil {
		mutate(header, claims)
	}
	return signJWS(signer, header, claims)
}

// proof mints the DPoP proof of d over session and nonce for the node's URL.
func (e *testEnv) proof(d *testDevice, session, nonce string, mutate func(header, claims map[string]any)) string {
	pub := d.key.Public().(ed25519.PublicKey)
	header := map[string]any{"alg": "EdDSA", "typ": "dpop+jwt", "jwk": map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64Encode(pub)}}
	claims := map[string]any{
		"sub": d.id, "aud": policyData.Identity.AudTunnel, "htm": policyData.Protocol.ProofHTM, "htu": e.srv.nodeURL, "iat": e.now().Unix(),
		"jti": randomHex(12), "ath": sha256B64([]byte(session)), "nonce": nonce,
	}
	if mutate != nil {
		mutate(header, claims)
	}
	return signJWS(d.key, header, claims)
}

// ---------------------------------------------------------------------------------------------------------------------------- device side

// dialNode connects to the node's own name the way a device does: TLS 1.3, the node's public certificate, ALPN all-tunnel/2.
func (e *testEnv) dialNode() (*tls.Conn, error) {
	return tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", e.httpsAddr, &tls.Config{
		ServerName: testNodeHost, RootCAs: e.nodePool, NextProtos: []string{policyData.Protocol.ALPN}, MinVersion: tls.VersionTLS13,
	})
}

// devConn is the control connection of a device, played by a test.
type devConn struct {
	t  *testing.T
	e  *testEnv
	d  *testDevice
	c  *tls.Conn
	br *bufio.Reader

	session string
	ok      message // the parsed OK, once the handshake finished

	feed chan string // once a devServer reads the connection, the lines that are not OPEN arrive here (closed at the end of the connection)
}

func (e *testEnv) connect(d *testDevice) *devConn {
	e.t.Helper()
	c, err := e.dialNode()
	if err != nil {
		e.t.Fatal(err)
	}
	dc := &devConn{t: e.t, e: e, d: d, c: c, br: bufio.NewReaderSize(c, 1<<17)}
	e.t.Cleanup(func() { _ = c.Close() })
	return dc
}

func (dc *devConn) send(line string) {
	dc.t.Helper()
	_ = dc.c.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(dc.c, line+"\n"); err != nil {
		dc.t.Fatalf("send %.40q: %v", line, err)
	}
}

// try reads one line within timeout.
func (dc *devConn) try(timeout time.Duration) (string, error) {
	if dc.feed != nil {
		select {
		case line, ok := <-dc.feed:
			if !ok {
				return "", io.EOF
			}
			return line, nil
		case <-time.After(timeout):
			return "", &net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}
		}
	}
	_ = dc.c.SetReadDeadline(time.Now().Add(timeout))
	b, err := dc.br.ReadString('\n')
	if err != nil {
		return strings.TrimSuffix(b, "\n"), err
	}
	return strings.TrimSuffix(b, "\n"), nil
}

func (dc *devConn) recv() string {
	dc.t.Helper()
	line, err := dc.try(5 * time.Second)
	if err != nil {
		dc.t.Fatalf("no line from the node: %q %v", line, err)
	}
	return line
}

// expectClosed asserts the node closes the connection within timeout (any lines before the close are returned).
func (dc *devConn) expectClosed(timeout time.Duration) []string {
	dc.t.Helper()
	var lines []string
	deadline := time.Now().Add(timeout)
	for {
		line, err := dc.try(time.Until(deadline))
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				dc.t.Fatalf("connection still open after %s (lines so far %q)", timeout, lines)
			}
			return lines
		}
		lines = append(lines, line)
	}
}

// hello performs HELLO and PROOF and returns the node's answer line (CHALLENGE and OK, or an ERR at any step) without judging it.
func (dc *devConn) hello(session func() string, proof func(session, nonce string) string) (final string) {
	dc.t.Helper()
	dc.session = session()
	dc.send("HELLO 2 " + dc.session)
	line := dc.recv()
	m, err := parseLine(line, dirN2D)
	if err != nil || m.str("verb") != "CHALLENGE" {
		return line
	}
	dc.send("PROOF " + proof(dc.session, m.str("nonce")))
	return dc.recv()
}

// connectOK completes the handshake for d with good tokens and fails the test unless the node says OK.
func (e *testEnv) connectOK(d *testDevice) *devConn {
	e.t.Helper()
	dc := e.connect(d)
	line := dc.hello(func() string { return e.session(d, nil) }, func(s, n string) string { return e.proof(d, s, n, nil) })
	m, err := parseLine(line, dirN2D)
	if err != nil || m.str("verb") != "OK" {
		e.t.Fatalf("handshake for %s: %q", d.id, line)
	}
	dc.ok = m
	return dc
}

// helloAsync runs a whole HELLO for d on its own connection in the background and delivers the node's final line (or the error that ended the
// exchange); it never calls t.Fatal, so it is safe off the test goroutine.
func (e *testEnv) helloAsync(d *testDevice) <-chan string {
	out := make(chan string, 1)
	c, err := e.dialNode()
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = c.Close() })
	go func() {
		br := bufio.NewReader(c)
		read := func() string {
			_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
			l, err := br.ReadString('\n')
			if err != nil {
				return "read error: " + err.Error()
			}
			return strings.TrimSuffix(l, "\n")
		}
		session := e.session(d, nil)
		_, _ = io.WriteString(c, "HELLO 2 "+session+"\n")
		line := read()
		if nonce, ok := strings.CutPrefix(line, "CHALLENGE "); ok {
			_, _ = io.WriteString(c, "PROOF "+e.proof(d, session, nonce, nil)+"\n")
			line = read()
		}
		out <- line
	}()
	return out
}

// renew sends RENEW with a fresh session, answers the CHALLENGE and returns the final line.
func (dc *devConn) renew() string {
	dc.t.Helper()
	dc.session = dc.e.session(dc.d, nil)
	dc.send("RENEW " + dc.session)
	line := dc.recv()
	m, err := parseLine(line, dirN2D)
	if err != nil || m.str("verb") != "CHALLENGE" {
		return line
	}
	dc.send("PROOF " + dc.e.proof(dc.d, dc.session, m.str("nonce"), nil))
	return dc.recv()
}

// devServer plays the device's side of the streams: it reads the control connection, attaches every OPEN through a new data connection and
// serves it with handler. Lines that are not OPEN are kept for the test.
type devServer struct {
	dc       *devConn
	handler  func(c net.Conn)
	noAttach bool

	mu    sync.Mutex
	opens []message
	other []string
	wg    sync.WaitGroup
	done  chan struct{}
}

func (dc *devConn) serve(handler func(c net.Conn)) *devServer {
	ds := &devServer{dc: dc, handler: handler, done: make(chan struct{})}
	dc.feed = make(chan string, 1024)
	if handler == nil {
		ds.handler = ds.echo
	}
	go ds.loop()
	return ds
}

func (ds *devServer) loop() {
	defer close(ds.done)
	defer close(ds.dc.feed)
	for {
		_ = ds.dc.c.SetReadDeadline(time.Time{})
		line, err := ds.dc.br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSuffix(line, "\n")
		m, perr := parseLine(line, dirN2D)
		if perr == nil && m.str("verb") == "OPEN" {
			ds.mu.Lock()
			ds.opens = append(ds.opens, m)
			ds.mu.Unlock()
			if !ds.noAttach {
				ds.wg.Add(1)
				go ds.attach(m.str("stream_id"), m.str("secret"))
			}
			continue
		}
		ds.mu.Lock()
		ds.other = append(ds.other, line)
		ds.mu.Unlock()
		select {
		case ds.dc.feed <- line:
		default:
		}
	}
}

func (ds *devServer) attach(id, secret string) {
	defer ds.wg.Done()
	c, err := ds.dc.e.dialNode()
	if err != nil {
		return
	}
	defer c.Close()
	// No reply line: on success the raw stream starts right after ATTACH.
	fmt.Fprintf(c, "ATTACH %s %s\n", id, secret)
	ds.handler(c)
}

func (ds *devServer) openCount() int { ds.mu.Lock(); defer ds.mu.Unlock(); return len(ds.opens) }

func (ds *devServer) openList() []message {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	return append([]message(nil), ds.opens...)
}

func (ds *devServer) otherLines() []string {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	return append([]string(nil), ds.other...)
}

// seenRequest is what the device observed after TLS termination (plaintext).
type seenRequest struct {
	method, uri, host string
	header            http.Header
	body              []byte
}

var (
	seenMu   sync.Mutex
	seenByDS = map[*devServer][]seenRequest{}
)

func (ds *devServer) seen() []seenRequest {
	seenMu.Lock()
	defer seenMu.Unlock()
	return append([]seenRequest(nil), seenByDS[ds]...)
}

// echo is the default device behavior: terminate TLS with the device certificate and answer HTTP/1.1 requests with "echo:"+body.
func (ds *devServer) echo(c net.Conn) {
	tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{ds.dc.d.cert}, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		return
	}
	_ = tc.SetDeadline(time.Time{})
	br := bufio.NewReader(tc)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		body, _ := io.ReadAll(req.Body)
		seenMu.Lock()
		seenByDS[ds] = append(seenByDS[ds], seenRequest{method: req.Method, uri: req.RequestURI, host: req.Host, header: req.Header.Clone(), body: body})
		seenMu.Unlock()
		out := append([]byte("echo:"), body...)
		fmt.Fprintf(tc, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", len(out))
		if _, err := tc.Write(out); err != nil {
			return
		}
		if req.Close {
			return
		}
	}
}

// ---------------------------------------------------------------------------------------------------------------------------- client side

// clientTLS dials :443 as ChatGPT would: normal TLS verifying the DEVICE's certificate for d's host.
func (e *testEnv) clientTLS(d *testDevice) (*tls.Conn, error) {
	return tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", e.httpsAddr, &tls.Config{
		ServerName: d.host, RootCAs: d.pool, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12,
	})
}

// postOver sends one POST with the given body over c and returns the response body.
func postOver(c net.Conn, host string, body []byte) ([]byte, error) {
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	req, _ := http.NewRequest("POST", "https://"+host+"/mcp", bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	if err := req.Write(c); err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// rawExchange sends raw bytes to addr and returns everything read until EOF.
func rawExchange(t *testing.T, addr, request string) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, request); err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(c)
	return string(b)
}

func eventually(t *testing.T, what string, within time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func (e *testEnv) waitIdle() {
	e.t.Helper()
	eventually(e.t, "all streams closed", 5*time.Second, func() bool { return e.srv.streams.Load() == 0 })
}

// chunkConn writes in tiny pieces with a pause, so the node sees a ClientHello arriving over many TCP reads.
type chunkConn struct {
	net.Conn
	size  int
	delay time.Duration
}

func (c chunkConn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := min(c.size, len(p))
		w, err := c.Conn.Write(p[:n])
		total += w
		if err != nil {
			return total, err
		}
		p = p[n:]
		time.Sleep(c.delay)
	}
	return total, nil
}

// ---------------------------------------------------------------------------------------------------------------------------- the transcript

// transcriptDoc is the recording of the node in the contracts' format, closed with an end event, ready for ctCheckTranscript.
func (e *testEnv) transcriptDoc() map[string]any {
	e.traceMu.Lock()
	events := append([]any(nil), e.events...)
	e.traceMu.Unlock()
	events = append(events, map[string]any{"t": epochSeconds(e.now()), "ev": "end"})
	keys := map[string]any{}
	list := []any{}
	if k, ok := e.keys.Key(testKID); ok {
		keys = map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64Encode(k), "kid": testKID, "alg": "EdDSA", "use": "sig", "key_ops": []any{"verify"}}
		list = append(list, keys)
	}
	return map[string]any{
		"ctx": map[string]any{"node_id": testNodeID, "node_url": e.srv.nodeURL, "skew": float64(e.srv.cfg.ClockSkew / time.Second),
			"jwks": map[string]any{"keys": list}, "randoms": map[string]any{}},
		"events": events,
	}
}

// checkTranscript runs the contracts' checker over what the node did and fails the test on the first violation.
func (e *testEnv) checkTranscript() {
	e.t.Helper()
	if violation := ctCheckTranscript(e.transcriptDoc()); violation != "" {
		e.t.Fatalf("the node broke the contract: %s", violation)
	}
}

// pemOf is the PEM of a certificate chain and its ECDSA key.
func pemOf(t *testing.T, cert tls.Certificate) (certPEM, keyPEM []byte) {
	t.Helper()
	for _, der := range cert.Certificate {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	der, err := x509.MarshalECPrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	return certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

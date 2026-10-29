package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"math/rand/v2"
	"net"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// The cleartext handshake observer (observer.go): what the node reads of the first messages of a TLS handshake, and nothing else.

// recordedServerHello runs a TLS server with cfg against a client with ccfg over a pipe and returns the bytes the server sent first (until the client
// has what it needs): the device's side of a handshake, as the node would splice it.
func recordedServerHello(t testing.TB, scfg, ccfg *tls.Config) []byte {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var mu sync.Mutex
	var sent bytes.Buffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
		rec := &recordingConn{Conn: raw, onWrite: func(p []byte) { mu.Lock(); sent.Write(p); mu.Unlock() }}
		_ = tls.Server(rec, scfg).Handshake()
	}()
	c, err := net.DialTimeout("tcp", ln.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_ = tls.Client(c, ccfg).Handshake()
	c.Close()
	<-done
	mu.Lock()
	defer mu.Unlock()
	return append([]byte(nil), sent.Bytes()...)
}

type recordingConn struct {
	net.Conn
	onWrite func([]byte)
}

func (r *recordingConn) Write(p []byte) (int, error) {
	r.onWrite(p)
	return r.Conn.Write(p)
}

func testServerConfig(t testing.TB) *tls.Config {
	t.Helper()
	_, cert := makeCA(t, "observer.example.test")
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
}

func TestObserver_ClientHelloGroupsAndECH(t *testing.T) {
	hello := captureClientHello(t, &tls.Config{ServerName: "dev1.example.test", InsecureSkipVerify: true, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256}})
	scan := scanClientHello(hello)
	shape := shapeOfClientHello(scan.hello)
	if !shape.ok || shape.ech {
		t.Fatalf("%+v", shape)
	}
	words := map[string]bool{}
	for _, g := range shape.groups {
		words[groupWord(g)] = true
	}
	for _, want := range []string{"x25519mlkem768", "x25519", "secp256r1"} {
		if !words[want] {
			t.Errorf("offered groups %v lack %s", shape.groups, want)
		}
	}
	m := newMetrics()
	m.observeClientHello(hello)
	if m.obsHellos.Load() != 1 || m.obsOffered.get("x25519mlkem768") != 1 || m.obsOffered.get("x25519") != 1 || m.obsECH.Load() != 0 {
		t.Fatalf("counters: %d hellos, %d hybrid", m.obsHellos.Load(), m.obsOffered.get("x25519mlkem768"))
	}
	// a hello that is cut short, or not a hello, is not observed
	m.observeClientHello(hello[:len(hello)/2])
	m.observeClientHello([]byte("GET / HTTP/1.1\r\n"))
	if m.obsHellos.Load() != 1 {
		t.Fatal("an incomplete hello was observed")
	}
}

func TestObserver_ServerHelloOfEveryKindOfHandshake(t *testing.T) {
	cases := map[string]struct {
		server, client         *tls.Config
		version, cipher, group string
		retries                int64
	}{
		"tls 1.3 with the hybrid group": {
			&tls.Config{}, &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519}},
			"tls13", "tls_aes_128_gcm_sha256", "x25519mlkem768", 0,
		},
		"tls 1.3 with x25519 only": {
			&tls.Config{}, &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519}},
			"tls13", "tls_aes_128_gcm_sha256", "x25519", 0,
		},
		"tls 1.3 with chacha": {
			&tls.Config{CipherSuites: nil}, &tls.Config{CurvePreferences: []tls.CurveID{tls.CurveP256}},
			"tls13", "tls_aes_128_gcm_sha256", "secp256r1", 0,
		},
		"tls 1.2": {
			&tls.Config{}, &tls.Config{MaxVersion: tls.VersionTLS12},
			"tls12", "ecdhe_ecdsa_aes_128_gcm_sha256", "none", 0,
		},
		"a hello retry request": {
			&tls.Config{CurvePreferences: []tls.CurveID{tls.CurveP256}}, &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}},
			"tls13", "tls_aes_128_gcm_sha256", "secp256r1", 1,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			scfg := testServerConfig(t)
			scfg.CurvePreferences, scfg.CipherSuites = c.server.CurvePreferences, c.server.CipherSuites
			ccfg := &tls.Config{ServerName: "observer.example.test", InsecureSkipVerify: true, CurvePreferences: c.client.CurvePreferences, MaxVersion: c.client.MaxVersion}
			stream := recordedServerHello(t, scfg, ccfg)
			// the same bytes, whole and one at a time, give the same reading
			for _, chunk := range []int{len(stream), 1, 7} {
				m := newMetrics()
				w := newServerHelloWatch(m)
				for off := 0; off < len(stream); off += chunk {
					w.feed(stream[off:min(off+chunk, len(stream))])
				}
				if m.obsVersion.get(c.version) != 1 || m.obsCipher.get(c.cipher) != 1 || m.obsGroup.get(c.group) != 1 || m.obsRetry.Load() != c.retries || m.obsUnparsed.Load() != 0 {
					t.Fatalf("chunk %d: version %d cipher %d group %d retries %d unparsed %d\n%s", chunk, m.obsVersion.get(c.version), m.obsCipher.get(c.cipher),
						m.obsGroup.get(c.group), m.obsRetry.Load(), m.obsUnparsed.Load(), m.renderGroups())
				}
				if !w.done {
					t.Fatal("the watcher kept reading after the ServerHello")
				}
			}
		})
	}
}

func (m *metrics) renderGroups() string {
	var b bytes.Buffer
	m.obsVersion.write(&b)
	m.obsCipher.write(&b)
	m.obsGroup.write(&b)
	return b.String()
}

func TestObserver_ReadsNothingAfterTheServerHelloAndGivesUpOnWhatIsNotOne(t *testing.T) {
	scfg := testServerConfig(t)
	stream := recordedServerHello(t, scfg, &tls.Config{ServerName: "observer.example.test", InsecureSkipVerify: true})
	m := newMetrics()
	w := newServerHelloWatch(m)
	w.feed(stream)
	if m.obsVersion.get("tls13") != 1 {
		t.Fatal("not read")
	}
	before := len(w.buf)
	w.feed(bytes.Repeat([]byte{22, 3, 3, 0, 4, 2, 0, 0, 0}, 100)) // more "hellos": never looked at
	if m.obsVersion.get("tls13") != 1 || len(w.buf) != before {
		t.Fatal("the watcher read on after the ServerHello")
	}
	for name, first := range map[string][]byte{
		"an HTTP answer":              []byte("HTTP/1.1 200 OK\r\n\r\n"),
		"an alert":                    {21, 3, 3, 0, 2, 2, 40},
		"application data":            {23, 3, 3, 0, 5, 1, 2, 3, 4, 5},
		"a ServerHello that lies":     {22, 3, 3, 0, 8, 2, 0, 0, 40, 1, 2, 3, 4},
		"a certificate where a hello": {22, 3, 3, 0, 6, 11, 0, 0, 2, 0, 0},
	} {
		m := newMetrics()
		w := newServerHelloWatch(m)
		w.feed(first)
		if m.obsUnparsed.Load() != 1 || !w.done {
			t.Errorf("%s: unparsed %d, done %v", name, m.obsUnparsed.Load(), w.done)
		}
		w.feed(first)
		if m.obsUnparsed.Load() != 1 {
			t.Errorf("%s: counted twice", name)
		}
	}
	// a stream that never shows a hello in the observer's budget of bytes stops being watched
	m2 := newMetrics()
	w2 := newServerHelloWatch(m2)
	for i := 0; i < 20 && !w2.done; i++ {
		w2.feed(append([]byte{22, 3, 3, 0x03, 0xe8}, make([]byte, 500)...)) // a record that never completes
	}
	if !w2.done || m2.obsUnparsed.Load() != 1 || len(w2.buf) > maxObserved {
		t.Fatalf("done %v unparsed %d buffered %d", w2.done, m2.obsUnparsed.Load(), len(w2.buf))
	}
}

func TestObserver_NeverPanicsAndNeverReadsOutsideItsInput(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 11))
	hello := captureClientHello(t, &tls.Config{ServerName: "dev1.example.test", InsecureSkipVerify: true})
	scfg := testServerConfig(t)
	server := recordedServerHello(t, scfg, &tls.Config{ServerName: "observer.example.test", InsecureSkipVerify: true})
	m := newMetrics()
	for i := 0; i < 3000; i++ {
		b := make([]byte, rng.IntN(400))
		for j := range b {
			b[j] = byte(rng.IntN(256))
		}
		shapeOfClientHello(b)
		_, _ = parseServerHello(b)
		newServerHelloWatch(m).feed(b)
		// a real hello with bytes flipped and with its tail cut
		mut := append([]byte(nil), hello...)
		for k := 0; k < 3; k++ {
			mut[rng.IntN(len(mut))] ^= byte(1 << rng.IntN(8))
		}
		m.observeClientHello(mut[:rng.IntN(len(mut))+1])
		sv := append([]byte(nil), server...)
		sv[rng.IntN(len(sv))] ^= byte(1 << rng.IntN(8))
		w := newServerHelloWatch(m)
		w.feed(sv[:rng.IntN(len(sv))+1])
	}
}

func TestObserver_GREASEIsNotCountedAndWordsAreAClosedList(t *testing.T) {
	for _, g := range []uint16{0x0a0a, 0x1a1a, 0xfafa} {
		if !isGREASE(g) {
			t.Errorf("%#x is GREASE", g)
		}
	}
	if isGREASE(0x001d) || isGREASE(0x11ec) {
		t.Error("a real group was taken for GREASE")
	}
	m := newMetrics()
	m.obsOffered.inc("a group nobody has heard of")
	m.obsOffered.inc("another")
	if m.obsOffered.get("other") != 2 {
		t.Fatal("an unknown word is counted as other")
	}
	if groupWord(0x1234) != "other" || cipherWord(0x1234) != "other" || versionWord(0x7f1c) != "other" || groupWord(0x0100) != "ffdhe" {
		t.Fatal("the word tables")
	}
}

func TestNode_ObserverReportsTLSVersionCipherAndGroupForAGoClientIncludingTheHybrid(t *testing.T) {
	e := newTestEnv(t, nil)
	d := e.newDevice()
	dc := e.connectOK(d)
	dc.serve(nil)
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", e.httpsAddr, &tls.Config{
		ServerName: d.host, RootCAs: d.pool, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
	})
	if err != nil {
		t.Fatal(err)
	}
	if st := c.ConnectionState(); st.Version != tls.VersionTLS13 {
		t.Fatalf("the Go handshake itself: version %#x", st.Version)
	}
	if _, err := postOver(c, d.host, []byte("x")); err != nil {
		t.Fatal(err)
	}
	c.Close()
	m := e.srv.met
	if m.obsHellos.Load() != 1 || m.obsOffered.get("x25519mlkem768") != 1 || m.obsOffered.get("x25519") != 1 {
		t.Fatalf("offered:\n%s", e.srv.renderMetrics())
	}
	if m.obsVersion.get("tls13") != 1 || m.obsCipher.get("tls_aes_128_gcm_sha256") != 1 || m.obsGroup.get("x25519mlkem768") != 1 {
		t.Fatalf("selected:\n%s", e.srv.renderMetrics())
	}
	// the node's own conversation with a device (its name, its certificate) is not observed: it is the node's TLS, not a client's
	if m.obsHellos.Load() != 1 {
		t.Fatalf("the device's own connections were observed: %d", m.obsHellos.Load())
	}
}

func openSSLWith(t *testing.T, group string) string {
	t.Helper()
	for _, bin := range []string{"/opt/homebrew/bin/openssl", "openssl"} {
		path, err := exec.LookPath(bin)
		if err != nil {
			continue
		}
		out, err := exec.Command(path, "list", "-tls-groups").CombinedOutput()
		if err == nil && strings.Contains(strings.ToLower(string(out)), strings.ToLower(group)) {
			return path
		}
	}
	return ""
}

func TestNode_ObserverReportsTheGroupsAnOpenSSLClientOffersAndWhatTheServerSelects(t *testing.T) {
	bin := openSSLWith(t, "X25519MLKEM768")
	if bin == "" {
		t.Skip("no OpenSSL with X25519MLKEM768 on this machine")
	}
	for name, c := range map[string]struct {
		groups  string
		offered []string
		chosen  string
	}{
		"the hybrid first": {"X25519MLKEM768:X25519", []string{"x25519mlkem768", "x25519"}, "x25519mlkem768"},
		"x25519 and p-256": {"X25519:P-256", []string{"x25519", "secp256r1"}, "x25519"},
		"p-256 only":       {"P-256", []string{"secp256r1"}, "secp256r1"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newTestEnv(t, nil)
			d := e.newDevice()
			dc := e.connectOK(d)
			dc.serve(nil)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bin, "s_client", "-connect", e.httpsAddr, "-servername", d.host, "-tls1_3", "-groups", c.groups)
			cmd.Stdin = strings.NewReader("")
			out, _ := cmd.CombinedOutput()
			if !strings.Contains(string(out), "TLSv1.3") {
				t.Fatalf("OpenSSL did not complete a TLS 1.3 handshake:\n%s", out)
			}
			eventually(t, "the observer saw the handshake", 5*time.Second, func() bool { return e.srv.met.obsHellos.Load() == 1 && e.srv.met.obsVersion.get("tls13") == 1 })
			for _, g := range c.offered {
				if e.srv.met.obsOffered.get(g) != 1 {
					t.Errorf("OpenSSL offered %s and the node did not count it:\n%s", g, e.srv.renderMetrics())
				}
			}
			if e.srv.met.obsGroup.get(c.chosen) != 1 {
				t.Errorf("the selected group should be %s:\n%s", c.chosen, e.srv.renderMetrics())
			}
		})
	}
}

// helloWithExtensions builds a ClientHello for host with the extensions of the test (supported_groups, an ECH extension, GREASE).
func helloWithExtensions(host string, groups []uint16, ech bool) []byte {
	ext := sniExt(host)
	if len(groups) > 0 {
		list := []byte{byte(len(groups) * 2 >> 8), byte(len(groups) * 2)}
		for _, g := range groups {
			list = append(list, byte(g>>8), byte(g))
		}
		ext = append(append([]byte{0, 10, byte(len(list) >> 8), byte(len(list))}, list...), ext...)
	}
	if ech {
		ext = append([]byte{0xfe, 0x0d, 0, 4, 1, 2, 3, 4}, ext...)
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
	return append([]byte{22, 3, 1, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

func TestNode_ObserverCountsAnECHExtensionGREASEAndAServerThatAnswersWithoutTLS(t *testing.T) {
	e := newTestEnv(t, nil)
	d := e.newDevice()
	dc := e.connectOK(d)
	dc.serve(func(c net.Conn) { _, _ = c.Write([]byte("HTTP/1.1 400 not tls\r\n\r\n")) })
	raw := sendRaw(t, e, helloWithExtensions(d.host, []uint16{0x0a0a, 0x11ec, 0x001d, 0x001d, 0x9999}, true), 0)
	_ = raw.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	_, _ = raw.Read(buf)
	eventually(t, "the hello observed", 3*time.Second, func() bool { return e.srv.met.obsHellos.Load() == 1 })
	m := e.srv.met
	if m.obsECH.Load() != 1 {
		t.Fatalf("ECH: %d", m.obsECH.Load())
	}
	if m.obsOffered.get("x25519mlkem768") != 1 || m.obsOffered.get("x25519") != 1 || m.obsOffered.get("other") != 1 {
		t.Fatalf("a group listed twice counts once, GREASE not at all, an unknown one as other:\n%s", e.srv.renderMetrics())
	}
	eventually(t, "the answer that was not a ServerHello", 3*time.Second, func() bool { return m.obsUnparsed.Load() == 1 })
}

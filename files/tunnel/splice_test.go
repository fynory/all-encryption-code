package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// ------------------------------------------------------------------------------------------------------------------------------------
// Blindness: the node forwards ciphertext and never the plaintext.
// ------------------------------------------------------------------------------------------------------------------------------------

func TestBlindSplice_NodeNeverSeesPlaintext(t *testing.T) {
	e := newTestEnv(t, nil)
	d := e.newDevice()
	dc := e.connectOK(d)
	ds := dc.serve(nil)

	c, err := e.clientTLS(d)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	clientAddr := c.LocalAddr().String()

	// The client verified the DEVICE's certificate (issued by the device's CA for the device's name). It is not the node's own certificate.
	st := c.ConnectionState()
	if fingerprintOf(st.PeerCertificates[0].Raw) != fingerprintOf(d.cert.Certificate[0]) {
		t.Fatal("client did not reach the device's TLS server")
	}
	if st.NegotiatedProtocol != "http/1.1" {
		t.Fatalf("ALPN = %q, want http/1.1", st.NegotiatedProtocol)
	}

	body := []byte(strings.Repeat("A", 100) + marker + strings.Repeat("B", 5000))
	resp, err := postOver(c, d.host, body)
	if err != nil {
		t.Fatal(err)
	}
	// Teeth: the endpoints really exchanged the marker in the clear.
	if !bytes.Contains(resp, []byte(marker)) {
		t.Fatal("client did not read the marker back from the device")
	}
	_ = c.Close()
	e.waitIdle()

	seen := ds.seen()
	if len(seen) != 1 || !bytes.Contains(seen[0].body, []byte(marker)) {
		t.Fatalf("the device did not receive the marker in plaintext: %+v", seen)
	}
	opens := ds.openList()
	if len(opens) != 1 {
		t.Fatalf("expected exactly one stream, got %v", opens)
	}

	// What the node could see: every byte it forwarded (both directions, including the peeked ClientHello) and every log line.
	tapped := e.tapped(opens[0].str("stream_id"))
	if len(tapped) < len(body)+len(resp) {
		t.Fatalf("tap saw only %d bytes; the stream carried at least %d", len(tapped), len(body)+len(resp))
	}
	for name, hay := range map[string][]byte{
		"forwarded bytes (this stream)": tapped,
		"forwarded bytes (all)":         e.tappedAll(),
		"logs":                          []byte(e.logs.String()),
	} {
		if bytes.Contains(hay, []byte(marker)) {
			t.Fatalf("node-visible %s contain the plaintext marker", name)
		}
		if bytes.Contains(hay, []byte(strings.Repeat("A", 100))) || bytes.Contains(hay, []byte(strings.Repeat("B", 100))) {
			t.Fatalf("node-visible %s contain plaintext filler", name)
		}
	}
	// What it saw is TLS: a ClientHello first, then encrypted application data.
	if !bytes.HasPrefix(tapped, []byte{0x16, 0x03}) {
		t.Fatalf("first forwarded bytes are not a TLS handshake record: % x", tapped[:8])
	}
	if !bytes.Contains(tapped, []byte{0x17, 0x03, 0x03}) {
		t.Fatal("no TLS application-data record seen")
	}
	// Logs carry only metadata (sizes, ids, times, reasons): no name, no address, no identity of a device.
	for _, want := range []string{`"stream_open"`, `"stream_close"`, `"up_bytes"`, `"down_bytes"`} {
		if !strings.Contains(e.logs.String(), want) {
			t.Fatalf("logs lack %s:\n%s", want, e.logs.String())
		}
	}
	for name, secret := range map[string]string{"host": d.host, "label": d.label, "device id": d.id, "client address": clientAddr, "session": dc.session} {
		if strings.Contains(e.logs.String(), secret) {
			t.Fatalf("the logs name the %s", name)
		}
	}
	e.checkTranscript()
}

// ------------------------------------------------------------------------------------------------------------------------------------
// Splice correctness
// ------------------------------------------------------------------------------------------------------------------------------------

func TestSplice_LargeBodiesBothWays(t *testing.T) {
	e := newTestEnv(t, nil)
	d := e.newDevice()
	dc := e.connectOK(d)
	dc.serve(nil)
	body := make([]byte, 6<<20)
	if _, err := rand.Read(body); err != nil {
		t.Fatal(err)
	}
	c, err := e.clientTLS(d)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := postOver(c, d.host, body)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp) != len(body)+5 || sha256.Sum256(resp[5:]) != sha256.Sum256(body) {
		t.Fatalf("body corrupted or truncated: got %d bytes, want %d", len(resp), len(body)+5)
	}
	_ = c.Close()
	e.waitIdle()
	if n := e.logs.Count(`"reason":"closed"`); n < 1 {
		t.Fatalf("stream did not close cleanly:\n%s", e.logs.String())
	}
}

func TestSplice_ManyConcurrentStreams(t *testing.T) {
	e := newTestEnv(t, nil)
	d := e.newDevice()
	dc := e.connectOK(d)
	ds := dc.serve(nil)
	const n = 30
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := e.clientTLS(d)
			if err != nil {
				errs <- err
				return
			}
			defer c.Close()
			body := append(make([]byte, 20000), fmt.Sprintf("stream-%d", i)...)
			if _, err := rand.Read(body[:20000]); err != nil {
				errs <- err
				return
			}
			resp, err := postOver(c, d.host, body)
			if err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(resp, append([]byte("echo:"), body...)) {
				errs <- fmt.Errorf("stream %d: wrong echo", i)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	e.waitIdle()
	ids := map[string]bool{}
	for _, m := range ds.openList() {
		ids[m.str("stream_id")] = true
	}
	if len(ids) != n {
		t.Fatalf("expected %d distinct stream ids, got %d", n, len(ids))
	}
	e.checkTranscript()
}

func TestSplice_ClientHelloArrivesInTinyPieces(t *testing.T) {
	e := newTestEnv(t, nil)
	d := e.newDevice()
	dc := e.connectOK(d)
	dc.serve(nil)
	tcp, err := net.Dial("tcp", e.httpsAddr)
	if err != nil {
		t.Fatal(err)
	}
	c := tls.Client(chunkConn{Conn: tcp, size: 5, delay: time.Millisecond}, &tls.Config{ServerName: d.host, RootCAs: d.pool, NextProtos: []string{"http/1.1"}})
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	resp, err := postOver(c, d.host, []byte("tiny-pieces-"+marker))
	if err != nil || !bytes.HasSuffix(resp, []byte(marker)) {
		t.Fatalf("resp=%q err=%v", resp, err)
	}
}

func TestSplice_ClientHalfClosesButStillReadsResponse(t *testing.T) {
	e := newTestEnv(t, nil)
	d := e.newDevice()
	dc := e.connectOK(d)
	dc.serve(nil)
	tcp, err := net.Dial("tcp", e.httpsAddr)
	if err != nil {
		t.Fatal(err)
	}
	c := tls.Client(tcp, &tls.Config{ServerName: d.host, RootCAs: d.pool, NextProtos: []string{"http/1.1"}})
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	body := []byte("half-close-" + marker)
	req, _ := http.NewRequest("POST", "https://"+d.host+"/mcp", bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	if err := req.Write(c); err != nil {
		t.Fatal(err)
	}
	// FIN toward the node right after the request: the device's answer must still make it back.
	if err := tcp.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	if !bytes.HasSuffix(got, []byte(marker)) {
		t.Fatalf("response lost after client half-close: %q", got)
	}
}

func deviceTLSServer(d *testDevice, c net.Conn) *tls.Conn {
	return tls.Server(c, &tls.Config{Certificates: []tls.Certificate{d.cert}, NextProtos: []string{"http/1.1"}})
}

func TestSplice_DeviceResetMidResponseClosesClientPromptly(t *testing.T) {
	e := newTestEnv(t, nil)
	d := e.newDevice()
	dc := e.connectOK(d)
	started := make(chan struct{}, 1)
	dc.serve(func(c net.Conn) {
		tc := deviceTLSServer(d, c)
		if tc.Handshake() != nil {
			return
		}
		req, err := http.ReadRequest(bufio.NewReader(tc))
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, req.Body)
		_, _ = io.WriteString(tc, "HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\nhalf")
		started <- struct{}{}
		// Abort the tunnel connection with a TCP reset.
		raw := c.(*tls.Conn).NetConn().(*net.TCPConn)
		_ = raw.SetLinger(0)
		_ = raw.Close()
	})
	c, err := e.clientTLS(d)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err = postOver(c, d.host, []byte("x")); err == nil {
		t.Fatal("client should see the truncated response as an error")
	}
	<-started
	e.waitIdle()
	if e.logs.Count(`"reason":"conn_error"`) == 0 {
		t.Fatalf("expected conn_error:\n%s", e.logs.String())
	}
}

func TestSplice_ClientResetClosesDevicePromptly(t *testing.T) {
	e := newTestEnv(t, nil)
	d := e.newDevice()
	dc := e.connectOK(d)
	handlerDone := make(chan error, 1)
	dc.serve(func(c net.Conn) {
		tc := deviceTLSServer(d, c)
		if err := tc.Handshake(); err != nil {
			handlerDone <- err
			return
		}
		_ = tc.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, err := io.Copy(io.Discard, tc) // blocks until the stream dies
		handlerDone <- err
	})
	tcp, err := net.Dial("tcp", e.httpsAddr)
	if err != nil {
		t.Fatal(err)
	}
	c := tls.Client(tcp, &tls.Config{ServerName: d.host, RootCAs: d.pool})
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	_ = tcp.(*net.TCPConn).SetLinger(0)
	_ = tcp.Close() // RST
	select {
	case <-handlerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("device side was not closed after the client vanished")
	}
	e.waitIdle()
}

// ------------------------------------------------------------------------------------------------------------------------------------
// :443 routing decisions
// ------------------------------------------------------------------------------------------------------------------------------------

func TestSNIRouting_Rejections(t *testing.T) {
	e := newTestEnv(t, func(c *Config) { c.HelloTimeout = 400 * time.Millisecond })
	d := e.newDevice()
	dc := e.connectOK(d)
	ds := dc.serve(nil)

	dialTLS := func(serverName string) error {
		tcp, err := net.Dial("tcp", e.httpsAddr)
		if err != nil {
			t.Fatal(err)
		}
		defer tcp.Close()
		_ = tcp.SetDeadline(time.Now().Add(5 * time.Second))
		return tls.Client(tcp, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}).Handshake()
	}

	t.Run("no SNI is closed with an alert", func(t *testing.T) {
		err := dialTLS("")
		if err == nil || !strings.Contains(err.Error(), "unrecognized name") {
			t.Fatalf("err = %v", err)
		}
		if e.logs.Count(`"reason":"no_sni"`) != 1 {
			t.Fatalf("logs:\n%s", e.logs.String())
		}
	})
	t.Run("unknown host", func(t *testing.T) {
		err := dialTLS("nobody.example.test")
		if err == nil || !strings.Contains(err.Error(), "unrecognized name") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("unusable SNI value", func(t *testing.T) {
		out := rawExchange(t, e.httpsAddr, string(buildHello(sniExt("192.0.2.3"), true)))
		if out != "\x15\x03\x03\x00\x02\x02\x70" {
			t.Fatalf("response = %q", out)
		}
		if e.logs.Count(`"reason":"bad_sni"`) != 1 {
			t.Fatalf("logs:\n%s", e.logs.String())
		}
	})
	t.Run("plain HTTP on 443 is just closed", func(t *testing.T) {
		if out := rawExchange(t, e.httpsAddr, "GET / HTTP/1.1\r\nHost: "+d.host+"\r\n\r\n"); out != "" {
			t.Fatalf("response = %q", out)
		}
		if e.logs.Count(`"reason":"not_tls"`) != 1 {
			t.Fatalf("logs:\n%s", e.logs.String())
		}
	})
	t.Run("silent client times out", func(t *testing.T) {
		c, err := net.Dial("tcp", e.httpsAddr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		start := time.Now()
		if n, err := c.Read(make([]byte, 1)); n != 0 || err == nil {
			t.Fatalf("n=%d err=%v", n, err)
		}
		if time.Since(start) > 3*time.Second {
			t.Fatal("hello timeout not enforced")
		}
		eventually(t, "hello_timeout log", 2*time.Second, func() bool { return e.logs.Count(`"reason":"hello_timeout"`) == 1 })
	})
	if n := ds.openCount(); n != 0 {
		t.Fatalf("the device was asked to open %d streams for traffic that should never reach it", n)
	}
}

func TestSNIRouting_DeviceOffline(t *testing.T) {
	e := newTestEnv(t, nil)
	d := e.newDevice()
	// No device connected yet.
	if _, err := e.clientTLS(d); err == nil || !strings.Contains(err.Error(), "unrecognized name") {
		t.Fatalf("err = %v", err)
	}
	// Online, works; offline again after the control connection ends.
	dc := e.connectOK(d)
	dc.serve(nil)
	c, err := e.clientTLS(d)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	_ = dc.c.Close()
	eventually(t, "device offline", 3*time.Second, func() bool { return !e.srv.Online(d.host) })
	if _, err := e.clientTLS(d); err == nil {
		t.Fatal("handshake should fail while the device is offline")
	}
	e.checkTranscript()
}

// ------------------------------------------------------------------------------------------------------------------------------------
// Limits, timeouts, shutdown
// ------------------------------------------------------------------------------------------------------------------------------------

func holdHandler(d *testDevice, release <-chan struct{}) func(net.Conn) {
	return func(c net.Conn) {
		tc := deviceTLSServer(d, c)
		if tc.Handshake() != nil {
			return
		}
		select {
		case <-release:
		case <-time.After(15 * time.Second):
		}
	}
}

func TestLimits_PerHostAndGlobal(t *testing.T) {
	t.Run("per host", func(t *testing.T) {
		release := make(chan struct{})
		e := newTestEnv(t, func(c *Config) { c.MaxStreamsPerHost = 2 })
		d := e.newDevice()
		dc := e.connectOK(d)
		dc.serve(holdHandler(d, release))
		c1, err1 := e.clientTLS(d)
		c2, err2 := e.clientTLS(d)
		if err1 != nil || err2 != nil {
			t.Fatalf("first two streams must work: %v %v", err1, err2)
		}
		if _, err := e.clientTLS(d); err == nil || !strings.Contains(err.Error(), "internal error") {
			t.Fatalf("third stream must be refused, got %v", err)
		}
		if e.logs.Count(`"reason":"host_limit"`) != 1 {
			t.Fatalf("logs:\n%s", e.logs.String())
		}
		close(release)
		c1.Close()
		c2.Close()
		e.waitIdle()
		e.srv.routes.mu.Lock()
		leaked := e.srv.routes.byHost[d.host].streams
		e.srv.routes.mu.Unlock()
		if leaked != 0 {
			t.Fatalf("per-host counter leaked: %d", leaked)
		}
	})
	t.Run("global", func(t *testing.T) {
		release := make(chan struct{})
		e := newTestEnv(t, func(c *Config) { c.MaxStreams = 1 })
		d := e.newDevice()
		dc := e.connectOK(d)
		dc.serve(holdHandler(d, release))
		c1, err := e.clientTLS(d)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.clientTLS(d); err == nil {
			t.Fatal("second stream must be refused")
		}
		close(release)
		c1.Close()
		e.waitIdle()
		if e.logs.Count(`"reason":"global_limit"`) != 1 {
			t.Fatalf("logs:\n%s", e.logs.String())
		}
	})
}

func TestLimits_StreamByteCap(t *testing.T) {
	e := newTestEnv(t, func(c *Config) { c.MaxStreamBytes = 100_000 })
	d := e.newDevice()
	dc := e.connectOK(d)
	dc.serve(nil)
	c, err := e.clientTLS(d)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := postOver(c, d.host, make([]byte, 400_000)); err == nil {
		t.Fatal("a stream above the byte cap must be cut")
	}
	e.waitIdle()
	if e.logs.Count(`"reason":"byte_cap"`) != 1 {
		t.Fatalf("logs:\n%s", e.logs.String())
	}
}

func TestLimits_StreamIdleAndMaxAge(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
		reason string
	}{
		{"idle", func(c *Config) { c.StreamIdle = 300 * time.Millisecond }, "idle"},
		{"max age", func(c *Config) { c.StreamMaxAge = 300 * time.Millisecond }, "max_age"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			release := make(chan struct{})
			defer close(release)
			e := newTestEnv(t, tc.mutate)
			d := e.newDevice()
			dc := e.connectOK(d)
			dc.serve(holdHandler(d, release))
			c, err := e.clientTLS(d)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := c.Read(make([]byte, 1)); err == nil {
				t.Fatal("the stream should have been closed by the node")
			}
			e.waitIdle()
			if e.logs.Count(`"reason":"`+tc.reason+`"`) != 1 {
				t.Fatalf("logs:\n%s", e.logs.String())
			}
		})
	}
}

func TestLimits_AttachTimeoutClosesTheClientAndForgetsTheStream(t *testing.T) {
	e := newTestEnv(t, func(c *Config) { c.AttachTimeout = 300 * time.Millisecond })
	d := e.newDevice()
	dc := e.connectOK(d)
	ds := dc.serve(nil)
	ds.noAttach = true
	if _, err := e.clientTLS(d); err == nil || !strings.Contains(err.Error(), "internal error") {
		t.Fatalf("err = %v", err)
	}
	e.waitIdle()
	e.srv.mu.Lock()
	left := len(e.srv.pending)
	e.srv.mu.Unlock()
	if left != 0 {
		t.Fatalf("%d pending streams leaked", left)
	}
	if e.logs.Count(`"reason":"attach_timeout"`) != 1 {
		t.Fatalf("logs:\n%s", e.logs.String())
	}
}

func TestShutdown_TellsDevicesAndClosesEverythingWithinGrace(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	e := newTestEnv(t, nil)
	d := e.newDevice()
	dc := e.connectOK(d)
	ds := dc.serve(holdHandler(d, release))
	c, err := e.clientTLS(d)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	e.srv.Shutdown(500 * time.Millisecond)
	if time.Since(start) > 4*time.Second {
		t.Fatal("shutdown hung")
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("stream survived shutdown")
	}
	if _, err := net.DialTimeout("tcp", e.httpsAddr, 500*time.Millisecond); err == nil {
		t.Fatal("listener still open after shutdown")
	}
	<-ds.done
	if !containsLine(ds.otherLines(), "CLOSE shutdown") {
		t.Fatalf("the device was not told: %q", ds.otherLines())
	}
}

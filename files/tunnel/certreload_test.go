package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The node's own public-CA certificate is hot reloaded: a renewal goes into service without a restart and without a dropped connection, and a renewal
// that is not good never replaces the one that works.

type certFiles struct {
	dir, cert, key string
}

func newCertFiles(t *testing.T) *certFiles {
	dir := t.TempDir()
	return &certFiles{dir: dir, cert: filepath.Join(dir, "fullchain.pem"), key: filepath.Join(dir, "privkey.pem")}
}

// write puts a certificate for names, valid between notBefore and notAfter, on disk (the key too, unless keyFrom is set: then that pair's key is
// written, which is a renewal whose key does not match). It returns the serial.
func (c *certFiles) write(t *testing.T, serial int64, notBefore, notAfter time.Time, names ...string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: names[0]}, NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: names,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	c.put(t, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

// put writes both files the way a renewal tool does: each replaced atomically, the key after the certificate (so there is a moment when they do not match).
func (c *certFiles) put(t *testing.T, certPEM, keyPEM []byte) {
	t.Helper()
	for path, data := range map[string][]byte{c.cert: certPEM, c.key: keyPEM} {
		tmp := path + ".new"
		if err := os.WriteFile(tmp, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, path); err != nil {
			t.Fatal(err)
		}
	}
}

func (c *certFiles) fresh(t *testing.T, serial int64, names ...string) {
	t.Helper()
	c.write(t, serial, time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour), names...)
}

// servedSerial connects to the node's own name and reports the serial of the certificate it presents.
func servedSerial(t *testing.T, addr string) int64 {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, &tls.Config{
		ServerName: testNodeHost, InsecureSkipVerify: true, NextProtos: []string{policyData.Protocol.ALPN}, MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64()
}

func certNode(t *testing.T, r *certReloader) *testEnv {
	return newTestEnv(t, func(c *Config) { c.CertSource = r.get })
}

func TestCertReload_ARenewalIsInServiceForTheNextHandshakeAndAnOpenConnectionIsUntouched(t *testing.T) {
	files := newCertFiles(t)
	files.fresh(t, 1, testNodeHost)
	r, err := newCertReloader(files.cert, files.key, testNodeHost, clock{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.lookGap = 0
	e := certNode(t, r)
	if got := servedSerial(t, e.httpsAddr); got != 1 {
		t.Fatalf("served %d", got)
	}
	// a device is connected (its TLS session was made with the first certificate)
	d := e.newDevice()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", e.httpsAddr, &tls.Config{
		ServerName: testNodeHost, InsecureSkipVerify: true, NextProtos: []string{policyData.Protocol.ALPN}, MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	dc := &devConn{t: t, e: e, d: d, c: conn, br: bufio.NewReaderSize(conn, 1<<17)}
	dc.session = e.session(d, nil)
	dc.send("HELLO 2 " + dc.session)
	m, perr := parseLine(dc.recv(), dirN2D)
	if perr != nil || m.str("verb") != "CHALLENGE" {
		t.Fatal("no challenge")
	}
	dc.send("PROOF " + e.proof(d, dc.session, m.str("nonce"), nil))
	if line := dc.recv(); !strings.HasPrefix(line, "OK ") {
		t.Fatalf("%q", line)
	}

	// the renewal lands on disk, the node is not restarted
	time.Sleep(20 * time.Millisecond)
	files.fresh(t, 2, testNodeHost)
	if got := servedSerial(t, e.httpsAddr); got != 2 {
		t.Fatalf("after the renewal the node served %d", got)
	}
	// the connection that was up goes on
	dc.send("PING")
	if line := dc.recv(); line != "PONG" {
		t.Fatalf("a connection made with the old certificate: %q", line)
	}
	if !e.srv.Online(d.host) {
		t.Fatal("the device was dropped by the renewal")
	}
	if want := r.NotAfter(); want.Before(time.Now().Add(50 * 24 * time.Hour)) {
		t.Fatalf("not_after %s", want)
	}
}

func TestCertReload_ARenewalThatIsNotGoodNeverReplacesTheOneThatWorks(t *testing.T) {
	files := newCertFiles(t)
	files.fresh(t, 1, testNodeHost)
	var logs syncBuf
	r, err := newCertReloader(files.cert, files.key, testNodeHost, clock{}, slog.New(slog.NewJSONHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	r.lookGap = 0
	e := certNode(t, r)
	good := func() {
		t.Helper()
		if got := servedSerial(t, e.httpsAddr); got != 1 {
			t.Fatalf("the node serves %d, the certificate that works is 1", got)
		}
	}
	now := time.Now()
	for name, write := range map[string]func(){
		"another name":   func() { files.write(t, 10, now.Add(-time.Hour), now.Add(48*time.Hour), "someone-else.example.test") },
		"expired":        func() { files.write(t, 11, now.Add(-72*time.Hour), now.Add(-time.Hour), testNodeHost) },
		"not yet valid":  func() { files.write(t, 12, now.Add(48*time.Hour), now.Add(96*time.Hour), testNodeHost) },
		"garbage":        func() { files.put(t, []byte("garbage"), []byte("garbage")) },
		"half written":   func() { _ = os.WriteFile(files.cert, []byte("-----BEGIN CERTIFICATE-----\nAAAA"), 0o600) },
		"a missing key":  func() { _ = os.Remove(files.key) },
		"a missing cert": func() { files.fresh(t, 13, testNodeHost); _ = os.Remove(files.cert) },
		"a certificate and a key that are not a pair": func() {
			other := newCertFiles(t)
			other.fresh(t, 14, testNodeHost)
			certPEM, _ := os.ReadFile(other.cert)
			third := newCertFiles(t)
			third.fresh(t, 15, testNodeHost)
			keyPEM, _ := os.ReadFile(third.key)
			files.put(t, certPEM, keyPEM)
		},
	} {
		time.Sleep(15 * time.Millisecond)
		write()
		good()
		if name != "a missing key" && name != "a missing cert" && name != "half written" && r.LastError() == "" {
			t.Errorf("%s: the refusal is not recorded", name)
		}
	}
	if !strings.Contains(logs.String(), "node_cert_reload_refused") {
		t.Fatal("refusals are not logged")
	}
	// the files are in a bad state now; a good renewal still gets in
	time.Sleep(20 * time.Millisecond)
	files.fresh(t, 3, testNodeHost)
	if got := servedSerial(t, e.httpsAddr); got != 3 {
		t.Fatalf("a good renewal after the bad ones: served %d", got)
	}
	if r.LastError() != "" {
		t.Fatalf("last error %q", r.LastError())
	}
}

func TestCertReload_ARefusedRenewalIsNotParsedAgainAtEveryHandshake(t *testing.T) {
	files := newCertFiles(t)
	files.fresh(t, 1, testNodeHost)
	var logs syncBuf
	r, err := newCertReloader(files.cert, files.key, testNodeHost, clock{}, slog.New(slog.NewJSONHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	r.lookGap = 0
	time.Sleep(15 * time.Millisecond)
	files.put(t, []byte("garbage"), []byte("garbage"))
	for i := 0; i < 50; i++ {
		if pair, err := r.get(nil); err != nil || pair.Leaf.SerialNumber.Int64() != 1 {
			t.Fatalf("handshake %d: %v", i, err)
		}
	}
	if n := logs.Count("node_cert_reload_refused"); n != 1 {
		t.Fatalf("one bad renewal was parsed and refused %d times", n)
	}
}

func TestCertReload_ReloadNowIsWhatSIGHUPDoes(t *testing.T) {
	files := newCertFiles(t)
	files.fresh(t, 1, testNodeHost)
	r, err := newCertReloader(files.cert, files.key, testNodeHost, clock{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// a look gap: the handshake path has just looked and does not look again for a while, SIGHUP does not wait
	_, _ = r.get(nil)
	files.fresh(t, 2, testNodeHost)
	if pair, _ := r.get(nil); pair.Leaf.SerialNumber.Int64() != 1 {
		t.Fatal("looked inside the gap")
	}
	if err := r.Reload(); err != nil {
		t.Fatal(err)
	}
	if pair, _ := r.get(nil); pair.Leaf.SerialNumber.Int64() != 2 {
		t.Fatal("Reload did not put the new certificate in service")
	}
	files.write(t, 3, time.Now().Add(-time.Hour), time.Now().Add(-time.Minute), testNodeHost)
	if err := r.Reload(); err == nil || r.LastError() == "" {
		t.Fatal("an expired certificate was accepted by Reload")
	}
	if pair, _ := r.get(nil); pair.Leaf.SerialNumber.Int64() != 2 {
		t.Fatal("a refused Reload replaced the certificate")
	}
}

func TestCertReload_TheWatcherPicksUpARenewalWithoutAnyHandshakeAndWarnsBeforeTheEnd(t *testing.T) {
	files := newCertFiles(t)
	files.write(t, 1, time.Now().Add(-time.Hour), time.Now().Add(3*24*time.Hour), testNodeHost) // 3 days left: under the warning
	var logs syncBuf
	clk := newFakeClock()
	r, err := newCertReloader(files.cert, files.key, testNodeHost, newClock(clk.Now, clk.AfterFunc), slog.New(slog.NewJSONHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	eventually(t, "the first look and its warning", 2*time.Second, func() bool { return logs.Count("node_cert_expires_soon") == 1 })
	eventually(t, "the watcher sleeping", 2*time.Second, func() bool { return clk.pending() == 1 })

	time.Sleep(20 * time.Millisecond)
	files.fresh(t, 2, testNodeHost)
	clk.Advance(certWatchEvery)
	eventually(t, "the renewal in service", 2*time.Second, func() bool { return logs.Count("node_cert_reloaded") == 1 })
	if pair, _ := r.get(nil); pair.Leaf.SerialNumber.Int64() != 2 {
		t.Fatal("not in service")
	}
	eventually(t, "the watcher sleeping again", 2*time.Second, func() bool { return clk.pending() == 1 })
	clk.Advance(certWatchEvery)
	time.Sleep(50 * time.Millisecond)
	if logs.Count("node_cert_expires_soon") != 1 {
		t.Fatal("warned about a certificate with 60 days left")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the watcher did not stop")
	}
}

func TestCertReload_TheNodeDoesNotStartWithoutAUsableCertificate(t *testing.T) {
	files := newCertFiles(t)
	if _, err := newCertReloader(files.cert, files.key, testNodeHost, clock{}, nil); err == nil {
		t.Fatal("started without files")
	}
	files.write(t, 1, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), "other.example.test")
	if _, err := newCertReloader(files.cert, files.key, testNodeHost, clock{}, nil); err == nil || !strings.Contains(err.Error(), testNodeHost) {
		t.Fatalf("started with a certificate for another name: %v", err)
	}
	files.write(t, 2, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour), testNodeHost)
	if _, err := newCertReloader(files.cert, files.key, testNodeHost, clock{}, nil); err == nil {
		t.Fatal("started with an expired certificate")
	}
}

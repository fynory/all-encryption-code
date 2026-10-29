package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	mrand "math/rand"
	"net"
	"os"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

// captureClientHello returns the first TLS record a real crypto/tls client
// sends (its ClientHello), exactly as it appears on the wire.
func captureClientHello(t testing.TB, cfg *tls.Config) []byte {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() { _ = tls.Client(c1, cfg).Handshake() }()
	_ = c2.SetReadDeadline(time.Now().Add(5 * time.Second))
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c2, hdr); err != nil {
		t.Fatal(err)
	}
	rec := make([]byte, int(hdr[3])<<8|int(hdr[4]))
	if _, err := io.ReadFull(c2, rec); err != nil {
		t.Fatal(err)
	}
	return append(hdr, rec...)
}

func realHello(t testing.TB, serverName string) []byte {
	return captureClientHello(t, &tls.Config{ServerName: serverName, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
}

// refragment rewraps the handshake payload of a single-record ClientHello
// into records of at most n payload bytes each.
func refragment(hello []byte, n int) []byte {
	payload := hello[5:]
	var out []byte
	for len(payload) > 0 {
		k := min(n, len(payload))
		out = append(out, 22, 3, 3, byte(k>>8), byte(k))
		out = append(out, payload[:k]...)
		payload = payload[k:]
	}
	return out
}

func TestScanSNI_RealClientHellos(t *testing.T) {
	cases := []struct{ in, want string }{
		{"dev1.example.test", "dev1.example.test"},
		{"Dev1.Example.TEST", "dev1.example.test"}, // normalized
		{"nodo-abc123.example.test", "nodo-abc123.example.test"},
		{"", ""},          // no SNI at all
		{"127.0.0.1", ""}, // Go omits SNI for IP literals
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			res := scanClientHello(realHello(t, tc.in))
			if res.err != nil || !res.complete || res.sni != tc.want {
				t.Fatalf("got %+v, want sni %q", res, tc.want)
			}
		})
	}
}

// Modern clients (Chrome, Go 1.24+, OpenSSL 3.5) offer the X25519MLKEM768
// hybrid key share, which makes the ClientHello well over a kilobyte.
func TestScanSNI_LargePostQuantumClientHello(t *testing.T) {
	hello := captureClientHello(t, &tls.Config{
		ServerName: "dev1.example.test", InsecureSkipVerify: true,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
	})
	if len(hello) < 1200 {
		t.Fatalf("expected a large (ML-KEM) hello, got %d bytes", len(hello))
	}
	if res := scanClientHello(hello); res.err != nil || !res.complete || res.sni != "dev1.example.test" {
		t.Fatalf("%+v", res)
	}
	// ... split in half across two records, and arriving a few bytes at a time.
	if res := scanClientHello(refragment(hello, len(hello)/2)); res.err != nil || res.sni != "dev1.example.test" {
		t.Fatalf("two records: %+v", res)
	}
	peeked, sni, err := readClientHello(byteConn{r: iotest.OneByteReader(bytes.NewReader(hello))}, time.Second)
	if err != nil || sni != "dev1.example.test" || !bytes.Equal(peeked, hello) {
		t.Fatalf("one-byte reads: sni=%q err=%v", sni, err)
	}
}

// A padded hello close to the 16 KiB record limit (RFC 7685 padding, ECH).
func TestScanSNI_HugePaddedHello(t *testing.T) {
	pad := make([]byte, 14000)
	ext := append([]byte{0, 21, byte(len(pad) >> 8), byte(len(pad))}, pad...) // padding extension
	ext = append(ext, sniExt("dev1.example.test")...)
	hello := buildHello(ext, true)
	if len(hello) < 14000 || len(hello) > maxRecordPayload {
		t.Fatalf("test hello is %d bytes", len(hello))
	}
	peeked, sni, err := readClientHello(byteConn{r: bytes.NewReader(hello)}, time.Second)
	if err != nil || sni != "dev1.example.test" || !bytes.Equal(peeked, hello) {
		t.Fatalf("sni=%q err=%v", sni, err)
	}
}

func TestScanSNI_EveryPrefixNeedsMore(t *testing.T) {
	hello := realHello(t, "dev1.example.test")
	for n := 0; n < len(hello); n++ {
		res := scanClientHello(hello[:n])
		if res.err != nil || res.complete || res.need <= n {
			t.Fatalf("prefix %d/%d: got %+v", n, len(hello), res)
		}
	}
	if res := scanClientHello(hello); !res.complete || res.sni != "dev1.example.test" {
		t.Fatalf("full: %+v", res)
	}
}

func TestScanSNI_HelloSplitAcrossRecords(t *testing.T) {
	hello := realHello(t, "dev1.example.test")
	payload := len(hello) - 5
	for _, n := range []int{payload/maxHelloRecords + 1, 100, 300, 1000, payload} {
		frag := refragment(hello, n)
		res := scanClientHello(frag)
		if res.err != nil || !res.complete || res.sni != "dev1.example.test" {
			t.Fatalf("records of %d bytes: %+v", n, res)
		}
		// no decision before the last byte
		for i := 0; i < len(frag); i++ {
			if r := scanClientHello(frag[:i]); r.complete || r.err != nil {
				t.Fatalf("records of %d bytes: decided early at %d/%d: %+v", n, i, len(frag), r)
			}
		}
	}
	// Absurdly fragmented hellos (more records than the cap) are refused.
	if res := scanClientHello(refragment(hello, 1)); !errors.Is(res.err, errHelloMalformed) {
		t.Fatalf("1-byte records: %+v", res)
	}
}

func TestScanSNI_TrailingBytesAreIgnored(t *testing.T) {
	hello := realHello(t, "dev1.example.test")
	res := scanClientHello(append(append([]byte(nil), hello...), []byte("\x17\x03\x03\x00\x05trail")...))
	if res.err != nil || !res.complete || res.sni != "dev1.example.test" {
		t.Fatalf("%+v", res)
	}
}

// buildHello assembles a ClientHello record from parts, for hostile cases.
func buildHello(extensions []byte, withExt bool) []byte {
	var body []byte
	body = append(body, 3, 3)                // legacy_version
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // session id len
	body = append(body, 0, 2, 0x13, 0x01)    // one cipher suite
	body = append(body, 1, 0)                // compression
	if withExt {
		body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
		body = append(body, extensions...)
	}
	hs := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{22, 3, 1, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

func sniExt(names ...string) []byte {
	var list []byte
	for _, n := range names {
		list = append(list, 0, byte(len(n)>>8), byte(len(n)))
		list = append(list, n...)
	}
	data := append([]byte{byte(len(list) >> 8), byte(len(list))}, list...)
	return append([]byte{0, 0, byte(len(data) >> 8), byte(len(data))}, data...)
}

func TestScanSNI_HandBuiltHellos(t *testing.T) {
	good := scanClientHello(buildHello(sniExt("a.example.test"), true))
	if good.err != nil || good.sni != "a.example.test" {
		t.Fatalf("baseline: %+v", good)
	}
	noExt := scanClientHello(buildHello(nil, false))
	if noExt.err != nil || !noExt.complete || noExt.sni != "" {
		t.Fatalf("no extensions: %+v", noExt)
	}
	otherExtOnly := scanClientHello(buildHello([]byte{0, 43, 0, 3, 2, 3, 4}, true))
	if otherExtOnly.err != nil || otherExtOnly.sni != "" {
		t.Fatalf("other extension only: %+v", otherExtOnly)
	}
}

func TestScanSNI_Rejects(t *testing.T) {
	dupExt := append(sniExt("a.example.test"), sniExt("b.example.test")...)
	rec := func(typ byte, ver byte, payload []byte) []byte {
		return append([]byte{typ, 3, ver, byte(len(payload) >> 8), byte(len(payload))}, payload...)
	}
	var tooManyRecords []byte
	for _, b := range append([]byte{1, 0, 0, 200}, make([]byte, 40)...) {
		tooManyRecords = append(tooManyRecords, rec(22, 1, []byte{b})...)
	}
	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"http on 443", []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), errNotTLS},
		{"ssl2-style", []byte{0x80, 0x2e, 0x01, 0x00, 0x02}, errNotTLS},
		{"application data record", rec(23, 3, []byte{1, 2, 3}), errNotTLS},
		{"bad record major version", append([]byte{22, 7, 3, 0, 4}, 1, 0, 0, 0), errNotTLS},
		{"zero length record", []byte{22, 3, 1, 0, 0}, errHelloMalformed},
		{"oversize record", []byte{22, 3, 1, 0xff, 0xff}, errHelloMalformed},
		{"server hello", rec(22, 3, []byte{2, 0, 0, 0}), errNotClientHello},
		{"hello longer than cap", rec(22, 3, []byte{1, 0xff, 0xff, 0xff}), errHelloTooLarge},
		{"body shorter than its fields", rec(22, 3, []byte{1, 0, 0, 5, 3, 3, 0, 0, 0}), errHelloMalformed},
		{"duplicate server_name extension", buildHello(dupExt, true), errHelloMalformed},
		{"two host_names in one extension", buildHello(sniExt("a.example.test", "b.example.test"), true), errHelloMalformed},
		{"space in name", buildHello(sniExt("a b.example.test"), true), errBadSNI},
		{"NUL in name", buildHello(sniExt("a\x00b.example.test"), true), errBadSNI},
		{"slash in name", buildHello(sniExt("a/b.example.test"), true), errBadSNI},
		{"empty name", buildHello(sniExt(""), true), errBadSNI},
		{"ip literal name", buildHello(sniExt("192.0.2.1"), true), errBadSNI},
		{"label over 63", buildHello(sniExt(strings.Repeat("a", 64)+".example.test"), true), errBadSNI},
		{"empty label", buildHello(sniExt("a..example.test"), true), errBadSNI},
		{"leading dot", buildHello(sniExt(".example.test"), true), errBadSNI},
		{"name over 253", buildHello(sniExt(strings.Repeat("abcdefgh.", 30)+"test"), true), errBadSNI},
		{"extension length overruns", buildHello([]byte{0, 0, 0xff, 0xff, 1}, true), errHelloMalformed},
		{"too many records", tooManyRecords, errHelloMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := scanClientHello(tc.in)
			if !errors.Is(res.err, tc.want) {
				t.Fatalf("got %+v, want error %v", res, tc.want)
			}
		})
	}
}

// Mutating a valid hello in every way must never panic or run out of bounds.
func TestScanSNI_NeverPanicsOnMutations(t *testing.T) {
	hello := realHello(t, "dev1.example.test")
	rng := mrand.New(mrand.NewSource(1))
	for i := 0; i < 30000; i++ {
		b := append([]byte(nil), hello...)
		for k := rng.Intn(4); k >= 0; k-- {
			b[rng.Intn(len(b))] = byte(rng.Intn(256))
		}
		if rng.Intn(3) == 0 {
			b = b[:rng.Intn(len(b)+1)]
		}
		res := scanClientHello(b)
		if res.complete && res.err == nil && res.sni != "" {
			if n, ok := normalizeName(res.sni); !ok || n != res.sni {
				t.Fatalf("returned an unnormalized name %q", res.sni)
			}
		}
	}
}

func FuzzScanClientHello(f *testing.F) {
	f.Add(realHello(f, "dev1.example.test"))
	f.Add(realHello(f, ""))
	f.Add(buildHello(sniExt("a.example.test"), true))
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		res := scanClientHello(data)
		if res.complete && res.err == nil && res.sni != "" {
			if n, ok := normalizeName(res.sni); !ok || n != res.sni {
				t.Fatalf("returned an unnormalized name %q", res.sni)
			}
		}
		if !res.complete && res.err == nil && res.need <= len(data) {
			t.Fatalf("need %d not beyond len %d", res.need, len(data))
		}
	})
}

// byteConn is a net.Conn that serves a reader (for readClientHello tests).
type byteConn struct {
	net.Conn
	r io.Reader
}

func (b byteConn) Read(p []byte) (int, error)      { return b.r.Read(p) }
func (b byteConn) SetReadDeadline(time.Time) error { return nil }

func TestReadClientHello_OneByteReads(t *testing.T) {
	hello := realHello(t, "dev1.example.test")
	trail := []byte("EXTRA")
	in := append(append([]byte(nil), hello...), trail...)
	peeked, sni, err := readClientHello(byteConn{r: iotest.OneByteReader(bytes.NewReader(in))}, time.Second)
	if err != nil || sni != "dev1.example.test" {
		t.Fatalf("sni=%q err=%v", sni, err)
	}
	if !bytes.Equal(peeked, hello) { // one-byte reads cannot over-read past the hello
		t.Fatalf("peeked %d bytes, want exactly the %d-byte hello", len(peeked), len(hello))
	}
}

func TestReadClientHello_ReturnsEveryByteRead(t *testing.T) {
	hello := realHello(t, "dev1.example.test")
	in := append(append([]byte(nil), hello...), []byte("COALESCED-AFTER-HELLO")...)
	peeked, sni, err := readClientHello(byteConn{r: bytes.NewReader(in)}, time.Second)
	if err != nil || sni != "dev1.example.test" {
		t.Fatalf("sni=%q err=%v", sni, err)
	}
	if !bytes.Equal(peeked, in) { // everything read must be replayed to the device
		t.Fatalf("peeked %d bytes, want all %d", len(peeked), len(in))
	}
}

func TestReadClientHello_SplitReadsOverPipe(t *testing.T) {
	hello := realHello(t, "dev1.example.test")
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() {
		for i := 0; i < len(hello); i += 3 {
			_, _ = c1.Write(hello[i:min(i+3, len(hello))])
			time.Sleep(200 * time.Microsecond)
		}
	}()
	peeked, sni, err := readClientHello(c2, 5*time.Second)
	if err != nil || sni != "dev1.example.test" || !bytes.Equal(peeked, hello) {
		t.Fatalf("sni=%q err=%v peeked=%d/%d", sni, err, len(peeked), len(hello))
	}
}

func TestReadClientHello_MissingSNIIsNotAnError(t *testing.T) {
	peeked, sni, err := readClientHello(byteConn{r: bytes.NewReader(realHello(t, ""))}, time.Second)
	if err != nil || sni != "" || len(peeked) == 0 {
		t.Fatalf("sni=%q err=%v", sni, err)
	}
}

func TestReadClientHello_FailureModes(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()
		_, _, err := readClientHello(c2, 100*time.Millisecond)
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("eof before hello", func(t *testing.T) {
		hello := realHello(t, "x.example.test")
		_, _, err := readClientHello(byteConn{r: bytes.NewReader(hello[:20])}, time.Second)
		if !errors.Is(err, io.EOF) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("not tls fails fast", func(t *testing.T) {
		_, _, err := readClientHello(byteConn{r: strings.NewReader("GET / HTTP/1.1\r\n")}, time.Second)
		if !errors.Is(err, errNotTLS) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("stream of records beyond the cap", func(t *testing.T) {
		endless := io.MultiReader(bytes.NewReader([]byte{22, 3, 1, 0x3f, 0xff, 1, 0, 0xff, 0xff}), iotest.ErrReader(io.ErrUnexpectedEOF))
		_, _, err := readClientHello(byteConn{r: endless}, time.Second)
		if err == nil {
			t.Fatal("expected an error")
		}
	})
}

func TestNormalizeName(t *testing.T) {
	ok := map[string]string{
		"Example.COM": "example.com", "a.b.c.": "a.b.c",
		"nodo-abc123.example.test": "nodo-abc123.example.test",
		"localhost":                "localhost", "psrhz6n5wpzbm6yfkngo.devices.all-e2e.test": "psrhz6n5wpzbm6yfkngo.devices.all-e2e.test",
		"PSRHZ6N5WPZBM6YFKNGO.Devices.ALL-E2E.test.": "psrhz6n5wpzbm6yfkngo.devices.all-e2e.test",
		"xn--bcher-kva.example":                      "xn--bcher-kva.example",
	}
	for in, want := range ok {
		if got, good := normalizeName(in); !good || got != want {
			t.Errorf("%q -> %q,%v want %q", in, got, good, want)
		}
	}
	long63, long64 := strings.Repeat("a", 63), strings.Repeat("a", 64)
	for _, in := range []string{
		"", ".", "..", "a..b", "a.b..", ".a.b", "a b", "a/b", "::1", "127.0.0.1", "[::1]", "é.example.test", "a\x00b", "a\tb", "a\nb", "a.b\n",
		"x_y.example.test", "_acme-challenge.example.test", "-a.example.test", "a-.example.test", "a.-b.test", "a.b-.test", "a*.example.test",
		"192.0.2.4", "1.2.3", "0x7f.1", "a.123", "999", long64 + ".test", strings.Repeat(long63+".", 4) + "test", "a.b.c:443", "a" + "@b.test", "a b.test", "ａ.test",
	} {
		if got, good := normalizeName(in); good {
			t.Errorf("%q should be rejected, got %q", in, got)
		}
	}
	if _, good := normalizeName(long63 + ".test"); !good {
		t.Error("a 63-byte label is valid")
	}
}

func TestScanSNI_BytesAfterTheExtensionsAreAHelloThatLiesAboutItsLength(t *testing.T) {
	hello := buildHello(sniExt("a.example.test"), true)
	// grow the handshake message by two bytes that no field accounts for
	lying := append([]byte(nil), hello...)
	lying = append(lying, 0xde, 0xad)
	hsLen := int(lying[6])<<16 | int(lying[7])<<8 | int(lying[8])
	hsLen += 2
	lying[6], lying[7], lying[8] = byte(hsLen>>16), byte(hsLen>>8), byte(hsLen)
	recLen := int(lying[3])<<8 | int(lying[4]) + 2
	lying[3], lying[4] = byte(recLen>>8), byte(recLen)
	if res := scanClientHello(lying); res.err == nil {
		t.Fatalf("accepted: %+v", res)
	}
}

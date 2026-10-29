package main

// The cleartext handshake observer (the design plan, sections 3 and 7). The node splices bytes it cannot read, but the first messages of a TLS
// handshake are cleartext by design, and what they say is the measurement G1 needs: which groups real ChatGPT clients offer (does the hybrid
// X25519MLKEM768 come?), and what the device's TLS server selects (version, cipher, group) so the plan's claims about strength are measured and not
// assumed. It reads three things and nothing else:
//
//   - the ClientHello's supported_groups (and whether it carries an ECH extension), from the bytes the node already read to learn the SNI;
//   - the ServerHello's version (supported_versions, else the legacy version), cipher suite and, in TLS 1.3, the key_share's selected group, from the
//     first records the device sends back; a HelloRetryRequest is counted and the observer waits for the real ServerHello;
//   - nothing after that: once the ServerHello is read (or the stream proves not to be TLS) the observer stops, and the rest of the stream is never
//     looked at.
//
// What it keeps is a count per word of a CLOSED list (the tables below): never a name, an address, a label, a stream or a time. The words are the
// metrics' label values, so a client cannot make a new series by offering a new group: it is counted as "other". Nothing here is written to the log.

import "bytes"

const (
	extSupportedGroups   = 10
	extSupportedVersions = 43
	extKeyShare          = 51
	extECH               = 0xfe0d // the RFC's code point (the draft ones are not counted)
)

// Words of the observer, in the order the metrics list them.
var (
	obsGroupWords = []string{
		"x25519", "secp256r1", "secp384r1", "secp521r1", "x448", "x25519mlkem768", "secp256r1mlkem768", "secp384r1mlkem1024", "x25519kyber768draft00", "ffdhe", "other",
	}
	obsVersionWords = []string{"tls13", "tls12", "tls11", "tls10", "other"}
	obsCipherWords  = []string{
		"tls_aes_128_gcm_sha256", "tls_aes_256_gcm_sha384", "tls_chacha20_poly1305_sha256",
		"ecdhe_ecdsa_aes_128_gcm_sha256", "ecdhe_ecdsa_aes_256_gcm_sha384", "ecdhe_rsa_aes_128_gcm_sha256", "ecdhe_rsa_aes_256_gcm_sha384",
		"ecdhe_ecdsa_chacha20_poly1305", "ecdhe_rsa_chacha20_poly1305", "other",
	}
	// the selected group of a handshake that has none (TLS 1.2 here, or a ServerHello without a key share) is counted under this word
	obsNoGroup = "none"
)

func isGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a && byte(v>>8) == byte(v) }

// groupWord names a TLS named group.
func groupWord(g uint16) string {
	switch g {
	case 0x001d:
		return "x25519"
	case 0x0017:
		return "secp256r1"
	case 0x0018:
		return "secp384r1"
	case 0x0019:
		return "secp521r1"
	case 0x001e:
		return "x448"
	case 0x11ec:
		return "x25519mlkem768"
	case 0x11eb:
		return "secp256r1mlkem768"
	case 0x11ed:
		return "secp384r1mlkem1024"
	case 0x6399:
		return "x25519kyber768draft00"
	}
	if g >= 0x0100 && g <= 0x01ff {
		return "ffdhe"
	}
	return "other"
}

func versionWord(v uint16) string {
	switch v {
	case 0x0304:
		return "tls13"
	case 0x0303:
		return "tls12"
	case 0x0302:
		return "tls11"
	case 0x0301:
		return "tls10"
	}
	return "other"
}

func cipherWord(c uint16) string {
	switch c {
	case 0x1301:
		return "tls_aes_128_gcm_sha256"
	case 0x1302:
		return "tls_aes_256_gcm_sha384"
	case 0x1303:
		return "tls_chacha20_poly1305_sha256"
	case 0xc02b:
		return "ecdhe_ecdsa_aes_128_gcm_sha256"
	case 0xc02c:
		return "ecdhe_ecdsa_aes_256_gcm_sha384"
	case 0xc02f:
		return "ecdhe_rsa_aes_128_gcm_sha256"
	case 0xc030:
		return "ecdhe_rsa_aes_256_gcm_sha384"
	case 0xcca9:
		return "ecdhe_ecdsa_chacha20_poly1305"
	case 0xcca8:
		return "ecdhe_rsa_chacha20_poly1305"
	}
	return "other"
}

// helloShape is what the observer takes from a ClientHello.
type helloShape struct {
	groups []uint16
	ech    bool
	ok     bool
}

// shapeOfClientHello reads a ClientHello body (the bytes after the 4-byte handshake header). It never reads outside body, and anything it cannot make
// sense of is simply not observed.
func shapeOfClientHello(body []byte) helloShape {
	c := &cursor{b: body}
	c.take(2)  // legacy_version
	c.take(32) // random
	c.take(c.u8())
	c.take(c.u16()) // cipher suites
	c.take(c.u8())  // compression methods
	if c.bad || len(c.b) < 2 {
		return helloShape{}
	}
	ext := &cursor{b: c.take(c.u16())}
	if c.bad {
		return helloShape{}
	}
	shape := helloShape{ok: true}
	for len(ext.b) > 0 {
		typ := ext.u16()
		data := &cursor{b: ext.take(ext.u16())}
		if ext.bad {
			return helloShape{}
		}
		switch typ {
		case extSupportedGroups:
			list := &cursor{b: data.take(data.u16())}
			for len(list.b) >= 2 {
				if g := uint16(list.u16()); !isGREASE(g) {
					shape.groups = append(shape.groups, g)
				}
			}
		case extECH:
			shape.ech = true
		}
	}
	return shape
}

// serverHello is what the observer takes from a ServerHello (or a HelloRetryRequest).
type serverHello struct {
	version, cipher uint16
	group           uint16
	hasGroup        bool
	retry           bool
}

// helloRetryRandom is the fixed "random" that makes a ServerHello a HelloRetryRequest (RFC 8446 section 4.1.3).
var helloRetryRandom = []byte{
	0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
	0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
}

// parseServerHello reads a ServerHello message body (after the 4-byte handshake header).
func parseServerHello(body []byte) (serverHello, bool) {
	c := &cursor{b: body}
	legacy := uint16(c.u16())
	random := c.take(32)
	c.take(c.u8()) // session id echo
	cipher := uint16(c.u16())
	c.take(1) // compression method
	if c.bad {
		return serverHello{}, false
	}
	sh := serverHello{version: legacy, cipher: cipher, retry: bytes.Equal(random, helloRetryRandom)}
	if len(c.b) == 0 {
		return sh, true // TLS 1.2 without extensions
	}
	ext := &cursor{b: c.take(c.u16())}
	if c.bad {
		return serverHello{}, false
	}
	for len(ext.b) > 0 {
		typ := ext.u16()
		data := &cursor{b: ext.take(ext.u16())}
		if ext.bad {
			return serverHello{}, false
		}
		switch typ {
		case extSupportedVersions:
			if v := uint16(data.u16()); !data.bad {
				sh.version = v
			}
		case extKeyShare:
			// ServerHello: the group, then the key exchange. HelloRetryRequest: the group alone.
			if g := uint16(data.u16()); !data.bad {
				sh.group, sh.hasGroup = g, true
			}
		}
	}
	return sh, true
}

// maxObserved is the most the observer reads of a stream's first bytes from the device before it gives up: a ServerHello is a hundred bytes, and a
// stream that has not shown one in this much is not a TLS handshake the observer understands.
const maxObserved = 16 << 10

// serverHelloWatch reads the device's first bytes of ONE client stream until the ServerHello has been seen, reporting to counters. It is used by one
// goroutine (the pump of that direction).
type serverHelloWatch struct {
	m    *metrics
	buf  []byte
	seen int // hellos read: a retry request and the ServerHello after it make two
	done bool
}

func newServerHelloWatch(m *metrics) *serverHelloWatch { return &serverHelloWatch{m: m} }

// feed gives the watcher the next bytes the device sent toward the client. After the ServerHello it costs one comparison.
func (w *serverHelloWatch) feed(p []byte) {
	if w.done {
		return
	}
	if len(w.buf)+len(p) > maxObserved {
		w.giveUp()
		return
	}
	w.buf = append(w.buf, p...)
	for len(w.buf) > 0 {
		// Only a handshake or a ChangeCipherSpec record (TLS 1.x) can come before the ServerHello: anything else is not one, said as soon as it shows.
		if (w.buf[0] != 20 && w.buf[0] != 22) || (len(w.buf) >= 2 && w.buf[1] != 3) {
			w.giveUp()
			return
		}
		if len(w.buf) < 5 {
			return
		}
		n := int(w.buf[3])<<8 | int(w.buf[4])
		if len(w.buf) < 5+n {
			return // the rest of the record is still on its way
		}
		typ, payload := w.buf[0], w.buf[5:5+n]
		w.buf = w.buf[5+n:]
		if typ == 22 && !w.handshake(payload) {
			return
		} // (a ChangeCipherSpec of the TLS 1.3 compatibility mode is not a hello: keep reading)
	}
}

// handshake reads the hello a handshake record starts with. It reports whether the watcher goes on (a retry request is followed by a ServerHello).
func (w *serverHelloWatch) handshake(payload []byte) bool {
	if len(payload) < 4 || payload[0] != 2 {
		w.giveUp()
		return false
	}
	l := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if len(payload) < 4+l { // a ServerHello split over records: not seen in practice, not observed
		w.giveUp()
		return false
	}
	sh, ok := parseServerHello(payload[4 : 4+l])
	if !ok {
		w.giveUp()
		return false
	}
	w.seen++
	if sh.retry {
		w.m.obsRetry.Add(1)
		if w.seen >= 2 { // two retries are not a handshake
			w.giveUp()
			return false
		}
		return true
	}
	w.m.obsVersion.inc(versionWord(sh.version))
	w.m.obsCipher.inc(cipherWord(sh.cipher))
	if sh.hasGroup {
		w.m.obsGroup.inc(groupWord(sh.group))
	} else {
		w.m.obsGroup.inc(obsNoGroup)
	}
	w.done, w.buf = true, nil
	return false
}

// giveUp stops watching a stream whose first bytes were not a ServerHello the observer follows.
func (w *serverHelloWatch) giveUp() {
	w.m.obsUnparsed.Add(1)
	w.done, w.buf = true, nil
}

// observeClientHello counts what a ClientHello offered. peeked is the bytes the node read to find the SNI.
func (m *metrics) observeClientHello(peeked []byte) {
	scan := scanClientHello(peeked)
	if !scan.complete || scan.err != nil {
		return
	}
	shape := shapeOfClientHello(scan.hello)
	if !shape.ok {
		return
	}
	m.obsHellos.Add(1)
	seen := map[string]bool{} // a group counts once per ClientHello, however many times it is listed
	for _, g := range shape.groups {
		if w := groupWord(g); !seen[w] {
			seen[w] = true
			m.obsOffered.inc(w)
		}
	}
	if shape.ech {
		m.obsECH.Add(1)
	}
}

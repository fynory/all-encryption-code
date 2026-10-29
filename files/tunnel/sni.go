package main

import (
	"errors"
	"net"
	"strings"
	"time"
)

// This file reads the CLEARTEXT part of a TLS ClientHello, only to learn the
// server name (SNI) the client asked for. Nothing in this program ever
// decrypts, terminates or alters a client's TLS session: the bytes read here
// are replayed verbatim to the device, which is the real TLS server.

const (
	recordTypeHandshake  = 22
	handshakeClientHello = 1

	maxRecordPayload    = 1 << 14 // TLS plaintext record limit
	maxClientHelloBytes = 64 << 10
	maxHelloRecords     = 32
	// Upper bound on the bytes buffered while looking for the SNI.
	maxPeek = maxClientHelloBytes + maxHelloRecords*5 + 4
)

var (
	errNotTLS         = errors.New("not a TLS handshake record")
	errNotClientHello = errors.New("handshake is not a ClientHello")
	errHelloMalformed = errors.New("malformed ClientHello")
	errHelloTooLarge  = errors.New("ClientHello too large")
	errBadSNI         = errors.New("invalid server name")
)

// helloScan is the outcome of looking at a prefix of the client's bytes.
type helloScan struct {
	complete bool   // the whole ClientHello message is present
	sni      string // normalized server name; "" when the extension is absent
	need     int    // when !complete: total buffer length required before rescanning is useful
	err      error
	hello    []byte // when complete: the ClientHello's body (the observer reads the groups it offers from it)
}

// scanClientHello inspects buf, the bytes received so far from a client. It
// never panics on any input and never reads outside buf. The handshake message
// may be split across several TLS records (rare, but legal) and across any
// number of TCP reads.
func scanClientHello(buf []byte) helloScan {
	if len(buf) == 0 {
		return helloScan{need: 1}
	}
	var hs []byte
	off := 0
	for rec := 0; ; rec++ {
		if rec >= maxHelloRecords {
			return helloScan{err: errHelloMalformed}
		}
		if len(buf)-off >= 1 && buf[off] != recordTypeHandshake {
			return helloScan{err: errNotTLS}
		}
		if len(buf)-off >= 2 && buf[off+1] != 3 {
			return helloScan{err: errNotTLS}
		}
		if len(buf)-off < 5 {
			return helloScan{need: off + 5}
		}
		n := int(buf[off+3])<<8 | int(buf[off+4])
		if n == 0 || n > maxRecordPayload {
			return helloScan{err: errHelloMalformed}
		}
		if len(buf)-off-5 < n {
			return helloScan{need: off + 5 + n}
		}
		hs = append(hs, buf[off+5:off+5+n]...)
		off += 5 + n

		if len(hs) >= 1 && hs[0] != handshakeClientHello {
			return helloScan{err: errNotClientHello}
		}
		if len(hs) >= 4 {
			l := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
			if l > maxClientHelloBytes {
				return helloScan{err: errHelloTooLarge}
			}
			if len(hs) >= 4+l {
				sni, err := parseClientHelloBody(hs[4 : 4+l])
				return helloScan{complete: true, sni: sni, err: err, hello: hs[4 : 4+l]}
			}
		}
	}
}

// cursor is a bounds-checked reader over a byte slice.
type cursor struct {
	b   []byte
	bad bool
}

func (c *cursor) take(n int) []byte {
	if c.bad || n < 0 || n > len(c.b) {
		c.bad = true
		return nil
	}
	out := c.b[:n]
	c.b = c.b[n:]
	return out
}

func (c *cursor) u8() int {
	b := c.take(1)
	if b == nil {
		return 0
	}
	return int(b[0])
}

func (c *cursor) u16() int {
	b := c.take(2)
	if b == nil {
		return 0
	}
	return int(b[0])<<8 | int(b[1])
}

// parseClientHelloBody walks a ClientHello body (the bytes after the 4-byte
// handshake header) and returns the normalized host_name from the
// server_name extension: "" when there is none, errBadSNI when it is present
// but unusable.
func parseClientHelloBody(b []byte) (string, error) {
	c := &cursor{b: b}
	c.take(2)  // legacy_version
	c.take(32) // random
	c.take(c.u8())
	if cs := c.u16(); cs < 2 || cs%2 != 0 {
		return "", errHelloMalformed
	} else {
		c.take(cs)
	}
	c.take(c.u8()) // compression methods
	if c.bad {
		return "", errHelloMalformed
	}
	if len(c.b) == 0 {
		return "", nil // no extensions at all
	}
	extLen := c.u16()
	ext := &cursor{b: c.take(extLen)}
	if c.bad || len(c.b) != 0 { // the extensions end the message: bytes after them are a hello that lies about its own length
		return "", errHelloMalformed
	}
	found := false
	name := ""
	for len(ext.b) > 0 {
		typ := ext.u16()
		data := &cursor{b: ext.take(ext.u16())}
		if ext.bad {
			return "", errHelloMalformed
		}
		if typ != 0 { // server_name
			continue
		}
		if found {
			return "", errHelloMalformed // duplicate extension
		}
		found = true
		listLen := data.u16()
		list := &cursor{b: data.take(listLen)}
		if data.bad || len(data.b) != 0 {
			return "", errHelloMalformed
		}
		hostNames := 0
		for len(list.b) > 0 {
			nameType := list.u8()
			raw := list.take(list.u16())
			if list.bad {
				return "", errHelloMalformed
			}
			if nameType != 0 {
				continue
			}
			hostNames++
			if hostNames > 1 {
				return "", errHelloMalformed
			}
			n, ok := normalizeName(string(raw))
			if !ok {
				return "", errBadSNI
			}
			name = n
		}
	}
	return name, nil
}

// readClientHello reads from c until the ClientHello is complete (or invalid,
// too large, or the deadline passes). It returns EVERY byte it read from the
// connection, which the caller must forward to the device first.
func readClientHello(c net.Conn, timeout time.Duration) (peeked []byte, sni string, err error) {
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()

	buf := make([]byte, 0, 2048)
	need := 1
	for {
		for len(buf) >= need {
			res := scanClientHello(buf)
			if res.err != nil {
				return buf, "", res.err
			}
			if res.complete {
				return buf, res.sni, nil
			}
			need = res.need
			if need > maxPeek {
				return buf, "", errHelloTooLarge
			}
		}
		if len(buf) == cap(buf) {
			next := 2 * cap(buf)
			if next > maxPeek {
				next = maxPeek
			}
			if next <= len(buf) {
				return buf, "", errHelloTooLarge
			}
			grown := make([]byte, len(buf), next)
			copy(grown, buf)
			buf = grown
		}
		n, rerr := c.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if rerr != nil {
			if n > 0 && len(buf) >= need {
				continue // decide on what we have before reporting the error
			}
			return buf, "", rerr
		}
	}
}

// normalizeName is the one way a server name becomes a routing key, for an SNI and for a Host header alike: lower case, at most one trailing dot
// removed, then strict LDH. A name the table could hold under two spellings, or that a resolver would read differently from the node, is refused:
// letters, digits and hyphens only (no underscore), labels of 1..63 bytes that neither start nor end with a hyphen, at most 253 bytes in all, a last
// label that is not all digits (so no dotted-decimal address in disguise) and not an IP literal. The device's own name always passes: it is one
// label under a zone.
func normalizeName(s string) (string, bool) {
	b := []byte(s)
	for i, ch := range b {
		if ch >= 'A' && ch <= 'Z' {
			b[i] = ch + ('a' - 'A')
		}
	}
	s = string(b)
	if len(s) > 1 && s[len(s)-1] == '.' {
		s = s[:len(s)-1]
	}
	if s == "" || len(s) > 253 || net.ParseIP(s) != nil {
		return "", false
	}
	start := 0
	for i := 0; i <= len(s); i++ {
		if i < len(s) && s[i] != '.' {
			ch := s[i]
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return "", false
			}
			continue
		}
		label := s[start:i]
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		if i == len(s) && strings.Trim(label, "0123456789") == "" {
			return "", false
		}
		start = i + 1
	}
	return s, true
}

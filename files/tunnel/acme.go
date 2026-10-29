package main

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Port 80 serves ONE thing: the HTTP-01 challenge files of the node's own certificate, from the webroot its certificate client writes. It never
// forwards a byte to a device (a certificate for a device is issued over DNS-01 and the CAA allows nothing else), it answers only for the node's own
// name, and everything else is a 404.

const (
	maxACMEHeadBytes = 8 << 10

	resp404 = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
)

var acmePathRE = regexp.MustCompile(`^/\.well-known/acme-challenge/([A-Za-z0-9_-]{1,128})$`)

// hostOnly strips an optional :port and normalizes a Host header value.
func hostOnly(h string) (string, bool) {
	if i := strings.LastIndexByte(h, ':'); i >= 0 && !strings.Contains(h[i:], "]") {
		h = h[:i]
	}
	return normalizeName(h)
}

// readHTTPHead reads up to the end of the request head (CRLF CRLF).
func readHTTPHead(c net.Conn, timeout time.Duration) ([]byte, error) {
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	buf := make([]byte, 0, 1024)
	searched := 0
	for {
		if len(buf) == cap(buf) {
			if cap(buf) >= maxACMEHeadBytes {
				return nil, errHelloTooLarge
			}
			grown := make([]byte, len(buf), min(2*cap(buf), maxACMEHeadBytes))
			copy(grown, buf)
			buf = grown
		}
		n, err := c.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		from := max(0, searched-3)
		if i := bytes.Index(buf[from:], []byte("\r\n\r\n")); i >= 0 {
			return buf[:from+i+4], nil
		}
		searched = len(buf)
		if err != nil {
			return nil, err
		}
	}
}

// acmeChallenge reads the challenge file of a token from the webroot: a regular file (never a link) no larger than the cap.
func (s *Server) acmeChallenge(token string) ([]byte, bool) {
	if s.cfg.ACMEWebroot == "" {
		return nil, false
	}
	path := filepath.Join(s.cfg.ACMEWebroot, ".well-known", "acme-challenge", token)
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() > s.cfg.ACMEMaxBytes {
		return nil, false
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, s.cfg.ACMEMaxBytes+1))
	if err != nil || int64(len(body)) > s.cfg.ACMEMaxBytes {
		return nil, false
	}
	return body, true
}

// handleHTTP serves only GET/HEAD /.well-known/acme-challenge/<token> for the node's own name; everything else is a 404.
func (s *Server) handleHTTP(c net.Conn) {
	defer s.wg.Done()
	defer c.Close()
	// The same sources, the same limits as :443: a source that floods one port does not get a second budget on the other.
	if peer, ok, fromOpenAI := s.sourceOf(c); ok {
		release, why := s.ips.admit(peer, fromOpenAI)
		if why != "" {
			s.met.rejected.inc(why)
			return
		}
		defer release()
	}
	if !tryAcquire(&s.unauth, int64(s.cfg.MaxUnauth)) {
		return
	}
	defer s.unauth.Add(-1)

	head, err := readHTTPHead(c, s.cfg.HelloTimeout)
	if err != nil {
		return
	}
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(head)))
	if err != nil {
		return
	}
	_ = c.SetWriteDeadline(time.Now().Add(s.cfg.ACMETimeout))
	reply404 := func(reason string) {
		s.log.Debug("acme_reject", "reason", reason)
		_, _ = io.WriteString(c, resp404)
	}
	host, hostOK := hostOnly(req.Host)
	if !hostOK || host != s.cfg.NodeHost {
		reply404("not_own_host")
		return
	}
	m := acmePathRE.FindStringSubmatch(req.RequestURI)
	if (req.Method != http.MethodGet && req.Method != http.MethodHead) || m == nil {
		reply404("not_acme_path")
		return
	}
	body, found := s.acmeChallenge(m[1])
	if !found {
		reply404("no_challenge")
		return
	}
	_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "+strconv.Itoa(len(body))+"\r\nConnection: close\r\n\r\n")
	if req.Method == http.MethodGet {
		_, _ = c.Write(body)
	}
}

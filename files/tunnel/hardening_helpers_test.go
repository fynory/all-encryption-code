package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// Every test client of this package comes from loopback, which is ONE source. The hardening tests need many: virtualIPs gives each connection the source
// address the test names. The test dials from a local port it chose and records which address that port stands for; the node's peerOf hook reads the
// record by the connection's remote port. (Nothing of this is in the production build: Config.peerOf is nil there.)
type virtualIPs struct {
	mu     sync.Mutex
	byPort map[int]netip.Addr
	next   int
}

func newVirtualIPs() *virtualIPs {
	return &virtualIPs{byPort: map[int]netip.Addr{}, next: 20000 + rand.IntN(6000)}
}

// peerOf is the node's hook: the address a port stands for, or the real remote address of a connection nobody chose one for.
func (v *virtualIPs) peerOf(c net.Conn) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(c.RemoteAddr().String()); err == nil {
		v.mu.Lock()
		addr, ok := v.byPort[int(ap.Port())]
		v.mu.Unlock()
		if ok {
			return addr, true
		}
	}
	return peerAddr(c)
}

// dial opens a TCP connection to addr that the node sees as coming from ip.
func (v *virtualIPs) dial(ip, addr string) (net.Conn, error) {
	want := netip.MustParseAddr(ip)
	var last error
	for try := 0; try < 400; try++ {
		v.mu.Lock()
		port := v.next
		if v.next++; v.next >= 32000 {
			v.next = 20000
		}
		v.byPort[port] = want
		v.mu.Unlock()
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}, Timeout: 3 * time.Second}
		c, err := d.Dial("tcp", addr)
		if err == nil {
			return c, nil
		}
		if !strings.Contains(err.Error(), "address already in use") && !strings.Contains(err.Error(), "can't assign requested address") {
			return nil, err
		}
		last = err
	}
	return nil, last
}

// newVIPEnv is newTestEnv with source addresses a test can choose (e.vip.dial, e.clientFrom). The per-source limits are the policy's here: a test that
// wants other numbers sets them in mutate.
func newVIPEnv(t *testing.T, mutate func(*testEnv, *Config)) *testEnv {
	t.Helper()
	vip := newVirtualIPs()
	return newEnv(t, nil, func(e *testEnv, cfg *Config) {
		e.vip = vip
		cfg.peerOf = vip.peerOf
		cfg.PerIPConcurrent, cfg.PerIPNewPerS = DefaultConfig().PerIPConcurrent, DefaultConfig().PerIPNewPerS
		cfg.UnknownSNIPerIP, cfg.LabelNewPerS, cfg.LabelNewBurst = DefaultConfig().UnknownSNIPerIP, DefaultConfig().LabelNewPerS, DefaultConfig().LabelNewBurst
		cfg.LabelAnonSlice = DefaultConfig().LabelAnonSlice
		if mutate != nil {
			mutate(e, cfg)
		}
	})
}

// clientFrom connects to device d the way a ChatGPT client at address ip does and completes the TLS handshake with the device. The error is what the
// client saw: a node that drops a source without an answer shows as a closed or reset connection, one that refuses with an alert as "internal error".
func (e *testEnv) clientFrom(ip string, d *testDevice) (*tls.Conn, error) {
	raw, err := e.vip.dial(ip, e.httpsAddr)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, &tls.Config{ServerName: d.host, RootCAs: d.pool, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
	_ = tc.SetDeadline(time.Now().Add(4 * time.Second))
	if err := tc.Handshake(); err != nil {
		_ = raw.Close()
		return nil, err
	}
	_ = tc.SetDeadline(time.Time{})
	e.t.Cleanup(func() { _ = tc.Close() })
	return tc, nil
}

// helloFrom connects from ip and sends a ClientHello for host (no device behind it needed); it returns the connection and what the node did, as the
// bytes it answered with until it closed (a TLS alert is 7 bytes, a dropped source is none) and whether it closed within the wait.
func (e *testEnv) helloFrom(ip, host string, wait time.Duration) (answer []byte, closed bool) {
	e.t.Helper()
	raw, err := e.vip.dial(ip, e.httpsAddr)
	if err != nil {
		e.t.Fatal(err)
	}
	defer raw.Close()
	_, _ = raw.Write(helloOf(host, 0, 16000))
	_ = raw.SetReadDeadline(time.Now().Add(wait))
	b, err := io.ReadAll(raw)
	var ne net.Error
	return b, !(errors.As(err, &ne) && ne.Timeout())
}

// metricValue reads one series of the node's metrics text ("name" or `name{label="word"}`).
func (e *testEnv) metricValue(series string) int64 {
	e.t.Helper()
	for _, line := range strings.Split(e.srv.renderMetrics(), "\n") {
		if rest, ok := strings.CutPrefix(line, series+" "); ok {
			var n int64
			if _, err := fmt.Sscan(rest, &n); err != nil {
				e.t.Fatalf("series %s: %q", series, line)
			}
			return n
		}
	}
	e.t.Fatalf("no series %s in the metrics:\n%s", series, e.srv.renderMetrics())
	return 0
}

// rejected is how many connections the node counted as refused for reason.
func (e *testEnv) rejected(reason string) int64 {
	return e.metricValue(fmt.Sprintf(`all_tunnel_conn_rejected_total{reason=%q}`, reason))
}

// httpGet reads a loopback URL of the node's metrics listener.
func httpGet(t *testing.T, url string) (int, string, http.Header) {
	t.Helper()
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), resp.Header
}

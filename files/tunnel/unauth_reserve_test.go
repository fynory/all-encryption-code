package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"testing"
	"time"
)

// The unauthenticated budget keeps a reserve (policy node_limits.openai_reserved_pct), as the stream budget does. Before it, every connection took a slot of the whole
// budget before its ClientHello, so twenty addresses holding the most one source may hold (16 half-open connections each) took all 256 of them and every other connection,
// a ChatGPT client or a device reconnecting, was dropped with no answer for as long as the attack lasted (the chaos suite's slowloris check).
func TestNode_TwentyAnonymousSourcesCannotStarveChatGPTNorADeviceThatReconnects(t *testing.T) {
	release := make(chan struct{})
	e := newVIPEnv(t, func(e *testEnv, c *Config) {
		c.PerIPConcurrent, c.MaxUnauth, c.OpenAIReservedPct, c.HelloTimeout = 4, 16, 25, 20*time.Second
		c.PrefixFetch = func(context.Context) ([]byte, error) { return []byte(listOf("192.0.2.0/24")), nil }
	})
	eventually(t, "the OpenAI list", 3*time.Second, func() bool { return e.srv.openai.size() == 1 })
	d := e.newDevice()
	dc := e.connectOK(d)
	dc.serve(holdHandler(d, release))
	defer close(release)
	// a second device, at an address of its own, connects once and lets go: it will be a device that reconnects
	const home = "198.51.100.200"
	back := e.newDevice()
	first := e.connectOKFrom(home, back)
	_ = first.c.Close()
	eventually(t, "the node saw the control connection go", 3*time.Second, func() bool {
		return e.srv.ips.knownDevice(netip.MustParseAddr(home)) && !e.srv.ips.isDevice(netip.MustParseAddr(home))
	})

	// twenty anonymous sources, each holding the most it may hold, saying nothing
	var idle []net.Conn
	for source := 0; source < 20; source++ {
		ip := "198.51.100." + itoa(100+source)
		for i := 0; i < 4; i++ {
			c, err := e.vip.dial(ip, e.httpsAddr)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			idle = append(idle, c)
		}
	}
	share := e.srv.anonUnauthMax()
	if share != 12 {
		t.Fatalf("the anonymous share is %d, want 16 less the reserve of 25 percent: 12", share)
	}
	eventually(t, "the anonymous share is full and the rest were refused", 4*time.Second, func() bool {
		return e.srv.anonUnauth.Load() == share && e.rejected("unauth_anon_limit") >= int64(len(idle))-share
	})
	if got := e.srv.unauth.Load(); got > share {
		t.Fatalf("the attack holds %d unauthenticated slots of 16: more than its share of %d", got, share)
	}

	// ChatGPT (an address of the OpenAI list) is served through the attack
	good, err := e.clientFrom("192.0.2.9", d)
	if err != nil {
		t.Fatalf("a client from the OpenAI list was turned away while twenty anonymous sources held the budget: %v", err)
	}
	_ = good.Close()
	// a device that reconnects (it held a control connection a moment ago, from this address) gets its HELLO through; one nobody knows waits
	_ = e.connectOKFrom(home, back)
	stranger := e.newDevice()
	if conn, err := e.dialFrom("198.51.100.201"); err == nil {
		line := (&devConn{t: t, e: e, d: stranger, c: conn, br: bufio.NewReaderSize(conn, 1<<17)})
		if _, err := line.try(2 * time.Second); err == nil {
			t.Fatalf("a device from an address nobody knows got an answer through a full anonymous share")
		}
	}
	// an anonymous source with no reason to be trusted is the one that waits: the share is the price of the reserve
	if _, err := e.clientFrom("203.0.113.77", d); err == nil {
		t.Fatalf("an anonymous source got through a full anonymous share")
	}
	// when the attack ends the share is free again
	for _, c := range idle {
		_ = c.Close()
	}
	eventually(t, "the anonymous share is free", 4*time.Second, func() bool { return e.srv.anonUnauth.Load() == 0 })
	later, err := e.clientFrom("203.0.113.77", d)
	if err != nil {
		t.Fatalf("an anonymous source is still refused after the attack: %v", err)
	}
	_ = later.Close()
}

// dialFrom connects to the node's own name the way a device at ip does (the source address is the test's choice).
func (e *testEnv) dialFrom(ip string) (*tls.Conn, error) {
	raw, err := e.vip.dial(ip, e.httpsAddr)
	if err != nil {
		return nil, err
	}
	c := tls.Client(raw, &tls.Config{ServerName: testNodeHost, RootCAs: e.nodePool, NextProtos: []string{policyData.Protocol.ALPN}, MinVersion: tls.VersionTLS13})
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if err := c.Handshake(); err != nil {
		_ = raw.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	e.t.Cleanup(func() { _ = c.Close() })
	return c, nil
}

// connectOKFrom is connectOK from a source address of the test's choice.
func (e *testEnv) connectOKFrom(ip string, d *testDevice) *devConn {
	e.t.Helper()
	c, err := e.dialFrom(ip)
	if err != nil {
		e.t.Fatalf("the device at %s was turned away: %v", ip, err)
	}
	dc := &devConn{t: e.t, e: e, d: d, c: c, br: bufio.NewReaderSize(c, 1<<17)}
	line := dc.hello(func() string { return e.session(d, nil) }, func(s, n string) string { return e.proof(d, s, n, nil) })
	m, err := parseLine(line, dirN2D)
	if err != nil || m.str("verb") != "OK" {
		e.t.Fatalf("handshake for %s from %s: %q", d.id, ip, line)
	}
	dc.ok = m
	return dc
}

func TestIPLimits_ADeviceThatLetGoIsKnownForHintTTLAndThenForgotten(t *testing.T) {
	l, clk := newTestLimits(t, func(c *Config) { c.HintTTL = 15 * time.Minute })
	addr := netip.MustParseAddr("203.0.113.5")
	if l.knownDevice(addr) {
		t.Fatal("an address nobody has seen is known as a device's")
	}
	unmark := l.markDevice(addr)
	if !l.knownDevice(addr) {
		t.Fatal("an address that holds a control connection is not known as a device's")
	}
	unmark()
	if !l.knownDevice(addr) {
		t.Fatal("a device that just let go is an anonymous source again at once: its reconnection would wait for the anonymous share")
	}
	clk.Advance(14 * time.Minute)
	if !l.knownDevice(addr) {
		t.Fatal("known for less than hint_ttl_s after the last connection ended")
	}
	clk.Advance(2 * time.Minute)
	if l.knownDevice(addr) {
		t.Fatal("known for longer than hint_ttl_s")
	}
	l.markDevice(addr)()
	clk.Advance(20 * time.Minute)
	l.Sweep()
	if len(l.past) != 0 {
		t.Fatalf("the sweep left %d remembered devices", len(l.past))
	}
}

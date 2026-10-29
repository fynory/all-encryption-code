package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"hash/maphash"
	"io"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// The limits of the public listener (limits.go): per source, per device host, global, and the ban for trying names that are not a device.

func newTestLimits(t *testing.T, mutate func(*Config)) (*ipLimits, *fakeClock) {
	t.Helper()
	cfg := DefaultConfig()
	if mutate != nil {
		mutate(&cfg)
	}
	fc := newFakeClock()
	return newIPLimits(&cfg, newClock(fc.Now, fc.AfterFunc), maphash.MakeSeed()), fc
}

func TestDefaultConfigHardeningIsThePolicysNumbers(t *testing.T) {
	cfg := DefaultConfig()
	for name, c := range map[string]struct{ got, key int }{
		"PerIPConcurrent":    {cfg.PerIPConcurrent, ctPolInt("node_limits.per_ip_concurrent")},
		"PerIPNewPerS":       {cfg.PerIPNewPerS, ctPolInt("node_limits.per_ip_new_per_s")},
		"IPv6PrefixBits":     {cfg.IPv6PrefixBits, ctPolInt("node_limits.ipv6_prefix_bits")},
		"IPTableMax":         {cfg.IPTableMax, ctPolInt("node_limits.ip_table_max")},
		"OpenAIPerIPFactor":  {cfg.OpenAIPerIPFactor, ctPolInt("node_limits.openai_per_ip_factor")},
		"DevicePerIPFactor":  {cfg.DevicePerIPFactor, ctPolInt("node_limits.device_per_ip_factor")},
		"UnknownSNIPerIP":    {cfg.UnknownSNIPerIP, ctPolInt("node_limits.unknown_sni_per_ip")},
		"LabelAnonSlice":     {cfg.LabelAnonSlice, ctPolInt("node_limits.label_anon_slice")},
		"LabelNewPerS":       {cfg.LabelNewPerS, ctPolInt("node_limits.label_new_per_s")},
		"LabelNewBurst":      {cfg.LabelNewBurst, ctPolInt("node_limits.label_new_burst")},
		"OpenAIReservedPct":  {cfg.OpenAIReservedPct, ctPolInt("node_limits.openai_reserved_pct")},
		"HintsPerLabel":      {cfg.HintsPerLabel, ctPolInt("node_limits.hint_addresses_per_label")},
		"GatedStreamsPerDay": {cfg.GatedStreamsPerDay, ctPolInt("gated.streams_per_day")},
	} {
		if c.got != c.key {
			t.Errorf("%s = %d, policy %d", name, c.got, c.key)
		}
	}
	for name, c := range map[string]struct {
		got time.Duration
		key string
	}{
		"UnknownSNIWindow":    {cfg.UnknownSNIWindow, "node_limits.unknown_sni_window_s"},
		"UnknownSNIBan":       {cfg.UnknownSNIBan, "node_limits.unknown_sni_ban_s"},
		"HintTTL":             {cfg.HintTTL, "node_limits.hint_ttl_s"},
		"TCPKeepalive":        {cfg.TCPKeepalive, "node_limits.tcp_keepalive_s"},
		"OpenAIPrefixRefresh": {cfg.OpenAIPrefixRefresh, "node_limits.openai_prefix_refresh_s"},
		"HelloTimeout":        {cfg.HelloTimeout, "node_limits.client_hello_deadline_s"},
		"StreamIdle":          {cfg.StreamIdle, "timing.stream_idle_s"},
		"StreamMaxAge":        {cfg.StreamMaxAge, "timing.stream_max_age_s"},
	} {
		if c.got != time.Duration(ctPolInt(c.key))*time.Second {
			t.Errorf("%s = %s, policy %s = %d", name, c.got, c.key, ctPolInt(c.key))
		}
	}
	if int64(cfg.GatedBytesPerDay) != int64(ctPol("gated.bytes_per_day").(float64)) {
		t.Errorf("GatedBytesPerDay = %d", cfg.GatedBytesPerDay)
	}
	if cfg.LabelAnonSlice+ctPolInt("node_limits.label_hint_slice") != cfg.MaxStreamsPerHost {
		t.Errorf("the anonymous slice %d and the hint slice %d are not the whole host cap %d", cfg.LabelAnonSlice, ctPolInt("node_limits.label_hint_slice"), cfg.MaxStreamsPerHost)
	}
}

func TestConfig_HardeningIsValidated(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"no per-source cap":         func(c *Config) { c.PerIPConcurrent = 0 },
		"no per-source rate":        func(c *Config) { c.PerIPNewPerS = 0 },
		"a prefix of 0 bits":        func(c *Config) { c.IPv6PrefixBits = 0 },
		"a prefix of 129 bits":      func(c *Config) { c.IPv6PrefixBits = 129 },
		"the whole node reserved":   func(c *Config) { c.OpenAIReservedPct = 100 },
		"no ban":                    func(c *Config) { c.UnknownSNIBan = 0 },
		"no hint life":              func(c *Config) { c.HintTTL = 0 },
		"no gated budget":           func(c *Config) { c.GatedBytesPerDay = 0 },
		"no keepalive":              func(c *Config) { c.TCPKeepalive = 0 },
		"no device factor":          func(c *Config) { c.DevicePerIPFactor = 0 },
		"metrics on the network":    func(c *Config) { c.MetricsAddr = "0.0.0.0:9101" },
		"metrics on a host name":    func(c *Config) { c.MetricsAddr = "example.org:9101" },
		"metrics without a port":    func(c *Config) { c.MetricsAddr = "127.0.0.1" },
		"prefix list over http":     func(c *Config) { c.OpenAIPrefixesURL = "http://example.org/list.json" },
		"prefix list with a secret": func(c *Config) { c.OpenAIPrefixesURL = "https://user:pass" + "@example.org/list.json" },
	} {
		cfg := DefaultConfig()
		cfg.HTTPSAddr, cfg.HTTPAddr = "", ""
		cfg.NodeID = "t1"
		cfg.Keys, cfg.Control = StaticKeys{}, &fakeControl{}
		mutate(&cfg)
		if err := cfg.validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	good := DefaultConfig()
	good.HTTPSAddr, good.HTTPAddr = "", ""
	good.NodeID = "t1"
	good.Keys, good.Control = StaticKeys{}, &fakeControl{}
	good.MetricsAddr, good.OpenAIPrefixesURL = "[::1]:9101", "http://127.0.0.1:8080/list.json"
	if err := good.validate(); err != nil {
		t.Errorf("a loopback metrics address and a loopback mirror: %v", err)
	}
}

func TestIPLimits_ConcurrentCapAndRateBucketPerSource(t *testing.T) {
	l, fc := newTestLimits(t, func(c *Config) { c.PerIPConcurrent, c.PerIPNewPerS = 3, 5 })
	a := netip.MustParseAddr("198.51.100.7")
	var releases []func()
	for i := 0; i < 3; i++ {
		rel, why := l.admit(a, false)
		if why != "" {
			t.Fatalf("connection %d: %s", i, why)
		}
		releases = append(releases, rel)
	}
	if _, why := l.admit(a, false); why != refuseConcurrent {
		t.Fatalf("a fourth concurrent connection: %q", why)
	}
	// another source is untouched
	if _, why := l.admit(netip.MustParseAddr("198.51.100.8"), false); why != "" {
		t.Fatalf("another source: %q", why)
	}
	releases[0]()
	releases[0]() // a second release of the same slot gives nothing back
	if _, why := l.admit(a, false); why != "" {
		t.Fatalf("after one release: %q", why)
	}
	if _, why := l.admit(a, false); why != refuseConcurrent {
		t.Fatalf("the double release freed a slot that was not its own: %q", why)
	}
	// the bucket: 5 new connections in a second, however fast they are released
	b := netip.MustParseAddr("203.0.113.1")
	admitted := 0
	for i := 0; i < 20; i++ {
		rel, why := l.admit(b, false)
		if why == "" {
			admitted++
			rel()
		} else if why != refuseRate {
			t.Fatalf("%q", why)
		}
	}
	if admitted != 5 {
		t.Fatalf("admitted %d in one instant, want the burst of 5", admitted)
	}
	fc.Advance(400 * time.Millisecond)
	got := 0
	for i := 0; i < 10; i++ {
		if rel, why := l.admit(b, false); why == "" {
			got++
			rel()
		}
	}
	if got != 2 {
		t.Fatalf("after 400 ms %d more were admitted, want 2 (5 per second)", got)
	}
}

func TestIPLimits_AnIPv6SourceIsItsPrefixAndAnOpenAIAddressHasLargerLimits(t *testing.T) {
	l, _ := newTestLimits(t, func(c *Config) { c.PerIPConcurrent, c.PerIPNewPerS, c.OpenAIPerIPFactor = 2, 100, 4 })
	hold := func(addr string, openai bool) string {
		_, why := l.admit(netip.MustParseAddr(addr), openai)
		return why
	}
	// ten addresses of one /64 are one source
	for i := 0; i < 2; i++ {
		if why := hold(fmt.Sprintf("2001:db8:aaaa:1::%x", i+1), false); why != "" {
			t.Fatalf("%q", why)
		}
	}
	for i := 3; i < 10; i++ {
		if why := hold(fmt.Sprintf("2001:db8:aaaa:1::%x", i), false); why != refuseConcurrent {
			t.Fatalf("address %d of the same /64: %q", i, why)
		}
	}
	// the next /64 is another source
	if why := hold("2001:db8:aaaa:2::1", false); why != "" {
		t.Fatalf("the next /64: %q", why)
	}
	// an address of the OpenAI list holds factor times as many
	got := 0
	for i := 0; i < 20; i++ {
		if hold("192.0.2.9", true) == "" {
			got++
		}
	}
	if got != 8 {
		t.Fatalf("an OpenAI address held %d, want 2*4", got)
	}
	// an IPv4-mapped address is the IPv4 address
	if why := hold("::ffff:192.0.2.77", false); why != "" {
		t.Fatalf("%q", why)
	}
	for i := 0; i < 2; i++ {
		_, why := l.admit(netip.MustParseAddr("192.0.2.77"), false)
		if i == 0 && why != "" {
			t.Fatalf("%q", why)
		}
		if i == 1 && why != refuseConcurrent {
			t.Fatalf("the mapped and the plain address are two sources: %q", why)
		}
	}
}

func TestIPLimits_UnknownNamesBanASourceForAWhileAndOnlyDistinctNamesCount(t *testing.T) {
	l, fc := newTestLimits(t, func(c *Config) {
		c.UnknownSNIPerIP, c.UnknownSNIWindow, c.UnknownSNIBan = 3, time.Minute, 10*time.Minute
	})
	a := netip.MustParseAddr("198.51.100.20")
	// the same offline device asked for again and again is not a scan
	for i := 0; i < 50; i++ {
		if l.strike(a, "offline.example.org", false) {
			t.Fatal("a repeated name banned the source")
		}
	}
	for _, name := range []string{"b", "c"} {
		if l.strike(a, name+".example.org", false) {
			t.Fatalf("banned at %s", name)
		}
	}
	if !l.strike(a, "d.example.org", false) {
		t.Fatal("the fourth distinct name (budget 3) did not ban")
	}
	if _, why := l.admit(a, false); why != refuseBanned {
		t.Fatalf("a banned source: %q", why)
	}
	if _, why := l.admit(netip.MustParseAddr("198.51.100.21"), false); why != "" {
		t.Fatalf("a ban reached another source: %q", why)
	}
	fc.Advance(9 * time.Minute)
	if _, why := l.admit(a, false); why != refuseBanned {
		t.Fatalf("still banned at 9 minutes: %q", why)
	}
	fc.Advance(2 * time.Minute)
	if _, why := l.admit(a, false); why != "" {
		t.Fatalf("the ban outlived its time: %q", why)
	}
	// the window: strikes older than it are forgotten
	b := netip.MustParseAddr("198.51.100.30")
	l.strike(b, "x1", false)
	l.strike(b, "x2", false)
	l.strike(b, "x3", false)
	fc.Advance(2 * time.Minute)
	if l.strike(b, "x4", false) {
		t.Fatal("strikes older than the window counted")
	}
	// junk (no TLS, no name) counts every time: there is no name to be the same
	c := netip.MustParseAddr("198.51.100.40")
	banned := false
	for i := 0; i < 4 && !banned; i++ {
		banned = l.strike(c, "", false)
	}
	if !banned {
		t.Fatal("four junk hellos did not ban")
	}
	// an address of the OpenAI list is never struck, whatever it tries
	o := netip.MustParseAddr("192.0.2.50")
	for i := 0; i < 100; i++ {
		if l.strike(o, fmt.Sprintf("n%d.example.org", i), true) {
			t.Fatal("an OpenAI address was banned")
		}
	}
	if _, why := l.admit(o, true); why != "" {
		t.Fatalf("%q", why)
	}
}

func TestIPLimits_ATableThatIsFullSharesAnOverflowEntryAndShrinksWhenIdle(t *testing.T) {
	l, fc := newTestLimits(t, func(c *Config) { c.IPTableMax, c.PerIPConcurrent, c.PerIPNewPerS = 4, 1, 1000 })
	for i := 0; i < 4; i++ {
		rel, why := l.admit(netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", i+1)), false)
		if why != "" {
			t.Fatal(why)
		}
		rel()
	}
	// the table is full of idle entries: a new source sweeps them and gets its own
	fc.Advance(2 * time.Second)
	if _, why := l.admit(netip.MustParseAddr("198.51.100.99"), false); why != "" {
		t.Fatalf("%q", why)
	}
	size, _, _, overflowed := l.snapshot()
	if size > 4 || overflowed != 0 {
		t.Fatalf("size %d, overflowed %d", size, overflowed)
	}
	// four sources that hold connections cannot be swept: the fifth shares the overflow entry, which is bounded as a crowd (not zero, not unbounded)
	l2, _ := newTestLimits(t, func(c *Config) { c.IPTableMax, c.PerIPConcurrent, c.PerIPNewPerS = 4, 1, 1000 })
	for i := 0; i < 4; i++ {
		if _, why := l2.admit(netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", i+1)), false); why != "" {
			t.Fatal(why)
		}
	}
	if _, why := l2.admit(netip.MustParseAddr("203.0.113.1"), false); why != "" {
		t.Fatalf("the first of the overflow: %q", why)
	}
	if _, _, _, overflowed := l2.snapshot(); overflowed == 0 {
		t.Fatal("no overflow was counted")
	}
	size, _, _, _ = l2.snapshot()
	if size != 4 {
		t.Fatalf("the table grew past its bound: %d", size)
	}
	// a later sweep drops what is idle
	l3, fc3 := newTestLimits(t, func(c *Config) { c.IPTableMax, c.PerIPNewPerS = 100, 1000 })
	for i := 0; i < 30; i++ {
		rel, _ := l3.admit(netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", i+1)), false)
		rel()
	}
	fc3.Advance(3 * time.Minute)
	l3.Sweep()
	if size, _, _, _ := l3.snapshot(); size != 0 {
		t.Fatalf("an idle table kept %d entries", size)
	}
}

func TestBucketAndLogSampler(t *testing.T) {
	var b bucket
	now := time.Now()
	taken := 0
	for i := 0; i < 10; i++ {
		if b.take(now, 2, 3) {
			taken++
		}
	}
	if taken != 3 {
		t.Fatalf("a burst of 3 gave %d", taken)
	}
	if !b.take(now.Add(time.Second), 2, 3) || !b.take(now.Add(time.Second), 2, 3) || b.take(now.Add(time.Second), 2, 3) {
		t.Fatal("two tokens a second")
	}
	fc := newFakeClock()
	s := newLogSampler(newClock(fc.Now, fc.AfterFunc))
	if ok, cut := s.allow("r"); !ok || cut != 0 {
		t.Fatal("the first line is written")
	}
	for i := 0; i < 5; i++ {
		if ok, _ := s.allow("r"); ok {
			t.Fatal("a repeat inside a second was written")
		}
	}
	if ok, _ := s.allow("other"); !ok {
		t.Fatal("another reason has its own second")
	}
	fc.Advance(1100 * time.Millisecond)
	if ok, cut := s.allow("r"); !ok || cut != 5 {
		t.Fatalf("ok=%v, left out %d, want 5", ok, cut)
	}
}

// ------------------------------------------------------------------------------------------------------------------------------------
// The node: what a source can do to it
// ------------------------------------------------------------------------------------------------------------------------------------

func TestNode_OneSourceCannotHoldMoreThanThePerIPCapNorFillTheGlobalBudget(t *testing.T) {
	release := make(chan struct{})
	e := newVIPEnv(t, func(e *testEnv, c *Config) {
		c.PerIPConcurrent, c.MaxUnauth, c.HelloTimeout = 4, 16, 3*time.Second
	})
	d := e.newDevice()
	dc := e.connectOK(d)
	dc.serve(holdHandler(d, release))
	defer close(release)

	// pre-hello: the attacker opens 40 connections and says nothing. Only 4 are served, and the budget everybody shares is not touched beyond them.
	var idle []net.Conn
	for i := 0; i < 40; i++ {
		c, err := e.vip.dial("198.51.100.66", e.httpsAddr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		idle = append(idle, c)
	}
	eventually(t, "the node counted the refused ones", 3*time.Second, func() bool { return e.rejected(refuseConcurrent) >= 36 })
	if got := e.srv.unauth.Load(); got > 4 {
		t.Fatalf("one source holds %d pre-hello slots, cap 4", got)
	}
	// somebody else is served through it
	good, err := e.clientFrom("203.0.113.5", d)
	if err != nil {
		t.Fatalf("a client of another source while one floods: %v", err)
	}
	_ = good.Close()

	// streams: the same source holds at most 4 streams to the device, the next one is dropped with no answer at all
	for _, c := range idle {
		_ = c.Close()
	}
	eventually(t, "the slots of the closed connections are back", 3*time.Second, func() bool { return e.srv.unauth.Load() == 0 })
	var held []*tls.Conn
	for i := 0; i < 8; i++ {
		tc, err := e.clientFrom("198.51.100.66", d)
		if err == nil {
			held = append(held, tc)
		}
	}
	if len(held) != 4 {
		t.Fatalf("one source held %d streams, cap 4", len(held))
	}
	// (the stream of the other source is still open too: the device holds it until the half-close timeout)
	eventually(t, "the streams open are the 4 held and the other source's", 3*time.Second, func() bool { return e.metricValue(`all_tunnel_streams_open`) == 5 })
	e.checkTranscript()
}

func TestNode_ANewConnectionRateLimitsASourceAndItRecoversWithTime(t *testing.T) {
	e := newVIPEnv(t, func(e *testEnv, c *Config) { c.PerIPNewPerS, c.PerIPConcurrent = 5, 1000 })
	dropped := 0
	for i := 0; i < 15; i++ {
		answer, closed := e.helloFrom("198.51.100.90", "nothing.devices.all-e2e.test", 300*time.Millisecond)
		if closed && len(answer) == 0 {
			dropped++
		}
	}
	if dropped != 10 {
		t.Fatalf("%d connections dropped without an answer, want 10 of 15 (burst of 5)", dropped)
	}
	if e.rejected(refuseRate) != 10 {
		t.Fatalf("counted %d", e.rejected(refuseRate))
	}
	e.offsetNS.Add(int64(3 * time.Second))
	if answer, _ := e.helloFrom("198.51.100.90", "nothing.devices.all-e2e.test", 300*time.Millisecond); len(answer) == 0 {
		t.Fatal("still dropped after the bucket refilled")
	}
}

func TestNode_UnknownNamesBanTheSourceAtAccept(t *testing.T) {
	e := newVIPEnv(t, func(e *testEnv, c *Config) {
		c.UnknownSNIPerIP, c.UnknownSNIBan, c.PerIPNewPerS = 3, 5*time.Minute, 1000
	})
	d := e.newDevice()
	dc := e.connectOK(d)
	dc.serve(nil)
	scanner := "198.51.100.101"
	for i := 0; i < 3; i++ {
		answer, _ := e.helloFrom(scanner, fmt.Sprintf("%020d.devices.all-e2e.test", i), time.Second)
		if len(answer) != 7 { // a TLS alert: the node answered
			t.Fatalf("name %d: %v", i, answer)
		}
	}
	// the fourth different name goes over the budget: it is still answered (the alert), and from then on the source is dropped at accept
	if answer, _ := e.helloFrom(scanner, "zzzzzzzzzzzzzzzzzzzz.devices.all-e2e.test", time.Second); len(answer) != 7 {
		t.Fatalf("the name that went over: %v", answer)
	}
	answer, closed := e.helloFrom(scanner, d.host, time.Second)
	if !closed || len(answer) != 0 {
		t.Fatalf("a banned source got %v (closed %v)", answer, closed)
	}
	if e.rejected(refuseBanned) != 1 || e.metricValue(`all_tunnel_ip_bans_total`) != 1 {
		t.Fatalf("counters: banned %d, bans %d", e.rejected(refuseBanned), e.metricValue(`all_tunnel_ip_bans_total`))
	}
	// the device's clients from anywhere else are served; so is ChatGPT retrying an OFFLINE device from one address (one name, however often)
	if tc, err := e.clientFrom("203.0.113.9", d); err != nil {
		t.Fatalf("another source: %v", err)
	} else {
		_ = tc.Close()
	}
	for i := 0; i < 10; i++ {
		if answer, _ := e.helloFrom("203.0.113.10", "offlineoffline22222.devices.all-e2e.test", time.Second); len(answer) != 7 {
			t.Fatalf("retry %d of an offline name: %v", i, answer)
		}
	}
	if answer, closed := e.helloFrom("203.0.113.10", d.host, time.Second); closed && len(answer) == 0 {
		t.Fatal("a source retrying one offline name was banned")
	}
	// the ban ends
	e.offsetNS.Add(int64(6 * time.Minute))
	if answer, closed := e.helloFrom(scanner, d.host, time.Second); closed && len(answer) == 0 {
		t.Fatal("still banned after the ban time")
	}
}

func TestNode_ClientsThatAreNotTLSAreStruckAndAnOpenAIAddressIsNeverBanned(t *testing.T) {
	var vipPrefix = "192.0.2.0/24"
	e := newVIPEnv(t, func(e *testEnv, c *Config) {
		c.UnknownSNIPerIP, c.PerIPNewPerS, c.PerIPConcurrent = 3, 1000, 1000
		c.PrefixFetch = func(context.Context) ([]byte, error) {
			return []byte(`{"prefixes":[{"ipv4Prefix":"` + vipPrefix + `"}]}`), nil
		}
	})
	eventually(t, "the prefix list is in", 3*time.Second, func() bool { return e.srv.openai.size() == 1 })
	junk := func(ip string) bool {
		raw, err := e.vip.dial(ip, e.httpsAddr)
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		_, _ = raw.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
		_ = raw.SetReadDeadline(time.Now().Add(time.Second))
		_, _ = io.ReadAll(raw)
		return true
	}
	for i := 0; i < 8; i++ {
		junk("198.51.100.150")
		junk("192.0.2.150") // ChatGPT's address
	}
	if answer, closed := e.helloFrom("198.51.100.150", "x.devices.all-e2e.test", time.Second); !closed || len(answer) != 0 {
		t.Fatalf("a source that sent junk four times was served: %v", answer)
	}
	if answer, _ := e.helloFrom("192.0.2.150", "x.devices.all-e2e.test", time.Second); len(answer) != 7 {
		t.Fatalf("an OpenAI address was dropped: %v", answer)
	}
}

func TestNode_SlowlorisBeforeTheClientHelloIsDroppedAtTheDeadlineWithoutAnOpen(t *testing.T) {
	// The real policy deadline (5 s), not a shortened one.
	e := newTestEnv(t, func(c *Config) { c.HelloTimeout = DefaultConfig().HelloTimeout })
	if DefaultConfig().HelloTimeout != 5*time.Second {
		t.Fatalf("the policy deadline is %s", DefaultConfig().HelloTimeout)
	}
	d := e.newDevice()
	dc := e.connectOK(d)
	ds := dc.serve(nil)
	ds.noAttach = true
	hello := helloOf(d.host, 0, 16000)
	c, err := net.DialTimeout("tcp", e.httpsAddr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	started := time.Now()
	done := make(chan time.Duration, 1)
	go func() {
		_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
		_, _ = io.ReadAll(c)
		done <- time.Since(started)
	}()
	// one byte a second, never the whole hello
	for i := 0; i < len(hello)/2 && time.Since(started) < 8*time.Second; i++ {
		if _, err := c.Write(hello[i : i+1]); err != nil {
			break
		}
		time.Sleep(time.Second)
	}
	select {
	case took := <-done:
		if took < 4500*time.Millisecond || took > 6500*time.Millisecond {
			t.Fatalf("dropped after %s, want about 5 s", took)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the slow client was never dropped")
	}
	if ds.openCount() != 0 {
		t.Fatal("an OPEN was sent for a ClientHello that never completed")
	}
	if e.logs.Count(`"reason":"hello_timeout"`) < 1 {
		t.Fatalf("logs:\n%s", e.logs.String())
	}
	if e.rejected("hello_timeout") != 1 {
		t.Fatalf("counted %d", e.rejected("hello_timeout"))
	}
}

func TestNode_ManyHeldStreamsFromManySourcesLeaveRoomForASourceTheDeviceMarkedGood(t *testing.T) {
	release := make(chan struct{})
	e := newVIPEnv(t, func(e *testEnv, c *Config) { c.PerIPNewPerS = 1000 })
	d := e.newDevice()
	dc := e.connectOK(d)
	ds := dc.serve(holdHandler(d, release))
	defer close(release)

	// 20 attacker sources, 4 attempts each: 80 attempts to hold 64 streams. The anonymous slice (16) is all they get.
	held := 0
	for i := 0; i < 20; i++ {
		for j := 0; j < 4; j++ {
			if _, err := e.clientFrom(fmt.Sprintf("198.51.100.%d", 100+i), d); err == nil {
				held++
			}
		}
	}
	if held != DefaultConfig().LabelAnonSlice {
		t.Fatalf("the attackers held %d streams, want the anonymous slice of %d", held, DefaultConfig().LabelAnonSlice)
	}
	if e.logs.Count(`"reason":"host_limit"`) < 1 {
		t.Fatalf("no host_limit in the logs:\n%s", e.logs.String())
	}
	// ChatGPT's address has not been marked: it cannot get in either, which is the price of a slice that is anonymous
	if _, err := e.clientFrom("203.0.113.77", d); err == nil {
		t.Fatal("an unmarked source got into a full anonymous slice")
	}
	// the device marks it (it just completed authenticated calls); now it has the reserved slice
	dc.send("HINT 203.0.113.77 203.0.113.78 203.0.113.79 203.0.113.80")
	eventually(t, "the hint is in the table", 3*time.Second, func() bool { return e.srv.hints.good(d.host, netip.MustParseAddr("203.0.113.80")) })
	tc, err := e.clientFrom("203.0.113.77", d)
	if err != nil {
		t.Fatalf("a marked source with the anonymous slice full: %v", err)
	}
	defer tc.Close()
	eventually(t, "the OPEN of the marked source", 3*time.Second, func() bool {
		for _, o := range ds.openList() {
			if o.str("peer_ip") == "203.0.113.77" {
				return o.str("class") == "hint"
			}
		}
		return false
	})
	// the marked sources can hold up to the whole host cap (16 held + 48 reserved), and no more
	more := 1
	for i := 0; i < 80; i++ {
		if _, err := e.clientFrom(fmt.Sprintf("203.0.113.%d", 77+i%4), d); err == nil {
			more++
		}
	}
	if want := ctPolInt("node_limits.label_streams_max") - held; more != want {
		t.Fatalf("the marked sources held %d more streams, want %d (the whole cap of the host)", more, want)
	}
	// the mark lasts hint_ttl_s and no longer
	e.offsetNS.Add(int64(DefaultConfig().HintTTL + time.Minute))
	if e.srv.hints.good(d.host, netip.MustParseAddr("203.0.113.77")) {
		t.Fatal("the mark outlived its TTL")
	}
}

func TestNode_AHintMarksAddressesOnlyForTheHostOfTheDeviceThatSentIt(t *testing.T) {
	e := newVIPEnv(t, nil)
	a, b := e.newDevice(), e.newDevice()
	ca, cb := e.connectOK(a), e.connectOK(b)
	ca.serve(nil)
	cb.serve(nil)
	ca.send("HINT 203.0.113.50 2001:db8::50")
	eventually(t, "the hint", 3*time.Second, func() bool { return e.srv.hints.good(a.host, netip.MustParseAddr("203.0.113.50")) })
	if e.srv.hints.good(b.host, netip.MustParseAddr("203.0.113.50")) {
		t.Fatal("a device marked an address for another device's host")
	}
	if !e.srv.hints.good(a.host, netip.MustParseAddr("2001:db8::50")) {
		t.Fatal("the IPv6 address was not marked")
	}
	// a HINT before the OK marks nothing: the connection has no host yet
	c := e.connect(e.newDevice())
	c.send("HINT 203.0.113.51")
	time.Sleep(100 * time.Millisecond)
	if e.srv.hints.size() != 2 {
		t.Fatalf("%d addresses in the table", e.srv.hints.size())
	}
}

func TestNode_PerHostNewStreamRateIsKeptForSourcesNotMarkedGood(t *testing.T) {
	release := make(chan struct{})
	e := newVIPEnv(t, func(e *testEnv, c *Config) { c.LabelNewPerS, c.LabelNewBurst = 2, 3 })
	d := e.newDevice()
	dc := e.connectOK(d)
	dc.serve(holdHandler(d, release))
	defer close(release)
	ok := 0
	for i := 0; i < 8; i++ {
		if _, err := e.clientFrom(fmt.Sprintf("198.51.100.%d", 10+i), d); err == nil {
			ok++
		}
	}
	if ok != 3 {
		t.Fatalf("%d streams began in an instant, want the burst of 3", ok)
	}
	if e.rejected("label_rate") != 5 {
		t.Fatalf("counted %d", e.rejected("label_rate"))
	}
	// a marked source is not paced by it (the stream cap still applies)
	dc.send("HINT 203.0.113.1")
	eventually(t, "the hint", 3*time.Second, func() bool { return e.srv.hints.good(d.host, netip.MustParseAddr("203.0.113.1")) })
	for i := 0; i < 6; i++ {
		if _, err := e.clientFrom("203.0.113.1", d); err != nil {
			t.Fatalf("marked stream %d: %v", i, err)
		}
	}
	// and time refills the bucket
	e.offsetNS.Add(int64(2 * time.Second))
	if _, err := e.clientFrom("198.51.100.99", d); err != nil {
		t.Fatalf("after a second the bucket had tokens again: %v", err)
	}
}

func TestNode_TheGlobalBudgetKeepsAShareForOpenAIAndMarkedSources(t *testing.T) {
	release := make(chan struct{})
	e := newVIPEnv(t, func(e *testEnv, c *Config) {
		c.MaxStreams, c.OpenAIReservedPct, c.LabelAnonSlice = 8, 25, 64
		c.PrefixFetch = func(context.Context) ([]byte, error) {
			return []byte(`{"prefixes":[{"ipv4Prefix":"192.0.2.0/24"}]}`), nil
		}
	})
	eventually(t, "the prefix list is in", 3*time.Second, func() bool { return e.srv.openai.size() == 1 })
	d := e.newDevice()
	dc := e.connectOK(d)
	ds := dc.serve(holdHandler(d, release))
	defer close(release)
	anon := 0
	for i := 0; i < 12; i++ {
		if _, err := e.clientFrom(fmt.Sprintf("198.51.100.%d", 10+i), d); err == nil {
			anon++
		}
	}
	if anon != 6 {
		t.Fatalf("anonymous sources held %d of 8, want 6 (25%% reserved)", anon)
	}
	if e.logs.Count(`"reason":"anon_global_limit"`) < 1 {
		t.Fatalf("logs:\n%s", e.logs.String())
	}
	for i := 0; i < 2; i++ {
		if _, err := e.clientFrom("192.0.2.9", d); err != nil {
			t.Fatalf("OpenAI stream %d: %v", i, err)
		}
	}
	if _, err := e.clientFrom("192.0.2.10", d); err == nil {
		t.Fatal("the budget of 8 was exceeded")
	}
	classes := map[string]int{}
	for _, o := range ds.openList() {
		classes[o.str("class")]++
	}
	if classes["openai"] != 2 || classes["anon"] != 6 {
		t.Fatalf("classes in the OPENs: %v", classes)
	}
}

func TestNode_EverySocketItAcceptsHasTCPKeepalive(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TCPKeepalive = 7 * time.Second
	s := &Server{cfg: cfg}
	lc := s.listenConfig()
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	srv := <-accepted
	defer srv.Close()
	raw, err := srv.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var on int
	var gerr error
	_ = raw.Control(func(fd uintptr) {
		on, gerr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE)
	})
	if gerr != nil || on == 0 {
		t.Fatalf("SO_KEEPALIVE = %d, %v", on, gerr)
	}
	if got := s.listenConfig().KeepAliveConfig; !got.Enable || got.Idle != 7*time.Second || got.Interval != 7*time.Second || got.Count != keepaliveProbes {
		t.Fatalf("%+v", got)
	}
}

// ------------------------------------------------------------------------------------------------------------------------------------
// The review's findings: a device's own connections, the overflow entry, the addresses of devices
// ------------------------------------------------------------------------------------------------------------------------------------

// simultaneousClients opens one stream to d from each address at the same time and returns how many were served and what failed.
func simultaneousClients(e *testEnv, d *testDevice, addrs []string) (ok int, failed []error) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, ip := range addrs {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			_, err := e.clientFrom(ip, d)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed = append(failed, err)
			} else {
				ok++
			}
		}(ip)
	}
	wg.Wait()
	return ok, failed
}

func TestNode_ADevicesOwnConnectionsAreNotChargedToTheAnonymousBucketAtPolicyLimits(t *testing.T) {
	release := make(chan struct{})
	e := newVIPEnv(t, nil) // the policy's per-source numbers: 16 held and 10 new a second per anonymous source
	d := e.newDevice()
	dc := e.connectOK(d)
	ds := dc.serve(holdHandler(d, release))
	defer close(release)
	// 32 sources the device marked good: only the device's own ATTACH connections (one per stream, all from its one address) are in question here
	var addrs []string
	var marked []string
	for i := 0; i < 32; i++ {
		addrs = append(addrs, fmt.Sprintf("203.0.113.%d", 1+i))
		marked = append(marked, addrs[i])
	}
	dc.send("HINT " + strings.Join(marked[:16], " "))
	dc.send("HINT " + strings.Join(marked[16:], " "))
	eventually(t, "the hints", 3*time.Second, func() bool { return e.srv.hints.good(d.host, netip.MustParseAddr(addrs[31])) })

	ok, failed := simultaneousClients(e, d, addrs)
	if ok != 32 {
		t.Fatalf("%d of 32 simultaneous streams were served (%v): the device's ATTACHes were refused as an anonymous source's connections (ip_rate %d, ip_concurrent %d)",
			ok, failed, e.rejected(refuseRate), e.rejected(refuseConcurrent))
	}
	if e.rejected(refuseRate)+e.rejected(refuseConcurrent) != 0 {
		t.Fatalf("refused at accept: ip_rate %d, ip_concurrent %d", e.rejected(refuseRate), e.rejected(refuseConcurrent))
	}
	if ds.openCount() != 32 {
		t.Fatalf("%d OPENs", ds.openCount())
	}
	// and the same device keeps its larger allowance only while it holds an authenticated control connection: when it is gone the address is anonymous again
	_ = dc.c.Close()
	eventually(t, "the device is gone", 3*time.Second, func() bool { return e.srv.controlCount() == 0 })
	eventually(t, "the address is no longer a device's", 3*time.Second, func() bool { return !e.srv.ips.isDevice(netip.MustParseAddr("127.0.0.1")) })
}

func TestIPLimits_ADeviceAddressHasLargerLimitsAndItsAuthenticatedConnectionsGiveTheirTokenBack(t *testing.T) {
	l, _ := newTestLimits(t, func(c *Config) { c.PerIPConcurrent, c.PerIPNewPerS, c.DevicePerIPFactor = 100, 3, 4 })
	// an anonymous source is held to 3 new connections in an instant
	a := netip.MustParseAddr("198.51.100.7")
	for i := 0; i < 3; i++ {
		if _, why := l.admit(a, false); why != "" {
			t.Fatal(why)
		}
	}
	if _, why := l.admit(a, false); why != refuseRate {
		t.Fatalf("%q", why)
	}
	// the address of a device has 4 times that (12), from the moment its control connection authenticates, though its bucket was made before
	b := netip.MustParseAddr("198.51.100.8")
	if _, why := l.admit(b, false); why != "" { // the control connection, admitted as any source's
		t.Fatal(why)
	}
	unmark := l.markDevice(b)
	if !l.isDevice(b) {
		t.Fatal("not a device")
	}
	var rels []func()
	for i := 0; i < 12; i++ {
		rel, why := l.admit(b, false)
		if why != "" {
			t.Fatalf("connection %d of the device: %q", i+1, why)
		}
		rels = append(rels, rel)
	}
	if _, why := l.admit(b, false); why != refuseRate {
		t.Fatalf("the thirteenth after the mark: %q", why)
	}
	// the ones that proved who they are (attached) give their token back: all of them are in the bucket again
	for _, rel := range rels {
		l.refund(b, false)
		rel()
	}
	for i := 0; i < 12; i++ {
		if _, why := l.admit(b, false); why != "" {
			t.Fatalf("after the refunds, connection %d: %q", i+1, why)
		}
	}
	// a refund never fills the bucket past its burst
	for i := 0; i < 50; i++ {
		l.refund(b, false)
	}
	if got := l.entries[l.keyOf(b)].tokens; got > 12 {
		t.Fatalf("%v tokens in a bucket of 12", got)
	}
	unmark()
	unmark() // once
	if l.isDevice(b) {
		t.Fatal("still a device after its connection ended")
	}
	// two devices behind one address: it stays a device until the last one is gone
	u1, u2 := l.markDevice(b), l.markDevice(b)
	u1()
	if !l.isDevice(b) {
		t.Fatal("one device left, the address is no longer one")
	}
	u2()
	if l.isDevice(b) || len(l.devices) != 0 {
		t.Fatal("the table of devices did not empty")
	}
}

func TestIPLimits_TheOverflowEntryIsNeverStruckNorBanned(t *testing.T) {
	l, _ := newTestLimits(t, func(c *Config) { c.IPTableMax, c.PerIPConcurrent, c.PerIPNewPerS, c.UnknownSNIPerIP = 4, 1, 1000, 3 })
	for i := 0; i < 4; i++ { // four sources that hold connections fill the table and cannot be swept
		if _, why := l.admit(netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", i+1)), false); why != "" {
			t.Fatal(why)
		}
	}
	scanner := netip.MustParseAddr("203.0.113.9")
	for i := 0; i < 10; i++ {
		if l.strike(scanner, fmt.Sprintf("n%d.example.org", i), false) {
			t.Fatalf("a scanner inside the overflow banned the whole crowd with name %d", i)
		}
	}
	if _, _, bans, _ := l.snapshot(); bans != 0 {
		t.Fatalf("%d bans", bans)
	}
	// an innocent new source (it too lands in the overflow) is served as before
	if _, why := l.admit(netip.MustParseAddr("192.0.2.77"), false); why != "" {
		t.Fatalf("an innocent new source was refused: %q", why)
	}
	// a source with an entry of its own is still struck and banned
	l2, _ := newTestLimits(t, func(c *Config) { c.UnknownSNIPerIP = 3 })
	banned := false
	for i := 0; i < 4; i++ {
		banned = l2.strike(scanner, fmt.Sprintf("n%d.example.org", i), false)
	}
	if !banned {
		t.Fatal("a source of its own was not banned")
	}
}

func TestNode_ASourceADeviceMarkedGoodIsNeverBannedForTheNamesItAsks(t *testing.T) {
	e := newVIPEnv(t, func(e *testEnv, c *Config) { c.UnknownSNIPerIP, c.PerIPNewPerS = 3, 1000 })
	d := e.newDevice()
	dc := e.connectOK(d)
	dc.serve(nil)
	dc.send("HINT 203.0.113.50")
	eventually(t, "the hint", 3*time.Second, func() bool { return e.srv.hints.goodAnywhere(netip.MustParseAddr("203.0.113.50")) })
	// a shared egress address that the fleet knows: many devices are offline at any moment, so it asks for many names
	for i := 0; i < 10; i++ {
		if answer, closed := e.helloFrom("203.0.113.50", fmt.Sprintf("off%d.%s", i, testZone), 500*time.Millisecond); closed && len(answer) == 0 {
			t.Fatalf("name %d: the marked address was dropped without an answer", i)
		}
	}
	if e.metricValue(`all_tunnel_ip_bans_total`) != 0 {
		t.Fatal("a marked address was banned")
	}
	// the same behaviour from an address nobody marked is a scan
	for i := 0; i < 10; i++ {
		e.helloFrom("198.51.100.50", fmt.Sprintf("off%d.%s", i, testZone), 500*time.Millisecond)
	}
	if e.metricValue(`all_tunnel_ip_bans_total`) != 1 {
		t.Fatal("an unmarked scanner was not banned")
	}
}

func TestNode_AMetricsPortThatIsTakenDoesNotKeepTheNodeFromStarting(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	e := newVIPEnv(t, func(e *testEnv, c *Config) { c.MetricsAddr = taken.Addr().String() })
	if e.srv.MetricsAddr() != "" {
		t.Fatalf("metrics listen on %s", e.srv.MetricsAddr())
	}
	if e.logs.Count(`"msg":"metrics_unavailable"`) != 1 || strings.Contains(e.logs.String(), taken.Addr().String()) {
		t.Fatalf("logs:\n%s", e.logs.String())
	}
	d := e.newDevice()
	e.connectOK(d).serve(nil)
	if _, err := e.clientFrom("198.51.100.5", d); err != nil {
		t.Fatalf("the node does not serve: %v", err)
	}
}

// The embedded policy is a PROJECTION of contracts/policy.json once a runtime's file holds only the sections it reads: a section or key the node reads
// that the projection lacks would read as zero. This holds for every json field of Policy, whatever the projection is.
func TestPolicyCopyHoldsEveryKeyTheNodeReads(t *testing.T) {
	var raw map[string]any
	if err := json.Unmarshal(policyJSON, &raw); err != nil {
		t.Fatal(err)
	}
	var walk func(path string, typ reflect.Type, at any)
	walk = func(path string, typ reflect.Type, at any) {
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if name == "" || name == "-" {
				continue
			}
			obj, _ := at.(map[string]any)
			got, ok := obj[name]
			if !ok {
				t.Errorf("tunnel/policy.json has no %s.%s, which the node reads (add it to the node's projection in the contract lint table and sync)", path, name)
				continue
			}
			if f.Type.Kind() == reflect.Struct {
				walk(path+"."+name, f.Type, got)
			}
		}
	}
	walk("policy", reflect.TypeOf(Policy{}), raw)
}

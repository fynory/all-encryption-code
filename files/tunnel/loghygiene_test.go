package main

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
)

// No IP or SNI in persistent logs (plan section 5): a full run of the node through everything it does, then a grep of what it wrote and of its metrics
// for every address, label, host name and device id the run used, and for anything shaped like one.

func TestLogs_AFullRunLeavesNoAddressNoLabelNoNameInTheLogsOrTheMetrics(t *testing.T) {
	e := newVIPEnv(t, func(e *testEnv, c *Config) {
		c.UnknownSNIPerIP, c.LabelNewPerS, c.LabelNewBurst, c.PerIPConcurrent = 3, 2, 3, 4
		c.GatedBytesPerDay = 70_000
		c.MaxStreamsPerHost = 6
		c.LabelAnonSlice = 3
		c.PrefixFetch = func(context.Context) ([]byte, error) {
			return []byte(`{"prefixes":[{"ipv4Prefix":"192.0.2.0/24"},{"ipv6Prefix":"2001:db8:cafe::/48"}]}`), nil
		}
		c.PerIPNewPerS = 1 << 20
	})
	eventually(t, "the prefix list", 3*time.Second, func() bool { return e.srv.openai.size() == 2 })
	release := make(chan struct{})

	paid, gated, offline := e.newDevice(), e.newDevice(), e.newDevice()
	e.plan(gated).status, e.plan(gated).plan = statusGated, "trial"
	pc := e.connectOK(paid)
	pc.serve(holdHandler(paid, release))
	gc := e.connectOK(gated)
	gc.serve(nil)

	ips := []string{"198.51.100.17", "203.0.113.200", "2001:db8:1234:5678::9", "192.0.2.77", "2001:db8:cafe::1", "198.51.100.18"}
	// streams from several sources, a HINT, the label rate and the host cap
	pc.send("HINT 203.0.113.200 2001:db8:1234:5678::9")
	eventually(t, "the hint", 3*time.Second, func() bool { return e.srv.hints.size() == 2 })
	for _, ip := range ips {
		for i := 0; i < 3; i++ {
			_, _ = e.clientFrom(ip, paid)
		}
	}
	// names that are nobody's, a scanner that is banned, junk
	scanner := "198.51.100.99"
	names := []string{offline.host}
	for i := 0; i < 5; i++ {
		names = append(names, fmt.Sprintf("%c%019d.devices.all-e2e.test", 'a'+i, i))
	}
	for _, n := range names {
		e.helloFrom(scanner, n, 500*time.Millisecond)
	}
	e.helloFrom(scanner, paid.host, 500*time.Millisecond)
	ips = append(ips, scanner)
	// the gated device runs out of bytes; the paid one renews; a refused device
	if c, err := e.clientFrom("198.51.100.50", gated); err == nil {
		_, _ = postOver(c, gated.host, make([]byte, 300_000))
	}
	ips = append(ips, "198.51.100.50")
	pc.drainFeed()
	if r := pc.renew(); !strings.HasPrefix(r, "OK ") {
		t.Fatalf("renew: %q", r)
	}
	stranger := e.newDeviceNoPlan()
	sc := e.connect(stranger)
	sc.hello(func() string { return e.session(stranger, nil) }, func(s, n string) string { return e.proof(stranger, s, n, nil) })
	// a client that is not TLS, a cut hello, a client that says nothing
	raw := sendRaw(t, e, []byte("GET / HTTP/1.1\r\n\r\n"), 0)
	_ = raw
	go e.srv.Drain(3 * time.Second)
	eventually(t, "draining", 3*time.Second, func() bool { return e.srv.Draining() })
	e.helloFrom("198.51.100.60", paid.host, 500*time.Millisecond)
	ips = append(ips, "198.51.100.60")
	close(release)
	time.Sleep(300 * time.Millisecond)

	logs, metrics := e.logs.String(), e.srv.renderMetrics()
	// The node's own listen address (the "listening" line, written once from its configuration) is the operator's, not a client's, and the time of each
	// line is not an address however it reads.
	var kept []string
	for _, line := range strings.Split(logs, "\n") {
		if !strings.Contains(line, `"msg":"listening"`) {
			kept = append(kept, regexp.MustCompile(`"time":"[^"]*",`).ReplaceAllString(line, ""))
		}
	}
	logs = strings.Join(kept, "\n")
	if len(logs) < 2000 || !strings.Contains(logs, `"msg":"stream_open"`) || !strings.Contains(logs, `"msg":"source_banned"`) || !strings.Contains(logs, `"msg":"conn_reject"`) {
		t.Fatalf("the control is empty: the run did not exercise the node (%d bytes of logs)", len(logs))
	}
	secrets := map[string]string{
		"the loopback address": "127.0.0.1", "the loopback v6": "::1",
	}
	for i, ip := range ips {
		secrets[fmt.Sprintf("source %d", i)] = ip
	}
	for _, d := range []*testDevice{paid, gated, offline, stranger} {
		secrets["a label"+d.label] = d.label
		secrets["a host"+d.label] = d.host
		secrets["a device id"+d.label] = d.id
	}
	for _, n := range names {
		secrets["the name "+n] = n
		secrets["the label of "+n] = n[:20]
	}
	secrets["the zone"] = testZone
	secrets["the node's own name"] = testNodeHost
	for what, secret := range secrets {
		for where, text := range map[string]string{"logs": logs, "metrics": metrics} {
			if strings.Contains(text, secret) {
				t.Errorf("%s hold %s (%q)", where, what, secret)
			}
		}
	}
	for what, re := range map[string]*regexp.Regexp{
		"an IPv4 address":      regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`),
		"an IPv6 address":      regexp.MustCompile(`(?i)\b[0-9a-f]{0,4}:[0-9a-f]{0,4}:[0-9a-f:]{2,}`),
		"something label-like": regexp.MustCompile(`\b[a-z2-7]{20}\b`), // on word boundaries: a 32-character hex stream id holds a run of 20 such characters now and then
		"a host name":          regexp.MustCompile(`[a-z0-9-]+\.[a-z0-9-]+\.(test|org|com|net)`),
	} {
		for where, text := range map[string]string{"logs": logs, "metrics": metrics} {
			if m := re.FindString(text); m != "" {
				t.Errorf("%s hold %s: %q", where, what, m)
			}
		}
	}
	// the one way a source appears is the per-boot salted short hash, and it is not the address
	re := regexp.MustCompile(`"source":"([0-9a-f]{8})"`)
	m := re.FindStringSubmatch(logs)
	if m == nil {
		t.Fatalf("a ban was logged without the short hash:\n%s", grepLines(logs, "source_banned"))
	}
	if m[1] != e.srv.short(scanner) {
		t.Fatalf("the hash %s is not the scanner's %s", m[1], e.srv.short(scanner))
	}
	// the salt is per boot: another node hashes the same address to another word
	other := newVIPEnv(t, nil)
	if other.srv.short(scanner) == e.srv.short(scanner) {
		t.Fatal("two boots hash an address to the same word")
	}
}

func grepLines(text, sub string) string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, sub) {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

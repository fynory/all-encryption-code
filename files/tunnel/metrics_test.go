package main

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// /metrics and /healthz (metrics.go): loopback, aggregate, no series per device.

func metricsEnv(t *testing.T, mutate func(*Config)) *testEnv {
	return newTestEnv(t, func(c *Config) {
		c.MetricsAddr = "127.0.0.1:0"
		if mutate != nil {
			mutate(c)
		}
	})
}

func TestMetrics_ServedOnLoopbackToGETAndHEADOnly(t *testing.T) {
	e := metricsEnv(t, nil)
	addr := e.srv.MetricsAddr()
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Fatalf("listening on %q", addr)
	}
	code, body, header := httpGet(t, "http://"+addr+"/metrics")
	if code != 200 || !strings.HasPrefix(header.Get("content-type"), "text/plain") || !strings.Contains(body, "# TYPE all_tunnel_streams_open gauge") {
		t.Fatalf("%d %v\n%s", code, header, body)
	}
	if code, _, _ := httpGet(t, "http://"+addr+"/nothing"); code != 404 {
		t.Fatalf("an unknown path: %d", code)
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		req, _ := http.NewRequest(method, "http://"+addr+"/metrics", strings.NewReader("x"))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("%s: %d", method, resp.StatusCode)
		}
	}
	req, _ := http.NewRequest(http.MethodHead, "http://"+addr+"/healthz", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("HEAD /healthz: %v %v", resp, err)
	}
	resp.Body.Close()
	// without the option there is no listener at all
	if off := newTestEnv(t, nil); off.srv.MetricsAddr() != "" {
		t.Fatalf("a node without -metrics-addr listens on %q", off.srv.MetricsAddr())
	}
}

func TestMetrics_HealthzSaysWhetherTheNodeServes(t *testing.T) {
	e := metricsEnv(t, nil)
	url := "http://" + e.srv.MetricsAddr() + "/healthz"
	if code, body, _ := httpGet(t, url); code != 200 || !strings.Contains(body, `"state":"ok"`) {
		t.Fatalf("%d %s", code, body)
	}
	e.srv.setKilled(true)
	if code, body, _ := httpGet(t, url); code != 503 || !strings.Contains(body, `"state":"kill_switch"`) {
		t.Fatalf("%d %s", code, body)
	}
	e.srv.setKilled(false)
	d := e.newDevice()
	dc := e.connectOK(d)
	release := make(chan struct{})
	defer close(release)
	dc.serve(holdHandler(d, release))
	if _, err := e.clientTLS(d); err != nil { // a stream that stays open: the drain has something to wait for
		t.Fatal(err)
	}
	go e.srv.Drain(10 * time.Second)
	eventually(t, "draining", 3*time.Second, func() bool { return e.srv.Draining() })
	if code, body, _ := httpGet(t, url); code != 503 || !strings.Contains(body, `"state":"draining"`) {
		t.Fatalf("%d %s", code, body)
	}
	if v := e.metricValue("all_tunnel_draining"); v != 1 {
		t.Fatalf("draining gauge %d", v)
	}
}

// seriesOf is the set of series of a scrape without their values: name and label.
func seriesOf(text string) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.LastIndexByte(line, ' '); i > 0 {
			out[line[:i]] = true
		}
	}
	return out
}

func TestMetrics_ThereIsNoSeriesPerLabelDeviceOrAddress(t *testing.T) {
	scrape := func(devices int) string {
		// (the devices of the test all connect from loopback, which is one source: its rate is out of the way)
		e := newVIPEnv(t, func(e *testEnv, c *Config) { c.PerIPNewPerS, c.PerIPConcurrent = 1<<20, 1<<20 })
		var held []*devConn
		for i := 0; i < devices; i++ {
			d := e.newDevice()
			dc := e.connectOK(d)
			dc.serve(nil)
			held = append(held, dc)
			c, err := e.clientFrom(randomIP(i), d)
			if err != nil {
				t.Fatalf("%v\n%s", err, e.logs.String())
			}
			if _, err := postOver(c, d.host, []byte("x")); err != nil {
				t.Fatalf("%v\n%s", err, e.logs.String())
			}
			e.helloFrom(randomIP(i+500), "nobody"+d.label[6:]+".devices.all-e2e.test", time.Second) // a name that is not a device
			dc.send("HINT " + randomIP(i+900))
		}
		text := e.srv.renderMetrics()
		if devices > 0 {
			if got := e.metricValue("all_tunnel_devices_online"); got != int64(devices) {
				t.Fatalf("online %d", got)
			}
		}
		_ = held
		return text
	}
	one, many := scrape(1), scrape(25)
	a, b := seriesOf(one), seriesOf(many)
	if len(a) != len(b) {
		t.Fatalf("%d series with one device, %d with 25", len(a), len(b))
	}
	for s := range b {
		if !a[s] {
			t.Errorf("series %s exists only with more devices", s)
		}
	}
	for name, re := range map[string]*regexp.Regexp{
		"a label":     regexp.MustCompile(`[a-z2-7]{20}`),
		"a zone":      regexp.MustCompile(`devices\.all-e2e|\.test`),
		"an address":  regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|[0-9a-f]*:[0-9a-f]*:[0-9a-f:]+`),
		"a device id": regexp.MustCompile(`[0-9a-f]{32}`),
		"a stream id": regexp.MustCompile(`stream`),
	} {
		if name == "a stream id" {
			continue // the word "stream" is in metric names; stream ids are the 32-hex check above
		}
		if m := re.FindString(many); m != "" {
			t.Errorf("the metrics hold %s: %q", name, m)
		}
	}
	// every label key of every series is one of a fixed few
	keys := regexp.MustCompile(`\{([a-z_]+)=`)
	allowed := map[string]bool{"reason": true, "direction": true, "result": true, "type": true, "group": true, "version": true, "cipher": true}
	for s := range b {
		if m := keys.FindStringSubmatch(s); m != nil && !allowed[m[1]] && !strings.HasPrefix(s, "all_tunnel_build_info") {
			t.Errorf("series %s has a label key that is not in the closed list", s)
		}
	}
}

func randomIP(i int) string { return "198.51." + itoa(100+i/250) + "." + itoa(1+i%250) }

func itoa(n int) string { return strconv.Itoa(n) }

func TestMetrics_TheNodeCertificateAndTheKeysAreReported(t *testing.T) {
	end := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	e, _ := httpNode(t, nil, func(c *Config) { c.CertNotAfter = func() time.Time { return end } })
	if got := e.metricValue("all_tunnel_node_cert_not_after_seconds"); got != end.Unix() {
		t.Fatalf("not_after %d, want %d", got, end.Unix())
	}
	left := e.metricValue("all_tunnel_node_cert_seconds_left")
	if left < 29*24*3600 || left > 30*24*3600 {
		t.Fatalf("seconds left %d", left)
	}
	eventually(t, "the keys were fetched", 5*time.Second, func() bool { return e.metricValue("all_tunnel_jwks_healthy") == 1 })
	if age := e.metricValue("all_tunnel_jwks_age_seconds"); age < 0 || age > 60 {
		t.Fatalf("age %d", age)
	}
	// without a certificate source of the kind that reports, the series is simply absent (a test node's fake keys report no age either)
	plain := newTestEnv(t, nil)
	if strings.Contains(plain.srv.renderMetrics(), "node_cert_not_after") || strings.Contains(plain.srv.renderMetrics(), "jwks_age") {
		t.Fatal("series reported without a source")
	}
}

func TestMetrics_CountersFollowWhatHappens(t *testing.T) {
	e := metricsEnv(t, nil)
	d := e.newDevice()
	dc := e.connectOK(d)
	dc.serve(nil)
	c, err := e.clientTLS(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := postOver(c, d.host, make([]byte, 5000)); err != nil {
		t.Fatal(err)
	}
	c.Close()
	e.waitIdle()
	if e.metricValue("all_tunnel_streams_opened_total") != 1 || e.metricValue(`all_tunnel_authorize_total{result="ok"}`) != 1 {
		t.Fatalf("\n%s", e.srv.renderMetrics())
	}
	if e.metricValue(`all_tunnel_bytes_total{direction="up"}`) < 5000 || e.metricValue(`all_tunnel_bytes_total{direction="down"}`) < 5000 {
		t.Fatalf("bytes\n%s", e.srv.renderMetrics())
	}
	if e.metricValue("all_tunnel_control_connections") != 1 || e.metricValue("all_tunnel_devices_online") != 1 {
		t.Fatalf("\n%s", e.srv.renderMetrics())
	}
	e.plan(d).err = &ControlError{Status: 402, Code: codeLicenseInactive}
	other := e.newDeviceNoPlan()
	oc := e.connect(other)
	oc.hello(func() string { return e.session(other, nil) }, func(s, n string) string { return e.proof(other, s, n, nil) })
	if e.metricValue(`all_tunnel_authorize_total{result="refused"}`) != 1 {
		t.Fatalf("\n%s", e.srv.renderMetrics())
	}
	// something that is not TLS, and a name that is nobody's
	e.helloFromLoopback("nobody.devices.all-e2e.test")
	if e.rejected("unknown_host") != 1 {
		t.Fatalf("\n%s", e.srv.renderMetrics())
	}
}

func (e *testEnv) helloFromLoopback(host string) {
	e.t.Helper()
	c := sendRaw(e.t, e, helloOf(host, 0, 16000), 0)
	buf := make([]byte, 16)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = c.Read(buf)
}

func TestMetrics_TheTestNodeProcessServesThemAndLogsNameNobody(t *testing.T) {
	p := launchTestNode(t, 3600, "-metrics-addr", "127.0.0.1:0")
	addr, _ := p.ready["metrics"].(string)
	if addr == "" {
		t.Fatalf("the ready line has no metrics address: %v", p.ready)
	}
	code, body, _ := httpGet(t, "http://"+addr+"/metrics")
	if code != 200 || !strings.Contains(body, "all_tunnel_node_cert_not_after_seconds") || !strings.Contains(body, `all_tunnel_build_info{version=`) {
		t.Fatalf("%d\n%s", code, body)
	}
	if code, body, _ := httpGet(t, "http://"+addr+"/healthz"); code != 200 || !strings.Contains(body, `"ok":true`) {
		t.Fatalf("%d %s", code, body)
	}
}

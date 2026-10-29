package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"sync/atomic"
	"time"
)

// /metrics and /healthz (the design plan, section 5): loopback only, aggregate counters only. There is NO series per device, per label, per
// address or per name, by construction: every counter is a member of a family whose words are a closed list written below, and a word that is not in
// the list is counted as "other". The number of series therefore does not depend on how many devices or clients the node serves, and nothing a client
// or a device sends can make a new one. The operator's tools read it from the machine (the monitor of WP22 reads the node certificate's not_after and the
// age of the control plane's keys from here, and the bytes per user come from the devices' own heartbeats, not from the node).

// family is a counter with one label whose values are a closed list of words.
type family struct {
	name, help, label string
	words             []string
	vals              []atomic.Int64
	idx               map[string]int
}

func newFamily(name, help, label string, words []string) *family {
	f := &family{name: name, help: help, label: label, words: append([]string(nil), words...), idx: map[string]int{}}
	f.vals = make([]atomic.Int64, len(f.words))
	for i, w := range f.words {
		f.idx[w] = i
	}
	if _, ok := f.idx["other"]; !ok {
		f.idx["other"] = len(f.words)
		f.words = append(f.words, "other")
		f.vals = make([]atomic.Int64, len(f.words))
	}
	return f
}

func (f *family) add(word string, n int64) {
	i, ok := f.idx[word]
	if !ok {
		i = f.idx["other"]
	}
	f.vals[i].Add(n)
}

func (f *family) inc(word string) { f.add(word, 1) }

// get is the count of a word (0 for one that is not in the list).
func (f *family) get(word string) int64 {
	if i, ok := f.idx[word]; ok {
		return f.vals[i].Load()
	}
	return 0
}

func (f *family) write(b *bytes.Buffer) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s counter\n", f.name, f.help, f.name)
	for i, w := range f.words {
		fmt.Fprintf(b, "%s{%s=%q} %d\n", f.name, f.label, w, f.vals[i].Load())
	}
}

// The closed lists of words.
var (
	// why a connection or a stream was refused before it carried anything
	rejectWords = []string{
		refuseBanned, refuseRate, refuseConcurrent, "unauth_limit", "unauth_anon_limit", "not_tls", "bad_hello", "hello_too_large", "hello_timeout", "closed_before_hello",
		"read_error", "no_sni", "bad_sni", "unknown_host", "device_offline", "host_limit", "label_rate", "global_limit", "anon_global_limit", "draining",
		"gated_streams", "gated_bytes", "attach_timeout", "control_write_failed", "shutting_down", "other",
	}
	// why a stream that was served ended
	streamEndWords = []string{
		"closed", "idle", "max_age", "byte_cap", "conn_error", "shutdown", "half_close_timeout", "gated_bytes",
		closeRevoked, closeExpired, closeReleased, closeKilled, closePaused, closeDrain, "other",
	}
	authorizeWords = []string{"ok", "refused", "unavailable", "other"}
	feedWords      = []string{feedRevoke, feedPause, feedResume, feedLicenseEnd, feedRelease, feedKill, feedKillClear, "other"}
	prefixWords    = []string{prefixOK, prefixFetch, prefixEmpty, prefixCorrupt, prefixTooLarge, prefixTooMany, prefixBadPrefix, "other"}
	directionWords = []string{"up", "down", "other"}
)

// metrics holds the node's counters. Every member is aggregate and every label value comes from a list above or from the observer's tables.
type metrics struct {
	rejected      *family
	streamEnd     *family
	bytes         *family
	authorize     *family
	feedEvents    *family
	prefixRefresh *family
	streamsOpened atomic.Int64
	gatedCut      atomic.Int64 // streams cut because a gated device's byte budget ran out
	hintsMarked   atomic.Int64
	bansTotal     atomic.Int64

	obsOffered  *family // groups a ClientHello offered
	obsVersion  *family // what the ServerHello selected
	obsCipher   *family
	obsGroup    *family
	obsHellos   atomic.Int64 // ClientHellos observed
	obsECH      atomic.Int64 // of them, how many carried an ECH extension
	obsRetry    atomic.Int64 // HelloRetryRequests
	obsUnparsed atomic.Int64 // streams whose first bytes from the device were not a ServerHello the observer follows
}

func newMetrics() *metrics {
	return &metrics{
		rejected:      newFamily("all_tunnel_conn_rejected_total", "Connections and streams refused before they carried anything, by reason.", "reason", rejectWords),
		streamEnd:     newFamily("all_tunnel_stream_closed_total", "Client streams that were served and ended, by why.", "reason", streamEndWords),
		bytes:         newFamily("all_tunnel_bytes_total", "Bytes spliced, client to device (up) and device to client (down).", "direction", directionWords),
		authorize:     newFamily("all_tunnel_authorize_total", "Calls to the control plane's authorize, by outcome.", "result", authorizeWords),
		feedEvents:    newFamily("all_tunnel_feed_events_total", "Feed events applied, by type.", "type", feedWords),
		prefixRefresh: newFamily("all_tunnel_openai_prefix_refresh_total", "Refreshes of the OpenAI prefix list, by outcome.", "result", prefixWords),
		obsOffered:    newFamily("all_tunnel_tls_client_offered_group_total", "ClientHellos that offered a named group (each counted once per hello).", "group", obsGroupWords),
		obsVersion:    newFamily("all_tunnel_tls_selected_version_total", "TLS version a device's ServerHello selected.", "version", obsVersionWords),
		obsCipher:     newFamily("all_tunnel_tls_selected_cipher_total", "Cipher suite a device's ServerHello selected.", "cipher", obsCipherWords),
		obsGroup:      newFamily("all_tunnel_tls_selected_group_total", "Key-exchange group a device's ServerHello selected (none: TLS 1.2).", "group", append(append([]string(nil), obsGroupWords...), obsNoGroup)),
	}
}

func writeCounter(b *bytes.Buffer, name, help string, v int64) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, v)
}

func writeGauge(b *bytes.Buffer, name, help string, v any) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s gauge\n%s %v\n", name, help, name, name, v)
}

// render is the text of /metrics (Prometheus exposition format).
func (s *Server) renderMetrics() string {
	m := s.met
	var b bytes.Buffer
	now := s.now()
	fmt.Fprintf(&b, "# HELP all_tunnel_build_info The node's build.\n# TYPE all_tunnel_build_info gauge\nall_tunnel_build_info{version=%q} 1\n", version)
	writeGauge(&b, "all_tunnel_uptime_seconds", "Seconds since the node started.", int64(now.Sub(s.startedAt).Seconds()))
	writeGauge(&b, "all_tunnel_goroutines", "Goroutines.", runtime.NumGoroutine())

	writeGauge(&b, "all_tunnel_streams_open", "Client streams being served now.", s.streams.Load())
	writeCounter(&b, "all_tunnel_streams_opened_total", "Client streams served since start.", m.streamsOpened.Load())
	writeGauge(&b, "all_tunnel_control_connections", "Control connections of devices, authenticated or not yet.", s.controlCount())
	writeGauge(&b, "all_tunnel_devices_online", "Devices online (one number: no list of them exists in the metrics).", s.routes.onlineCount())
	writeGauge(&b, "all_tunnel_unauthenticated_connections", "Connections that have not finished their first message.", s.unauth.Load())
	writeGauge(&b, "all_tunnel_pump_big_buffers", "32 KiB buffers held by a stream's pump now (an idle stream holds none).", s.bigBuffersInUse.Load())
	writeGauge(&b, "all_tunnel_unauthenticated_anonymous_connections", "Of those, the ones whose source is not ChatGPT's, not a device's and not marked good (they share what the reserve leaves).", s.anonUnauth.Load())
	writeGauge(&b, "all_tunnel_pending_attach", "OPENs waiting for their ATTACH.", s.pendingCount())
	writeGauge(&b, "all_tunnel_draining", "1 while the node drains (SIGTERM).", boolNum(s.draining.Load()))
	writeGauge(&b, "all_tunnel_kill_switch", "1 while the control plane's kill switch is on.", boolNum(s.killed.Load()))

	m.rejected.write(&b)
	m.streamEnd.write(&b)
	m.bytes.write(&b)
	m.authorize.write(&b)
	m.feedEvents.write(&b)

	size, banned, bans, overflowed := s.ips.snapshot()
	writeGauge(&b, "all_tunnel_ip_table_entries", "Sources remembered (a number: no address leaves the node).", size)
	writeGauge(&b, "all_tunnel_ip_banned", "Sources dropped at accept now for trying too many names.", banned)
	writeCounter(&b, "all_tunnel_ip_bans_total", "Sources banned since start.", int64(bans))
	writeCounter(&b, "all_tunnel_ip_table_overflow_total", "Sources that did not fit in the table and shared the overflow entry.", int64(overflowed))
	writeGauge(&b, "all_tunnel_hint_addresses", "Addresses devices marked good, all devices together.", s.hints.size())
	writeCounter(&b, "all_tunnel_hints_total", "HINT messages accepted.", m.hintsMarked.Load())
	writeGauge(&b, "all_tunnel_gated_records", "Device hosts with a gated-day record.", s.gates.size())
	writeCounter(&b, "all_tunnel_gated_cut_total", "Streams cut because a gated device's byte budget ran out.", m.gatedCut.Load())

	writeGauge(&b, "all_tunnel_openai_prefixes", "Prefixes in the OpenAI list in use.", s.openai.size())
	writeGauge(&b, "all_tunnel_openai_prefix_age_seconds", "Seconds since the OpenAI list in use was installed (-1: none).", int64(s.openai.age().Seconds()))
	m.prefixRefresh.write(&b)

	if s.cfg.CertNotAfter != nil {
		if na := s.cfg.CertNotAfter(); !na.IsZero() {
			writeGauge(&b, "all_tunnel_node_cert_not_after_seconds", "The end of the node's own certificate, Unix seconds (the monitor alerts under 14 and 5 days).", na.Unix())
			writeGauge(&b, "all_tunnel_node_cert_seconds_left", "Seconds the node's own certificate has left.", int64(na.Sub(now).Seconds()))
		}
	}
	if kh, ok := s.cfg.Keys.(interface{ Age() time.Duration }); ok {
		writeGauge(&b, "all_tunnel_jwks_age_seconds", "Seconds since the control plane's keys were last fetched (-1: never).", int64(kh.Age().Seconds()))
	}
	if kh, ok := s.cfg.Keys.(keyHealth); ok {
		writeGauge(&b, "all_tunnel_jwks_healthy", "1 while the node can vouch for the control plane's keys.", boolNum(kh.Healthy()))
	}
	writeGauge(&b, "all_tunnel_control_plane_down", "1 while nothing has answered from the control plane for the policy's quiet period.", boolNum(s.health.down(now, s.cfg.DownQuiet)))

	writeCounter(&b, "all_tunnel_tls_client_hellos_observed_total", "ClientHellos the handshake observer read.", m.obsHellos.Load())
	m.obsOffered.write(&b)
	writeCounter(&b, "all_tunnel_tls_client_ech_total", "ClientHellos that carried an ECH extension.", m.obsECH.Load())
	m.obsVersion.write(&b)
	m.obsCipher.write(&b)
	m.obsGroup.write(&b)
	writeCounter(&b, "all_tunnel_tls_hello_retry_total", "HelloRetryRequests seen from devices.", m.obsRetry.Load())
	writeCounter(&b, "all_tunnel_tls_server_hello_unparsed_total", "Streams whose first bytes from the device were not a ServerHello the observer follows.", m.obsUnparsed.Load())
	return b.String()
}

func boolNum(v bool) int {
	if v {
		return 1
	}
	return 0
}

// healthState is the answer of /healthz: whether the node serves, in one word. A node that drains, has its kill switch on, or cannot vouch for the control
// plane's keys is not serving new devices, and says so with 503; a control plane that is down is reported but is 200, because what is connected goes on.
func (s *Server) healthState() (code int, body map[string]any) {
	state := "ok"
	switch {
	case s.draining.Load():
		state = "draining"
	case s.killed.Load():
		state = "kill_switch"
	}
	if kh, ok := s.cfg.Keys.(keyHealth); ok && state == "ok" && !kh.Healthy() {
		state = "keys_stale"
	}
	code = http.StatusOK
	if state != "ok" {
		code = http.StatusServiceUnavailable
	}
	return code, map[string]any{"ok": state == "ok", "state": state, "control_plane_down": s.health.down(s.now(), s.cfg.DownQuiet)}
}

// metricsServer is the loopback HTTP listener of /metrics and /healthz.
type metricsServer struct {
	ln  net.Listener
	srv *http.Server
}

func (s *Server) startMetrics() error {
	if s.cfg.MetricsAddr == "" {
		return nil
	}
	ln, err := net.Listen("tcp", s.cfg.MetricsAddr)
	if err != nil {
		return fmt.Errorf("metrics listener: %w", err)
	}
	mux := http.NewServeMux()
	handle := func(path string, serve func(w http.ResponseWriter)) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.Header().Set("allow", "GET, HEAD")
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if host, _, err := net.SplitHostPort(r.RemoteAddr); err != nil || !net.ParseIP(host).IsLoopback() {
				http.NotFound(w, r) // the listener is loopback already; a connection that is not is not served
				return
			}
			serve(w)
		})
	}
	handle("/metrics", func(w http.ResponseWriter) {
		w.Header().Set("content-type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(s.renderMetrics()))
	})
	handle("/healthz", func(w http.ResponseWriter) {
		code, body := s.healthState()
		raw, _ := json.Marshal(body)
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(code)
		_, _ = w.Write(append(raw, '\n'))
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, MaxHeaderBytes: 4 << 10}
	s.metricsSrv = &metricsServer{ln: ln, srv: srv}
	go func() { _ = srv.Serve(ln) }()
	return nil
}

func (s *Server) stopMetrics() {
	if s.metricsSrv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = s.metricsSrv.srv.Shutdown(ctx)
	_ = s.metricsSrv.srv.Close()
}

// MetricsAddr is where /metrics listens ("" when it does not).
func (s *Server) MetricsAddr() string {
	if s.metricsSrv == nil {
		return ""
	}
	return s.metricsSrv.ln.Addr().String()
}

// controlCount is the number of control connections.
func (s *Server) controlCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

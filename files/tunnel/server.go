package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/maphash"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// TLS alert descriptions, sent (in the clear, as a fatal alert record) to a client we decide not to serve.
	alertInternalError    = 80
	alertUnrecognizedName = 112
)

var (
	errOffline       = errors.New("device_offline")
	errAttachTimeout = errors.New("attach_timeout")
	errControlWrite  = errors.New("control_write_failed")
	errShuttingDown  = errors.New("shutting_down")
	errByteCap       = errors.New("stream byte cap reached")
	errHostTaken     = errors.New("host_taken")
	errGatedBytes    = errors.New("gated byte budget spent")
)

// pendingStream is an OPEN waiting for its ATTACH: the secret is one use, and only the device that was sent the OPEN knows it.
type pendingStream struct {
	cc     *ctrl
	secret string
	ch     chan net.Conn // buffered(1): the ATTACHed data connection
}

// Server is the tunnel node. It never terminates a client's TLS: the only TLS it speaks is the one it holds for its own name, with devices.
type Server struct {
	cfg    Config
	log    *slog.Logger
	tlsCfg *tls.Config
	routes *routeTable
	replay *replayCache

	nodeURL string // the htu of a proof: this node's URL

	clk    clock
	health *cpHealth

	ctx    context.Context
	cancel context.CancelFunc
	bg     sync.WaitGroup // the feed loop, the background tasks and the refreshes of connections: ended by cancel

	mu      sync.Mutex
	pending map[string]*pendingStream
	conns   map[*ctrl]struct{} // every live control connection, for shutdown

	streams     atomic.Int64 // client connections being served, global
	anonStreams atomic.Int64 // of them, the ones whose source is neither openai nor marked good: they may not use the share reserved for the others
	unauth      atomic.Int64 // connections that have not finished their first message
	anonUnauth  atomic.Int64 // of them, the ones whose source is neither ChatGPT's, nor a device's, nor marked good: they may not use the share that is kept for the others
	authQ       atomic.Int64 // exchanges that wait for, or are in, a call to authorize
	connSeq     atomic.Int64

	authSem chan struct{} // the calls to authorize in flight: at most cfg.AuthorizeMax

	watchMu sync.Mutex
	watches map[*feedWatch]struct{} // the exchanges waiting for authorize, each told of the feed events applied meanwhile

	killed   atomic.Bool  // the global kill switch is on: no device is served until it is cleared
	draining atomic.Bool  // SIGTERM: no new client and no new device connection, the open streams finish
	drainFor atomic.Int64 // the quiet period this drain was started with, in nanoseconds (what a late device is told)

	// hardening (limits.go, hints.go, gated.go, openai_prefixes.go, metrics.go, observer.go)
	ips       *ipLimits
	hints     *hintTable
	openai    *openaiPrefixes
	gates     *gateTable
	met       *metrics
	sampler   *logSampler
	seed      maphash.Seed // per boot: what Server.short hashes with, so two log lines of one source can be told apart and nothing can be read back
	startedAt time.Time

	httpsLn, httpLn net.Listener
	metricsSrv      *metricsServer
	wg              sync.WaitGroup
	bufPool         sync.Pool    // the 32 KiB buffers a pump takes for bulk reads
	smallBufPool    sync.Pool    // the 4 KiB buffers a pump waits in a read with
	bigBuffersInUse atomic.Int64 // 32 KiB buffers held by a pump now (an idle stream holds none: tests and the memory check read it)
}

const (
	pumpSmallBuf = 4 << 10
	pumpBigBuf   = 32 << 10
)

// NewServer validates cfg and builds the node. It does not listen yet.
func NewServer(cfg Config) (*Server, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Health == nil {
		cfg.Health = &cpHealth{}
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	clk := newClock(cfg.Now, cfg.AfterFunc)
	s := &Server{
		cfg:       cfg,
		log:       cfg.Logger,
		routes:    newRouteTable(),
		replay:    newReplayCache(replayLimit),
		nodeURL:   nodeProofURL(cfg.NodeHost, cfg.PublicPort),
		clk:       clk,
		health:    cfg.Health,
		ctx:       ctx,
		cancel:    cancel,
		pending:   map[string]*pendingStream{},
		conns:     map[*ctrl]struct{}{},
		watches:   map[*feedWatch]struct{}{},
		authSem:   make(chan struct{}, cfg.AuthorizeMax),
		seed:      maphash.MakeSeed(),
		met:       newMetrics(),
		sampler:   newLogSampler(clk),
		hints:     newHintTable(clk, cfg.HintTTL, cfg.HintsPerLabel),
		gates:     newGateTable(clk),
		startedAt: clk.Now(),
	}
	s.ips = newIPLimits(&cfg, clk, s.seed)
	s.openai = newOpenAIPrefixes(&cfg, clk, s.met.prefixRefresh.inc)
	s.routes.lim = labelLimitsOf(&cfg)
	if cfg.HTTPSAddr != "" {
		s.tlsCfg = &tls.Config{
			GetCertificate: cfg.CertSource,
			MinVersion:     tls.VersionTLS13,
			NextProtos:     []string{policyData.Protocol.ALPN},
		}
	}
	s.bufPool.New = func() any { b := make([]byte, pumpBigBuf); return &b }
	s.smallBufPool.New = func() any { b := make([]byte, pumpSmallBuf); return &b }
	return s, nil
}

// replayLimit bounds the proofs remembered at once (a proof lives for the policy's proof TTL, so this is the number of proofs per minute the node
// admits before it refuses more).
const replayLimit = 1 << 18

func (s *Server) now() time.Time { return s.clk.Now() }

func addrOf(ln net.Listener) string {
	if ln == nil {
		return ""
	}
	return ln.Addr().String()
}

func (s *Server) HTTPSAddr() string { return addrOf(s.httpsLn) }
func (s *Server) HTTPAddr() string  { return addrOf(s.httpLn) }

// Online reports whether the host has a live control connection that opens streams.
func (s *Server) Online(host string) bool {
	cc, _ := s.routes.lookup(host)
	return cc != nil && cc.canOpen(s.now())
}

// Start opens the two listeners (443 and 80: there is no other) and serves until Shutdown.
func (s *Server) Start() error {
	// Every socket the node accepts gets TCP keepalive from the policy: a stream whose peer vanished (a computer that slept, a network that changed) ends
	// by itself instead of holding its slot until the idle timeout.
	lc := s.listenConfig()
	listen := func(addr string) (net.Listener, error) {
		if addr == "" {
			return nil, nil
		}
		return lc.Listen(context.Background(), "tcp", addr)
	}
	var err error
	if s.httpsLn, err = listen(s.cfg.HTTPSAddr); err != nil {
		return fmt.Errorf("https listener: %w", err)
	}
	if s.httpLn, err = listen(s.cfg.HTTPAddr); err != nil {
		_ = s.closeListeners()
		return fmt.Errorf("http listener: %w", err)
	}
	if merr := s.startMetrics(); merr != nil {
		// The node serves without its metrics rather than not at all: a port that is taken is not a reason for a fleet's devices to lose their node.
		// The operator sees the line and the missing /healthz.
		s.log.Warn("metrics_unavailable")
	}
	// What the node must already have stopped serving is known before the first device connects: the feed's first answer (a revoke that happened while
	// the node was down, the kill switch) comes first, bounded so that a late control plane does not keep the node from starting.
	s.startBackground()
	for _, l := range []struct {
		ln net.Listener
		fn func(net.Conn)
	}{{s.httpsLn, s.handleHTTPS}, {s.httpLn, s.handleHTTP}} {
		if l.ln != nil {
			s.wg.Add(1)
			go s.acceptLoop(l.ln, l.fn)
		}
	}
	s.log.Info("listening", "https", s.HTTPSAddr(), "http", s.HTTPAddr(), "node", s.cfg.NodeID)
	return nil
}

// keepaliveProbes is how many unanswered keepalive probes end a connection.
const keepaliveProbes = 4

// listenConfig is how the node's listeners are made: the connections they accept have TCP keepalive on, with the policy's period.
func (s *Server) listenConfig() net.ListenConfig {
	return net.ListenConfig{KeepAliveConfig: net.KeepAliveConfig{Enable: true, Idle: s.cfg.TCPKeepalive, Interval: s.cfg.TCPKeepalive, Count: keepaliveProbes}}
}

func (s *Server) closeListeners() error {
	var first error
	for _, ln := range []net.Listener{s.httpsLn, s.httpLn} {
		if ln != nil {
			if err := ln.Close(); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}

// Shutdown stops accepting, tells every device the node is going (CLOSE shutdown) and waits (up to grace) for streams to finish; the streams are
// force-closed when it ends.
func (s *Server) Shutdown(grace time.Duration) { s.shutdown(grace, closeShutdown) }

func (s *Server) shutdown(grace time.Duration, reason string) {
	_ = s.closeListeners()
	s.stopMetrics()
	s.mu.Lock()
	live := make([]*ctrl, 0, len(s.conns))
	for cc := range s.conns {
		live = append(live, cc)
	}
	s.mu.Unlock()
	for _, cc := range live {
		cc.close(reason)
	}
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(grace):
	}
	s.mu.Lock() // with goBackground: a task is either counted before the wait below starts, or sees the node ended and does not start
	s.cancel()
	s.mu.Unlock()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
	bgDone := make(chan struct{})
	go func() { s.bg.Wait(); close(bgDone) }()
	select {
	case <-bgDone:
	case <-time.After(2 * time.Second):
	}
}

func (s *Server) acceptLoop(ln net.Listener, handle func(net.Conn)) {
	defer s.wg.Done()
	var delay time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if s.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			delay = min(max(2*delay, 5*time.Millisecond), time.Second)
			s.log.Warn("accept_error", "retry_in_ms", delay.Milliseconds())
			select {
			case <-time.After(delay):
			case <-s.ctx.Done():
				return
			}
			continue
		}
		delay = 0
		s.wg.Add(1)
		go handle(c)
	}
}

func tryAcquire(counter *atomic.Int64, limit int64) bool {
	for {
		cur := counter.Load()
		if cur >= limit {
			return false
		}
		if counter.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

// anonUnauthMax is the most unauthenticated connections the sources nobody vouches for may hold together.
func (s *Server) anonUnauthMax() int64 {
	return int64(s.cfg.MaxUnauth - s.cfg.MaxUnauth*s.cfg.OpenAIReservedPct/100)
}

func newStreamID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// newSecret is a 256-bit one-use attach secret (43 base64url characters).
func newSecret() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return b64Encode(b[:])
}

// newNonce is the 128-bit CHALLENGE nonce (22 base64url characters).
func newNonce() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return b64Encode(b[:])
}

func (s *Server) tapBytes(id, dir string, p []byte) {
	if s.cfg.tap != nil {
		s.cfg.tap(id, dir, p)
	}
}

// emit records one protocol step for the contracts' transcript checker; it costs nothing when no trace is set.
func (s *Server) emit(at time.Time, ev map[string]any) {
	if s.cfg.trace != nil {
		ev["t"] = epochSeconds(at)
		s.cfg.trace(ev)
	}
}

// sendAlert writes one fatal TLS alert record, then lets the peer drain for a moment so it is not reset before it can read the alert.
func sendAlert(c net.Conn, desc byte) {
	_ = c.SetWriteDeadline(time.Now().Add(time.Second))
	_, _ = c.Write([]byte{21, 3, 3, 0, 2, 2, desc})
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	_, _ = io.Copy(io.Discard, io.LimitReader(c, 16<<10))
}

func helloReason(err error) string {
	switch {
	case errors.Is(err, errNotTLS):
		return "not_tls"
	case errors.Is(err, errNotClientHello), errors.Is(err, errHelloMalformed):
		return "bad_hello"
	case errors.Is(err, errHelloTooLarge):
		return "hello_too_large"
	case errors.Is(err, os.ErrDeadlineExceeded):
		return "hello_timeout"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "closed_before_hello"
	default:
		return "read_error"
	}
}

// peerAddr is the client's address as the contracts write it in an OPEN: no zone, an IPv4-mapped address as the IPv4 address it carries.
func peerAddr(c net.Conn) (netip.Addr, bool) {
	ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		return netip.Addr{}, false
	}
	return ap.Addr().WithZone("").Unmap(), true
}

// ---------------------------------------------------------------- routing table

// hostEntry is what the node knows about one device host: the control connection that serves it (nil while the device is away) and how many client
// streams are open on it.
type hostEntry struct {
	cc      *ctrl
	streams int64                    // client streams open on the host, all slices together
	anon    int64                    // of them, the ones in the anonymous slice (the rest are in the slice of sources the device marked good)
	live    map[*liveStream]struct{} // the client streams being served on this host: what a revoke, a pause or an expiry must be able to cut
	gated   atomic.Bool              // the control plane's last status for the host's connection is gated: its streams are held to the day's budget (gated.go)
	newOnes bucket                   // the host's budget of new streams per second, for sources that are not marked good
}

// liveStream is one client stream the node serves for a host, from the moment it is admitted (before its OPEN) to its end. A revoke, a pause, an
// expired connection or the kill switch kills it: whichever connections it holds are closed, and one that is not attached yet is closed the moment it is.
type liveStream struct {
	mu     sync.Mutex
	client net.Conn
	dev    net.Conn
	killed string // why it was killed, "" while it lives

	he    *hostEntry // the host's entry: what says, at every chunk, whether the host is gated now (a RENEW may have made it so since the stream began)
	usage *dayUsage  // the host's gated-day record
	anon  bool       // the stream counts in the host's anonymous slice
}

// bind gives the stream its two connections. It reports false when the stream was killed before they were ready (the caller closes them).
func (l *liveStream) bind(client, dev net.Conn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.killed != "" {
		return false
	}
	l.client, l.dev = client, dev
	return true
}

func (l *liveStream) kill(reason string) {
	l.mu.Lock()
	if l.killed == "" {
		l.killed = reason
	}
	client, dev := l.client, l.dev
	l.mu.Unlock()
	if client != nil {
		_ = client.Close()
	}
	if dev != nil {
		_ = dev.Close()
	}
}

func (l *liveStream) killedBy() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.killed
}

// routeTable maps a host to the control connection of the device that owns it. The host comes ONLY from the control plane's answer; the table
// refuses to give one host to two devices and replaces a connection only by a newer one of the SAME subject. It is safe for concurrent use.
type routeTable struct {
	mu     sync.Mutex
	byHost map[string]*hostEntry
	bySub  map[string]*ctrl
	lim    labelLimits
}

// labelLimits are what one device host accepts: how many streams (a cap on the whole, and on what sources that are not marked good may hold of it),
// and how fast new ones may begin when they come from such sources.
type labelLimits struct {
	total, anon int
	rate, burst float64
}

func labelLimitsOf(cfg *Config) labelLimits {
	return labelLimits{total: cfg.MaxStreamsPerHost, anon: min(cfg.LabelAnonSlice, cfg.MaxStreamsPerHost), rate: float64(cfg.LabelNewPerS), burst: float64(cfg.LabelNewBurst)}
}

func newRouteTable() *routeTable {
	return &routeTable{byHost: map[string]*hostEntry{}, bySub: map[string]*ctrl{}}
}

// activate binds cc to host as subject sub. It returns the connection it replaced (the same subject's older one: the caller closes it) or
// errHostTaken when another subject holds the host. bound, when set, runs under the table's lock once cc is bound, so whatever it records is
// ordered like the routing decisions are.
func (rt *routeTable) activate(cc *ctrl, sub, host string, bound func()) (*ctrl, error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	he := rt.byHost[host]
	if he != nil && he.cc != nil && he.cc != cc && he.cc.subject() != sub {
		return nil, errHostTaken
	}
	var old *ctrl
	prevHost := ""
	if prev := rt.bySub[sub]; prev != nil && prev != cc {
		old, prevHost = prev, prev.hostName()
		if pe := rt.byHost[prevHost]; pe != nil && pe.cc == prev {
			pe.cc = nil
		}
	}
	he = rt.byHost[host] // looked up again: unbinding the older connection must not have dropped it from under us
	if he == nil {
		he = &hostEntry{}
		rt.byHost[host] = he
	}
	he.cc = cc
	rt.bySub[sub] = cc
	if prevHost != "" && prevHost != host {
		if pe := rt.byHost[prevHost]; pe != nil {
			rt.dropIfIdle(prevHost, pe)
		}
	}
	cc.bind(sub, host)
	if bound != nil {
		bound()
	}
	return old, nil
}

// remove unbinds cc (it never touches a newer connection that replaced it).
func (rt *routeTable) remove(cc *ctrl) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	sub, host := cc.subject(), cc.hostName()
	if rt.bySub[sub] == cc {
		delete(rt.bySub, sub)
	}
	if he := rt.byHost[host]; he != nil && he.cc == cc {
		he.cc = nil
		rt.dropIfIdle(host, he)
	}
}

func (rt *routeTable) dropIfIdle(host string, he *hostEntry) {
	if he.cc == nil && he.streams == 0 {
		delete(rt.byHost, host)
	}
}

func (rt *routeTable) lookup(host string) (*ctrl, *hostEntry) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	he := rt.byHost[host]
	if he == nil {
		return nil, nil
	}
	return he.cc, he
}

// The reasons routes.acquire gives for a stream it does not admit.
const (
	admitUnknown   = "unknown_host" // no device is online under the name
	admitHostLimit = "host_limit"   // the host holds all the streams its slice allows
	admitLabelRate = "label_rate"   // the host is being asked for new streams faster than it accepts from sources that are not marked good
)

// acquire counts one more client stream on the host and registers it so that it can be killed. A source the device marked good (hint) may use any of
// the host's cap; any other source only the anonymous slice, which is what leaves room for the good ones when an attacker holds streams, and its new
// streams are also paced per host. It returns the connection to OPEN on, or why the stream is refused.
func (rt *routeTable) acquire(host string, hint bool, now time.Time) (*ctrl, *liveStream, string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	he := rt.byHost[host]
	if he == nil || he.cc == nil {
		return nil, nil, admitUnknown
	}
	if he.streams >= int64(rt.lim.total) || (!hint && he.anon >= int64(rt.lim.anon)) {
		return nil, nil, admitHostLimit
	}
	if !hint && !he.newOnes.take(now, rt.lim.rate, rt.lim.burst) {
		return nil, nil, admitLabelRate
	}
	he.streams++
	if !hint {
		he.anon++
	}
	ls := &liveStream{he: he, anon: !hint}
	if he.live == nil {
		he.live = map[*liveStream]struct{}{}
	}
	he.live[ls] = struct{}{}
	return he.cc, ls, ""
}

func (rt *routeTable) release(host string, ls *liveStream) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	he := ls.he
	he.streams--
	if ls.anon {
		he.anon--
	}
	delete(he.live, ls)
	if rt.byHost[host] == he {
		rt.dropIfIdle(host, he)
	}
}

// setGated records, for the host cc serves, whether the control plane last called it gated. A connection that has been replaced says nothing.
func (rt *routeTable) setGated(cc *ctrl, gated bool) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if he := rt.byHost[cc.hostName()]; he != nil && he.cc == cc {
		he.gated.Store(gated)
	}
}

// onlineCount is the number of device hosts with a control connection bound to them.
func (rt *routeTable) onlineCount() int {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	n := 0
	for _, he := range rt.byHost {
		if he.cc != nil {
			n++
		}
	}
	return n
}

// killStreams kills the client streams being served on host. Unless force, it does nothing while a connection of the device is bound to the host (an
// expiry that raced a newer connection must not cut what that one serves).
func (rt *routeTable) killStreams(host, reason string, force bool) int {
	rt.mu.Lock()
	var doomed []*liveStream
	if he := rt.byHost[host]; he != nil && (force || he.cc == nil) {
		for ls := range he.live {
			doomed = append(doomed, ls)
		}
	}
	rt.mu.Unlock()
	for _, ls := range doomed {
		ls.kill(reason)
	}
	return len(doomed)
}

// killAllStreams kills every client stream on every host (the kill switch, a feed reset).
func (rt *routeTable) killAllStreams(reason string) {
	rt.mu.Lock()
	var doomed []*liveStream
	for _, he := range rt.byHost {
		for ls := range he.live {
			doomed = append(doomed, ls)
		}
	}
	rt.mu.Unlock()
	for _, ls := range doomed {
		ls.kill(reason)
	}
}

// hostHasLabel reports whether host is <label>.<something>.
func hostHasLabel(host, label string) bool {
	return len(host) > len(label) && host[len(label)] == '.' && host[:len(label)] == label
}

// hostsOfLabel are the hosts the table knows (a connection bound to them, or streams still open on them) whose label is label. A host is
// <label>.<zone>, and the label is the first 20 characters: the control plane's answer is the only thing that ever put a host in the table.
func (rt *routeTable) hostsOfLabel(label string) []string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	var hosts []string
	for host := range rt.byHost {
		if hostHasLabel(host, label) {
			hosts = append(hosts, host)
		}
	}
	return hosts
}

// controls are the connections bound to a host of label, and every connection when label is "".
func (rt *routeTable) controls(label string) []*ctrl {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	var out []*ctrl
	for host, he := range rt.byHost {
		if he.cc != nil && (label == "" || hostHasLabel(host, label)) {
			out = append(out, he.cc)
		}
	}
	return out
}

// ---------------------------------------------------------------- the control connection of one device

// ctrl is one control connection of a device: from HELLO to its close.
type ctrl struct {
	s    *Server
	id   string
	conn net.Conn
	wmu  sync.Mutex

	mu         sync.Mutex
	sub, host  string
	status     string
	plan       string    // paid or trial, as the control plane last said (the grace is for paid)
	jti        string    // the session the device last authenticated with: what a refresh of this connection tells the control plane
	authAt     int64     // the control plane's own time (epoch s) at its last answer for this connection: a feed event older than it is already in it
	validUntil time.Time // what the control plane granted, never changed by the node
	graceUntil time.Time // a paid connection's end while the control plane does not answer (zero when it is not in its grace)
	renewDown  bool      // the last RENEW got no answer from the control plane (a timeout, a 5xx, a 429)
	refused    bool      // the last RENEW got an answer from the control plane, and it was no: the control plane being down later does not extend it
	ready      bool      // an OK was sent: the connection is in the routing table
	lastRenew  time.Time
	stop       func() bool // the timer that ends the connection at validUntil (or at the end of its grace)

	refreshing, refreshAgain bool // a refresh of this connection (feed pause/resume) is running, and another event came while it ran

	done   chan struct{}
	once   sync.Once
	reason atomic.Value // string, why it was closed
}

func (s *Server) newCtrl(c net.Conn) *ctrl {
	cc := &ctrl{s: s, id: fmt.Sprintf("c%d", s.connSeq.Add(1)), conn: c, done: make(chan struct{})}
	s.mu.Lock()
	s.conns[cc] = struct{}{}
	s.mu.Unlock()
	return cc
}

func (c *ctrl) subject() string  { c.mu.Lock(); defer c.mu.Unlock(); return c.sub }
func (c *ctrl) hostName() string { c.mu.Lock(); defer c.mu.Unlock(); return c.host }

func (c *ctrl) bind(sub, host string) {
	c.mu.Lock()
	c.sub, c.host = sub, host
	c.mu.Unlock()
}

// setReady records what the control plane decided: the connection serves streams from now on, until validUntil. A new decision ends any grace.
func (c *ctrl) setReady(resp AuthorizeResponse, jti string, validUntil time.Time) {
	c.mu.Lock()
	c.ready, c.status, c.plan, c.jti, c.authAt, c.validUntil = true, resp.Status, resp.Plan, jti, resp.ServerTime, validUntil
	c.graceUntil, c.renewDown, c.refused = time.Time{}, false, false
	c.mu.Unlock()
}

// setStatus records a status the control plane gave in an answer that does not extend the connection (a refresh after a pause or a resume).
func (c *ctrl) setStatus(resp AuthorizeResponse) {
	c.mu.Lock()
	c.status, c.plan, c.authAt = resp.Status, resp.Plan, resp.ServerTime
	c.mu.Unlock()
}

// pause stops this connection from opening streams until the control plane says otherwise.
func (c *ctrl) pause() {
	c.mu.Lock()
	c.status = statusPaused
	c.mu.Unlock()
}

// markRenew records how the control plane came out of a RENEW that was not granted: it did not answer (down), or it answered no (refused).
func (c *ctrl) markRenew(down, refused bool) {
	c.mu.Lock()
	c.renewDown, c.refused = down, refused
	c.mu.Unlock()
}

// canOpen reports whether a client stream may be opened on this connection at now: an OK was sent, the device is not paused and valid_until has not
// come. A paused connection stays up (a resume arrives as a statement) but opens nothing.
func (c *ctrl) canOpen(now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ready && c.status != statusPaused && now.Before(c.validUntil)
}

// tooSoon records a RENEW at now and reports whether the previous one was less than gap ago.
func (c *ctrl) tooSoon(now time.Time, gap time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.lastRenew.IsZero() && now.Sub(c.lastRenew) < gap {
		return true
	}
	c.lastRenew = now
	return false
}

func (c *ctrl) isReady() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.ready }

func (c *ctrl) writeLocked(line string, at time.Time) error {
	err := c.sendLocked(line)
	c.s.emit(at, map[string]any{"conn": c.id, "ev": "send", "line": line})
	return err
}

// sendLocked puts one line on the wire without recording it, for a caller that records it itself.
func (c *ctrl) sendLocked(line string) error {
	_ = c.conn.SetWriteDeadline(time.Now().Add(c.s.cfg.WriteTimeout))
	_, err := io.WriteString(c.conn, line+"\n")
	return err
}

func (c *ctrl) write(line string) error { return c.writeAt(line, c.s.now()) }

// writeAt writes one line; at is the moment recorded in the trace (the moment the decision to write it was taken).
func (c *ctrl) writeAt(line string, at time.Time) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.writeLocked(line, at)
}

// close ends the connection for reason (a CLOSE reason, or another word for the log). A reason the device is told (CLOSE <reason>) is sent first,
// unless the writer is stuck.
func (c *ctrl) close(reason string) {
	c.once.Do(func() {
		c.reason.Store(reason)
		close(c.done)
		c.mu.Lock()
		if c.stop != nil {
			c.stop()
		}
		c.mu.Unlock()
		// The CLOSE line goes out under the write lock, so it follows an OK that is still being written; a writer that is stuck is not waited for.
		told, ready := false, false
		if c.lockWrite(closeWait) {
			if ready = c.isReady(); ready && inList(policyData.Protocol.CloseReasons, reason) {
				_ = c.writeLocked(closeLine(reason), c.s.now())
				told = true
			}
			c.wmu.Unlock()
		} else {
			ready = c.isReady()
		}
		if ready && !told {
			// The transport ended without a CLOSE line (the device went away, the write was stuck). The recording still has to know this
			// connection is over, so a trace gets a marker that never went on the wire.
			c.s.emit(c.s.now(), map[string]any{"conn": c.id, "ev": "send", "line": "CLOSE", "wire": false})
		}
		_ = c.conn.Close()
		host := c.hostName()
		c.s.routes.remove(c)
		c.s.mu.Lock()
		delete(c.s.conns, c)
		c.s.mu.Unlock()
		// A connection that ends because its grant ended (not because the device went away) takes the streams of its host with it, unless a newer
		// connection of the device already serves them.
		if ready && endsStreams(reason) {
			c.s.routes.killStreams(host, reason, false)
		}
	})
}

// endsStreams says whether a connection closed for reason takes the host's open streams with it: the grant ended (expired, revoked, released) or the
// kill switch is on. A device that went away, a replaced connection and a node going down leave them to their own limits.
func endsStreams(reason string) bool {
	switch reason {
	case closeExpired, closeRevoked, closeReleased, closeKilled:
		return true
	}
	return false
}

// closeWait is how long a close waits for a writer that holds the connection's write lock before it gives up on the CLOSE line.
const closeWait = 250 * time.Millisecond

func (c *ctrl) lockWrite(wait time.Duration) bool {
	deadline := time.Now().Add(wait)
	for !c.wmu.TryLock() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(time.Millisecond)
	}
	return true
}

func (c *ctrl) closeReason() string {
	if r, ok := c.reason.Load().(string); ok {
		return r
	}
	return ""
}

// arm schedules the end of the connection at validUntil (CLOSE expired); a RENEW arms it again for the new moment.
func (c *ctrl) arm(validUntil time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stop != nil {
		c.stop()
	}
	c.stop = c.s.clk.AfterFunc(validUntil.Sub(c.s.now()), func() { c.expire(validUntil) })
}

// expire is the end of the grant the timer was armed for. A grant a RENEW replaced since is not this one, and nothing happens. Otherwise the
// connection closes, except for a paid one while the control plane does not answer: it keeps its connection and its streams (but opens no new
// stream: canOpen is false from valid_until) for the grace, and closes when that is over. A trial or a gated connection is never extended, and
// neither is a paid one the control plane did answer (its RENEW was refused, or never came).
func (c *ctrl) expire(validUntil time.Time) {
	c.mu.Lock()
	current := c.validUntil.Equal(validUntil)
	inGrace := !c.graceUntil.IsZero()
	paid := c.plan == "paid"
	down := c.renewDown
	refused := c.refused
	c.mu.Unlock()
	if !current {
		return
	}
	now := c.s.now()
	if !inGrace && paid && !refused && c.s.cfg.Grace > 0 && (down || c.s.health.down(now, c.s.cfg.DownQuiet)) {
		graceUntil := validUntil.Add(c.s.cfg.Grace)
		c.mu.Lock()
		c.graceUntil = graceUntil
		if c.stop != nil {
			c.stop()
		}
		c.stop = c.s.clk.AfterFunc(graceUntil.Sub(now), func() { c.expire(validUntil) })
		c.mu.Unlock()
		c.s.log.Warn("control_grace", "conn", c.id, "grace_s", int64(c.s.cfg.Grace/time.Second))
		return
	}
	c.close(closeExpired)
}

// bufConn serves reads through the bufio.Reader that parsed the first protocol line, so no byte the peer sent right after it is lost.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func (b *bufConn) CloseWrite() error {
	if cw, ok := b.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return b.Conn.Close()
}

// prefixConn replays the bytes already read from a connection before reading on: the ClientHello that was peeked to learn the SNI.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (p *prefixConn) Read(b []byte) (int, error) {
	if len(p.prefix) > 0 {
		n := copy(b, p.prefix)
		p.prefix = p.prefix[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

// ---------------------------------------------------------------- :443

// sourceOf is the source address of an accepted connection and whether it is in the OpenAI list.
func (s *Server) sourceOf(c net.Conn) (peer netip.Addr, ok, openai bool) {
	if s.cfg.peerOf != nil {
		peer, ok = s.cfg.peerOf(c)
	} else {
		peer, ok = peerAddr(c)
	}
	return peer, ok, ok && s.openai.contains(peer)
}

// short is the per-boot salted short hash of a word (an address, a name): how a log line tells two of them apart without holding either. The salt
// lives in memory only, so the hash cannot be read back, and it changes at every start, so it cannot be followed from one boot to the next.
func (s *Server) short(word string) string {
	return fmt.Sprintf("%08x", uint32(maphash.String(s.seed, word)))
}

// refused counts a connection or stream the node did not serve and writes its log line, at most one a second per reason: a flood must not become a flood
// of log lines (the count is in the metrics, and the line says how many were left out). The line never names a source or a name.
func (s *Server) refused(level slog.Level, msg, reason string, attrs ...any) {
	s.met.rejected.inc(reason)
	if ok, cut := s.sampler.allow(msg + "/" + reason); ok {
		attrs = append(attrs, "reason", reason)
		if cut > 0 {
			attrs = append(attrs, "suppressed", cut)
		}
		s.log.Log(context.Background(), level, msg, attrs...)
	}
}

// handleHTTPS is the one public listener. It reads only the cleartext ClientHello for the SNI: the node's own name is the control handler (the
// device speaks protocol v2 to it over TLS with ALPN all-tunnel/2), any other name is a client of a device and is spliced as raw bytes.
//
// Before a byte is read, the source is admitted: a source that is banned, that opens connections faster than the policy lets it, or that already holds
// the most it may is dropped without an answer (limits.go).
func (s *Server) handleHTTPS(c net.Conn) {
	defer s.wg.Done()
	handedOff := false // an ATTACHed data connection belongs to its stream from then on
	defer func() {
		if !handedOff {
			_ = c.Close()
		}
	}()
	id := newStreamID()
	start := s.now()

	peer, havePeer, fromOpenAI := s.sourceOf(c)
	slotDone := func() {}
	if havePeer {
		rel, why := s.ips.admit(peer, fromOpenAI)
		if why != "" {
			s.refused(slog.LevelInfo, "conn_reject", why, "stream", id)
			return
		}
		slotDone = rel
	}
	defer slotDone()

	// The unauthenticated budget has a reserve, as the stream budget has: a source that is neither an address of the OpenAI list, nor one that holds (or just held) a device's
	// control connection, nor one a device marked good, may not take the share kept for those (policy node_limits.openai_reserved_pct). Twenty anonymous addresses holding the
	// most a source may hold fill the anonymous share, never the whole budget: ChatGPT's clients and the devices that reconnect (they are unauthenticated until their PROOF) go on.
	anon := !(havePeer && (fromOpenAI || s.ips.knownDevice(peer) || s.hints.goodAnywhere(peer)))
	if anon && !tryAcquire(&s.anonUnauth, s.anonUnauthMax()) {
		s.refused(slog.LevelWarn, "conn_reject", "unauth_anon_limit")
		return
	}
	if !tryAcquire(&s.unauth, int64(s.cfg.MaxUnauth)) {
		if anon {
			s.anonUnauth.Add(-1)
		}
		s.refused(slog.LevelWarn, "conn_reject", "unauth_limit")
		return
	}
	released := false
	release := func() {
		if !released {
			released = true
			s.unauth.Add(-1)
			if anon {
				s.anonUnauth.Add(-1)
			}
		}
	}
	defer release()
	var unmark func()
	// strike is a source that sent something no client of a device sends: a name that is not a device online, or a ClientHello that is no TLS. Too
	// many different ones and the source is dropped at accept for a while (an address of the OpenAI list is never struck: ChatGPT retrying an
	// offline device is not a scan).
	strike := func(name string) {
		// An address a device marked good (it just completed authenticated calls) is not a scanner, whatever names it asks for: at fleet scale a shared
		// egress address asks for many devices that are offline at that moment.
		if havePeer && !s.hints.goodAnywhere(peer) && s.ips.strike(peer, name, fromOpenAI) {
			s.met.bansTotal.Add(1)
			s.log.Info("source_banned", "source", s.short(peer.String()), "ban_s", int64(s.cfg.UnknownSNIBan/time.Second))
		}
	}

	peeked, sni, err := readClientHello(c, s.cfg.HelloTimeout)
	if err != nil && !errors.Is(err, errBadSNI) {
		// A ClientHello that is truncated, malformed, too large or never finished never produces an OPEN.
		s.emit(start, map[string]any{"ev": "client_hello", "sni": "", "complete": false})
		reason := helloReason(err)
		s.refused(slog.LevelInfo, "conn_reject", reason, "stream", id, "peeked_bytes", len(peeked))
		if reason == "not_tls" || reason == "bad_hello" || reason == "hello_too_large" {
			strike("")
		}
		return
	}
	if err != nil || sni == "" {
		reason := "no_sni"
		if err != nil {
			reason = "bad_sni"
		}
		s.emit(s.now(), map[string]any{"ev": "tls_alert", "sni": ""})
		s.refused(slog.LevelInfo, "conn_reject", reason, "stream", id, "peeked_bytes", len(peeked))
		strike("")
		sendAlert(c, alertUnrecognizedName)
		return
	}
	if sni == s.cfg.NodeHost {
		// A connection of the node's own name that proves who it is (a device's control connection after its proof, a data connection after its ATTACH)
		// stops being an unknown source's: it gives back its slot and the token it took, and a control connection marks its address as a device's for as
		// long as it lives, so that the connections of the streams it serves are not held to what an anonymous source gets (limits.go).
		defer func() {
			if unmark != nil {
				unmark()
			}
		}()
		handedOff = s.serveOwnName(c, peeked, func(control bool) {
			release()
			if havePeer {
				s.ips.refund(peer, fromOpenAI)
				if control && unmark == nil {
					unmark = s.ips.markDevice(peer)
				}
			}
			slotDone()
		})
		return
	}
	release()
	s.met.observeClientHello(peeked)
	s.serveClient(c, id, sni, peeked, start, peer, havePeer, strike)
}

// classOf names the class of a client stream's source for the OPEN: the configured classifier when there is one, otherwise openai for an address of
// the OpenAI list, hint for one the device marked, anon for the rest. marked says whether the device marked the address (what puts the stream in the
// host's hint slice, whatever class the OPEN says).
func (s *Server) classOf(peer netip.Addr, havePeer bool, host string) (class string, marked bool) {
	class = classAnon
	if havePeer {
		marked = s.hints.good(host, peer)
	}
	switch {
	case s.cfg.Classify != nil && havePeer:
		if got := s.cfg.Classify(peer, host); inList(policyData.Protocol.SourceClasses, got) {
			class = got
		}
	case havePeer && s.openai.contains(peer):
		class = classOpenAI
	case marked:
		class = classHint
	}
	return class, marked || class == classHint
}

// serveClient splices one client of a device. Everything the node learned is the SNI and the ClientHello's bytes, and the OPEN is sent only now
// that the ClientHello is complete and well formed.
func (s *Server) serveClient(c net.Conn, id, sni string, peeked []byte, start time.Time, peer netip.Addr, havePeer bool, strike func(name string)) {
	if s.cfg.divert != nil && s.cfg.divert(c, peeked, s.log) {
		return
	}
	class, marked := s.classOf(peer, havePeer, sni)
	peerText := "0.0.0.0"
	if havePeer {
		peerText = peer.String()
	}
	hello := map[string]any{"ev": "client_hello", "sni": sni, "complete": true, "peer_ip": peerText, "class": class}
	s.emit(s.now(), hello)

	if s.draining.Load() {
		// A draining node takes no new client: the TLS alert, never an OPEN. (The client's ClientHello is not forwarded anywhere.)
		s.refused(slog.LevelInfo, "stream_reject", "draining", "stream", id, "peeked_bytes", len(peeked))
		s.alert(c, sni, alertInternalError)
		return
	}
	// The global budget: every stream counts in it, and a stream whose source is neither ChatGPT's (the OpenAI list) nor marked good by a device may not
	// take the share that is reserved for those (policy node_limits.openai_reserved_pct).
	if !tryAcquire(&s.streams, int64(s.cfg.MaxStreams)) {
		s.refused(slog.LevelWarn, "stream_reject", "global_limit", "stream", id)
		s.alert(c, sni, alertInternalError)
		return
	}
	defer s.streams.Add(-1)
	if class == classAnon && !marked {
		if !tryAcquire(&s.anonStreams, int64(s.cfg.MaxStreams-s.cfg.MaxStreams*s.cfg.OpenAIReservedPct/100)) {
			s.refused(slog.LevelWarn, "stream_reject", "anon_global_limit", "stream", id)
			s.alert(c, sni, alertInternalError)
			return
		}
		defer s.anonStreams.Add(-1)
	}

	cc, live, why := s.routes.acquire(sni, marked, s.now())
	if why != "" {
		desc := byte(alertInternalError)
		if why == admitUnknown {
			desc = alertUnrecognizedName
			strike(sni)
		}
		s.refused(slog.LevelInfo, "stream_reject", why, "stream", id, "peeked_bytes", len(peeked))
		s.alert(c, sni, desc)
		return
	}
	defer s.routes.release(sni, live)
	// The host's record of today's gated budget: every stream holds it, so that a host that turns gated while the stream is open is held to it too.
	live.usage = s.gates.acquire(sni)
	defer s.gates.release(live.usage)
	if live.he.gated.Load() {
		if ok, reason := live.usage.admit(s.now(), s.cfg.GatedBytesPerDay, s.cfg.GatedStreamsPerDay); !ok {
			s.refused(slog.LevelInfo, "stream_reject", reason, "stream", id, "peeked_bytes", len(peeked))
			s.alert(c, sni, alertInternalError)
			return
		}
	}

	dc, err := s.openStream(cc, id, peerText, class)
	if err != nil {
		s.refused(slog.LevelInfo, "stream_reject", err.Error(), "stream", id, "peeked_bytes", len(peeked), "wait_ms", s.now().Sub(start).Milliseconds())
		s.alert(c, sni, alertInternalError)
		return
	}
	defer dc.Close()
	if !live.bind(c, dc) {
		// Cut (a revoke, a pause) between the OPEN and the ATTACH: nothing of the client's goes to the device.
		s.refused(slog.LevelInfo, "stream_reject", live.killedBy(), "stream", id, "peeked_bytes", len(peeked))
		s.alert(c, sni, alertInternalError)
		return
	}
	s.met.streamsOpened.Add(1)
	s.log.Info("stream_open", "stream", id, "hello_bytes", len(peeked), "setup_ms", s.now().Sub(start).Milliseconds(), "class", class)
	res := s.splice(id, c, dc, peeked, live)
	if why := live.killedBy(); why != "" {
		res.reason = why
	}
	s.met.streamEnd.inc(res.reason)
	s.log.Info("stream_close", "stream", id, "up_bytes", res.up, "down_bytes", res.down,
		"duration_ms", s.now().Sub(start).Milliseconds(), "reason", res.reason)
}

func (s *Server) alert(c net.Conn, sni string, desc byte) {
	s.emit(s.now(), map[string]any{"ev": "tls_alert", "sni": sni})
	sendAlert(c, desc)
}

// openStream registers a pending stream, tells the device (OPEN over its control connection) and waits for its ATTACH. The returned connection has
// had its ATTACH line consumed; the caller's first write is the first byte of the raw stream (there is deliberately no reply line in between, so a
// device can hand the connection straight to its TLS layer).
func (s *Server) openStream(cc *ctrl, id, peer, class string) (net.Conn, error) {
	at := s.now()
	if !cc.canOpen(at) {
		return nil, errOffline
	}
	secret := newSecret()
	p := &pendingStream{cc: cc, secret: secret, ch: make(chan net.Conn, 1)}
	s.mu.Lock()
	s.pending[id] = p
	s.mu.Unlock()

	if err := cc.writeAt(formatLine(message{"verb": "OPEN", "stream_id": id, "secret": secret, "peer_ip": peer, "class": class}), at); err != nil {
		s.dropPending(id)
		cc.close("write_error")
		return nil, errControlWrite
	}
	timer := time.NewTimer(s.cfg.AttachTimeout)
	defer timer.Stop()
	done := cc.done
wait:
	for {
		select {
		case dc := <-p.ch:
			return dc, nil
		case <-timer.C:
			break wait
		case <-done:
			if cc.closeReason() != closeReplaced {
				break wait
			}
			// A newer connection of the same device took over: this OPEN was sent with the old one, and its attach secret is still good.
			done = nil
		case <-s.ctx.Done():
			break wait
		}
	}
	// Failed: unregister, but an ATTACH may have just landed.
	if !s.dropPending(id) {
		return <-p.ch, nil
	}
	switch {
	case s.ctx.Err() != nil:
		return nil, errShuttingDown
	case cc.closeReason() != "" && cc.closeReason() != closeReplaced:
		return nil, errOffline
	}
	return nil, errAttachTimeout
}

// dropPending removes id; it reports whether the entry was still there.
func (s *Server) dropPending(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.pending[id]
	delete(s.pending, id)
	return ok
}

// ---------------------------------------------------------------- splice

type spliceResult struct {
	up, down int64 // client->device, device->client
	reason   string
}

func classifyErr(err error) string {
	switch {
	case err == nil:
		return "closed"
	case errors.Is(err, errByteCap):
		return "byte_cap"
	case errors.Is(err, errGatedBytes):
		return "gated_bytes"
	case errors.Is(err, os.ErrDeadlineExceeded):
		return "idle"
	default:
		return "conn_error"
	}
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

// pump copies src to dst with per-read idle deadlines and the shared byte budget. A clean EOF half-closes dst and returns nil. While the stream's host
// is gated, every chunk is also charged to the host's budget of the day, and the stream ends where the budget does. watch, when set, reads the
// device's first bytes for the handshake observer.
func (s *Server) pump(id, dir string, dst, src net.Conn, ctr, total *atomic.Int64, live *liveStream, watch *serverHelloWatch) error {
	// A pump spends the whole life of an idle stream blocked in a read, so the buffer it waits with is a small one (4 KiB); it takes a 32 KiB one only for a read that filled
	// the small one (a bulk transfer) and gives it back when a read comes back short. An idle stream then holds about 8 KiB of buffer instead of 64 KiB (the acceptance is under 64 KiB of memory per stream).
	sp := s.smallBufPool.Get().(*[]byte)
	small := *sp
	defer s.smallBufPool.Put(sp)
	var bp *[]byte // the big buffer, while this pump holds one
	giveBack := func() {
		if bp != nil {
			s.bigBuffersInUse.Add(-1)
			s.bufPool.Put(bp)
			bp = nil
		}
	}
	defer giveBack()
	buf := small
	for {
		_ = src.SetReadDeadline(time.Now().Add(s.cfg.StreamIdle))
		n, rerr := src.Read(buf)
		if n > 0 {
			chunk, spent := buf[:n], false
			if live != nil && live.he.gated.Load() {
				if got := live.usage.charge(s.now(), int64(n), s.cfg.GatedBytesPerDay); got < int64(n) {
					chunk, spent = buf[:got], true
				}
			}
			if total.Add(int64(len(chunk))) > s.cfg.MaxStreamBytes {
				return errByteCap
			}
			if len(chunk) > 0 {
				s.tapBytes(id, dir, chunk)
				if watch != nil {
					watch.feed(chunk)
				}
				_ = dst.SetWriteDeadline(time.Now().Add(s.cfg.StreamIdle))
				if _, werr := dst.Write(chunk); werr != nil {
					return werr
				}
				ctr.Add(int64(len(chunk)))
				s.met.bytes.add(dir, int64(len(chunk)))
			}
			if spent {
				s.met.gatedCut.Add(1)
				return errGatedBytes
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				closeWrite(dst)
				return nil
			}
			return rerr
		}
		switch { // the buffer for the next read: bulk traffic gets the big one, a trickle (and the wait of an idle stream) the small one
		case bp == nil && n == len(small):
			bp = s.bufPool.Get().(*[]byte)
			s.bigBuffersInUse.Add(1)
			buf = *bp
		case bp != nil && n < len(small):
			giveBack()
			buf = small
		}
	}
}

// splice copies bytes both ways between client and dev until both sides are done, one fails, or a limit trips. preload (the peeked ClientHello) is
// written to dev before anything else from the client. Neither side's bytes are interpreted.
func (s *Server) splice(id string, client, dev net.Conn, preload []byte, live *liveStream) spliceResult {
	var up, down, total atomic.Int64
	var rmu sync.Mutex
	reason := ""
	setReason := func(r string) {
		rmu.Lock()
		if reason == "" {
			reason = r
		}
		rmu.Unlock()
	}
	closeBoth := func() { _ = client.Close(); _ = dev.Close() }

	age := time.AfterFunc(s.cfg.StreamMaxAge, func() { setReason("max_age"); closeBoth() })
	defer age.Stop()
	stopWatch := make(chan struct{})
	defer close(stopWatch)
	go func() {
		select {
		case <-s.ctx.Done():
			setReason("shutdown")
			closeBoth()
		case <-stopWatch:
		}
	}()

	results := make(chan error, 2)
	go func() { // client -> device
		if len(preload) > 0 {
			if live.he.gated.Load() && live.usage.charge(s.now(), int64(len(preload)), s.cfg.GatedBytesPerDay) < int64(len(preload)) {
				// a ClientHello cut short is of no use to anyone: nothing of it goes to the device
				s.met.gatedCut.Add(1)
				results <- errGatedBytes
				return
			}
			_ = dev.SetWriteDeadline(time.Now().Add(s.cfg.WriteTimeout))
			if _, err := dev.Write(preload); err != nil {
				results <- err
				return
			}
			s.tapBytes(id, "up", preload)
			up.Add(int64(len(preload)))
			total.Add(int64(len(preload)))
			s.met.bytes.add("up", int64(len(preload)))
		}
		results <- s.pump(id, "up", dev, client, &up, &total, live, nil)
	}()
	go func() { // device -> client
		results <- s.pump(id, "down", client, dev, &down, &total, live, newServerHelloWatch(s.met))
	}()

	first := <-results
	if first == nil {
		// One direction ended cleanly (and was half-closed): the other gets a bounded time to finish.
		t := time.NewTimer(s.cfg.HalfCloseTimeout)
		select {
		case second := <-results:
			setReason(classifyErr(second))
		case <-t.C:
			setReason("half_close_timeout")
			closeBoth()
			<-results
		}
		t.Stop()
	} else {
		setReason(classifyErr(first))
		closeBoth()
		<-results
	}
	closeBoth()
	rmu.Lock()
	defer rmu.Unlock()
	return spliceResult{up: up.Load(), down: down.Load(), reason: reason}
}

// ---------------------------------------------------------------- the node's own name: control and data connections of devices

func readLine(br *bufio.Reader) (string, error) {
	b, err := br.ReadSlice('\n')
	if err != nil {
		return "", err
	}
	return string(b[:len(b)-1]), nil
}

func writeLineThenClose(c net.Conn, line string) {
	_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.WriteString(c, line+"\n")
	_ = c.Close()
}

// serveOwnName terminates the DEVICE-facing TLS on the node's own name (its public-CA certificate, TLS 1.3, ALPN all-tunnel/2), reads the first line
// and dispatches HELLO or ATTACH. This is the tunnel's own connection to its own client, never a client's TLS. It reports whether the connection was
// handed to a stream (an ATTACH that matched), in which case the caller must not close it.
func (s *Server) serveOwnName(raw net.Conn, peeked []byte, release func(control bool)) bool {
	tc := tls.Server(&prefixConn{Conn: raw, prefix: peeked}, s.tlsCfg)
	_ = tc.SetDeadline(time.Now().Add(s.cfg.FirstLineTimeout))
	if err := tc.Handshake(); err != nil {
		s.log.Debug("control_tls_failed")
		return false
	}
	if tc.ConnectionState().NegotiatedProtocol != policyData.Protocol.ALPN {
		s.log.Info("control_reject", "reason", "bad_alpn")
		return false
	}
	br := bufio.NewReaderSize(tc, policyData.Protocol.LineMaxBytes)
	line, err := readLine(br)
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) {
			writeLineThenClose(tc, errLine(codeLineTooLong))
		} else {
			s.log.Info("control_reject", "reason", "bad_first_line")
		}
		return false
	}
	first, perr := parseLine(line, dirD2N)
	if perr != nil {
		// An ATTACH or a HELLO with a bad field answers with its own word; anything else is not a command.
		code := errCode(perr)
		if v, _, _ := strings.Cut(line, " "); v != "HELLO" && v != "ATTACH" {
			code = codeBadCommand // contract section 2: a first line that is not HELLO or ATTACH is bad_command, whatever else is wrong with it
		}
		s.log.Info("control_reject", "reason", code)
		writeLineThenClose(tc, errLine(code))
		return false
	}
	switch first.str("verb") {
	case "HELLO":
		cc := s.newCtrl(tc)
		s.emit(s.now(), map[string]any{"ev": "recv", "conn": cc.id, "line": line})
		if s.draining.Load() {
			// A draining node takes no new device either: it is told to try the other node. (An ATTACH for a stream that already has its OPEN is served.)
			s.log.Info("control_reject", "conn", cc.id, "reason", "draining")
			_ = cc.write(errLine(codeControlUnavailable))
			cc.close("refused")
			return false
		}
		s.serveControl(cc, br, first, release)
		return false
	case "ATTACH":
		return s.serveAttach(tc, br, first, line, fmt.Sprintf("d%d", s.connSeq.Add(1)), release)
	}
	s.log.Info("control_reject", "reason", codeBadCommand)
	writeLineThenClose(tc, errLine(codeBadCommand))
	return false
}

// exchange is one authentication in flight on a control connection: the HELLO that opened it, or a RENEW.
type exchange struct {
	kind     string // "hello" or "renew"
	token    string
	session  *SessionClaims
	nonce    string
	deadline time.Time
}

// refuse answers a failed HELLO or RENEW (or PROOF) with ERR. A refused HELLO closes the connection; a refused RENEW keeps it, with its old
// valid_until.
func (s *Server) refuse(cc *ctrl, kind, code string) bool {
	_ = cc.write(errLine(code))
	if kind == "hello" {
		cc.close("refused")
		return false
	}
	return true
}

// beginExchange verifies the session of a HELLO or RENEW and, when it holds, sends the CHALLENGE. A RENEW must be for the same subject as the
// connection. It reports whether the connection goes on.
func (s *Server) beginExchange(cc *ctrl, ex *exchange, kind, token string) bool {
	*ex = exchange{}
	now := s.now()
	session, err := verifySession(token, now, s.cfg.Keys, s.cfg.ClockSkew)
	if err != nil {
		code := errFor(tokenWord(err), codeAuth)
		if kh, ok := s.cfg.Keys.(keyHealth); ok && tokenWord(err) == tokUnknownKID && !kh.Healthy() {
			// The node cannot vouch for the control plane's keys (stale beyond the policy's window): not the device's fault, so not auth.
			code = codeControlUnavailable
			if kind == "renew" {
				// ... and it is the control plane being unreachable, which is what a paid device's grace is for: without this the connection closed at valid_until although the
				// device did everything right (its session was refused only because the node could not read the control plane's keys).
				cc.markRenew(true, false)
			}
		}
		s.log.Info("session_refused", "conn", cc.id, "kind", kind, "reason", tokenWord(err), "answer", code)
		return s.refuse(cc, kind, code)
	}
	if kind == "renew" && session.Subject != cc.subject() {
		s.log.Info("session_refused", "conn", cc.id, "kind", kind, "reason", "other_subject")
		return s.refuse(cc, kind, codeAuth)
	}
	*ex = exchange{kind: kind, token: token, session: session, nonce: newNonce(), deadline: now.Add(s.cfg.FirstLineTimeout)}
	if err := cc.write(formatLine(message{"verb": "CHALLENGE", "nonce": ex.nonce})); err != nil {
		cc.close("write_error")
		return false
	}
	return true
}

// serveControl runs a control connection from its HELLO to its end. release gives back the unauthenticated slot once the device has authenticated.
func (s *Server) serveControl(cc *ctrl, br *bufio.Reader, hello message, release func(control bool)) {
	tc := cc.conn
	defer cc.close("closed")
	defer s.routes.remove(cc) // idempotent: a close that raced an activation must not leave a route behind
	start := s.now()
	ex := &exchange{}
	if !s.beginExchange(cc, ex, "hello", hello.str("session")) {
		return
	}
	reason := ""
	for {
		deadline := s.now().Add(s.cfg.DeadPeer)
		if !cc.isReady() || ex.nonce != "" {
			deadline = s.now().Add(s.cfg.FirstLineTimeout)
			if !ex.deadline.IsZero() && ex.deadline.Before(deadline) {
				deadline = ex.deadline
			}
		}
		_ = tc.SetReadDeadline(deadline)
		line, err := readLine(br)
		if err != nil {
			switch {
			case errors.Is(err, bufio.ErrBufferFull):
				_ = cc.write(errLine(codeLineTooLong))
				reason = closeProtocol
			case errors.Is(err, os.ErrDeadlineExceeded) && ex.nonce != "" && cc.isReady():
				// The device never answered a RENEW's CHALLENGE: the exchange is dropped, the connection and its old valid_until stay.
				*ex = exchange{}
				continue
			case errors.Is(err, os.ErrDeadlineExceeded):
				reason = closeIdle
			default:
				reason = "closed"
			}
			cc.close(reason)
			s.log.Info("control_down", "conn", cc.id, "duration_ms", s.now().Sub(start).Milliseconds(), "reason", cc.closeReason())
			return
		}
		s.emit(s.now(), map[string]any{"ev": "recv", "conn": cc.id, "line": line})
		m, perr := parseLine(line, dirD2N)
		if perr != nil {
			_ = cc.write(errLine(errCode(perr)))
			cc.close(closeProtocol)
			return
		}
		switch m.str("verb") {
		case "PROOF":
			if ex.nonce == "" {
				_ = cc.write(errLine(codeBadCommand))
				cc.close(closeProtocol)
				return
			}
			if !s.finishExchange(cc, ex, m.str("proof"), release) {
				return
			}
		case "RENEW":
			if !cc.isReady() || ex.nonce != "" {
				_ = cc.write(errLine(codeBadCommand))
				cc.close(closeProtocol)
				return
			}
			if cc.tooSoon(s.now(), s.cfg.MinRenewGap) {
				// a device cannot turn one connection into a stream of authorize calls: the connection and its old valid_until stay
				if err := cc.write(errLine(codeBusy)); err != nil {
					cc.close("write_error")
					return
				}
				continue
			}
			if !s.beginExchange(cc, ex, "renew", m.str("session")) {
				return
			}
		case "PING":
			if err := cc.write(formatLine(message{"verb": "PONG"})); err != nil {
				cc.close("write_error")
				return
			}
		case "HINT":
			if cc.isReady() {
				var addrs []netip.Addr
				for _, a := range m["addresses"].([]any) {
					if addr, err := netip.ParseAddr(a.(string)); err == nil {
						addrs = append(addrs, addr)
					}
				}
				// filed under the host the control plane gave THIS connection: a device can mark addresses for no other host than its own
				s.hints.mark(cc.hostName(), addrs)
				s.met.hintsMarked.Add(1)
				if s.cfg.OnHint != nil {
					s.cfg.OnHint(cc.hostName(), addrs)
				}
			}
		case "CLOSE":
			cc.close("device_close")
			s.log.Info("control_down", "conn", cc.id, "duration_ms", s.now().Sub(start).Milliseconds(), "reason", "device_close")
			return
		default: // HELLO again, or anything else the device must not send here
			_ = cc.write(errLine(codeBadCommand))
			cc.close(closeProtocol)
			return
		}
	}
}

// finishExchange checks the PROOF of the exchange in flight and, when it holds, asks the control plane what the device may do and answers OK. It
// reports whether the connection goes on.
func (s *Server) finishExchange(cc *ctrl, ex *exchange, proof string, release func(control bool)) bool {
	cur := *ex
	*ex = exchange{} // the nonce is spent whatever the verdict
	now := s.now()
	pc, err := verifyProof(proof, now, cur.token, cur.session, cur.nonce, s.nodeURL, s.cfg.ClockSkew)
	if err == nil && !s.replay.spend(pc.JTI, pc.IssuedAt, now, s.cfg.ClockSkew) {
		err = tokFail(tokReplayedJTI)
	}
	if err != nil {
		s.log.Info("proof_refused", "conn", cc.id, "kind", cur.kind, "reason", tokenWord(err))
		return s.refuse(cc, cur.kind, errFor(tokenWord(err), codeBadProof))
	}

	// The device has proven itself, so it no longer holds a pre-authentication slot: a slow control plane must not starve the ClientHellos of
	// clients and the ATTACHes of devices that are already connected. What waits for authorize is bounded on its own.
	if cur.kind == "hello" {
		release(true)
	}
	if s.killed.Load() {
		// The kill switch is on: nobody is served, and nothing is asked of the control plane until it is cleared.
		s.log.Info("authorize_skipped", "conn", cc.id, "kind", cur.kind, "reason", "kill_switch")
		return s.refuse(cc, cur.kind, codeControlUnavailable)
	}

	// The control plane decides; nothing the device said names a host. Until its answer is acted on the feed is listened to: an event the feed
	// applies while the call is in flight is not in the answer, and cannot find a connection that is not yet in the routing table.
	watch := s.watchFeed()
	defer watch.stop()
	req := AuthorizeRequest{DeviceID: cur.session.Subject, SessionJTI: cur.session.JTI, Reason: cur.kind, Node: s.cfg.NodeID}
	s.emit(s.now(), map[string]any{"conn": cc.id, "ev": "cp", "call": "authorize", "body": req.toMap()})
	resp, err := s.authorize(req)
	if err == nil {
		if cerr := checkAuthorize(resp, req); cerr != nil {
			s.log.Warn("authorize_answer_refused", "conn", cc.id, "reason", cerr.Error())
			s.health.bad(s.now())
			err = &ControlError{Status: 502, Code: "bad_response"}
		}
	}
	if err != nil {
		status, word := 503, "control_unavailable"
		if ce, ok := err.(*ControlError); ok {
			status, word = ce.Status, ce.Code
		}
		s.emit(s.now(), map[string]any{"conn": cc.id, "ev": "cp_reply", "status": status, "body": map[string]any{"ok": false, "error": word}})
		code := errForControl(err)
		if cur.kind == "renew" && !isLocalFailure(err) {
			// A RENEW this node could not even send (its own queue was full or its turn did not come) says nothing about the control plane.
			cc.markRenew(code == codeControlUnavailable, code != codeControlUnavailable)
		}
		s.log.Info("authorize_refused", "conn", cc.id, "kind", cur.kind, "reason", code)
		return s.refuse(cc, cur.kind, code)
	}
	s.emit(s.now(), map[string]any{"conn": cc.id, "ev": "cp_reply", "status": 200, "body": resp.toMap()})
	if resp.E2EKill {
		// The device is told first (the switch closes every connection, this one included), then nobody is served until it is cleared.
		s.log.Warn("kill_switch_seen", "conn", cc.id, "via", "authorize")
		s.refuse(cc, cur.kind, codeControlUnavailable)
		s.setKilled(true)
		return false
	}

	validUntil := time.Unix(resp.ValidUntil, 0)
	if !validUntil.After(s.now()) {
		// A grant that has already ended is never relayed.
		return s.refuse(cc, cur.kind, codeAuth)
	}
	if v := watch.verdict(resp.Host, resp.ServerTime); v.cut != "" {
		// A revoke, a release or the end of the license was applied while the call was in flight: the answer is older than it. Nothing is served.
		s.log.Info("authorize_overtaken", "conn", cc.id, "kind", cur.kind, "reason", v.cut)
		if cur.kind != "hello" {
			cc.close(v.cut)
			return false
		}
		return s.refuse(cc, cur.kind, v.err)
	}
	ok := okBody{Node: s.cfg.NodeID, Host: resp.Host, Status: resp.Status, ValidUntil: resp.ValidUntil, ServerTime: resp.ServerTime, Policy: boundWindows(resp.Policy)}

	// Publish and answer under the write lock, so no OPEN can be sent before the OK line.
	cc.wmu.Lock()
	var old *ctrl
	recorded := false
	if cur.kind == "hello" {
		// The OK is recorded under the routing table's lock, so two HELLOs of one subject that race are recorded in the order they were routed.
		old, err = s.routes.activate(cc, cur.session.Subject, resp.Host, func() {
			recorded = true
			s.emit(s.now(), map[string]any{"conn": cc.id, "ev": "send", "line": ok.line()})
		})
		if err != nil {
			cc.wmu.Unlock()
			s.log.Warn("host_refused", "conn", cc.id, "reason", err.Error())
			return s.refuse(cc, cur.kind, codeAuth)
		}
	} else if cc.hostName() != resp.Host {
		// The control plane now says this device owns another host: the one this connection serves is no longer its own. Fail closed.
		cc.wmu.Unlock()
		s.log.Warn("renew_host_changed", "conn", cc.id)
		cc.close(closeRevoked)
		return false
	}
	cc.setReady(resp, cur.session.JTI, validUntil)
	s.routes.setGated(cc, resp.Status == statusGated) // every status the control plane gives, a RENEW's included, decides what the host's streams are held to
	// The connection is in the routing table now, so the feed reaches it directly; what it applied before that is taken from the watch. A pause is
	// put back at once (setReady wrote the answer's status over it), and the control plane is asked again.
	late := watch.verdict(resp.Host, resp.ServerTime)
	if late.paused {
		cc.pause()
	}
	var werr error
	if recorded {
		werr = cc.sendLocked(ok.line())
	} else {
		werr = cc.writeLocked(ok.line(), s.now())
	}
	if werr == nil {
		werr = s.followUp(cc, resp)
	}
	cc.wmu.Unlock()
	if old != nil {
		old.close(closeReplaced)
	}
	if werr != nil {
		cc.close("write_error")
		return false
	}
	if late.cut != "" {
		// Applied between the check above and the connection joining the routing table: the OK is out, and the CLOSE follows it.
		cc.close(late.cut)
		s.routes.killStreams(resp.Host, late.cut, true)
		return false
	}
	if late.refresh {
		if late.paused {
			s.routes.killStreams(resp.Host, closePaused, true)
		}
		s.refreshAsync(cc)
	}
	cc.arm(validUntil)
	if cur.kind == "hello" {
		s.log.Info("control_up", "conn", cc.id, "status", resp.Status, "plan", resp.Plan, "replaced_previous", old != nil)
	} else {
		s.log.Info("control_renewed", "conn", cc.id, "status", resp.Status, "plan", resp.Plan)
	}
	return true
}

// followUp writes what goes right after an OK, under the connection's write lock so that no OPEN comes between: the control plane's signed access
// statement, forwarded as it is (the device verifies it, the node cannot change a letter of it without breaking it), and DRAIN when the node is
// already draining (a connection that was authenticating when SIGTERM came).
func (s *Server) followUp(cc *ctrl, resp AuthorizeResponse) error {
	if line := statementLine(resp.Access); resp.Access != "" && line != "" {
		if err := cc.writeLocked(line, s.now()); err != nil {
			return err
		}
	}
	if s.draining.Load() {
		return cc.writeLocked(drainLine(time.Duration(s.drainFor.Load())), s.now())
	}
	return nil
}

// The two ways authorize fails without having asked the control plane anything: the node's own queue was full, or its turn did not come in time.
var (
	errAuthorizeFull = &ControlError{Status: 503, Code: codeControlUnavailable}
	errAuthorizeWait = &ControlError{Status: 503, Code: codeControlUnavailable}
)

func isLocalFailure(err error) bool { return err == errAuthorizeFull || err == errAuthorizeWait }

// authorize asks the control plane for the verdict on one exchange. At most cfg.AuthorizeMax calls run at once; the exchanges waiting for a turn
// are bounded by the pre-authentication limit and share the call's time limit, and beyond either the device is told control_unavailable. What the
// call itself came to is recorded, so the node knows whether its control plane answers.
func (s *Server) authorize(req AuthorizeRequest) (AuthorizeResponse, error) {
	if !tryAcquire(&s.authQ, int64(s.cfg.MaxUnauth)) {
		s.met.authorize.inc("unavailable")
		return AuthorizeResponse{}, errAuthorizeFull
	}
	defer s.authQ.Add(-1)
	ctx, cancel := context.WithTimeout(s.ctx, s.cfg.AuthorizeTimeout)
	defer cancel()
	select {
	case s.authSem <- struct{}{}:
		defer func() { <-s.authSem }()
	case <-ctx.Done():
		s.met.authorize.inc("unavailable")
		return AuthorizeResponse{}, errAuthorizeWait
	}
	resp, err := s.cfg.Control.Authorize(ctx, req)
	s.health.record(s.now(), err)
	switch {
	case err == nil:
		s.met.authorize.inc("ok")
	case isRefusal(err):
		s.met.authorize.inc("refused")
	default:
		s.met.authorize.inc("unavailable")
	}
	return resp, err
}

// serveAttach hands a data connection to the stream its ATTACH names. The secret is one use: a wrong one is refused and does not consume the stream,
// a used or unknown id is unknown_stream. On success there is NO reply: the next byte the node sends is the first byte of the client's stream.
func (s *Server) serveAttach(tc *tls.Conn, br *bufio.Reader, m message, line, connName string, release func(control bool)) bool {
	id, secret := m.str("stream_id"), m.str("secret")
	verdict := func(result string) {
		s.emit(s.now(), map[string]any{"conn": connName, "ev": "attach", "line": line, "result": result})
	}
	s.mu.Lock()
	p := s.pending[id]
	switch {
	case p == nil:
		s.mu.Unlock()
		verdict("err")
		s.log.Info("attach_reject", "reason", codeUnknownStream)
		writeLineThenClose(tc, errLine(codeUnknownStream))
		return false
	case subtle.ConstantTimeCompare([]byte(p.secret), []byte(secret)) != 1:
		s.mu.Unlock()
		verdict("err")
		s.log.Info("attach_reject", "reason", codeAuth, "stream", id)
		writeLineThenClose(tc, errLine(codeAuth))
		return false
	}
	delete(s.pending, id) // single use
	_ = tc.SetDeadline(time.Time{})
	verdict("ok")
	p.ch <- &bufConn{Conn: tc, r: br} // buffered(1): never blocks; the stream goroutine owns tc from here
	s.mu.Unlock()
	release(false)
	return true
}

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"time"
)

// Config is everything the node needs. DefaultConfig gives the production values, every one of them read from policy.json; tests override the
// timeouts and addresses.
type Config struct {
	HTTPSAddr   string // :443 the one public listener: own-name SNI is the control handler (ALPN all-tunnel/2), any other SNI is spliced. "" disables.
	HTTPAddr    string // :80 only the node's own ACME webroot. "" disables.
	NodeID      string // the node's id in the control plane (authorize carries it; OK says it)
	NodeHost    string // the node's own name: the SNI that reaches the control handler, and the host of the proof's URL
	PublicPort  int    // the port devices dial, only for the proof's URL (443)
	ACMEWebroot string // directory whose .well-known/acme-challenge the node's own certificate client writes; "" serves nothing on :80

	// CertSource gives the node's public-CA certificate for its own name (hot reload is the certificate piece's business, the node asks at every
	// handshake).
	CertSource func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	// Keys are the control plane's public keys: sessions are verified offline against them.
	Keys KeySource
	// Control is the node's side of POST /v1/tunnel/authorize.
	Control ControlPlane
	// Feed is the node's side of GET /v1/tunnel/feed: what the node must stop serving (a revoke, a pause, a released label, the kill switch). Nil runs
	// the node without a feed (the test node's fake control plane has none).
	Feed FeedSource
	// Health is the node's record of whether its control plane answers (the paid grace asks it); the JWKS cache and the feed loop write to the same
	// one. Nil gets a fresh one.
	Health *cpHealth
	// Background are tasks that live as long as the node: the JWKS refresh, the certificate watcher. They start with the listeners and end when the
	// node shuts down.
	Background []func(ctx context.Context)

	MaxStreams        int   // concurrent client connections, global
	MaxStreamsPerHost int   // concurrent client connections per device host
	MaxUnauth         int   // concurrent connections that have not yet finished their first message (a ClientHello or a first line)
	MaxStreamBytes    int64 // bytes (both directions summed) per stream
	ACMEMaxBytes      int64 // bytes of a webroot challenge file served on :80

	HelloTimeout     time.Duration // a client must deliver a full ClientHello within this
	AttachTimeout    time.Duration // a device must ATTACH within this after OPEN
	FirstLineTimeout time.Duration // TLS handshake + first protocol line; also the time a device has to answer CHALLENGE with PROOF
	DeadPeer         time.Duration // a control connection that says nothing for this long is dropped
	MinRenewGap      time.Duration // a RENEW sooner than this after the previous one is busy: a device cannot turn one connection into a stream of authorize calls
	WriteTimeout     time.Duration // one control-line write
	StreamIdle       time.Duration // no bytes in a direction for this long closes the stream
	StreamMaxAge     time.Duration // hard cap on one stream's lifetime
	HalfCloseTimeout time.Duration // after one direction ends cleanly, the other has this long
	ACMETimeout      time.Duration // a whole request on :80
	AuthorizeMax     int           // calls to authorize in flight at once, whoever asks
	AuthorizeTimeout time.Duration // the control plane's time to answer authorize; beyond it the device gets control_unavailable
	ShutdownGrace    time.Duration
	FeedPoll         time.Duration // the longest the node waits between two looks at the feed, and the longest a poll asks the control plane to hold an answer
	FeedStartWait    time.Duration // how long Start waits for the feed's first answer before it accepts connections (the node starts without it when it is late)
	Grace            time.Duration // how long a paid connection outlives its valid_until while the control plane does not answer
	DownQuiet        time.Duration // how long nothing may have answered for the control plane to count as down
	DrainQuiet       time.Duration // how long a draining node keeps its open streams before it cuts them

	// Hardening (limits.go, hints.go, gated.go, openai_prefixes.go, metrics.go). Every number comes from policy.json (node_limits, gated).
	PerIPConcurrent     int           // connections one source holds at once: pre-hello, and the client streams it has open (an IPv6 source is its /64)
	PerIPNewPerS        int           // new connections per second one source may open (a burst of this many, then this many per second)
	IPv6PrefixBits      int           // the length of the IPv6 prefix that counts as one source
	IPTableMax          int           // sources remembered at once; beyond it new ones share one overflow entry
	OpenAIPerIPFactor   int           // the per-source limits of an address in the OpenAI prefix list are this many times larger (one egress address serves many users)
	DevicePerIPFactor   int           // the same for an address that holds an authenticated control connection: a device opens one connection per stream it serves
	UnknownSNIPerIP     int           // distinct names that are not a device online (or malformed ClientHellos) one source may try within UnknownSNIWindow
	UnknownSNIWindow    time.Duration //
	UnknownSNIBan       time.Duration // how long a source that went over the budget is dropped at accept (memory only)
	LabelAnonSlice      int           // of MaxStreamsPerHost, what a source that is not marked good may hold; the rest is the slice of sources the device marked with HINT
	LabelNewPerS        int           // new client streams per second one device host accepts from sources that are not marked good
	LabelNewBurst       int           //
	OpenAIReservedPct   int           // of MaxStreams, the share only sources of the openai or hint class may use
	HintTTL             time.Duration // how long a HINT keeps an address good
	HintsPerLabel       int           // addresses remembered per device host
	GatedBytesPerDay    int64         // a gated device's byte budget per UTC day (both directions, all its streams)
	GatedStreamsPerDay  int           // and its stream budget
	TCPKeepalive        time.Duration // keepalive period of every socket the node holds
	MetricsAddr         string        // loopback address of /metrics and /healthz; "" disables
	OpenAIPrefixesURL   string        // where the connector prefixes are published; "" disables the refresh
	OpenAIPrefixesCache string        // file with the last good list (public data), read at start and written at every good refresh; "" keeps it in memory only
	OpenAIPrefixRefresh time.Duration
	// PrefixFetch replaces the HTTPS GET of OpenAIPrefixesURL (tests, and a deployment that mirrors the list).
	PrefixFetch func(ctx context.Context) ([]byte, error)
	// CertNotAfter reports the end of the node's own certificate, for the metrics (nil: not reported).
	CertNotAfter func() time.Time

	// ClockSkew is how far a device's clock may be ahead of the node's: a session or proof issued up to this far in the future still verifies. The
	// device compensates its clock with the control plane's server_time, this is the window left over.
	ClockSkew time.Duration

	Logger *slog.Logger

	// Now is the node's clock (time.Now when nil), AfterFunc its timers (time.AfterFunc when nil). Every lifetime the node decides (valid_until, the
	// grace, the feed's pace, a drain's quiet period, the JWKS cache) runs on them, so a test drives hours in an instant.
	Now       func() time.Time
	AfterFunc func(d time.Duration, f func()) (stop func() bool)
	// Classify overrides the class of a client's source address for the OPEN: openai, hint or anon. Nil is the node's own: openai for an address of
	// the OpenAI prefix list, hint for one the device marked with HINT, anon for the rest.
	Classify func(peer netip.Addr, host string) string
	// OnHint is told of the source addresses a device marked as good with HINT, besides the node's own hint table (nil: only the table).
	OnHint func(host string, addrs []netip.Addr)

	// tap, when non-nil, is called with every payload buffer the node forwards (never set in production). Tests use it to prove what the node
	// can and cannot see.
	tap func(streamID, direction string, p []byte)
	// divert, when non-nil, may take a client connection before the node opens a stream for it (never set in production: only the test-only mutation of
	// blindmutant_test_hook.go sets it, to be a node that does what the blindness gate must catch). It reports whether it handled the connection.
	divert func(c net.Conn, peeked []byte, log *slog.Logger) bool
	// peerOf, when non-nil, tells the source address of an accepted connection instead of its remote address (never set in production: a test gives
	// loopback connections the addresses of many sources).
	peerOf func(c net.Conn) (netip.Addr, bool)
	// trace, when non-nil, receives one event per protocol step in the format of the contracts' transcript checker (never set in production).
	trace func(event map[string]any)
}

// DefaultConfig returns the production defaults: every window and limit comes from policy.json.
func DefaultConfig() Config {
	p := policyData
	return Config{
		HTTPSAddr:           ":443",
		HTTPAddr:            ":80",
		PublicPort:          443,
		MaxStreams:          p.NodeLimits.GlobalStreamsMax,
		MaxStreamsPerHost:   p.NodeLimits.LabelStreamsMax,
		MaxUnauth:           p.NodeLimits.MaxUnauthenticatedControl,
		MaxStreamBytes:      512 << 20,
		ACMEMaxBytes:        8 << 10,
		HelloTimeout:        secs(p.NodeLimits.ClientHelloDeadlineS),
		AttachTimeout:       secs(p.Protocol.AttachTimeoutS),
		FirstLineTimeout:    secs(p.Protocol.FirstLineTimeoutS),
		DeadPeer:            secs(p.Timing.DeadPeerS),
		MinRenewGap:         secs(p.Timing.BackoffMinS),
		WriteTimeout:        5 * time.Second,
		StreamIdle:          secs(p.Timing.StreamIdleS),
		StreamMaxAge:        secs(p.Timing.StreamMaxAgeS),
		HalfCloseTimeout:    secs(p.Timing.HalfCloseS),
		ACMETimeout:         15 * time.Second,
		AuthorizeMax:        p.Authorization.AuthorizeMaxConcur,
		AuthorizeTimeout:    10 * time.Second,
		ShutdownGrace:       10 * time.Second,
		FeedPoll:            secs(p.Timing.FeedPollS),
		FeedStartWait:       3 * time.Second,
		Grace:               secs(p.Authorization.GracePaidS),
		DownQuiet:           2 * secs(p.Timing.FeedPollS),
		DrainQuiet:          secs(p.Timing.DrainQuietS),
		ClockSkew:           secs(p.Authorization.NodeSkewS),
		PerIPConcurrent:     p.NodeLimits.PerIPConcurrent,
		PerIPNewPerS:        p.NodeLimits.PerIPNewPerS,
		IPv6PrefixBits:      p.NodeLimits.IPv6PrefixBits,
		IPTableMax:          p.NodeLimits.IPTableMax,
		OpenAIPerIPFactor:   p.NodeLimits.OpenAIPerIPFactor,
		DevicePerIPFactor:   p.NodeLimits.DevicePerIPFactor,
		UnknownSNIPerIP:     p.NodeLimits.UnknownSNIPerIP,
		UnknownSNIWindow:    secs(p.NodeLimits.UnknownSNIWindowS),
		UnknownSNIBan:       secs(p.NodeLimits.UnknownSNIBanS),
		LabelAnonSlice:      p.NodeLimits.LabelAnonSlice,
		LabelNewPerS:        p.NodeLimits.LabelNewPerS,
		LabelNewBurst:       p.NodeLimits.LabelNewBurst,
		OpenAIReservedPct:   p.NodeLimits.OpenAIReservedPct,
		HintTTL:             secs(p.NodeLimits.HintTTLS),
		HintsPerLabel:       p.NodeLimits.HintAddressesPerLabel,
		GatedBytesPerDay:    p.Gated.BytesPerDay,
		GatedStreamsPerDay:  p.Gated.StreamsPerDay,
		TCPKeepalive:        secs(p.NodeLimits.TCPKeepaliveS),
		OpenAIPrefixRefresh: secs(p.NodeLimits.OpenAIPrefixRefreshS),
		Logger:              slog.New(slog.NewJSONHandler(io.Discard, nil)),
	}
}

// validate refuses a configuration the node cannot run safely. It does not touch the network.
func (c *Config) validate() error {
	if !reNodeID.MatchString(c.NodeID) {
		return fmt.Errorf("node id %q: want 1-16 characters of [a-z0-9]", c.NodeID)
	}
	if c.HTTPSAddr != "" {
		host, ok := normalizeName(c.NodeHost)
		if !ok || host != c.NodeHost {
			return fmt.Errorf("node host %q is not a normalized DNS name", c.NodeHost)
		}
		if validFQDN(host) {
			return fmt.Errorf("node host %q looks like a device host", host)
		}
		if c.CertSource == nil {
			return fmt.Errorf("no certificate source for the node's own name")
		}
	}
	if c.Keys == nil || c.Control == nil {
		return fmt.Errorf("the node needs a key source and a control plane")
	}
	if c.PublicPort < 1 || c.PublicPort > 65535 {
		return fmt.Errorf("public port %d", c.PublicPort)
	}
	if c.ClockSkew < 0 || c.ClockSkew > secs(policyData.Authorization.NodeSkewMaxS) {
		return fmt.Errorf("clock skew %s is beyond the policy's %s", c.ClockSkew, secs(policyData.Authorization.NodeSkewMaxS))
	}
	if c.Feed != nil && (c.FeedPoll < time.Millisecond || c.FeedPoll > secs(policyData.Timing.FeedPollS)) {
		return fmt.Errorf("feed poll %s is beyond the policy's %s", c.FeedPoll, secs(policyData.Timing.FeedPollS))
	}
	if c.DrainQuiet < 0 || c.DrainQuiet > 24*time.Hour {
		return fmt.Errorf("drain quiet period %s: want 0 to 24h", c.DrainQuiet)
	}
	if c.Grace < 0 || c.Grace > secs(policyData.Authorization.GracePaidS) {
		return fmt.Errorf("grace %s is beyond the policy's %s", c.Grace, secs(policyData.Authorization.GracePaidS))
	}
	if c.AuthorizeMax < 1 {
		return fmt.Errorf("authorize concurrency must be at least 1")
	}
	if c.MaxStreams < 1 || c.MaxStreamsPerHost < 1 || c.MaxUnauth < 1 {
		return fmt.Errorf("stream limits must be at least 1")
	}
	if c.PerIPConcurrent < 1 || c.PerIPNewPerS < 1 || c.IPTableMax < 1 || c.OpenAIPerIPFactor < 1 || c.DevicePerIPFactor < 1 || c.LabelAnonSlice < 1 || c.LabelNewPerS < 1 || c.LabelNewBurst < 1 {
		return fmt.Errorf("per-source and per-device limits must be at least 1")
	}
	if c.IPv6PrefixBits < 1 || c.IPv6PrefixBits > 128 {
		return fmt.Errorf("ipv6 prefix of %d bits", c.IPv6PrefixBits)
	}
	if c.OpenAIReservedPct < 0 || c.OpenAIReservedPct > 90 {
		return fmt.Errorf("openai reserved share %d%%: want 0 to 90", c.OpenAIReservedPct)
	}
	if c.UnknownSNIPerIP < 1 || c.UnknownSNIWindow <= 0 || c.UnknownSNIBan <= 0 || c.HintTTL <= 0 || c.HintsPerLabel < 1 || c.TCPKeepalive <= 0 {
		return fmt.Errorf("the unknown-name budget, the hint table and the keepalive need positive values")
	}
	if c.GatedBytesPerDay < 1 || c.GatedStreamsPerDay < 1 {
		return fmt.Errorf("a gated device's daily budgets must be at least 1")
	}
	if c.MetricsAddr != "" {
		if err := checkLoopbackAddr(c.MetricsAddr); err != nil {
			return err
		}
	}
	if c.OpenAIPrefixesURL != "" {
		if u, err := url.Parse(c.OpenAIPrefixesURL); err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHost(u.Hostname()))) {
			return fmt.Errorf("prefix list URL %q: want https://<host>/<path> (plain http only for a loopback mirror)", c.OpenAIPrefixesURL)
		}
	}
	return nil
}

// checkLoopbackAddr refuses a metrics address that is not loopback: the counters are for the machine's own operator, never for the network.
func checkLoopbackAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("metrics address %q: %w", addr, err)
	}
	if !isLoopbackHost(host) {
		return fmt.Errorf("metrics address %q is not a loopback address: /metrics and /healthz are for this machine only", addr)
	}
	return nil
}

// isLoopbackHost reports whether host is a loopback IP literal.
func isLoopbackHost(host string) bool {
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

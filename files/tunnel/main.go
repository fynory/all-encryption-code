package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

// version is overridden at build time: -ldflags "-X main.version=..."
var version = "dev"

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func envStr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envInt(key string, def int64) int64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

func envDur(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

// backend is what the node asks of the outside world: the control plane's keys, the authorize call and the feed. The production build registers the real
// ones (backend_prod.go: the HTTP client with the node's assertion, the JWKS cache); the test-node build (`-tags testnode`) registers file-driven fakes. A
// build with neither refuses to start rather than run without verifying anyone.
type backend struct {
	// flags registers the backend's own flags and returns what completes cfg once the flags are parsed.
	flags func(fs *flag.FlagSet, stdout io.Writer) func(cfg *Config) error
}

var theBackend *backend

// Where the production build looks by default: its /metrics and /healthz (loopback), and the list of OpenAI connector prefixes. The test node leaves both
// empty (many test nodes run side by side and none may call the network).
var (
	defaultMetricsAddr       string
	defaultOpenAIPrefixesURL string
)

var errNoBackend = errors.New("this build has no control-plane client: use the production build, or the test-node build (-tags testnode) with its fakes")

// errDone is what a backend's complete returns when it did what the command line asked (printing a key) and the node must not start.
var errDone = errors.New("done")

func run(args []string, stdout, stderr io.Writer) int {
	cfg := DefaultConfig()
	fs := flag.NewFlagSet("all-tunnel", flag.ContinueOnError)
	fs.SetOutput(stderr)

	fs.StringVar(&cfg.HTTPSAddr, "https-addr", envStr("TUNNEL_HTTPS_ADDR", cfg.HTTPSAddr), "the public listener: devices' control and data connections and clients' TLS, told apart by SNI [TUNNEL_HTTPS_ADDR]")
	fs.StringVar(&cfg.HTTPAddr, "http-addr", envStr("TUNNEL_HTTP_ADDR", cfg.HTTPAddr), "listener that serves only the node's own ACME webroot, '' disables [TUNNEL_HTTP_ADDR]")
	fs.StringVar(&cfg.NodeID, "node-id", envStr("TUNNEL_NODE_ID", ""), "this node's id in the control plane, 1-16 characters of [a-z0-9] [TUNNEL_NODE_ID]")
	fs.StringVar(&cfg.NodeHost, "node-host", envStr("TUNNEL_NODE_HOST", ""), "this node's own public name: the SNI that reaches the control handler [TUNNEL_NODE_HOST]")
	fs.IntVar(&cfg.PublicPort, "public-port", int(envInt("TUNNEL_PUBLIC_PORT", int64(cfg.PublicPort))), "the port devices dial, only for the proof's URL [TUNNEL_PUBLIC_PORT]")
	fs.StringVar(&cfg.ACMEWebroot, "acme-webroot", envStr("TUNNEL_ACME_WEBROOT", ""), "directory with .well-known/acme-challenge for the node's own certificate [TUNNEL_ACME_WEBROOT]")
	certFile := fs.String("cert-file", envStr("TUNNEL_CERT_FILE", ""), "the node's public-CA certificate chain (PEM), re-read when it changes [TUNNEL_CERT_FILE]")
	keyFile := fs.String("key-file", envStr("TUNNEL_KEY_FILE", ""), "the node certificate's private key (PEM) [TUNNEL_KEY_FILE]")
	skewS := fs.Int64("clock-skew", envInt("TUNNEL_CLOCK_SKEW_S", int64(cfg.ClockSkew/time.Second)), "seconds a device's clock may be ahead of this node's (at most the policy's maximum) [TUNNEL_CLOCK_SKEW_S]")
	fs.DurationVar(&cfg.FeedPoll, "feed-poll", envDur("TUNNEL_FEED_POLL", cfg.FeedPoll), "how often the node looks at the control plane's feed (at most the policy's) [TUNNEL_FEED_POLL]")
	fs.DurationVar(&cfg.Grace, "grace", envDur("TUNNEL_GRACE", cfg.Grace), "how long a paid connection outlives its valid_until while the control plane does not answer (at most the policy's) [TUNNEL_GRACE]")
	fs.DurationVar(&cfg.DrainQuiet, "drain-quiet", envDur("TUNNEL_DRAIN_QUIET", cfg.DrainQuiet), "on SIGTERM keep the open streams this long at most, then cut them and exit; the unit's TimeoutStopSec must be longer [TUNNEL_DRAIN_QUIET]")

	fs.StringVar(&cfg.MetricsAddr, "metrics-addr", envStr("TUNNEL_METRICS_ADDR", defaultMetricsAddr), "loopback address of /metrics and /healthz (aggregate counters only), '' disables [TUNNEL_METRICS_ADDR]")
	fs.StringVar(&cfg.OpenAIPrefixesURL, "openai-prefixes-url", envStr("TUNNEL_OPENAI_PREFIXES_URL", defaultOpenAIPrefixesURL), "where OpenAI publishes its connector prefixes (the node's openai quota class), '' disables the refresh [TUNNEL_OPENAI_PREFIXES_URL]")
	fs.StringVar(&cfg.OpenAIPrefixesCache, "openai-prefixes-cache", envStr("TUNNEL_OPENAI_PREFIXES_CACHE", ""), "file that keeps the last good prefix list across restarts (public data) [TUNNEL_OPENAI_PREFIXES_CACHE]")
	fs.IntVar(&cfg.MaxStreams, "max-streams", int(envInt("TUNNEL_MAX_STREAMS", int64(cfg.MaxStreams))), "max concurrent client connections [TUNNEL_MAX_STREAMS]")
	fs.IntVar(&cfg.MaxStreamsPerHost, "max-streams-per-host", int(envInt("TUNNEL_MAX_STREAMS_PER_HOST", int64(cfg.MaxStreamsPerHost))), "max concurrent client connections per device [TUNNEL_MAX_STREAMS_PER_HOST]")
	fs.Int64Var(&cfg.MaxStreamBytes, "max-stream-bytes", envInt("TUNNEL_MAX_STREAM_BYTES", cfg.MaxStreamBytes), "max bytes (both directions) per stream [TUNNEL_MAX_STREAM_BYTES]")
	fs.DurationVar(&cfg.StreamIdle, "stream-idle", envDur("TUNNEL_STREAM_IDLE", cfg.StreamIdle), "close a stream after this long without bytes [TUNNEL_STREAM_IDLE]")
	fs.DurationVar(&cfg.StreamMaxAge, "stream-max-age", envDur("TUNNEL_STREAM_MAX_AGE", cfg.StreamMaxAge), "hard cap on one stream's lifetime [TUNNEL_STREAM_MAX_AGE]")
	fs.DurationVar(&cfg.HelloTimeout, "hello-timeout", envDur("TUNNEL_HELLO_TIMEOUT", cfg.HelloTimeout), "client must send its ClientHello within this [TUNNEL_HELLO_TIMEOUT]")
	fs.DurationVar(&cfg.AttachTimeout, "attach-timeout", envDur("TUNNEL_ATTACH_TIMEOUT", cfg.AttachTimeout), "device must ATTACH within this after OPEN [TUNNEL_ATTACH_TIMEOUT]")
	fs.DurationVar(&cfg.DeadPeer, "dead-peer", envDur("TUNNEL_DEAD_PEER", cfg.DeadPeer), "drop a control connection silent for this long [TUNNEL_DEAD_PEER]")

	logFormat := fs.String("log-format", envStr("TUNNEL_LOG_FORMAT", "json"), "json or text [TUNNEL_LOG_FORMAT]")
	logLevel := fs.String("log-level", envStr("TUNNEL_LOG_LEVEL", "info"), "debug, info, warn or error [TUNNEL_LOG_LEVEL]")
	showVersion := fs.Bool("version", false, "print the version and exit")

	var complete func(*Config) error
	if theBackend != nil {
		complete = theBackend.flags(fs, stdout)
	}

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, "all-tunnel", version)
		return 0
	}

	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(*logLevel)); err != nil {
		fmt.Fprintln(stderr, "error: bad -log-level")
		return 2
	}
	hopts := &slog.HandlerOptions{Level: lvl}
	if *logFormat == "text" {
		cfg.Logger = slog.New(slog.NewTextHandler(stderr, hopts))
	} else {
		cfg.Logger = slog.New(slog.NewJSONHandler(stderr, hopts))
	}
	cfg.ClockSkew = time.Duration(*skewS) * time.Second

	if complete == nil {
		fmt.Fprintln(stderr, "error:", errNoBackend)
		return 1
	}
	var reloader *certReloader
	if *certFile != "" || *keyFile != "" {
		var err error
		if reloader, err = newCertReloader(*certFile, *keyFile, cfg.NodeHost, newClock(nil, nil), cfg.Logger); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		cfg.CertSource = reloader.get
		cfg.CertNotAfter = reloader.NotAfter
		cfg.Background = append(cfg.Background, reloader.Run)
	}
	if err := complete(&cfg); err != nil {
		if errors.Is(err, errDone) {
			return 0
		}
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}

	srv, err := NewServer(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	if err := srv.Start(); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	cfg.Logger.Info("started", "version", version, "node", cfg.NodeID)
	announce(stdout, srv)

	return serveUntilSignalled(srv, cfg, reloader)
}

// serveUntilSignalled is the node's life after it started. SIGTERM drains (the open streams finish, up to the quiet period, then it exits; a second
// SIGTERM stops waiting), SIGINT stops at once (a developer's Ctrl-C), SIGHUP reads the node's certificate again.
func serveUntilSignalled(srv *Server, cfg Config, reloader *certReloader) int {
	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)
	drained := make(chan struct{})
	draining := false
	for {
		select {
		case <-drained:
			return 0
		case sig := <-sigs:
			switch sig {
			case syscall.SIGHUP:
				if reloader == nil {
					continue
				}
				if err := reloader.Reload(); err != nil {
					cfg.Logger.Warn("node_cert_reload_refused", "reason", err.Error())
				} else {
					cfg.Logger.Info("node_cert_reloaded", "not_after", reloader.NotAfter().UTC().Format(time.RFC3339))
				}
			case syscall.SIGTERM:
				if !draining {
					draining = true
					go func() {
						srv.Drain(cfg.DrainQuiet)
						close(drained)
					}()
					continue
				}
				cfg.Logger.Warn("drain_cut_short")
				go srv.Shutdown(0)
			default:
				cfg.Logger.Info("shutting_down", "grace", cfg.ShutdownGrace.String())
				srv.Shutdown(cfg.ShutdownGrace)
				return 0
			}
		}
	}
}

// announce is called once the node listens; the test-node build uses it to tell a harness the ports it got. The production build says nothing.
var announce = func(io.Writer, *Server) {}

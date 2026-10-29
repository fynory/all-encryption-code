package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// The node's own public-CA certificate (the one devices verify on the node's own name, ALPN all-tunnel/2) is renewed by the node's own ACME client
// (certbot, HTTP-01 through the webroot on :80) and replaced on disk. certReloader puts the new one in service without a restart and without a dropped
// handshake: it reads the files at start and again whenever they change, at a handshake or on its own timer, and a renewal that is not good (half
// written, a key that does not match, another name, already expired) never replaces the certificate that works.

// fileSig is what the node looks at to know a file changed: its modification time and size (certbot's live files are symlinks into an archive, and Stat
// follows them, so a renewal that moves the link is a different file).
type fileSig struct{ mod, size int64 }

func sigOf(path string) (fileSig, error) {
	st, err := os.Stat(path)
	if err != nil {
		return fileSig{}, err
	}
	return fileSig{st.ModTime().UnixNano(), st.Size()}, nil
}

const (
	certLookGap    = time.Second      // a handshake looks at the files at most this often (certReloader.lookGap)
	certRetryGap   = 30 * time.Second // a renewal that did not load is tried again after this even if its files did not change again
	certWatchEvery = time.Minute      // the node looks at the files by itself this often
	certWarnDays   = 5                // days before the end at which the log says it loudly
)

type certReloader struct {
	certPath, keyPath string
	host              string // the node's own name the certificate must be valid for; "" skips the name check (tests)
	clk               clock
	log               *slog.Logger
	lookGap           time.Duration

	mu        sync.Mutex
	pair      *tls.Certificate
	notAfter  time.Time
	certSig   fileSig // what the certificate in service was read from
	keySig    fileSig
	lookedAt  time.Time
	failedAt  time.Time
	failedCrt fileSig // what the last refused renewal was read from
	failedKey fileSig
	lastErr   string
	loads     int
}

func newCertReloader(certPath, keyPath, host string, clk clock, log *slog.Logger) (*certReloader, error) {
	if clk.now == nil {
		clk = newClock(nil, nil)
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	r := &certReloader{certPath: certPath, keyPath: keyPath, host: host, clk: clk, log: log, lookGap: certLookGap}
	if err := r.load(); err != nil {
		return nil, fmt.Errorf("node certificate: %w", err)
	}
	return r, nil
}

// load reads the pair, checks it and puts it in service. The caller holds no lock.
func (r *certReloader) load() error {
	cs, cerr := sigOf(r.certPath)
	ks, kerr := sigOf(r.keyPath)
	if err := errors.Join(cerr, kerr); err != nil {
		return err
	}
	pair, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	now := r.clk.Now()
	if r.host != "" {
		if err := leaf.VerifyHostname(r.host); err != nil {
			return fmt.Errorf("the certificate is not for %s", r.host)
		}
	}
	if !now.Before(leaf.NotAfter) {
		return fmt.Errorf("the certificate expired at %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if now.Add(time.Hour).Before(leaf.NotBefore) {
		return fmt.Errorf("the certificate is not valid before %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	pair.Leaf = leaf
	r.mu.Lock()
	r.pair, r.notAfter, r.certSig, r.keySig = &pair, leaf.NotAfter, cs, ks
	r.lastErr, r.failedAt, r.failedCrt, r.failedKey = "", time.Time{}, fileSig{}, fileSig{}
	r.loads++
	r.mu.Unlock()
	return nil
}

// refresh looks at the files (at most every certLookGap unless force) and loads them when they are not the ones in service. A refused renewal is
// remembered by its files, so it is parsed again only when they change or certRetryGap passed.
func (r *certReloader) refresh(force bool) {
	now := r.clk.Now()
	r.mu.Lock()
	if !force && now.Sub(r.lookedAt) < r.lookGap {
		r.mu.Unlock()
		return
	}
	r.lookedAt = now
	cur, curKey, failedCrt, failedKey, failedAt := r.certSig, r.keySig, r.failedCrt, r.failedKey, r.failedAt
	r.mu.Unlock()

	cs, cerr := sigOf(r.certPath)
	ks, kerr := sigOf(r.keyPath)
	if cerr != nil || kerr != nil {
		return // a renewal in the middle of replacing its files: the certificate in service stays
	}
	if cs == cur && ks == curKey {
		return
	}
	if !force && cs == failedCrt && ks == failedKey && !failedAt.IsZero() && now.Sub(failedAt) < certRetryGap {
		return
	}
	if err := r.load(); err != nil {
		r.mu.Lock()
		r.failedCrt, r.failedKey, r.failedAt, r.lastErr = cs, ks, now, err.Error()
		r.mu.Unlock()
		r.log.Warn("node_cert_reload_refused", "reason", err.Error())
		return
	}
	r.log.Info("node_cert_reloaded", "not_after", r.NotAfter().UTC().Format(time.RFC3339))
}

// Reload loads the files now, whatever they look like (SIGHUP): it returns why a renewal was refused.
func (r *certReloader) Reload() error {
	if err := r.load(); err != nil {
		r.mu.Lock()
		r.lastErr = err.Error()
		r.mu.Unlock()
		return err
	}
	return nil
}

// get is the Config.CertSource: the certificate in service, after a look at the files.
func (r *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.refresh(false)
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pair, nil
}

// NotAfter is the end of the certificate in service (the monitor alerts under 14 days and under 5).
func (r *certReloader) NotAfter() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.notAfter
}

// LastError is why the last renewal was refused ("" when the certificate in service is the newest on disk).
func (r *certReloader) LastError() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastErr
}

// Run looks at the files on its own timer, so a renewal is in service even when no device is connecting, and says in the log how long the certificate
// has left (the provider's expiry e-mails no longer exist, the node's own log and the site's monitor are what warn).
func (r *certReloader) Run(ctx context.Context) {
	for {
		r.refresh(true)
		left := r.NotAfter().Sub(r.clk.Now())
		switch {
		case left <= 0:
			r.log.Error("node_cert_expired")
		case left < certWarnDays*24*time.Hour:
			r.log.Warn("node_cert_expires_soon", "days_left", int(left/(24*time.Hour)))
		}
		if !r.clk.sleep(ctx, certWatchEvery) {
			return
		}
	}
}

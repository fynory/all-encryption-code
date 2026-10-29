package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"log/slog"
	"regexp"
	"sync"
	"time"
)

// The control plane's published keys are the root of trust for the sessions a node verifies offline. The node reads them through KeySource: "is this
// kid a key of the control plane, and which one". What fetches, caches and refreshes them is JWKSCache below (issuer pinned, 300 s cache, reload on an
// unknown kid, at most 16 keys, fail closed after 30 minutes without a refresh).

// KeySource gives the public Ed25519 key of a control-plane kid. A source that cannot vouch for its keys any more (stale beyond the policy's window)
// answers false for every kid: the node then refuses every session, it never trusts an old set.
type KeySource interface {
	Key(kid string) (ed25519.PublicKey, bool)
}

// keyHealth is what a KeySource may add: whether it can vouch for its keys right now. When it cannot, a session whose kid it does not know is refused
// as control_unavailable (try again later) and not as auth (your credentials are wrong).
type keyHealth interface {
	Healthy() bool
}

// StaticKeys is a fixed key set: what the tests and the test-node binary use, and what a real source returns once it has a fresh set.
type StaticKeys map[string]ed25519.PublicKey

func (k StaticKeys) Key(kid string) (ed25519.PublicKey, bool) {
	key, ok := k[kid]
	return key, ok
}

// SwapKeys is a key set that can be replaced while the node runs (a rotation, or a refresh that returned a new set). It is safe for concurrent use.
type SwapKeys struct {
	mu   sync.RWMutex
	keys StaticKeys
}

func NewSwapKeys(keys StaticKeys) *SwapKeys { return &SwapKeys{keys: keys} }

// Set replaces the whole set; a nil or empty set refuses everything.
func (s *SwapKeys) Set(keys StaticKeys) {
	s.mu.Lock()
	s.keys = keys
	s.mu.Unlock()
}

func (s *SwapKeys) Key(kid string) (ed25519.PublicKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.keys.Key(kid)
}

var errBadJWKS = errors.New("bad_jwks")

var reB64Charset = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// b64Decode is the strict base64url of the contracts: no padding and the canonical encoding (a text that decodes to bytes that encode differently
// is refused, so one token has one text).
func b64Decode(text string) ([]byte, error) {
	if !reB64Charset.MatchString(text) {
		return nil, errors.New("base64url")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(text)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != text {
		return nil, errors.New("base64url")
	}
	return raw, nil
}

func b64Encode(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

// publicKeyX decodes the x of an Ed25519 JWK: 43 canonical base64url characters that are 32 bytes.
func publicKeyX(x string) (ed25519.PublicKey, bool) {
	if len(x) != 43 {
		return nil, false
	}
	raw, err := b64Decode(x)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, false
	}
	return ed25519.PublicKey(raw), true
}

// ParseJWKS reads the control plane's GET /.well-known/device-jwks.json (jwks.schema.json): one to max_keys Ed25519 keys, each with its kid, alg
// EdDSA, use sig and key_ops [verify], no private part, no repeated kid. A set the schema refuses is bad_jwks and nothing of it is used.
func ParseJWKS(doc []byte) (StaticKeys, error) {
	value, err := parseJSON(string(doc))
	if err != nil {
		return nil, errBadJWKS
	}
	top, ok := value.(map[string]any)
	if !ok || len(top) != 1 {
		return nil, errBadJWKS
	}
	list, ok := top["keys"].([]any)
	if !ok || len(list) < 1 || len(list) > policyData.JWKS.MaxKeys {
		return nil, errBadJWKS
	}
	keys := StaticKeys{}
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok || len(m) != 7 {
			return nil, errBadJWKS
		}
		kid, _ := m["kid"].(string)
		x, _ := m["x"].(string)
		ops, _ := m["key_ops"].([]any)
		if m["kty"] != "OKP" || m["crv"] != "Ed25519" || m["alg"] != "EdDSA" || m["use"] != "sig" || !reKID.MatchString(kid) ||
			len(ops) != 1 || ops[0] != "verify" {
			return nil, errBadJWKS
		}
		key, ok := publicKeyX(x)
		if !ok {
			return nil, errBadJWKS
		}
		if _, dup := keys[kid]; dup {
			return nil, errBadJWKS
		}
		keys[kid] = key
	}
	return keys, nil
}

// ---------------------------------------------------------------------------------------------------------------------------- the cache

// JWKSConfig configures a JWKSCache. Every window defaults to the policy's.
type JWKSConfig struct {
	// Fetch reads the control plane's GET /.well-known/device-jwks.json. The URL is the configured control plane's and nothing else: the issuer is
	// pinned by the caller, an answer cannot name another place to read the keys from.
	Fetch        func(ctx context.Context) ([]byte, error)
	Clock        clock
	TTL          time.Duration // how long a fetched set is used before the next refresh
	StaleAfter   time.Duration // beyond this without a successful refresh the cache vouches for nothing
	MinReload    time.Duration // between two fetches that an unknown kid (or a stale set) asked for: a flood of random kids is one fetch, not thousands
	FetchTimeout time.Duration
	Observe      func(ok bool) // every fetch's outcome (the node's reachability record)
	Log          *slog.Logger
}

// JWKSCache is the node's KeySource for the control plane's keys. It fetches the set at start and every TTL (a failure is retried with the policy's
// backoff and the old set keeps serving), reloads when a session names a kid it does not hold (so a rotation reaches a node at the next RENEW, with at
// most one fetch per MinReload however many sessions ask), keeps at most the policy's number of keys (ParseJWKS refuses a bigger set whole), replaces
// the whole set on every successful fetch (a key the control plane dropped stops being trusted), and FAILS CLOSED: after StaleAfter without a refresh
// it answers false for every kid, an old set is never trusted.
type JWKSCache struct {
	cfg JWKSConfig

	mu          sync.Mutex
	keys        StaticKeys
	fetchedAt   time.Time // the last successful fetch
	attemptedAt time.Time // the last fetch of any outcome that was asked for by a lookup
	flight      chan struct{}
	failures    int
}

func NewJWKSCache(cfg JWKSConfig) *JWKSCache {
	if cfg.TTL <= 0 {
		cfg.TTL = secs(policyData.JWKS.CacheS)
	}
	if cfg.StaleAfter <= 0 {
		cfg.StaleAfter = secs(policyData.JWKS.StaleFailClosedS)
	}
	if cfg.MinReload <= 0 {
		cfg.MinReload = minReload
	}
	if cfg.FetchTimeout <= 0 {
		cfg.FetchTimeout = fetchTimeout
	}
	if cfg.Clock.now == nil {
		cfg.Clock = newClock(nil, nil)
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	return &JWKSCache{cfg: cfg}
}

// fetchTimeout bounds one fetch of the keys (a lookup that triggers one waits at most this long).
const fetchTimeout = 5 * time.Second

// minReload is the default gap between fetches that lookups ask for.
const minReload = 10 * time.Second

func (c *JWKSCache) fresh(now time.Time) bool {
	return !c.fetchedAt.IsZero() && now.Sub(c.fetchedAt) <= c.cfg.StaleAfter
}

// Healthy reports whether the cache can vouch for its keys: it has a set that is not older than StaleAfter.
func (c *JWKSCache) Healthy() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fresh(c.cfg.Clock.Now())
}

// Age is how long ago the last successful fetch was (a negative duration when there has not been one): the monitor's "age of the JWKS".
func (c *JWKSCache) Age() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fetchedAt.IsZero() {
		return -1
	}
	return c.cfg.Clock.Now().Sub(c.fetchedAt)
}

// Key is the KeySource lookup.
func (c *JWKSCache) Key(kid string) (ed25519.PublicKey, bool) {
	now := c.cfg.Clock.Now()
	c.mu.Lock()
	fresh := c.fresh(now)
	key, known := c.keys[kid]
	due := !c.fetchedAt.IsZero() && now.Sub(c.fetchedAt) >= c.cfg.TTL
	askAllowed := c.attemptedAt.IsZero() || now.Sub(c.attemptedAt) >= c.cfg.MinReload
	if due && fresh && known && askAllowed {
		// The attempt is stamped here, with the reading this lookup took, not by the goroutine whenever it gets to run: the gap to the next attempt
		// must not depend on scheduling, and a burst of lookups past the TTL starts one refresh, not one each.
		c.attemptedAt = now
	}
	c.mu.Unlock()

	switch {
	case fresh && known && !due:
		return key, true
	case fresh && known:
		// Past its TTL but still vouched for: serve it and refresh behind the lookup (the periodic loop is the main path; this covers a busy node
		// whose loop is in a backoff).
		if askAllowed {
			go func() { _ = c.reload(context.Background(), false) }()
		}
		return key, true
	case !askAllowed:
		return nil, false
	}
	// An unknown kid, or a set that is no longer vouched for: one fetch (every concurrent lookup waits for the same one), then the answer.
	_ = c.reload(context.Background(), true)
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.fresh(c.cfg.Clock.Now()) {
		return nil, false
	}
	key, known = c.keys[kid]
	return key, known
}

// Refresh fetches the set now (single flight) and replaces the cached one when the answer is a valid set. It returns the fetch's error.
func (c *JWKSCache) Refresh(ctx context.Context) error { return c.reload(ctx, false) }

func (c *JWKSCache) reload(ctx context.Context, fromLookup bool) error {
	c.mu.Lock()
	if wait := c.flight; wait != nil {
		c.mu.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
			return ctx.Err()
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.fresh(c.cfg.Clock.Now()) {
			return nil
		}
		return errors.New("jwks refresh failed")
	}
	wait := make(chan struct{})
	c.flight = wait
	if fromLookup {
		c.attemptedAt = c.cfg.Clock.Now()
	}
	c.mu.Unlock()

	fctx, cancel := context.WithTimeout(ctx, c.cfg.FetchTimeout)
	doc, err := c.cfg.Fetch(fctx)
	cancel()
	var keys StaticKeys
	if err == nil {
		keys, err = ParseJWKS(doc)
	}
	now := c.cfg.Clock.Now()
	c.mu.Lock()
	if err == nil {
		c.keys, c.fetchedAt, c.failures = keys, now, 0
	} else {
		c.failures++
	}
	c.flight = nil
	close(wait)
	c.mu.Unlock()
	if c.cfg.Observe != nil {
		c.cfg.Observe(err == nil)
	}
	if err != nil {
		c.cfg.Log.Warn("jwks_refresh_failed", "reason", errorWord(err))
	}
	return err
}

// errorWord is a short, address-free word for a failure: nothing from the network goes to a log.
func errorWord(err error) string {
	switch {
	case errors.Is(err, errBadJWKS):
		return "bad_jwks"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	}
	var ce *ControlError
	if errors.As(err, &ce) {
		return ce.Code
	}
	return "unreachable"
}

// Run keeps the set fresh until ctx ends: a fetch now, then one every TTL (spread a little, so two nodes do not call together), and after a failure the
// policy's backoff.
func (c *JWKSCache) Run(ctx context.Context) {
	for {
		err := c.Refresh(ctx)
		c.mu.Lock()
		failures := c.failures
		c.mu.Unlock()
		wait := jitter(c.cfg.TTL, 10)
		if err != nil {
			wait = backoff(failures)
		}
		if !c.cfg.Clock.sleep(ctx, wait) {
			return
		}
	}
}

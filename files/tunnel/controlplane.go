package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The real control-plane client (the contract, sections 3.3 and 4): what the node says to POST /v1/tunnel/authorize and GET /v1/tunnel/feed.
//
// The node holds exactly ONE secret: its own Ed25519 signing key. Every request carries an assertion (header x-all-node-assertion), a 60 s JWS bound to
// the method, the URL and the SHA-256 of the exact body bytes, used once. The control plane has the public half (TUNNEL_NODE_KEYS; removing the kid
// revokes the node). There is no shared secret, no commerce key and no bearer token in this program, and the request a device could influence is only
// the device id and the session id inside the authorize body: never a host name.

const (
	authorizePath = "/v1/tunnel/authorize"
	feedPath      = "/v1/tunnel/feed"
	jwksPath      = "/.well-known/device-jwks.json"

	maxControlBody = 256 << 10 // an answer carries at most a 64 KiB statement; anything bigger is not the control plane
	maxJWKSBody    = 64 << 10
)

var reErrorWord = regexp.MustCompile(`^[a-z_]{1,48}$`)

// HTTPControlConfig is what the client needs. Everything but the key has a safe default.
type HTTPControlConfig struct {
	BaseURL string // https://<control plane>, nothing after the host
	NodeID  string
	KID     string // the kid of this node's public key in TUNNEL_NODE_KEYS
	Key     ed25519.PrivateKey
	Client  *http.Client     // nil: a client of its own (TLS, no proxy, no redirect, bounded connections)
	Now     func() time.Time // nil: time.Now
	Version string           // for the User-Agent
}

// HTTPControl is the node's ControlPlane and FeedSource.
type HTTPControl struct {
	base    *url.URL
	hostHTU string // the host as the control plane's runtime writes it in a URL: the port only when it is not 443
	nodeID  string
	kid     string
	key     ed25519.PrivateKey
	client  *http.Client
	now     func() time.Time
	agent   string
}

// NewHTTPControl validates the configuration. It does not touch the network.
func NewHTTPControl(cfg HTTPControlConfig) (*HTTPControl, error) {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("control plane URL %q: want https://<host>[:port] and nothing else", cfg.BaseURL)
	}
	if !reNodeID.MatchString(cfg.NodeID) || !reKID.MatchString(cfg.KID) {
		return nil, fmt.Errorf("control plane client: bad node id or kid")
	}
	if len(cfg.Key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("control plane client: no node signing key")
	}
	c := &HTTPControl{base: u, nodeID: cfg.NodeID, kid: cfg.KID, key: cfg.Key, client: cfg.Client, now: cfg.Now, agent: "all-tunnel/" + cfg.Version}
	c.hostHTU = strings.ToLower(u.Host)
	if u.Port() == "443" {
		c.hostHTU = strings.ToLower(u.Hostname())
	}
	if c.client == nil {
		c.client = newControlClient()
	} else {
		// A client that was handed in is used as it is, except that it never follows a redirect: an assertion must not travel to a host nobody configured.
		own := *c.client
		own.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		c.client = &own
	}
	if c.now == nil {
		c.now = time.Now
	}
	return c, nil
}

// newControlClient is the client of the node to its control plane: TLS from the system roots, no proxy from the environment, no redirect followed (a
// redirect would carry an assertion to a host nobody configured) and a bounded pool (authorize may run authorize_max_concurrent at once, plus the feed).
func newControlClient() *http.Client {
	limit := policyData.Authorization.AuthorizeMaxConcur
	return &http.Client{
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         (&net.Dialer{Timeout: 5 * time.Second, KeepAliveConfig: net.KeepAliveConfig{Enable: true}}).DialContext,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: 5 * time.Second,
			ForceAttemptHTTP2:   true,
			MaxIdleConnsPerHost: limit + 2,
			MaxConnsPerHost:     limit + 2,
			IdleConnTimeout:     90 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// compactJWS signs header and claims (canonical JSON, base64url) with key.
func compactJWS(key ed25519.PrivateKey, header, claims map[string]any) string {
	input := b64Encode([]byte(canonicalJSON(header))) + "." + b64Encode([]byte(canonicalJSON(claims)))
	return input + "." + b64Encode(ed25519.Sign(key, []byte(input)))
}

// assertion is the node's proof for ONE request: the method, the exact URL and the hash of the exact body bytes, 60 s, with a jti nobody reuses.
func (c *HTTPControl) assertion(method, requestURL string, body []byte) string {
	iat := c.now().Unix()
	return compactJWS(c.key,
		map[string]any{"alg": "EdDSA", "typ": "node-assertion", "kid": c.kid},
		map[string]any{"typ": "node-assertion", "ver": 1, "sub": c.nodeID, "aud": policyData.Identity.AudNodeAssert, "htm": method, "htu": requestURL,
			"iat": iat, "exp": iat + int64(policyData.Authorization.NodeAssertionTTLS), "jti": newNonce(), "bh": sha256B64(body)})
}

// do sends one signed request and returns the status and the body (at most maxControlBody). A transport failure is a plain error; any answer, including
// an error answer, is a status.
func (c *HTTPControl) do(ctx context.Context, method, pathAndQuery string, body []byte) (int, []byte, error) {
	requestURL := "https://" + c.hostHTU + pathAndQuery
	req, err := http.NewRequestWithContext(ctx, method, c.base.Scheme+"://"+c.base.Host+pathAndQuery, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("x-all-node-assertion", c.assertion(method, requestURL, body))
	req.Header.Set("accept", "application/json")
	req.Header.Set("user-agent", c.agent)
	if method == http.MethodPost {
		req.Header.Set("content-type", "application/json")
	}
	return c.send(req, maxControlBody)
}

func (c *HTTPControl) send(req *http.Request, limit int64) (int, []byte, error) {
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return 0, nil, err
	}
	if int64(len(data)) > limit {
		return resp.StatusCode, nil, errors.New("control plane answer too large")
	}
	return resp.StatusCode, data, nil
}

// controlError turns a non-200 answer into a ControlError: the closed word of the error body when it is one (never any other text from the network),
// bad_response when it is not.
func controlError(status int, data []byte) *ControlError {
	word := "bad_response"
	if value, err := parseJSON(string(data)); err == nil {
		if m, ok := value.(map[string]any); ok && m["ok"] == false {
			if s, ok := m["error"].(string); ok && reErrorWord.MatchString(s) {
				word = s
			}
		}
	}
	return &ControlError{Status: status, Code: word}
}

// Authorize asks the control plane what the device the node authenticated may do. The body carries the device id, the session's jti, the reason and
// the node: never a host name. Anything but a well-formed 200 is an error the node maps to a closed word (errForControl).
func (c *HTTPControl) Authorize(ctx context.Context, req AuthorizeRequest) (AuthorizeResponse, error) {
	body := []byte(canonicalJSON(req.toMap()))
	status, data, err := c.do(ctx, http.MethodPost, authorizePath, body)
	if err != nil {
		return AuthorizeResponse{}, err
	}
	if status != http.StatusOK {
		return AuthorizeResponse{}, controlError(status, data)
	}
	resp, err := parseAuthorizeResponse(data)
	if err != nil {
		return AuthorizeResponse{}, &ControlError{Status: http.StatusBadGateway, Code: "bad_response"}
	}
	return resp, nil
}

// parseAuthorizeResponse reads a 200 answer of authorize (authorize-response.schema.json). The fields the node uses are checked strictly; a field it
// does not know is ignored (a newer control plane may add one).
func parseAuthorizeResponse(data []byte) (AuthorizeResponse, error) {
	value, err := parseJSON(string(data))
	if err != nil {
		return AuthorizeResponse{}, err
	}
	m, ok := value.(map[string]any)
	if !ok || m["ok"] != true {
		return AuthorizeResponse{}, errors.New("authorize answer shape")
	}
	if v, ok := claimInt(m, "v"); !ok || v != 1 {
		return AuthorizeResponse{}, errors.New("authorize answer version")
	}
	var a AuthorizeResponse
	var okDevice, okLabel, okHost, okStatus, okPlan bool
	a.DeviceID, okDevice = claimString(m, "device_id")
	a.Label, okLabel = claimString(m, "label")
	a.Host, okHost = claimString(m, "host")
	a.Status, okStatus = claimString(m, "status")
	a.Plan, okPlan = claimString(m, "plan")
	validUntil, okUntil := epochOK(m["valid_until"])
	serverTime, okTime := epochOK(m["server_time"])
	policy, okPolicy := checkPolicyBlock(m["policy"])
	if !okDevice || !reDeviceID.MatchString(a.DeviceID) || !okLabel || !okHost || !okStatus || !okPlan || !okUntil || !okTime || !okPolicy {
		return AuthorizeResponse{}, errors.New("authorize answer fields")
	}
	a.ValidUntil, a.ServerTime, a.Policy = validUntil, serverTime, policy
	if access, present := m["access"]; present {
		text, ok := access.(string)
		if !ok || statementLine(text) == "" {
			return AuthorizeResponse{}, errors.New("authorize answer access")
		}
		a.Access = text
	}
	if nodes, present := m["nodes"]; present {
		if _, ok := nodes.([]any); !ok {
			return AuthorizeResponse{}, errors.New("authorize answer nodes")
		}
		a.Nodes = nodes
	}
	if wave, ok := claimInt(m, "e2e_wave"); ok && wave >= 0 && wave <= 100 {
		a.E2EWave = int(wave)
	}
	a.E2EKill, _ = m["e2e_kill"].(bool)
	a.CopyE2EE, _ = m["copy_e2ee"].(bool)
	return a, nil
}

// ---------------------------------------------------------------------------------------------------------------------------- the feed

// Types of a feed event (policy enums.feed_event_type). kill and kill_clear are global; every other event names a device and its label.
const (
	feedRevoke     = "revoke"
	feedPause      = "pause"
	feedResume     = "resume"
	feedLicenseEnd = "license_end"
	feedRelease    = "release"
	feedKill       = "kill"
	feedKillClear  = "kill_clear"
)

// FeedEvent is one entry of GET /v1/tunnel/feed (feed-response.schema.json).
type FeedEvent struct {
	Epoch    int64
	Type     string
	DeviceID string // empty for a global event
	Label    string // empty for a global event
	At       int64  // epoch seconds
}

func (e FeedEvent) global() bool { return e.Type == feedKill || e.Type == feedKillClear }

// FeedAnswer is the answer of the feed: Epoch is where the node's cursor goes next. Reset says the cursor is not one the control plane can serve from
// (older than its history, or ahead of it). Skipped counts the events of the answer the node could not read (an unknown type or a malformed field).
type FeedAnswer struct {
	Epoch      int64
	ServerTime int64
	Reset      bool
	Events     []FeedEvent
	Skipped    int
}

// FeedSource is the node's side of GET /v1/tunnel/feed. since is the node's cursor; wait asks the control plane to hold an empty answer until an event
// arrives (at most policy timing.feed_poll_s).
type FeedSource interface {
	Feed(ctx context.Context, since int64, wait time.Duration) (FeedAnswer, error)
}

// Feed polls the feed. The URL is the one that is signed, exactly: https://<host><path>?since=<n>[&wait=<s>].
func (c *HTTPControl) Feed(ctx context.Context, since int64, wait time.Duration) (FeedAnswer, error) {
	query := "?since=" + strconv.FormatInt(since, 10)
	if w := int64(wait / time.Second); w > 0 {
		query += "&wait=" + strconv.FormatInt(min(w, int64(policyData.Timing.FeedPollS)), 10)
	}
	status, data, err := c.do(ctx, http.MethodGet, feedPath+query, nil)
	if err != nil {
		return FeedAnswer{}, err
	}
	if status != http.StatusOK {
		return FeedAnswer{}, controlError(status, data)
	}
	answer, err := parseFeedAnswer(data)
	if err != nil {
		return FeedAnswer{}, &ControlError{Status: http.StatusBadGateway, Code: "bad_response"}
	}
	return answer, nil
}

// parseFeedAnswer reads a feed answer. The envelope is read strictly (a node must not act on an answer it cannot make sense of); an event it cannot
// read, or whose type it does not know, is skipped and counted, because the rest of the answer is still true and a revoke must not wait for it.
func parseFeedAnswer(data []byte) (FeedAnswer, error) {
	value, err := parseJSON(string(data))
	if err != nil {
		return FeedAnswer{}, err
	}
	m, ok := value.(map[string]any)
	if !ok || m["ok"] != true {
		return FeedAnswer{}, errors.New("feed answer shape")
	}
	if v, ok := claimInt(m, "v"); !ok || v != 1 {
		return FeedAnswer{}, errors.New("feed answer version")
	}
	epoch, okEpoch := claimInt(m, "epoch")
	serverTime, okTime := epochOK(m["server_time"])
	list, okList := m["events"].([]any)
	if !okEpoch || epoch < 0 || epoch > 1<<53-1 || !okTime || !okList || len(list) > feedMaxEvents {
		return FeedAnswer{}, errors.New("feed answer fields")
	}
	answer := FeedAnswer{Epoch: epoch, ServerTime: serverTime}
	if reset, present := m["reset"]; present {
		if answer.Reset, ok = reset.(bool); !ok {
			return FeedAnswer{}, errors.New("feed answer reset")
		}
	}
	for _, item := range list {
		event, ok := parseFeedEvent(item)
		if !ok {
			answer.Skipped++
			continue
		}
		answer.Events = append(answer.Events, event)
	}
	return answer, nil
}

const feedMaxEvents = 1000 // feed-response.schema.json: events maxItems

func parseFeedEvent(item any) (FeedEvent, bool) {
	m, ok := item.(map[string]any)
	if !ok {
		return FeedEvent{}, false
	}
	epoch, okEpoch := claimInt(m, "epoch")
	at, okAt := epochOK(m["at"])
	kind, okKind := claimString(m, "type")
	if !okEpoch || epoch < 1 || epoch > 1<<53-1 || !okAt || !okKind || !inList(policyData.Enums.FeedEventType, kind) {
		return FeedEvent{}, false
	}
	event := FeedEvent{Epoch: epoch, Type: kind, At: at}
	device, label := m["device_id"], m["label"]
	if event.global() {
		return event, device == nil && label == nil
	}
	event.DeviceID, _ = device.(string)
	event.Label, _ = label.(string)
	return event, reDeviceID.MatchString(event.DeviceID) && reLabel.MatchString(event.Label)
}

// FetchJWKS reads the control plane's published keys. The document is public, so the request carries no assertion; it is read from the configured
// control plane only, never from a URL an answer names, and a redirect is not followed.
func (c *HTTPControl) FetchJWKS(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base.Scheme+"://"+c.base.Host+jwksPath, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("accept", "application/json")
	req.Header.Set("user-agent", c.agent)
	status, data, err := c.send(req, maxJWKSBody)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, &ControlError{Status: status, Code: "jwks_unavailable"}
	}
	return data, nil
}

// ---------------------------------------------------------------------------------------------------------------------------- the node's key

// LoadNodeKey reads the node's Ed25519 signing key: a PKCS#8 PEM file that only its owner may read (a key a group or the world can read is refused,
// the way ssh refuses one). The one exception is the copy systemd hands the service (LoadCredential=): systemd 255 makes it 0440 root:root with an
// ACL for the unit's dynamic user, inside $CREDENTIALS_DIRECTORY, which only that unit can open; there the group bits are the ACL mask, not a group,
// so only world bits are refused.
func LoadNodeKey(path string) (ed25519.PrivateKey, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("node key: %w", err)
	}
	refused := os.FileMode(0o077)
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" && filepath.IsAbs(dir) && filepath.Dir(filepath.Clean(path)) == filepath.Clean(dir) {
		refused = 0o007
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&refused != 0 {
		return nil, fmt.Errorf("node key %s must be a regular file readable by its owner only (mode 0600)", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("node key: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("node key %s is not a PKCS#8 PEM private key", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("node key %s: %w", path, err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("node key %s is not an Ed25519 key", path)
	}
	return key, nil
}

// GenerateNodeKey creates the node's key at path (mode 0600, never overwriting a file that is there) and returns it.
func GenerateNodeKey(path string) (ed25519.PrivateKey, error) {
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("node key: %w", err)
	}
	if _, err := f.Write(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return key, f.Close()
}

// NodeKeysEntry is the TUNNEL_NODE_KEYS document (node-keys.schema.json) that registers this node's public key with the control plane. Printing it is
// all the node does to "publish" its key: the deployment owner sets the variable (the design plan, section 9); revoking the node is removing
// the kid from it.
func NodeKeysEntry(nodeID, kid string, key ed25519.PrivateKey) string {
	pub := key.Public().(ed25519.PublicKey)
	entry, _ := json.Marshal(map[string]any{"keys": []any{map[string]any{"kid": kid, "node": nodeID, "kty": "OKP", "crv": "Ed25519", "x": b64Encode(pub)}}})
	return string(entry)
}

// ---------------------------------------------------------------------------------------------------------------------------- reachability

// cpHealth is what the node has seen of its control plane's reachability: the moment of the last answer of any kind (an error answer such as a 402 is
// an answer: the control plane is up) and of the last failure to get one (a transport error, a timeout, a 5xx, a 429, an answer it could not read).
// The paid grace asks it, so that one slow answer never decides alone.
type cpHealth struct {
	mu       sync.Mutex
	lastGood time.Time
	lastBad  time.Time
}

func (h *cpHealth) good(now time.Time) {
	h.mu.Lock()
	h.lastGood = now
	h.mu.Unlock()
}

func (h *cpHealth) bad(now time.Time) {
	h.mu.Lock()
	h.lastBad = now
	h.mu.Unlock()
}

// down reports whether the last thing the node saw was a failure and nothing has answered for at least quiet.
func (h *cpHealth) down(now time.Time, quiet time.Duration) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lastBad.After(h.lastGood) && now.Sub(h.lastGood) >= quiet
}

// record files the outcome of one call to the control plane.
func (h *cpHealth) record(now time.Time, err error) {
	if err == nil || isRefusal(err) {
		h.good(now)
		return
	}
	h.bad(now)
}

// isRefusal reports whether err is the control plane saying no (a 4xx other than 429): it answered, so it is reachable.
func isRefusal(err error) bool {
	var ce *ControlError
	return errors.As(err, &ce) && ce.Status >= 400 && ce.Status < 500 && ce.Status != http.StatusTooManyRequests
}

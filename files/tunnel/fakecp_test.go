package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

// fakeCP is a control plane over real HTTPS (httptest): it authenticates the node with the contracts' own verifier (the Go twin of the TypeScript one
// the Worker runs), decides authorize with the environment's fakeControl, keeps a feed and publishes the keys. It is what the real client, the JWKS
// cache and the feed loop are tested against.
type fakeCP struct {
	t   *testing.T
	env *testEnv
	srv *httptest.Server

	nodeKID string
	nodeKey ed25519.PrivateKey

	mu       sync.Mutex
	nodeKeys map[string]ctNodeKey
	seen     map[string]bool
	jwks     map[string]ed25519.PublicKey // kid -> key, what GET /.well-known/device-jwks.json says
	down     int                          // when not 0, every endpoint answers with this status
	hold     time.Duration                // how long a feed poll with wait is held, in real time, when nothing is new
	events   []FeedEvent
	head     int64
	floor    int64
	changed  chan struct{}
	bodies   [][]byte      // the body of every authenticated authorize
	headers  []http.Header // the headers of every authenticated request, to see that nothing but the assertion authenticates
	refused  int           // requests whose assertion was refused
	feedLog  []feedCall
	counts   map[string]int
	inflight int
	maxIn    int
	delay    time.Duration
	// redirect, when set, answers authorize with a redirect to that URL
	redirect string
}

type feedCall struct {
	since int64
	wait  int64
	url   string
}

func newFakeCP(t *testing.T, env *testEnv) *fakeCP {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cp := &fakeCP{
		t: t, env: env, nodeKID: "node-t1-1", nodeKey: priv,
		nodeKeys: map[string]ctNodeKey{}, seen: map[string]bool{}, jwks: map[string]ed25519.PublicKey{},
		changed: make(chan struct{}), counts: map[string]int{},
	}
	cp.nodeKeys[cp.nodeKID] = ctNodeKey{node: testNodeID, x: b64Encode(pub)}
	cp.jwks[testKID] = env.cpKey.Public().(ed25519.PublicKey)
	cp.srv = httptest.NewTLSServer(http.HandlerFunc(cp.handle))
	t.Cleanup(cp.srv.Close)
	return cp
}

func (cp *fakeCP) url() string { return cp.srv.URL }

// control is the real client of the node, pointed at this control plane.
func (cp *fakeCP) control() *HTTPControl {
	hc, err := NewHTTPControl(HTTPControlConfig{BaseURL: cp.srv.URL, NodeID: testNodeID, KID: cp.nodeKID, Key: cp.nodeKey, Client: cp.srv.Client(), Now: cp.env.now, Version: "test"})
	if err != nil {
		cp.t.Fatal(err)
	}
	return hc
}

func (cp *fakeCP) setDown(status int) {
	cp.mu.Lock()
	cp.down = status
	cp.mu.Unlock()
}

// addEvent appends a feed event (epoch is the next one) and wakes the polls that are held.
func (cp *fakeCP) addEvent(kind string, d *testDevice) int64 {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.head++
	e := FeedEvent{Epoch: cp.head, Type: kind, At: cp.env.now().Unix()}
	if d != nil {
		e.DeviceID, e.Label = d.id, d.label
	}
	cp.events = append(cp.events, e)
	close(cp.changed)
	cp.changed = make(chan struct{})
	return e.Epoch
}

func (cp *fakeCP) callCount(name string) int {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return cp.counts[name]
}

func (cp *fakeCP) maxInflight() int {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return cp.maxIn
}

func (cp *fakeCP) feedCalls() []feedCall {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return append([]feedCall(nil), cp.feedLog...)
}

func (cp *fakeCP) reply(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, canonicalJSON(body))
}

func (cp *fakeCP) refuse(w http.ResponseWriter, status int, word string, extra map[string]any) {
	body := map[string]any{"ok": false, "error": word}
	for k, v := range extra {
		body[k] = v
	}
	cp.reply(w, status, body)
}

func (cp *fakeCP) handle(w http.ResponseWriter, r *http.Request) {
	cp.mu.Lock()
	down := cp.down
	cp.counts[r.URL.Path]++
	cp.mu.Unlock()
	if down != 0 {
		cp.refuse(w, down, "end_to_end_unavailable", map[string]any{"retry_after_s": 15})
		return
	}
	switch {
	case r.URL.Path == jwksPath && r.Method == http.MethodGet:
		cp.serveJWKS(w)
	case r.URL.Path == authorizePath && r.Method == http.MethodPost:
		cp.serveAuthorize(w, r)
	case r.URL.Path == feedPath && r.Method == http.MethodGet:
		cp.serveFeed(w, r)
	default:
		cp.refuse(w, 404, "not_found", nil)
	}
}

func (cp *fakeCP) serveJWKS(w http.ResponseWriter) {
	cp.mu.Lock()
	list := []any{}
	for kid, key := range cp.jwks {
		list = append(list, map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64Encode(key), "kid": kid, "alg": "EdDSA", "use": "sig", "key_ops": []any{"verify"}})
	}
	cp.mu.Unlock()
	cp.reply(w, 200, map[string]any{"keys": list})
}

// authenticate checks the node's assertion for exactly this request with the contracts' verifier. It answers 401 and reports false when it fails.
func (cp *fakeCP) authenticate(w http.ResponseWriter, r *http.Request, body []byte) bool {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	result := ctVerifyNodeAssertion(r.Header.Get("x-all-node-assertion"), epochSeconds(cp.env.now()), cp.nodeKeys, r.Method, "https://"+r.Host+r.URL.RequestURI(), body, 5, cp.seen)
	if !result.ok {
		cp.refused++
		cp.reply(w, 401, map[string]any{"ok": false, "error": "unauthorized"})
		return false
	}
	cp.seen[result.jti] = true
	cp.headers = append(cp.headers, r.Header.Clone())
	return true
}

func (cp *fakeCP) serveAuthorize(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if cp.redirect != "" {
		http.Redirect(w, r, cp.redirect, http.StatusFound)
		return
	}
	if !cp.authenticate(w, r, body) {
		return
	}
	cp.mu.Lock()
	cp.bodies = append(cp.bodies, body)
	cp.mu.Unlock()
	doc, err := parseJSON(string(body))
	if err != nil || len(ctSchemaSet.validate("authorize-request.schema.json", doc)) > 0 {
		cp.refuse(w, 400, "invalid_authorize_request", nil)
		return
	}
	m := doc.(map[string]any)
	req := AuthorizeRequest{DeviceID: m["device_id"].(string), SessionJTI: m["session_jti"].(string), Reason: m["reason"].(string), Node: m["node"].(string)}
	cp.mu.Lock()
	cp.inflight++
	cp.maxIn = max(cp.maxIn, cp.inflight)
	delay := cp.delay
	cp.mu.Unlock()
	defer func() {
		cp.mu.Lock()
		cp.inflight--
		cp.mu.Unlock()
	}()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
	}
	resp, aerr := cp.env.cp.Authorize(r.Context(), req)
	if aerr != nil {
		if ce, ok := aerr.(*ControlError); ok {
			extra := map[string]any{}
			if ce.Code == codeLicenseInactive {
				extra["status"] = "trial_ended"
			}
			cp.refuse(w, ce.Status, ce.Code, extra)
			return
		}
		cp.refuse(w, 503, "end_to_end_unavailable", nil)
		return
	}
	cp.reply(w, 200, resp.toMap())
}

// replyFeed answers a feed poll after checking the answer against the contracts' own rules (schema, strictly increasing epochs, scopes): the fake must
// never be more lenient than the real control plane, or the node would be tested against something that does not exist.
func (cp *fakeCP) replyFeed(w http.ResponseWriter, since int64, body map[string]any) {
	if doc, err := parseJSON(canonicalJSON(body)); err != nil {
		cp.t.Errorf("the fake feed made a body that is not JSON: %v", err)
	} else if _, reset := body["reset"]; !reset {
		if errs := ctCheckFeed(doc, float64(since)); len(errs) > 0 {
			cp.t.Errorf("the fake feed broke the contract: %v", errs)
		}
	}
	cp.reply(w, 200, body)
}

func (cp *fakeCP) serveFeed(w http.ResponseWriter, r *http.Request) {
	if !cp.authenticate(w, r, nil) {
		return
	}
	since, err := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	if err != nil {
		cp.refuse(w, 400, "invalid_feed_request", nil)
		return
	}
	wait, _ := strconv.ParseInt(r.URL.Query().Get("wait"), 10, 64)
	cp.mu.Lock()
	cp.feedLog = append(cp.feedLog, feedCall{since: since, wait: wait, url: r.URL.RequestURI()})
	hold := cp.hold
	cp.mu.Unlock()

	deadline := time.Now().Add(min(hold, time.Duration(wait)*time.Second))
	for {
		cp.mu.Lock()
		if since > cp.head || since < cp.floor {
			head := cp.head
			cp.mu.Unlock()
			cp.replyFeed(w, since, map[string]any{"ok": true, "v": 1, "epoch": head, "server_time": cp.env.now().Unix(), "reset": true, "events": []any{}})
			return
		}
		var out []any
		for _, e := range cp.events {
			if e.Epoch > since {
				var device, label any
				if !e.global() {
					device, label = e.DeviceID, e.Label
				}
				out = append(out, map[string]any{"epoch": e.Epoch, "type": e.Type, "device_id": device, "label": label, "at": e.At})
			}
		}
		changed, head := cp.changed, cp.head
		cp.mu.Unlock()
		if len(out) > 0 || !time.Now().Before(deadline) {
			if out == nil {
				out = []any{}
			}
			cp.replyFeed(w, since, map[string]any{"ok": true, "v": 1, "epoch": head, "server_time": cp.env.now().Unix(), "events": out})
			return
		}
		select {
		case <-changed:
		case <-time.After(time.Until(deadline)):
		case <-r.Context().Done():
			return
		}
	}
}

// httpNode starts a node whose control plane, key set and feed are the real clients talking to a fakeCP over HTTPS, on the fake clock when clk is set.
func httpNode(t *testing.T, clk *fakeClock, mutate func(*Config)) (*testEnv, *fakeCP) {
	t.Helper()
	var cp *fakeCP
	e := newEnv(t, clk, func(e *testEnv, cfg *Config) {
		cp = newFakeCP(t, e)
		control := cp.control()
		health := &cpHealth{}
		clock := newClock(e.now, cfg.AfterFunc)
		jwks := NewJWKSCache(JWKSConfig{Fetch: control.FetchJWKS, Clock: clock, Log: cfg.Logger, MinReload: time.Millisecond, Observe: func(ok bool) {
			if ok {
				health.good(clock.Now())
			} else {
				health.bad(clock.Now())
			}
		}})
		cfg.Keys, cfg.Control, cfg.Feed, cfg.Health = jwks, control, control, health
		cfg.Background = append(cfg.Background, jwks.Run)
		cfg.FeedStartWait = 5 * time.Second
		cfg.MinRenewGap = 0
		if mutate != nil {
			mutate(cfg)
		}
	})
	return e, cp
}

package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The JWKS cache: the control plane's keys are the root of trust of every session the node verifies offline.

// jwksSource is a control plane's key endpoint as the cache sees it: a set that the tests change and a switch that makes it fail.
type jwksSource struct {
	mu    sync.Mutex
	keys  map[string]ed25519.PublicKey
	fail  error
	raw   []byte
	calls atomic.Int64
}

func newJWKSSource(kids ...string) *jwksSource {
	s := &jwksSource{keys: map[string]ed25519.PublicKey{}}
	for _, kid := range kids {
		s.add(kid)
	}
	return s
}

func (s *jwksSource) add(kid string) ed25519.PublicKey {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	s.mu.Lock()
	s.keys[kid] = pub
	s.mu.Unlock()
	return pub
}

func (s *jwksSource) drop(kid string) {
	s.mu.Lock()
	delete(s.keys, kid)
	s.mu.Unlock()
}

func (s *jwksSource) setFail(err error) {
	s.mu.Lock()
	s.fail = err
	s.mu.Unlock()
}

func (s *jwksSource) fetch(ctx context.Context) ([]byte, error) {
	s.calls.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return nil, s.fail
	}
	if s.raw != nil {
		return s.raw, nil
	}
	list := []any{}
	for kid, key := range s.keys {
		list = append(list, map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64Encode(key), "kid": kid, "alg": "EdDSA", "use": "sig", "key_ops": []any{"verify"}})
	}
	return []byte(canonicalJSON(map[string]any{"keys": list})), nil
}

func newTestCache(src *jwksSource, clk *fakeClock) *JWKSCache {
	return NewJWKSCache(JWKSConfig{Fetch: src.fetch, Clock: newClock(clk.Now, clk.AfterFunc), MinReload: 5 * time.Second})
}

func TestJWKS_FetchesOnDemandCachesFor300sAndRefreshesBehindTheLookup(t *testing.T) {
	src := newJWKSSource("a")
	clk := newFakeClock()
	c := newTestCache(src, clk)
	if policyData.JWKS.CacheS != 300 || c.cfg.TTL != 300*time.Second {
		t.Fatalf("the cache lives %s; the plan says 300 s", c.cfg.TTL)
	}
	if _, ok := c.Key("a"); !ok || src.calls.Load() != 1 {
		t.Fatalf("first lookup: fetched %d", src.calls.Load())
	}
	for i := 0; i < 50; i++ {
		if _, ok := c.Key("a"); !ok {
			t.Fatal("a cached key was lost")
		}
	}
	if src.calls.Load() != 1 {
		t.Fatalf("a cached set was fetched again: %d", src.calls.Load())
	}
	// past its TTL a lookup still answers from the set (it is vouched for) and refreshes behind it
	clk.Advance(301 * time.Second)
	if _, ok := c.Key("a"); !ok {
		t.Fatal("a set past its TTL but inside the stale window must still serve")
	}
	eventually(t, "the refresh behind the lookup", 2*time.Second, func() bool { return src.calls.Load() == 2 })
}

func TestJWKS_ARotationIsFollowedAtTheNextLookupAndADroppedKeyStopsBeingTrusted(t *testing.T) {
	src := newJWKSSource("old")
	clk := newFakeClock()
	c := newTestCache(src, clk)
	if _, ok := c.Key("old"); !ok {
		t.Fatal("old")
	}
	newPub := src.add("new")
	clk.Advance(6 * time.Second) // past the minimum gap between forced reloads
	got, ok := c.Key("new")      // an unknown kid reloads
	if !ok || !got.Equal(newPub) {
		t.Fatal("a rotated-in key was not picked up at the first lookup that needed it")
	}
	if _, ok := c.Key("old"); !ok {
		t.Fatal("the old key is still published, so still trusted")
	}
	src.drop("old")
	clk.Advance(301 * time.Second)
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Key("old"); ok {
		t.Fatal("a key the control plane stopped publishing is still trusted")
	}
	if _, ok := c.Key("new"); !ok {
		t.Fatal("new")
	}
}

func TestJWKS_AFloodOfUnknownKidsIsOneFetchPerMinimumGapNotAFetchPerSession(t *testing.T) {
	src := newJWKSSource("a")
	clk := newFakeClock()
	c := newTestCache(src, clk)
	if _, ok := c.Key("a"); !ok {
		t.Fatal("a")
	}
	before := src.calls.Load()
	var wg sync.WaitGroup
	var wrongly atomic.Int64
	for i := 0; i < 4000; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, ok := c.Key(fmt.Sprintf("random-%d", i)); ok {
				wrongly.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if wrongly.Load() != 0 {
		t.Fatal("an unknown kid was accepted")
	}
	// the first of them may fetch (the cache had not looked for a while); the rest never do
	if n := src.calls.Load() - before; n > 1 {
		t.Fatalf("4000 sessions with unknown kids made %d fetches", n)
	}
	// a legitimate rotation right after the flood waits for the gap, and is picked up after it
	src.add("rotated")
	if _, ok := c.Key("rotated"); ok {
		t.Fatal("served inside the minimum gap")
	}
	clk.Advance(6 * time.Second)
	if _, ok := c.Key("rotated"); !ok {
		t.Fatal("not picked up after the gap")
	}
	// and the known keys were never refused while the flood ran
	if _, ok := c.Key("a"); !ok {
		t.Fatal("a known key was refused")
	}
}

// waitIdle waits until the source has been asked n times and no fetch is in flight.
func (c *JWKSCache) waitIdle(t *testing.T, src *jwksSource, n int64) {
	t.Helper()
	eventually(t, "the background refresh to end", 3*time.Second, func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return src.calls.Load() >= n && c.flight == nil
	})
}

func TestJWKS_ALookupPastTheTTLStampsItsRefreshBeforeItReturns(t *testing.T) {
	src := newJWKSSource("a")
	clk := newFakeClock()
	c := newTestCache(src, clk)
	if _, ok := c.Key("a"); !ok {
		t.Fatal("start")
	}
	clk.Advance(6 * time.Minute) // past the 5 minute TTL, still vouched for
	at := clk.Now()
	if _, ok := c.Key("a"); !ok {
		t.Fatal("a set past its TTL but not stale must still be served")
	}
	// the gap to the next attempt counts from this lookup, whenever the refresh goroutine happens to run
	c.mu.Lock()
	stamped := c.attemptedAt
	c.mu.Unlock()
	if !stamped.Equal(at) {
		t.Fatalf("the attempt is stamped %s, the lookup was at %s", stamped, at)
	}
	c.waitIdle(t, src, 2)
	if _, ok := c.Key("zzz"); ok || src.calls.Load() != 2 {
		t.Fatalf("an unknown kid inside the gap fetched again (%d fetches)", src.calls.Load())
	}
}

func TestJWKS_FailsClosedAfterThirtyMinutesWithoutARefreshAndRecovers(t *testing.T) {
	if policyData.JWKS.StaleFailClosedS != 1800 {
		t.Fatalf("the plan says 30 minutes, the policy says %d s", policyData.JWKS.StaleFailClosedS)
	}
	src := newJWKSSource("a")
	clk := newFakeClock()
	c := newTestCache(src, clk)
	if _, ok := c.Key("a"); !ok || !c.Healthy() {
		t.Fatal("start")
	}
	src.setFail(errors.New("unreachable"))
	// the control plane is down: the set keeps serving for the stale window
	clk.Advance(29 * time.Minute)
	if _, ok := c.Key("a"); !ok || !c.Healthy() {
		t.Fatal("a set 29 minutes old must still be trusted")
	}
	// that lookup refreshed the set behind itself (and failed): the fake clock moves only once it is over
	c.waitIdle(t, src, 2)
	clk.Advance(2 * time.Minute) // 31 minutes without a refresh
	if _, ok := c.Key("a"); ok {
		t.Fatal("a set 31 minutes old was trusted: the cache must fail closed")
	}
	if c.Healthy() {
		t.Fatal("healthy while stale")
	}
	if age := c.Age(); age < 31*time.Minute {
		t.Fatalf("age %s", age)
	}
	// the control plane is back: the next lookup (after the gap) recovers by itself
	src.setFail(nil)
	clk.Advance(6 * time.Second)
	if _, ok := c.Key("a"); !ok || !c.Healthy() {
		t.Fatal("the cache did not recover when the control plane came back")
	}
}

func TestJWKS_ABadSetIsNeverUsedAndNeverReplacesAGoodOne(t *testing.T) {
	src := newJWKSSource("good")
	clk := newFakeClock()
	c := newTestCache(src, clk)
	if _, ok := c.Key("good"); !ok {
		t.Fatal("start")
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	x := b64Encode(pub)
	key := func(kid string) string {
		return fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q,"kid":%q,"alg":"EdDSA","use":"sig","key_ops":["verify"]}`, x, kid)
	}
	many := make([]string, 17)
	for i := range many {
		many[i] = key(fmt.Sprintf("k%d", i))
	}
	for name, raw := range map[string]string{
		"17 keys":         `{"keys":[` + strings.Join(many, ",") + `]}`,
		"a repeated kid":  `{"keys":[` + key("dup") + `,` + key("dup") + `]}`,
		"no keys":         `{"keys":[]}`,
		"a private part":  `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + x + `","d":"` + x + `","kid":"p","alg":"EdDSA","use":"sig","key_ops":["verify"]}]}`,
		"not json":        `<html>`,
		"an extra member": `{"keys":[` + key("a") + `],"issuer":"https://elsewhere.example"}`,
	} {
		src.mu.Lock()
		src.raw = []byte(raw)
		src.mu.Unlock()
		clk.Advance(6 * time.Second)
		if err := c.Refresh(context.Background()); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, ok := c.Key("good"); !ok {
			t.Errorf("%s: the good set was lost", name)
		}
		if _, ok := c.Key("dup"); ok {
			t.Errorf("%s: part of a refused set was used", name)
		}
	}
	// sixteen keys is the most
	sixteen := many[:16]
	src.mu.Lock()
	src.raw = []byte(`{"keys":[` + strings.Join(sixteen, ",") + `]}`)
	src.mu.Unlock()
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatalf("16 keys: %v", err)
	}
	if _, ok := c.Key("k15"); !ok {
		t.Fatal("k15")
	}
}

func TestJWKS_RunKeepsTheSetFreshAndBacksOffAfterAFailure(t *testing.T) {
	src := newJWKSSource("a")
	clk := newFakeClock()
	var observed []bool
	var mu sync.Mutex
	c := NewJWKSCache(JWKSConfig{Fetch: src.fetch, Clock: newClock(clk.Now, clk.AfterFunc), Observe: func(ok bool) {
		mu.Lock()
		observed = append(observed, ok)
		mu.Unlock()
	}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	eventually(t, "the first fetch", 2*time.Second, func() bool { return src.calls.Load() == 1 })
	eventually(t, "the loop sleeping", 2*time.Second, func() bool { return clk.pending() == 1 })
	clk.Advance(5 * time.Minute) // the TTL, spread by at most 10 percent: not yet at 270 s, surely at 330 s
	clk.Advance(30 * time.Second)
	eventually(t, "the periodic refresh", 2*time.Second, func() bool { return src.calls.Load() == 2 })
	eventually(t, "the loop sleeping again", 2*time.Second, func() bool { return clk.pending() == 1 })
	src.setFail(errors.New("down"))
	clk.Advance(6 * time.Minute)
	eventually(t, "a failed refresh", 2*time.Second, func() bool { return src.calls.Load() == 3 })
	eventually(t, "the backoff timer", 2*time.Second, func() bool { return clk.pending() == 1 })
	// after a failure the next try comes after the policy's backoff (1 s, then 2 s), not after another 5 minutes
	clk.Advance(2 * time.Second)
	eventually(t, "the retry after the backoff", 2*time.Second, func() bool { return src.calls.Load() == 4 })
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not end with its context")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(observed) < 4 || !observed[0] || observed[2] {
		t.Fatalf("observed outcomes %v", observed)
	}
}

func TestJWKS_ThePinnedControlPlaneIsTheOnlyPlaceTheKeysComeFrom(t *testing.T) {
	var landed atomic.Int64
	elsewhere := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		landed.Add(1)
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer elsewhere.Close()
	redirecting := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+jwksPath, http.StatusFound)
	}))
	defer redirecting.Close()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	hc, err := NewHTTPControl(HTTPControlConfig{BaseURL: redirecting.URL, NodeID: "t1", KID: "k1", Key: priv, Client: redirecting.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hc.FetchJWKS(context.Background()); err == nil || landed.Load() != 0 {
		t.Fatalf("the keys were read through a redirect: err=%v landed=%d", err, landed.Load())
	}

	// an oversized or failing answer is no set
	big := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", maxJWKSBody+10)))
	}))
	defer big.Close()
	hc, _ = NewHTTPControl(HTTPControlConfig{BaseURL: big.URL, NodeID: "t1", KID: "k1", Key: priv, Client: big.Client()})
	if _, err := hc.FetchJWKS(context.Background()); err == nil {
		t.Fatal("an oversized document was read")
	}
}

func TestJWKS_ARotationMidConnectionWorksAndAStaleSetFailsClosedForNewSessions(t *testing.T) {
	clk := newFakeClock()
	e, cp := httpNode(t, clk, nil)
	d := e.newDevice()
	conn := e.connectOK(d)

	// The control plane rotates: a new key signs the sessions from now on, the old one stays published for a while.
	newPub, newPriv, _ := ed25519.GenerateKey(rand.Reader)
	const newKID = "cp-test-2"
	cp.mu.Lock()
	cp.jwks[newKID] = newPub
	cp.mu.Unlock()
	clk.Advance(2 * time.Second) // past the cache's minimum gap between two forced reloads
	rotated := func(dev *testDevice) string {
		return e.sessionSignedBy(newPriv, dev, func(h, c map[string]any) { h["kid"] = newKID })
	}

	// the connection that was up before the rotation renews with a session of the new key
	conn.session = rotated(d)
	conn.send("RENEW " + conn.session)
	line := conn.recv()
	m, err := parseLine(line, dirN2D)
	if err != nil || m.str("verb") != "CHALLENGE" {
		t.Fatalf("a session of the rotated-in key was refused at RENEW: %q", line)
	}
	conn.send("PROOF " + e.proof(d, conn.session, m.str("nonce"), nil))
	if line = conn.recv(); !strings.HasPrefix(line, "OK ") {
		t.Fatalf("renew after a rotation: %q", line)
	}
	// and so does a new device
	d2 := e.newDevice()
	conn2 := e.connect(d2)
	if line := conn2.hello(func() string { return rotated(d2) }, func(s, n string) string { return e.proof(d2, s, n, nil) }); !strings.HasPrefix(line, "OK ") {
		t.Fatalf("hello after a rotation: %q", line)
	}

	// The control plane goes away. For 29 minutes the node still vouches for the set it has; at 31 it vouches for nothing.
	cp.setDown(503)
	clk.Advance(29 * time.Minute)
	d3 := e.newDevice()
	e.cp.set(d3.id, &devicePlan{host: d3.host, err: &ControlError{Status: 503, Code: "end_to_end_unavailable"}})
	if line := e.connect(d3).hello(func() string { return rotated(d3) }, func(s, n string) string { return e.proof(d3, s, n, nil) }); line != "ERR control_unavailable" {
		t.Fatalf("29 minutes of silence, authorize down: %q", line) // the keys still verify; it is authorize that is unavailable
	}
	if strings.Contains(e.logs.String(), `"msg":"session_refused"`) {
		t.Fatal("the session was refused at verification: the set should still have been trusted at 29 minutes")
	}
	clk.Advance(2 * time.Minute)
	if line := e.connect(d3).hello(func() string { return rotated(d3) }, func(s, n string) string { return e.proof(d3, s, n, nil) }); line != "ERR control_unavailable" {
		t.Fatalf("31 minutes of silence: %q", line)
	}
	if !strings.Contains(e.logs.String(), `"msg":"session_refused"`) || !strings.Contains(e.logs.String(), `"reason":"unknown_kid"`) {
		t.Fatal("a session was verified against a set older than the policy's window")
	}
	// told to retry later, not told its credentials are wrong
	if !strings.Contains(e.logs.String(), `"answer":"control_unavailable"`) {
		t.Fatal("the refusal because of stale keys is not logged as such")
	}
	// the connections that were already authenticated are untouched
	if !e.srv.Online(d.host) || !e.srv.Online(d2.host) {
		t.Fatal("a stale JWKS closed connections that were already authenticated")
	}
	// and a RENEW on them is refused as unavailable too, keeping the connection
	conn.session = rotated(d)
	conn.send("RENEW " + conn.session)
	if line := conn.recv(); line != "ERR control_unavailable" {
		t.Fatalf("renew on a stale set: %q", line)
	}

	// back to normal
	cp.setDown(0)
	e.cp.set(d3.id, &devicePlan{host: d3.host, validFor: time.Hour})
	clk.Advance(6 * time.Second)
	if line := e.connect(d3).hello(func() string { return rotated(d3) }, func(s, n string) string { return e.proof(d3, s, n, nil) }); !strings.HasPrefix(line, "OK ") {
		t.Fatalf("after the control plane came back: %q", line)
	}
}

func TestJWKS_AFloodOfHellosWithRandomKidsCostsTheControlPlaneAtMostOneFetchAndHarmsNoLegitimateDevice(t *testing.T) {
	clk := newFakeClock()
	e, cp := httpNode(t, clk, nil)
	d := e.newDevice()
	_ = e.connectOK(d) // the cache has its keys
	before := cp.callCount(jwksPath)

	var wg sync.WaitGroup
	var wrong atomic.Int64
	for i := 0; i < 300; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			attacker := &testDevice{id: randomHex(16), key: d.key}
			c, err := e.dialNode()
			if err != nil {
				return // the node was full: also fine
			}
			defer c.Close()
			session := e.session(attacker, func(h, claims map[string]any) { h["kid"] = "rogue-" + randomHex(6) })
			_, _ = c.Write([]byte("HELLO 2 " + session + "\n"))
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			line, _ := bufio.NewReader(c).ReadString('\n')
			if strings.TrimSpace(line) != "ERR auth" {
				wrong.Add(1)
			}
		}()
	}
	wg.Wait()
	if wrong.Load() != 0 {
		t.Fatalf("%d of the 300 sessions with a made-up kid were not refused with auth", wrong.Load())
	}
	if n := cp.callCount(jwksPath) - before; n > 1 {
		t.Fatalf("300 sessions with random kids made the node fetch the keys %d times", n)
	}
	// a legitimate device is served as before
	d2 := e.newDevice()
	_ = e.connectOK(d2)
}

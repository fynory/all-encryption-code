package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ALL 2.0, WP26: the self-check. A real TLS server with a real certificate chain is dialed the way ChatGPT will, and the first step that fails is the answer: a wrong chain,
// an expired certificate, a key that is not the one the computer expects, a name that is not its own, a TLS version below 1.3, a /healthz that does not say ok, a port
// that is closed and a server that never answers. Every answer is the contract's selfcheck-result.

const selfCheckHost = "abcdefghijklmnopqrst.devices.all-e2e.test"

type selfCheckAuthority struct {
	pool *x509.CertPool
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newSelfCheckAuthority(t *testing.T, name string) *selfCheckAuthority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(240 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &selfCheckAuthority{pool: pool, cert: cert, key: key}
}

type selfCheckLeaf struct {
	certificate tls.Certificate
	spki        string
	notAfter    int64
}

// issue signs a leaf for `host` that is valid from `notBefore` to `notAfter`.
func (a *selfCheckAuthority) issue(t *testing.T, host string, notBefore, notAfter time.Time) selfCheckLeaf {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, &key.PublicKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return selfCheckLeaf{certificate: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, spki: base64.RawURLEncoding.EncodeToString(sum[:]), notAfter: leaf.NotAfter.Unix()}
}

func (a *selfCheckAuthority) good(t *testing.T) selfCheckLeaf {
	return a.issue(t, selfCheckHost, time.Now().Add(-time.Hour), time.Now().Add(45*24*time.Hour))
}

// serveSelfCheck runs a TLS server (HTTP/1.1 behind it) on a loopback port with the certificate and the TLS limits given, and returns its address.
func serveSelfCheck(t *testing.T, leaf selfCheckLeaf, maxVersion uint16, healthz http.HandlerFunc) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthz)
	server := httptest.NewUnstartedServer(mux)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{leaf.certificate}, MinVersion: tls.VersionTLS12, MaxVersion: maxVersion}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server.Listener.Addr().String()
}

func okHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func checkWith(t *testing.T, authority *selfCheckAuthority, addr, host string, expect []string, change func(*SelfCheckConfig)) SelfCheckResult {
	t.Helper()
	cfg := SelfCheckConfig{Roots: authority.pool, Timeout: 5 * time.Second}
	if change != nil {
		change(&cfg)
	}
	result := SelfCheck(context.Background(), cfg, addr, host, expect)
	// every answer, whatever it says, is the contract and carries no host and no address
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var instance any
	if err := json.Unmarshal(encoded, &instance); err != nil {
		t.Fatal(err)
	}
	if problems := ctLoadSchemas().validate("selfcheck-result.schema.json", instance); len(problems) != 0 {
		t.Fatalf("not the contract: %v in %s", problems, encoded)
	}
	if strings.Contains(string(encoded), host) || strings.Contains(string(encoded), "127.0.0.1") {
		t.Fatalf("the answer names a host or an address: %s", encoded)
	}
	return result
}

func reasonOf(r SelfCheckResult) string {
	if r.Reason == nil {
		return ""
	}
	return *r.Reason
}

func TestSelfCheckPassesForAGoodChainTheRightKeyAndAHealthyPath(t *testing.T) {
	authority := newSelfCheckAuthority(t, "good root")
	leaf := authority.good(t)
	addr := serveSelfCheck(t, leaf, tls.VersionTLS13, okHealthz)
	result := checkWith(t, authority, addr, selfCheckHost, []string{leaf.spki}, nil)
	if !result.OK || result.Reason != nil || !result.Healthz {
		t.Fatalf("a good path: %+v", result)
	}
	if result.TLSVersion == nil || *result.TLSVersion != "1.3" || result.SPKISHA256 == nil || *result.SPKISHA256 != leaf.spki || result.NotAfter == nil || *result.NotAfter != leaf.notAfter {
		t.Fatalf("what it saw: %+v", result)
	}
	// without an expectation (the operator's canary asks only whether the chain is good) the key is not compared
	if anyKey := checkWith(t, authority, addr, selfCheckHost, nil, nil); !anyKey.OK {
		t.Fatalf("no expectation: %+v", anyKey)
	}
	// the expected set may hold the key of the generation that is about to replace this one
	if two := checkWith(t, authority, addr, selfCheckHost, []string{strings.Repeat("A", 43), leaf.spki}, nil); !two.OK {
		t.Fatalf("a set of two: %+v", two)
	}
}

func TestSelfCheckFailsForAChainThatDoesNotLeadToAPublicRoot(t *testing.T) {
	trusted := newSelfCheckAuthority(t, "the root the checker trusts")
	stranger := newSelfCheckAuthority(t, "another root")
	addr := serveSelfCheck(t, stranger.good(t), tls.VersionTLS13, okHealthz)
	result := checkWith(t, trusted, addr, selfCheckHost, nil, nil)
	if result.OK || reasonOf(result) != selfCheckChain || result.Healthz {
		t.Fatalf("a wrong chain: %+v", result)
	}
	// and a self-signed leaf with no authority at all
	selfSigned := trusted.issue(t, selfCheckHost, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	selfSigned.certificate.Certificate = selfSigned.certificate.Certificate[:1]
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: selfCheckHost}, DNSNames: []string{selfCheckHost}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	own := serveSelfCheck(t, selfCheckLeaf{certificate: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}}, tls.VersionTLS13, okHealthz)
	if again := checkWith(t, trusted, own, selfCheckHost, nil, nil); reasonOf(again) != selfCheckChain {
		t.Fatalf("a self-signed leaf: %+v", again)
	}
}

func TestSelfCheckFailsForAnExpiredCertificateAndForOneThatIsNotYetValid(t *testing.T) {
	authority := newSelfCheckAuthority(t, "root")
	expired := authority.issue(t, selfCheckHost, time.Now().Add(-90*24*time.Hour), time.Now().Add(-time.Hour))
	result := checkWith(t, authority, serveSelfCheck(t, expired, tls.VersionTLS13, okHealthz), selfCheckHost, []string{expired.spki}, nil)
	if result.OK || reasonOf(result) != selfCheckExpired {
		t.Fatalf("expired: %+v", result)
	}
	if result.NotAfter == nil || *result.NotAfter != expired.notAfter {
		t.Fatalf("the answer still says when it expired: %+v", result)
	}
	future := authority.issue(t, selfCheckHost, time.Now().Add(24*time.Hour), time.Now().Add(48*time.Hour))
	if early := checkWith(t, authority, serveSelfCheck(t, future, tls.VersionTLS13, okHealthz), selfCheckHost, nil, nil); reasonOf(early) != selfCheckExpired {
		t.Fatalf("not yet valid: %+v", early)
	}
	// validity is judged at the moment the check says: a good certificate seen ten years from now is an expired one
	good := authority.good(t)
	later := checkWith(t, authority, serveSelfCheck(t, good, tls.VersionTLS13, okHealthz), selfCheckHost, nil, func(cfg *SelfCheckConfig) {
		cfg.Now = func() time.Time { return time.Now().Add(10 * 365 * 24 * time.Hour) }
	})
	if reasonOf(later) != selfCheckExpired {
		t.Fatalf("in ten years: %+v", later)
	}
}

func TestSelfCheckFailsForAKeyThatIsNotTheOneTheComputerExpects(t *testing.T) {
	authority := newSelfCheckAuthority(t, "root")
	leaf := authority.good(t)
	other := authority.good(t)
	addr := serveSelfCheck(t, leaf, tls.VersionTLS13, okHealthz)
	result := checkWith(t, authority, addr, selfCheckHost, []string{other.spki}, nil)
	if result.OK || reasonOf(result) != selfCheckSPKI || result.Healthz {
		t.Fatalf("a mismatching key: %+v", result)
	}
	if result.SPKISHA256 == nil || *result.SPKISHA256 != leaf.spki {
		t.Fatalf("the answer says which key it saw (so the operator can compare): %+v", result)
	}
}

func TestSelfCheckFailsForANameThatIsNotTheComputersOwn(t *testing.T) {
	authority := newSelfCheckAuthority(t, "root")
	wrong := authority.issue(t, "tsrqponmlkjihgfedcba.devices.all-e2e.test", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	result := checkWith(t, authority, serveSelfCheck(t, wrong, tls.VersionTLS13, okHealthz), selfCheckHost, []string{wrong.spki}, nil)
	if result.OK || reasonOf(result) != selfCheckName {
		t.Fatalf("a certificate for another label: %+v", result)
	}
}

func TestSelfCheckRequiresTLS13(t *testing.T) {
	authority := newSelfCheckAuthority(t, "root")
	leaf := authority.good(t)
	result := checkWith(t, authority, serveSelfCheck(t, leaf, tls.VersionTLS12, okHealthz), selfCheckHost, []string{leaf.spki}, nil)
	if result.OK || reasonOf(result) != selfCheckTLSVersion || result.TLSVersion == nil || *result.TLSVersion != "1.2" {
		t.Fatalf("a TLS 1.2 server: %+v", result)
	}
}

func TestSelfCheckFailsWhenHealthzDoesNotSayOk(t *testing.T) {
	authority := newSelfCheckAuthority(t, "root")
	leaf := authority.good(t)
	for name, handler := range map[string]http.HandlerFunc{
		"a server error": func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "down", http.StatusInternalServerError) },
		"not ok":         func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"ok":false}`)) },
		"not json":       func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`<html>welcome</html>`)) },
		"no member":      func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{}`)) },
		"a redirect":     func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/elsewhere", http.StatusFound) },
	} {
		result := checkWith(t, authority, serveSelfCheck(t, leaf, tls.VersionTLS13, handler), selfCheckHost, []string{leaf.spki}, nil)
		if result.OK || reasonOf(result) != selfCheckHealthz || result.Healthz {
			t.Fatalf("%s: %+v", name, result)
		}
		if result.SPKISHA256 == nil {
			t.Fatalf("%s: the TLS part passed, so the answer still carries what it saw", name)
		}
	}
}

func TestSelfCheckSaysUnreachableForAClosedPortAndTimeoutForAServerThatNeverAnswers(t *testing.T) {
	authority := newSelfCheckAuthority(t, "root")
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := closed.Addr().String()
	closed.Close()
	if result := checkWith(t, authority, address, selfCheckHost, nil, nil); result.OK || reasonOf(result) != selfCheckUnreachable {
		t.Fatalf("a closed port: %+v", result)
	}
	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			conn, err := silent.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, conn)
			mu.Unlock()
		}
	}()
	defer func() {
		mu.Lock()
		for _, conn := range held {
			conn.Close()
		}
		mu.Unlock()
	}()
	started := time.Now()
	result := checkWith(t, authority, silent.Addr().String(), selfCheckHost, nil, func(cfg *SelfCheckConfig) { cfg.Timeout = 300 * time.Millisecond })
	if result.OK || reasonOf(result) != selfCheckTimeout {
		t.Fatalf("a server that never answers: %+v", result)
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("the timeout did not bound the check: %v", elapsed)
	}
	// a server that answers the handshake and then says nothing about /healthz is a timeout too, not a hang
	leaf := authority.good(t)
	stalled := serveSelfCheck(t, leaf, tls.VersionTLS13, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	started = time.Now()
	hung := checkWith(t, authority, stalled, selfCheckHost, []string{leaf.spki}, func(cfg *SelfCheckConfig) { cfg.Timeout = 400 * time.Millisecond })
	if hung.OK || reasonOf(hung) != selfCheckTimeout || time.Since(started) > 3*time.Second {
		t.Fatalf("a healthz that never answers: %+v after %v", hung, time.Since(started))
	}
}

func TestSelfCheckReasonsAreThePolicysEnumInTheOrderTheStepsRun(t *testing.T) {
	policy := ctPolStrings("enums.selfcheck_reason")
	ours := []string{selfCheckChain, selfCheckExpired, selfCheckSPKI, selfCheckName, selfCheckTLSVersion, selfCheckHealthz, selfCheckUnreachable, selfCheckTimeout}
	if fmt.Sprint(policy) != fmt.Sprint(ours) {
		t.Fatalf("policy %v, code %v", policy, ours)
	}
}

func TestSelfCheckTunnelsThroughTheDialerItIsGiven(t *testing.T) {
	// the node dials its own public path through whatever Dial gives: here, a function that ignores the address and goes to the test server
	authority := newSelfCheckAuthority(t, "root")
	leaf := authority.good(t)
	real := serveSelfCheck(t, leaf, tls.VersionTLS13, okHealthz)
	var dialed string
	result := checkWith(t, authority, "203.0.113.9:443", selfCheckHost, []string{leaf.spki}, func(cfg *SelfCheckConfig) {
		cfg.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialed = addr
			return (&net.Dialer{}).DialContext(ctx, network, real)
		}
	})
	if !result.OK || dialed != "203.0.113.9:443" {
		t.Fatalf("%+v dialed %q", result, dialed)
	}
}

// ---- the HTTP shape ----------------------------------------------------------------------------------------------------------------------------

func selfCheckPost(handler http.Handler, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/selfcheck", bytes.NewBufferString(body))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestSelfCheckHandlerAnswersTheContractAndRefusesWhatItDoesNotKnow(t *testing.T) {
	authority := newSelfCheckAuthority(t, "root")
	leaf := authority.good(t)
	addr := serveSelfCheck(t, leaf, tls.VersionTLS13, okHealthz)
	cfg := SelfCheckConfig{Roots: authority.pool, Timeout: 5 * time.Second}
	labelOK := func(label string) bool { return ctLabelOK(label) }
	lookup := func(label string) (string, bool) {
		return label + ".devices.all-e2e.test", label == "abcdefghijklmnopqrst"
	}
	handler := NewSelfCheckHandler(cfg, addr, lookup, labelOK, 0)
	good := selfCheckPost(handler, fmt.Sprintf(`{"v":1,"label":"abcdefghijklmnopqrst","expect":["%s"]}`, leaf.spki))
	var answer map[string]any
	if good.Code != http.StatusOK || json.Unmarshal(good.Body.Bytes(), &answer) != nil || answer["ok"] != true {
		t.Fatalf("%d %s", good.Code, good.Body.String())
	}
	if problems := ctLoadSchemas().validate("selfcheck-result.schema.json", answer); len(problems) != 0 {
		t.Fatalf("not the contract: %v", problems)
	}
	if good.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("an answer about one computer is never cached")
	}
	// an unknown or offline label is the same kind of answer as any other failure: unreachable, never a different status that tells which labels exist
	offline := selfCheckPost(handler, `{"v":1,"label":"tsrqponmlkjihgfedcba","expect":[]}`)
	var gone map[string]any
	if offline.Code != http.StatusOK || json.Unmarshal(offline.Body.Bytes(), &gone) != nil || gone["ok"] != false || gone["reason"] != "unreachable" {
		t.Fatalf("%d %s", offline.Code, offline.Body.String())
	}
	for _, body := range []string{
		``, `{`, `[]`, `{"v":2,"label":"abcdefghijklmnopqrst","expect":[]}`, `{"v":1,"label":"short","expect":[]}`, `{"v":1,"label":"ABCDEFGHIJKLMNOPQRST","expect":[]}`,
		`{"v":1,"label":"abcdefghijklmnopqrst","expect":["short"]}`, `{"v":1,"label":"abcdefghijklmnopqrst","expect":[],"host":"evil.example"}`,
		`{"v":1,"label":"abcdefghijklmnopqrst","expect":[]} {}`, fmt.Sprintf(`{"v":1,"label":"abcdefghijklmnopqrst","expect":["%[1]s","%[1]s","%[1]s","%[1]s","%[1]s"]}`, strings.Repeat("A", 43)),
		`{"v":1,"label":"abcdefghijklmnopqrst","expect":[],"pad":"` + strings.Repeat("x", 2000) + `"}`,
	} {
		if refused := selfCheckPost(handler, body); refused.Code != http.StatusBadRequest {
			t.Fatalf("%q: %d %s", truncate(body), refused.Code, refused.Body.String())
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(method, "/selfcheck", nil))
		if recorder.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s: %d", method, recorder.Code)
		}
	}
}

func TestSelfCheckHandlerSpacesTheChecksOfOneLabelAndCapsTheOnesInFlight(t *testing.T) {
	authority := newSelfCheckAuthority(t, "root")
	leaf := authority.good(t)
	addr := serveSelfCheck(t, leaf, tls.VersionTLS13, okHealthz)
	cfg := SelfCheckConfig{Roots: authority.pool, Timeout: 5 * time.Second}
	lookup := func(label string) (string, bool) { return selfCheckHost, true }
	spaced := NewSelfCheckHandler(cfg, addr, lookup, ctLabelOK, time.Hour)
	body := func(label string) string {
		return fmt.Sprintf(`{"v":1,"label":"%s","expect":["%s"]}`, label, leaf.spki)
	}
	if first := selfCheckPost(spaced, body("abcdefghijklmnopqrst")); first.Code != http.StatusOK {
		t.Fatalf("%d %s", first.Code, first.Body.String())
	}
	if again := selfCheckPost(spaced, body("abcdefghijklmnopqrst")); again.Code != http.StatusTooManyRequests || !strings.Contains(again.Body.String(), `"busy"`) {
		t.Fatalf("a second check of the same label within the spacing: %d %s", again.Code, again.Body.String())
	}
	if other := selfCheckPost(spaced, body("tsrqponmlkjihgfedcba")); other.Code != http.StatusOK {
		t.Fatalf("another label is its own: %d", other.Code)
	}
	// at most selfCheckInFlight checks run at once, whatever labels they are for: the rest are busy, none waits
	release := make(chan struct{})
	started := make(chan struct{}, 16)
	slow := func(ctx context.Context, network, addr string) (net.Conn, error) {
		started <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil, context.Canceled
	}
	capped := NewSelfCheckHandler(SelfCheckConfig{Dial: slow, Roots: authority.pool, Timeout: 5 * time.Second}, addr, lookup, ctLabelOK, 0)
	var wg sync.WaitGroup
	results := make(chan int, 16)
	labels := []string{"aaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbb", "cccccccccccccccccccc", "dddddddddddddddddddd", "eeeeeeeeeeeeeeeeeeee", "ffffffffffffffffffff"}
	for _, label := range labels[:selfCheckInFlight] {
		wg.Add(1)
		go func(label string) {
			defer wg.Done()
			results <- selfCheckPost(capped, body(label)).Code
		}(label)
	}
	for range labels[:selfCheckInFlight] {
		<-started
	}
	if extra := selfCheckPost(capped, body(labels[selfCheckInFlight])); extra.Code != http.StatusTooManyRequests {
		t.Fatalf("one more than the cap: %d", extra.Code)
	}
	close(release)
	wg.Wait()
	close(results)
	for code := range results {
		if code != http.StatusOK {
			t.Fatalf("the checks in flight finish normally: %d", code)
		}
	}
}

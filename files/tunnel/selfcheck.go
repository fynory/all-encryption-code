package main

// Self-check (ALL 2.0, WP26; the design plan, section 6 point 4, the migration notes): before a computer is told to reconnect, somebody OUTSIDE the
// computer's own process dials its public name the way ChatGPT will, and says whether it works. The computer asks it of a node (the node is on the other side of
// the internet from the computer's own network), and the same function runs from the computer itself (the device's enrolment code) and from the operator's canary.
//
//	dial the public address, SNI = the computer's host, TLS 1.2 offered and 1.3 required
//	verify the chain against the public roots, the name and the validity at this moment
//	compare the leaf's SubjectPublicKeyInfo hash with the one the computer expects (a certificate that is not the computer's own key is not the computer)
//	GET /healthz through the same connection and read {"ok": true}
//
// The answer is contracts/schemas/selfcheck-result.schema.json: ok, the FIRST step that failed as one closed word (chain, expired, spki, name, tls_version, healthz,
// unreachable, timeout), the TLS version, the leaf's SPKI hash and its not_after. No host, no address, no free text: it can be shown, stored and sent as it is.
//
// What this file does NOT do: it does not decide who may ask, it has no listener of its own and it does not know the label registry. NewSelfCheckHandler is the
// HTTP shape (a POST with {v, label, expect}) for the operator's loopback port, with the per-label spacing and the cap on checks in flight that keep it from being
// a way to make the node dial itself; the route in server.go and the policy numbers (selfcheck.timeout_s, selfcheck.min_interval_s) are the node integration's (WP17).

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// The reasons, in the order the steps run. They are policy.enums.selfcheck_reason (the test pins that they are the same list).
const (
	selfCheckChain       = "chain"
	selfCheckExpired     = "expired"
	selfCheckSPKI        = "spki"
	selfCheckName        = "name"
	selfCheckTLSVersion  = "tls_version"
	selfCheckHealthz     = "healthz"
	selfCheckUnreachable = "unreachable"
	selfCheckTimeout     = "timeout"
)

// SelfCheckResult is the contract's selfcheck-result.
type SelfCheckResult struct {
	V          int     `json:"v"`
	OK         bool    `json:"ok"`
	Reason     *string `json:"reason"`
	TLSVersion *string `json:"tls_version"`
	SPKISHA256 *string `json:"spki_sha256"`
	NotAfter   *int64  `json:"not_after"`
	Healthz    bool    `json:"healthz"`
}

// SelfCheckConfig is what the check needs from outside. Nothing here has a default that is a number: the timeout is the caller's (the policy's).
type SelfCheckConfig struct {
	// Dial opens the transport to the public address; nil is a plain TCP dial.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Roots are the public roots the chain must lead to; nil is the system's.
	Roots *x509.CertPool
	// Now is the moment validity is judged at; nil is the clock.
	Now func() time.Time
	// Timeout bounds the whole check (dial, handshake and healthz); zero leaves it to the context.
	Timeout time.Duration
}

func selfCheckFail(res *SelfCheckResult, reason string) SelfCheckResult {
	res.OK = false
	res.Reason = &reason
	return *res
}

// SelfCheck dials addr ("host:port", the public address of the node or of the computer's name), speaks TLS as `host`, and judges what it finds. `expect` is the set
// of SPKI hashes (SHA-256, base64url, no padding) the computer may be serving; empty means "any" (the operator's canary asks only whether the chain is good).
func SelfCheck(ctx context.Context, cfg SelfCheckConfig, addr, host string, expect []string) SelfCheckResult {
	res := SelfCheckResult{V: 1}
	if cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.Timeout)
		defer cancel()
	}
	dial := cfg.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	conn, err := dial(ctx, "tcp", addr)
	if err != nil {
		return selfCheckFail(&res, networkReason(ctx, err))
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	now := time.Now
	if cfg.Now != nil {
		now = cfg.Now
	}

	// Every step that can fail inside the handshake records its reason here before it refuses the connection: the standard library would otherwise report them all as one
	// "certificate" error, and an operator needs to know which of the four it was.
	var found string
	verify := func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			found = selfCheckChain
			return errors.New("no certificate")
		}
		leaf := state.PeerCertificates[0]
		sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		spki := base64.RawURLEncoding.EncodeToString(sum[:])
		notAfter := leaf.NotAfter.Unix()
		res.SPKISHA256, res.NotAfter = &spki, &notAfter
		version := tlsVersionText(state.Version)
		res.TLSVersion = &version
		if state.Version != tls.VersionTLS13 {
			found = selfCheckTLSVersion
			return errors.New("tls version")
		}
		intermediates := x509.NewCertPool()
		for _, extra := range state.PeerCertificates[1:] {
			intermediates.AddCert(extra)
		}
		if _, verr := leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: cfg.Roots, Intermediates: intermediates, CurrentTime: now()}); verr != nil {
			found = verifyReason(verr)
			return verr
		}
		if len(expect) > 0 && !containsText(expect, spki) {
			found = selfCheckSPKI
			return errors.New("spki")
		}
		return nil
	}
	secure := tls.Client(conn, &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		// The verification is VerifyConnection above, so that every failure has its own reason; nothing is accepted that it refuses.
		InsecureSkipVerify: true,
		VerifyConnection:   verify,
	})
	if err := secure.HandshakeContext(ctx); err != nil {
		if found != "" {
			return selfCheckFail(&res, found)
		}
		if strings.Contains(err.Error(), "protocol version") {
			return selfCheckFail(&res, selfCheckTLSVersion)
		}
		return selfCheckFail(&res, networkReason(ctx, err))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/healthz", nil)
	if err != nil {
		return selfCheckFail(&res, selfCheckHealthz)
	}
	req.Header.Set("User-Agent", "all-tunnel-selfcheck")
	req.Close = true
	if err := req.Write(secure); err != nil {
		return selfCheckFail(&res, networkReason(ctx, err))
	}
	response, err := http.ReadResponse(bufio.NewReader(io.LimitReader(secure, 64<<10)), req)
	if err != nil {
		return selfCheckFail(&res, networkReasonOr(ctx, err, selfCheckHealthz))
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4<<10))
	if err != nil {
		return selfCheckFail(&res, networkReasonOr(ctx, err, selfCheckHealthz))
	}
	var health struct {
		OK *bool `json:"ok"`
	}
	if response.StatusCode != http.StatusOK || json.Unmarshal(body, &health) != nil || health.OK == nil || !*health.OK {
		return selfCheckFail(&res, selfCheckHealthz)
	}
	res.Healthz = true
	res.OK = true
	return res
}

func tlsVersionText(version uint16) string {
	if version == tls.VersionTLS13 {
		return "1.3"
	}
	return "1.2"
}

func containsText(list []string, text string) bool {
	for _, item := range list {
		if item == text {
			return true
		}
	}
	return false
}

// verifyReason is the first of the three things x509 checks that is wrong: the validity, the name, or the chain (an unknown authority, a bad signature, a certificate
// that is not for a server, anything else).
func verifyReason(err error) string {
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
		return selfCheckExpired
	}
	var wrongName x509.HostnameError
	if errors.As(err, &wrongName) {
		return selfCheckName
	}
	return selfCheckChain
}

func networkReason(ctx context.Context, err error) string {
	return networkReasonOr(ctx, err, selfCheckUnreachable)
}

// networkReasonOr is `timeout` when the time ran out (the context, a deadline on the connection, a net.Error that says so) and `otherwise` for every other way a
// connection can end.
func networkReasonOr(ctx context.Context, err error, otherwise string) string {
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) || ctx.Err() != nil || (errors.As(err, &netErr) && netErr.Timeout()) {
		return selfCheckTimeout
	}
	return otherwise
}

// ---- the HTTP shape --------------------------------------------------------------------------------------------------------------------------

// selfCheckRequest is {"v": 1, "label": "...", "expect": ["<spki>", ...]}; nothing else is accepted.
type selfCheckRequest struct {
	V      int      `json:"v"`
	Label  string   `json:"label"`
	Expect []string `json:"expect"`
}

const (
	selfCheckBodyMax    = 1024
	selfCheckExpectMax  = 4
	selfCheckSPKILength = 43
	selfCheckInFlight   = 4
)

// NewSelfCheckHandler is POST {v, label, expect} -> selfcheck-result, for a port that is not public (the operator's loopback listener). `lookup` says which host a label
// stands for on this node and whether its computer is connected (an unknown or offline label is an `unreachable` answer, never an error that tells which); `labelOK`
// is the label pattern of the policy. A label is checked at most once per `minInterval` and at most selfCheckInFlight checks run at once: a loop of requests is a
// 429, never a flood of dials.
func NewSelfCheckHandler(cfg SelfCheckConfig, addr string, lookup func(label string) (host string, ok bool), labelOK func(string) bool, minInterval time.Duration) http.Handler {
	var mu sync.Mutex
	last := map[string]time.Time{}
	slots := make(chan struct{}, selfCheckInFlight)
	reply := func(w http.ResponseWriter, status int, value any) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(value)
	}
	refuse := func(w http.ResponseWriter, status int, word string) {
		reply(w, status, map[string]any{"ok": false, "error": word})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			refuse(w, http.StatusMethodNotAllowed, "invalid_request")
			return
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, selfCheckBodyMax))
		decoder.DisallowUnknownFields()
		var asked selfCheckRequest
		if err := decoder.Decode(&asked); err != nil || decoder.More() || asked.V != 1 || !labelOK(asked.Label) || len(asked.Expect) > selfCheckExpectMax {
			refuse(w, http.StatusBadRequest, "invalid_request")
			return
		}
		for _, spki := range asked.Expect {
			if len(spki) != selfCheckSPKILength {
				refuse(w, http.StatusBadRequest, "invalid_request")
				return
			}
		}
		mu.Lock()
		if at, seen := last[asked.Label]; seen && time.Since(at) < minInterval {
			mu.Unlock()
			refuse(w, http.StatusTooManyRequests, "busy")
			return
		}
		select {
		case slots <- struct{}{}:
			last[asked.Label] = time.Now()
			if len(last) > 4096 {
				for label, at := range last {
					if time.Since(at) >= minInterval {
						delete(last, label)
					}
				}
			}
			mu.Unlock()
		default:
			mu.Unlock()
			refuse(w, http.StatusTooManyRequests, "busy")
			return
		}
		defer func() { <-slots }()
		host, online := lookup(asked.Label)
		if !online {
			reason := selfCheckUnreachable
			reply(w, http.StatusOK, SelfCheckResult{V: 1, Reason: &reason})
			return
		}
		reply(w, http.StatusOK, SelfCheck(r.Context(), cfg, addr, host, asked.Expect))
	})
}

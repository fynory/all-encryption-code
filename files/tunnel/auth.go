package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Device authentication of protocol v2 (the contract, section 3): the node verifies the device's session JWT offline against the control
// plane's keys, makes the device prove it holds the session's key (a DPoP proof over the NODE's URL and a nonce the node just made), and then asks
// the control plane what the device is allowed: the host, the status and how long. Nothing a device sends names a host.

// A token problem is one closed word. The words and their order are those of the contracts' verifiers (tests run every golden vector through
// the functions below).
const (
	tokMalformed     = "malformed_token"
	tokBadAlg        = "bad_alg"
	tokUnknownKID    = "unknown_kid"
	tokBadSignature  = "bad_signature"
	tokWrongType     = "wrong_type"
	tokWrongIssuer   = "wrong_issuer"
	tokWrongAudience = "wrong_audience"
	tokWrongKey      = "wrong_key"
	tokWrongSubject  = "wrong_subject"
	tokWrongHTM      = "wrong_htm"
	tokWrongHTU      = "wrong_htu"
	tokWrongATH      = "wrong_ath"
	tokWrongNonce    = "wrong_nonce"
	tokBadClaims     = "bad_claims"
	tokBadLifetime   = "bad_lifetime"
	tokNotYetValid   = "not_yet_valid"
	tokExpired       = "expired"
	tokStaleProof    = "stale_proof"
	tokReplayedJTI   = "replayed_jti"
)

type tokenError struct{ word string }

func (e *tokenError) Error() string { return e.word }

func tokFail(word string) error { return &tokenError{word} }

// tokenWord is the closed word of a token error ("" when err is nil).
func tokenWord(err error) string {
	if err == nil {
		return ""
	}
	if te, ok := err.(*tokenError); ok {
		return te.word
	}
	return tokMalformed
}

// errFor turns a token word into the ERR a refused HELLO, RENEW or PROOF is answered with, as the reference node of the contracts does: a clock that
// is off is clock_skew (the device shows it), a malformed token is bad_hello, a token for another audience or an expired one is auth, and every other
// word is the fallback (auth for a session, bad_proof for a proof) because nothing else may be told to a device that failed.
func errFor(word, fallback string) string {
	switch word {
	case tokMalformed:
		return codeBadHello
	case tokNotYetValid, tokStaleProof:
		return codeClockSkew
	case tokWrongAudience, tokExpired:
		return codeAuth
	}
	return fallback
}

type jws struct {
	header, claims map[string]any
	signature      []byte
	signingInput   []byte
}

// splitJWS splits and decodes a compact JWS. Any structural fault is malformed_token: ASCII only, three dot-separated base64url segments with no
// padding and canonical encoding, header and claims JSON objects without a repeated key and without a fraction, none of the headers that change
// how a signature is read (crit, b64, jku, x5u, x5c). An empty signature part is allowed here (alg none then fails as bad_alg, the more useful word).
func splitJWS(token string, maxBytes int) (*jws, error) {
	if len(token) > maxBytes {
		return nil, tokFail(tokMalformed)
	}
	for i := 0; i < len(token); i++ {
		if token[i] > 0x7f {
			return nil, tokFail(tokMalformed)
		}
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, tokFail(tokMalformed)
	}
	decode := func(text string) (map[string]any, bool) {
		raw, err := b64Decode(text)
		if err != nil {
			return nil, false
		}
		value, err := parseJSON(string(raw))
		if err != nil {
			return nil, false
		}
		object, ok := value.(map[string]any)
		return object, ok
	}
	header, ok1 := decode(parts[0])
	claims, ok2 := decode(parts[1])
	if !ok1 || !ok2 {
		return nil, tokFail(tokMalformed)
	}
	var signature []byte
	if parts[2] != "" {
		raw, err := b64Decode(parts[2])
		if err != nil {
			return nil, tokFail(tokMalformed)
		}
		signature = raw
	}
	for _, name := range []string{"crit", "b64", "jku", "x5u", "x5c"} {
		if _, present := header[name]; present {
			return nil, tokFail(tokMalformed)
		}
	}
	return &jws{header, claims, signature, []byte(parts[0] + "." + parts[1])}, nil
}

func verifyEd25519(key ed25519.PublicKey, signature, input []byte) bool {
	return len(signature) == ed25519.SignatureSize && len(key) == ed25519.PublicKeySize && ed25519.Verify(key, input, signature)
}

func claimInt(claims map[string]any, key string) (int64, bool) {
	f, ok := claims[key].(float64)
	if !ok || f != float64(int64(f)) {
		return 0, false
	}
	return int64(f), true
}

func claimString(claims map[string]any, key string) (string, bool) {
	s, ok := claims[key].(string)
	return s, ok
}

// epochClaim reads an epoch-seconds claim in the contracts' range.
func epochClaim(claims map[string]any, key string) (int64, bool) {
	n, ok := epochOK(claims[key])
	return n, ok
}

// SessionClaims are the claims of a verified device session the node keeps for the life of a connection.
type SessionClaims struct {
	Subject    string // the device id
	JTI        string
	Generation int64
	IssuedAt   int64
	ExpiresAt  int64
	KeyX       string // the session's bound key (cnf.jwk.x): the key a proof must be signed with
}

func epochSeconds(t time.Time) float64 { return float64(t.UnixNano()) / 1e9 }

// publicJWKOK is the contracts' public JWK: OKP, Ed25519, an x of 43 canonical characters, no private part.
func publicJWKX(value any) (string, bool) {
	jwk, ok := value.(map[string]any)
	if !ok {
		return "", false
	}
	x, hasX := jwk["x"].(string)
	if _, private := jwk["d"]; private || jwk["kty"] != "OKP" || jwk["crv"] != "Ed25519" || !hasX {
		return "", false
	}
	if _, ok := publicKeyX(x); !ok {
		return "", false
	}
	return x, true
}

// verifySession verifies a device session offline: the signature before any claim is trusted, then the audience (the node accepts only
// all-tunnel: the relay's and the control plane's audiences and a missing audience are refused), the lifetime (exactly the policy's session TTL) and the clock within skew.
// The words, in the order the checks fail: malformed_token, bad_alg, unknown_kid, bad_signature, wrong_type, wrong_issuer, wrong_audience,
// bad_claims, bad_lifetime, not_yet_valid, expired.
func verifySession(token string, now time.Time, keys KeySource, skew time.Duration) (*SessionClaims, error) {
	if len(token) > policyData.Protocol.JWTMaxBytes {
		return nil, tokFail(tokMalformed)
	}
	j, err := splitJWS(token, policyData.Protocol.JWTMaxBytes)
	if err != nil {
		return nil, err
	}
	if j.header["alg"] != "EdDSA" {
		return nil, tokFail(tokBadAlg)
	}
	kid, isString := j.header["kid"].(string)
	if !isString || !reKID.MatchString(kid) {
		return nil, tokFail(tokUnknownKID)
	}
	key, known := keys.Key(kid)
	if !known {
		return nil, tokFail(tokUnknownKID)
	}
	if !verifyEd25519(key, j.signature, j.signingInput) {
		return nil, tokFail(tokBadSignature)
	}
	c := j.claims
	if j.header["typ"] != "device-session" || c["typ"] != "device-session" {
		return nil, tokFail(tokWrongType)
	}
	if ver, ok := claimInt(c, "ver"); !ok || ver != int64(policyData.Protocol.Version) {
		return nil, tokFail(tokWrongType)
	}
	if c["iss"] != policyData.Identity.Issuer {
		return nil, tokFail(tokWrongIssuer)
	}
	if c["aud"] != policyData.Identity.AudTunnel {
		return nil, tokFail(tokWrongAudience)
	}
	sub, subOK := claimString(c, "sub")
	jti, jtiOK := claimString(c, "jti")
	iat, iatOK := epochClaim(c, "iat")
	exp, expOK := epochClaim(c, "exp")
	generation, genOK := claimInt(c, "generation")
	x, cnfOK := "", false
	if cnf, ok := c["cnf"].(map[string]any); ok && len(cnf) == 1 {
		if jwk, ok := cnf["jwk"].(map[string]any); ok && len(jwk) == 3 {
			x, cnfOK = publicJWKX(jwk)
		}
	}
	if !subOK || !reDeviceID.MatchString(sub) || !jtiOK || !reJTI.MatchString(jti) || !iatOK || !expOK || !genOK || generation < 1 || generation > 1<<53-1 || !cnfOK {
		return nil, tokFail(tokBadClaims)
	}
	if exp-iat != int64(policyData.Authorization.SessionTTLS) {
		return nil, tokFail(tokBadLifetime)
	}
	t := epochSeconds(now)
	if float64(iat) > t+skew.Seconds() {
		return nil, tokFail(tokNotYetValid)
	}
	if float64(exp) <= t {
		return nil, tokFail(tokExpired)
	}
	return &SessionClaims{Subject: sub, JTI: jti, Generation: generation, IssuedAt: iat, ExpiresAt: exp, KeyX: x}, nil
}

func sha256B64(data []byte) string {
	sum := sha256.Sum256(data)
	return b64Encode(sum[:])
}

// nodeProofURL is the htu a proof must carry: https://<node host>[:<port> when it is not 443]/all-tunnel/2.
func nodeProofURL(host string, port int) string {
	u := "https://" + host
	if port != 443 {
		u += ":" + strconv.Itoa(port)
	}
	return u + policyData.Protocol.ProofHTUPath
}

// proofClaims is what a verified proof leaves the node: the jti, to be spent once.
type proofClaims struct {
	JTI      string
	IssuedAt int64
}

// verifyProof verifies the DPoP proof of the session the connection said it holds: signed by the session's bound key, for this session (ath),
// this node's URL (htu), this exchange (the nonce the node made) and this moment (iat within the policy's proof TTL). The jti is NOT spent here: the
// caller spends it (replayCache.spend) so that a replay is refused even between two connections. Words, in order: malformed_token, bad_alg,
// wrong_type, wrong_key, bad_signature, wrong_subject, wrong_audience, wrong_htm, wrong_htu, wrong_ath, wrong_nonce, bad_claims, not_yet_valid,
// stale_proof.
func verifyProof(proof string, now time.Time, sessionToken string, session *SessionClaims, nonce, htu string, skew time.Duration) (*proofClaims, error) {
	if len(proof) > policyData.Protocol.JWTMaxBytes {
		return nil, tokFail(tokMalformed)
	}
	j, err := splitJWS(proof, policyData.Protocol.JWTMaxBytes)
	if err != nil {
		return nil, err
	}
	if j.header["alg"] != "EdDSA" {
		return nil, tokFail(tokBadAlg)
	}
	if j.header["typ"] != "dpop+jwt" {
		return nil, tokFail(tokWrongType)
	}
	x, ok := publicJWKX(j.header["jwk"])
	if !ok {
		return nil, tokFail(tokMalformed)
	}
	if x != session.KeyX {
		return nil, tokFail(tokWrongKey)
	}
	key, _ := publicKeyX(x)
	if !verifyEd25519(key, j.signature, j.signingInput) {
		return nil, tokFail(tokBadSignature)
	}
	c := j.claims
	switch {
	case c["sub"] != session.Subject:
		return nil, tokFail(tokWrongSubject)
	case c["aud"] != policyData.Identity.AudTunnel:
		return nil, tokFail(tokWrongAudience)
	case c["htm"] != policyData.Protocol.ProofHTM:
		return nil, tokFail(tokWrongHTM)
	case c["htu"] != htu:
		return nil, tokFail(tokWrongHTU)
	case c["ath"] != sha256B64([]byte(sessionToken)):
		return nil, tokFail(tokWrongATH)
	case c["nonce"] != nonce:
		return nil, tokFail(tokWrongNonce)
	}
	jti, jtiOK := claimString(c, "jti")
	iat, iatOK := epochClaim(c, "iat")
	if !jtiOK || !reJTI.MatchString(jti) || !iatOK {
		return nil, tokFail(tokBadClaims)
	}
	t := epochSeconds(now)
	if float64(iat) > t+skew.Seconds() {
		return nil, tokFail(tokNotYetValid)
	}
	if float64(iat+int64(policyData.Authorization.ProofTTLS)) <= t {
		return nil, tokFail(tokStaleProof)
	}
	return &proofClaims{JTI: jti, IssuedAt: iat}, nil
}

// replayCache remembers the proofs the node has accepted until they could not verify any more (a proof is single use for the policy's proof TTL,
// plus the skew a fast clock is allowed). A session's jti is NOT single use: a cached session reconnects. The cache is bounded: when it is full of
// live entries a new proof is refused (the connection gets bad_proof), never admitted unchecked.
type replayCache struct {
	mu    sync.Mutex
	seen  map[string]time.Time // jti -> when it can be forgotten
	limit int
}

func newReplayCache(limit int) *replayCache {
	return &replayCache{seen: map[string]time.Time{}, limit: limit}
}

// spend records a proof jti issued at iat. It reports false when the jti was already spent (or the cache is full of live entries).
func (r *replayCache) spend(jti string, iat int64, now time.Time, skew time.Duration) bool {
	forget := time.Unix(iat, 0).Add(secs(policyData.Authorization.ProofTTLS) + skew)
	r.mu.Lock()
	defer r.mu.Unlock()
	if until, dup := r.seen[jti]; dup && now.Before(until) {
		return false
	}
	if len(r.seen) >= r.limit {
		for id, until := range r.seen {
			if !now.Before(until) {
				delete(r.seen, id)
			}
		}
		if len(r.seen) >= r.limit {
			return false
		}
	}
	r.seen[jti] = forget
	return true
}

func (r *replayCache) size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.seen)
}

// ControlPlane is the node's side of POST /v1/tunnel/authorize: what the control plane decides for a device whose session the node verified. The
// request never carries a host name; the answer's host, status and valid_until are what the node relays. The real client (node assertion, retry,
// concurrency cap, grace) is the control-plane piece; the node core is written against this interface and tested with a fake.
type ControlPlane interface {
	Authorize(ctx context.Context, req AuthorizeRequest) (AuthorizeResponse, error)
}

// AuthorizeRequest is authorize-request.schema.json.
type AuthorizeRequest struct {
	DeviceID   string
	SessionJTI string
	Reason     string // "hello" or "renew"
	Node       string
}

func (r AuthorizeRequest) toMap() map[string]any {
	return map[string]any{"v": 1, "device_id": r.DeviceID, "session_jti": r.SessionJTI, "reason": r.Reason, "node": r.Node}
}

// AuthorizeResponse is the 200 answer of authorize (authorize-response.schema.json): the node uses Host, Status, ValidUntil, ServerTime and the
// Policy windows; the rest travels to the pieces that need it.
type AuthorizeResponse struct {
	DeviceID   string
	Label      string
	Host       string
	Status     string // active, gated or paused
	Plan       string // paid or trial
	ValidUntil int64  // epoch seconds
	ServerTime int64
	Policy     okPolicy
	Access     string // the signed access statement, when the answer has one
	Nodes      any    // the signed list of nodes, opaque to this piece
	E2EWave    int
	E2EKill    bool
	CopyE2EE   bool
}

func (a AuthorizeResponse) toMap() map[string]any {
	m := map[string]any{"ok": true, "v": 1, "device_id": a.DeviceID, "label": a.Label, "host": a.Host, "status": a.Status, "plan": a.Plan,
		"valid_until": a.ValidUntil, "server_time": a.ServerTime, "policy": a.Policy.toMap(), "e2e_wave": a.E2EWave, "e2e_kill": a.E2EKill,
		"copy_e2ee": a.CopyE2EE}
	if a.Nodes != nil {
		m["nodes"] = a.Nodes
	}
	if a.Access != "" {
		m["access"] = a.Access
	}
	return m
}

// ControlError is a refusal of authorize: the HTTP status and the closed word of the error body (license_inactive, device_revoked, ...). A transport
// failure or a timeout is any other error: the node answers control_unavailable.
type ControlError struct {
	Status int
	Code   string
}

func (e *ControlError) Error() string { return fmt.Sprintf("authorize: %d %s", e.Status, e.Code) }

// errForControl is the ERR word of a failed authorize.
func errForControl(err error) string {
	ce, ok := err.(*ControlError)
	if !ok {
		return codeControlUnavailable
	}
	if ce.Status >= 500 || ce.Status == 429 || ce.Status < 400 {
		return codeControlUnavailable
	}
	switch ce.Code {
	case codeLicenseInactive, codeDeviceRevoked, codePaused:
		return ce.Code
	case "unauthorized", "invalid_authorize_request", "request_too_large", "bad_response":
		// The control plane refused the NODE (its assertion, its request), not the device: nothing the device can fix, so "try later", never "auth".
		return codeControlUnavailable
	}
	return codeAuth
}

// checkAuthorize refuses an answer that is not what was asked: another device's, a host that is not exactly one label under a zone or does not start
// with the answer's own label, an unknown status or plan, windows out of range. The node never relays an answer it cannot vouch for.
func checkAuthorize(a AuthorizeResponse, req AuthorizeRequest) error {
	switch {
	case a.DeviceID != req.DeviceID:
		return fmt.Errorf("authorize answer is for another device")
	case !reLabel.MatchString(a.Label), !validFQDN(a.Host), !strings.HasPrefix(a.Host, a.Label+"."):
		return fmt.Errorf("authorize answer has a bad host")
	case !validStatus(a.Status):
		return fmt.Errorf("authorize answer has a bad status")
	case a.Plan != "paid" && a.Plan != "trial":
		return fmt.Errorf("authorize answer has a bad plan")
	case a.ValidUntil < 1 || a.ValidUntil > epochMax || a.ServerTime < 1 || a.ServerTime > epochMax:
		return fmt.Errorf("authorize answer has a bad time")
	}
	for _, v := range []int64{a.Policy.PingIntervalS, a.Policy.DeadPeerS, a.Policy.StreamIdleS, a.Policy.StreamMaxAgeS, a.Policy.RenewBeforeValidUntilS} {
		if v < 1 || v > 86400 {
			return fmt.Errorf("authorize answer has a bad policy window")
		}
	}
	return nil
}

// boundWindows bounds the windows of the answer to policy.json: the node never offers a device a window longer than the table's own. (The control
// plane builds them from the same table, so this changes nothing for an honest answer.)
func boundWindows(p okPolicy) okPolicy {
	t := policyData.Timing
	return okPolicy{
		PingIntervalS:          min(p.PingIntervalS, int64(t.PingIntervalS)),
		DeadPeerS:              min(p.DeadPeerS, int64(t.DeadPeerS)),
		StreamIdleS:            min(p.StreamIdleS, int64(t.StreamIdleS)),
		StreamMaxAgeS:          min(p.StreamMaxAgeS, int64(t.StreamMaxAgeS)),
		RenewBeforeValidUntilS: min(p.RenewBeforeValidUntilS, int64(t.RenewBeforeValidUntilS)),
	}
}

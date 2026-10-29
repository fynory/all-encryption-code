package main

import (
	"bufio"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Protocol v2 on the wire (the contract, section 2, contracts/schemas/wire-v2.grammar.json). A line is ASCII 0x20-0x7e ended by LF, fields
// are separated by exactly one space and none is empty. Two kinds of connection are told apart by the first line: a control connection (HELLO) and a
// data connection (ATTACH, one per client stream).

// Error words of ERR lines (policy protocol.error_codes) and the words of the node's own decisions.
const (
	codeBadHello           = "bad_hello"
	codeBadCommand         = "bad_command"
	codeUnsupportedVersion = "unsupported_version"
	codeBadProof           = "bad_proof"
	codeAuth               = "auth"
	codeClockSkew          = "clock_skew"
	codeUnknownStream      = "unknown_stream"
	codeBadAttach          = "bad_attach"
	codeLicenseInactive    = "license_inactive"
	codeDeviceRevoked      = "device_revoked"
	codePaused             = "paused"
	codeBusy               = "busy"
	codeControlUnavailable = "control_unavailable"
	codeLineTooLong        = "line_too_long"
)

// Reasons of a CLOSE line (policy protocol.close_reasons) the node sends.
const (
	closeReplaced = "replaced"
	closeRevoked  = "revoked"
	closeExpired  = "expired"
	closeIdle     = "idle"
	closeProtocol = "protocol"
	closeShutdown = "shutdown"
	closeReleased = "released"
	closeKilled   = "killed"
	closeDrain    = "drain"
	closePaused   = "paused"
)

// Classes of the source of a client stream (policy protocol.source_classes).
const (
	classOpenAI = "openai"
	classHint   = "hint"
	classAnon   = "anon"
)

// Direction of a line: d2n is device to node, n2d is node to device, both is CLOSE.
const (
	dirD2N  = "d2n"
	dirN2D  = "n2d"
	dirBoth = "both"
)

// protoError is a refused line: code is the word of the ERR the node answers with.
type protoError struct{ code string }

func (e *protoError) Error() string { return e.code }

func protoFail(code string) error { return &protoError{code} }

// errCode is the ERR word of an error: its own when it is a protoError, line_too_long for an over-long line, bad_command otherwise.
func errCode(err error) string {
	var pe *protoError
	if errors.As(err, &pe) {
		return pe.code
	}
	if errors.Is(err, bufio.ErrBufferFull) {
		return codeLineTooLong
	}
	return codeBadCommand
}

// message is one parsed line: {"verb": ..., <field>: ...}. HINT gives "addresses" ([]any of strings) and OK gives "body".
type message map[string]any

func (m message) str(key string) string { s, _ := m[key].(string); return s }

type fieldSpec struct {
	name, kind string
	err        string // ERR word when the field is wrong (default bad_command)
}

type verbSpec struct {
	dir      string
	max      int // longest line, LF included; 0 = protocol.line_max_bytes
	fields   []fieldSpec
	optional []fieldSpec
	repeat   *fieldSpec // HINT: one to hint_max_addresses of the same kind
	json     bool       // OK: the rest of the line is one canonical JSON object
}

// verbs is wire-v2.grammar.json, written out. protocol_test.go runs every vector of contracts/vectors/lines.json through it.
var verbs = map[string]verbSpec{
	"HELLO": {dir: dirD2N, fields: []fieldSpec{{"version", "version", ""}, {"session", "jwt", codeBadHello}}},
	"PROOF": {dir: dirD2N, fields: []fieldSpec{{"proof", "jwt", codeBadProof}}},
	"RENEW": {dir: dirD2N, fields: []fieldSpec{{"session", "jwt", codeBadHello}}},
	"PING":  {dir: dirD2N},
	"HINT":  {dir: dirD2N, repeat: &fieldSpec{"address", "ip", ""}},
	"CLOSE": {dir: dirBoth, optional: []fieldSpec{{"reason", "close_reason", ""}}},
	"ATTACH": {dir: dirD2N, fields: []fieldSpec{
		{"stream_id", "stream_id", codeBadAttach},
		{"secret", "attach_secret", codeBadAttach},
	}},
	"CHALLENGE": {dir: dirN2D, fields: []fieldSpec{{"nonce", "nonce", ""}}},
	"OK":        {dir: dirN2D, json: true},
	"ERR":       {dir: dirN2D, fields: []fieldSpec{{"code", "error_code", ""}}},
	"OPEN": {dir: dirN2D, max: policyData.Protocol.OpenLineMaxBytes, fields: []fieldSpec{
		{"stream_id", "stream_id", ""},
		{"secret", "attach_secret", ""},
		{"peer_ip", "ip", ""},
		{"class", "source_class", ""},
	}},
	"PONG":      {dir: dirN2D},
	"STATEMENT": {dir: dirN2D, max: policyData.Protocol.StatementLineMaxBytes, fields: []fieldSpec{{"statement", "statement", ""}}},
	"DRAIN":     {dir: dirN2D, fields: []fieldSpec{{"quiet_s", "seconds", ""}}},
}

// isJWSShape is the textual shape of a compact JWS: three non-empty base64url segments.
func isJWSShape(s string) bool {
	dots := 0
	segment := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '.':
			if segment == 0 {
				return false
			}
			dots++
			segment = 0
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
			segment++
		default:
			return false
		}
	}
	return dots == 2 && segment > 0
}

// validIP is the contracts' address: IPv4 dotted quad without leading zeros or RFC 4291 text in lower case, no zone, no brackets.
func validIP(s string) bool {
	if s == "" || s != strings.ToLower(s) || strings.ContainsAny(s, "%[] \t\r\n/") {
		return false
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}

func fieldOK(kind, token string) bool {
	switch kind {
	case "version":
		return len(token) >= 1 && len(token) <= 3 && allDigits(token)
	case "jwt":
		return len(token) <= policyData.Protocol.JWTMaxBytes && isJWSShape(token)
	case "statement":
		return isJWSShape(token)
	case "nonce":
		return reNonce.MatchString(token)
	case "stream_id":
		return reStreamID.MatchString(token)
	case "attach_secret":
		return reSecret.MatchString(token)
	case "ip":
		return validIP(token)
	case "source_class":
		return inList(policyData.Protocol.SourceClasses, token)
	case "close_reason":
		return inList(policyData.Protocol.CloseReasons, token)
	case "error_code":
		return inList(policyData.Protocol.ErrorCodes, token)
	case "seconds":
		return token == "0" || (len(token) <= 6 && token[0] != '0' && allDigits(token))
	}
	return false
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// parseLine parses one protocol line (the text before the LF) travelling in dir ("d2n" or "n2d"). The error is a *protoError whose code is the word
// the node answers with.
func parseLine(line, dir string) (message, error) {
	for i := 0; i < len(line); i++ {
		if line[i] < 0x20 || line[i] > 0x7e {
			return nil, protoFail(codeBadCommand)
		}
	}
	verb, rest, hasSpace := strings.Cut(line, " ")
	spec, known := verbs[verb]
	limit := policyData.Protocol.LineMaxBytes
	if known && spec.max > 0 {
		limit = spec.max
	}
	if len(line)+1 > limit {
		return nil, protoFail(codeLineTooLong)
	}
	if !known || (spec.dir != dir && spec.dir != dirBoth) || line == "" || (hasSpace && rest == "") {
		return nil, protoFail(codeBadCommand)
	}
	out := message{"verb": verb}
	if spec.json {
		if !hasSpace {
			return nil, protoFail(codeBadCommand)
		}
		body, err := parseJSON(rest)
		if err != nil || checkOKBody(body) != nil {
			return nil, protoFail(codeBadCommand)
		}
		out["body"] = body
		return out, nil
	}
	var tokens []string
	if hasSpace {
		tokens = strings.Split(rest, " ")
	}
	for _, token := range tokens {
		if token == "" {
			return nil, protoFail(codeBadCommand)
		}
	}
	if spec.repeat != nil {
		if len(tokens) < 1 || len(tokens) > policyData.Protocol.HintMaxAddresses {
			return nil, protoFail(codeBadCommand)
		}
		addresses := make([]any, len(tokens))
		for i, token := range tokens {
			if !fieldOK(spec.repeat.kind, token) {
				return nil, protoFail(codeBadCommand)
			}
			addresses[i] = token
		}
		out["addresses"] = addresses
		return out, nil
	}
	rules := append(append([]fieldSpec{}, spec.fields...), spec.optional...)
	if len(tokens) < len(spec.fields) || len(tokens) > len(rules) {
		return nil, protoFail(codeBadCommand)
	}
	for i, token := range tokens {
		rule := rules[i]
		if verb == "HELLO" && rule.name == "version" {
			// the protocol version is 2: another number is unsupported_version, anything else is a malformed line
			if token != strconv.Itoa(policyData.Protocol.Version) {
				if fieldOK(rule.kind, token) {
					return nil, protoFail(codeUnsupportedVersion)
				}
				return nil, protoFail(codeBadCommand)
			}
		} else if !fieldOK(rule.kind, token) {
			code := rule.err
			if code == "" {
				code = codeBadCommand
			}
			return nil, protoFail(code)
		}
		out[rule.name] = token
	}
	return out, nil
}

// formatLine is the canonical line (without LF) of a message the node sends; it parses its own output, so a node can never write a line its
// own grammar refuses.
func formatLine(m message) string {
	verb := m.str("verb")
	spec := verbs[verb]
	var line string
	switch {
	case spec.json:
		line = verb + " " + canonicalJSON(m["body"])
	case spec.repeat != nil:
		parts := []string{verb}
		for _, address := range m["addresses"].([]any) {
			parts = append(parts, address.(string))
		}
		line = strings.Join(parts, " ")
	default:
		parts := []string{verb}
		for _, rule := range append(append([]fieldSpec{}, spec.fields...), spec.optional...) {
			if v, ok := m[rule.name]; ok {
				parts = append(parts, v.(string))
			}
		}
		line = strings.Join(parts, " ")
	}
	dir := spec.dir
	if dir == dirBoth {
		dir = dirD2N
	}
	if _, err := parseLine(line, dir); err != nil {
		panic("tunnel: formatted a line its own grammar refuses: " + verb + ": " + err.Error())
	}
	return line
}

// statementLine is the STATEMENT the node forwards, or "" when the statement is not one the grammar allows (too long, not a JWS): it is then dropped,
// never written, never a panic. The statement itself is the control plane's signed access statement; the node passes it on as it is.
func statementLine(statement string) string {
	line := "STATEMENT " + statement
	if _, err := parseLine(line, dirN2D); err != nil {
		return ""
	}
	return line
}

// drainLine tells a device the node is going down and how long it keeps its open streams.
func drainLine(quiet time.Duration) string {
	return formatLine(message{"verb": "DRAIN", "quiet_s": strconv.Itoa(int(quiet / time.Second))})
}

func errLine(code string) string { return formatLine(message{"verb": "ERR", "code": code}) }

func closeLine(reason string) string {
	if reason == "" {
		return "CLOSE"
	}
	return formatLine(message{"verb": "CLOSE", "reason": reason})
}

// okBody is what an OK answers: the control plane's decision, relayed (the contract, section 2). Host, status, valid_until and
// server_time are what the control plane answered; policy is that answer's windows, bounded by policy.json.
type okBody struct {
	Node       string
	Host       string
	Status     string
	ValidUntil int64
	ServerTime int64
	Policy     okPolicy
}

type okPolicy struct {
	PingIntervalS, DeadPeerS, StreamIdleS, StreamMaxAgeS, RenewBeforeValidUntilS int64
}

func (p okPolicy) toMap() map[string]any {
	return map[string]any{"ping_interval_s": p.PingIntervalS, "dead_peer_s": p.DeadPeerS, "stream_idle_s": p.StreamIdleS,
		"stream_max_age_s": p.StreamMaxAgeS, "renew_before_valid_until_s": p.RenewBeforeValidUntilS}
}

func (b okBody) line() string {
	return formatLine(message{"verb": "OK", "body": map[string]any{"v": policyData.Protocol.Version, "node": b.Node, "host": b.Host, "status": b.Status,
		"valid_until": b.ValidUntil, "server_time": b.ServerTime, "policy": b.Policy.toMap()}})
}

// epochOK is the contracts' epoch in seconds.
func epochOK(v any) (int64, bool) {
	f, ok := v.(float64)
	if !ok || f != float64(int64(f)) || f < 1 || f > epochMax {
		return 0, false
	}
	return int64(f), true
}

const epochMax = 4102444800 // 2100-01-01, common.schema.json epoch_s

var okPolicyKeys = []string{"ping_interval_s", "dead_peer_s", "stream_idle_s", "stream_max_age_s", "renew_before_valid_until_s"}

// checkPolicyBlock validates the five windows of an authorize answer or an OK (integers 1..86400: capped at a day only to refuse nonsense).
func checkPolicyBlock(v any) (okPolicy, bool) {
	m, ok := v.(map[string]any)
	if !ok || len(m) != len(okPolicyKeys) {
		return okPolicy{}, false
	}
	var got [5]int64
	for i, key := range okPolicyKeys {
		f, ok := m[key].(float64)
		if !ok || f != float64(int64(f)) || f < 1 || f > 86400 {
			return okPolicy{}, false
		}
		got[i] = int64(f)
	}
	return okPolicy{got[0], got[1], got[2], got[3], got[4]}, true
}

var reNodeID = anchored(`^[a-z0-9]{1,16}$`)

// checkOKBody validates ok-body.schema.json.
func checkOKBody(v any) error {
	m, ok := v.(map[string]any)
	if !ok || len(m) != 7 {
		return errors.New("ok body shape")
	}
	if f, ok := m["v"].(float64); !ok || f != float64(policyData.Protocol.Version) {
		return errors.New("ok body v")
	}
	if n, ok := m["node"].(string); !ok || !reNodeID.MatchString(n) {
		return errors.New("ok body node")
	}
	if h, ok := m["host"].(string); !ok || !validFQDN(h) {
		return errors.New("ok body host")
	}
	if s, ok := m["status"].(string); !ok || !validStatus(s) {
		return errors.New("ok body status")
	}
	for _, key := range []string{"valid_until", "server_time"} {
		if _, ok := epochOK(m[key]); !ok {
			return errors.New("ok body " + key)
		}
	}
	if _, ok := checkPolicyBlock(m["policy"]); !ok {
		return errors.New("ok body policy")
	}
	return nil
}

// Statuses of an authorize answer (policy enums.authorize_status).
const (
	statusActive = "active"
	statusGated  = "gated"
	statusPaused = "paused"
)

func validStatus(s string) bool { return s == statusActive || s == statusGated || s == statusPaused }

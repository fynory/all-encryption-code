package main

// The Go reference verifier of the ALL 2.0 contracts (the contract): the same checks as contracts/e2e_contracts.py and
// contracts/ts/verify.ts, written independently, so that the three give the same verdict AND the same error word on every golden vector
// (contracts_test.go runs them). It lives in a test file on purpose: WP01 is spec and fixtures only. The node (WP05, WP06) is written in its
// own files and is tested against these functions and against the vectors; every constant is read from contracts/policy.json, never typed.

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const ctContracts = "../contracts"

// ---------------------------------------------------------------------------------------------------------------------------- JSON

// ctParseJSON parses one JSON value: duplicate object keys are an error (a body with a repeated key means different things to different
// implementations), numbers are float64 and a non-integral one is the caller's business, anything after the value is an error.
func ctParseJSON(text string) (any, error) {
	if !utf8.ValidString(text) {
		return nil, errors.New("utf-8")
	}
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	value, err := ctDecodeValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data")
	}
	return value, nil
}

func ctDecodeValue(dec *json.Decoder) (any, error) {
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := token.(type) {
	case json.Delim:
		if t == '{' {
			out := map[string]any{}
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, errors.New("key")
				}
				if _, dup := out[key]; dup {
					return nil, errors.New("duplicate key")
				}
				value, err := ctDecodeValue(dec)
				if err != nil {
					return nil, err
				}
				out[key] = value
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return out, nil
		}
		if t == '[' {
			out := []any{}
			for dec.More() {
				value, err := ctDecodeValue(dec)
				if err != nil {
					return nil, err
				}
				out = append(out, value)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return out, nil
		}
		return nil, errors.New("delimiter")
	case json.Number:
		f, err := strconv.ParseFloat(string(t), 64)
		if err != nil || math.IsInf(f, 0) {
			return nil, errors.New("number")
		}
		return f, nil
	default:
		return token, nil // string, bool, nil
	}
}

// ctNoFloats refuses a non-integral number anywhere in a value (bodies hold integers, never fractions).
func ctNoFloats(value any) error {
	switch v := value.(type) {
	case float64:
		if v != math.Trunc(v) {
			return errors.New("float")
		}
	case map[string]any:
		for _, item := range v {
			if err := ctNoFloats(item); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range v {
			if err := ctNoFloats(item); err != nil {
				return err
			}
		}
	}
	return nil
}

func ctEscape(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r < 0x20 || r > 0x7e:
			if r > 0xffff {
				r -= 0x10000
				fmt.Fprintf(&b, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
			} else {
				fmt.Fprintf(&b, `\u%04x`, r)
			}
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// ctCanonicalJSON is the form of a JSON body on a wire line: keys sorted, no whitespace, ASCII only.
func ctCanonicalJSON(value any) string {
	switch v := value.(type) {
	case nil:
		return "null"
	case bool:
		return strconv.FormatBool(v)
	case float64:
		return strconv.FormatInt(int64(v), 10)
	case string:
		return ctEscape(v)
	case []any:
		parts := make([]string, len(v))
		for i, item := range v {
			parts[i] = ctCanonicalJSON(item)
		}
		return "[" + strings.Join(parts, ",") + "]"
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, key := range keys {
			parts[i] = ctEscape(key) + ":" + ctCanonicalJSON(v[key])
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
	panic(fmt.Sprintf("canonical json: %T", value))
}

func ctEqual(a, b any) bool {
	switch x := a.(type) {
	case nil:
		return b == nil
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case float64:
		y, ok := b.(float64)
		return ok && x == y
	case string:
		y, ok := b.(string)
		return ok && x == y
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !ctEqual(x[i], y[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for key, item := range x {
			other, present := y[key]
			if !present || !ctEqual(item, other) {
				return false
			}
		}
		return true
	}
	return false
}

func ctLoadFile(path string) (any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ctParseJSON(string(raw))
}

// ---------------------------------------------------------------------------------------------------------------------------- policy

var ctPolicy = func() map[string]any {
	value, err := ctLoadFile(filepath.Join(ctContracts, "policy.json"))
	if err != nil {
		panic(err)
	}
	return value.(map[string]any)
}()

// ctPol reads one policy value by its dotted key.
func ctPol(dotted string) any {
	var value any = ctPolicy
	for _, part := range strings.Split(dotted, ".") {
		value = value.(map[string]any)[part]
	}
	return value
}

func ctPolInt(dotted string) int    { return int(ctPol(dotted).(float64)) }
func ctPolStr(dotted string) string { return ctPol(dotted).(string) }

func ctPolStrings(dotted string) []string {
	var out []string
	for _, item := range ctPol(dotted).([]any) {
		out = append(out, item.(string))
	}
	return out
}

// ctAnchored compiles one of the contracts' ^...$ patterns (RE2: `$` is the end of the text, as in JavaScript).
func ctAnchored(pattern string) *regexp.Regexp {
	if !strings.HasPrefix(pattern, "^") || !strings.HasSuffix(pattern, "$") {
		panic("contract patterns are anchored: " + pattern)
	}
	return regexp.MustCompile(pattern)
}

var (
	ctLabelRE    = ctAnchored(ctPolStr("identity.label_regex"))
	ctFQDNRE     = ctAnchored(ctPolStr("identity.fqdn_regex"))
	ctNonceRE    = ctAnchored(ctPolStr("identity.nonce_regex"))
	ctKidRE      = ctAnchored(ctPolStr("identity.kid_regex"))
	ctDeviceIDRE = ctAnchored(ctPolStr("identity.device_id_regex"))
)

func ctLabelOK(value string) bool { return ctLabelRE.MatchString(value) }

func ctFQDNOK(value string, zones []string) bool {
	if len(value) > ctPolInt("identity.fqdn_max_length") || !ctFQDNRE.MatchString(value) {
		return false
	}
	if zones == nil {
		return true
	}
	zone := value[strings.Index(value, ".")+1:]
	for _, z := range zones {
		if z == zone {
			return true
		}
	}
	return false
}

// ctHostPattern is the detector a node or a device builds for its own address in a zone.
func ctHostPattern(zone string) *regexp.Regexp {
	label := ctPolStr("identity.label_regex")
	return regexp.MustCompile("^" + label[1:len(label)-1] + `\.` + regexp.QuoteMeta(zone) + "$")
}

func ctValidIP(value string) bool {
	if value == "" || value != strings.ToLower(value) || strings.ContainsAny(value, "%[] \t\r\n/") {
		return false
	}
	_, err := netip.ParseAddr(value)
	return err == nil
}

// ---------------------------------------------------------------------------------------------------------------------------- JSON Schema subset

type ctSchemas struct {
	docs     map[string]any
	patterns map[string]*regexp.Regexp
}

func ctLoadSchemas() *ctSchemas {
	matches, err := filepath.Glob(filepath.Join(ctContracts, "schemas", "*.schema.json"))
	if err != nil || len(matches) == 0 {
		panic("no schemas")
	}
	s := &ctSchemas{docs: map[string]any{}, patterns: map[string]*regexp.Regexp{}}
	for _, path := range matches {
		doc, err := ctLoadFile(path)
		if err != nil {
			panic(err)
		}
		s.docs[filepath.Base(path)] = doc
	}
	return s
}

func (s *ctSchemas) validate(name string, instance any) []string {
	var errs []string
	s.check(name, s.docs[name], instance, "", &errs)
	return errs
}

func (s *ctSchemas) resolve(doc, ref string) (string, any) {
	file, pointer, _ := strings.Cut(ref, "#")
	target := file
	if target == "" {
		target = doc
	}
	node := s.docs[target]
	if pointer != "" {
		for _, part := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
			part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
			node = node.(map[string]any)[part]
		}
	}
	return target, node
}

func (s *ctSchemas) pattern(text string) *regexp.Regexp {
	if p, ok := s.patterns[text]; ok {
		return p
	}
	p := ctAnchored(text)
	s.patterns[text] = p
	return p
}

func ctTypeOK(kind string, value any) bool {
	switch kind {
	case "string":
		_, ok := value.(string)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "null":
		return value == nil
	case "object":
		_, ok := value.(map[string]any)
		return ok
	case "array":
		_, ok := value.([]any)
		return ok
	case "integer":
		f, ok := value.(float64)
		return ok && f == math.Trunc(f)
	case "number":
		_, ok := value.(float64)
		return ok
	}
	return false
}

func (s *ctSchemas) check(doc string, schemaAny any, value any, path string, errs *[]string) {
	schema := schemaAny.(map[string]any)
	at := path
	if at == "" {
		at = "/"
	}
	if ref, ok := schema["$ref"].(string); ok {
		target, node := s.resolve(doc, ref)
		s.check(target, node, value, path, errs)
	}
	if want, ok := schema["const"]; ok && !ctEqual(value, want) {
		*errs = append(*errs, at+": const")
	}
	if list, ok := schema["enum"].([]any); ok {
		found := false
		for _, item := range list {
			found = found || ctEqual(value, item)
		}
		if !found {
			*errs = append(*errs, at+": enum")
		}
	}
	if kinds, ok := schema["type"]; ok {
		var names []any
		if list, isList := kinds.([]any); isList {
			names = list
		} else {
			names = []any{kinds}
		}
		match := false
		for _, name := range names {
			match = match || ctTypeOK(name.(string), value)
		}
		if !match {
			*errs = append(*errs, at+": type")
			return
		}
	}
	if options, ok := schema["oneOf"].([]any); ok {
		hits := 0
		for _, option := range options {
			var trial []string
			s.check(doc, option, value, path, &trial)
			if len(trial) == 0 {
				hits++
			}
		}
		if hits != 1 {
			*errs = append(*errs, at+": oneOf")
		}
	}
	switch v := value.(type) {
	case string:
		if n, ok := schema["minLength"].(float64); ok && float64(utf8.RuneCountInString(v)) < n {
			*errs = append(*errs, at+": minLength")
		}
		if n, ok := schema["maxLength"].(float64); ok && float64(utf8.RuneCountInString(v)) > n {
			*errs = append(*errs, at+": maxLength")
		}
		if p, ok := schema["pattern"].(string); ok && !s.pattern(p).MatchString(v) {
			*errs = append(*errs, at+": pattern")
		}
		if schema["format"] == "ip" && !ctValidIP(v) {
			*errs = append(*errs, at+": format")
		}
	case float64:
		if n, ok := schema["minimum"].(float64); ok && v < n {
			*errs = append(*errs, at+": minimum")
		}
		if n, ok := schema["maximum"].(float64); ok && v > n {
			*errs = append(*errs, at+": maximum")
		}
	case map[string]any:
		if required, ok := schema["required"].([]any); ok {
			for _, key := range required {
				if _, present := v[key.(string)]; !present {
					*errs = append(*errs, path+"/"+key.(string)+": required")
				}
			}
		}
		props, _ := schema["properties"].(map[string]any)
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if sub, ok := props[key]; ok {
				s.check(doc, sub, v[key], path+"/"+key, errs)
			} else if schema["additionalProperties"] == false {
				*errs = append(*errs, path+"/"+key+": additionalProperties")
			}
		}
	case []any:
		if n, ok := schema["minItems"].(float64); ok && float64(len(v)) < n {
			*errs = append(*errs, at+": minItems")
		}
		if n, ok := schema["maxItems"].(float64); ok && float64(len(v)) > n {
			*errs = append(*errs, at+": maxItems")
		}
		if schema["uniqueItems"] == true {
			for i := range v {
				for j := i + 1; j < len(v); j++ {
					if ctEqual(v[i], v[j]) {
						*errs = append(*errs, at+": uniqueItems")
						i, j = len(v), len(v)
					}
				}
			}
		}
		if items, ok := schema["items"]; ok {
			for i, item := range v {
				s.check(doc, items, item, path+"/"+strconv.Itoa(i), errs)
			}
		}
	}
}

var ctSchemaSet = ctLoadSchemas()

// ---------------------------------------------------------------------------------------------------------------------------- the wire grammar

type ctProtoErr struct{ code string }

func (e *ctProtoErr) Error() string { return e.code }

var ctGrammar = func() map[string]any {
	value, err := ctLoadFile(filepath.Join(ctContracts, "schemas", "wire-v2.grammar.json"))
	if err != nil {
		panic(err)
	}
	return value.(map[string]any)
}()

func ctFieldOK(kind, token string) bool {
	spec := ctGrammar["types"].(map[string]any)[kind].(map[string]any)
	if key, ok := spec["max_bytes_from"].(string); ok && len(token) > int(ctPol(key).(float64)) {
		return false
	}
	if p, ok := spec["pattern"].(string); ok && !ctAnchored(p).MatchString(token) {
		return false
	}
	if spec["format"] == "ip" && !ctValidIP(token) {
		return false
	}
	if key, ok := spec["enum_from"].(string); ok {
		found := false
		for _, item := range ctPolStrings(key) {
			found = found || item == token
		}
		if !found {
			return false
		}
	}
	return true
}

func ctRules(spec map[string]any, key string) []map[string]any {
	var out []map[string]any
	if list, ok := spec[key].([]any); ok {
		for _, item := range list {
			out = append(out, item.(map[string]any))
		}
	}
	return out
}

// ctParseLine parses one protocol line (the text before the LF) travelling in `direction` ("d2n" or "n2d"): {"verb": ..., <field>: ...}; HINT
// gives "addresses" and OK gives "body". The error is a *ctProtoErr whose code is the word the node answers with.
func ctParseLine(line, direction string) (map[string]any, error) {
	for _, r := range line {
		if r < 0x20 || r > 0x7e {
			return nil, &ctProtoErr{"bad_command"}
		}
	}
	verb, rest, hasSpace := strings.Cut(line, " ")
	var spec map[string]any
	if s, ok := ctGrammar["verbs"].(map[string]any)[verb]; ok {
		spec = s.(map[string]any)
	}
	limit := ctPolInt("protocol.line_max_bytes")
	if spec != nil {
		if key, ok := spec["max"].(string); ok {
			limit = int(ctPol(key).(float64))
		}
	}
	if len(line)+1 > limit {
		return nil, &ctProtoErr{"line_too_long"}
	}
	if spec == nil || (spec["dir"] != direction && spec["dir"] != "both") || line == "" || (hasSpace && rest == "") {
		return nil, &ctProtoErr{"bad_command"}
	}
	out := map[string]any{"verb": verb}
	if schema, ok := spec["json"].(string); ok {
		if !hasSpace {
			return nil, &ctProtoErr{"bad_command"}
		}
		body, err := ctParseJSON(rest)
		if err == nil {
			err = ctNoFloats(body)
		}
		if err != nil || len(ctSchemaSet.validate(schema, body)) > 0 {
			return nil, &ctProtoErr{"bad_command"}
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
			return nil, &ctProtoErr{"bad_command"}
		}
	}
	if repeat, ok := spec["repeat"].(map[string]any); ok {
		min, max := int(repeat["min"].(float64)), int(ctPol(repeat["max_from"].(string)).(float64))
		if len(tokens) < min || len(tokens) > max {
			return nil, &ctProtoErr{"bad_command"}
		}
		addresses := make([]any, len(tokens))
		for i, token := range tokens {
			if !ctFieldOK(repeat["type"].(string), token) {
				return nil, &ctProtoErr{"bad_command"}
			}
			addresses[i] = token
		}
		out["addresses"] = addresses
		return out, nil
	}
	fields, optional := ctRules(spec, "fields"), ctRules(spec, "optional")
	if len(tokens) < len(fields) || len(tokens) > len(fields)+len(optional) {
		return nil, &ctProtoErr{"bad_command"}
	}
	for i, token := range tokens {
		rule := append(append([]map[string]any{}, fields...), optional...)[i]
		kind := rule["type"].(string)
		if want, ok := rule["equals"].(string); ok && token != want {
			if ctFieldOK(kind, token) {
				return nil, &ctProtoErr{rule["error_if_number"].(string)}
			}
			return nil, &ctProtoErr{"bad_command"}
		}
		if !ctFieldOK(kind, token) {
			code := "bad_command"
			if custom, ok := rule["error"].(string); ok {
				code = custom
			}
			return nil, &ctProtoErr{code}
		}
		out[rule["name"].(string)] = token
	}
	return out, nil
}

// ctFormatLine is the canonical line of a parsed message (the inverse of ctParseLine, which it is checked against).
func ctFormatLine(message map[string]any) (string, error) {
	verb := message["verb"].(string)
	spec := ctGrammar["verbs"].(map[string]any)[verb].(map[string]any)
	var line string
	switch {
	case spec["json"] != nil:
		line = verb + " " + ctCanonicalJSON(message["body"])
	case spec["repeat"] != nil:
		parts := []string{verb}
		for _, address := range message["addresses"].([]any) {
			parts = append(parts, address.(string))
		}
		line = strings.Join(parts, " ")
	default:
		parts := []string{verb}
		for _, rule := range append(ctRules(spec, "fields"), ctRules(spec, "optional")...) {
			if value, ok := message[rule["name"].(string)]; ok {
				parts = append(parts, value.(string))
			}
		}
		line = strings.Join(parts, " ")
	}
	direction := spec["dir"].(string)
	if direction == "both" {
		direction = "d2n"
	}
	if _, err := ctParseLine(line, direction); err != nil {
		return "", err
	}
	return line, nil
}

// ---------------------------------------------------------------------------------------------------------------------------- tokens

type ctResult struct {
	ok     bool
	err    string
	claims map[string]any
	jti    string
}

func ctFail(code string) ctResult { return ctResult{err: code} }

var ctB64Charset = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func ctB64Decode(text string) ([]byte, error) {
	if !ctB64Charset.MatchString(text) {
		return nil, errors.New("base64url")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(text)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != text {
		return nil, errors.New("base64url")
	}
	return raw, nil
}

func ctB64Encode(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

func ctSHA256B64(data []byte) string {
	sum := sha256.Sum256(data)
	return ctB64Encode(sum[:])
}

type ctJWS struct {
	header, claims map[string]any
	signature      []byte
	signingInput   []byte
}

// ctJWSParts splits and decodes a compact JWS; any structural fault is "malformed_token". An empty signature part is allowed here (alg none
// then fails as bad_alg, which is the more useful word).
func ctJWSParts(token string, maxBytes int) (*ctJWS, string) {
	for _, r := range token {
		if r > 0x7f {
			return nil, "malformed_token"
		}
	}
	if len(token) > maxBytes {
		return nil, "malformed_token"
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, "malformed_token"
	}
	decode := func(text string) (map[string]any, bool) {
		raw, err := ctB64Decode(text)
		if err != nil {
			return nil, false
		}
		value, err := ctParseJSON(string(raw))
		if err != nil {
			return nil, false
		}
		object, ok := value.(map[string]any)
		return object, ok
	}
	header, ok1 := decode(parts[0])
	claims, ok2 := decode(parts[1])
	if !ok1 || !ok2 {
		return nil, "malformed_token"
	}
	var signature []byte
	if parts[2] != "" {
		raw, err := ctB64Decode(parts[2])
		if err != nil {
			return nil, "malformed_token"
		}
		signature = raw
	}
	for _, name := range []string{"crit", "b64", "jku", "x5u", "x5c"} {
		if _, present := header[name]; present {
			return nil, "malformed_token"
		}
	}
	if ctNoFloats(claims) != nil {
		return nil, "malformed_token"
	}
	return &ctJWS{header, claims, signature, []byte(parts[0] + "." + parts[1])}, ""
}

func ctEd25519OK(x string, signature, input []byte) bool {
	if len(signature) != ed25519.SignatureSize {
		return false
	}
	raw, err := ctB64Decode(x)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(raw), input, signature)
}

func ctStr(m map[string]any, key string) (string, bool) {
	s, ok := m[key].(string)
	return s, ok
}

func ctNum(m map[string]any, key string) (float64, bool) {
	f, ok := m[key].(float64)
	return f, ok
}

// ctClaimsOK validates claims by a schema, ignoring the errors of the named keys (checked earlier under their own error word).
func ctClaimsOK(claims map[string]any, schema string, ignore ...string) bool {
	for _, e := range ctSchemaSet.validate(schema, claims) {
		skipped := false
		for _, name := range ignore {
			skipped = skipped || strings.HasPrefix(e, "/"+name+":")
		}
		if !skipped {
			return false
		}
	}
	return true
}

func ctJWKX(value any) (string, bool) {
	jwk, ok := value.(map[string]any)
	if !ok {
		return "", false
	}
	x, hasX := jwk["x"].(string)
	if _, private := jwk["d"]; private || jwk["kty"] != "OKP" || jwk["crv"] != "Ed25519" || !hasX || len(x) != 43 {
		return "", false
	}
	raw, err := ctB64Decode(x)
	if err != nil || len(raw) != 32 {
		return "", false
	}
	return x, true
}

// ctParseJWKS: kid -> x, or "bad_jwks".
func ctParseJWKS(doc any) (map[string]string, string) {
	if len(ctSchemaSet.validate("jwks.schema.json", doc)) > 0 {
		return nil, "bad_jwks"
	}
	keys := map[string]string{}
	for _, item := range doc.(map[string]any)["keys"].([]any) {
		key := item.(map[string]any)
		kid := key["kid"].(string)
		if _, dup := keys[kid]; dup {
			return nil, "bad_jwks"
		}
		keys[kid] = key["x"].(string)
	}
	return keys, ""
}

type ctNodeKey struct{ node, x string }

// ctParseNodeKeys: kid -> (node, x), or "bad_node_keys".
func ctParseNodeKeys(doc any) (map[string]ctNodeKey, string) {
	if len(ctSchemaSet.validate("node-keys.schema.json", doc)) > 0 {
		return nil, "bad_node_keys"
	}
	keys := map[string]ctNodeKey{}
	for _, item := range doc.(map[string]any)["keys"].([]any) {
		key := item.(map[string]any)
		kid := key["kid"].(string)
		if _, dup := keys[kid]; dup {
			return nil, "bad_node_keys"
		}
		keys[kid] = ctNodeKey{key["node"].(string), key["x"].(string)}
	}
	return keys, ""
}

// ctSignedByJWKS: the common first half of the session and statement checks (parse, alg, kid, signature, typ).
func ctSignedByJWKS(token string, keys map[string]string, typ string) (*ctJWS, string) {
	jws, code := ctJWSParts(token, ctPolInt("protocol.statement_line_max_bytes"))
	if code != "" {
		return nil, code
	}
	if jws.header["alg"] != "EdDSA" {
		return nil, "bad_alg"
	}
	kid, isString := ctStr(jws.header, "kid")
	if !isString || !ctKidRE.MatchString(kid) {
		return nil, "unknown_kid"
	}
	x, known := keys[kid]
	if !known {
		return nil, "unknown_kid"
	}
	if !ctEd25519OK(x, jws.signature, jws.signingInput) {
		return nil, "bad_signature"
	}
	if jws.header["typ"] != typ || jws.claims["typ"] != typ {
		return nil, "wrong_type"
	}
	return jws, ""
}

// ctVerifySession is verify_session of e2e_contracts.py.
func ctVerifySession(token string, now float64, audience string, keys map[string]string, skew float64) ctResult {
	if len(token) > ctPolInt("protocol.jwt_max_bytes") {
		return ctFail("malformed_token")
	}
	jws, code := ctSignedByJWKS(token, keys, "device-session")
	if code != "" {
		return ctFail(code)
	}
	claims := jws.claims
	if v, ok := ctNum(claims, "ver"); !ok || v != 2 {
		return ctFail("wrong_type")
	}
	if claims["iss"] != ctPolStr("identity.issuer") {
		return ctFail("wrong_issuer")
	}
	if claims["aud"] != audience {
		return ctFail("wrong_audience")
	}
	if !ctClaimsOK(claims, "session-claims.schema.json", "aud") {
		return ctFail("bad_claims")
	}
	iat, _ := ctNum(claims, "iat")
	exp, _ := ctNum(claims, "exp")
	if exp-iat != float64(ctPolInt("authorization.session_ttl_s")) {
		return ctFail("bad_lifetime")
	}
	if iat > now+skew {
		return ctFail("not_yet_valid")
	}
	if exp <= now {
		return ctFail("expired")
	}
	return ctResult{ok: true, claims: claims, jti: claims["jti"].(string)}
}

// ctVerifyProof is verify_proof.
func ctVerifyProof(proof string, now float64, sessionToken string, sessionClaims map[string]any, nonce, htu string, skew float64, seen map[string]bool) ctResult {
	if len(proof) > ctPolInt("protocol.jwt_max_bytes") {
		return ctFail("malformed_token")
	}
	jws, code := ctJWSParts(proof, ctPolInt("protocol.jwt_max_bytes"))
	if code != "" {
		return ctFail(code)
	}
	if jws.header["alg"] != "EdDSA" {
		return ctFail("bad_alg")
	}
	if jws.header["typ"] != "dpop+jwt" {
		return ctFail("wrong_type")
	}
	x, ok := ctJWKX(jws.header["jwk"])
	if !ok {
		return ctFail("malformed_token")
	}
	bound := sessionClaims["cnf"].(map[string]any)["jwk"].(map[string]any)["x"].(string)
	if x != bound {
		return ctFail("wrong_key")
	}
	if !ctEd25519OK(x, jws.signature, jws.signingInput) {
		return ctFail("bad_signature")
	}
	claims := jws.claims
	switch {
	case claims["sub"] != sessionClaims["sub"]:
		return ctFail("wrong_subject")
	case claims["aud"] != ctPolStr("identity.aud_tunnel"):
		return ctFail("wrong_audience")
	case claims["htm"] != ctPolStr("protocol.proof_htm"):
		return ctFail("wrong_htm")
	case claims["htu"] != htu:
		return ctFail("wrong_htu")
	case claims["ath"] != ctSHA256B64([]byte(sessionToken)):
		return ctFail("wrong_ath")
	case claims["nonce"] != nonce:
		return ctFail("wrong_nonce")
	case !ctClaimsOK(claims, "proof-claims.schema.json", "htu"):
		return ctFail("bad_claims")
	}
	iat, _ := ctNum(claims, "iat")
	if iat > now+skew {
		return ctFail("not_yet_valid")
	}
	if iat+float64(ctPolInt("authorization.proof_ttl_s")) <= now {
		return ctFail("stale_proof")
	}
	id := claims["jti"].(string)
	if seen[id] {
		return ctFail("replayed_jti")
	}
	return ctResult{ok: true, claims: claims, jti: id}
}

// ctVerifyNodeAssertion is verify_node_assertion.
func ctVerifyNodeAssertion(token string, now float64, keys map[string]ctNodeKey, method, url string, body []byte, skew float64, seen map[string]bool) ctResult {
	jws, code := ctJWSParts(token, ctPolInt("protocol.jwt_max_bytes"))
	if code != "" {
		return ctFail(code)
	}
	if jws.header["alg"] != "EdDSA" {
		return ctFail("bad_alg")
	}
	kid, isString := ctStr(jws.header, "kid")
	if !isString || !ctKidRE.MatchString(kid) {
		return ctFail("unknown_kid")
	}
	key, known := keys[kid]
	if !known {
		return ctFail("unknown_kid")
	}
	if !ctEd25519OK(key.x, jws.signature, jws.signingInput) {
		return ctFail("bad_signature")
	}
	claims := jws.claims
	if v, ok := ctNum(claims, "ver"); jws.header["typ"] != "node-assertion" || claims["typ"] != "node-assertion" || !ok || v != 1 {
		return ctFail("wrong_type")
	}
	switch {
	case claims["aud"] != ctPolStr("identity.aud_node_assertion"):
		return ctFail("wrong_audience")
	case claims["sub"] != key.node:
		return ctFail("wrong_subject")
	case claims["htm"] != method:
		return ctFail("wrong_htm")
	case claims["htu"] != url:
		return ctFail("wrong_htu")
	case !ctClaimsOK(claims, "node-assertion-claims.schema.json", "htm", "htu", "aud", "sub"):
		return ctFail("bad_claims")
	}
	iat, _ := ctNum(claims, "iat")
	exp, _ := ctNum(claims, "exp")
	switch {
	case exp-iat != float64(ctPolInt("authorization.node_assertion_ttl_s")):
		return ctFail("bad_lifetime")
	case iat > now+skew:
		return ctFail("not_yet_valid")
	case exp <= now:
		return ctFail("expired")
	case claims["bh"] != ctSHA256B64(body):
		return ctFail("wrong_body_hash")
	}
	id := claims["jti"].(string)
	if seen[id] {
		return ctFail("replayed_jti")
	}
	return ctResult{ok: true, claims: claims, jti: id}
}

// ctVerifyStatement is verify_statement.
func ctVerifyStatement(token string, now float64, keys map[string]string, deviceID string, lastSeq float64) ctResult {
	jws, code := ctSignedByJWKS(token, keys, "device-access")
	if code != "" {
		return ctFail(code)
	}
	claims := jws.claims
	if v, ok := ctNum(claims, "ver"); !ok || v != 1 {
		return ctFail("wrong_type")
	}
	switch {
	case claims["iss"] != ctPolStr("identity.issuer"):
		return ctFail("wrong_issuer")
	case claims["aud"] != ctPolStr("identity.aud_access"):
		return ctFail("wrong_audience")
	case claims["sub"] != deviceID:
		return ctFail("wrong_subject")
	}
	_, hasPaywall := claims["paywall"]
	_, hasPaused := claims["paused"]
	_, hasResumed := claims["resumed"]
	if !ctClaimsOK(claims, "statement-claims.schema.json", "aud", "sub") || hasPaywall != (claims["mode"] == "paywall") || (hasPaused && hasResumed) {
		return ctFail("bad_claims")
	}
	iat, _ := ctNum(claims, "iat")
	exp, _ := ctNum(claims, "exp")
	ttl := exp - iat
	capName := "authorization.access_ttl_paid_s"
	if claims["mode"] == "paywall" {
		capName = "authorization.access_ttl_paywall_s"
	}
	if ttl <= 0 || ttl > float64(ctPolInt(capName)) {
		return ctFail("bad_lifetime")
	}
	if iat > now+float64(ctPolInt("authorization.access_future_slack_s")) {
		return ctFail("not_yet_valid")
	}
	if seq, _ := ctNum(claims, "seq"); seq < lastSeq {
		return ctFail("stale_seq")
	}
	return ctResult{ok: true, claims: claims, jti: claims["jti"].(string)}
}

// ---------------------------------------------------------------------------------------------------------------------------- the feed

// ctCheckFeed is check_feed: the schema and the rules a schema cannot say.
func ctCheckFeed(body any, since float64) []string {
	if errs := ctSchemaSet.validate("feed-response.schema.json", body); len(errs) > 0 {
		return errs
	}
	var errs []string
	previous := since
	doc := body.(map[string]any)
	for i, item := range doc["events"].([]any) {
		event := item.(map[string]any)
		epoch := event["epoch"].(float64)
		if epoch <= previous {
			errs = append(errs, fmt.Sprintf("/events/%d: order", i))
		}
		previous = math.Max(previous, epoch)
		kind := event["type"].(string)
		global := kind == "kill" || kind == "kill_clear"
		if global != (event["device_id"] == nil && event["label"] == nil) {
			errs = append(errs, fmt.Sprintf("/events/%d: scope", i))
		}
		if (event["device_id"] == nil) != (event["label"] == nil) {
			errs = append(errs, fmt.Sprintf("/events/%d: scope", i))
		}
	}
	if doc["epoch"].(float64) < previous {
		errs = append(errs, "/epoch: behind events")
	}
	return errs
}

// ---------------------------------------------------------------------------------------------------------------------------- surface identity proof

func ctSurfaceKey(secret string) ([]byte, bool) {
	raw, err := ctB64Decode(secret)
	return raw, err == nil && len(raw) == 32
}

func ctSurfaceMAC(secret, nonce string) (string, bool) {
	key, ok := ctSurfaceKey(secret)
	if !ok {
		return "", false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("all-surface-challenge-v1\n" + nonce))
	return ctB64Encode(mac.Sum(nil)), true
}

func ctSurfaceProof(secret, nonce string, pid, port int) (string, bool) {
	key, ok := ctSurfaceKey(secret)
	if !ok {
		return "", false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("all-surface-proof-v1\n" + nonce + "\n" + strconv.Itoa(pid) + "\n" + strconv.Itoa(port)))
	return ctB64Encode(mac.Sum(nil)), true
}

func ctEqualText(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func ctVerifySurfaceChallenge(secret, nonce, mac string) ctResult {
	want, ok := ctSurfaceMAC(secret, nonce)
	if !ok || !ctNonceRE.MatchString(nonce) || !ctEqualText(want, mac) {
		return ctFail("bad_challenge")
	}
	return ctResult{ok: true}
}

func ctVerifySurfaceProof(secret, nonce string, pid, port int, proof string) ctResult {
	want, ok := ctSurfaceProof(secret, nonce, pid, port)
	if !ok || !ctNonceRE.MatchString(nonce) || !ctEqualText(want, proof) {
		return ctFail("bad_proof")
	}
	return ctResult{ok: true}
}

func ctIdentityRequest(host string, port int, nonce, mac string) string {
	return fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s:%d\r\n%s: %s\r\n%s: %s\r\nConnection: keep-alive\r\n\r\n", ctPolStr("surface.identity_path"), host, port,
		ctPolStr("surface.identity_challenge_header"), nonce, ctPolStr("surface.identity_mac_header"), mac)
}

// ---------------------------------------------------------------------------------------------------------------------------- node behaviour

type ctConn struct {
	phase, session, kind, nonce, proof, host, status, sub string
	claims                                                map[string]any
	sessionOK, authorized, superseded                     bool
	reply                                                 map[string]any
	validUntil                                            float64
}

// ctHello is a complete ClientHello waiting for its OPEN.
type ctHello struct{ ip, class string }

type ctStream struct {
	secret   string
	t        float64
	consumed bool
}

func ctText(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// ctCheckTranscript is check_transcript: does the recorded behaviour of one node obey the contract? "" is ok, otherwise the violation word.
func ctCheckTranscript(doc map[string]any) string {
	ctx := doc["ctx"].(map[string]any)
	keys, code := ctParseJWKS(ctx["jwks"])
	if code != "" {
		return code
	}
	skew := ctx["skew"].(float64)
	conns := map[string]*ctConn{}
	var order []string
	seen := map[string]bool{}
	streams := map[string]*ctStream{}
	secretsUsed := map[string]bool{}
	hellos := map[string][]ctHello{} // per host: the peer_ip and class of each complete ClientHello still waiting for its OPEN
	ended := false
	var now float64

	for _, item := range doc["events"].([]any) {
		event := item.(map[string]any)
		now = event["t"].(float64)
		kind := ctText(event, "ev")
		var conn *ctConn
		if name, ok := event["conn"].(string); ok && (kind == "recv" || kind == "send" || kind == "cp" || kind == "cp_reply") {
			if conns[name] == nil {
				conns[name] = &ctConn{phase: "new", kind: "hello", proof: "none"}
				order = append(order, name)
			}
			conn = conns[name]
		}
		switch kind {
		case "client_hello":
			if event["complete"] == true {
				hellos[ctText(event, "sni")] = append(hellos[ctText(event, "sni")], ctHello{ctText(event, "peer_ip"), ctText(event, "class")})
			}
		case "recv":
			message, err := ctParseLine(ctText(event, "line"), "d2n")
			if err != nil {
				continue
			}
			verb := message["verb"].(string)
			if (verb == "HELLO" && conn.phase == "new") || (verb == "RENEW" && conn.phase == "ready") {
				token := message["session"].(string)
				result := ctVerifySession(token, now, ctPolStr("identity.aud_tunnel"), keys, skew)
				conn.sessionOK = result.ok && (verb == "HELLO" || result.claims["sub"] == conn.sub)
				conn.session = token
				conn.claims = nil
				if result.ok {
					conn.claims = result.claims
				}
				conn.kind = map[bool]string{true: "hello", false: "renew"}[verb == "HELLO"]
				conn.nonce = ""
				conn.proof, conn.authorized, conn.reply = "none", false, nil
				if verb == "HELLO" {
					conn.phase = "hello"
				}
			} else if verb == "PROOF" && conn.sessionOK && conn.nonce != "" {
				result := ctVerifyProof(message["proof"].(string), now, conn.session, conn.claims, conn.nonce, ctx["node_url"].(string), skew, seen)
				switch {
				case result.ok:
					conn.proof = "ok"
				case result.err == "replayed_jti":
					conn.proof = "replayed"
				default:
					conn.proof = "invalid"
				}
				conn.authorized, conn.reply = false, nil
				if result.ok {
					seen[result.jti] = true
				}
			}
		case "cp":
			body := event["body"].(map[string]any)
			if len(ctSchemaSet.validate("authorize-request.schema.json", body)) > 0 || conn.claims == nil || body["device_id"] != conn.claims["sub"] ||
				body["session_jti"] != conn.claims["jti"] || body["reason"] != conn.kind || body["node"] != ctx["node_id"] {
				return "bad_authorize_request"
			}
			if conn.proof == "ok" {
				conn.authorized = true
			}
		case "cp_reply":
			conn.reply = nil
			if conn.authorized {
				conn.reply = event
			}
		case "send":
			message, err := ctParseLine(ctText(event, "line"), "n2d")
			if err != nil {
				return "bad_line"
			}
			switch message["verb"].(string) {
			case "CHALLENGE":
				if !conn.sessionOK || (conn.phase != "hello" && conn.phase != "ready") {
					return "challenge_for_invalid_session"
				}
				conn.nonce = message["nonce"].(string)
			case "OK":
				if ctText(event, "line") != "OK "+ctCanonicalJSON(message["body"]) {
					return "bad_line"
				}
				switch conn.proof {
				case "none":
					return "ok_without_proof"
				case "replayed":
					return "replayed_proof_accepted"
				case "invalid":
					return "ok_with_invalid_proof"
				}
				if !conn.authorized || conn.reply == nil || conn.reply["status"].(float64) != 200 {
					if conn.kind == "renew" {
						return "renew_without_authorize"
					}
					return "ok_without_authorize"
				}
				body, answer := message["body"].(map[string]any), conn.reply["body"].(map[string]any)
				if body["host"] != answer["host"] {
					return "host_not_from_control_plane"
				}
				if body["status"] != answer["status"] || body["valid_until"] != answer["valid_until"] || !ctEqual(body["policy"], answer["policy"]) || body["node"] != ctx["node_id"] {
					return "ok_mismatch_control_plane"
				}
				conn.phase, conn.host, conn.status = "ready", body["host"].(string), body["status"].(string)
				conn.validUntil, conn.sub = body["valid_until"].(float64), conn.claims["sub"].(string)
				conn.proof, conn.authorized, conn.reply = "none", false, nil
				for _, name := range order {
					if other := conns[name]; other != conn && other.phase == "ready" && other.sub == conn.sub {
						other.superseded = true
					}
				}
			case "OPEN":
				switch {
				case conn.phase != "ready" || conn.status == "":
					return "open_before_ok"
				case conn.status == "paused":
					return "open_when_paused"
				case now >= conn.validUntil:
					return "open_after_valid_until"
				case len(hellos[conn.host]) == 0:
					for _, list := range hellos {
						if len(list) > 0 {
							return "open_wrong_host"
						}
					}
					return "open_without_client_hello"
				}
				waiting := -1
				for k, hello := range hellos[conn.host] {
					if hello.ip == message["peer_ip"] && hello.class == message["class"] {
						waiting = k
						break
					}
				}
				if waiting < 0 {
					return "open_wrong_client"
				}
				id, secret := message["stream_id"].(string), message["secret"].(string)
				if streams[id] != nil || secretsUsed[secret] {
					return "duplicate_stream"
				}
				hellos[conn.host] = append(hellos[conn.host][:waiting], hellos[conn.host][waiting+1:]...)
				streams[id] = &ctStream{secret: secret, t: now}
				secretsUsed[secret] = true
			case "CLOSE":
				conn.phase = "closed"
			}
		case "attach":
			message, err := ctParseLine(ctText(event, "line"), "d2n")
			if err != nil {
				continue
			}
			known := streams[message["stream_id"].(string)]
			good := known != nil && ctEqualText(known.secret, message["secret"].(string))
			fresh := good && !known.consumed && now-known.t <= float64(ctPolInt("protocol.attach_timeout_s"))
			if event["result"] == "ok" {
				switch {
				case known == nil:
					return "attach_unknown_accepted"
				case !good:
					return "attach_wrong_secret_accepted"
				case known.consumed:
					return "attach_secret_reused"
				case !fresh:
					return "attach_after_timeout"
				}
				known.consumed = true
			} else if fresh {
				return "attach_refused_good_secret"
			}
		case "end":
			ended = true
			for _, name := range order {
				other := conns[name]
				if other.phase == "ready" && other.superseded {
					return "replaced_not_closed"
				}
				if other.phase == "ready" && now > other.validUntil {
					return "no_close_at_valid_until"
				}
			}
		}
	}
	if !ended {
		return "transcript_without_end"
	}
	return ""
}

// ---------------------------------------------------------------------------------------------------------------------------- an active node (the Go twin of contracts/fake_node.py)

type ctSimConn struct {
	phase, session, kind, nonce, host, status, sub string
	claims                                         map[string]any
	waiting                                        bool
	validUntil                                     float64
}

type ctNodeSim struct {
	nodeID, nodeURL            string
	keys                       map[string]string
	skew                       float64
	nonces, streamIDs, secrets []string
	conns                      map[string]*ctSimConn
	order                      []string
	seen                       map[string]bool
	streams                    map[string]*ctStream
}

func ctNewNodeSim(ctx map[string]any) *ctNodeSim {
	keys, code := ctParseJWKS(ctx["jwks"])
	if code != "" {
		panic(code)
	}
	randoms := ctx["randoms"].(map[string]any)
	list := func(name string) []string {
		var out []string
		for _, item := range randoms[name].([]any) {
			out = append(out, item.(string))
		}
		return out
	}
	return &ctNodeSim{nodeID: ctx["node_id"].(string), nodeURL: ctx["node_url"].(string), keys: keys, skew: ctx["skew"].(float64), nonces: list("nonces"),
		streamIDs: list("stream_ids"), secrets: list("secrets"), conns: map[string]*ctSimConn{}, seen: map[string]bool{}, streams: map[string]*ctStream{}}
}

func ctSend(t float64, conn, line string) map[string]any {
	return map[string]any{"t": t, "conn": conn, "ev": "send", "line": line}
}

func (n *ctNodeSim) conn(name string) *ctSimConn {
	if n.conns[name] == nil {
		n.conns[name] = &ctSimConn{phase: "new", kind: "hello"}
		n.order = append(n.order, name)
	}
	return n.conns[name]
}

func ctErrLine(code string) string {
	line, err := ctFormatLine(map[string]any{"verb": "ERR", "code": code})
	if err != nil {
		panic(err)
	}
	return line
}

func ctErrFor(code, fallback string) string {
	switch code {
	case "malformed_token":
		return "bad_hello"
	case "not_yet_valid", "stale_proof":
		return "clock_skew"
	case "wrong_audience", "expired":
		return "auth"
	}
	return fallback
}

func (n *ctNodeSim) handle(event map[string]any) []map[string]any {
	t := event["t"].(float64)
	switch event["ev"] {
	case "recv":
		return n.recv(t, event["conn"].(string), event["line"].(string))
	case "cp_reply":
		return n.cpReply(t, event["conn"].(string), event["status"].(float64), event["body"])
	case "client_hello":
		return n.clientHello(t, event)
	case "attach":
		return n.attach(t, event)
	case "tick":
		var out []map[string]any
		for _, name := range n.order {
			if c := n.conns[name]; c.phase == "ready" && t >= c.validUntil {
				c.phase = "closed"
				out = append(out, ctSend(t, name, "CLOSE expired"))
			}
		}
		return out
	}
	return nil
}

func (n *ctNodeSim) recv(t float64, name, line string) []map[string]any {
	c := n.conn(name)
	message, err := ctParseLine(line, "d2n")
	if err != nil {
		return []map[string]any{ctSend(t, name, ctErrLine(err.(*ctProtoErr).code))}
	}
	verb := message["verb"].(string)
	switch verb {
	case "HELLO", "RENEW":
		if (verb == "HELLO" && c.phase != "new") || (verb == "RENEW" && c.phase != "ready") { // RENEW only on a live connection
			return []map[string]any{ctSend(t, name, ctErrLine("bad_command"))}
		}
		token := message["session"].(string)
		result := ctVerifySession(token, t, ctPolStr("identity.aud_tunnel"), n.keys, n.skew)
		if !result.ok {
			return []map[string]any{ctSend(t, name, ctErrLine(ctErrFor(result.err, "auth")))}
		}
		if verb == "RENEW" && result.claims["sub"] != c.sub {
			return []map[string]any{ctSend(t, name, ctErrLine("auth"))}
		}
		c.session, c.claims, c.kind, c.waiting = token, result.claims, "hello", false
		if verb == "RENEW" {
			c.kind = "renew"
		} else {
			c.phase = "hello"
		}
		c.nonce, n.nonces = n.nonces[0], n.nonces[1:]
		return []map[string]any{ctSend(t, name, "CHALLENGE "+c.nonce)}
	case "PROOF":
		if c.nonce == "" {
			return []map[string]any{ctSend(t, name, ctErrLine("bad_command"))}
		}
		result := ctVerifyProof(message["proof"].(string), t, c.session, c.claims, c.nonce, n.nodeURL, n.skew, n.seen)
		c.nonce = ""
		if !result.ok {
			word := "bad_proof"
			if result.err != "replayed_jti" {
				word = ctErrFor(result.err, "bad_proof")
			}
			return []map[string]any{ctSend(t, name, ctErrLine(word))}
		}
		n.seen[result.jti] = true
		c.waiting = true
		body := map[string]any{"v": 1.0, "device_id": c.claims["sub"], "session_jti": c.claims["jti"], "reason": c.kind, "node": n.nodeID}
		return []map[string]any{{"t": t, "conn": name, "ev": "cp", "call": "authorize", "body": body}}
	case "PING":
		return []map[string]any{ctSend(t, name, "PONG")}
	case "HINT":
		return nil
	case "CLOSE":
		c.phase = "closed"
		return nil
	}
	return []map[string]any{ctSend(t, name, ctErrLine("bad_command"))}
}

func (n *ctNodeSim) cpReply(t float64, name string, status float64, body any) []map[string]any {
	c := n.conn(name)
	if !c.waiting {
		return nil
	}
	c.waiting = false
	if status != 200 {
		word := "auth"
		if status >= 500 || status == 429 {
			word = "control_unavailable"
		}
		if m, ok := body.(map[string]any); ok {
			switch m["error"] {
			case "license_inactive", "device_revoked", "paused":
				word = m["error"].(string)
			}
		}
		return []map[string]any{ctSend(t, name, ctErrLine(word))}
	}
	answer, _ := body.(map[string]any)
	if len(ctSchemaSet.validate("authorize-response.schema.json", body)) > 0 || answer["device_id"] != c.claims["sub"] {
		return []map[string]any{ctSend(t, name, ctErrLine("control_unavailable"))}
	}
	okBody := map[string]any{"v": 2.0, "node": n.nodeID, "host": answer["host"], "status": answer["status"], "valid_until": answer["valid_until"],
		"server_time": answer["server_time"], "policy": answer["policy"]}
	line, err := ctFormatLine(map[string]any{"verb": "OK", "body": okBody})
	if err != nil {
		panic(err)
	}
	out := []map[string]any{ctSend(t, name, line)}
	c.phase, c.host, c.status, c.validUntil, c.sub = "ready", answer["host"].(string), answer["status"].(string), answer["valid_until"].(float64), c.claims["sub"].(string)
	for _, other := range n.order {
		if o := n.conns[other]; other != name && o.phase == "ready" && o.sub == c.sub {
			o.phase = "closed"
			out = append(out, ctSend(t, other, "CLOSE replaced"))
		}
	}
	return out
}

func (n *ctNodeSim) clientHello(t float64, event map[string]any) []map[string]any {
	sni := event["sni"].(string)
	alert := []map[string]any{{"t": t, "ev": "tls_alert", "sni": sni}}
	if event["complete"] != true {
		return alert
	}
	for _, name := range n.order {
		c := n.conns[name]
		if c.phase == "ready" && c.host == sni && c.status != "paused" && t < c.validUntil {
			id, secret := n.streamIDs[0], n.secrets[0]
			n.streamIDs, n.secrets = n.streamIDs[1:], n.secrets[1:]
			n.streams[id] = &ctStream{secret: secret, t: t}
			line, err := ctFormatLine(map[string]any{"verb": "OPEN", "stream_id": id, "secret": secret, "peer_ip": event["peer_ip"], "class": event["class"]})
			if err != nil {
				panic(err)
			}
			return []map[string]any{ctSend(t, name, line)}
		}
	}
	return alert
}

func (n *ctNodeSim) attach(t float64, event map[string]any) []map[string]any {
	out := map[string]any{"t": t, "conn": event["conn"], "ev": "attach", "line": event["line"], "result": "err"}
	message, err := ctParseLine(event["line"].(string), "d2n")
	if err != nil {
		return []map[string]any{out}
	}
	known := n.streams[message["stream_id"].(string)]
	if known != nil && known.secret == message["secret"].(string) && !known.consumed && t-known.t <= float64(ctPolInt("protocol.attach_timeout_s")) {
		known.consumed = true
		out["result"] = "ok"
	}
	return []map[string]any{out}
}

// ctSplitTranscript is split_transcript: (inputs, outputs) of a golden transcript.
func ctSplitTranscript(events []any) (inputs, outputs []map[string]any) {
	for _, item := range events {
		event := item.(map[string]any)
		switch event["ev"] {
		case "recv", "cp_reply", "client_hello", "tick", "end":
			inputs = append(inputs, event)
		case "attach":
			stripped := map[string]any{}
			for key, value := range event {
				if key != "result" {
					stripped[key] = value
				}
			}
			inputs = append(inputs, stripped)
			outputs = append(outputs, event)
		case "send", "cp", "tls_alert":
			outputs = append(outputs, event)
		}
	}
	return inputs, outputs
}

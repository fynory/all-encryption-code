package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The tokens and bodies of the contracts are JSON that every implementation must read the same way, so the node reads it strictly: valid
// UTF-8, no repeated key (a body with a repeated key means different things to different parsers), no non-integral number, nothing after the value.

// parseJSON parses one JSON value into maps, slices, strings, bools, nil and float64 (integers up to 2^53 are exact).
func parseJSON(text string) (any, error) {
	if !utf8.ValidString(text) {
		return nil, errors.New("utf-8")
	}
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	value, err := decodeValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data")
	}
	if err := noFractions(value); err != nil {
		return nil, err
	}
	return value, nil
}

func decodeValue(dec *json.Decoder) (any, error) {
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := token.(type) {
	case json.Delim:
		switch t {
		case '{':
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
				value, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				out[key] = value
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return out, nil
		case '[':
			out := []any{}
			for dec.More() {
				value, err := decodeValue(dec)
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

// noFractions refuses a non-integral number anywhere in a value (the contracts' bodies hold integers, never fractions).
func noFractions(value any) error {
	switch v := value.(type) {
	case float64:
		if v != math.Trunc(v) {
			return errors.New("fraction")
		}
	case map[string]any:
		for _, item := range v {
			if err := noFractions(item); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range v {
			if err := noFractions(item); err != nil {
				return err
			}
		}
	}
	return nil
}

func escapeJSON(s string) string {
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

// canonicalJSON is the form of a JSON body on a wire line: keys sorted, no whitespace, ASCII only, integers without a fraction.
func canonicalJSON(value any) string {
	switch v := value.(type) {
	case nil:
		return "null"
	case bool:
		return strconv.FormatBool(v)
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		return strconv.FormatInt(int64(v), 10)
	case string:
		return escapeJSON(v)
	case []any:
		parts := make([]string, len(v))
		for i, item := range v {
			parts[i] = canonicalJSON(item)
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
			parts[i] = escapeJSON(key) + ":" + canonicalJSON(v[key])
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
	panic(fmt.Sprintf("canonical json: %T", value))
}

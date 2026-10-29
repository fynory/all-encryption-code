package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"time"
)

// The address ranges OpenAI publishes for its connector traffic (the design plan, section 5). The node reads them once a day into the "openai"
// source class of an OPEN, which is a QUOTA and not an allowlist: ChatGPT can be made to call any name from those addresses, so the class never lets a
// stream past a limit; it only keeps ChatGPT's own share of the node (policy node_limits.openai_reserved_pct) and per-source limits larger by a factor
// (openai_per_ip_factor) for an address that serves many users. The published list is "best effort" (G1 measures the addresses ChatGPT really comes from).
//
// A list that is empty, corrupt, too big, or that holds a prefix too wide to be a connector's range (0.0.0.0/0 would make everyone "openai") replaces
// nothing: the node keeps the last good one, which is also kept in a file (public data) so that a restart during an outage of the publisher does not
// start with none.

// The words of a refresh's outcome, in the log and in the metrics.
const (
	prefixOK        = "ok"
	prefixFetch     = "fetch_failed"
	prefixEmpty     = "empty"
	prefixCorrupt   = "corrupt"
	prefixTooLarge  = "too_large"
	prefixTooMany   = "too_many"
	prefixBadPrefix = "bad_prefix"
)

var (
	errPrefixEmpty    = errors.New(prefixEmpty)
	errPrefixCorrupt  = errors.New(prefixCorrupt)
	errPrefixTooLarge = errors.New(prefixTooLarge)
	errPrefixTooMany  = errors.New(prefixTooMany)
	errPrefixBad      = errors.New(prefixBadPrefix)
)

// prefixSet is an immutable list of prefixes with a lookup that costs one map probe per distinct prefix length.
type prefixSet struct {
	set  map[netip.Prefix]struct{}
	lens []int
}

func newPrefixSet(prefixes []netip.Prefix) *prefixSet {
	p := &prefixSet{set: make(map[netip.Prefix]struct{}, len(prefixes))}
	for _, pf := range prefixes {
		p.set[pf] = struct{}{}
		if !slices.Contains(p.lens, pf.Bits()) {
			p.lens = append(p.lens, pf.Bits())
		}
	}
	return p
}

func (p *prefixSet) len() int { return len(p.set) }

func (p *prefixSet) contains(a netip.Addr) bool {
	a = a.WithZone("").Unmap()
	for _, bits := range p.lens {
		if pf, err := a.Prefix(bits); err == nil {
			if _, ok := p.set[pf]; ok {
				return true
			}
		}
	}
	return false
}

// prefixLimits are the sanity bounds a list is read under (policy node_limits).
type prefixLimits struct {
	maxBytes, maxEntries, minV4, minV6 int
}

// parsePrefixes reads a published list: {"prefixes": [{"ipv4Prefix": "a.b.c.d/n"}, {"ipv6Prefix": "..."}]} and nothing else of consequence. Every entry
// must be one of those two shapes with a prefix of its own family, not narrower than the policy's minimum width (a connector range is a /28 or so, not a
// continent); a single bad entry refuses the whole list, because a list that is partly wrong is not one to trust the rest of.
func parsePrefixes(body []byte, lim prefixLimits) ([]netip.Prefix, error) {
	if len(body) > lim.maxBytes {
		return nil, errPrefixTooLarge
	}
	value, err := parseJSON(string(body))
	if err != nil {
		return nil, errPrefixCorrupt
	}
	doc, ok := value.(map[string]any)
	if !ok {
		return nil, errPrefixCorrupt
	}
	list, ok := doc["prefixes"].([]any)
	if !ok {
		return nil, errPrefixCorrupt
	}
	if len(list) == 0 {
		return nil, errPrefixEmpty
	}
	if len(list) > lim.maxEntries {
		return nil, errPrefixTooMany
	}
	out := make([]netip.Prefix, 0, len(list))
	for _, item := range list {
		entry, ok := item.(map[string]any)
		if !ok || len(entry) != 1 {
			return nil, errPrefixCorrupt
		}
		for key, raw := range entry {
			text, ok := raw.(string)
			if !ok || (key != "ipv4Prefix" && key != "ipv6Prefix") {
				return nil, errPrefixCorrupt
			}
			pf, err := netip.ParsePrefix(text)
			if err != nil || pf.Addr().Zone() != "" || pf.Addr().Is4In6() || pf.Addr().IsUnspecified() {
				return nil, errPrefixBad
			}
			minBits := lim.minV6
			if key == "ipv4Prefix" {
				if !pf.Addr().Is4() {
					return nil, errPrefixBad
				}
				minBits = lim.minV4
			} else if !pf.Addr().Is6() {
				return nil, errPrefixBad
			}
			if pf.Bits() < minBits {
				return nil, errPrefixBad
			}
			out = append(out, pf.Masked())
		}
	}
	return out, nil
}

// encodePrefixes writes a list in the format parsePrefixes reads (what the file of the last good list holds).
func encodePrefixes(set *prefixSet) []byte {
	all := make([]netip.Prefix, 0, len(set.set))
	for pf := range set.set {
		all = append(all, pf)
	}
	slices.SortFunc(all, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	entries := make([]map[string]string, 0, len(all))
	for _, pf := range all {
		key := "ipv6Prefix"
		if pf.Addr().Is4() {
			key = "ipv4Prefix"
		}
		entries = append(entries, map[string]string{key: pf.String()})
	}
	raw, _ := json.Marshal(map[string]any{"prefixes": entries})
	return raw
}

// openaiPrefixes is the node's current list and what keeps it fresh.
type openaiPrefixes struct {
	cur   atomic.Pointer[prefixSet]
	at    atomic.Int64 // when the list in use was installed (clock nanoseconds since the epoch), 0 when none
	clk   clock
	log   *slog.Logger
	lim   prefixLimits
	every time.Duration
	file  string
	fetch func(ctx context.Context) ([]byte, error)
	count func(result string) // the metrics' counter of outcomes
}

func newOpenAIPrefixes(cfg *Config, clk clock, count func(string)) *openaiPrefixes {
	l := policyData.NodeLimits
	o := &openaiPrefixes{
		clk: clk, log: cfg.Logger, every: cfg.OpenAIPrefixRefresh, file: cfg.OpenAIPrefixesCache, count: count,
		lim: prefixLimits{maxBytes: l.OpenAIPrefixBodyMaxBytes, maxEntries: l.OpenAIPrefixMax, minV4: l.OpenAIPrefixMinV4Bits, minV6: l.OpenAIPrefixMinV6Bits},
	}
	switch {
	case cfg.PrefixFetch != nil:
		o.fetch = cfg.PrefixFetch
	case cfg.OpenAIPrefixesURL != "":
		o.fetch = func(ctx context.Context) ([]byte, error) {
			return httpFetchList(ctx, cfg.OpenAIPrefixesURL, int64(o.lim.maxBytes))
		}
	}
	return o
}

// contains reports whether a is in the list in use (false when there is none).
func (o *openaiPrefixes) contains(a netip.Addr) bool {
	if set := o.cur.Load(); set != nil {
		return set.contains(a)
	}
	return false
}

// size is how many prefixes are in use, and age how long ago the list was installed (-1 when there is none).
func (o *openaiPrefixes) size() int {
	if set := o.cur.Load(); set != nil {
		return set.len()
	}
	return 0
}

func (o *openaiPrefixes) age() time.Duration {
	at := o.at.Load()
	if at == 0 {
		return -1
	}
	return o.clk.Now().Sub(time.Unix(0, at))
}

// apply reads body and, when it is a good list, puts it in use and (unless it came from the file) keeps it in the file. A list that is not good
// changes nothing, and the error says why in one of the outcome words.
func (o *openaiPrefixes) apply(body []byte, fromFile bool) error {
	prefixes, err := parsePrefixes(body, o.lim)
	if err != nil {
		return err
	}
	set := newPrefixSet(prefixes)
	o.cur.Store(set)
	o.at.Store(o.clk.Now().UnixNano())
	if !fromFile && o.file != "" {
		if werr := writeAtomic(o.file, encodePrefixes(set)); werr != nil {
			o.log.Warn("openai_prefixes_not_kept", "reason", "write_failed")
		}
	}
	return nil
}

// writeAtomic replaces path with data in one rename, so a crash never leaves half a list.
func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".prefixes-*")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(tmp.Name())
		return errors.Join(werr, cerr)
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return nil
}

// refresh fetches and applies once, and says what came of it.
func (o *openaiPrefixes) refresh(ctx context.Context) string {
	if o.fetch == nil {
		return prefixFetch
	}
	fctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	body, err := o.fetch(fctx)
	result := prefixOK
	switch {
	case err != nil && errors.Is(err, errPrefixTooLarge):
		result = prefixTooLarge
	case err != nil:
		result = prefixFetch
	default:
		if aerr := o.apply(body, false); aerr != nil {
			result = aerr.Error()
		}
	}
	o.count(result)
	if result == prefixOK {
		o.log.Info("openai_prefixes_refreshed", "prefixes", o.size())
	} else {
		o.log.Warn("openai_prefixes_refused", "reason", result, "keeping", o.size())
	}
	return result
}

// Run is the node's background task: the last good list from the file, then a refresh at start and every refresh period (a failed one is tried again
// after minutes, not a day), until the node ends.
func (o *openaiPrefixes) Run(ctx context.Context) {
	if o.file != "" {
		if body, err := os.ReadFile(o.file); err == nil {
			if aerr := o.apply(body, true); aerr != nil {
				o.log.Warn("openai_prefixes_file_refused", "reason", aerr.Error())
			}
		}
	}
	if o.fetch == nil {
		return
	}
	failures := 0
	for {
		wait := o.every
		if o.refresh(ctx) == prefixOK {
			failures = 0
		} else {
			failures++
			wait = min(5*time.Minute<<min(failures-1, 4), o.every)
		}
		if !o.clk.sleep(ctx, jitter(wait, 10)) {
			return
		}
	}
}

// httpFetchList is the one request the node makes to the publisher: HTTPS, no redirect, no credentials, at most limit bytes.
func httpFetchList(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("accept", "application/json")
	req.Header.Set("user-agent", "all-tunnel/"+version)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, errPrefixTooLarge
	}
	return body, nil
}

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testPrefixLimits() prefixLimits {
	l := policyData.NodeLimits
	return prefixLimits{maxBytes: l.OpenAIPrefixBodyMaxBytes, maxEntries: l.OpenAIPrefixMax, minV4: l.OpenAIPrefixMinV4Bits, minV6: l.OpenAIPrefixMinV6Bits}
}

func listOf(prefixes ...string) string {
	var items []string
	for _, p := range prefixes {
		key := "ipv4Prefix"
		if strings.Contains(p, ":") {
			key = "ipv6Prefix"
		}
		items = append(items, fmt.Sprintf(`{%q:%q}`, key, p))
	}
	return `{"creationTime":"2026-10-01T00:00:00.000000","prefixes":[` + strings.Join(items, ",") + `]}`
}

func TestPrefixes_AGoodListIsReadAndLooksUpIPv4AndIPv6(t *testing.T) {
	got, err := parsePrefixes([]byte(listOf("203.0.113.0/28", "198.51.100.64/26", "2001:db8:abcd::/48", "192.0.2.5/24")), testPrefixLimits())
	if err != nil {
		t.Fatal(err)
	}
	set := newPrefixSet(got)
	for addr, want := range map[string]bool{
		"203.0.113.7": true, "203.0.113.16": false, "198.51.100.100": true, "198.51.100.200": false, "2001:db8:abcd:1::9": true, "2001:db8:abce::1": false,
		"192.0.2.99":         true, // 192.0.2.5/24 is the /24
		"::ffff:203.0.113.7": true, "198.51.100.8": false,
	} {
		if set.contains(netip.MustParseAddr(addr)) != want {
			t.Errorf("%s: want %v", addr, want)
		}
	}
	if set.len() != 4 {
		t.Fatalf("%d prefixes", set.len())
	}
}

func TestPrefixes_ACorruptEmptyHugeOrTooWideListIsRefused(t *testing.T) {
	lim := testPrefixLimits()
	manyItems := make([]string, lim.maxEntries+1)
	for i := range manyItems {
		manyItems[i] = fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)
	}
	for name, c := range map[string]struct {
		body string
		want error
	}{
		"empty body":                 {"", errPrefixCorrupt},
		"not json":                   {"<html>", errPrefixCorrupt},
		"a list not an object":       {`[{"ipv4Prefix":"203.0.113.0/28"}]`, errPrefixCorrupt},
		"no prefixes key":            {`{"x":[]}`, errPrefixCorrupt},
		"an empty list":              {`{"prefixes":[]}`, errPrefixEmpty},
		"an entry that is a string":  {`{"prefixes":["203.0.113.0/28"]}`, errPrefixCorrupt},
		"an unknown key":             {`{"prefixes":[{"cidr":"203.0.113.0/28"}]}`, errPrefixCorrupt},
		"two keys in one entry":      {`{"prefixes":[{"ipv4Prefix":"203.0.113.0/28","ipv6Prefix":"2001:db8::/48"}]}`, errPrefixCorrupt},
		"a number as the prefix":     {`{"prefixes":[{"ipv4Prefix":5}]}`, errPrefixCorrupt},
		"not a prefix":               {`{"prefixes":[{"ipv4Prefix":"203.0.113.0"}]}`, errPrefixBad},
		"a v6 prefix under a v4 key": {`{"prefixes":[{"ipv4Prefix":"2001:db8::/48"}]}`, errPrefixBad},
		"a v4 prefix under a v6 key": {`{"prefixes":[{"ipv6Prefix":"203.0.113.0/28"}]}`, errPrefixBad},
		"everything":                 {listOf("0.0.0.0/0"), errPrefixBad},
		"half the internet":          {listOf("128.0.0.0/1"), errPrefixBad},
		"a wide v4 range":            {listOf("10.0.0.0/8"), errPrefixBad},
		"a wide v6 range":            {listOf("2000::/3"), errPrefixBad},
		"a mapped address":           {`{"prefixes":[{"ipv6Prefix":"::ffff:203.0.113.0/120"}]}`, errPrefixBad},
		"two good prefixes":          {listOf("203.0.113.0/28", "198.51.100.0/26") + "", nil},
		"too many entries":           {listOf(manyItems...), errPrefixTooMany},
		"a body that is too big":     {`{"prefixes":[],"pad":"` + strings.Repeat("x", lim.maxBytes) + `"}`, errPrefixTooLarge},
		"a repeated key":             {`{"prefixes":[{"ipv4Prefix":"203.0.113.0/28","ipv4Prefix":"198.51.100.0/26"}]}`, errPrefixCorrupt},
	} {
		_, err := parsePrefixes([]byte(c.body), lim)
		if c.want == nil {
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		if !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
	// one bad entry refuses the whole list
	if _, err := parsePrefixes([]byte(`{"prefixes":[{"ipv4Prefix":"203.0.113.0/28"},{"ipv4Prefix":"0.0.0.0/0"}]}`), lim); err == nil {
		t.Error("a list with one too-wide prefix was taken")
	}
}

type prefixHarness struct {
	o       *openaiPrefixes
	fc      *fakeClock
	results sync.Map // outcome word -> *atomic.Int64
	logs    *syncBuf
	file    string
}

func (h *prefixHarness) count(word string) int64 {
	if v, ok := h.results.Load(word); ok {
		return v.(*atomic.Int64).Load()
	}
	return 0
}

func newPrefixHarness(t *testing.T, fetch func(context.Context) ([]byte, error)) *prefixHarness {
	t.Helper()
	h := &prefixHarness{fc: newFakeClock(), logs: &syncBuf{}, file: filepath.Join(t.TempDir(), "prefixes.json")}
	cfg := DefaultConfig()
	cfg.OpenAIPrefixesCache = h.file
	cfg.PrefixFetch = fetch
	cfg.Logger = slog.New(slog.NewJSONHandler(h.logs, nil))
	h.o = newOpenAIPrefixes(&cfg, newClock(h.fc.Now, h.fc.AfterFunc), func(word string) {
		v, _ := h.results.LoadOrStore(word, &atomic.Int64{})
		v.(*atomic.Int64).Add(1)
	})
	return h
}

func TestPrefixes_ARefreshThatFailsKeepsTheLastGoodListAndAFileSurvivesARestart(t *testing.T) {
	var mu sync.Mutex
	body, fail := listOf("203.0.113.0/28"), error(nil)
	h := newPrefixHarness(t, func(context.Context) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		return []byte(body), fail
	})
	in := netip.MustParseAddr("203.0.113.5")
	if h.o.contains(in) {
		t.Fatal("a list that nobody read is in use")
	}
	if got := h.o.refresh(context.Background()); got != prefixOK || !h.o.contains(in) || h.o.size() != 1 {
		t.Fatalf("first refresh: %s, size %d", got, h.o.size())
	}
	good := h.o.cur.Load()
	for name, c := range map[string]struct {
		body string
		err  error
		want string
	}{
		"the publisher is down":   {"", errors.New("connection refused"), prefixFetch},
		"an empty list":           {`{"prefixes":[]}`, nil, prefixEmpty},
		"a corrupt body":          {"{{{", nil, prefixCorrupt},
		"a list of the internet":  {listOf("0.0.0.0/0"), nil, prefixBadPrefix},
		"a body past the limit":   {"", errPrefixTooLarge, prefixTooLarge},
		"a list with too many":    {listOf(strings.Split(strings.Repeat("10.1.1.0/24,", 2049), ",")[:2049]...), nil, prefixTooMany},
		"nothing but whitespace":  {"   ", nil, prefixCorrupt},
		"a list of another shape": {`{"prefixes":[{"cidr":"203.0.113.0/28"}]}`, nil, prefixCorrupt},
	} {
		mu.Lock()
		body, fail = c.body, c.err
		mu.Unlock()
		if got := h.o.refresh(context.Background()); got != c.want {
			t.Errorf("%s: outcome %q, want %q", name, got, c.want)
		}
		if h.o.cur.Load() != good || !h.o.contains(in) {
			t.Fatalf("%s: the list in use changed", name)
		}
	}
	// a new good list replaces it, and the file holds it
	mu.Lock()
	body, fail = listOf("198.51.100.0/26", "2001:db8::/32"), nil
	mu.Unlock()
	if h.o.refresh(context.Background()) != prefixOK || h.o.contains(in) || !h.o.contains(netip.MustParseAddr("198.51.100.9")) {
		t.Fatal("the new list was not taken")
	}
	// a restart with the publisher down: the file is the list
	restarted := newPrefixHarness(t, func(context.Context) ([]byte, error) { return nil, errors.New("down") })
	raw, err := os.ReadFile(h.file)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(restarted.file, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { restarted.o.Run(ctx); close(done) }()
	eventually(t, "the list from the file", 3*time.Second, func() bool { return restarted.o.size() == 2 })
	if !restarted.o.contains(netip.MustParseAddr("2001:db8:1::1")) {
		t.Fatal("the IPv6 prefix of the file is not in use")
	}
	eventually(t, "the failed refresh was counted", 3*time.Second, func() bool { return restarted.count(prefixFetch) >= 1 })
	if restarted.o.size() != 2 {
		t.Fatal("a failed refresh dropped the list of the file")
	}
	cancel()
	<-done
	if info, err := os.Stat(h.file); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("the file: %v %v", info, err)
	}
	// a file that is corrupt is ignored
	if err := os.WriteFile(restarted.file, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	again := newPrefixHarness(t, nil)
	again.file = restarted.file
	again.o.file = restarted.file
	again.o.Run(context.Background())
	if again.o.size() != 0 || !strings.Contains(again.logs.String(), "openai_prefixes_file_refused") {
		t.Fatalf("size %d logs %s", again.o.size(), again.logs.String())
	}
}

func TestPrefixes_RunRefreshesDailyAndRetriesAFailureSoonerNotAtOnce(t *testing.T) {
	var calls atomic.Int64
	var fail atomic.Bool
	fail.Store(true)
	h := newPrefixHarness(t, func(context.Context) ([]byte, error) {
		calls.Add(1)
		if fail.Load() {
			return nil, errors.New("down")
		}
		return []byte(listOf("203.0.113.0/28")), nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.o.Run(ctx)
	eventually(t, "the first attempt", 3*time.Second, func() bool { return calls.Load() == 1 })
	// 4 minutes later nothing was retried (the retry waits minutes, not seconds: the publisher is not hammered)
	h.fc.Advance(4 * time.Minute)
	time.Sleep(50 * time.Millisecond)
	if calls.Load() != 1 {
		t.Fatalf("%d calls after 4 minutes", calls.Load())
	}
	fail.Store(false)
	h.fc.Advance(2 * time.Minute)
	eventually(t, "the retry and the good list", 3*time.Second, func() bool { return h.o.size() == 1 })
	n := calls.Load()
	// then the next refresh is a day later (give or take the jitter that keeps nodes from calling in step)
	h.fc.Advance(20 * time.Hour)
	time.Sleep(50 * time.Millisecond)
	if calls.Load() != n {
		t.Fatalf("refreshed again before the day was over (%d calls, was %d)", calls.Load(), n)
	}
	h.fc.Advance(8 * time.Hour)
	eventually(t, "the daily refresh", 3*time.Second, func() bool { return calls.Load() == n+1 })
	if age := h.o.age(); age < 0 || age > time.Minute {
		t.Fatalf("age %s", age)
	}
}

func TestPrefixes_TheHTTPFetchReadsOneUrlWithoutRedirectsAndWithinTheLimit(t *testing.T) {
	var hits atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/list.json", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("cookie") != "" || r.Header.Get("authorization") != "" {
			t.Error("the fetch sent credentials")
		}
		_, _ = w.Write([]byte(listOf("203.0.113.0/28")))
	})
	mux.HandleFunc("/moved", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/list.json", http.StatusFound) })
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(make([]byte, 3000)) })
	mux.HandleFunc("/missing", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ctx := context.Background()
	if body, err := httpFetchList(ctx, srv.URL+"/list.json", 4096); err != nil || !strings.Contains(string(body), "203.0.113.0/28") {
		t.Fatalf("%q %v", body, err)
	}
	if _, err := httpFetchList(ctx, srv.URL+"/moved", 4096); err == nil {
		t.Fatal("a redirect was followed")
	}
	if _, err := httpFetchList(ctx, srv.URL+"/big", 1000); !errors.Is(err, errPrefixTooLarge) {
		t.Fatalf("%v", err)
	}
	if _, err := httpFetchList(ctx, srv.URL+"/missing", 4096); err == nil {
		t.Fatal("a 404 is not a list")
	}
}

func TestNode_ASourceInTheOpenAIListIsClassedOpenAIAndGetsLargerPerSourceLimits(t *testing.T) {
	release := make(chan struct{})
	e := newVIPEnv(t, func(e *testEnv, c *Config) {
		c.PerIPConcurrent, c.PerIPNewPerS, c.OpenAIPerIPFactor = 2, 1000, 4
		c.PrefixFetch = func(context.Context) ([]byte, error) { return []byte(listOf("192.0.2.0/24")), nil }
	})
	eventually(t, "the list", 3*time.Second, func() bool { return e.srv.openai.size() == 1 })
	d := e.newDevice()
	dc := e.connectOK(d)
	ds := dc.serve(holdHandler(d, release))
	defer close(release)
	held := func(ip string) int {
		n := 0
		for i := 0; i < 20; i++ {
			if _, err := e.clientFrom(ip, d); err == nil {
				n++
			}
		}
		return n
	}
	if n := held("198.51.100.1"); n != 2 {
		t.Fatalf("an ordinary source held %d, cap 2", n)
	}
	if n := held("192.0.2.1"); n != 8 {
		t.Fatalf("an OpenAI address held %d, want 2 x 4", n)
	}
	seen := map[string]bool{}
	for _, o := range ds.openList() {
		seen[o.str("peer_ip")+" "+o.str("class")] = true
	}
	if !seen["192.0.2.1 openai"] || !seen["198.51.100.1 anon"] {
		t.Fatalf("OPENs: %v", seen)
	}
	e.checkTranscript()
	_ = fmt.Sprint
}

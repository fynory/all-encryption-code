package main

import (
	"hash/maphash"
	"net/netip"
	"sync"
	"time"
)

// Limits of the public listener (the design plan, section 5): who may hold how many connections, how fast new ones may arrive, and who is dropped
// for trying names that are not a device. Everything is kept only in memory, for the life of the process: a source's address is a map key here and is never
// part of a log line, a metric label or a file (a log line that must tell two sources apart uses Server.short, the per-boot salted short hash).
//
// A source is an IPv4 address, or the /64 (policy node_limits.ipv6_prefix_bits) of an IPv6 one, so that rotating inside a prefix an attacker owns does not
// make new sources. An address of the OpenAI prefix list gets limits openai_per_ip_factor times larger (one egress address serves many users), is never
// banned, and is still bounded: the list is a quota class, not an allowlist (anyone can make ChatGPT call a name through those addresses).
//
// A device is a source too, and a busy one: for every client stream it serves it opens one data connection to the node, from one address. While an address
// holds a device's authenticated control connection its limits are device_per_ip_factor times larger, and the connections that prove who they are (the
// control connection once it authenticates, a data connection once it attaches) give back the token they took from the bucket: a device is not
// charged for serving its clients, only for what it tries before it has proven itself.

// Why a connection was refused before any byte of it was read, as the metrics name it.
const (
	refuseBanned     = "ip_banned"
	refuseRate       = "ip_rate"
	refuseConcurrent = "ip_concurrent"
)

// ipEntry is what the node remembers of one source.
type ipEntry struct {
	conns    int       // connections it holds now (pre-hello, and its client streams)
	tokens   float64   // new-connection bucket
	refilled time.Time // when tokens were last computed
	banUntil time.Time
	strikes  []uint64  // the distinct names (or junk hellos) tried in the current window, as per-boot hashes: never the names
	strikeAt time.Time // when the current window began
	junk     uint64
}

// ipLimits is the table of sources. It is safe for concurrent use.
type ipLimits struct {
	clk clock

	concurrent int
	rate       float64 // new connections per second, and the burst
	factor     int     // the multiple of the limits an address of the OpenAI list has
	devFactor  int     // and an address that holds an authenticated control connection
	v6bits     int
	max        int
	strikeMax  int
	window     time.Duration
	ban        time.Duration

	seed maphash.Seed

	mu        sync.Mutex
	entries   map[netip.Addr]*ipEntry
	overflow  ipEntry                  // the shared entry of every source that does not fit in the table
	devices   map[netip.Addr]int       // the sources that hold an authenticated control connection, and how many
	past      map[netip.Addr]time.Time // the sources that held one and let go of it, and when: a device that reconnects is not an anonymous source (pastTTL)
	pastTTL   time.Duration
	lastSweep time.Time

	overflowed, bans uint64 // counters for the metrics
}

func newIPLimits(cfg *Config, clk clock, seed maphash.Seed) *ipLimits {
	return &ipLimits{
		clk: clk, concurrent: cfg.PerIPConcurrent, rate: float64(cfg.PerIPNewPerS), factor: cfg.OpenAIPerIPFactor, devFactor: cfg.DevicePerIPFactor, v6bits: cfg.IPv6PrefixBits,
		max: cfg.IPTableMax, strikeMax: cfg.UnknownSNIPerIP, window: cfg.UnknownSNIWindow, ban: cfg.UnknownSNIBan, seed: seed,
		entries: map[netip.Addr]*ipEntry{}, devices: map[netip.Addr]int{}, past: map[netip.Addr]time.Time{}, pastTTL: cfg.HintTTL,
	}
}

// keyOf is the identity limits are kept under.
func (l *ipLimits) keyOf(a netip.Addr) netip.Addr {
	a = a.WithZone("").Unmap()
	if a.Is6() {
		if p, err := a.Prefix(l.v6bits); err == nil {
			return p.Addr()
		}
	}
	return a
}

// entryLocked finds or makes the entry of key. A full table is swept of the idle ones first (at most once a second); when it is still full the source
// shares the overflow entry, which has the limits of a crowd (the table's size divided by 1024 times a source's), never none.
func (l *ipLimits) entryLocked(key netip.Addr, now time.Time) (*ipEntry, int) {
	if e := l.entries[key]; e != nil {
		return e, 1
	}
	if len(l.entries) >= l.max && now.Sub(l.lastSweep) >= time.Second {
		l.sweepLocked(now)
	}
	if len(l.entries) >= l.max {
		l.overflowed++
		return &l.overflow, max(1, l.max/1024)
	}
	e := &ipEntry{tokens: l.rate, refilled: now}
	l.entries[key] = e
	return e, 1
}

// sweepLocked forgets the sources that hold nothing, are not banned, have a full bucket and no strikes in the window.
func (l *ipLimits) sweepLocked(now time.Time) {
	l.lastSweep = now
	for key, e := range l.entries {
		if e.conns == 0 && !now.Before(e.banUntil) && now.Sub(e.refilled) >= time.Second && now.Sub(e.strikeAt) >= l.window {
			delete(l.entries, key)
		}
	}
}

// Sweep is the periodic cleanup (a background task calls it), so an idle table shrinks without a new source having to arrive.
func (l *ipLimits) Sweep() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clk.Now()
	l.sweepLocked(now)
	for key, at := range l.past {
		if now.Sub(at) >= l.pastTTL {
			delete(l.past, key)
		}
	}
}

// multLocked is the multiple of a plain source's limits that key has: the crowd's (scale) for the overflow entry, times the larger of the OpenAI list's
// and a device's.
func (l *ipLimits) multLocked(key netip.Addr, scale int, openai bool) int {
	mult := scale
	switch {
	case openai:
		mult *= l.factor
	case l.devices[key] > 0:
		mult *= l.devFactor
	}
	return mult
}

// markDevice records that a device holds an authenticated control connection from addr, until the function it returns is called (once).
func (l *ipLimits) markDevice(addr netip.Addr) (unmark func()) {
	key := l.keyOf(addr)
	l.mu.Lock()
	if l.devices[key]++; l.devices[key] == 1 {
		// The bucket of this address was made when the control connection was admitted, with a plain source's burst: it now holds the device's.
		e, scale := l.entries[key], 1
		if e == nil {
			e, scale = &l.overflow, max(1, l.max/1024)
		}
		e.tokens = max(e.tokens, l.rate*float64(l.multLocked(key, scale, false)))
	}
	l.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			if l.devices[key]--; l.devices[key] <= 0 {
				delete(l.devices, key)
				if len(l.past) < l.max { // a table that is full forgets the newest, never grows: the address is simply not remembered as a device's
					l.past[key] = l.clk.Now()
				}
			}
		})
	}
}

// knownDevice reports whether addr holds an authenticated control connection now or let go of one less than hint_ttl_s ago: a device that reconnects after its
// connection dropped is not an anonymous source (it is unauthenticated until its PROOF, and it is what an attack on the unauthenticated budget must not lock out).
func (l *ipLimits) knownDevice(addr netip.Addr) bool {
	key := l.keyOf(addr)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.devices[key] > 0 {
		return true
	}
	at, ok := l.past[key]
	return ok && l.clk.Now().Sub(at) < l.pastTTL
}

// isDevice reports whether addr holds an authenticated control connection now.
func (l *ipLimits) isDevice(addr netip.Addr) bool {
	key := l.keyOf(addr)
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.devices[key] > 0
}

// refund gives back the new-connection token that admit took for a connection that has since proved who it is (a device's control connection after its
// proof, a data connection after its ATTACH): those are not what the per-source rate is there to bound.
func (l *ipLimits) refund(addr netip.Addr, openai bool) {
	key := l.keyOf(addr)
	l.mu.Lock()
	defer l.mu.Unlock()
	e, scale := l.entries[key], 1
	if e == nil {
		e, scale = &l.overflow, max(1, l.max/1024)
	}
	e.tokens = min(l.rate*float64(l.multLocked(key, scale, openai)), e.tokens+1)
}

// admit decides whether a new connection from addr may be served. It returns the function that gives its slot back (once), or the reason it was
// refused. The new-connection bucket is charged for every accepted connection, the concurrent count until release is called.
func (l *ipLimits) admit(addr netip.Addr, openai bool) (release func(), refused string) {
	now := l.clk.Now()
	key := l.keyOf(addr)
	l.mu.Lock()
	defer l.mu.Unlock()
	e, scale := l.entryLocked(key, now)
	mult := l.multLocked(key, scale, openai)
	if !openai && now.Before(e.banUntil) {
		return nil, refuseBanned
	}
	burst := l.rate * float64(mult) // the bucket holds a second's worth of new connections and refills at that rate
	e.tokens = min(burst, e.tokens+now.Sub(e.refilled).Seconds()*burst)
	e.refilled = now
	if e.tokens < 1 {
		return nil, refuseRate
	}
	if e.conns >= l.concurrent*mult {
		return nil, refuseConcurrent
	}
	e.tokens--
	e.conns++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			e.conns--
			l.mu.Unlock()
		})
	}, ""
}

// strike records that addr tried name, which is not a device that is online (name "" for a ClientHello that is no TLS or names nothing: each one is a
// strike of its own). The same name again within the window costs nothing, so ChatGPT retrying an offline device is not a scan; more than the
// budget of distinct names bans the source for the ban period, which is reported (true) once. An address of the OpenAI list is never struck, nor are the
// sources that do not fit in the table (they share one entry that must never be banned).
func (l *ipLimits) strike(addr netip.Addr, name string, openai bool) (banned bool) {
	if openai {
		return false
	}
	now := l.clk.Now()
	key := l.keyOf(addr)
	l.mu.Lock()
	defer l.mu.Unlock()
	e, _ := l.entryLocked(key, now)
	if e == &l.overflow {
		// The overflow entry is a crowd, not a source: a scanner inside it must not ban every other new source for the ban period. Its limits (concurrent
		// and rate) are the crowd's whole defence.
		return false
	}
	if now.Sub(e.strikeAt) >= l.window {
		e.strikes, e.strikeAt = e.strikes[:0], now
	}
	var h uint64
	if name != "" {
		h = maphash.String(l.seed, name)
		for _, seen := range e.strikes {
			if seen == h {
				return false
			}
		}
	} else {
		e.junk++
		h = e.junk // a counter cannot collide with a name's hash in practice, and a repeat of it would only cost a strike
	}
	e.strikes = append(e.strikes, h)
	if len(e.strikes) <= l.strikeMax {
		return false
	}
	e.strikes, e.banUntil = e.strikes[:0], now.Add(l.ban)
	l.bans++
	return true
}

// snapshot is what the metrics report: the size of the table, the sources banned now, the bans and the overflows so far.
func (l *ipLimits) snapshot() (size, banned int, bans, overflowed uint64) {
	now := l.clk.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.entries {
		if now.Before(e.banUntil) {
			banned++
		}
	}
	return len(l.entries), banned, l.bans, l.overflowed
}

// bucket is a token bucket: rate tokens a second up to burst.
type bucket struct {
	tokens   float64
	refilled time.Time
}

// take spends one token at now; it reports false when there is none.
func (b *bucket) take(now time.Time, rate, burst float64) bool {
	if b.refilled.IsZero() {
		b.tokens = burst
	} else {
		b.tokens = min(burst, b.tokens+now.Sub(b.refilled).Seconds()*rate)
	}
	b.refilled = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// logSampler lets a log line that a flood can repeat out at most once a second per reason, with how many were left out: an attack must not fill the disk
// through the log (nor hide the other lines in it).
type logSampler struct {
	clk clock
	mu  sync.Mutex
	at  map[string]time.Time
	cut map[string]int
}

func newLogSampler(clk clock) *logSampler {
	return &logSampler{clk: clk, at: map[string]time.Time{}, cut: map[string]int{}}
}

// allow reports whether a line for reason may be written now, and how many of its kind were left out since the last one.
func (l *logSampler) allow(reason string) (ok bool, suppressed int) {
	now := l.clk.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if last, seen := l.at[reason]; seen && now.Sub(last) < time.Second {
		l.cut[reason]++
		return false, 0
	}
	l.at[reason] = now
	suppressed = l.cut[reason]
	delete(l.cut, reason)
	return true, suppressed
}

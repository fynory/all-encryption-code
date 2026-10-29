package main

import (
	"net/netip"
	"sync"
	"time"
)

// HINT (the design plan, sections 2 and 5): a device tells its node which source addresses just completed authenticated calls to it. They get the
// slice of the device's stream cap that anonymous sources cannot use (policy node_limits.label_hint_slice), so a flood from many addresses cannot lock
// out the one that is ChatGPT. The table is memory only, an address stays good for hint_ttl_s after the last HINT that named it, a device can mark
// at most hint_addresses_per_label addresses (the oldest go first), and a mark is filed under the host the control plane's answer gave that connection:
// a device cannot mark an address for any host but its own.

type hintSet struct {
	until map[netip.Addr]time.Time
}

// hintTable is the node's record of the addresses devices marked good, per device host.
type hintTable struct {
	clk clock
	ttl time.Duration
	cap int

	mu    sync.Mutex
	hosts map[string]*hintSet
}

func newHintTable(clk clock, ttl time.Duration, perLabel int) *hintTable {
	return &hintTable{clk: clk, ttl: ttl, cap: perLabel, hosts: map[string]*hintSet{}}
}

// mark records the addresses (never more than the protocol's list) as good for host from now until the TTL.
func (h *hintTable) mark(host string, addrs []netip.Addr) {
	now := h.clk.Now()
	h.mu.Lock()
	defer h.mu.Unlock()
	set := h.hosts[host]
	if set == nil {
		set = &hintSet{until: map[netip.Addr]time.Time{}}
		h.hosts[host] = set
	}
	for _, a := range addrs {
		set.until[a.WithZone("").Unmap()] = now.Add(h.ttl)
	}
	if len(set.until) <= h.cap {
		return
	}
	for a, t := range set.until { // expired first
		if !now.Before(t) {
			delete(set.until, a)
		}
	}
	for len(set.until) > h.cap { // then the ones that will expire soonest, which are the ones marked longest ago
		var oldest netip.Addr
		var first time.Time
		for a, t := range set.until {
			if first.IsZero() || t.Before(first) {
				oldest, first = a, t
			}
		}
		delete(set.until, oldest)
	}
}

// good reports whether the device of host marked addr and the mark has not expired.
func (h *hintTable) good(host string, addr netip.Addr) bool {
	now := h.clk.Now()
	addr = addr.WithZone("").Unmap()
	h.mu.Lock()
	defer h.mu.Unlock()
	set := h.hosts[host]
	if set == nil {
		return false
	}
	t, ok := set.until[addr]
	return ok && now.Before(t)
}

// goodAnywhere reports whether the device of ANY host marked addr and the mark has not expired.
func (h *hintTable) goodAnywhere(addr netip.Addr) bool {
	now := h.clk.Now()
	addr = addr.WithZone("").Unmap()
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, set := range h.hosts {
		if t, ok := set.until[addr]; ok && now.Before(t) {
			return true
		}
	}
	return false
}

// Sweep forgets what expired (a background task calls it).
func (h *hintTable) Sweep() {
	now := h.clk.Now()
	h.mu.Lock()
	defer h.mu.Unlock()
	for host, set := range h.hosts {
		for a, t := range set.until {
			if !now.Before(t) {
				delete(set.until, a)
			}
		}
		if len(set.until) == 0 {
			delete(h.hosts, host)
		}
	}
}

// size is the number of addresses held, for the metrics (an aggregate: never per device).
func (h *hintTable) size() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, set := range h.hosts {
		n += len(set.until)
	}
	return n
}

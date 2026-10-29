package main

import (
	"sync"
	"time"
)

// The gated thin pipe (the design plan, sections 3 and 5). A device whose trial ended, or whose license lapsed within the policy's cut-off, is
// authorized as gated: it is served, but only a little (policy gated.bytes_per_day and gated.streams_per_day), enough for its paywall card to reach
// ChatGPT. The device's own gate is not a boundary against its owner (he can edit his files), so THIS is: the node counts, and it counts on every
// status the control plane gives, a RENEW included, so a device that turns gated in the middle of a connection is held to the budget from that moment
// on, its streams already open included (they are cut when the bytes run out).
//
// The count is per UTC day and per device host, in memory. What a device used while gated is not forgotten by reconnecting; it is forgotten at midnight.

// dayUsage is what one device host used of its gated budget today.
type dayUsage struct {
	mu      sync.Mutex
	day     int64
	bytes   int64
	streams int
	users   int // streams holding this record: it is never swept while there are any
}

// rollLocked starts a new day's count when the day changed.
func (u *dayUsage) rollLocked(now time.Time) {
	if day := now.Unix() / 86400; day != u.day {
		u.day, u.bytes, u.streams = day, 0, 0
	}
}

// admit counts a new stream of a gated device, or refuses it (reason says which budget is spent). A byte budget that is already spent also refuses:
// the stream would get nothing.
func (u *dayUsage) admit(now time.Time, bytesMax int64, streamsMax int) (ok bool, reason string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.rollLocked(now)
	switch {
	case u.streams >= streamsMax:
		return false, "gated_streams"
	case u.bytes >= bytesMax:
		return false, "gated_bytes"
	}
	u.streams++
	return true, ""
}

// charge takes n bytes of today's budget and returns how many of them may be forwarded: all of them while there is budget, fewer at the edge, none
// after it.
func (u *dayUsage) charge(now time.Time, n, bytesMax int64) int64 {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.rollLocked(now)
	take := min(n, max(bytesMax-u.bytes, 0))
	u.bytes += take
	return take
}

// gateTable keeps the usage of every device host that was gated today.
type gateTable struct {
	clk clock

	mu     sync.Mutex
	byHost map[string]*dayUsage
}

func newGateTable(clk clock) *gateTable { return &gateTable{clk: clk, byHost: map[string]*dayUsage{}} }

// acquire gives the usage record of host (made when there is none) and counts the caller as a user; release gives it back.
func (g *gateTable) acquire(host string) *dayUsage {
	g.mu.Lock()
	defer g.mu.Unlock()
	u := g.byHost[host]
	if u == nil {
		u = &dayUsage{day: g.clk.Now().Unix() / 86400}
		g.byHost[host] = u
	}
	u.mu.Lock()
	u.users++
	u.mu.Unlock()
	return u
}

func (g *gateTable) release(u *dayUsage) {
	u.mu.Lock()
	u.users--
	u.mu.Unlock()
}

// Sweep forgets the records nobody holds that have nothing to remember: a previous day's, or an empty one (a background task calls it).
func (g *gateTable) Sweep() {
	now := g.clk.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	for host, u := range g.byHost {
		u.mu.Lock()
		if u.users == 0 {
			u.rollLocked(now)
			if u.bytes == 0 && u.streams == 0 {
				delete(g.byHost, host)
			}
		}
		u.mu.Unlock()
	}
}

// size is the number of device hosts with a record, for the metrics.
func (g *gateTable) size() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.byHost)
}

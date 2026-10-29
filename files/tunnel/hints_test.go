package main

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func newTestHints(ttl time.Duration, perLabel int) (*hintTable, *fakeClock) {
	fc := newFakeClock()
	return newHintTable(newClock(fc.Now, fc.AfterFunc), ttl, perLabel), fc
}

func addrs(texts ...string) []netip.Addr {
	var out []netip.Addr
	for _, t := range texts {
		out = append(out, netip.MustParseAddr(t))
	}
	return out
}

func TestHints_AMarkLastsItsTTLFromTheLastHintAndBelongsToOneHost(t *testing.T) {
	h, fc := newTestHints(15*time.Minute, 64)
	a := netip.MustParseAddr("203.0.113.5")
	h.mark("one.example", addrs("203.0.113.5"))
	if !h.good("one.example", a) {
		t.Fatal("not good right after the HINT")
	}
	if h.good("two.example", a) {
		t.Fatal("a mark for one host counts for another")
	}
	fc.Advance(14 * time.Minute)
	if !h.good("one.example", a) {
		t.Fatal("expired early")
	}
	h.mark("one.example", addrs("203.0.113.5")) // the device says it again: the clock starts over
	fc.Advance(14 * time.Minute)
	if !h.good("one.example", a) {
		t.Fatal("a repeated HINT did not renew the mark")
	}
	fc.Advance(2 * time.Minute)
	if h.good("one.example", a) {
		t.Fatal("outlived its TTL")
	}
	h.Sweep()
	if h.size() != 0 {
		t.Fatalf("%d left after the sweep", h.size())
	}
}

func TestHints_AddressesAreCompared_AsTheyAre_WithoutZoneOrMapping(t *testing.T) {
	h, _ := newTestHints(time.Hour, 64)
	h.mark("h", addrs("::ffff:203.0.113.9", "fe80::1%eth0"))
	if !h.good("h", netip.MustParseAddr("203.0.113.9")) {
		t.Fatal("an IPv4-mapped mark is the IPv4 address")
	}
	if !h.good("h", netip.MustParseAddr("fe80::1")) {
		t.Fatal("a zone is not part of an address")
	}
	if h.good("h", netip.MustParseAddr("203.0.113.10")) {
		t.Fatal("the neighbouring address is good too")
	}
}

func TestHints_ADeviceCanMarkOnlyAFixedNumberAndTheOldestGoFirst(t *testing.T) {
	h, fc := newTestHints(time.Hour, 5)
	for i := 0; i < 5; i++ {
		h.mark("h", addrs(fmt.Sprintf("203.0.113.%d", i+1)))
		fc.Advance(time.Second)
	}
	h.mark("h", addrs("203.0.113.100", "203.0.113.101"))
	if h.size() != 5 {
		t.Fatalf("%d addresses, cap 5", h.size())
	}
	for _, gone := range []string{"203.0.113.1", "203.0.113.2"} {
		if h.good("h", netip.MustParseAddr(gone)) {
			t.Fatalf("%s kept although it is the oldest", gone)
		}
	}
	for _, kept := range []string{"203.0.113.3", "203.0.113.5", "203.0.113.100", "203.0.113.101"} {
		if !h.good("h", netip.MustParseAddr(kept)) {
			t.Fatalf("%s lost", kept)
		}
	}
	// a flood of hints cannot grow the table without bound
	for i := 0; i < 1000; i++ {
		h.mark("h", addrs(fmt.Sprintf("198.51.100.%d", i%250)))
	}
	if h.size() > 5 {
		t.Fatalf("%d addresses after a flood", h.size())
	}
}

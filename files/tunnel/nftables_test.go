package main

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// deploy/nftables.conf and deploy/sysctl.conf cannot be run on the machines the tests run on (no nftables, no root), so what is tested is what can be:
// that the kernel's limits are never stricter than the node's own (a retuned policy must not leave the kernel refusing what the node would serve), that
// the file only adds drops, and that it touches no port but the node's two.

func readDeploy(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile("deploy/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func nftLines(conf string) []string {
	var out []string
	for _, line := range strings.Split(conf, "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

func TestNftables_TheKernelNeverRefusesWhatTheNodeWouldServe(t *testing.T) {
	conf := readDeploy(t, "nftables.conf")
	l := policyData.NodeLimits
	factor := max(l.OpenAIPerIPFactor, l.DevicePerIPFactor)
	perSourceHeld := l.PerIPConcurrent * factor
	perSourceRate := l.PerIPNewPerS * factor
	numbers := func(re string) []int {
		var out []int
		for _, m := range regexp.MustCompile(re).FindAllStringSubmatch(conf, -1) {
			n, _ := strconv.Atoi(m[1])
			out = append(out, n)
		}
		return out
	}
	held := numbers(`tcp dport 443 ct state new add @held[46] \{[^}]*ct count over (\d+)`)
	rate := numbers(`tcp dport 443 ct state new add @rate[46] \{[^}]*limit rate over (\d+)/second`)
	burst := numbers(`tcp dport 443 ct state new add @rate[46] \{[^}]*burst (\d+) packets`)
	if len(held) != 2 || len(rate) != 2 || len(burst) != 2 {
		t.Fatalf("the rules of :443 per source (IPv4 and IPv6 each): held %v rate %v burst %v", held, rate, burst)
	}
	for _, n := range held {
		// the kernel counts a device's data connections too (one per open stream, the node frees its own slot at attach): room for one device at its cap
		if n < l.LabelStreamsMax+1 {
			t.Errorf("the kernel holds a source to %d connections, a device at its cap of %d streams holds %d", n, l.LabelStreamsMax, l.LabelStreamsMax+1)
		}
		if n < perSourceHeld {
			t.Errorf("the kernel holds a source to %d connections, the node allows an OpenAI address %d", n, perSourceHeld)
		}
	}
	for _, n := range rate {
		if n < perSourceRate {
			t.Errorf("the kernel allows %d new connections a second per source, the node allows an OpenAI address %d", n, perSourceRate)
		}
	}
	for i, n := range burst {
		if n < rate[i] {
			t.Errorf("a burst of %d is smaller than the rate %d", n, rate[i])
		}
	}
	// an IPv6 source is the policy's prefix: the mask of the rules is that many bits
	mask := regexp.MustCompile(`ip6 saddr & ((?:[0-9a-f]{4}:)+:)`).FindStringSubmatch(conf)
	if mask == nil || strings.Count(mask[1], "ffff") != l.IPv6PrefixBits/16 || l.IPv6PrefixBits%16 != 0 {
		t.Errorf("the IPv6 mask %v is not the policy's %d bits", mask, l.IPv6PrefixBits)
	}
	// the whole node: the global flood limit is above everything the node could serve at once
	if all := numbers(`tcp dport \{ 80, 443 \} ct state new limit rate over (\d+)/second`); len(all) != 1 || all[0] < l.GlobalStreamsMax {
		t.Errorf("the global limit %v must exceed the node's %d streams", all, l.GlobalStreamsMax)
	}
	// port 80 serves one webroot: its limits are small, and the rules for it exist for IPv4 and IPv6
	if h80 := numbers(`tcp dport 80 ct state new add @held80_[46] \{[^}]*ct count over (\d+)`); len(h80) != 2 || h80[0] > held[0] {
		t.Errorf("port 80 holds %v", h80)
	}
}

func TestNftables_LoadingTheFileTwiceDoesNotStackItsRules(t *testing.T) {
	lines := nftLines(readDeploy(t, "nftables.conf"))
	var ensure, drop, body = -1, -1, -1
	for i, line := range lines {
		switch {
		case line == "table inet all_tunnel" && ensure < 0:
			ensure = i
		case line == "delete table inet all_tunnel":
			drop = i
		case line == "table inet all_tunnel {":
			body = i
		}
	}
	if ensure < 0 || drop != ensure+1 || body != drop+1 {
		t.Fatalf("want 'table', 'delete table' and the table's body in a row, got lines %d, %d, %d", ensure, drop, body)
	}
}

func TestNftables_OnlyAddsDropsAndTouchesOnlyThePortsOfTheNode(t *testing.T) {
	conf := readDeploy(t, "nftables.conf")
	if !strings.Contains(conf, "policy accept") || strings.Contains(conf, "policy drop") {
		t.Fatal("the chain must accept by default: loading the fragment must never lock the operator out")
	}
	for _, line := range nftLines(conf) {
		if !strings.Contains(line, "dport") {
			continue
		}
		if !regexp.MustCompile(`^tcp dport (443|80|\{ 80, 443 \}) `).MatchString(line) {
			t.Errorf("a rule on a port that is not the node's: %s", line)
		}
		if !strings.HasSuffix(line, "drop") {
			t.Errorf("a rule that is not a drop: %s", line)
		}
	}
	// every set the rules name is declared, and every set declared is used
	declared := regexp.MustCompile(`set (\w+) \{`).FindAllStringSubmatch(conf, -1)
	for _, m := range declared {
		if strings.Count(conf, "@"+m[1]+" ") == 0 {
			t.Errorf("set %s is declared and never used", m[1])
		}
	}
	for _, m := range regexp.MustCompile(`@(\w+) `).FindAllStringSubmatch(conf, -1) {
		if !strings.Contains(conf, "set "+m[1]+" {") {
			t.Errorf("set %s is used and never declared", m[1])
		}
	}
	if strings.Count(conf, "{")-strings.Count(conf, "}") != 0 {
		t.Error("unbalanced braces")
	}
}

func TestSysctl_SYNCookiesAreOn(t *testing.T) {
	conf := readDeploy(t, "sysctl.conf")
	if !regexp.MustCompile(`(?m)^net\.ipv4\.tcp_syncookies\s*=\s*1\s*$`).MatchString(conf) {
		t.Fatal("net.ipv4.tcp_syncookies = 1 is not set")
	}
}

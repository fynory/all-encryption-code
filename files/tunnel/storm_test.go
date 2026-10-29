package main

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// A node that restarts meets every device at once. The control plane is asked by at most authorize_max_concurrent calls at a time, what waits is
// bounded, the rest is told to try again, and the devices (who back off) all get in.

func TestStorm_AFleetReconnectsAtOnceAfterANodeRestartAndTheControlPlaneNeverSeesMoreThanTheBound(t *testing.T) {
	var lim syscall.Rlimit
	_ = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim)
	devices := 1000
	if lim.Cur < 8192 {
		devices = max(60, int(lim.Cur)/12)
	}
	e, cp := httpNode(t, nil, func(c *Config) {
		c.HelloTimeout, c.FirstLineTimeout, c.AuthorizeTimeout = 10*time.Second, 20*time.Second, 10*time.Second
		c.MaxUnauth = 64 // small, so that the storm really exceeds what may wait for the control plane
	})
	cp.mu.Lock()
	cp.delay = 25 * time.Millisecond
	cp.mu.Unlock()
	all := make([]*testDevice, devices)
	for i := range all {
		all[i] = e.newDevice()
	}

	var connected, refusedBusy atomic.Int64
	var wg sync.WaitGroup
	for _, d := range all {
		wg.Add(1)
		go func(d *testDevice) {
			defer wg.Done()
			for attempt := 0; attempt < 60; attempt++ {
				line := helloOnce(e, d)
				switch {
				case strings.HasPrefix(line, "OK "):
					connected.Add(1)
					return
				case line == "ERR control_unavailable" || strings.HasPrefix(line, "unreachable"):
					refusedBusy.Add(1)
					time.Sleep(time.Duration(30+attempt*10) * time.Millisecond) // the device's backoff
				default:
					t.Errorf("a device was refused with %q", line)
					return
				}
			}
			t.Errorf("a device never got in")
		}(d)
	}
	wg.Wait()
	if int(connected.Load()) != devices {
		t.Fatalf("%d of %d devices connected", connected.Load(), devices)
	}
	if peak := cp.maxInflight(); peak > policyData.Authorization.AuthorizeMaxConcur {
		t.Fatalf("the control plane saw %d authorizations at once, the bound is %d", peak, policyData.Authorization.AuthorizeMaxConcur)
	}
	if refusedBusy.Load() == 0 {
		t.Log("(the storm never exceeded what may wait; the bound was still respected)")
	}
	for _, d := range all[:5] {
		if !e.srv.Online(d.host) {
			t.Fatal("a connected device is not online")
		}
	}
	t.Log(fmt.Sprintf("%d devices, %d told to try again, peak %d at the control plane", devices, refusedBusy.Load(), cp.maxInflight()))
}

// helloOnce is a whole HELLO of d on its own connection, as a device does it: the node's final line, or "unreachable: ..." when the node would not
// even take the connection (it is full of connections that have not authenticated yet). The connection is left open: a device that got in stays in.
func helloOnce(e *testEnv, d *testDevice) string {
	c, err := e.dialNode()
	if err != nil {
		return "unreachable: " + err.Error()
	}
	br := bufio.NewReader(c)
	read := func() string {
		_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
		l, err := br.ReadString('\n')
		if err != nil {
			return "unreachable: " + err.Error()
		}
		return strings.TrimSuffix(l, "\n")
	}
	session := e.session(d, nil)
	_, _ = io.WriteString(c, "HELLO 2 "+session+"\n")
	line := read()
	if nonce, ok := strings.CutPrefix(line, "CHALLENGE "); ok {
		_, _ = io.WriteString(c, "PROOF "+e.proof(d, session, nonce, nil)+"\n")
		line = read()
	}
	if !strings.HasPrefix(line, "OK ") {
		_ = c.Close()
	} else {
		e.t.Cleanup(func() { _ = c.Close() })
	}
	return line
}

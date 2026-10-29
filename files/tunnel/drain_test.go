package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// SIGTERM drains (the design plan, section 5): nothing new is accepted, what is open finishes, the devices are told to prefer the other node,
// and the node is gone by the end of the quiet period.

func drainAsync(e *testEnv, quiet time.Duration) (done chan struct{}, started time.Time) {
	done = make(chan struct{})
	started = time.Now()
	go func() {
		e.srv.Drain(quiet)
		close(done)
	}()
	return done, started
}

func TestDrain_NothingNewIsAcceptedOpenStreamsContinueDrainIsDeliveredAndTheNodeLeavesWhenTheyEnd(t *testing.T) {
	e := newTestEnv(t, nil)
	d, other := e.newDevice(), e.newDevice()
	dc := e.connectOK(d)
	ds := dc.serve(nil)
	oc := e.connectOK(other)
	otherServer := oc.serve(nil)

	c, err := e.clientTLS(d)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := postOver(c, d.host, []byte("before")); err != nil || string(resp) != "echo:before" {
		t.Fatalf("%q %v", resp, err)
	}

	quiet := 8 * time.Second
	done, started := drainAsync(e, quiet)
	for name, dev := range map[string]*devServer{"first": ds, "second": otherServer} {
		dev := dev
		eventually(t, name+" told DRAIN", 3*time.Second, func() bool { return containsLine(dev.otherLines(), "DRAIN "+strconv.Itoa(int(quiet/time.Second))) })
	}

	// no new client: the TLS alert, no OPEN, nothing forwarded
	opens := ds.openCount()
	if _, err := e.clientTLS(d); err == nil {
		t.Fatal("a client was accepted by a draining node")
	}
	if _, err := e.clientTLS(other); err == nil {
		t.Fatal("a client of another device was accepted by a draining node")
	}
	time.Sleep(100 * time.Millisecond)
	if ds.openCount() != opens || otherServer.openCount() != 0 {
		t.Fatal("a draining node sent an OPEN")
	}
	// no new device: told to go to the other node
	stranger := e.newDevice()
	sc := e.connect(stranger)
	if line := sc.hello(func() string { return e.session(stranger, nil) }, func(s, n string) string { return e.proof(stranger, s, n, nil) }); line != "ERR control_unavailable" {
		t.Fatalf("a HELLO during a drain: %q", line)
	}
	// the stream that was open goes on, and so does a RENEW of the device that holds it
	if resp, err := postOver(c, d.host, []byte("during")); err != nil || string(resp) != "echo:during" {
		t.Fatalf("an open stream during a drain: %q %v", resp, err)
	}
	dc.drainFeed() // the DRAIN line the device was sent is still unread
	if r := dc.renew(); !strings.HasPrefix(r, "OK ") {
		t.Fatalf("renew during a drain: %q", r)
	}
	select {
	case <-done:
		t.Fatal("the node left with a stream open")
	case <-time.After(300 * time.Millisecond):
	}

	// the last stream ends: the node closes the devices (CLOSE drain) and exits well inside the quiet period
	_ = c.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the node did not leave when its last stream ended")
	}
	if took := time.Since(started); took >= quiet {
		t.Fatalf("it took %s, the quiet period is %s", took, quiet)
	}
	<-ds.done
	if !containsLine(ds.otherLines(), "CLOSE drain") {
		t.Fatalf("lines %q", ds.otherLines())
	}
	if _, err := e.dialNode(); err == nil {
		t.Fatal("the node still listens after it drained")
	}
}

func TestDrain_ALongStreamIsCutAtTheEndOfTheQuietPeriodAndNotBefore(t *testing.T) {
	e := newTestEnv(t, nil)
	d := e.newDevice()
	dc := e.connectOK(d)
	_ = dc.serve(nil)
	stream := streamOpen(t, e, d)

	quiet := 2 * time.Second
	done, started := drainAsync(e, quiet)
	time.Sleep(quiet / 2)
	if stream.dead(50 * time.Millisecond) {
		t.Fatal("the stream was cut before the quiet period was over")
	}
	select {
	case <-done:
	case <-time.After(quiet + 4*time.Second):
		t.Fatal("the node did not exit by the end of the quiet period")
	}
	if took := time.Since(started); took < quiet-100*time.Millisecond || took > quiet+3*time.Second {
		t.Fatalf("it took %s for a quiet period of %s", took, quiet)
	}
	if !stream.dead(2 * time.Second) {
		t.Fatal("the stream outlived the node")
	}
}

func TestDrain_AnAttachForAStreamThatAlreadyHasItsOpenIsStillServed(t *testing.T) {
	e := newTestEnv(t, nil)
	d := e.newDevice()
	dc := e.connectOK(d)
	ds := dc.serve(nil)
	ds.noAttach = true // the device is slow: it has been sent the OPEN and has not attached yet

	type result struct {
		resp []byte
		err  error
	}
	got := make(chan result, 1)
	go func() {
		c, err := e.clientTLS(d)
		if err != nil {
			got <- result{nil, err}
			return
		}
		defer c.Close()
		resp, err := postOver(c, d.host, []byte("late"))
		got <- result{resp, err}
	}()
	eventually(t, "the OPEN", 3*time.Second, func() bool { return ds.openCount() == 1 })

	done, _ := drainAsync(e, 10*time.Second)
	eventually(t, "draining", 2*time.Second, func() bool { return e.srv.Draining() })
	open := ds.openList()[0]
	ds.wg.Add(1)
	go ds.attach(open.str("stream_id"), open.str("secret"))
	select {
	case r := <-got:
		if r.err != nil || string(r.resp) != "echo:late" {
			t.Fatalf("a client whose stream was being set up when the drain began: %q %v", r.resp, r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stream that was being set up was not served")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("no exit after the last stream")
	}
}

func TestDrain_ADeviceThatIsAuthenticatingWhenTheDrainStartsIsToldToo(t *testing.T) {
	// A HELLO past the gate whose authorize is still running when SIGTERM comes: its OK is followed by DRAIN, so it never serves as if nothing happened.
	e := newTestEnv(t, nil)
	holder := e.newDevice()
	hc := e.connectOK(holder)
	_ = hc.serve(nil)
	held := streamOpen(t, e, holder) // a stream that keeps the node draining for a while
	defer held.Close()
	d := e.newDevice()
	e.plan(d).delay = 400 * time.Millisecond
	dc := e.connect(d)
	dc.session = e.session(d, nil)
	dc.send("HELLO 2 " + dc.session)
	m, err := parseLine(dc.recv(), dirN2D)
	if err != nil || m.str("verb") != "CHALLENGE" {
		t.Fatal("no challenge")
	}
	dc.send("PROOF " + e.proof(d, dc.session, m.str("nonce"), nil))
	time.Sleep(100 * time.Millisecond) // inside the slow authorize
	done, _ := drainAsync(e, 5*time.Second)
	eventually(t, "draining", 2*time.Second, func() bool { return e.srv.Draining() })
	if line := dc.recv(); !strings.HasPrefix(line, "OK ") {
		t.Fatalf("%q", line)
	}
	if line := dc.recv(); line != "DRAIN 5" {
		t.Fatalf("after the OK of a device that authenticated during the drain: %q", line)
	}
	_ = dc.c.Close()
	_ = held.Close()
	<-done
}

func TestDrain_ARevokeInTheMiddleOfADrainStillCuts(t *testing.T) {
	f := &scriptedFeed{}
	e := withFeed(t, f)
	d := e.newDevice()
	dc := e.connectOK(d)
	ds := dc.serve(nil)
	stream := streamOpen(t, e, d)
	done, _ := drainAsync(e, 6*time.Second)
	eventually(t, "draining", 2*time.Second, func() bool { return e.srv.Draining() })
	f.push(e.event(feedRevoke, d))
	if !stream.dead(3 * time.Second) {
		t.Fatal("a revoke during a drain did not cut the stream")
	}
	eventually(t, "CLOSE revoked", 2*time.Second, func() bool { return containsLine(ds.otherLines(), "CLOSE revoked") })
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the node did not leave once nothing was open")
	}
}

func TestDrain_ASecondDrainIsNoOp(t *testing.T) {
	e := newTestEnv(t, nil)
	done, _ := drainAsync(e, time.Second)
	<-done
	finished := make(chan struct{})
	go func() { e.srv.Drain(time.Second); close(finished) }()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("a second Drain blocked")
	}
}

// A call of 900 s that started before SIGTERM finishes; the quiet period is the policy's twenty minutes, on a clock the test moves.
func TestDrain_ASigtermDuringA900SecondStreamLetsItFinishAndOneThatNeverEndsIsCutAtTwentyMinutes(t *testing.T) {
	if policyData.Timing.DrainQuietS != 1200 {
		t.Fatalf("the plan says 20 minutes, the policy says %d s", policyData.Timing.DrainQuietS)
	}
	for _, endsAt := range []time.Duration{900 * time.Second, 0} {
		e := newClockEnv(t, nil)
		d := e.newDevice()
		dc := e.connectOK(d)
		ds := dc.serve(nil)
		stream := streamOpen(t, e, d)
		var exited atomic.Bool
		done := make(chan struct{})
		go func() {
			e.srv.Drain(e.srv.cfg.DrainQuiet)
			exited.Store(true)
			close(done)
		}()
		eventually(t, "DRAIN delivered", 3*time.Second, func() bool { return containsLine(ds.otherLines(), "DRAIN 1200") })

		e.clk.Advance(899 * time.Second)
		time.Sleep(400 * time.Millisecond)
		if exited.Load() || stream.dead(50*time.Millisecond) {
			t.Fatalf("ends at %s: the stream or the node was cut at 899 s", endsAt)
		}
		if endsAt > 0 {
			// the call finishes at 900 s: the node leaves at once, 300 s early
			e.clk.Advance(time.Second)
			_ = stream.Close()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("the node did not leave after the 900 s stream finished")
			}
			continue
		}
		e.clk.Advance(300 * time.Second) // 1199 s
		time.Sleep(400 * time.Millisecond)
		if exited.Load() {
			t.Fatal("the node left before the quiet period was over")
		}
		e.clk.Advance(2 * time.Second) // 1201 s
		select {
		case <-done:
		case <-time.After(6 * time.Second):
			t.Fatal("a stream that never ends kept the node past the quiet period")
		}
		if !stream.dead(2 * time.Second) {
			t.Fatal("the stream outlived the node")
		}
	}
}

// ---------------------------------------------------------------------------------------------------------------------------- the real process

func TestTestNodeBinary_SigtermDrainsAndTheProcessExitsInsideTheQuietPeriod(t *testing.T) {
	for _, longStream := range []bool{false, true} {
		p := launchTestNode(t, 600, "-drain-quiet", "3s")
		e, d, cmd := p.e, p.d, p.cmd
		dc := e.connectOK(d)
		ds := dc.serve(nil)
		stream := streamOpen(t, e, d)
		if !longStream {
			_ = stream.Close()
		}
		start := time.Now()
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		eventually(t, "DRAIN 3 delivered", 3*time.Second, func() bool { return containsLine(ds.otherLines(), "DRAIN 3") })
		if longStream {
			// no new client; the open one goes on
			if _, err := e.clientTLS(d); err == nil {
				t.Fatal("a client was accepted by a draining process")
			}
			if resp, err := postOver(stream.Conn, d.host, []byte("still")); err != nil || string(resp) != "echo:still" {
				t.Fatalf("the open stream during the drain: %q %v", resp, err)
			}
		}
		select {
		case err := <-p.exited:
			if err != nil {
				t.Fatalf("exit: %v\n%s", err, p.logs.String())
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("the process did not exit (long stream: %v)\n%s", longStream, p.logs.String())
		}
		took := time.Since(start)
		switch {
		case !longStream && took > 2*time.Second:
			t.Errorf("an idle node took %s to drain", took)
		case longStream && (took < 2500*time.Millisecond || took > 3*time.Second+3*time.Second):
			t.Errorf("a node with a stream that never ends left after %s; the quiet period is 3 s", took)
		}
		<-ds.done
		if !containsLine(ds.otherLines(), "CLOSE drain") {
			t.Errorf("lines %q", ds.otherLines())
		}
	}
}

func TestTestNodeBinary_ASecondSigtermDuringADrainStopsWaiting(t *testing.T) {
	p := launchTestNode(t, 600, "-drain-quiet", "5m")
	dc := p.e.connectOK(p.d)
	_ = dc.serve(nil)
	stream := streamOpen(t, p.e, p.d)
	defer stream.Close()
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	select {
	case <-p.exited:
		t.Fatal("the process left with a stream open and five minutes of quiet period left")
	default:
	}
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-p.exited:
		if err != nil {
			t.Fatalf("exit: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("a second SIGTERM did not stop the drain\n%s", p.logs.String())
	}
}

func TestTestNodeBinary_AFeedFileRevokesAStreamAndTheKillSwitchClosesEverything(t *testing.T) {
	dir := t.TempDir()
	feed := filepath.Join(dir, "feed.json")
	writeFeed := func(epoch int, events ...map[string]any) {
		t.Helper()
		list := []any{}
		for _, ev := range events {
			list = append(list, ev)
		}
		b, _ := json.Marshal(map[string]any{"epoch": epoch, "events": list})
		if err := os.WriteFile(feed+".tmp", b, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(feed+".tmp", feed); err != nil {
			t.Fatal(err)
		}
	}
	writeFeed(0)
	p := launchTestNode(t, 600, "-test-feed", feed, "-feed-poll", "100ms")
	e, d := p.e, p.d
	dc := e.connectOK(d)
	ds := dc.serve(nil)
	stream := streamOpen(t, e, d)

	at := time.Now().Unix()
	writeFeed(1, map[string]any{"epoch": 1, "type": "revoke", "device_id": d.id, "label": d.label, "at": at})
	eventually(t, "CLOSE revoked", 5*time.Second, func() bool { return containsLine(ds.otherLines(), "CLOSE revoked") })
	if !stream.dead(3 * time.Second) {
		t.Fatal("the revoked device's stream is still open")
	}
	// the kill switch: nobody is served
	writeFeed(2, map[string]any{"epoch": 1, "type": "revoke", "device_id": d.id, "label": d.label, "at": at},
		map[string]any{"epoch": 2, "type": "kill", "device_id": nil, "label": nil, "at": at})
	time.Sleep(600 * time.Millisecond)
	c := e.connect(d)
	if line := c.hello(func() string { return e.session(d, nil) }, func(s, n string) string { return e.proof(d, s, n, nil) }); line != "ERR control_unavailable" {
		t.Fatalf("a HELLO while the kill switch is on: %q", line)
	}
	writeFeed(3, map[string]any{"epoch": 3, "type": "kill_clear", "device_id": nil, "label": nil, "at": at})
	eventually(t, "served again", 5*time.Second, func() bool {
		cc := e.connect(d)
		return strings.HasPrefix(cc.hello(func() string { return e.session(d, nil) }, func(s, n string) string { return e.proof(d, s, n, nil) }), "OK ")
	})
	if strings.Contains(p.logs.String(), d.id) || strings.Contains(p.logs.String(), d.label) {
		t.Fatal("the process logs name a device")
	}
}

// drainFeed discards what the node already sent and the test did not read.
func (dc *devConn) drainFeed() {
	for {
		select {
		case <-dc.feed:
		default:
			return
		}
	}
}

package main

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// An idle stream spends its life blocked in a read. The pump waits with a 4 KiB buffer and takes a 32 KiB one only for a read that filled the small one, giving it back when a
// read comes back short: an idle stream holds about 8 KiB of buffer, not 64 KiB (the chaos suite's memory-per-stream check).
func TestPump_AnIdleStreamHoldsNoBigBufferAndABulkTransferGetsOneAndGivesItBack(t *testing.T) {
	e := newTestEnv(t, nil)
	srcA, srcB := tcpPair(t)
	dstA, dstB := tcpPair(t)
	var ctr, total atomic.Int64
	done := make(chan error, 1)
	go func() { done <- e.srv.pump("s1", "up", dstA, srcB, &ctr, &total, nil, nil) }()
	drain := make(chan int, 1)
	go func() {
		n := 0
		buf := make([]byte, 1<<16)
		for {
			k, err := dstB.Read(buf)
			n += k
			if err != nil {
				drain <- n
				return
			}
		}
	}()
	time.Sleep(100 * time.Millisecond)
	if got := e.srv.bigBuffersInUse.Load(); got != 0 {
		t.Fatalf("an idle pump holds %d big buffers", got)
	}
	// a trickle never takes one
	for i := 0; i < 5; i++ {
		_, _ = srcA.Write([]byte("tiny"))
		time.Sleep(20 * time.Millisecond)
	}
	if got := e.srv.bigBuffersInUse.Load(); got != 0 {
		t.Fatalf("a trickle took %d big buffers", got)
	}
	// a bulk write fills the small buffer: the pump takes the big one for the following reads, and gives it back when a read comes back short
	bulk := make([]byte, 1<<20)
	var peak atomic.Int64
	stopPoll := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopPoll:
				return
			default:
				if v := e.srv.bigBuffersInUse.Load(); v > peak.Load() {
					peak.Store(v)
				}
				time.Sleep(100 * time.Microsecond)
			}
		}
	}()
	go func() { _, _ = srcA.Write(bulk) }()
	eventually(t, "the bulk transfer went through", 5*time.Second, func() bool { return ctr.Load() >= int64(len(bulk)+20) })
	close(stopPoll)
	if peak.Load() < 1 {
		t.Fatalf("a bulk transfer never took a big buffer: its throughput would be that of 4 KiB reads")
	}
	_, _ = srcA.Write([]byte("short"))
	eventually(t, "the big buffer went back to the pool after a short read", 3*time.Second, func() bool { return e.srv.bigBuffersInUse.Load() == 0 })
	_ = srcA.Close()
	if err := <-done; err != nil {
		t.Fatalf("a clean end of the source is not an error: %v", err)
	}
	_ = dstA.Close()
	if n := <-drain; n != len(bulk)+20+5 {
		t.Fatalf("the far side received %d bytes, want %d: the byte accounting changed", n, len(bulk)+25)
	}
	if got := e.srv.bigBuffersInUse.Load(); got != 0 {
		t.Fatalf("%d big buffers leaked", got)
	}
}

func tcpPair(t *testing.T) (a, b net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	acc := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); acc <- c }()
	a, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b = <-acc
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

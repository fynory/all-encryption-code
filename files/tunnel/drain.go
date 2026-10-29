package main

import (
	"time"
)

// Draining (the design plan, section 5): what a node does on SIGTERM, so that a deploy or a restart costs the people on it as little as
// possible. In this order:
//
//  1. It stops taking anything new. A client that connects now gets a TLS alert and no OPEN (the DNS no longer points at a node being taken down, but
//     a client that resolved it a minute ago still arrives); a device that sends a HELLO gets ERR control_unavailable and goes to the other node.
//     The listeners stay open on purpose: a device's ATTACH for a stream that already has its OPEN must still be served, and closing the port would
//     turn a drain into a reset for every client that is a handshake away from its stream.
//  2. It tells every device it serves DRAIN <quiet_s>: prefer the other node for new connections; the open streams continue here for the quiet period.
//  3. It waits until the streams are gone or the quiet period (policy timing.drain_quiet_s, 20 minutes) is over, whichever comes first, then
//     closes what is left and exits. A call of 900 s that started before SIGTERM finishes; one that would run past the quiet period is cut, and the
//     runbook says so (it may already have run on the computer).
//
// The control connections stay up for the whole drain (a RENEW is answered), and the feed keeps being applied: a revoke during a drain still cuts.

// drainPoll is how often a drain looks at whether the streams are gone.
const drainPoll = 250 * time.Millisecond

// Draining reports whether the node is draining.
func (s *Server) Draining() bool { return s.draining.Load() }

// Drain runs a drain to its end (the streams gone, or quiet over) and shuts the node down. It returns when the node is down. A second call is a no-op.
func (s *Server) Drain(quiet time.Duration) {
	s.drainFor.CompareAndSwap(0, int64(quiet))
	if !s.draining.CompareAndSwap(false, true) {
		return
	}
	s.log.Info("draining", "quiet_s", int64(quiet/time.Second), "streams", s.streams.Load())
	line := drainLine(quiet)
	for _, cc := range s.routes.controls("") {
		if cc.isReady() {
			_ = cc.write(line) // a device that cannot be told is no worse off: it learns when the connection closes
		}
	}

	over := make(chan struct{})
	stop := s.clk.AfterFunc(quiet, func() { close(over) })
	defer stop()
	for s.streams.Load() > 0 || s.pendingCount() > 0 {
		select {
		case <-over:
			s.log.Warn("drain_quiet_over", "streams", s.streams.Load())
			s.shutdown(0, closeDrain)
			return
		case <-s.ctx.Done():
			return
		default:
		}
		time.Sleep(drainPoll)
	}
	s.log.Info("drained")
	s.shutdown(s.cfg.ShutdownGrace, closeDrain)
}

func (s *Server) pendingCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending)
}

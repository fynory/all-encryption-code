package main

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

// The feed consumer (the design plan, sections 2, 3 and 5; the contract, section 4): what the node must stop serving, learned from
// GET /v1/tunnel/feed within policy timing.feed_apply_deadline_s. A node never decides to cut a device by itself; it cuts what the control plane says
// to cut, and it keeps serving what is already authenticated until valid_until when the control plane cannot be asked.
//
//	revoke, release, license_end   the device's control connection is closed and the streams of its host are killed
//	pause                          no new stream; the streams in flight are killed; the connection stays (a resume arrives as a statement) and the
//	                               node asks the control plane for the device's signed statement, which carries the pause, and forwards it
//	resume                         the node asks again: the control plane's answer decides the status, and its statement (resumed) is forwarded
//	kill, kill_clear               the global switch: every connection is closed (CLOSE killed) and every stream killed, and nobody is served
//	                               (control_unavailable) until it is cleared
//	reset                          the cursor is not one the control plane can serve from: every tunnel is closed, the devices reconnect and are
//	                               authorized again
//
// Events are applied in epoch order, each once: an event at or below the cursor is dropped, so a duplicate or a replay changes nothing, and a batch
// that arrives out of order is sorted first. An event older than a connection's last answer from the control plane (by the control plane's own clock)
// is already part of that answer and is skipped: after a restart the feed is replayed from the start, and a device that came back since its revoke
// must not be cut again by the old event.

// feedWaitSlack is how much longer than its hold the node lets one poll take.
const feedWaitSlack = 10 * time.Second

// startBackground starts the feed loop and the node's background tasks. The feed's first answer is awaited (bounded) so that the node does not accept
// a device before it knows what it must not serve.
func (s *Server) startBackground() {
	for _, task := range append([]func(context.Context){s.openai.Run, s.sweepLoop}, s.cfg.Background...) {
		s.bg.Add(1)
		go func(task func(context.Context)) {
			defer s.bg.Done()
			task(s.ctx)
		}(task)
	}
	if s.cfg.Feed == nil {
		return
	}
	caughtUp := make(chan struct{})
	s.bg.Add(1)
	go func() {
		defer s.bg.Done()
		s.runFeed(s.ctx, caughtUp)
	}()
	select {
	case <-caughtUp:
	case <-time.After(s.cfg.FeedStartWait):
		s.log.Warn("feed_late", "waited_ms", s.cfg.FeedStartWait.Milliseconds())
	}
}

// runFeed polls until ctx ends. close(caughtUp) runs once, after the first answer applied or the first failure.
func (s *Server) runFeed(ctx context.Context, caughtUp chan struct{}) {
	var cursor int64
	failures := 0
	first := true
	signal := func() {
		if first {
			first = false
			close(caughtUp)
		}
	}
	defer signal()
	for ctx.Err() == nil {
		started := s.now()
		wait := s.cfg.FeedPoll
		if first {
			wait = 0 // the first look answers at once: it is the one the listeners wait for
		}
		pctx, cancel := context.WithTimeout(ctx, s.cfg.FeedPoll+feedWaitSlack)
		answer, err := s.cfg.Feed.Feed(pctx, cursor, wait)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.health.record(s.now(), err)
			failures++
			s.log.Warn("feed_failed", "reason", errorWord(err), "failures", failures)
			signal()
			// Retry quickly (never beyond the poll period: the moment the control plane is back, a revoke is heard within the apply deadline).
			if !s.clk.sleep(ctx, jitter(min(backoff(failures), s.cfg.FeedPoll), 20)) {
				return
			}
			continue
		}
		failures = 0
		s.health.good(s.now())
		next, applied := s.applyFeed(answer, cursor)
		cursor = next
		signal()
		if !applied && wait > 0 {
			// Nothing new in a poll that asked to be held. A control plane that holds it has already spent the period; one that answers at once is
			// polled once per period. (The first look asks for no hold: the long polls start right after it.)
			if rest := wait - s.now().Sub(started); rest > 0 && !s.clk.sleep(ctx, rest) {
				return
			}
		}
	}
}

// applyFeed applies one answer and returns the cursor for the next poll, and whether the answer carried anything the node acted on.
func (s *Server) applyFeed(answer FeedAnswer, cursor int64) (int64, bool) {
	if answer.Skipped > 0 {
		s.log.Warn("feed_events_skipped", "count", answer.Skipped)
	}
	if answer.Reset {
		s.log.Warn("feed_reset", "cursor", cursor, "epoch", answer.Epoch)
		s.closeAll(closeExpired)
		return answer.Epoch, true
	}
	if answer.Epoch < cursor {
		// The control plane's feed never goes back without saying reset; an answer that does is not one this node can act on.
		s.log.Warn("feed_behind_cursor", "cursor", cursor, "epoch", answer.Epoch)
		return cursor, false
	}
	events := append([]FeedEvent(nil), answer.Events...)
	sort.SliceStable(events, func(i, j int) bool { return events[i].Epoch < events[j].Epoch })
	next := cursor
	applied := false
	for _, event := range events {
		if event.Epoch <= next {
			continue // a duplicate, or an event this node has already applied
		}
		s.applyEvent(event)
		next, applied = event.Epoch, true
	}
	return max(next, answer.Epoch), applied
}

func (s *Server) applyEvent(event FeedEvent) {
	s.log.Info("feed_event", "type", event.Type, "epoch", event.Epoch)
	s.met.feedEvents.inc(event.Type)
	// Noted before the table is looked at: a HELLO that joins the table after that look has the note to read, and one that joined before it is found.
	s.noteEvent(event)
	switch event.Type {
	case feedKill:
		s.setKilled(true)
		return
	case feedKillClear:
		if s.killed.Swap(false) {
			s.log.Warn("kill_switch_cleared")
		}
		return
	}
	reason := map[string]string{feedRevoke: closeRevoked, feedRelease: closeReleased, feedLicenseEnd: closeRevoked}[event.Type]
	hosts := s.routes.hostsOfLabel(event.Label)
	for _, cc := range s.routes.controls(event.Label) {
		if cc.answeredAfter(event.At) {
			continue // the answer the control plane gave this connection already knew
		}
		switch event.Type {
		case feedPause:
			cc.pause()
			s.routes.killStreams(cc.hostName(), closePaused, true)
			s.refreshAsync(cc)
		case feedResume:
			s.refreshAsync(cc)
		default:
			cc.close(reason)
			s.routes.killStreams(cc.hostName(), reason, true)
		}
	}
	if reason != "" {
		// Streams of a host whose control connection is already gone (the device dropped, the streams did not yet).
		for _, host := range hosts {
			s.routes.killStreams(host, reason, false)
		}
	}
}

// ---------------------------------------------------------------------------------------------------------------------------- events during authorize

// feedWatch collects the feed events that are applied while one exchange waits for the control plane. The answer it gets was decided before them, so
// it cannot be served as it is: a revoke applied meanwhile found no connection to close (a HELLO is not in the routing table until its OK), and a
// pause applied meanwhile to a connection that is renewing is written over by the answer's status. The notes live exactly as long as the call: nothing
// is kept for an exchange that is not waiting.
type feedWatch struct {
	s     *Server
	mu    sync.Mutex
	notes []FeedEvent
}

func (s *Server) watchFeed() *feedWatch {
	w := &feedWatch{s: s}
	s.watchMu.Lock()
	s.watches[w] = struct{}{}
	s.watchMu.Unlock()
	return w
}

func (w *feedWatch) stop() {
	w.s.watchMu.Lock()
	delete(w.s.watches, w)
	w.s.watchMu.Unlock()
}

// noteEvent hands an applied event to every exchange that is waiting for authorize. The kill switch and a reset are not among them: they close every
// connection, the exchanges in flight included.
func (s *Server) noteEvent(event FeedEvent) {
	switch event.Type {
	case feedRevoke, feedRelease, feedLicenseEnd, feedPause, feedResume:
	default:
		return
	}
	s.watchMu.Lock()
	defer s.watchMu.Unlock()
	for w := range s.watches {
		w.mu.Lock()
		w.notes = append(w.notes, event)
		w.mu.Unlock()
	}
}

// feedVerdict is what the events applied during a call mean for its answer.
type feedVerdict struct {
	cut     string // the answer must not be served: the CLOSE reason of the event that overtook it
	err     string // what a device that has not been told OK yet is answered
	paused  bool   // the last pause or resume event of the host was a pause
	refresh bool   // a pause or a resume came: the control plane is asked again, its answer decides
}

// verdict reads the notes that concern host, leaving out those older than the answer (by the control plane's own clock, as answeredAfter does: the
// answer already knew them).
func (w *feedWatch) verdict(host string, serverTime int64) feedVerdict {
	w.mu.Lock()
	defer w.mu.Unlock()
	var v feedVerdict
	for _, n := range w.notes {
		if !hostHasLabel(host, n.Label) || serverTime > n.At {
			continue
		}
		switch n.Type {
		case feedRevoke, feedRelease:
			if v.cut == "" {
				v.cut, v.err = map[string]string{feedRevoke: closeRevoked, feedRelease: closeReleased}[n.Type], codeDeviceRevoked
			}
		case feedLicenseEnd:
			if v.cut == "" {
				v.cut, v.err = closeRevoked, codeLicenseInactive
			}
		case feedPause:
			v.paused, v.refresh = true, true
		case feedResume:
			v.paused, v.refresh = false, true
		}
	}
	return v
}

// answeredAfter reports whether the control plane's last answer for this connection is newer than an event stamped at (epoch seconds).
func (c *ctrl) answeredAfter(at int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.authAt > at
}

// setKilled turns the kill switch on: every control connection is closed (CLOSE killed) and every stream killed. While it is on no device is served.
func (s *Server) setKilled(on bool) {
	if !on {
		s.killed.Store(false)
		return
	}
	if s.killed.Swap(true) {
		return
	}
	s.log.Warn("kill_switch_on")
	s.closeAll(closeKilled)
}

// closeAll closes every control connection with reason and kills every client stream: the kill switch and a feed reset.
func (s *Server) closeAll(reason string) {
	s.mu.Lock()
	live := make([]*ctrl, 0, len(s.conns))
	for cc := range s.conns {
		live = append(live, cc)
	}
	s.mu.Unlock()
	for _, cc := range live {
		cc.close(reason)
	}
	s.routes.killAllStreams(reason)
}

// ---------------------------------------------------------------------------------------------------------------------------- refresh of a connection

// refreshAsync asks the control plane again about one connection (after a pause or a resume event), in the background: the answer decides its status,
// and its signed statement (which carries the pause or the resume) is forwarded to the device. Events that arrive while a refresh runs are folded into
// one more. Until the control plane answers, a paused connection stays paused: the node never lifts a pause by itself.
func (s *Server) refreshAsync(cc *ctrl) {
	cc.mu.Lock()
	if cc.refreshing {
		cc.refreshAgain = true
		cc.mu.Unlock()
		return
	}
	cc.refreshing = true
	cc.mu.Unlock()
	if !s.goBackground(func() { s.refreshLoop(cc) }) {
		cc.mu.Lock()
		cc.refreshing = false
		cc.mu.Unlock()
	}
}

// goBackground runs task as one of the node's background tasks, unless the node has ended: the wait for them (shutdown) must not start while one is
// being added.
func (s *Server) goBackground(task func()) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx.Err() != nil {
		return false
	}
	s.bg.Add(1)
	go func() {
		defer s.bg.Done()
		task()
	}()
	return true
}

func (s *Server) refreshLoop(cc *ctrl) {
	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()
	go func() {
		select {
		case <-cc.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	failures := 0
	for ctx.Err() == nil {
		cc.mu.Lock()
		cc.refreshAgain = false
		cc.mu.Unlock()
		if err := s.refreshOnce(cc); err != nil {
			failures++
			if !s.clk.sleep(ctx, jitter(backoff(failures), 20)) {
				break
			}
			continue
		}
		failures = 0
		cc.mu.Lock()
		again := cc.refreshAgain
		if !again {
			cc.refreshing = false
		}
		cc.mu.Unlock()
		if !again {
			return
		}
	}
	cc.mu.Lock()
	cc.refreshing = false
	cc.mu.Unlock()
}

var errRefreshLater = errors.New("the control plane did not answer")

// refreshOnce is one authorize call for an established connection. It returns errRefreshLater when the control plane could not be asked (try again),
// and nil when the connection's state is settled (updated, or closed).
func (s *Server) refreshOnce(cc *ctrl) error {
	cc.mu.Lock()
	req := AuthorizeRequest{DeviceID: cc.sub, SessionJTI: cc.jti, Reason: "renew", Node: s.cfg.NodeID}
	host := cc.host
	cc.mu.Unlock()
	if s.killed.Load() {
		return nil
	}
	resp, err := s.authorize(req)
	if err == nil {
		if cerr := checkAuthorize(resp, req); cerr != nil {
			s.health.bad(s.now())
			err = &ControlError{Status: 502, Code: "bad_response"}
		}
	}
	if err != nil {
		if isRefusal(err) {
			// The control plane says this device is no longer served (revoked, license over, not enrolled): it is cut.
			s.log.Info("refresh_refused", "conn", cc.id, "reason", errForControl(err))
			cc.close(closeRevoked)
			s.routes.killStreams(host, closeRevoked, true)
			return nil
		}
		return errRefreshLater
	}
	if resp.E2EKill {
		s.setKilled(true)
		return nil
	}
	if resp.Host != host {
		s.log.Warn("refresh_host_changed", "conn", cc.id)
		cc.close(closeRevoked)
		s.routes.killStreams(host, closeRevoked, true)
		return nil
	}
	cc.setStatus(resp)
	s.routes.setGated(cc, resp.Status == statusGated)
	if resp.Status == statusPaused {
		s.routes.killStreams(host, closePaused, true)
	}
	if line := statementLine(resp.Access); resp.Access != "" && line != "" {
		if err := cc.write(line); err != nil {
			cc.close("write_error")
			return nil
		}
	}
	s.log.Info("control_refreshed", "conn", cc.id, "status", resp.Status)
	return nil
}

// sweepLoop forgets, once a minute, what the tables of sources, hints and gated days hold that nobody needs any more, so an idle node's memory shrinks.
func (s *Server) sweepLoop(ctx context.Context) {
	for s.clk.sleep(ctx, time.Minute) {
		s.ips.Sweep()
		s.hints.Sweep()
		s.gates.Sweep()
	}
}

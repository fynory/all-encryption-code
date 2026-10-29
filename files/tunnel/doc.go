// Command all-tunnel is the SNI-routing tunnel node of ALL 2.0 end-to-end encryption (the design plan, sections 2, 3 and 5, and
// the contract document, which this program implements).
//
// What it does: ChatGPT (any HTTPS client) connects to :443 and speaks normal TLS. The node reads only the cleartext ClientHello to learn the SNI name,
// finds the device that owns that name, and copies raw bytes between the client and the device. The TLS server is the DEVICE (it holds the private
// key and the publicly trusted certificate for its own name); this program never decrypts, never terminates and never rewrites a client's TLS, and it
// never logs payload bytes, addresses or names (only times, sizes, reasons and stream ids).
//
// # Ports
//
// There are exactly two, and no other:
//
//	:443   the one public listener. The first thing read is the ClientHello's SNI:
//	         - the node's OWN name (-node-host): the control handler. The device speaks TLS 1.3 to it, with the node's public-CA certificate
//	           and ALPN all-tunnel/2, and protocol v2 inside (control and data connections, below);
//	         - any other name: a client of a device. If a device is online for that name and may serve, the node sends it OPEN and splices the
//	           client's bytes to the data connection that comes back; otherwise the client gets a TLS alert and nothing else happens.
//	:80    the node's own ACME webroot and nothing else: GET/HEAD /.well-known/acme-challenge/<token> for the node's own name, from
//	       -acme-webroot. It never reaches a device (a certificate for a device is issued over DNS-01, and CAA allows nothing else).
//
// The 1.1 experiment's separate device port and the self-signed certificate that devices pinned are gone.
//
// # Device protocol (version 2)
//
// Every connection to the node's own name first completes TLS, then the device sends ONE text line (ASCII 0x20-0x7e, fields separated by one space,
// ended by LF, at most 8192 bytes, within first_line_timeout_s). The grammar is contracts/schemas/wire-v2.grammar.json; proto.go implements it and
// protocol_test.go runs every golden vector through it. The first line tells the two kinds of connection apart.
//
// Control connection (one per device, kept open):
//
//	device -> node  HELLO 2 <session>        the device's session JWT (aud all-tunnel, 300 s); no host name
//	node   -> device CHALLENGE <nonce>       once the session verified OFFLINE against the control plane's keys
//	device -> node  PROOF <dpop>             a DPoP proof over the NODE's URL (htu), the nonce and the session, signed by the session's bound key
//	node   -> device OK <json>               after the node asked the control plane (authorize): host, status, valid_until, windows, relayed as given
//	               or ERR <code>             a refused HELLO closes the connection
//
// The host a device is served under comes ONLY from the control plane's answer; nothing the device says can name one. The connection lives until the
// answer's valid_until: before that moment minus renew_before_valid_until_s the device sends
//
//	device -> node  RENEW <new session>      the same subject; CHALLENGE and PROOF follow, then the node calls authorize AGAIN and answers
//	node   -> device OK <json>               with the NEW valid_until and status (a trial that ended is gated from here, with no event needed)
//
// and a RENEW that is refused keeps the connection with its old valid_until. Without a RENEW the node sends CLOSE expired at valid_until and closes. A
// second authenticated HELLO of the same subject replaces the first (CLOSE replaced; its open streams keep running); a HELLO whose answer names a host
// that another subject holds is refused, and a RENEW whose answer names another host closes the connection (CLOSE revoked): the old host stops being
// served at once. Status paused keeps the connection but opens no stream; gated opens them (held to the day's byte and stream budget, see
// Hardening). PING is answered with PONG; a connection silent for dead_peer_s is dropped (CLOSE idle). HINT carries source addresses the device
// marked good (the node's hint table, and Config.OnHint).
//
// OPEN:
//
//	node   -> device OPEN <stream-id> <attach-secret> <peer-ip> <class>
//
// is sent ONLY after the client's ClientHello is complete and well formed (a truncated, stalled, oversized or malformed one, or one without a usable
// SNI, never produces an OPEN), never for a paused device, never at or after valid_until. stream-id is 128 random bits, attach-secret is 256 random
// bits and valid for ONE ATTACH, peer-ip is the client's address (no zone) and class is openai (the address is in OpenAI's published list), hint (the device marked it with
// HINT) or anon (Config.Classify overrides this).
//
// Data connection (one per OPEN, dialed by the device to the same name and port):
//
//	device -> node  ATTACH <stream-id> <attach-secret>
//	node   -> device ERR auth | ERR unknown_stream | ERR bad_attach   (then close), or NOTHING:
//
// on success there is NO reply line. The very next byte the node sends is the first byte of the raw stream of ONE client connection (the ClientHello,
// replayed exactly as received), and every byte the device sends from then on goes to that client. A wrong secret is refused and does not consume the
// stream; a used or unknown id is unknown_stream. EOF in one direction is propagated as a half-close and the other direction then has half_close_s to
// finish; each stream is bounded by the idle timeout, the maximum age and a byte cap, and streams per host and in total are capped.
//
// # Trust and what the node knows
//
// The node trusts the control plane's keys (a KeySource) to verify sessions and the control plane's answer (a ControlPlane) to decide what a device
// may do. The production build wires the real ones (backend_prod.go); the test-node build wires fakes. Every number, window and pattern is read from
// policy.json (a byte-identical copy of contracts/policy.json that the contract generator's sync writes).
//
// # The control plane (controlplane.go, jwks.go, feed.go)
//
// The node holds ONE secret: its own Ed25519 signing key (-node-key-file, mode 0600; -node-key-init makes it and prints the TUNNEL_NODE_KEYS entry that
// registers it, removing the kid from that variable revokes the node). Every request to /v1/tunnel/* carries an assertion in x-all-node-assertion, a
// 60 s JWS bound to the method, the exact URL and the SHA-256 of the exact body, used once. Nothing else authenticates the node: no shared secret, no
// commerce key. The client reads only the configured control plane (never a redirect, never a URL an answer names), caps every answer, and turns
// whatever it cannot read into bad_response: no text from the network reaches a device or a log.
//
//	authorize   asked at every HELLO and at every RENEW (the end of a trial turns a connection into gated with no event); at most
//	            authorization.authorize_max_concurrent calls run at once and what waits is bounded, the rest is told control_unavailable
//	JWKS        the published keys: fetched at start and every cache_s, reloaded when a session names an unknown kid (one fetch per minimum gap,
//	            however many sessions ask), replaced whole on every fetch, at most max_keys; after stale_fail_closed_s without a refresh the node
//	            vouches for nothing: new HELLOs and RENEWs are answered control_unavailable (not auth), connections already up are untouched
//	feed        GET /v1/tunnel/feed with a held poll (wait), applied within timing.feed_apply_deadline_s: revoke, release and license_end close the
//	            connection (CLOSE revoked/released) and kill the streams of the host; pause kills the streams, stops new ones and forwards the
//	            device's signed statement; resume asks the control plane again (its answer decides); kill/kill_clear are the global switch; reset
//	            closes everything so that devices come back and are authorized again. Events are applied once, in epoch order; a duplicate, a
//	            replay or an event older than a connection's last answer changes nothing
//	STATEMENT   the access statement of an authorize answer, forwarded unchanged right after the OK (under the write lock: no OPEN comes before it)
//
// # When the control plane does not answer
//
// What is authenticated goes on until valid_until: nothing is asked of the control plane to keep a connection or to open a stream. A new HELLO needs
// a good authorize. A PAID connection whose valid_until arrives while the control plane is not answering (its own RENEW got a 5xx, a 429 or a
// timeout, or nothing has answered for two poll periods) is kept for authorization.grace_paid_s more, opens no new stream in that time, and is closed
// when it is over; a trial or a gated connection is closed at valid_until, and so is a paid one whose RENEW the control plane answered (it said no).
// A connection that ends because its grant ended (expired, revoked, released, killed) takes the streams of its host with it.
//
// # Draining (drain.go)
//
// SIGTERM stops new ClientHellos (a TLS alert, no OPEN) and new HELLOs (ERR control_unavailable), tells every device DRAIN <quiet_s> (prefer the other
// node), keeps serving the streams that are open, the ATTACH of streams that already have their OPEN and the RENEW of the devices that hold them, and
// exits when the streams are gone or timing.drain_quiet_s (20 minutes, -drain-quiet) is over, whichever comes first, with CLOSE drain to the devices.
// A second SIGTERM stops waiting; SIGINT stops at once; SIGHUP reads the node's certificate again (certreload.go also looks at the files on its own).
//
// # Hardening (limits.go, hints.go, gated.go, openai_prefixes.go, observer.go, metrics.go; deploy/)
//
// Every number is policy.node_limits or policy.gated; nothing in this program types one. A SOURCE is an IPv4 address, or the /64 of an IPv6 one.
//
//	at accept     a source that is banned, that opens connections faster than per_ip_new_per_s, or that holds per_ip_concurrent already (pre-hello, and
//	              the client streams it has open: a device's control connection stops counting when it authenticates, a data connection when it
//	              attaches) is dropped with no answer; an address of the OpenAI list has openai_per_ip_factor times the limits and is never banned;
//	              an address that holds an authenticated control connection has device_per_ip_factor times the limits (a device opens one data
//	              connection per stream it serves), and a connection that has authenticated or attached gives back the token it took from the rate
//	              bucket; :80 is under the same limits
//	ClientHello   5 s (client_hello_deadline_s), no OPEN before it is complete and well formed
//	unknown names a source that tries more than unknown_sni_per_ip DISTINCT names that are not a device online (or sends no TLS) within
//	              unknown_sni_window_s is banned for unknown_sni_ban_s, in memory; the same name again costs nothing (ChatGPT retrying an offline device
//	              is not a scan); an address a device marked with HINT is never struck, and the shared overflow entry (what sources get when the
//	              table is full) is never struck or banned, so a scanner cannot turn a full table into a ban of every new source
//	per device    label_streams_max streams: label_anon_slice for any source, and the rest only for sources the device marked with HINT (a marked source
//	              may also use free anonymous room); new streams from sources that are not marked are paced at label_new_per_s (burst label_new_burst)
//	global        global_streams_max, of which openai_reserved_pct percent only openai or hint sources may use (a quota, not an allowlist: the class
//	              comes from OpenAI's published list, read at start and every openai_prefix_refresh_s, kept in a file, and a list that is empty, corrupt,
//	              too big or has a prefix wider than the policy's minimum replaces nothing)
//	HINT          addresses a device says just completed authenticated calls: memory only, hint_ttl_s from the last HINT, at most
//	              hint_addresses_per_label per device, filed under the host the control plane gave THAT connection
//	gated         gated.bytes_per_day and gated.streams_per_day per device host and UTC day, in memory; counted on every status the control plane gives
//	              (authorize at HELLO and RENEW, and the refresh after a pause or resume), so a device that turns gated mid-connection is cut on its
//	              open streams when the bytes run out, and reconnecting does not buy a new budget. The budget is spent by every stream of the host,
//	              whoever opens it: a device's name is public (certificate transparency), so a third party can use up a gated device's day (200
//	              streams or 10 MB) and keep its paywall card from reaching the user until midnight UTC. Accepted: a gated device is not a service
//	              anyone depends on, and the price of the alternative (telling clients apart) is a rule that fails open
//	sockets       TCP keepalive from tcp_keepalive_s on everything the node accepts; idle and maximum age of a stream are timing.stream_idle_s and
//	              timing.stream_max_age_s
//	logs          no address, no name, no label, no device id in a log line, ever: a line that must tell two sources apart carries Server.short, the
//	              per-boot salted short hash; lines a flood can repeat are written at most once a second per reason, with how many were left out
//	observer      the cleartext start of a handshake, counted by a closed list of words: the groups a ClientHello offers (X25519MLKEM768 included) and
//	              whether it carries an ECH extension, the version, cipher and group the device's ServerHello selects, HelloRetryRequests. Nothing
//	              else, nothing that names a client
//	/metrics      -metrics-addr (loopback only, 127.0.0.1:9101 in the production build) serves /metrics and /healthz: aggregate counters, no series
//	              per device, label, address or name, the node certificate's not_after and the age of the control plane's keys included; a metrics
//	              port that cannot be bound is a log line (metrics_unavailable), not a node that does not start
//	kernel        deploy/nftables.conf and deploy/sysctl.conf: per-source connection and rate limits above the node's own, SYN cookies. The kernel
//	              counts every connection a source HOLDS, a device's data connections (one per open stream) included, while the node frees its own
//	              slot at attach: the held limit is sized for that
//
// # Test node
//
// `go build -tags testnode` (build.sh test-node) builds the same node with file-driven fakes for the keys and the control plane. It is what
// ALL_TEST_NODE_BIN names for the device's tests; see testnode.go. It is never deployed.
// With -test-tap FILE it also records every byte it forwards and every control line for the blindness gate (tap_test_hook.go); the build with
// `-tags "testnode blindmutant"` (build.sh blind-mutant) is the node that gate must catch (blindmutant_test_hook.go). Neither is ever deployed.
//
// # Run
//
//	all-tunnel -node-id t1 -node-kid node-t1-1 -node-host t1.nodes.example.org -node-key-file node.key \
//	    -cert-file fullchain.pem -key-file privkey.pem -acme-webroot /var/lib/all-tunnel/acme
//
// See main.go and backend_prod.go for every flag; each also has a TUNNEL_* environment variable.
//
// # Operating it
//
// deploy/ holds what a node needs around the binary (the unit, the certbot units and hooks, the volatile journal, nftables, sysctl). the deploy tool
// installs it and runs the whole procedure (provision, bootstrap, canary-first deploy with its DNS, stream and health gates, rollback); the canary tool is
// the canary device the monitors probe through each node; the node runbook is the procedure, drain and lost-call caveat included.
package main

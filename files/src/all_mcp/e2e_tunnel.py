"""ALL 2.0, DEVICE side of the tunnel, protocol v2 (plan sections 2, 3 and 5; the contract, sections 2 and 3): ChatGPT speaks ordinary HTTPS to a name that
is this computer.

A tunnel node (a small Go program on a public IP) reads only the SNI of a client's ClientHello and copies bytes. For every client of this computer it says ``OPEN`` on
the control connection this module keeps to it; the device dials the node back (``ATTACH``) and the raw stream, the client's own TLS, is handed to the terminator
(e2e_terminator.py), which ends it here with the certificate whose key only this computer has.

What this module is, in the order a connection lives:

  * ``E2ETunnel`` keeps ONE control connection per node of the list the control plane gave this computer at enroll (``NodeLink``). Each one dials the node on its port with
    TLS 1.3, ALPN ``all-tunnel/2`` and the node's public-CA certificate (certifi's bundle, the node's name, and an optional set of SPKI pins), and says
    ``HELLO 2 <session>``; the session is a v2 session of audience ``all-tunnel`` that ``device_credentials`` mints (and re-mints, with the control plane's time, when this
    computer's clock is off). The node answers ``CHALLENGE``; the device answers ``PROOF`` (a DPoP proof over the NODE's URL, so the proof is good nowhere else); the node
    asks the control plane and answers ``OK``: the host this computer serves (it must be the one the control plane gave THIS computer at its own enroll: a node
    cannot rename a device), the status (active, gated, paused), when the connection ends (``valid_until``) and the windows it offers (ping, dead peer, idle, age).
    The device clamps every window to its own policy and never trusts an offer beyond it.
  * Before ``valid_until`` minus ``timing.renew_before_valid_until_s`` it sends ``RENEW`` with a NEW session (and the node asks the control plane again: this is how an
    ended trial becomes ``gated`` without waiting for an event). ``PING`` every ``timing.ping_interval_s``; a node that is silent for ``timing.dead_peer_s`` is
    dead. ``DRAIN`` makes the device prefer the other node; ``STATEMENT`` (the control plane's signed access statement, forwarded) is verified, must not be older than
    the last one taken, and is handed to ``device_access.ingest``. A refused connection is retried with full-jitter back-off from ``timing.backoff_min_s`` to
    ``timing.backoff_max_s``; a wake from sleep or a change of network drops the connection at once and reconnects without back-off
    (``timing.reconnect_after_wake_s`` is the bound the tests hold it to).
  * Streams: the OPEN passes ``Admission`` (e2e_terminator.py) before the device does anything for it, then ``ATTACH`` on a new connection to the same node, then the
    terminator. A good source address (one that just completed an authenticated call) is told to the node with ``HINT``.

The tunnel never trusts the node with anything but availability: a node can cut or delay, and cannot rename the device, extend its own grant past what the control plane
says, make it dial anything but the agent's one proven port, or lift a paywall (only signed statements do). Nothing of a client (an address, a name) is ever logged.

Nothing here runs on its own: all_mcp.e2e_runner starts it in a supervised child process of the relay service, after the enroll and the wave flag said so.
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import ipaddress
import json
import logging
import random
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import certifi
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import e2e_policy as policy
from .e2e_terminator import Admission, EndpointBudgets, TLS_HANDSHAKE_BYTE, Terminator, close_writer, keepalive

log = logging.getLogger("all_mcp.e2e_tunnel")

# Constants of this module that the policy does not define: how long a dial and the wait for an OK may take, how long a connection must have lived to count as
# stable (a node that accepts and closes in a loop does not reset the back-off), the least time between two RENEWs, and how the clock and the network are watched.
DIAL_SECONDS = 10.0
OK_WAIT_SECONDS = 30.0
STABLE_SECONDS = 30.0
RENEW_MIN_GAP_SECONDS = 5.0
RENEW_RETRY_SECONDS = (5.0, 15.0)
CLOCK_WATCH_SECONDS = 1.0
NETWORK_WATCH_SECONDS = 2.0
WALL_JUMP_SECONDS = 3.0
STALL_WAKE_SECONDS = 15.0
RESYNC_SECONDS = 20.0   # the limit of one background read of the control plane's time
REPLACED_WAIT_SECONDS = (5.0, 30.0)
DRAIN_RECHECK_SECONDS = 1.0   # how often a node that said DRAIN is looked at again to see whether the other node still serves
STATEMENTS_IN_FLIGHT = 4
# What a node can say (CLOSE <reason>) that means the control plane's answer about this computer has changed: the child reads its enroll again at once instead of
# waiting for its next turn (the kill switch must not take half an hour to reach a computer that is connected).
ATTENTION_WORDS = frozenset({"killed", "revoked", "released"})
HINT_RESEND_DIVISOR = 3
TUNNEL_PATH = policy.value("protocol.proof_htu_path")
_STATUSES = frozenset(policy.value("enums.authorize_status"))
_NODE_ID = re.compile(r"[a-z0-9]{1,16}")
_SECONDS = re.compile(r"(?:0|[1-9][0-9]{0,5})")
_STATEMENT = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")


# ------------------------------------------------------------------------------------------------------------------------ errors

class TunnelError(Exception):
    """A connection that has to end. `word` is a fixed word (never text from the network) that the status file and the heartbeat may carry."""

    def __init__(self, word: str):
        super().__init__(word)
        self.word = word


class ProtocolError(TunnelError):
    """A line that is not in the grammar (or arrives where it should not)."""


class NodeRefused(TunnelError):
    """The node answered ERR <code> (or closed with CLOSE <reason>)."""


class Kicked(Exception):
    """The connection was dropped on purpose (a wake from sleep, a change of network): reconnect at once, no back-off."""


# ------------------------------------------------------------------------------------------------------------------------ the lines

def valid_ip(text: Any) -> bool:
    """An address as the contract writes it: IPv4 dotted quad without leading zeros, or IPv6 in RFC 4291 text form, lower case, no zone, no brackets."""
    if not isinstance(text, str) or text != text.lower() or any(char in text for char in "%[] ") or not text.isascii():
        return False
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _bounded_json(text: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        keys = [key for key, _ in items]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate key")
        return dict(items)

    def refuse(_: str) -> Any:
        raise ValueError("not a plain number")

    return json.loads(text, object_pairs_hook=pairs, parse_float=refuse, parse_constant=refuse)


def _epoch(value: Any) -> bool:
    return type(value) is int and 1 <= value <= 4102444800


def _ok_body(text: str) -> dict[str, Any]:
    try:
        body = _bounded_json(text)
    except (ValueError, RecursionError):
        raise ProtocolError("bad_command") from None
    windows = ("ping_interval_s", "dead_peer_s", "stream_idle_s", "stream_max_age_s", "renew_before_valid_until_s")
    ok = (isinstance(body, dict) and set(body) == {"v", "node", "host", "status", "valid_until", "server_time", "policy"}
          and type(body["v"]) is int and body["v"] == policy.value("protocol.version")
          and isinstance(body["node"], str) and _NODE_ID.fullmatch(body["node"]) is not None
          and isinstance(body["host"], str) and len(body["host"]) <= policy.value("identity.fqdn_max_length")
          and policy.anchored("identity.fqdn_regex").fullmatch(body["host"]) is not None
          and body["status"] in _STATUSES and _epoch(body["valid_until"]) and _epoch(body["server_time"])
          and isinstance(body["policy"], dict) and set(body["policy"]) == set(windows)
          and all(type(body["policy"][name]) is int and 1 <= body["policy"][name] <= 86400 for name in windows))
    if not ok:
        raise ProtocolError("bad_command")
    return body


def parse_node_line(line: str) -> dict[str, Any]:
    """One line the node sent (the text before the LF), as {"verb": ..., <field>: ...}. Raises ProtocolError. The grammar is contracts/schemas/wire-v2.grammar.json
    (the tunnel client's tests run every n2d vector of contracts/vectors/lines.json through this function): a line is ASCII 0x20-0x7e, one space between fields,
    no empty field, and it has its own maximum."""
    if not isinstance(line, str) or not line or any(not 0x20 <= ord(char) <= 0x7E for char in line):
        raise ProtocolError("bad_command")
    verb, space, rest = line.partition(" ")
    if verb == "OPEN":
        limit = policy.value("protocol.open_line_max_bytes")
    elif verb == "STATEMENT":
        limit = policy.value("protocol.statement_line_max_bytes")
    else:
        limit = policy.value("protocol.line_max_bytes")
    if len(line) + 1 > limit:
        raise ProtocolError("line_too_long")
    if space and not rest:
        raise ProtocolError("bad_command")
    if verb == "OK":
        if not space:
            raise ProtocolError("bad_command")
        return {"verb": verb, "body": _ok_body(rest)}
    fields = rest.split(" ") if space else []
    if any(not field_ for field_ in fields):
        raise ProtocolError("bad_command")
    out: dict[str, Any] = {"verb": verb}
    if verb == "CHALLENGE" and len(fields) == 1 and policy.anchored("identity.nonce_regex").fullmatch(fields[0]):
        out["nonce"] = fields[0]
    elif verb == "ERR" and len(fields) == 1 and fields[0] in policy.value("protocol.error_codes"):
        out["code"] = fields[0]
    elif (verb == "OPEN" and len(fields) == 4 and policy.anchored("identity.stream_id_regex").fullmatch(fields[0])
          and policy.anchored("identity.attach_secret_regex").fullmatch(fields[1]) and valid_ip(fields[2])
          and fields[3] in policy.value("protocol.source_classes")):
        out.update(stream_id=fields[0], secret=fields[1], peer_ip=fields[2], cls=fields[3])
    elif verb == "PONG" and not fields:
        pass
    elif verb == "STATEMENT" and len(fields) == 1 and _STATEMENT.fullmatch(fields[0]):
        out["statement"] = fields[0]
    elif verb == "DRAIN" and len(fields) == 1 and _SECONDS.fullmatch(fields[0]):
        out["quiet_s"] = int(fields[0])
    elif verb == "CLOSE" and len(fields) <= 1 and (not fields or fields[0] in policy.value("protocol.close_reasons")):
        out["reason"] = fields[0] if fields else ""
    else:
        raise ProtocolError("bad_command")
    return out


def _token_line(verb: str, token: str) -> str:
    if (not isinstance(token, str) or not token.isascii() or len(token) > policy.value("protocol.jwt_max_bytes")
            or _STATEMENT.fullmatch(token) is None):
        raise ProtocolError("bad_command")
    return f"{verb} {token}\n" if verb != "HELLO" else f"HELLO {policy.value('protocol.version')} {token}\n"


def hello_line(session: str) -> str:
    return _token_line("HELLO", session)


def renew_line(session: str) -> str:
    return _token_line("RENEW", session)


def proof_line(proof: str) -> str:
    return _token_line("PROOF", proof)


def attach_line(stream_id: str, secret: str) -> str:
    if (policy.anchored("identity.stream_id_regex").fullmatch(stream_id) is None
            or policy.anchored("identity.attach_secret_regex").fullmatch(secret) is None):
        raise ProtocolError("bad_command")
    return f"ATTACH {stream_id} {secret}\n"


def hint_line(addresses: list[str]) -> str:
    if not 1 <= len(addresses) <= policy.value("protocol.hint_max_addresses") or not all(valid_ip(address) for address in addresses):
        raise ProtocolError("bad_command")
    return "HINT " + " ".join(addresses) + "\n"


def close_line(reason: str = "") -> str:
    if reason and reason not in policy.value("protocol.close_reasons"):
        raise ProtocolError("bad_command")
    return f"CLOSE {reason}\n" if reason else "CLOSE\n"


# ------------------------------------------------------------------------------------------------------------------------ windows

@dataclass(frozen=True)
class Windows:
    """The windows a connection works with: this device's own policy, or what a node offered clamped to it (never above)."""
    ping_interval: float
    dead_peer: float
    stream_idle: float
    stream_max_age: float
    renew_before: float

    @classmethod
    def own(cls) -> "Windows":
        return cls(float(policy.value("timing.ping_interval_s")), float(policy.value("timing.dead_peer_s")), float(policy.value("timing.stream_idle_s")),
                   float(policy.value("timing.stream_max_age_s")), float(policy.value("timing.renew_before_valid_until_s")))

    def clamped(self, offered: dict[str, int]) -> "Windows":
        """What the node offered in its OK, held to this device's own windows: each is the smaller of the two (and at least one second, or this device's own window
        when that is shorter: a window of nothing would close every stream at once). A dead-peer window that is not longer than the ping interval would drop a healthy
        connection between two pings, so it is raised to twice the ping interval, still never above this device's own."""
        def held(name: str, own: float) -> float:
            return max(min(1.0, own), min(float(offered[name]), own))

        ping = held("ping_interval_s", self.ping_interval)
        dead = held("dead_peer_s", self.dead_peer)
        if dead <= ping:
            dead = min(self.dead_peer, ping * 2)
            ping = min(ping, dead / 2)
        return Windows(ping, dead, held("stream_idle_s", self.stream_idle), held("stream_max_age_s", self.stream_max_age),
                       held("renew_before_valid_until_s", self.renew_before))


# ------------------------------------------------------------------------------------------------------------------------ nodes and their certificates

@dataclass(frozen=True)
class NodeSpec:
    """A node of the list the control plane gave this computer: its id, name, port and optional SPKI pins (base64url SHA-256 of the SubjectPublicKeyInfo).
    `address` (tests and a node reached by a fixed address) is where to connect; the name is still the one the certificate must carry."""
    id: str
    host: str
    port: int
    pins: frozenset[str] = frozenset()
    address: str | None = None

    @property
    def url(self) -> str:
        """The node's own URL: what the DPoP proof is bound to (``https://<host>[:<port> unless 443]/all-tunnel/2``)."""
        return f"https://{self.host}{'' if self.port == 443 else ':' + str(self.port)}{TUNNEL_PATH}"

    @classmethod
    def from_json(cls, value: dict[str, Any]) -> "NodeSpec":
        return cls(value["id"], value["host"], int(value["port"]), frozenset(value.get("pins") or ()))


def spki_pin(der: bytes) -> str:
    """The pin of a certificate: base64url (no padding) of the SHA-256 of its SubjectPublicKeyInfo, so a renewal with the same key keeps the pin."""
    public = x509.load_der_x509_certificate(der).public_key()
    spki = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.urlsafe_b64encode(hashlib.sha256(spki).digest()).rstrip(b"=").decode("ascii")


def node_client_context() -> ssl.SSLContext:
    """TLS to a node: its certificate must chain to a public root (certifi's bundle: fresh or lagging machines see the same roots as the rest of ALL) and carry the
    node's name, TLS 1.3 at least, and the ALPN that says this is the tunnel."""
    context = ssl.create_default_context(cafile=certifi.where())
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols([policy.value("protocol.alpn")])
    return context


# ------------------------------------------------------------------------------------------------------------------------ the network, as far as a change can be seen

# Interfaces a Mac raises and drops on its own (AirDrop's awdl/llw, VPN and iCloud Private Relay utun, the anpi/ap/bridge/gif/stf helpers): none of them is a move between
# networks, and counting them reconnected every tunnel each time AirDrop woke up.
VIRTUAL_INTERFACE_PREFIXES = ("lo", "loopback", "awdl", "llw", "utun", "anpi", "ap", "bridge", "gif", "stf")


def default_network_snapshot() -> tuple:
    """What changes when the computer moves between networks: the address the default routes would send from (a UDP connect sends nothing) and the interfaces that are
    up. Cheap enough to take every couple of seconds."""
    routes = []
    for family, probe in ((socket.AF_INET, "192.0.2.1"), (socket.AF_INET6, "2001:db8::1")):
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as probe_socket:
                probe_socket.connect((probe, 9))
                routes.append(probe_socket.getsockname()[0])
        except OSError:
            routes.append("")
    try:
        import psutil
        up = tuple(sorted(name for name, stats in psutil.net_if_stats().items() if stats.isup and not name.lower().startswith(VIRTUAL_INTERFACE_PREFIXES)))
    except Exception:  # noqa: BLE001 - the routes alone are a good enough signal
        up = ()
    return (*routes, up)


# ------------------------------------------------------------------------------------------------------------------------ one control connection per node

@dataclass
class _Conn:
    """What one control connection is doing right now."""
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    windows: Windows
    exchange: str = "hello"            # which exchange is under way: "hello" (first) or "renew"
    awaiting: str | None = "challenge"   # what the node owes: "challenge", then "ok"; None between exchanges
    exchange_deadline: float = 0.0
    session: str = ""                  # the session of the exchange under way
    ready: bool = False
    heard: float = 0.0
    ping_at: float = 0.0
    renew_at: float | None = None
    valid_server: float = 0.0          # valid_until, on the control plane's clock
    fetch: asyncio.Future | None = None
    ready_at: float = 0.0
    close_reason: str = ""
    grace_ok: bool = False             # the last RENEW was answered "control_unavailable": the control plane, not the node, is what does not answer


class NodeLink:
    """The control connection to one node, kept for as long as the tunnel runs: connect, authenticate, serve (OPEN, PING, RENEW, STATEMENT, DRAIN), and connect again
    when it ends."""

    def __init__(self, tunnel: "E2ETunnel", spec: NodeSpec):
        self.tunnel = tunnel
        self.spec = spec
        self.state = "connecting"      # connecting | ready | draining | down
        self.status = ""               # what the node last said about this computer: active | gated | paused
        self.valid_until = 0           # the control plane's moment, from the last OK
        self.last_error = ""
        self.connects = 0
        self.failures = 0
        self.renewals = 0
        self.drain_until = 0.0         # monotonic
        self._writer: asyncio.StreamWriter | None = None
        self._kick = asyncio.Event()
        self._streams: set[asyncio.Task] = set()
        self._task: asyncio.Task | None = None
        self._hinted: dict[str, float] = {}
        self._stopping = False

    # -- life
    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self.run(), name=f"e2e-node-{self.spec.id}")

    async def stop(self) -> None:
        self._stopping = True
        self._kick.set()
        if self._writer is not None:
            with contextlib.suppress(Exception):
                self._writer.write(close_line("shutdown").encode("ascii"))
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        for task in list(self._streams):
            task.cancel()
        await asyncio.gather(*self._streams, return_exceptions=True)

    def kick(self) -> None:
        """Drop the connection now and reconnect at once (a wake from sleep or a change of network: the connection is probably dead and only a timer would say so)."""
        self._kick.set()

    @property
    def ready(self) -> bool:
        return self.state in ("ready", "draining")

    # -- the reconnect loop
    def _delay(self, attempt: int) -> float:
        """Full-jitter back-off: somewhere between the policy's minimum and a ceiling that doubles with every failure up to its maximum."""
        low, high = self.tunnel.backoff
        return random.uniform(low, max(low, min(high, low * 2 ** (attempt + 1))))

    async def run(self) -> None:
        attempt = 0
        while not self._stopping:
            began = time.monotonic()
            delay: float | None = None
            try:
                await self._connection()
            except asyncio.CancelledError:
                raise
            except Kicked:
                self.last_error = "network_changed"
                delay, attempt = random.uniform(0.0, 1.0), 0
            except NodeRefused as refused:
                self.last_error = refused.word
                delay = self._refusal_delay(refused.word, attempt)
                if refused.word in ATTENTION_WORDS:
                    self.tunnel.attention.set()
                if refused.word == "clock_skew":
                    with contextlib.suppress(Exception):
                        await asyncio.to_thread(self.tunnel.credentials.sync_clock, True)   # the difference with the control plane is learned again
            except TunnelError as error:
                self.last_error = error.word
            except ssl.SSLCertVerificationError:
                self.last_error = "certificate_refused"   # the node's certificate is not for its name, has expired or has no public root
            except (ssl.SSLError, ConnectionError, OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError) as error:
                self.last_error = "timeout" if isinstance(error, asyncio.TimeoutError) else ("tls_error" if isinstance(error, ssl.SSLError) else "connect_failed")
            except Exception as error:  # noqa: BLE001 - what a credential or a storage problem says is a closed word, never its text
                self.last_error = self.tunnel.credential_word(error)
                delay = self._refusal_delay(self.last_error, attempt)   # a revoked computer or a license that is over is not asked again every second
                if self.last_error == "internal_error":
                    log.warning("tunnel node %s: %s", self.spec.id, type(error).__name__)
            finally:
                was_ready = self.state in ("ready", "draining")
                self.state = "down"
                self._writer = None
                self.tunnel.link_ended(self)
            if self._stopping:
                return
            self.failures += 1
            stable = was_ready and time.monotonic() - began >= STABLE_SECONDS
            if stable:
                attempt = 0
            if delay is None:
                delay = self._delay(attempt)
                attempt += 1
            self.state = "connecting"
            await self._wait_to_reconnect(delay)
            self._kick.clear()

    async def _wait_to_reconnect(self, delay: float) -> None:
        """Wait `delay` before dialing again. A node that said DRAIN is left alone for its quiet period while the other node serves, and that is looked at again every
        DRAIN_RECHECK_SECONDS: when the other node goes down too, this one is dialed at once rather than leaving the computer with no connection. A kick (wake, network
        change) ends the wait at any time."""
        until = time.monotonic() + delay
        while True:
            now = time.monotonic()
            if self.drain_until > now and self.tunnel.other_node_ready(self):
                left = max(until, self.drain_until) - now   # the node said it is going down: the other node serves while it does
            else:
                left = until - now
            if left <= 0:
                return
            try:
                await asyncio.wait_for(self._kick.wait(), min(left, DRAIN_RECHECK_SECONDS))
                return
            except asyncio.TimeoutError:
                continue

    def _refusal_delay(self, word: str, attempt: int) -> float | None:
        """After a refusal: the plain back-off for a hiccup, the ceiling for an answer that will not change by itself (a revoked computer, a license that is over, a
        node that names this computer something else) and a short wait for a node that closed because another connection of this computer replaced it."""
        low, high = self.tunnel.backoff
        if word in ("device_revoked", "license_inactive", "revoked", "released", "killed", "host_mismatch"):
            return random.uniform(high / 2, high)
        if word == "replaced":
            return random.uniform(*REPLACED_WAIT_SECONDS)
        return None

    # -- dialing
    async def dial(self, *, limit: int = 1 << 16) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """TLS to the node, verified before a single byte is sent: its certificate chains to a public root and carries its name (the context), is on the pin list when
        there is one, and the connection is TLS 1.3 with the ALPN of the tunnel."""
        spec = self.spec
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(spec.address or spec.host, spec.port, ssl=self.tunnel.client_context(), server_hostname=spec.host,
                                    ssl_handshake_timeout=DIAL_SECONDS, limit=limit), DIAL_SECONDS + 5)
        try:
            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object is None or ssl_object.version() != "TLSv1.3" or ssl_object.selected_alpn_protocol() != policy.value("protocol.alpn"):
                raise TunnelError("tls_error")
            if spec.pins:
                der = ssl_object.getpeercert(binary_form=True)
                if not der or spki_pin(der) not in spec.pins:
                    raise TunnelError("pin_mismatch")   # nothing was sent: the session never leaves this computer for a certificate that is not the pinned one
        except BaseException:
            await close_writer(writer)
            raise
        keepalive(writer)
        return reader, writer

    # -- one connection
    async def _write(self, conn: _Conn, line: str) -> None:
        conn.writer.write(line.encode("ascii"))
        await asyncio.wait_for(conn.writer.drain(), conn.windows.dead_peer)

    async def _connection(self) -> None:
        tunnel = self.tunnel
        reader, writer = await self.dial(limit=policy.value("protocol.statement_line_max_bytes") + 16)
        self._writer = writer
        conn = _Conn(reader, writer, tunnel.windows_own, heard=time.monotonic())
        try:
            conn.session = await tunnel.session(force=False)
            await self._write(conn, hello_line(conn.session))
            conn.exchange_deadline = time.monotonic() + OK_WAIT_SECONDS
            await self._serve(conn)
        finally:
            if conn.fetch is not None and not conn.fetch.done():
                conn.fetch.cancel()
            await close_writer(writer)

    def _timers(self, conn: _Conn, now: float) -> float:
        """Seconds until the next thing this connection has to do on its own."""
        times = [conn.heard + conn.windows.dead_peer]
        if conn.awaiting:
            times.append(conn.exchange_deadline)
        if conn.ready:
            times.append(conn.ping_at)
            if not conn.awaiting:   # while a RENEW is under way the node decides (and the exchange has its own deadline)
                times.append(self._local_valid_until(conn) + (self._grace_seconds() if conn.grace_ok else 0.0))
                if conn.renew_at is not None and conn.fetch is None:
                    times.append(conn.renew_at)
        return max(0.0, min(times) - now)

    @staticmethod
    def _grace_seconds() -> float:
        """How long past valid_until a connection may live while the control plane does not answer: the node's own grace for a paid computer (policy authorization.grace_paid_s)."""
        return float(policy.value("authorization.grace_paid_s"))

    def _local_valid_until(self, conn: _Conn) -> float:
        """valid_until as a reading of the monotonic clock: the control plane's moment minus its time now, plus now."""
        return time.monotonic() + (conn.valid_server - self.tunnel.now())

    async def _serve(self, conn: _Conn) -> None:
        read_task: asyncio.Task | None = None
        kick_task: asyncio.Task | None = None
        try:
            while True:
                if read_task is None:
                    read_task = asyncio.ensure_future(conn.reader.readuntil(b"\n"))
                if kick_task is None or kick_task.done():
                    kick_task = asyncio.ensure_future(self._kick.wait())
                waiting = {read_task, kick_task} | ({conn.fetch} if conn.fetch is not None else set())
                now = time.monotonic()
                done, _ = await asyncio.wait(waiting, timeout=self._timers(conn, now), return_when=asyncio.FIRST_COMPLETED)
                now = time.monotonic()
                if kick_task in done:
                    self._kick.clear()
                    raise Kicked
                if self._stopping:
                    return
                if conn.fetch is not None and conn.fetch in done:
                    fetch, conn.fetch = conn.fetch, None
                    await self._start_renew(conn, fetch)
                if read_task in done:
                    task, read_task = read_task, None
                    try:
                        raw = task.result()
                    except asyncio.IncompleteReadError:
                        raise TunnelError("closed_by_node") from None
                    except asyncio.LimitOverrunError:
                        raise ProtocolError("line_too_long") from None
                    conn.heard = now
                    await self._line(conn, raw[:-1].decode("ascii", "replace"), now)
                await self._tick(conn, now)
        finally:
            for task in (read_task, kick_task):
                if task is not None and not task.done():
                    task.cancel()
            await asyncio.gather(*(t for t in (read_task, kick_task) if t is not None), return_exceptions=True)

    async def _tick(self, conn: _Conn, now: float) -> None:
        if now - conn.heard >= conn.windows.dead_peer:
            raise TunnelError("dead_peer")
        if conn.awaiting and now >= conn.exchange_deadline:
            if not conn.ready:
                raise TunnelError("handshake_timeout")
            self._renew_failed(conn, now)   # a RENEW the node never answered: the connection is still good until valid_until
        if not conn.ready:
            return
        over = now - self._local_valid_until(conn)
        if over >= 0 and not conn.awaiting and not (conn.grace_ok and over < self._grace_seconds()):
            # The grant is over. A computer whose last RENEW got "control_unavailable" keeps its connection for the paid grace (the node decides who gets it: a trial or gated
            # computer is closed by the node at valid_until whatever this side does, and a refusal of the control plane is never "the control plane is down"): closing here, at
            # valid_until, made the grace useless: the device redialled, the node needed a good authorize for the new HELLO and the control plane was down.
            raise TunnelError("expired")
        if now >= conn.ping_at:
            await self._write(conn, "PING\n")
            conn.ping_at = now + conn.windows.ping_interval
        if conn.renew_at is not None and now >= conn.renew_at and conn.fetch is None and not conn.awaiting:
            conn.renew_at = None
            conn.fetch = asyncio.ensure_future(self.tunnel.session(force=True))

    async def _start_renew(self, conn: _Conn, fetch: asyncio.Future) -> None:
        try:
            session = fetch.result()
        except asyncio.CancelledError:
            raise
        except Exception as error:  # noqa: BLE001
            self.last_error = self.tunnel.credential_word(error)
            conn.grace_ok = self.last_error == "control_unreachable"   # the control plane did not answer this computer's own request for a session: that is the outage the grace is for (a refusal is not)
            self._renew_failed(conn, time.monotonic())
            return
        conn.session, conn.exchange, conn.awaiting = session, "renew", "challenge"
        conn.exchange_deadline = time.monotonic() + OK_WAIT_SECONDS
        await self._write(conn, renew_line(session))

    def _renew_failed(self, conn: _Conn, now: float) -> None:
        """A renewal that did not come through: the old valid_until still holds, so try again soon, and well before it."""
        conn.awaiting = None
        left = self._local_valid_until(conn) - now
        retry = random.uniform(*RENEW_RETRY_SECONDS)
        conn.renew_at = now + (min(retry, max(0.5, left / 2)) if left > 0 else retry)      # past valid_until (the grace) the retry keeps its normal pace, never a storm

    async def _line(self, conn: _Conn, line: str, now: float) -> None:
        message = parse_node_line(line)
        verb = message["verb"]
        if verb == "CHALLENGE":
            if conn.awaiting != "challenge":
                raise ProtocolError("unexpected_challenge")
            proof = await self.tunnel.proof(conn.session, message["nonce"], self.spec.url)
            conn.awaiting = "ok"
            conn.exchange_deadline = now + OK_WAIT_SECONDS
            await self._write(conn, proof_line(proof))
        elif verb == "OK":
            if conn.awaiting != "ok":
                raise ProtocolError("unexpected_ok")
            self._on_ok(conn, message["body"], now)
        elif verb == "ERR":
            if conn.ready:
                self.last_error = message["code"]
                if message["code"] == "control_unavailable":
                    conn.grace_ok = True       # "the control plane did not answer" is what earns the paid grace
                elif message["code"] != "busy":
                    conn.grace_ok = False      # any other word is an answer of the control plane (a refusal): no grace. "busy" (the node's own pacing) says nothing about the control plane
                self._renew_failed(conn, now)   # a refused RENEW keeps the connection and its old valid_until
            else:
                raise NodeRefused(message["code"])
        elif verb == "OPEN":
            if conn.ready:
                self.tunnel.on_open(self, message)
        elif verb == "PONG":
            return
        elif verb == "STATEMENT":
            self.tunnel.on_statement(message["statement"])
        elif verb == "DRAIN":
            self.drain_until = now + min(message["quiet_s"], policy.value("timing.drain_quiet_s"))   # the grammar allows far more than the policy
            if self.state == "ready":
                self.state = "draining"
        elif verb == "CLOSE":
            raise NodeRefused(message["reason"] or "closed_by_node")
        else:
            raise ProtocolError("bad_command")   # a verb the device only SENDS (HELLO, PING...) coming from the node

    def _on_ok(self, conn: _Conn, body: dict[str, Any], now: float) -> None:
        if body["host"] != self.tunnel.host:
            raise TunnelError("host_mismatch")   # the node says this computer is somebody else's name: it is not believed, nothing is served for it
        server_now = self.tunnel.now()
        limit = server_now + policy.value("authorization.valid_until_paid_s") + policy.value("authorization.node_skew_max_s")
        valid = min(float(body["valid_until"]), limit)
        if valid <= server_now:
            raise TunnelError("grant_expired")
        conn.windows = self.tunnel.windows_own.clamped(body["policy"])
        conn.valid_server = valid
        conn.grace_ok = False
        conn.awaiting = None
        self.status, self.valid_until = body["status"], int(valid)
        if conn.exchange == "renew":
            self.renewals += 1
        if not conn.ready:
            conn.ready, conn.ready_at = True, now
            # A draining node refuses a new HELLO and sends DRAIN right after the OK of one that was already authenticating (tunnel/server.go followUp), so
            # an OK on a new connection is a node that is not draining now, whatever the previous connection was told: a DRAIN that follows sets it again.
            self.drain_until = 0.0
            self.state = "ready"
            self.connects += 1
            self.last_error = ""
            conn.ping_at = now + conn.windows.ping_interval
            self.tunnel.link_ready(self)
        self.tunnel.windows_changed(conn.windows)
        wait = valid - server_now - conn.windows.renew_before
        conn.renew_at = now + max(wait, min(RENEW_MIN_GAP_SECONDS, (valid - server_now) / 2)) + random.uniform(0, min(10.0, max(0.0, wait) * 0.05))

    # -- what streams and statements ask of the control connection
    def send_hint(self, addresses: list[str]) -> None:
        """Tell the node about client addresses that just completed authenticated calls (each at most once in a third of the node's memory of them)."""
        writer = self._writer
        if writer is None or self.state not in ("ready", "draining"):
            return
        now = time.monotonic()
        fresh = [address for address in addresses if now - self._hinted.get(address, float("-inf")) >= policy.value("node_limits.hint_ttl_s") / HINT_RESEND_DIVISOR]
        for start in range(0, len(fresh), policy.value("protocol.hint_max_addresses")):
            batch = fresh[start:start + policy.value("protocol.hint_max_addresses")]
            try:
                writer.write(hint_line(batch).encode("ascii"))
            except (ProtocolError, OSError):
                return
            for address in batch:
                self._hinted[address] = now
        while len(self._hinted) > policy.value("surface.limiter_lru_max"):
            self._hinted.pop(next(iter(self._hinted)))

    def track(self, task: asyncio.Task) -> None:
        self._streams.add(task)
        task.add_done_callback(self._streams.discard)

    def snapshot(self) -> dict[str, Any]:
        return {"id": self.spec.id, "state": self.state, "status": self.status, "valid_until": self.valid_until or None, "last_error": self.last_error,
                "connects": self.connects, "failures": self.failures, "renewals": self.renewals, "streams": len(self._streams)}


# ------------------------------------------------------------------------------------------------------------------------ the tunnel

def _statement_seq(token: str) -> int | None:
    """The `seq` of a statement that was already verified (the signature is what makes it believable; this only reads it)."""
    try:
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        seq = claims.get("seq")
        return seq if type(seq) is int and seq >= 1 else None
    except (IndexError, ValueError, UnicodeError, AttributeError):
        return None


@dataclass
class TunnelStats:
    streams_opened: int = 0
    streams_refused: dict[str, int] = field(default_factory=dict)
    attach_failures: int = 0
    statements_taken: int = 0
    statements_refused: int = 0
    wakes: int = 0
    network_changes: int = 0

    def as_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


class E2ETunnel:
    """The device's side of the tunnel: a control connection to every node, the terminator for every stream, and the watchers of the clock and the network.

    `host` is the name this computer serves (from its own enroll); `nodes` the list the control plane gave it; `credentials` is a device_credentials.DeviceCredentials (or
    anything with ``tunnel_session``, ``tunnel_proof``, ``now``, ``sync_clock``, ``verify_access`` and ``clock``); `serving` a tls_store.ServingContext. `ingest` takes a
    verified statement (device_access.ingest). Everything else exists so that tests can drive it without a network, a clock or an agent."""

    def __init__(self, *, host: str, nodes: list[NodeSpec], credentials: Any, serving: Any, ingest: Callable[[str], bool] | None = None,
                 client_context: Callable[[], ssl.SSLContext] = node_client_context, own_windows: Windows | None = None,
                 backoff: tuple[float, float] | None = None, admission: Admission | None = None, budgets: EndpointBudgets | None = None,
                 terminator: Terminator | None = None, terminator_options: dict[str, Any] | None = None,
                 network_snapshot: Callable[[], Any] = default_network_snapshot, wall: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic):
        self.host = host
        self.credentials = credentials
        self._client_context = client_context
        self.windows_own = own_windows or Windows.own()
        self._windows = self.windows_own
        self.backoff = backoff or (float(policy.value("timing.backoff_min_s")), float(policy.value("timing.backoff_max_s")))
        self.admission = admission or Admission()
        self.terminator = terminator or Terminator(host=host, serving=serving, windows=lambda: self._windows,
                                                  budgets=budgets, **(terminator_options or {}))
        if ingest is None:
            from . import device_access
            ingest = device_access.ingest
        self._ingest = ingest
        self._network_snapshot = network_snapshot
        self._wall = wall
        self._monotonic = monotonic
        self.stats = TunnelStats()
        self.links: dict[str, NodeLink] = {}
        self._last_seq = 0
        self._statements = 0
        self._stop = asyncio.Event()
        self._watch_task: asyncio.Task | None = None
        self._resync_task: asyncio.Task | None = None
        self._changed = asyncio.Event()
        self._client_ctx: ssl.SSLContext | None = None
        self.attention = asyncio.Event()   # a node said something that changes what the control plane thinks of this computer: read the enroll again now
        self.set_nodes(nodes)

    # -- the nodes
    def set_nodes(self, nodes: list[NodeSpec]) -> None:
        """The list the control plane gave: a node that is new gets a connection, one that is gone loses it, one whose name, port or pins changed gets a fresh one."""
        wanted = {spec.id: spec for spec in nodes}
        for node_id, link in list(self.links.items()):
            if node_id not in wanted or link.spec != wanted[node_id]:
                del self.links[node_id]
                if self._watch_task is not None:   # running: end it in the background
                    asyncio.get_running_loop().create_task(link.stop())
        for node_id, spec in wanted.items():
            if node_id not in self.links:
                self.links[node_id] = NodeLink(self, spec)
                if self._watch_task is not None:
                    self.links[node_id].start()

    def other_node_ready(self, link: NodeLink) -> bool:
        return any(other is not link and other.state == "ready" for other in self.links.values())

    # -- what the links ask for (blocking credential work runs in a thread)
    def client_context(self) -> ssl.SSLContext:
        """The TLS context for every connection to a node, built once (loading the root bundle for each stream would cost more than the stream)."""
        if self._client_ctx is None:
            self._client_ctx = self._client_context()
        return self._client_ctx

    def now(self) -> float:
        """The control plane's time (the offset the credentials learned): what valid_until is measured against."""
        return self.credentials.now()

    async def session(self, *, force: bool) -> str:
        return await asyncio.to_thread(self.credentials.tunnel_session, force)

    async def proof(self, session: str, nonce: str, node_url: str) -> str:
        return await asyncio.to_thread(self.credentials.tunnel_proof, session, nonce, node_url)

    def credential_word(self, error: BaseException) -> str:
        """The closed word for a credential failure (never its text)."""
        code = getattr(error, "code", "")
        if code in ("device_revoked", "license_inactive", "device_identity_required", "device_owned_by_other_license", "invalid_license"):
            return {"device_owned_by_other_license": "device_revoked", "invalid_license": "license_inactive"}.get(code, code)
        if getattr(error, "retryable", False):
            return "control_unreachable"
        return "internal_error" if not hasattr(error, "code") else "session_refused"

    # -- links report
    def link_ready(self, link: NodeLink) -> None:
        self._changed.set()

    def link_ended(self, link: NodeLink) -> None:
        self._changed.set()

    def windows_changed(self, windows: Windows) -> None:
        self._windows = windows   # the windows the newest OK clamped: streams that start from now on use them

    # -- streams
    def on_open(self, link: NodeLink, message: dict[str, Any]) -> None:
        if link.status == "paused":
            return   # a node does not open streams for a paused computer; one that does is not served
        ticket, why = self.admission.admit(message["peer_ip"], message["cls"])
        if ticket is None:
            refused = self.stats.streams_refused
            refused[why] = refused.get(why, 0) + 1
            return   # no ATTACH: the node closes the client when the attach window ends
        self.stats.streams_opened += 1
        link.track(asyncio.create_task(self._stream(link, message, ticket)))

    async def _stream(self, link: NodeLink, message: dict[str, Any], ticket) -> None:
        writer: asyncio.StreamWriter | None = None
        try:
            try:
                reader, writer = await link.dial()
                writer.write(attach_line(message["stream_id"], message["secret"]).encode("ascii"))
                await asyncio.wait_for(writer.drain(), policy.value("protocol.attach_timeout_s"))
                first = await asyncio.wait_for(reader.read(1 << 16), self.terminator.handshake_timeout)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - a stream that cannot be attached is just not served
                self.stats.attach_failures += 1
                return
            if not first or first.startswith(b"ERR") or first[0] != TLS_HANDSHAKE_BYTE:
                self.stats.attach_failures += 1   # the node refused the attach, or what came is not a TLS handshake: no client of ChatGPT starts with anything else
                return
            await self.terminator.serve(reader, writer, ip=message["peer_ip"], first=first, on_good=lambda ip, link=link: link.send_hint([ip]))
        finally:
            self.admission.release(ticket)
            await close_writer(writer)

    # -- statements
    def on_statement(self, token: str) -> None:
        if self._statements >= STATEMENTS_IN_FLIGHT:
            return   # a node that floods statements gets nothing more verified than it can be served
        self._statements += 1
        task = asyncio.create_task(self._take_statement(token))
        task.add_done_callback(lambda _: setattr(self, "_statements", self._statements - 1))

    async def _take_statement(self, token: str) -> None:
        """A signed statement the node forwarded: taken only when it verifies against the control plane's keys (a forgery and a statement for another computer do
        not), carries a `seq`, and that `seq` is not lower than the highest taken so far (an old `active` replayed cannot lift a paywall). The same `seq` again is
        harmless. device_access.ingest then decides whether it is newer than what the computer holds."""
        try:
            await asyncio.to_thread(self.credentials.verify_access, token)
        except Exception:  # noqa: BLE001 - not believed
            self.stats.statements_refused += 1
            return
        seq = _statement_seq(token)
        if seq is None or seq < self._last_seq:
            self.stats.statements_refused += 1
            return
        self._last_seq = seq
        try:
            taken = await asyncio.to_thread(self._ingest, token)
        except Exception:  # noqa: BLE001
            taken = False
        if taken:
            self.stats.statements_taken += 1
        else:
            self.stats.statements_refused += 1

    # -- running
    async def run(self) -> None:
        """Keep every node's control connection up until stop()."""
        self._watch_task = asyncio.create_task(self._watch())
        for link in self.links.values():
            link.start()
        try:
            await self._stop.wait()
        finally:
            background = [task for task in (self._watch_task, self._resync_task) if task is not None]
            for task in background:
                task.cancel()
            await asyncio.gather(*background, *(link.stop() for link in list(self.links.values())), return_exceptions=True)

    def stop(self) -> None:
        self._stop.set()

    def kick_all(self, reason: str) -> None:
        """Drop every control connection now (wake, network change): each reconnects within a second or so, with no back-off."""
        if reason == "wake":
            self.stats.wakes += 1
        else:
            self.stats.network_changes += 1
        for link in self.links.values():
            link.kick()

    def _resync_clock(self) -> None:
        """Learn the control plane's time again in the background, never ahead of the reconnection: one at a time, each with its own limit."""
        if self._resync_task is not None and not self._resync_task.done():
            return

        async def resync() -> None:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(asyncio.to_thread(self.credentials.sync_clock, True), RESYNC_SECONDS)

        self._resync_task = asyncio.create_task(resync(), name="e2e-clock-resync")

    async def _watch(self) -> None:
        """Notice a wake from sleep, a step of the clock and a change of network, which no timer can: a connection that was open when the lid closed is dead and says
        nothing. The wall clock moving more than the monotonic one (macOS and Linux do not count sleep in the monotonic clock) or the loop not running for a long
        while (Windows does count it) is a wake; the routes and the interfaces that are up changing is a network change. Either one drops the connections."""
        last_wall, last_mono = self._wall(), self._monotonic()
        last_net = await asyncio.to_thread(self._network_snapshot)
        last_net_at = last_mono
        while True:
            await asyncio.sleep(CLOCK_WATCH_SECONDS)
            wall, mono = self._wall(), self._monotonic()
            jump = (wall - last_wall) - (mono - last_mono)
            stalled = mono - last_mono > STALL_WAKE_SECONDS
            last_wall, last_mono = wall, mono
            if abs(jump) > WALL_JUMP_SECONDS or stalled:
                # the connections start over at once (the network may not be usable yet, and a request waiting for it would keep the dead ones up); the difference
                # between this computer's clock and the control plane's, learned before, is learned again alongside
                self.kick_all("wake")
                self._resync_clock()
                last_net = await asyncio.to_thread(self._network_snapshot)
                last_net_at = mono
                continue
            if mono - last_net_at >= NETWORK_WATCH_SECONDS:
                last_net_at = mono
                try:
                    current = await asyncio.to_thread(self._network_snapshot)
                except Exception:  # noqa: BLE001
                    continue
                if current != last_net:
                    last_net = current
                    self.kick_all("network")
                    self._resync_clock()

    # -- what the status file shows
    def state(self) -> str:
        """connecting (no node yet), ready (every node), degraded (some, not all), clock_skew (no node, and the answer was that the clock is wrong)."""
        links = list(self.links.values())
        ready = [link for link in links if link.ready]
        if links and len(ready) == len(links):
            return "ready"
        if ready:
            return "degraded"
        if any(link.last_error == "clock_skew" for link in links):
            return "clock_skew"
        return "connecting"

    def snapshot(self) -> dict[str, Any]:
        links = list(self.links.values())
        return {"state": self.state(), "nodes": [link.snapshot() for link in links], "connected": sum(1 for link in links if link.ready), "configured": len(links),
                "last_error": next((link.last_error for link in links if link.last_error), ""), "stats": self.stats.as_dict(),
                "terminator": self.terminator.stats.as_dict(), "tls13": self.terminator.tls_ready(),
                "windows": {"ping_interval_s": self._windows.ping_interval, "dead_peer_s": self._windows.dead_peer,
                            "stream_idle_s": self._windows.stream_idle, "stream_max_age_s": self._windows.stream_max_age}}

"""The TLS terminator of ALL 2.0 (plan sections 2, 3 and 5): where ChatGPT's HTTPS ends on this computer.

The tunnel node forwards bytes it cannot read. Every stream the node opens for this computer (``OPEN``, then the device's ``ATTACH``) is a TLS connection that
ChatGPT made to ``<label>.<zone>``; this module wraps it in a server-side TLS with the device's own certificate and hands the plain HTTP/1.1 to the agent's E2E
listener, and nothing else:

  * TLS 1.3 at least, ALPN ``http/1.1``, and the SNI must be this computer's own name (a handshake for any other name, or with none, ends with an alert);
    the certificate is the one ``tls/current`` names at the moment of the handshake (``tls_store.ServingContext``), so a renewal drops no stream.
  * The terminator sees the HTTP in clear and the client's address in the OPEN (the TLS it terminates hides it from the agent), so the limits that need an
    address live here: streams in all, per address, per second, and per endpoint (``/register``, ``/authorize``, ``/token``, ``/pair``) per minute, with a part
    of the streams kept for class ``openai`` so that a flood of strangers cannot starve ChatGPT. The agent never sees an address and never needs one.
  * Nothing is rewritten. The request head is checked and forwarded byte for byte: it must arrive whole within ``terminator.request_head_s`` and within
    ``terminator.request_head_max_bytes``, ends at CRLFCRLF (a bare LF, an obsolete line fold, a repeated or non-numeric ``Content-Length``, a ``Content-Length``
    together with ``Transfer-Encoding``, or an ``Upgrade`` is refused: h11 in the agent would unfold, merge or accept them, which is how a request is smuggled).
    The body is followed by its framing (length or chunks), so that the NEXT request on the same connection is a head again and is counted too.
  * The destination is the ONE address in ``surfaces.json`` (never LOCAL), read again for every stream, its pid alive, and before the first byte of ChatGPT's
    goes anywhere the listener proves, on that same connection, that it is the agent (the HMAC challenge of surfaces.prove_listener): a port the agent freed
    and another process bound receives the challenge and nothing more.
  * Idle time and age come from the policy the node offered clamped to this device's own (``e2e_tunnel.Windows``); a stream is closed when it is silent for the
    first or has lived the second.

No address is written to a log (the plan: nothing persistent names a client).
"""
from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import re
import socket
import ssl
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Any, Callable

from . import e2e_policy as policy
from . import surfaces, tls_policy

log = logging.getLogger("all_mcp.e2e_terminator")

TLS_HANDSHAKE_BYTE = 0x16
# Constants of this module that the policy does not define (it defines the windows, the limits and the sizes): how long a local dial may take, how much of the
# agent's answer is read at once, and how the keepalive of a TCP connection is shaped.
LOCAL_DIAL_SECONDS = 5.0
READ_BYTES = 65536
KEEPALIVE_IDLE_SECONDS = 30
KEEPALIVE_INTERVAL_SECONDS = 10
KEEPALIVE_PROBES = 3
RATE_WINDOW_SECONDS = 1.0
BUDGET_WINDOW_SECONDS = 60.0
CHUNK_LINE_MAX = 64
TRAILER_MAX_BYTES = 16384
_TOKEN = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_REQUEST_LINE = re.compile(rb"([!#$%&'*+.^_`|~0-9A-Za-z-]{1,32}) (/[\x21-\x7e]*) HTTP/1\.([01])")
_DIGITS = re.compile(rb"[0-9]{1,18}")
_CHUNK_SIZE = re.compile(rb"[0-9a-fA-F]{1,15}")
# The end-points that are budgeted per address: the keys of policy.terminator.endpoint_budgets, which are also the paths the E2E surface answers, except
# ANONYMOUS_MCP, which is not a path: it is /mcp asked for without a credential the terminator has seen work (no bearer, or a bearer from an address that has
# never completed an authenticated call), the first call of every connector (the 401 that starts OAuth discovery) and what a scanner sends.
ANONYMOUS_MCP = "mcp_anonymous"
BUDGETED = tuple(name for name in policy.value("terminator.endpoint_budgets") if name != ANONYMOUS_MCP)
AUTHENTICATED_PATHS = frozenset({"/mcp", "/mcp/", "/token"})
# How long an address that completed an authenticated call is remembered as a client of this computer (ChatGPT's own addresses keep renewing it).
KNOWN_CLIENT_SECONDS = 3600.0


# ------------------------------------------------------------------------------------------------------------------------ small helpers

def ip_group(ip: str) -> str:
    """What a client address is counted as: an IPv4 address by itself, an IPv6 address by its /64 (a household or an ISP lease owns the whole /64), an IPv4-mapped
    IPv6 address as the IPv4 it carries. Anything that is not an address is one shared group, so the limits still apply to it."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return str(address.ipv4_mapped)
        return str(ipaddress.ip_network((str(address), policy.value("node_limits.ipv6_prefix_bits")), strict=False))
    return str(address)


def keepalive(writer: asyncio.StreamWriter) -> None:
    """TCP keepalive on the connection (a half-open one, after a network change, must not live for ever)."""
    sock = writer.get_extra_info("socket")
    if sock is None:
        return
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if hasattr(socket, "TCP_KEEPIDLE"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, KEEPALIVE_IDLE_SECONDS)
        elif hasattr(socket, "TCP_KEEPALIVE"):   # macOS
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPALIVE, KEEPALIVE_IDLE_SECONDS)
        if hasattr(socket, "TCP_KEEPINTVL"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, KEEPALIVE_INTERVAL_SECONDS)
        if hasattr(socket, "TCP_KEEPCNT"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, KEEPALIVE_PROBES)
    except OSError:
        pass


async def close_writer(writer: asyncio.StreamWriter | None) -> None:
    if writer is None:
        return
    with contextlib.suppress(Exception):
        writer.close()
    with contextlib.suppress(Exception):
        await asyncio.wait_for(writer.wait_closed(), 2.0)


def http_response(status: int, reason: str, text: str, *, extra: tuple[tuple[str, str], ...] = ()) -> bytes:
    """A complete small HTTP/1.1 answer the terminator gives itself (a refusal, never a rewrite of what the agent says): plain text, closes the connection."""
    body = (text + "\n").encode("ascii")
    lines = [f"HTTP/1.1 {status} {reason}", "Content-Type: text/plain", f"Content-Length: {len(body)}", "Cache-Control: no-store", "Connection: close"]
    lines.extend(f"{name}: {value}" for name, value in extra)
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body


# ------------------------------------------------------------------------------------------------------------------------ TLS over a stream that is not a socket

class TLSStream:
    """Server-side TLS over any asyncio byte stream (here: the data connection to the tunnel node, which is itself TLS). ``ssl.MemoryBIO`` lets TLS run over a stream
    that is not a socket, which asyncio's own start_tls cannot do on top of another TLS transport."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, context: ssl.SSLContext, *, initial: bytes = b""):
        self._reader = reader
        self._writer = writer
        self._incoming = ssl.MemoryBIO()
        self._outgoing = ssl.MemoryBIO()
        self._ssl = context.wrap_bio(self._incoming, self._outgoing, server_side=True)
        if initial:
            self._incoming.write(initial)
        self._eof = False
        self._decrypted = b""   # bytes already decrypted when a read was cancelled while it flushed a key update: given back by the next read, never lost

    async def flush(self) -> None:
        data = self._outgoing.read()
        if data:
            self._writer.write(data)
            await self._writer.drain()

    async def _feed(self) -> bool:
        if self._eof:
            return False
        data = await self._reader.read(READ_BYTES)
        if not data:
            self._incoming.write_eof()
            self._eof = True
            return False
        self._incoming.write(data)
        return True

    async def handshake(self, timeout: float) -> None:
        async def go() -> None:
            while True:
                try:
                    self._ssl.do_handshake()
                    return
                except ssl.SSLWantReadError:
                    await self.flush()
                    if not await self._feed():
                        raise ConnectionResetError("the client closed during the TLS handshake")
        try:
            await asyncio.wait_for(go(), timeout)
        finally:
            with contextlib.suppress(Exception):
                await self.flush()   # the final flight, or the alert that explains a refusal

    def selected_alpn(self) -> str | None:
        return self._ssl.selected_alpn_protocol()

    def version(self) -> str | None:
        return self._ssl.version()

    async def read(self, size: int = READ_BYTES) -> bytes:
        """Decrypted bytes; b"" when the client closed (close_notify or a plain close). Safe to cancel (a timeout): nothing that was decrypted is lost."""
        if self._decrypted:
            data, self._decrypted = self._decrypted, b""
            return data
        while True:
            try:
                data = self._ssl.read(size)
            except ssl.SSLWantReadError:
                await self.flush()
                if not await self._feed():
                    return b""
                continue
            except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
                return b""
            if self._outgoing.pending:
                self._decrypted = data
                await self.flush()   # TLS 1.3 key updates and the like
                self._decrypted = b""
            return data

    async def write(self, data: bytes) -> None:
        view = memoryview(data)
        while view:
            written = self._ssl.write(view[:16384])
            view = view[written:]
            if self._outgoing.pending >= READ_BYTES or not view:
                await self.flush()

    async def close(self) -> None:
        """Say close_notify and go; the peer's own close_notify is not waited for."""
        with contextlib.suppress(ssl.SSLError, OSError, ValueError):
            self._ssl.unwrap()
        with contextlib.suppress(Exception):
            await self.flush()


# ------------------------------------------------------------------------------------------------------------------------ limits

@dataclass(eq=False)
class Ticket:
    """One admitted stream: give it back with ``Admission.release``."""
    group: str
    cls: str
    released: bool = False


class Admission:
    """Who may hold a stream, decided from the OPEN (the client's address and the node's class for it) before the device dials the node back.

    The streams in all are ``terminator.max_streams``; ``node_limits.openai_reserved_pct`` of them are reserved to class ``openai`` (strangers and hinted
    addresses together can hold only the rest, so a flood from anywhere never leaves ChatGPT without a slot). A stranger or hinted address is also held to
    ``per_ip_concurrent`` streams and ``per_ip_new_per_s`` new ones a second (an IPv6 address by its /64); class ``openai`` is not counted per address, because
    a handful of addresses carry all of ChatGPT. Every table is bounded (``surface.limiter_lru_max``), the oldest entry is the first to go."""

    def __init__(self, *, max_streams: int | None = None, reserved_pct: int | None = None, per_ip_concurrent: int | None = None,
                 per_ip_new_per_s: int | None = None, table_max: int | None = None, clock: Callable[[], float] = time.monotonic):
        self.total_max = policy.value("terminator.max_streams") if max_streams is None else max_streams
        percent = policy.value("node_limits.openai_reserved_pct") if reserved_pct is None else reserved_pct
        self.reserved = -(-self.total_max * percent // 100)   # rounded up: a quarter of 3 streams is still one stream
        self.per_ip = policy.value("node_limits.per_ip_concurrent") if per_ip_concurrent is None else per_ip_concurrent
        self.per_ip_rate = policy.value("node_limits.per_ip_new_per_s") if per_ip_new_per_s is None else per_ip_new_per_s
        self._table_max = policy.value("surface.limiter_lru_max") if table_max is None else table_max
        self._clock = clock
        self.active = 0
        self.active_other = 0
        self._concurrent: dict[str, int] = {}
        self._arrivals: OrderedDict[str, deque[float]] = OrderedDict()

    @property
    def other_max(self) -> int:
        return self.total_max - self.reserved

    def admit(self, ip: str, cls: str) -> tuple[Ticket | None, str]:
        """(a ticket, "") when the stream may go on, else (None, the word that says why)."""
        group = ip_group(ip)
        openai = cls == "openai"
        if self.active >= self.total_max:
            return None, "full"
        if not openai:
            if self.active_other >= self.other_max:
                return None, "full_other"
            if self._concurrent.get(group, 0) >= self.per_ip:
                return None, "ip_concurrent"
            now = self._clock()
            window = self._arrivals.get(group)
            if window is None:
                window = self._arrivals[group] = deque()
                while len(self._arrivals) > self._table_max:
                    self._arrivals.popitem(last=False)
            else:
                self._arrivals.move_to_end(group)
            while window and now - window[0] >= RATE_WINDOW_SECONDS:
                window.popleft()
            if len(window) >= self.per_ip_rate:
                return None, "ip_rate"
            window.append(now)
            self._concurrent[group] = self._concurrent.get(group, 0) + 1
            self.active_other += 1
        self.active += 1
        return Ticket(group, cls), ""

    def release(self, ticket: Ticket) -> None:
        if ticket.released:
            return
        ticket.released = True
        self.active -= 1
        if ticket.cls != "openai":
            self.active_other -= 1
            left = self._concurrent.get(ticket.group, 1) - 1
            if left > 0:
                self._concurrent[ticket.group] = left
            else:
                self._concurrent.pop(ticket.group, None)


class EndpointBudgets:
    """The budgets per address and per endpoint class, per minute (``terminator.endpoint_budgets``): the endpoints that anybody who can read the certificate
    transparency logs can reach without a token (``/register``, ``/authorize``, ``/token``, ``/pair``). One address using up its budget costs the others nothing."""

    def __init__(self, *, budgets: dict[str, dict[str, int]] | None = None, table_max: int | None = None, clock: Callable[[], float] = time.monotonic):
        self._budgets = policy.value("terminator.endpoint_budgets") if budgets is None else budgets
        self._table_max = policy.value("surface.limiter_lru_max") if table_max is None else table_max
        self._clock = clock
        self._windows: OrderedDict[tuple[str, str], deque[float]] = OrderedDict()
        self._known: OrderedDict[str, float] = OrderedDict()   # address group -> when it last completed an authenticated call

    @staticmethod
    def classify(path: str, *, credential_seen: bool = True) -> str | None:
        """The budgeted endpoint a request path belongs to (its query is not part of it), or None. `/mcp` without a credential the terminator has seen work is the
        anonymous class of the policy; with one, it is not budgeted (ChatGPT's addresses carry the traffic of every user of this computer)."""
        name = path.split("?", 1)[0].rstrip("/")
        if name == "/mcp" and not credential_seen:
            return ANONYMOUS_MCP
        return name[1:] if name[1:] in BUDGETED else None

    def note_client(self, ip: str) -> None:
        """This address just completed an authenticated call: it is a client of this computer, and its `/mcp` calls are no longer counted as anonymous."""
        key = ip_group(ip)
        self._known[key] = self._clock()
        self._known.move_to_end(key)
        while len(self._known) > self._table_max:
            self._known.popitem(last=False)

    def is_client(self, ip: str) -> bool:
        key = ip_group(ip)
        since = self._known.get(key)
        if since is None:
            return False
        if self._clock() - since >= KNOWN_CLIENT_SECONDS:
            del self._known[key]
            return False
        return True

    def allow(self, endpoint: str, ip: str) -> tuple[bool, float]:
        """(True, 0) and the request is counted, or (False, seconds until it would be allowed)."""
        limit = self._budgets[endpoint]["per_ip_per_min"]
        key = (endpoint, ip_group(ip))
        now = self._clock()
        window = self._windows.get(key)
        if window is None:
            window = self._windows[key] = deque()
            while len(self._windows) > self._table_max:
                self._windows.popitem(last=False)
        else:
            self._windows.move_to_end(key)
        while window and now - window[0] >= BUDGET_WINDOW_SECONDS:
            window.popleft()
        if len(window) >= limit:
            return False, max(1.0, BUDGET_WINDOW_SECONDS - (now - window[0]))
        window.append(now)
        return True, 0.0


# ------------------------------------------------------------------------------------------------------------------------ the request head and its framing

class BadRequest(Exception):
    """A request the terminator refuses. `status` is what the client is told (when it can still be told), `word` a fixed word for the counters."""

    def __init__(self, status: int, word: str):
        super().__init__(word)
        self.status = status
        self.word = word


@dataclass(frozen=True)
class RequestHead:
    method: str
    target: str
    path: str
    headers: tuple[tuple[bytes, bytes], ...]   # lower-case name, value as sent (without the surrounding blanks)
    body: str                                  # "none" | "length" | "chunked"
    length: int
    raw_size: int

    def header(self, name: bytes) -> bytes | None:
        for key, value in self.headers:
            if key == name:
                return value
        return None


def parse_head(raw: bytes) -> RequestHead:
    """Check one request head (the bytes up to and including the CRLFCRLF) and say how its body is framed. Raises BadRequest. Nothing is changed: the caller forwards `raw`."""
    if len(raw) > policy.value("terminator.request_head_max_bytes"):
        raise BadRequest(431, "head_too_large")
    if not raw.endswith(b"\r\n\r\n"):
        raise BadRequest(400, "bad_head")
    body = raw[:-4]
    if b"\n" in body.replace(b"\r\n", b"") or b"\r" in body.replace(b"\r\n", b""):
        raise BadRequest(400, "bare_line_ending")   # a lone LF or CR: what a lenient parser reads as a line end and a strict one does not
    lines = body.split(b"\r\n")
    found = _REQUEST_LINE.fullmatch(lines[0])
    if found is None:
        raise BadRequest(400, "bad_request_line")
    headers: list[tuple[bytes, bytes]] = []
    for line in lines[1:]:
        if line[:1] in (b" ", b"\t"):
            raise BadRequest(400, "obs_fold")   # h11 unfolds an obsolete line fold into the previous header: the agent would read what this check never saw
        name, colon, value = line.partition(b":")
        if not colon or _TOKEN.fullmatch(name) is None:
            raise BadRequest(400, "bad_header")
        value = value.strip(b" \t")
        if any(byte < 0x20 and byte != 0x09 or byte == 0x7F for byte in value):
            raise BadRequest(400, "bad_header_value")
        if len(value) > policy.value("surface.header_value_max_bytes"):
            raise BadRequest(431, "header_too_large")
        headers.append((name.lower(), value))
    if len(headers) > policy.value("surface.headers_max"):
        raise BadRequest(431, "too_many_headers")
    lengths = [value for name, value in headers if name == b"content-length"]
    encodings = [value for name, value in headers if name == b"transfer-encoding"]
    if len(lengths) > 1:
        raise BadRequest(400, "repeated_content_length")   # even identical: h11 merges them, a proxy in front of another parser may not
    if len(encodings) > 1 or (encodings and encodings[0].lower() != b"chunked") or (encodings and lengths):
        raise BadRequest(400, "bad_framing")
    for name, value in headers:
        if name == b"upgrade" or (name == b"connection" and b"upgrade" in value.lower()):
            raise BadRequest(400, "upgrade")   # the E2E surface is plain HTTP: there is no protocol to switch to
    length, kind = 0, "none"
    if lengths:
        if _DIGITS.fullmatch(lengths[0]) is None:
            raise BadRequest(400, "bad_content_length")
        length, kind = int(lengths[0]), "length"
        if length > policy.value("surface.body_max_bytes"):
            raise BadRequest(413, "body_too_large")
    elif encodings:
        kind = "chunked"
    target = found.group(2).decode("ascii")
    path = target.split("?", 1)[0]
    if "%" in path:
        raise BadRequest(400, "encoded_path")   # the agent's server decodes the path before it routes (/%72egister is /register): the budgets below would read another name
    return RequestHead(found.group(1).decode("ascii"), target, path, tuple(headers), kind, length, len(raw))


@dataclass
class Segment:
    """A slice of what the client sent, in order: a head (with its parse) or part of a body (or of its chunk framing). Together they are exactly the bytes received."""
    kind: str   # "head" | "body"
    data: bytes
    head: RequestHead | None = None


class RequestFramer:
    """Splits the client's byte stream into request heads and body, so that every request of a keep-alive connection (not only the first) is a head again. A head is
    held back until it is whole and has passed ``parse_head`` (an incomplete head is never forwarded); body bytes are passed on as they arrive. Raises BadRequest."""

    def __init__(self) -> None:
        self._buffer = bytearray()
        self._state = "head"
        self._remaining = 0
        self._total = 0
        self._trailer = 0
        self._chunked_body = False

    @property
    def awaiting_head(self) -> bool:
        return self._state == "head"

    @property
    def partial_head(self) -> bool:
        return self._state == "head" and bool(self._buffer)

    def feed(self, data: bytes) -> list[Segment]:
        self._buffer += data
        out: list[Segment] = []
        while self._buffer:
            if self._state == "head":
                end = self._buffer.find(b"\r\n\r\n")
                if end < 0:
                    if len(self._buffer) > policy.value("terminator.request_head_max_bytes"):
                        raise BadRequest(431, "head_too_large")
                    break
                raw = bytes(self._buffer[:end + 4])
                head = parse_head(raw)
                del self._buffer[:end + 4]
                out.append(Segment("head", raw, head))
                self._total = 0
                if head.body == "length" and head.length:
                    self._state, self._remaining = "body", head.length
                elif head.body == "chunked":
                    self._state = "chunk_size"
            elif self._state == "body":
                take = min(self._remaining, len(self._buffer))
                out.append(Segment("body", bytes(self._buffer[:take])))
                del self._buffer[:take]
                self._remaining -= take
                if not self._remaining:
                    self._state = "head"
            elif self._state == "chunk_size":
                end = self._buffer.find(b"\r\n")
                if end < 0:
                    if len(self._buffer) > CHUNK_LINE_MAX:
                        raise BadRequest(400, "bad_chunk")
                    break
                if end > CHUNK_LINE_MAX or _CHUNK_SIZE.fullmatch(bytes(self._buffer[:end])) is None:
                    raise BadRequest(400, "bad_chunk")   # no chunk extensions: a size is hexadecimal digits and nothing else
                size = int(self._buffer[:end], 16)
                out.append(Segment("body", bytes(self._buffer[:end + 2])))
                del self._buffer[:end + 2]
                self._total += size
                if self._total > policy.value("surface.body_max_bytes"):
                    raise BadRequest(413, "body_too_large")
                self._state, self._remaining, self._trailer = ("trailer", 0, 0) if size == 0 else ("chunk_data", size, 0)
            elif self._state == "chunk_data":
                take = min(self._remaining, len(self._buffer))
                out.append(Segment("body", bytes(self._buffer[:take])))
                del self._buffer[:take]
                self._remaining -= take
                if not self._remaining:
                    self._state = "chunk_end"
            elif self._state == "chunk_end":
                if len(self._buffer) < 2:
                    break
                if bytes(self._buffer[:2]) != b"\r\n":
                    raise BadRequest(400, "bad_chunk")
                out.append(Segment("body", b"\r\n"))
                del self._buffer[:2]
                self._state = "chunk_size"
            else:   # trailer: header lines up to the empty one
                end = self._buffer.find(b"\r\n")
                if end < 0:
                    if len(self._buffer) + self._trailer > TRAILER_MAX_BYTES:
                        raise BadRequest(431, "head_too_large")
                    break
                line = bytes(self._buffer[:end + 2])
                self._trailer += len(line)
                if self._trailer > TRAILER_MAX_BYTES or b"\n" in line[:-2] or line[:1] in (b" ", b"\t"):
                    raise BadRequest(400, "bad_chunk")
                out.append(Segment("body", line))
                del self._buffer[:end + 2]
                if end == 0:
                    self._state = "head"
        return out


# ------------------------------------------------------------------------------------------------------------------------ the terminator

@dataclass
class TerminatorStats:
    streams: int = 0
    active: int = 0
    tls_streams: int = 0
    handshake_failures: int = 0
    no_certificate: int = 0
    refused: dict[str, int] = field(default_factory=dict)   # admission refusals, by word
    bad_requests: dict[str, int] = field(default_factory=dict)
    budget_refused: int = 0
    no_surface: int = 0
    identity_failures: int = 0
    agent_unreachable: int = 0
    head_timeouts: int = 0
    idle_closes: int = 0
    age_closes: int = 0
    bytes_up: int = 0      # client -> agent
    bytes_down: int = 0    # agent -> client

    def as_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)

    def count(self, table: dict[str, int], word: str) -> None:
        table[word] = table.get(word, 0) + 1


class Terminator:
    """Serves the streams the node opens: TLS, the checks above, the dial to the agent and the pipe between them.

    `serving` is a tls_store.ServingContext (or anything with ``listener_context()``, ``served()`` and ``number``); `windows` is a callable that returns the
    current ``e2e_tunnel.Windows`` (idle and age); `host` is the device's own name, the only SNI it answers; `on_good(ip)` is told when a client address just
    completed an authenticated call (the tunnel sends it to the node as a HINT). `load_target` and `prove` are the agent's surface file and the identity
    proof (surfaces.load_target, surfaces.prove_listener): tests replace them, nothing else does."""

    def __init__(self, *, host: str, serving: Any, windows: Callable[[], Any], budgets: EndpointBudgets | None = None,
                 on_good: Callable[[str], None] | None = None, load_target: Callable[[], Any] | None = None, prove: Callable[..., Any] | None = None,
                 local_port: int | None = None, handshake_timeout: float | None = None, head_timeout: float | None = None,
                 clock: Callable[[], float] = time.monotonic):
        self.host = host
        self.serving = serving
        self.windows = windows
        self.budgets = budgets if budgets is not None else EndpointBudgets(clock=clock)
        self.on_good = on_good
        self._load_target = load_target or surfaces.load_target
        self._prove = prove or surfaces.prove_listener
        self._local_port = local_port
        self.handshake_timeout = policy.value("terminator.tls_handshake_s") if handshake_timeout is None else handshake_timeout
        self.head_timeout = policy.value("terminator.request_head_s") if head_timeout is None else head_timeout
        self._clock = clock
        self.stats = TerminatorStats()
        self._context: ssl.SSLContext | None = None
        self._served_number: int | None = None
        self.last_error = ""

    # -- TLS
    def tls_ready(self) -> bool:
        """TLS 1.3 is what the terminator will not serve without (plan section 3): a Python whose OpenSSL has none must say so instead of serving less
        (tls_policy decides; the status file shows ``degraded`` / ``tls13_required``)."""
        return tls_policy.tls13_available()

    def _listener_context(self) -> ssl.SSLContext | None:
        """The one context that answers every handshake and follows the certificate pointer by itself; None while there is no certificate yet."""
        if self._context is not None:
            return self._context
        try:
            context = self.serving.listener_context()
        except Exception as exc:  # noqa: BLE001 - no certificate (or a store that cannot be read) is "no certificate", never a crash
            self.last_error = getattr(exc, "word", type(exc).__name__.lower())
            return None
        if context.minimum_version < ssl.TLSVersion.TLSv1_3:
            self.last_error = "tls13_required"
            return None
        wanted = self.host
        follow = context.sni_callback

        def only_my_name(connection, server_name, original):
            if not server_name or server_name.lower().rstrip(".") != wanted:
                return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME   # no SNI, or another name: the handshake ends with an alert
            return follow(connection, server_name, original) if follow is not None else None

        context.sni_callback = only_my_name
        self._context = context
        self.last_error = ""
        return context

    async def _handshake(self, reader, writer, first: bytes) -> TLSStream | None:
        ready = self.tls_ready()
        context = self._listener_context() if ready else None
        if context is None:
            if ready:
                self.stats.no_certificate += 1
            else:
                self.last_error = "tls13_required"   # never silent: the tunnel reports tls13=False and the runner turns it into `degraded`
                self.stats.handshake_failures += 1
            return None
        tls = TLSStream(reader, writer, context, initial=first)
        try:
            await tls.handshake(self.handshake_timeout)
        except (ssl.SSLError, OSError, ConnectionError, asyncio.TimeoutError, ValueError) as exc:
            self.stats.handshake_failures += 1
            log.debug("TLS handshake failed (%s)", type(exc).__name__)
            return None
        if tls.selected_alpn() not in (None, policy.value("terminator.tls_alpn")):
            self.stats.handshake_failures += 1
            return None
        self.stats.tls_streams += 1
        number = getattr(self.serving, "number", None)
        if number is not None and number != self._served_number:
            self._served_number = number
            with contextlib.suppress(Exception):
                await asyncio.to_thread(self.serving.served)   # a certificate that completed a handshake lets the previous generation go
        return tls

    # -- the agent
    async def _dial_agent(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None:
        """The agent's E2E listener, proven. Never LOCAL: surfaces.json names the E2E port (and is read again now: a restart of the agent moved it), the pid must
        be alive, and the listener must answer the challenge on this very connection before anything of ChatGPT's is written to it."""
        try:
            target = self._load_target()
        except surfaces.SurfaceIdentityError:
            self.stats.no_surface += 1
            return None
        if target.port == self._local_surface_port():
            self.stats.no_surface += 1   # a surfaces.json that names the LOCAL port is not an E2E listener (the bootstrap bearer works there)
            return None
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(target.host, target.port, limit=1 << 16), LOCAL_DIAL_SECONDS)
        except (OSError, asyncio.TimeoutError):
            self.stats.agent_unreachable += 1
            return None
        try:
            await self._prove(reader, writer, host=target.host, port=target.port, secret=target.secret, pid=target.pid, timeout=LOCAL_DIAL_SECONDS)
        except surfaces.SurfaceIdentityError:
            self.stats.identity_failures += 1
            await close_writer(writer)
            return None
        return reader, writer

    def _local_surface_port(self) -> int:
        if self._local_port is not None:
            return self._local_port
        import os
        return int(os.environ.get("ALL_MCP_PORT", "4410"))

    # -- one stream
    async def serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, *, ip: str, first: bytes,
                    on_good: Callable[[str], None] | None = None) -> None:
        """One stream the node attached: `first` is what has already been read (the ClientHello); `on_good` replaces the terminator's own when this stream came
        through a particular node (its HINT goes to that node). Returns when it ends; never raises."""
        self.stats.streams += 1
        self.stats.active += 1
        tls: TLSStream | None = None
        agent_writer: asyncio.StreamWriter | None = None
        try:
            tls = await self._handshake(reader, writer, first)
            if tls is None:
                return
            agent_writer = await self._exchange(tls, ip, on_good or self.on_good)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - a stream must end quietly
            log.debug("stream ended: %s", type(exc).__name__)
        finally:
            self.stats.active -= 1
            await close_writer(agent_writer)
            if tls is not None:
                await tls.close()

    async def _exchange(self, tls: TLSStream, ip: str, on_good: Callable[[str], None] | None) -> asyncio.StreamWriter | None:
        """The pipe between the client (through `tls`) and the agent, until either ends or a window runs out. Returns the agent's writer, which the caller closes."""
        windows = self.windows()
        framer = RequestFramer()
        started = self._clock()
        head_since = started   # the first request has head_timeout from the end of the handshake, a later one from its first byte
        last = started         # the last byte that moved in either direction
        forwarded = 0          # request heads passed on
        first_good = False
        first_status_seen = False
        agent_writer: asyncio.StreamWriter | None = None
        agent_task: asyncio.Task | None = None
        agent_done: asyncio.Future = asyncio.get_running_loop().create_future()

        async def refuse(status: int, reason: str, text: str, extra=()) -> None:
            with contextlib.suppress(Exception):
                await tls.write(http_response(status, reason, text, extra=extra))

        async def agent_to_client(agent_reader: asyncio.StreamReader) -> None:
            nonlocal last, first_status_seen
            while True:
                data = await agent_reader.read(READ_BYTES)
                if not data:
                    return
                if not first_status_seen:
                    first_status_seen = True
                    if first_good and data[:9] == b"HTTP/1.1 " and data[9:10] == b"2":
                        # a stranger cannot make the agent answer 2xx to an authenticated call: this address is a client of this device
                        self.budgets.note_client(ip)
                        if on_good is not None:
                            with contextlib.suppress(Exception):
                                on_good(ip)
                last = self._clock()
                self.stats.bytes_down += len(data)
                await tls.write(data)

        async def client_to_agent() -> None:
            nonlocal last, head_since, forwarded, first_good, agent_writer, agent_task
            while True:
                now = self._clock()
                if now - started >= windows.stream_max_age:
                    raise _Over("age")
                if now - last >= windows.stream_idle:
                    raise _Over("idle")
                waits = [windows.stream_idle - (now - last), windows.stream_max_age - (now - started)]
                if framer.awaiting_head and (framer.partial_head or not forwarded):
                    if now - head_since >= self.head_timeout:
                        raise _Over("head")
                    waits.append(self.head_timeout - (now - head_since))
                try:
                    data = await asyncio.wait_for(tls.read(), min(waits))
                except asyncio.TimeoutError:
                    continue   # the deadlines are looked at again above: traffic the other way may have moved the idle clock
                if not data:
                    return
                if forwarded and framer.awaiting_head and not framer.partial_head:
                    head_since = self._clock()
                last = self._clock()
                self.stats.bytes_up += len(data)
                try:
                    segments = framer.feed(data)
                except BadRequest as bad:
                    self.stats.count(self.stats.bad_requests, bad.word)
                    if not forwarded:
                        await refuse(bad.status, "Bad Request" if bad.status == 400 else "Request Rejected", bad.word)
                    return
                for segment in segments:
                    if segment.kind == "head":
                        head = segment.head
                        bearer = (head.header(b"authorization") or b"")[:7].lower() == b"bearer "
                        endpoint = self.budgets.classify(head.path, credential_seen=bearer and self.budgets.is_client(ip))
                        if endpoint is not None:
                            allowed, retry = self.budgets.allow(endpoint, ip)
                            if not allowed:
                                self.stats.budget_refused += 1
                                if not forwarded:
                                    await refuse(429, "Too Many Requests", "slow down", extra=(("Retry-After", str(int(retry) + 1)),))
                                return   # on a connection that is already carrying a request, closing is the only answer that cannot be woven into its response
                        if not forwarded:
                            dialed = await self._dial_agent()
                            if dialed is None:
                                await refuse(503, "Service Unavailable", "ALL is not answering here")
                                return
                            agent_reader, agent_writer = dialed
                            keepalive(agent_writer)
                            agent_task = asyncio.create_task(agent_to_client(agent_reader))
                            agent_task.add_done_callback(lambda task: agent_done.done() or agent_done.set_result(task))
                            first_good = head.path in AUTHENTICATED_PATHS and (head.path == "/token" or bearer)
                        forwarded += 1
                    agent_writer.write(segment.data)
                    await agent_writer.drain()

        up = asyncio.create_task(client_to_agent())
        try:
            done, _ = await asyncio.wait({up, agent_done}, return_when=asyncio.FIRST_COMPLETED)
            if up in done:
                over = up.exception()
                if isinstance(over, _Over):
                    {"age": self._count_age, "idle": self._count_idle, "head": self._count_head}[over.word]()
                    return agent_writer
                if over is not None:
                    raise over
                # the client finished its side (close_notify, or an end of the stream): say so to the agent and keep delivering what it is still answering, for a while
                if agent_task is not None and not agent_task.done():
                    with contextlib.suppress(Exception):
                        if agent_writer.can_write_eof():
                            agent_writer.write_eof()
                    with contextlib.suppress(asyncio.TimeoutError, Exception):
                        await asyncio.wait_for(asyncio.shield(agent_task), policy.value("timing.half_close_s"))
                return agent_writer
            task = agent_done.result()   # the agent ended its answer, or the connection: the stream is over
            if not task.cancelled() and task.exception() is not None and not isinstance(task.exception(), (ConnectionError, OSError)):
                raise task.exception()
            return agent_writer
        finally:
            for task in (up, agent_task):
                if task is not None and not task.done():
                    task.cancel()
            await asyncio.gather(*(t for t in (up, agent_task) if t is not None), return_exceptions=True)
            await close_writer(agent_writer)   # also when the client's side ended with an exception: the caller never gets the writer then

    def _count_age(self) -> None:
        self.stats.age_closes += 1

    def _count_idle(self) -> None:
        self.stats.idle_closes += 1

    def _count_head(self) -> None:
        self.stats.head_timeouts += 1


class _Over(Exception):
    """A window ran out (the stream's age, its silence, or the time a request head had): the stream is closed. `word` says which."""

    def __init__(self, word: str):
        super().__init__(word)
        self.word = word

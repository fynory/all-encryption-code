#!/usr/bin/env python3
"""Does a plaintext marker cross the tunnel server? Reads a tcpdump capture (classic pcap) and looks for markers in it.

This is the proof tool of the ALL end-to-end experiment (the 1.1 experiment plan section 2.9, test 2): the lead puts synthetic markers
into the bodies of requests and responses that go ChatGPT (or any HTTPS client) -> tunnel server -> device, captures the traffic on
the tunnel server (with its capture command) and this module says whether any marker is visible there. It is standard library
only, so it also runs from release_readiness later.

What it does, so that "no marker found" is not an empty statement:
  * decodes Ethernet / raw IP / Linux cooked (SLL, SLL2) frames, IPv4 and IPv6, TCP;
  * searches every marker in (a) the raw bytes of the file, (b) each TCP payload, (c) each TCP stream reassembled per direction, so a
    marker split across two segments is still found;
  * counts what WAS captured (flows, payload bytes per port, TLS records by type, the SNI names of the ClientHellos) and refuses to call
    the capture clean when it holds no payload at all: a capture that saw nothing proves nothing;
  * reads the hellos that cross in the clear with the ONE parser of the device (src/all_mcp/tls_policy.py, WP16): the version, cipher suite and selected group of every
    ServerHello (and the alert of a refused handshake), and what each ClientHello offered, so the blindness gate records them in e2e-proof.json.
Not covered: pcapng files (tcpdump -w writes classic pcap) and IP fragments.

WP23 made it the library of the blindness gate, so it also:
  * searches every marker in its ENCODED forms (`forms=True`, on in the command line): upper and lower case (DNS folds case), base64 at the three
    alignments, URL-safe base64, hex, UTF-16, and in what a stream holds once it is unwrapped: the TLS record headers taken out (a marker split across two
    records), gzip and zlib streams inflated, base64 runs decoded, DNS names joined across their labels;
  * reads UDP too (DNS on the node's resolver port is where a node could leak a marker without a TCP connection of its own);
  * refuses a capture that lost something: a hole in a flow's sequence numbers, a flow whose first or last bytes are missing, a packet cut by the snap length,
    a packet count that differs from what tcpdump says it captured, or kernel drops in tcpdump's own counters, is INCOMPLETE and never CLEAN (a marker may
    have been in the part that is missing);
  * lists every TLS flow with its SNI, the ServerHello's version, cipher and group, and the bytes each way (`flow_table`).

  python3 scripts/e2e_pcap.py FILE --marker TEXT [--marker TEXT ...] [--ports 443,8443] [--min-bytes N] [--tcpdump-log FILE] [--allow-midflow] [--exact] [--json]

Exit codes: 0 clean (markers given, none found, traffic seen, nothing missing); 5 a marker was found; 1 not conclusive (no markers given, no payload
captured, a capture that lost packets, or a damaged one); 2 unreadable file or bad usage.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import dataclasses
import json
import re
import struct
import sys
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Sequence

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", False), b"\xa1\xb2\xc3\xd4": (">", False),
    b"\x4d\x3c\xb2\xa1": ("<", True), b"\xa1\xb2\x3c\x4d": (">", True),
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
LINK_NULL, LINK_ETHERNET, LINK_RAW, LINK_SLL, LINK_SLL2 = 0, 1, 101, 113, 276
# BSD address families of a loopback frame (macOS numbers AF_INET6 as 30, FreeBSD as 28): what a `tcpdump -i lo0` file holds
BSD_FAMILY_ETHERTYPE = {2: 0x0800, 24: 0x86DD, 28: 0x86DD, 30: 0x86DD}
MAX_FILE_BYTES = 400 * 1024 * 1024
TLS_TYPES = {20: "change_cipher_spec", 21: "alert", 22: "handshake", 23: "application_data"}
MAX_EXAMPLES = 5
MAX_HELLOS_LISTED = 20
MAX_FLOWS_LISTED = 200
MAX_VIEW_BYTES = 64 * 1024 * 1024  # of one stream that is unwrapped (inflated, decoded) for the search
MAX_INFLATE_TRIES = 256  # offsets of one stream where a gzip or zlib header is tried
BASE64_RUN = re.compile(rb"[A-Za-z0-9+/_-]{24,}={0,2}")
TCP_FIN, UDP_DNS_PORT = 0x01, 53
_TLS_POLICY = None


def tls_policy():
    """The device's TLS policy module (the hello parser lives there, once): imported from this checkout's src/ the first time it is needed."""
    global _TLS_POLICY
    if _TLS_POLICY is None:
        src = str(Path(__file__).resolve().parents[1] / "src")
        if src not in sys.path:
            sys.path.insert(0, src)
        from all_mcp import tls_policy as module
        _TLS_POLICY = module
    return _TLS_POLICY


class PcapError(Exception):
    """The file cannot be read as a classic pcap capture."""


@dataclass
class Segment:
    src: str
    sport: int
    dst: str
    dport: int
    seq: int
    syn: bool
    payload: bytes
    fin: bool = False
    proto: str = "tcp"
    ack: int = 0
    has_ack: bool = False


@dataclass
class MarkerResult:
    marker: str  # what is shown: the marker itself, or the label of a secret (its value is never stored or printed)
    secret: bool = False
    raw_hits: int = 0
    packet_hits: int = 0
    stream_hits: int = 0
    where: list = field(default_factory=list)
    forms: list = field(default_factory=list)  # the forms in which it was found ("raw", "base64+1", "tls-records", ...)
    flows: list = field(default_factory=list)  # the connections it was found in, as flow_key() writes them

    @property
    def found(self) -> bool:
        return bool(self.raw_hits or self.packet_hits or self.stream_hits)


@dataclass
class PcapReport:
    file: str = ""
    link: str = ""
    packets: int = 0
    tcp_packets: int = 0
    skipped_frames: int = 0
    truncated_tail: bool = False
    payload_bytes: int = 0
    flows: int = 0
    ports: dict = field(default_factory=dict)  # port -> {"flows": n, "payload_bytes": n}
    tls_records: dict = field(default_factory=dict)
    tls_flows: int = 0
    non_tls_flows: list = field(default_factory=list)  # [{"flow": ..., "first_bytes": ...}] a plaintext start is worth a look
    sni_names: dict = field(default_factory=dict)
    server_hellos: list = field(default_factory=list)  # [{"flow", "version", "cipher", "group", "hybrid", "hello_retry_request"}] read from the ServerHello bytes
    client_hellos: list = field(default_factory=list)  # [{"flow", "server_name", "offers_hybrid", "groups", ...}]
    alerts: list = field(default_factory=list)  # [{"flow", "alert"}] a server that refused the handshake
    tls_summary: dict = field(default_factory=dict)  # counts of version, cipher and group over the ServerHellos: what e2e-proof.json records
    flow_table: list = field(default_factory=list)  # one entry per TCP connection: SNI, TLS version, cipher and group, bytes each way, records
    udp_packets: int = 0
    udp_payload_bytes: int = 0
    dns_names: dict = field(default_factory=dict)  # query name -> count, read from UDP and TCP port 53
    markers: list = field(default_factory=list)
    min_bytes: int = 1
    incomplete: list = field(default_factory=list)  # [{"where", "reason"}] everything that says part of the traffic is missing from the capture
    stats: dict = field(default_factory=dict)  # what the capture tool itself said (tcpdump's counters), when it was given
    secrets_are_markers: bool = False  # the secrets are all there is to search for (a marker file read by `e2e_blindness.py analyze`): they count as the markers of the verdict

    @property
    def found(self) -> bool:
        return any(m.found for m in self.markers)

    @property
    def traffic_seen(self) -> bool:
        return self.payload_bytes >= self.min_bytes

    @property
    def verdict(self) -> str:
        if self.found:
            return "FOUND"
        if not any(self.secrets_are_markers or not m.secret for m in self.markers):
            return "NO-MARKERS"  # a secret that is searched for in addition does not replace the markers the caller asked for
        if self.incomplete:
            return "INCOMPLETE"
        if not self.traffic_seen:
            return "NO-TRAFFIC"
        return "CLEAN"

    @property
    def exit_code(self) -> int:
        return {"CLEAN": 0, "FOUND": 5}.get(self.verdict, 1)

    def summary(self) -> str:
        ports = ", ".join(f"{p}: {v['flows']} flow(s) {v['payload_bytes']} B" for p, v in sorted(self.ports.items())) or "none"
        tls = ", ".join(f"{k} {v}" for k, v in sorted(self.tls_records.items())) or "none"
        text = (f"{self.packets} packet(s), {self.tcp_packets} TCP, {self.flows} flow(s), {self.payload_bytes} payload bytes; "
                f"by port: {ports}; TLS records: {tls}; SNI names seen: {', '.join(sorted(self.sni_names)) or 'none'}")
        if self.skipped_frames:
            text += f"; {self.skipped_frames} frame(s) not decoded"
        if self.truncated_tail:
            text += "; the last record of the file was cut"
        return text

    def to_dict(self) -> dict:
        data = dataclasses.asdict(self)
        data.update(verdict=self.verdict, found=self.found, traffic_seen=self.traffic_seen)
        for entry, result in zip(data["markers"], self.markers):
            entry["found"] = result.found
        return data


# --------------------------------------------------------------------------- decoding

def read_frames(data: bytes) -> tuple:
    """(link type, [frame bytes], truncated_tail) of a classic pcap file."""
    link, frames, truncated, _snapped = read_frames_ex(data)
    return link, frames, truncated


def read_frames_ex(data: bytes) -> tuple:
    """(link type, [frame bytes], truncated_tail, snapped): `snapped` counts the frames the capture cut short (captured length below the length on the wire)."""
    if data[:4] == PCAPNG_MAGIC:
        raise PcapError("this is a pcapng file; capture with `tcpdump -w` (classic pcap) or convert it with editcap -F pcap")
    if len(data) < 24 or data[:4] not in PCAP_MAGICS:
        raise PcapError("not a pcap capture (unknown magic number)")
    endian, _nano = PCAP_MAGICS[data[:4]]
    link = struct.unpack_from(endian + "I", data, 20)[0]
    frames, offset, truncated, snapped = [], 24, False, 0
    while offset < len(data):
        if offset + 16 > len(data):
            truncated = True
            break
        incl, orig = struct.unpack_from(endian + "II", data, offset + 8)
        offset += 16
        if incl > 262144 * 4 or offset + incl > len(data):
            truncated = True
            break
        snapped += 1 if orig > incl else 0
        frames.append(data[offset:offset + incl])
        offset += incl
    return link, frames, truncated, snapped


def _ip_version(frame: bytes, link: int) -> Optional[tuple]:
    """(ip packet bytes, ethertype) or None."""
    if link == LINK_ETHERNET:
        if len(frame) < 14:
            return None
        kind, start = struct.unpack_from(">H", frame, 12)[0], 14
        while kind in (0x8100, 0x88A8) and len(frame) >= start + 4:  # VLAN tags
            kind, start = struct.unpack_from(">H", frame, start + 2)[0], start + 4
        return frame[start:], kind
    if link == LINK_SLL:
        return (frame[16:], struct.unpack_from(">H", frame, 14)[0]) if len(frame) >= 16 else None
    if link == LINK_SLL2:
        return (frame[20:], struct.unpack_from(">H", frame, 0)[0]) if len(frame) >= 20 else None
    if link == LINK_RAW and frame:
        return frame, {4: 0x0800, 6: 0x86DD}.get(frame[0] >> 4, 0)
    if link == LINK_NULL and len(frame) >= 4:
        # the family is written in the capturing host's byte order: little-endian first (every Mac this runs on), then big-endian
        family = struct.unpack_from("<I", frame, 0)[0]
        if family not in BSD_FAMILY_ETHERTYPE:
            family = struct.unpack_from(">I", frame, 0)[0]
        return frame[4:], BSD_FAMILY_ETHERTYPE.get(family, 0)
    return None


def _ip_text(raw: bytes) -> str:
    if len(raw) == 4:
        return ".".join(str(b) for b in raw)
    return ":".join(f"{raw[i]:02x}{raw[i + 1]:02x}" for i in range(0, 16, 2))


def _ip_payload(frame: bytes, link: int, protocol: int) -> Optional[tuple]:
    """(source address, destination address, the IP payload) of an IPv4 or IPv6 frame that carries `protocol` (6 TCP, 17 UDP), or None."""
    found = _ip_version(frame, link)
    if not found:
        return None
    ip, kind = found
    if kind == 0x0800 and len(ip) >= 20 and ip[0] >> 4 == 4:
        header = (ip[0] & 15) * 4
        total = struct.unpack_from(">H", ip, 2)[0]
        fragment = struct.unpack_from(">H", ip, 6)[0] & 0x1FFF
        if ip[9] != protocol or header < 20 or fragment:
            return None
        return _ip_text(ip[12:16]), _ip_text(ip[16:20]), ip[header:total if 0 < total <= len(ip) else len(ip)]
    if kind == 0x86DD and len(ip) >= 40 and ip[0] >> 4 == 6:
        length, nxt, start = struct.unpack_from(">H", ip, 4)[0], ip[6], 40
        while nxt in (0, 43, 60) and len(ip) >= start + 8:  # hop-by-hop, routing, destination options
            nxt, start = ip[start], start + (ip[start + 1] + 1) * 8
        if nxt != protocol:
            return None
        return _ip_text(ip[8:24]), _ip_text(ip[24:40]), ip[start:40 + length if 0 < length else len(ip)]
    return None


def decode_tcp(frame: bytes, link: int) -> Optional[Segment]:
    found = _ip_payload(frame, link, 6)
    if not found:
        return None
    src, dst, tcp = found
    if len(tcp) < 20:
        return None
    sport, dport, seq = struct.unpack_from(">HHI", tcp, 0)
    offset = (tcp[12] >> 4) * 4
    if offset < 20 or offset > len(tcp):
        return None
    ack = struct.unpack_from(">I", tcp, 8)[0]
    return Segment(src, sport, dst, dport, seq, bool(tcp[13] & 0x02), bytes(tcp[offset:]), fin=bool(tcp[13] & TCP_FIN), ack=ack, has_ack=bool(tcp[13] & 0x10))


def decode_udp(frame: bytes, link: int) -> Optional[Segment]:
    """A UDP datagram as a Segment (proto "udp", no sequence number): what the node's resolver sends and receives."""
    found = _ip_payload(frame, link, 17)
    if not found:
        return None
    src, dst, udp = found
    if len(udp) < 8:
        return None
    sport, dport, length = struct.unpack_from(">HHH", udp, 0)
    return Segment(src, sport, dst, dport, 0, False, bytes(udp[8:length if 8 <= length <= len(udp) else len(udp)]), proto="udp")


# --------------------------------------------------------------------------- reassembly and TLS

def _relative(seq: int, base: int) -> int:
    rel = (seq - base) & 0xFFFFFFFF
    return rel - (1 << 32) if rel >= 1 << 31 else rel


def reassemble_checked(segments: Sequence[Segment], peer: Sequence[Segment] = ()) -> tuple:
    """(chunks, problems) for ONE direction of ONE flow: the payload as contiguous byte strings (a gap, i.e. a lost packet, starts a new one), and what says that
    part of it is missing from the capture: `hole` (a gap between two segments), `head_missing` (the handshake was captured and the first bytes are not),
    `no_syn` (the capture starts in the middle of the flow), `tail_missing` (the FIN, or what the OTHER side acknowledged, says more bytes were sent than were
    captured). `peer` is the opposite direction of the same flow: its acknowledgement numbers say how much of this direction arrived."""
    base, saw_syn = None, False
    for seg in segments:
        if seg.syn:
            base, saw_syn = (seg.seq + 1) & 0xFFFFFFFF, True
            break
    if base is None and segments:
        base = segments[0].seq
    placed, fin_end = [], None
    for seg in segments:
        if seg.fin:
            fin_end = max(fin_end or 0, _relative(seg.seq, base) + len(seg.payload))
        if seg.payload:
            placed.append((_relative(seg.seq, base), seg.payload))
    placed.sort(key=lambda item: item[0])
    chunks: list = []
    first, end = None, None
    for offset, payload in placed:
        if end is None or offset > end:
            chunks.append(bytearray(payload))
            end = offset + len(payload)
            first = offset if first is None else first
        elif offset + len(payload) > end:
            chunks[-1] += payload[end - offset:]
            end = offset + len(payload)
    problems: list = []
    if len(chunks) > 1:
        problems.append("hole")
    if chunks and not saw_syn:
        problems.append("no_syn")
    elif chunks and first is not None and first > 0:
        problems.append("head_missing")
    got = end or 0
    if fin_end is not None and fin_end > got:
        problems.append("tail_missing")
    elif base is not None:
        # base is the first payload byte's number: an acknowledgement of `base + n` says n bytes arrived (an ack number of 0 is a hand-built frame's: no information)
        acked = max((_relative(p.ack, base) for p in peer if p.has_ack and p.ack), default=0)
        if acked > got + (1 if fin_end is not None else 0):
            problems.append("tail_missing")
    return [bytes(c) for c in chunks], problems


def reassemble(segments: Sequence[Segment]) -> list:
    """The payload of ONE direction of ONE flow as contiguous byte strings (a gap, i.e. a lost packet, starts a new one)."""
    return reassemble_checked(segments)[0]


def tls_records(stream: bytes) -> Optional[dict]:
    """Counts the TLS records at the start of a stream, or None when the stream does not start like TLS."""
    counts: dict = {}
    offset = 0
    while offset + 5 <= len(stream):
        kind, major, length = stream[offset], stream[offset + 1], struct.unpack_from(">H", stream, offset + 3)[0]
        if kind not in TLS_TYPES or major != 3 or length > 18432:
            break
        counts[TLS_TYPES[kind]] = counts.get(TLS_TYPES[kind], 0) + 1
        offset += 5 + length
    return counts or None


def client_hello_sni(stream: bytes) -> Optional[str]:
    """The server name of a TLS ClientHello at the start of a stream (what a router that never decrypts can see), or None."""
    try:
        if len(stream) < 6 or stream[0] != 22 or stream[5] != 1:
            return None
        pos = 5 + 4 + 2 + 32  # record header, handshake header, version, random
        pos += 1 + stream[pos]  # session id
        pos += 2 + struct.unpack_from(">H", stream, pos)[0]  # cipher suites
        pos += 1 + stream[pos]  # compression methods
        end = pos + 2 + struct.unpack_from(">H", stream, pos)[0]
        pos += 2
        while pos + 4 <= min(end, len(stream)):
            kind, size = struct.unpack_from(">HH", stream, pos)
            pos += 4
            if kind == 0 and size >= 5:
                name_len = struct.unpack_from(">H", stream, pos + 3)[0]
                return stream[pos + 5:pos + 5 + name_len].decode("ascii", errors="replace")
            pos += size
    except (IndexError, struct.error):
        return None
    return None


def read_hello(stream: bytes, label: str, report: "PcapReport", hellos: list) -> dict:
    """Adds what the start of one direction of a flow says in the clear (a ClientHello, a ServerHello, an alert) to the report, and returns it for the flow's row:
    {"client": ClientHello dict, "server": the first ServerHello dict, "alert": name}. A hello that is cut or not TLS is skipped: the TLS record counts above already show it."""
    tls = tls_policy()
    seen: dict = {}
    try:
        if len(stream) > 5 and stream[0] == 22 and stream[5] == 1:
            client = tls.parse_client_hello(stream)
            if client is not None:
                seen["client"] = client.as_dict()
                if len(report.client_hellos) < MAX_HELLOS_LISTED:
                    report.client_hellos.append({"flow": label, **client.as_dict()})
            return seen
        observed = tls.observe_server(stream)
    except tls.TlsParseError:
        return seen
    for hello in observed.hellos:
        hellos.append(hello)
        seen.setdefault("server", hello.as_dict())
        if len(report.server_hellos) < MAX_HELLOS_LISTED:
            report.server_hellos.append({"flow": label, **hello.as_dict()})
    if observed.alert is not None:
        seen["alert"] = observed.alert.name
        if len(report.alerts) < MAX_HELLOS_LISTED:
            report.alerts.append({"flow": label, "alert": observed.alert.name})
    return seen


def printable(data: bytes, limit: int = 8, hide: Sequence[str] = ()) -> str:
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in data[:limit])
    for secret in hide:
        if secret:
            text = text.replace(secret, "<redacted>")
    return text


# --------------------------------------------------------------------------- what is searched for, and where

def needle_forms(value: str) -> list:
    """[(form, bytes)] the ways `value` can show up in a capture: as it is, upper and lower case (a DNS resolver folds case), base64 and URL-safe base64 at the three
    alignments it can have inside a longer text (only the characters that depend on the marker alone are kept), hex, and UTF-16 either way."""
    raw = value.encode("utf-8")
    forms = [("raw", raw)]
    for name, other in (("lower", raw.lower()), ("upper", raw.upper())):
        if other != raw:
            forms.append((name, other))
    for pad in range(3):
        encoded = base64.b64encode(b"\0" * pad + raw).rstrip(b"=")
        needle = encoded[-(-4 * pad // 3):(4 * (pad + len(raw))) // 3]
        if len(needle) >= 8:
            forms.append((f"base64+{pad}", needle))
            forms.append((f"base64url+{pad}", needle.replace(b"+", b"-").replace(b"/", b"_")))
    forms.append(("hex", raw.hex().encode("ascii")))
    if raw.hex().lower() != raw.hex().upper():
        forms.append(("HEX", raw.hex().upper().encode("ascii")))
    text = value
    forms.append(("utf16le", text.encode("utf-16-le")))
    forms.append(("utf16be", text.encode("utf-16-be")))
    unique, seen = [], set()
    for name, needle in forms:
        if needle and needle not in seen:
            seen.add(needle)
            unique.append((name, needle))
    return unique


def tls_body_view(stream: bytes) -> Optional[bytes]:
    """The record bodies of a stream that starts with TLS records, joined: a marker that a sender cut across two records has its halves next to each other here
    (the five-byte headers between them are gone). None when the stream does not start like TLS."""
    out, offset, seen = bytearray(), 0, 0
    while offset + 5 <= len(stream):
        kind, major, length = stream[offset], stream[offset + 1], struct.unpack_from(">H", stream, offset + 3)[0]
        if kind not in TLS_TYPES or major != 3 or length > 18432:
            break
        out += stream[offset + 5:offset + 5 + length]
        offset += 5 + length
        seen += 1
    return bytes(out) if seen else None


COMPRESSED_HEADER = re.compile(rb"\x1f\x8b\x08|\x78[\x01\x5e\x9c\xda]")


def inflate_views(data: bytes) -> list:
    """What the gzip and zlib streams that start anywhere in `data` hold (what could be read before the stream broke counts too: a capture can cut one short)."""
    views, tries = [], 0
    for found in COMPRESSED_HEADER.finditer(data):
        if tries >= MAX_INFLATE_TRIES:
            break
        tries += 1
        inflater = zlib.decompressobj(31 if data[found.start()] == 0x1F else 15)
        out, pos = bytearray(), found.start()
        try:
            while pos < len(data) and len(out) < MAX_VIEW_BYTES and not inflater.eof:
                out += inflater.decompress(data[pos:pos + 2048], MAX_VIEW_BYTES - len(out))
                pos += 2048
        except zlib.error:
            pass
        if len(out) >= 8:
            views.append(bytes(out))
    return views


def base64_views(data: bytes) -> list:
    """What the base64 (or URL-safe base64) texts inside `data` decode to."""
    views = []
    for found in BASE64_RUN.finditer(data):
        text = found.group(0).rstrip(b"=").replace(b"-", b"+").replace(b"_", b"/")
        text = text[:len(text) - len(text) % 4 or None] if len(text) % 4 == 1 else text
        try:
            views.append(binascii.a2b_base64(text + b"=" * (-len(text) % 4)))
        except (binascii.Error, ValueError):
            continue
    return views


def derived_views(data: bytes, depth: int = 2) -> list:
    """[(name, bytes)] of what `data` holds once it is unwrapped: the TLS record headers taken out, gzip and zlib inflated, base64 decoded; each of those unwrapped
    once more (a base64 text of a gzip body). Bounded: MAX_VIEW_BYTES of output in all."""
    out, budget = [], MAX_VIEW_BYTES
    frontier = [("", data[:MAX_VIEW_BYTES])]
    for _ in range(depth):
        nxt = []
        for prefix, blob in frontier:
            candidates = []
            body = tls_body_view(blob) if not prefix else None
            if body:
                candidates.append(("tls-records", body))
            candidates += [("inflate", view) for view in inflate_views(blob)]
            candidates += [("base64", view) for view in base64_views(blob)]
            for name, view in candidates:
                if budget <= 0:
                    return out
                budget -= len(view)
                label = f"{prefix}>{name}" if prefix else name
                out.append((label, view))
                nxt.append((label, view))
        frontier = nxt
    return out


def dns_names(payload: bytes) -> list:
    """The names a DNS message carries in its question and record sections (compression pointers followed), or [] when it is not DNS."""
    names: list = []

    def read(pos: int) -> tuple:
        labels, jumped, end, hops = [], False, pos, 0
        while True:
            length = payload[pos]
            if length == 0:
                return ".".join(labels), (end if jumped else pos + 1)
            if length & 0xC0 == 0xC0:
                target = ((length & 0x3F) << 8) | payload[pos + 1]
                end = end if jumped else pos + 2
                jumped, pos, hops = True, target, hops + 1
                if hops > 16:
                    raise IndexError
                continue
            labels.append(payload[pos + 1:pos + 1 + length].decode("ascii", errors="replace"))
            pos += 1 + length
            if not jumped:
                end = pos

    try:
        questions, answers, authority, extra = struct.unpack_from(">HHHH", payload, 4)
        pos = 12
        for _ in range(min(questions, 16)):
            name, pos = read(pos)
            names.append(name)
            pos += 4
        for _ in range(min(answers + authority + extra, 64)):
            name, pos = read(pos)
            names.append(name)
            size = struct.unpack_from(">H", payload, pos + 8)[0]
            pos += 10 + size
    except (IndexError, struct.error):
        pass
    return [name for name in names if name]


def parse_tcpdump_stats(text: str) -> dict:
    """tcpdump's own counters from what it prints when it ends ("12 packets captured", "12 packets received by filter", "0 packets dropped by kernel", "0 packets
    dropped by interface"): {"captured", "received", "dropped_kernel", "dropped_interface"}, only the ones the text has."""
    stats = {}
    for key, pattern in (("captured", r"(\d+) packets? captured"), ("received", r"(\d+) packets? received by filter"),
                         ("dropped_kernel", r"(\d+) packets? dropped by kernel"), ("dropped_interface", r"(\d+) packets? dropped by interface")):
        found = re.search(pattern, text or "")
        if found:
            stats[key] = int(found.group(1))
    return stats


def stats_problems(stats: dict, packets: int) -> list:
    """What tcpdump's counters say about a capture of `packets` packets, as [(where, reason)]; empty when they show nothing lost."""
    problems = []
    for key in ("dropped_kernel", "dropped_interface"):
        if stats.get(key):
            problems.append(("capture counters", f"tcpdump says {stats[key]} packet(s) {key.replace('dropped_', 'dropped by ')}"))
    if "captured" in stats and stats["captured"] != packets:
        problems.append(("capture counters", f"tcpdump says it captured {stats['captured']} packet(s) and the file holds {packets}"))
    if "received" in stats and "captured" in stats and stats["received"] != stats["captured"] and not stats.get("dropped_kernel"):
        problems.append(("capture counters", f"tcpdump received {stats['received']} packet(s) by the filter and captured {stats['captured']}"))
    return problems


def flow_key(src: str, sport: int, dst: str, dport: int) -> str:
    """One name for a connection, whichever direction a packet goes."""
    first, second = sorted([f"{src}:{sport}", f"{dst}:{dport}"])
    return f"{first} <-> {second}"


# --------------------------------------------------------------------------- analysis

def analyse(data: bytes, markers: Sequence[str] = (), *, ports: Optional[Sequence[int]] = None, min_bytes: int = 1, name: str = "",
            hide: Sequence[str] = (), secret_markers: Sequence[tuple] = (), forms: bool = False, stats: Optional[dict] = None,
            allow_midflow: bool = False, secrets_are_markers: bool = False) -> PcapReport:
    """`secret_markers` are (label, value) pairs searched like markers (a leaked secret is a finding) but shown only by their label. `forms` also searches every
    marker in its encoded forms and in what each stream holds once unwrapped (needle_forms, derived_views). `stats` is what the capture tool said about itself
    (parse_tcpdump_stats): kernel drops or a packet count that differs from the file's make the capture INCOMPLETE. `allow_midflow` accepts flows whose
    handshake is not in the capture (a capture that was already running); a hole, a missing tail or a cut packet is never accepted. `secrets_are_markers` lets
    secrets alone be what is searched for (their values are still never shown): without it a run that was given no marker is NO-MARKERS."""
    if len(data) > MAX_FILE_BYTES:
        raise PcapError(f"the capture is {len(data)} bytes; above {MAX_FILE_BYTES} it is not analysed in memory")
    link, frames, truncated, snapped = read_frames_ex(data)
    report = PcapReport(file=name, link={LINK_NULL: "bsd-loopback", LINK_ETHERNET: "ethernet", LINK_RAW: "raw-ip", LINK_SLL: "linux-sll",
                                         LINK_SLL2: "linux-sll2"}.get(link, f"unsupported({link})"),
                        packets=len(frames), truncated_tail=truncated, min_bytes=min_bytes, stats=dict(stats or {}), secrets_are_markers=secrets_are_markers)
    if report.link.startswith("unsupported"):
        raise PcapError(f"link type {link} is not supported (Ethernet, raw IP, BSD loopback and Linux cooked captures are)")
    wanted = set(ports) if ports else None
    flows: dict = {}  # (src, sport, dst, dport) -> [Segment]
    segments, datagrams = [], []
    for frame in frames:
        seg = decode_tcp(frame, link)
        if seg is None:
            seg = decode_udp(frame, link)
            if seg is None:
                report.skipped_frames += 1
                continue
        if wanted is not None and seg.sport not in wanted and seg.dport not in wanted:
            continue
        if seg.proto == "udp":
            report.udp_packets += 1
            report.udp_payload_bytes += len(seg.payload)
            datagrams.append(seg)
            continue
        report.tcp_packets += 1
        segments.append(seg)
        flows.setdefault((seg.src, seg.sport, seg.dst, seg.dport), []).append(seg)
    results = [MarkerResult(m) for m in markers] + [MarkerResult(f"<secret: {label}>", secret=True) for label, _ in secret_markers]
    values = [*markers, *(value for _, value in secret_markers)]
    needles: list = []  # (result, form, bytes)
    for result, value in zip(results, values):
        if not value:
            raise PcapError("an empty marker would match everything")
        for form, needle in (needle_forms(value) if forms else [("raw", value.encode("utf-8"))]):
            needles.append((result, form, needle))
    for result, form, needle in needles:
        hits = data.count(needle)
        if hits:
            result.raw_hits += hits
            if form not in result.forms:
                result.forms.append(form)

    def search(blob: bytes, view: str, where: str, key: str, kind: str) -> None:
        for result, form, needle in needles:
            hits = blob.count(needle)
            if not hits:
                continue
            if kind == "packet":
                result.packet_hits += hits
            else:
                result.stream_hits += hits
            name = form if view == "raw" else f"{view}:{form}"
            if name not in result.forms:
                result.forms.append(name)
            if key not in result.flows and len(result.flows) < MAX_FLOWS_LISTED:
                result.flows.append(key)
            if len(result.where) < MAX_EXAMPLES:
                result.where.append(f"{where} ({hits}x{'' if view == 'raw' else ', ' + view}{'' if form == 'raw' else ', ' + form})")

    connections = set()
    for seg in segments:
        report.payload_bytes += len(seg.payload)
        if seg.payload:
            search(seg.payload, "raw", f"one packet {seg.src}:{seg.sport} -> {seg.dst}:{seg.dport}", flow_key(seg.src, seg.sport, seg.dst, seg.dport), "packet")
        low, high = sorted([(seg.src, seg.sport), (seg.dst, seg.dport)])
        connections.add((low, high))
    report.flows = len(connections)

    def service_ports(a: int, b: int) -> set:
        # with a --ports filter: the filtered ports of this connection; without: the lower port is the service, the other an ephemeral one
        return {p for p in (a, b) if p in wanted} if wanted is not None else {min(a, b)}

    for low, high in connections:
        for port in service_ports(low[1], high[1]):
            report.ports.setdefault(port, {"flows": 0, "payload_bytes": 0})["flows"] += 1
    server_hellos: list = []
    table: dict = {}  # flow_key -> the row of flow_table
    for (src, sport, dst, dport), segs in flows.items():
        chunks, problems = reassemble_checked(segs, flows.get((dst, dport, src, sport), ()))
        if (dst, dport, src, sport) not in flows and any(seg.has_ack and seg.ack for seg in segs):
            problems.append("direction_missing")   # these segments acknowledge bytes of the other direction, which is not in the capture at all (an ack number of 0 is a hand-built frame's)
        label = f"{src}:{sport} -> {dst}:{dport}"
        key = flow_key(src, sport, dst, dport)
        for port in service_ports(sport, dport):
            report.ports[port]["payload_bytes"] += sum(len(c) for c in chunks)
        for problem in problems:
            if problem == "no_syn" and allow_midflow:
                continue
            report.incomplete.append({"where": label, "reason": problem})
        for chunk in chunks:
            search(chunk, "raw", f"stream {label}", key, "stream")
            if forms:
                for view, blob in derived_views(chunk):
                    search(blob, view, f"stream {label}", key, "stream")
        row = table.setdefault(key, {"flow": key, "client": None, "server": None, "sni": None, "tls": None, "alert": None, "offered": None,
                                     "bytes": {}, "tls_records": {}, "server_port": min(sport, dport)})
        row["bytes"][f"{src}:{sport}"] = sum(len(c) for c in chunks)
        if chunks:
            head = chunks[0]
            counts = tls_records(head)
            if counts:
                report.tls_flows += 1
                for k, v in counts.items():
                    report.tls_records[k] = report.tls_records.get(k, 0) + v
                    row["tls_records"][k] = row["tls_records"].get(k, 0) + v
                sni = client_hello_sni(head)
                if sni:
                    report.sni_names[sni] = report.sni_names.get(sni, 0) + 1
                    row["sni"], row["client"], row["server"] = sni, f"{src}:{sport}", f"{dst}:{dport}"
                seen = read_hello(head, label, report, server_hellos)
                row["offered"] = seen.get("client") or row["offered"]
                row["tls"] = seen.get("server") or row["tls"]
                row["alert"] = seen.get("alert") or row["alert"]
            elif len(report.non_tls_flows) < 10:
                report.non_tls_flows.append({"flow": label, "first_bytes": printable(head, hide=hide)})
    for dgram in datagrams:
        key = flow_key(dgram.src, dgram.sport, dgram.dst, dgram.dport)
        where = f"datagram {dgram.src}:{dgram.sport} -> {dgram.dst}:{dgram.dport}"
        search(dgram.payload, "raw", where, key, "packet")
        if UDP_DNS_PORT in (dgram.sport, dgram.dport):
            for dns_name in dns_names(dgram.payload):
                report.dns_names[dns_name] = report.dns_names.get(dns_name, 0) + 1
                if forms:
                    search(dns_name.replace(".", "").encode("ascii", errors="replace"), "dns-labels", where, key, "packet")
                    search(dns_name.encode("ascii", errors="replace"), "dns-name", where, key, "packet")
    report.flow_table = sorted(table.values(), key=lambda row: row["flow"])[:MAX_FLOWS_LISTED]
    report.tls_summary = tls_policy().summarize(server_hellos)
    if truncated:
        report.incomplete.append({"where": "capture file", "reason": "the last record of the file is cut"})
    if snapped:
        report.incomplete.append({"where": "capture file", "reason": f"{snapped} packet(s) were cut by the snap length"})
    for where, reason in stats_problems(report.stats, len(frames)):
        report.incomplete.append({"where": where, "reason": reason})
    report.markers = results
    return report


def analyse_file(path: Path, markers: Sequence[str] = (), **kwargs) -> PcapReport:
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise PcapError(f"cannot read {path}: {exc.strerror or exc}") from None
    return analyse(data, markers, name=str(path), **kwargs)


def describe(report: PcapReport) -> list:
    """Human lines: the verdict first, then the evidence."""
    lines = [f"CAPTURE {report.verdict}: " + {
        "CLEAN": f"{len(report.markers)} marker(s)" + (" (secrets included, never shown)" if any(m.secret for m in report.markers) else "") + f" searched in {report.payload_bytes} payload bytes (raw file, every packet, every "
                 f"reassembled stream): none found",
        "FOUND": "a marker (or a secret) crossed the capture point in the clear",
        "NO-TRAFFIC": f"no TCP payload was captured ({report.payload_bytes} bytes < {report.min_bytes}): the absence of a marker proves nothing",
        "NO-MARKERS": "no marker was given, so nothing was searched for",
        "INCOMPLETE": f"the capture lost part of the traffic ({len(report.incomplete)} finding(s) below): a marker could have been in the part that is missing, "
                      f"so it proves nothing",
    }[report.verdict], "  " + report.summary()]
    for finding in report.incomplete[:10]:
        lines.append(f"  incomplete: {finding['where']}: {finding['reason']}")
    for result in report.markers:
        state = "FOUND" if result.found else "absent"
        lines.append(f"  marker {result.marker!r}: {state} (raw file {result.raw_hits}, packets {result.packet_hits}, "
                     f"streams {result.stream_hits})" + (f" as {', '.join(result.forms)}" if result.forms else "") + ("; " + "; ".join(result.where) if result.where else ""))
    for hello in report.server_hellos:
        lines.append(f"  ServerHello {hello['flow']}: {hello['version']} {hello['cipher']} group {hello['group']}" + (" (hello retry request)" if hello["hello_retry_request"] else ""))
    for alert in report.alerts:
        lines.append(f"  alert {alert['flow']}: {alert['alert']}")
    for row in report.flow_table:
        if row["tls"]:
            lines.append(f"  flow {row['flow']}: SNI {row['sni'] or '-'}, {row['tls']['version']} {row['tls']['cipher']} group {row['tls']['group']}")
    for flow in report.non_tls_flows:
        lines.append(f"  flow that does not start like TLS: {flow['flow']} first bytes {flow['first_bytes']!r}")
    return lines


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("file", type=Path)
    parser.add_argument("--marker", action="append", default=[], help="plaintext marker to look for (repeatable)")
    parser.add_argument("--ports", default="", help="only flows that use one of these TCP ports (default: all TCP)")
    parser.add_argument("--min-bytes", type=int, default=1, help="TCP payload bytes the capture must hold to count as traffic")
    parser.add_argument("--tcpdump-log", type=Path, help="what tcpdump printed when it ended (its packet counters): kernel drops make the capture INCOMPLETE")
    parser.add_argument("--allow-midflow", action="store_true", help="accept flows whose handshake is not in the capture (a capture that was already running)")
    parser.add_argument("--exact", action="store_true", help="search the marker as it is only, not in its encoded forms (base64, hex, case, unwrapped records, inflated streams)")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        ports = [int(p) for p in args.ports.split(",") if p.strip()]
        stats = parse_tcpdump_stats(args.tcpdump_log.read_text(errors="replace")) if args.tcpdump_log else None
        report = analyse_file(args.file, args.marker, ports=ports or None, min_bytes=args.min_bytes, forms=not args.exact, stats=stats, allow_midflow=args.allow_midflow)
    except (PcapError, ValueError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report.to_dict(), indent=2) if args.json else "\n".join(describe(report)))
    return report.exit_code


if __name__ == "__main__":
    sys.exit(main())

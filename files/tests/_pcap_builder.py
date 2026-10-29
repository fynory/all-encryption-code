"""Builds classic pcap files for the pcap test suite and the capture test suite: Ethernet, Linux cooked v2 and raw-IP frames, IPv4 and
IPv6, TCP conversations whose segments can be split anywhere (a marker split across two packets), a REAL TLS ClientHello (made by Python's
ssl module through memory BIOs, so the SNI parser reads what a browser sends), and TLS application-data records that look like the real thing
(a record header, then random bytes: the analyser only reads headers and searches bytes). Checksums are zero: nothing here verifies them."""
from __future__ import annotations

import os
import socket
import ssl
import struct

ETHERNET, RAW, SLL2 = 1, 101, 276
SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01


def _ip4(src: str, dst: str, payload: bytes) -> bytes:
    header = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0x4000, 64, 6, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return header + payload


def _ip6(src: str, dst: str, payload: bytes) -> bytes:
    header = struct.pack(">IHBB16s16s", 0x60000000, len(payload), 6, 64, socket.inet_pton(socket.AF_INET6, src), socket.inet_pton(socket.AF_INET6, dst))
    return header + payload


def tcp_frame(src: str, sport: int, dst: str, dport: int, seq: int, flags: int, payload: bytes = b"", *, link: int = ETHERNET) -> bytes:
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, 0, 5 << 4, flags, 65535, 0, 0) + payload
    v6 = ":" in src
    ip = _ip6(src, dst, tcp) if v6 else _ip4(src, dst, tcp)
    kind = 0x86DD if v6 else 0x0800
    if link == ETHERNET:
        return b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + struct.pack(">H", kind) + ip
    if link == SLL2:
        return struct.pack(">HHIHBB8s", kind, 0, 1, 1, 0, 6, b"\x02\x00\x00\x00\x00\x01\x00\x00") + ip
    return ip


def pcap_file(frames: list, link: int = ETHERNET, endian: str = "<", nano: bool = False) -> bytes:
    magic = {("<", False): b"\xd4\xc3\xb2\xa1", (">", False): b"\xa1\xb2\xc3\xd4", ("<", True): b"\x4d\x3c\xb2\xa1", (">", True): b"\xa1\xb2\x3c\x4d"}[(endian, nano)]
    out = bytearray(magic + struct.pack(endian + "HHIIII", 2, 4, 0, 0, 262144, link))
    for index, frame in enumerate(frames):
        out += struct.pack(endian + "IIII", 1700000000 + index, 0, len(frame), len(frame)) + frame
    return bytes(out)


class Conversation:
    """One TCP connection, client -> server, with a handshake and segments cut wherever the test says."""

    def __init__(self, client=("203.0.113.9", 51000), server=("10.120.1.4", 443), *, link: int = ETHERNET, c_seq: int = 1000, s_seq: int = 9000):
        self.client, self.server, self.link = client, server, link
        self.c_seq, self.s_seq = c_seq, s_seq
        self.frames: list = []

    def _frame(self, from_client: bool, flags: int, payload: bytes = b"") -> None:
        src, dst = (self.client, self.server) if from_client else (self.server, self.client)
        seq = self.c_seq if from_client else self.s_seq
        self.frames.append(tcp_frame(src[0], src[1], dst[0], dst[1], seq, flags, payload, link=self.link))
        consumed = len(payload) + (1 if flags & (SYN | FIN) else 0)
        if from_client:
            self.c_seq += consumed
        else:
            self.s_seq += consumed

    def handshake(self) -> "Conversation":
        self._frame(True, SYN)
        self._frame(False, SYN | ACK)
        self._frame(True, ACK)
        return self

    def send(self, data: bytes, *, from_client: bool = True, cuts: tuple = ()) -> "Conversation":
        """Sends data in segments cut at the given offsets (default: one segment per 1400 bytes)."""
        points = sorted(set(cuts)) or list(range(1400, len(data), 1400))
        start = 0
        for point in [*points, len(data)]:
            if point > start:
                self._frame(from_client, PSH | ACK, data[start:point])
                start = point
        return self

    def reorder(self, first: int, second: int) -> "Conversation":
        self.frames[first], self.frames[second] = self.frames[second], self.frames[first]
        return self

    def duplicate(self, index: int) -> "Conversation":
        self.frames.append(self.frames[index])
        return self

    def pcap(self, **kwargs) -> bytes:
        return pcap_file(self.frames, self.link, **kwargs)


def client_hello(server_name: str) -> bytes:
    """The first flight of a real TLS client (Python's ssl through memory BIOs) for the given SNI name."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = context.wrap_bio(incoming, outgoing, server_hostname=server_name)
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


def app_data_records(total: int, *, avoid: tuple = ()) -> bytes:
    """TLS 1.2-style application-data records (type 23) of random bytes, `total` bytes of ciphertext in all."""
    out = bytearray()
    remaining = total
    while remaining > 0:
        size = min(remaining, 1200)
        while True:
            body = os.urandom(size)
            if not any(marker in body for marker in avoid):
                break
        out += b"\x17\x03\x03" + struct.pack(">H", size) + body
        remaining -= size
    return bytes(out)

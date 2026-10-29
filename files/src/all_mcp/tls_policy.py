"""The TLS policy of the ALL 2.0 terminator and the proof of what it can honestly claim (plan sections 2, 3 and 7; WP16).

Three things live here, and nothing else in the device decides them:

  * **The server context.** TLS 1.3 at least, ALPN ``http/1.1`` (the two words come from ``policy.terminator``), the certificate the generation names. The terminator
    refuses to start in exactly one case: the Python has no TLS 1.3 (``TlsUnavailable``, closed word ``tls13_required``). That is a reported ``degraded`` state
    (e2e_status, the tray, the heartbeat), never a silent fallback. The OpenSSL version does not stop anything: it is reported per operating system and it gates
    ONE claim, the hybrid key exchange (OpenSSL 3.5 brings X25519MLKEM768; an older one serves X25519 and says nothing about hybrid).
  * **A parser of the TLS hellos that cross the wire in the clear** (``parse_client_hello``, ``observe_server``): version, cipher suite and the group the server
    selected, read from the ServerHello bytes themselves, so a node observer, a pcap and the blindness gate (WP23) all read the same thing, and nothing depends on
    what Python's ``ssl`` module is willing to tell. It follows a hello across records and across TCP segments, a HelloRetryRequest and an alert; malformed bytes are
    ``TlsParseError`` with a closed word, never an ``IndexError``.
  * **The capability report** (``capability_report``): real loopback handshakes against the real server context (a client that offers hybrid, one that does not,
    one that speaks only TLS 1.2), and from what they showed, exactly which claims this operating system can prove. It is the JSON that feeds ``e2e-proof.json`` and the
    TLS sentences of the site (WP27): a sentence that is not in ``allowed_claims`` is not written.

``OPENSSL_CONF`` (the installer's OpenSSL config file) restricts the key-exchange groups and orders the TLS 1.3 suites. It was evaluated against the relay process and is
OFF by default: it is a process-wide setting, and a restricted list refuses a peer that offers only a group left out (a test shows one). It can be
turned on for the supervised e2e child alone (``runtime.env`` word ``ALL_E2E_OPENSSL_CONF=on``, ``apply_openssl_conf``), never for the relay process, and a runtime that
ignores it is detected (``openssl_conf_effective``) instead of trusted.

    python -m all_mcp.tls_policy report [--out FILE] [--no-probe]     # the per-OS report of this computer, JSON on stdout
"""
from __future__ import annotations

import argparse
import contextlib
import datetime
import json
import logging
import os
import platform
import queue
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from . import e2e_policy as policy
from .windows_console import hide_child_consoles, no_window_flags

log = logging.getLogger("all_mcp.tls_policy")

REPORT_VERSION = 1
TLS_13, TLS_12 = 0x0304, 0x0303
# Registry values (IANA TLS parameters), not policy: what a hello carries on the wire.
GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1, GROUP_SECP521R1 = 0x001D, 0x0017, 0x0018, 0x0019
GROUP_X25519_MLKEM768, GROUP_SECP256R1_MLKEM768, GROUP_X25519_KYBER768_DRAFT = 0x11EC, 0x11EB, 0x6399
HYBRID_GROUPS = frozenset({GROUP_X25519_MLKEM768, GROUP_SECP256R1_MLKEM768, GROUP_X25519_KYBER768_DRAFT})
GROUP_NAMES = {
    GROUP_X25519: "X25519", GROUP_SECP256R1: "secp256r1", GROUP_SECP384R1: "secp384r1", GROUP_SECP521R1: "secp521r1", 0x001E: "X448",
    0x0100: "ffdhe2048", 0x0101: "ffdhe3072", 0x0102: "ffdhe4096", GROUP_X25519_MLKEM768: "X25519MLKEM768", GROUP_SECP256R1_MLKEM768: "SecP256r1MLKEM768",
    GROUP_X25519_KYBER768_DRAFT: "X25519Kyber768Draft00",
}
CIPHER_NAMES = {
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384", 0x1303: "TLS_CHACHA20_POLY1305_SHA256", 0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
}
ALERT_NAMES = {
    0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 40: "handshake_failure", 42: "bad_certificate", 47: "illegal_parameter",
    70: "protocol_version", 71: "insufficient_security", 80: "internal_error", 86: "inappropriate_fallback", 90: "user_canceled", 109: "missing_extension",
    112: "unrecognized_name", 120: "no_application_protocol",
}
VERSION_NAMES = {0x0304: "TLSv1.3", 0x0303: "TLSv1.2", 0x0302: "TLSv1.1", 0x0301: "TLSv1.0", 0x0300: "SSLv3"}
HELLO_RETRY_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")   # RFC 8446 section 4.1.3: SHA-256("HelloRetryRequest")
EXT_SERVER_NAME, EXT_SUPPORTED_GROUPS, EXT_ALPN, EXT_SUPPORTED_VERSIONS, EXT_KEY_SHARE, EXT_ECH = 0, 10, 16, 43, 51, 0xFE0D
RECORD_HANDSHAKE, RECORD_ALERT, RECORD_CCS, RECORD_APPLICATION = 22, 21, 20, 23
RECORD_HEADER_BYTES = 5
RECORD_MAX_BYTES = 16384 + 2048        # a handshake record is at most 2^14 (the field allows more only for ciphertext); the slack is for sloppy senders
HELLO_MAX_BYTES = 1 << 17              # the largest hello that is read: a ClientHello offering X25519MLKEM768 is about 1.5 KB, 128 KB is already abuse
# The OpenSSL that brings X25519MLKEM768 in its default groups; the one number of this file that is a fact about a library, not a choice of ours.
HYBRID_MIN_OPENSSL = (3, 5)
PROBE_NAME = "probe.all.invalid"
PROBE_SECONDS = 20.0
PROBE_ROUNDS = 16
# The claims this module can prove, in the order the report lists them, and the one sentence of evidence each needs. A claim not in this table is never written.
CLAIMS = {
    "tls_1_3_minimum": "the terminator's context refuses below TLS 1.3 and a loopback handshake negotiated TLS 1.3",
    "tls_1_2_refused": "a client that speaks only TLS 1.2 was refused with an alert",
    "alpn_http_1_1": "a client that offered http/1.1 was given http/1.1",
    "forward_secrecy": "the ServerHello selected an ephemeral key-exchange group (TLS 1.3 has no static one)",
    "classical_fallback": "a client that offers no hybrid group still completed the handshake (X25519 or another classical group)",
    "hybrid_x25519mlkem768": "OpenSSL 3.5 or later AND a client that offered X25519MLKEM768 was answered with X25519MLKEM768",
}
# What no loopback report can prove, with the reason (the plan's section 10): they wait for the gate's real captures or are never true.
NEVER_CLAIMED = {
    "post_quantum_with_chatgpt": "needs the node counters of a real ChatGPT that negotiated 0x11EC (G1); a loopback client is not ChatGPT",
    "aes_256_only": "the client chooses the suite: ChatGPT may pick AES-128-GCM or ChaCha20",
    "tls_1_3_always": "only what the gate proves per system; the other end decides what it offers",
    "ech": "no Encrypted Client Hello: the node reads the SNI by design",
}
STATES = ("ready", "degraded")

# The switch of the OPENSSL_CONF restriction: a word of runtime.env that only the supervised e2e child honours. Absent means off.
OPENSSL_CONF_SWITCH = "ALL_E2E_OPENSSL_CONF"
OPENSSL_CONF_FILE = "openssl-all.cnf"
OPENSSL_CONF_DEFAULT_ON = False
ON_WORDS = frozenset({"on", "1", "true", "yes"})
# The groups the restricted list offers: hybrid first where the library knows it ("?" skips a name an older OpenSSL does not know), then the classical groups every
# TLS 1.3 peer of ours speaks. The TLS 1.3 suites are the three every OpenSSL has, ChaCha20 last so that a machine with AES hardware keeps its choice.
OPENSSL_CONF_GROUPS = "?X25519MLKEM768:X25519:secp256r1:secp384r1"
OPENSSL_CONF_SUITES = "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256"


class TlsParseError(ValueError):
    """The bytes are not a TLS hello. ``word`` is a closed word (``bad_record``, ``bad_hello``, ``bad_extension``, ``too_large``, ``not_handshake``)."""

    def __init__(self, word: str):
        super().__init__(word)
        self.word = word


class TlsUnavailable(RuntimeError):
    """The terminator cannot serve: this Python has no TLS 1.3. ``word`` is what the status file and the heartbeat carry."""

    def __init__(self, word: str = "tls13_required"):
        super().__init__(word)
        self.word = word


# ------------------------------------------------------------------------------------------------------------------------ names

def is_grease(value: int) -> bool:
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


def group_name(group: int | None) -> str | None:
    if group is None:
        return None
    return "grease" if is_grease(group) else GROUP_NAMES.get(group, f"0x{group:04x}")


def cipher_name(cipher: int | None) -> str | None:
    if cipher is None:
        return None
    return "grease" if is_grease(cipher) else CIPHER_NAMES.get(cipher, f"0x{cipher:04x}")


def version_name(version: int | None) -> str | None:
    return None if version is None else VERSION_NAMES.get(version, f"0x{version:04x}")


# ------------------------------------------------------------------------------------------------------------------------ the hello parser

@dataclass(frozen=True)
class ClientHelloInfo:
    """What a ClientHello says in the clear. ``key_share_groups`` are the groups it actually sent a key for (the server can choose only among those without a retry)."""
    versions: tuple[int, ...]
    cipher_suites: tuple[int, ...]
    groups: tuple[int, ...]
    key_share_groups: tuple[int, ...]
    server_name: str | None
    alpn: tuple[str, ...]
    extensions: tuple[int, ...]
    records: int

    @property
    def offers_tls13(self) -> bool:
        return TLS_13 in self.versions

    @property
    def offers_hybrid(self) -> bool:
        return any(group in HYBRID_GROUPS for group in self.groups)

    @property
    def sends_hybrid_key_share(self) -> bool:
        return any(group in HYBRID_GROUPS for group in self.key_share_groups)

    def as_dict(self) -> dict[str, Any]:
        return {"versions": [version_name(v) for v in self.versions if not is_grease(v)], "offers_hybrid": self.offers_hybrid,
                "sends_hybrid_key_share": self.sends_hybrid_key_share, "groups": [group_name(g) for g in self.groups if not is_grease(g)],
                "key_share_groups": [group_name(g) for g in self.key_share_groups if not is_grease(g)],
                "cipher_suites": [cipher_name(c) for c in self.cipher_suites if not is_grease(c)], "server_name": self.server_name, "alpn": list(self.alpn),
                "ech": EXT_ECH in self.extensions, "records": self.records}


@dataclass(frozen=True)
class ServerHelloInfo:
    """The ServerHello (or the HelloRetryRequest): the negotiated version, the suite and the group the server selected. In TLS 1.3 the version is the
    ``supported_versions`` extension, the legacy field of the hello says 1.2 for every handshake; ``group`` is None for TLS 1.2 (its curve is in a later message)."""
    version: int
    cipher: int
    group: int | None
    hello_retry_request: bool
    extensions: tuple[int, ...]
    records: int

    @property
    def version_name(self) -> str | None:
        return version_name(self.version)

    @property
    def cipher_name(self) -> str | None:
        return cipher_name(self.cipher)

    @property
    def group_name(self) -> str | None:
        return group_name(self.group)

    @property
    def hybrid(self) -> bool:
        return self.group in HYBRID_GROUPS

    def as_dict(self) -> dict[str, Any]:
        return {"version": self.version_name, "cipher": self.cipher_name, "group": self.group_name, "group_id": self.group,
                "hybrid": self.hybrid, "hello_retry_request": self.hello_retry_request}


@dataclass(frozen=True)
class TlsAlert:
    level: int
    description: int

    @property
    def name(self) -> str:
        return ALERT_NAMES.get(self.description, f"alert_{self.description}")


@dataclass(frozen=True)
class ServerObservation:
    """What the server side of a connection said before it went encrypted: the hellos (a retry request, then the real one), an alert if it refused, and whether
    the stream held enough to be sure (``complete`` is False while a record or a message is cut: read more bytes and ask again)."""
    hellos: tuple[ServerHelloInfo, ...] = ()
    alert: TlsAlert | None = None
    complete: bool = False

    @property
    def negotiated(self) -> ServerHelloInfo | None:
        """The hello that settled the handshake: the last one that is not a retry request (or the retry request when nothing followed it)."""
        real = [hello for hello in self.hellos if not hello.hello_retry_request]
        return real[-1] if real else (self.hellos[-1] if self.hellos else None)


def _read_records(stream: bytes) -> list[tuple[int, bytes]]:
    """The whole TLS records at the start of `stream` as (type, body); a record that is still arriving is left out. Stops at the first encrypted record: everything
    after the hello of a TLS 1.3 handshake is ciphertext."""
    records: list[tuple[int, bytes]] = []
    offset = 0
    while offset + RECORD_HEADER_BYTES <= len(stream):
        kind, major, length = stream[offset], stream[offset + 1], struct.unpack_from(">H", stream, offset + 3)[0]
        if kind not in (RECORD_HANDSHAKE, RECORD_ALERT, RECORD_CCS, RECORD_APPLICATION) or major != 3 or length > RECORD_MAX_BYTES or length == 0:
            raise TlsParseError("bad_record")
        if offset + RECORD_HEADER_BYTES + length > len(stream):
            break
        records.append((kind, stream[offset + RECORD_HEADER_BYTES:offset + RECORD_HEADER_BYTES + length]))
        offset += RECORD_HEADER_BYTES + length
        if kind == RECORD_APPLICATION:
            break
    return records


def _handshake_messages(stream: bytes, *, server: bool = False) -> tuple[list[tuple[int, bytes, int]], TlsAlert | None, bool]:
    """The handshake messages (type, body, records they span) of the clear part of `stream`, rebuilt across records: one message may be cut into several records and
    one record may hold several messages. Returns them with the alert (if a record was an alert) and whether the last message is whole.

    The clear part ends at the first change_cipher_spec: after it a TLS 1.2 handshake is encrypted (its Finished is still a "handshake" record), and a TLS 1.3 client
    or server sends it only for middleboxes, followed by ciphertext. The one exception is a server that answered with a HelloRetryRequest: its real ServerHello comes
    after that record, in the clear, once the client has sent its second hello."""
    messages: list[tuple[int, bytes, int]] = []
    pending = bytearray()
    spans = 0
    alert: TlsAlert | None = None
    for kind, body in _read_records(stream):
        if kind == RECORD_ALERT:
            if len(body) >= 2 and alert is None:
                alert = TlsAlert(body[0], body[1])
            continue
        if kind == RECORD_CCS:
            if server and not pending and messages and messages[-1][0] == 2 and messages[-1][1][2:34] == HELLO_RETRY_RANDOM:
                continue
            break
        if kind != RECORD_HANDSHAKE:
            break
        pending += body
        spans += 1
        while len(pending) >= 4:
            if server and pending[0] != 2:   # what follows a ServerHello in TLS 1.2 (a certificate chain, say) is not read: it may be large and it is not ours
                messages.append((pending[0], b"", spans))
                return messages, alert, True
            size = int.from_bytes(pending[1:4], "big")
            if size > HELLO_MAX_BYTES:
                raise TlsParseError("too_large")
            if len(pending) < 4 + size:
                break
            messages.append((pending[0], bytes(pending[4:4 + size]), spans))
            del pending[:4 + size]
            spans = 1 if pending else 0
    return messages, alert, not pending


def _take(data: bytes, offset: int, size: int) -> tuple[bytes, int]:
    if size < 0 or offset + size > len(data):
        raise TlsParseError("bad_hello")
    return data[offset:offset + size], offset + size


def _extensions(block: bytes) -> list[tuple[int, bytes]]:
    out: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(block):
        header, offset = _take(block, offset, 4)
        kind, size = struct.unpack(">HH", header)
        data, offset = _take(block, offset, size)
        out.append((kind, data))
    return out


def _u16_list(data: bytes, *, width: int = 2) -> tuple[int, ...]:
    """A length-prefixed list of 16-bit values (the prefix is `width` bytes: 1 for supported_versions, 2 for supported_groups)."""
    if len(data) < width or int.from_bytes(data[:width], "big") != len(data) - width or (len(data) - width) % 2:
        raise TlsParseError("bad_extension")
    body = data[width:]
    return struct.unpack(">" + "H" * (len(body) // 2), body)


def _hello_prefix(body: bytes) -> tuple[int, bytes, int]:
    """(legacy version, random, offset after the session id) of a Client or Server hello."""
    head, offset = _take(body, 0, 34)
    version, random = struct.unpack(">H", head[:2])[0], head[2:34]
    size = _take(body, offset, 1)[0][0]
    _, offset = _take(body, offset + 1, size)
    return version, random, offset


def _client_hello(body: bytes, records: int) -> ClientHelloInfo:
    _, _, offset = _hello_prefix(body)
    size, offset = _take(body, offset, 2)
    suites_raw, offset = _take(body, offset, struct.unpack(">H", size)[0])
    if len(suites_raw) % 2:
        raise TlsParseError("bad_hello")
    skip, offset = _take(body, offset, 1)
    _, offset = _take(body, offset, skip[0])
    versions: tuple[int, ...] = ()
    groups: tuple[int, ...] = ()
    shares: list[int] = []
    name: str | None = None
    alpn: list[str] = []
    kinds: list[int] = []
    if offset < len(body):
        size, offset = _take(body, offset, 2)
        block, offset = _take(body, offset, struct.unpack(">H", size)[0])
        for kind, data in _extensions(block):
            kinds.append(kind)
            if kind == EXT_SUPPORTED_VERSIONS:
                versions = _u16_list(data, width=1)
            elif kind == EXT_SUPPORTED_GROUPS:
                groups = _u16_list(data)
            elif kind == EXT_KEY_SHARE:
                if len(data) < 2 or struct.unpack_from(">H", data, 0)[0] != len(data) - 2:
                    raise TlsParseError("bad_extension")
                position = 2
                while position < len(data):
                    entry, position = _take(data, position, 4)
                    group, key_size = struct.unpack(">HH", entry)
                    _, position = _take(data, position, key_size)
                    shares.append(group)
            elif kind == EXT_SERVER_NAME:
                if len(data) >= 5 and data[2] == 0:
                    raw, _ = _take(data, 5, struct.unpack_from(">H", data, 3)[0])
                    name = raw.decode("ascii", errors="replace")
            elif kind == EXT_ALPN:
                if len(data) < 2 or struct.unpack_from(">H", data, 0)[0] != len(data) - 2:
                    raise TlsParseError("bad_extension")
                position = 2
                while position < len(data):
                    item, position = _take(data, position + 1, data[position])
                    alpn.append(item.decode("ascii", errors="replace"))
    return ClientHelloInfo(versions=versions, cipher_suites=struct.unpack(">" + "H" * (len(suites_raw) // 2), suites_raw), groups=groups,
                           key_share_groups=tuple(shares), server_name=name, alpn=tuple(alpn), extensions=tuple(kinds), records=records)


def _server_hello(body: bytes, records: int) -> ServerHelloInfo:
    legacy, random, offset = _hello_prefix(body)
    head, offset = _take(body, offset, 3)
    cipher = struct.unpack(">H", head[:2])[0]
    version, group = legacy, None
    kinds: list[int] = []
    retry = random == HELLO_RETRY_RANDOM
    if offset < len(body):
        size, offset = _take(body, offset, 2)
        block, offset = _take(body, offset, struct.unpack(">H", size)[0])
        for kind, data in _extensions(block):
            kinds.append(kind)
            if kind == EXT_SUPPORTED_VERSIONS:
                if len(data) != 2:
                    raise TlsParseError("bad_extension")
                version = struct.unpack(">H", data)[0]
            elif kind == EXT_KEY_SHARE:
                # ServerHello: a KeyShareEntry (group, length, key); HelloRetryRequest: only the group it wants
                if len(data) < 2 or (not retry and len(data) < 4):
                    raise TlsParseError("bad_extension")
                group = struct.unpack_from(">H", data, 0)[0]
                if not retry and struct.unpack_from(">H", data, 2)[0] != len(data) - 4:
                    raise TlsParseError("bad_extension")
    return ServerHelloInfo(version=version, cipher=cipher, group=group, hello_retry_request=retry, extensions=tuple(kinds), records=records)


def parse_client_hello(stream: bytes) -> ClientHelloInfo | None:
    """The ClientHello that starts `stream` (the client's bytes of one TCP connection, reassembled), or None while it is not whole yet. A hello may be cut across any
    number of records and segments; anything that is not a ClientHello is ``TlsParseError``."""
    messages, _alert, _clean = _handshake_messages(stream)
    if not messages:
        if len(stream) >= RECORD_HEADER_BYTES and stream[0] != RECORD_HANDSHAKE:
            raise TlsParseError("not_handshake")
        return None
    kind, body, records = messages[0]
    if kind != 1:
        raise TlsParseError("not_handshake")
    return _client_hello(body, records)


def observe_server(stream: bytes) -> ServerObservation:
    """What the server's bytes of one connection say in the clear: its ServerHello (and a HelloRetryRequest before it), or the alert it answered with."""
    messages, alert, clean = _handshake_messages(stream, server=True)
    hellos = tuple(_server_hello(body, records) for kind, body, records in messages if kind == 2)
    if messages and messages[0][0] != 2:
        raise TlsParseError("not_handshake")
    if not messages and alert is None and len(stream) >= RECORD_HEADER_BYTES and stream[0] not in (RECORD_HANDSHAKE, RECORD_ALERT):
        raise TlsParseError("not_handshake")
    return ServerObservation(hellos=hellos, alert=alert, complete=bool(hellos or alert) and clean)


def parse_server_hello(stream: bytes) -> ServerHelloInfo | None:
    """The ServerHello that settled the handshake (see ``ServerObservation.negotiated``), or None while it is not whole or when the server answered with an alert."""
    return observe_server(stream).negotiated


def summarize(hellos: Sequence[ServerHelloInfo]) -> dict[str, dict[str, int]]:
    """Counts of version, suite and group over many ServerHellos (a capture, a node's counters): the three tables ``e2e-proof.json`` carries."""
    out: dict[str, dict[str, int]] = {"versions": {}, "ciphers": {}, "groups": {}}
    for hello in hellos:
        if hello.hello_retry_request:
            continue
        for table, word in (("versions", hello.version_name), ("ciphers", hello.cipher_name), ("groups", hello.group_name or "none")):
            out[table][word or "unknown"] = out[table].get(word or "unknown", 0) + 1
    return out


# ------------------------------------------------------------------------------------------------------------------------ the runtime and the server context

@dataclass(frozen=True)
class Runtime:
    """What this Python's TLS library is: reported per operating system, tying the hybrid claim to the OpenSSL that carries it."""
    openssl: str
    openssl_info: tuple[int, ...]
    flavor: str
    has_tls13: bool
    python: str
    system: str
    release: str
    machine: str

    @classmethod
    def current(cls) -> "Runtime":
        text = getattr(ssl, "OPENSSL_VERSION", "")
        flavor = "libressl" if "LibreSSL" in text else "openssl" if text.startswith("OpenSSL") else "other"
        has13 = bool(getattr(ssl, "HAS_TLSv1_3", False)) and hasattr(ssl.TLSVersion, "TLSv1_3")
        return cls(openssl=text, openssl_info=tuple(getattr(ssl, "OPENSSL_VERSION_INFO", ())[:3]), flavor=flavor, has_tls13=has13,
                   python=platform.python_version(), system=platform.system(), release=platform.release(), machine=platform.machine())

    @property
    def hybrid_capable(self) -> bool:
        """OpenSSL 3.5 or later: the only library family that ships X25519MLKEM768 in its defaults. This is the gate of the hybrid claim, nothing more."""
        return self.flavor == "openssl" and tuple(self.openssl_info[:2]) >= HYBRID_MIN_OPENSSL

    def as_dict(self) -> dict[str, Any]:
        return {"os": {"system": self.system, "release": self.release, "machine": self.machine}, "python": self.python,
                "openssl": {"version": self.openssl, "version_info": list(self.openssl_info), "flavor": self.flavor, "has_tls13": self.has_tls13,
                            "hybrid_capable": self.hybrid_capable}}


def tls13_available(runtime: Runtime | None = None) -> bool:
    return (runtime or Runtime.current()).has_tls13


def require_tls13(runtime: Runtime | None = None) -> None:
    """The one condition the terminator refuses to start on. The caller reports it (status ``degraded``, reason ``tls13_required``); this is never swallowed."""
    if not tls13_available(runtime):
        log.error("this Python's TLS library has no TLS 1.3: the encrypted path cannot serve (%s)", (runtime or Runtime.current()).openssl)
        raise TlsUnavailable("tls13_required")


def start_decision(runtime: Runtime | None = None) -> dict[str, str]:
    """May the terminator start here, as the status file says it: ``ready`` or ``degraded`` with the closed word that says why."""
    if tls13_available(runtime):
        return {"state": "ready", "reason": ""}
    return {"state": "degraded", "reason": "tls13_required"}


_VERSIONS = {"TLSv1.3": "TLSv1_3", "TLSv1.2": "TLSv1_2"}


def minimum_version() -> "ssl.TLSVersion":
    word = policy.value("terminator.tls_min_version")
    if word not in _VERSIONS:
        raise TlsUnavailable("tls13_required")
    return getattr(ssl.TLSVersion, _VERSIONS[word])


def server_context(chain_path: Path | str, key_path: Path | str, *, runtime: Runtime | None = None) -> ssl.SSLContext:
    """The terminator's context for one certificate generation: TLS 1.3 at least, ALPN of the policy, nothing narrower. Raises ``TlsUnavailable`` when the Python
    has no TLS 1.3; every other property of the library (version, hybrid) is reported, not enforced."""
    require_tls13(runtime)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = minimum_version()
    context.set_alpn_protocols([policy.value("terminator.tls_alpn")])
    context.load_cert_chain(str(chain_path), str(key_path))
    return context


# ------------------------------------------------------------------------------------------------------------------------ OPENSSL_CONF

def render_openssl_conf() -> str:
    """The text of the installer's OpenSSL config file: groups and TLS 1.3 suites only. No ``MinProtocol`` (an outbound TLS 1.2 peer, a corporate proxy, must keep working),
    and the hybrid group behind ``?`` so that an OpenSSL that does not know it ignores the name instead of refusing the whole list."""
    return (
        "# ALL 2.0: key-exchange groups and TLS 1.3 suites for the e2e child process. OFF unless runtime.env says ALL_E2E_OPENSSL_CONF=on; see src/all_mcp/tls_policy.py.\n"
        "# Generated by tls_policy.render_openssl_conf(): a test compares this file with it.\n"
        "openssl_conf = all_openssl_init\n\n"
        "[all_openssl_init]\n"
        "ssl_conf = all_ssl\n\n"
        "[all_ssl]\n"
        "system_default = all_tls_defaults\n\n"
        "[all_tls_defaults]\n"
        f"Groups = {OPENSSL_CONF_GROUPS}\n"
        f"Ciphersuites = {OPENSSL_CONF_SUITES}\n"
    )


def openssl_conf_wanted(env: Mapping[str, str]) -> bool:
    word = str(env.get(OPENSSL_CONF_SWITCH, "")).strip().lower()
    return word in ON_WORDS if word else OPENSSL_CONF_DEFAULT_ON


def apply_openssl_conf(env: Mapping[str, str], directory: Path | str | None = None, *, switch: str | None = None) -> dict[str, str]:
    """The environment of the e2e child: a copy of `env`, with ``OPENSSL_CONF`` pointing at the restricted configuration only when it was turned on (`switch`, a
    word of runtime.env, or ``ALL_E2E_OPENSSL_CONF`` in `env`). Off (the default) returns the environment unchanged, so the child behaves as it did without this
    module. A file that cannot be written leaves the environment as it was: a policy nice-to-have never stops the child."""
    out = dict(env)
    wanted = openssl_conf_wanted({OPENSSL_CONF_SWITCH: switch} if switch is not None else out)
    if not wanted or directory is None:
        return out
    try:
        target = Path(directory) / OPENSSL_CONF_FILE
        target.parent.mkdir(parents=True, exist_ok=True)
        text = render_openssl_conf()
        if not target.exists() or target.read_text(encoding="utf-8") != text:
            target.write_text(text, encoding="utf-8")
        out["OPENSSL_CONF"] = str(target)
    except OSError as exc:
        log.warning("the OpenSSL restriction could not be written (%s): the child runs without it", type(exc).__name__)
    return out


# ------------------------------------------------------------------------------------------------------------------------ loopback handshakes

@dataclass(frozen=True)
class ClientProfile:
    """One kind of client for a probe. ``groups`` and ``ciphersuites`` are OpenSSL lists applied to a child process (Python cannot restrict a client's groups
    in-process); a profile without them runs in-process. ``max_version`` is a policy word (``TLSv1.2``)."""
    name: str
    groups: str | None = None
    ciphersuites: str | None = None
    max_version: str | None = None
    alpn: tuple[str, ...] = ("http/1.1",)
    server_name: str = PROBE_NAME

    @property
    def in_process(self) -> bool:
        return self.groups is None and self.ciphersuites is None


HYBRID_CLIENT = ClientProfile("hybrid_client")
CLASSIC_CLIENT = ClientProfile("classic_client", groups="X25519")
TLS12_CLIENT = ClientProfile("tls12_client", max_version="TLSv1.2")


@dataclass
class Handshake:
    """The outcome of one loopback handshake: what each side sent in the clear, parsed, and what the two ends reported themselves."""
    profile: str
    completed: bool = False
    error: str = ""
    client_hello: ClientHelloInfo | None = None
    server: ServerObservation = field(default_factory=ServerObservation)
    python_version: str | None = None       # the server's own view, to cross-check the parser against
    python_cipher: str | None = None
    alpn: str | None = None
    client_error: str = ""
    client_bytes: bytes = b""               # what each side wrote on the wire: a gate turns them into a capture, a test into a hello to cut and mutate
    server_bytes: bytes = b""

    @property
    def negotiated(self) -> ServerHelloInfo | None:
        return self.server.negotiated

    def as_dict(self) -> dict[str, Any]:
        hello = self.negotiated
        out: dict[str, Any] = {"completed": self.completed, "error": self.error, "alpn": self.alpn,
                               "client": self.client_hello.as_dict() if self.client_hello else None,
                               "server": hello.as_dict() if hello and self.completed else None,
                               "alert": self.server.alert.name if self.server.alert else None}
        if hello and self.completed:
            out["consistent"] = (hello.version_name == self.python_version and hello.cipher_name == self.python_cipher)
        return out


class _InProcessClient:
    def __init__(self, profile: ClientProfile):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE   # a loopback probe of our own server with a throw-away certificate: nothing is trusted, nothing is sent
        if profile.max_version:
            context.maximum_version = getattr(ssl.TLSVersion, _VERSIONS[profile.max_version])
        if profile.alpn:
            context.set_alpn_protocols(list(profile.alpn))
        self._in, self._out = ssl.MemoryBIO(), ssl.MemoryBIO()
        self._ssl = context.wrap_bio(self._in, self._out, server_hostname=profile.server_name)
        self.error = ""

    def step(self, data: bytes) -> tuple[bytes, bool]:
        if data:
            self._in.write(data)
        done = False
        try:
            self._ssl.do_handshake()
            done = True
        except ssl.SSLWantReadError:
            pass
        except ssl.SSLError as exc:
            self.error = (getattr(exc, "reason", None) or type(exc).__name__).lower()
            done = True
        return self._out.read(), done

    def close(self) -> None:
        return None


# The child of a probe: a client that reads the server's bytes from stdin and writes its own to stdout, one frame each (4-byte length, a tag, the bytes), so a probe
# needs no port and works inside any sandbox. Tags: D = bytes, a reply is expected; F = the last bytes (no reply), R = the result as JSON.
_CHILD = r"""
import json, ssl, struct, sys
cfg = json.loads(sys.argv[1])
def put(tag, payload):
    sys.stdout.buffer.write(struct.pack(">I", len(payload) + 1) + tag + payload); sys.stdout.buffer.flush()
def get():
    head = sys.stdin.buffer.read(4)
    if len(head) < 4: raise SystemExit(0)
    body = sys.stdin.buffer.read(struct.unpack(">I", head)[0])
    return body[1:]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
if cfg["max_version"]:
    ctx.maximum_version = getattr(ssl.TLSVersion, cfg["max_version"].replace("TLSv1.", "TLSv1_"))
if cfg["alpn"]:
    ctx.set_alpn_protocols(cfg["alpn"])
i, o = ssl.MemoryBIO(), ssl.MemoryBIO()
s = ctx.wrap_bio(i, o, server_hostname=cfg["server_name"])
data = b""
while True:
    if data:
        i.write(data)
    done, err = False, ""
    try:
        s.do_handshake(); done = True
    except ssl.SSLWantReadError:
        pass
    except ssl.SSLError as exc:
        done, err = True, (getattr(exc, "reason", None) or type(exc).__name__).lower()
    out = o.read()
    if done:
        put(b"F", out)
        put(b"R", json.dumps({"error": err}).encode())
        break
    put(b"D", out)
    data = get()
"""


class _ChildClient:
    """A client in a child process whose OpenSSL is configured by a conf file made for the profile (groups, suites): the only way to make a client that does not
    offer a group the library knows. The child is the same interpreter, so the library under test is the one the product ships."""

    def __init__(self, profile: ClientProfile, workdir: Path):
        lines = ["openssl_conf = probe_init", "", "[probe_init]", "ssl_conf = probe_ssl", "", "[probe_ssl]", "system_default = probe_defaults", "", "[probe_defaults]"]
        if profile.groups:
            lines.append(f"Groups = {profile.groups}")
        if profile.ciphersuites:
            lines.append(f"Ciphersuites = {profile.ciphersuites}")
        conf = workdir / f"{profile.name}.cnf"
        conf.write_text("\n".join(lines) + "\n", encoding="utf-8")
        env = {key: value for key, value in os.environ.items() if key != "OPENSSL_CONF"}
        env["OPENSSL_CONF"] = str(conf)
        config = json.dumps({"max_version": profile.max_version, "alpn": list(profile.alpn), "server_name": profile.server_name})
        self._proc = subprocess.Popen([sys.executable, "-I", "-c", _CHILD, config], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                      env=env, creationflags=no_window_flags())
        self._frames: "queue.Queue[tuple[bytes, bytes] | None]" = queue.Queue()
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()
        self.error = ""
        self._first = True

    def _read(self) -> None:
        try:
            stdout = self._proc.stdout
            while stdout is not None:
                head = stdout.read(4)
                if len(head) < 4:
                    break
                body = stdout.read(struct.unpack(">I", head)[0])
                self._frames.put((body[:1], body[1:]))
        except (OSError, ValueError):
            pass
        self._frames.put(None)

    def step(self, data: bytes) -> tuple[bytes, bool]:
        if not self._first:
            try:
                assert self._proc.stdin is not None
                self._proc.stdin.write(struct.pack(">I", len(data) + 1) + b"D" + data)
                self._proc.stdin.flush()
            except (OSError, ValueError):
                return b"", True
        self._first = False
        try:
            frame = self._frames.get(timeout=PROBE_SECONDS)
        except queue.Empty:
            self.error = "probe_timeout"
            return b"", True
        if frame is None:
            self.error = "probe_child_failed"
            return b"", True
        tag, payload = frame
        if tag == b"F":
            tail = self._frames.get(timeout=PROBE_SECONDS)
            if tail is not None and tail[0] == b"R":
                self.error = str(json.loads(tail[1].decode("utf-8")).get("error", ""))
            return payload, True
        return payload, False

    def close(self) -> None:
        with contextlib.suppress(Exception):
            if self._proc.stdin:
                self._proc.stdin.close()
        with contextlib.suppress(Exception):
            self._proc.wait(timeout=5)
        if self._proc.poll() is None:
            self._proc.kill()
            with contextlib.suppress(Exception):
                self._proc.wait(timeout=5)
        if self._proc.stdout:
            with contextlib.suppress(Exception):
                self._proc.stdout.close()


def handshake(context: ssl.SSLContext, profile: ClientProfile = HYBRID_CLIENT, *, workdir: Path | None = None) -> Handshake:
    """A real TLS handshake between `context` (a server context) and a client of `profile`, pumped through memory (no socket), with every byte each side wrote kept
    and parsed: the ClientHello, and the ServerHello or the alert the server answered with. Never raises for a refused handshake: that is the answer."""
    result = Handshake(profile=profile.name)
    server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    server = context.wrap_bio(server_in, server_out, server_side=True)
    scratch = None
    if profile.in_process:
        client: Any = _InProcessClient(profile)
    else:
        if workdir is None:
            scratch = tempfile.TemporaryDirectory(prefix="all-tls-probe-")
            workdir = Path(scratch.name)
        client = _ChildClient(profile, workdir)
    sent_by_client = bytearray()
    sent_by_server = bytearray()
    server_done = False
    try:
        data = b""
        for _ in range(PROBE_ROUNDS):
            to_server, client_done = client.step(data)
            sent_by_client += to_server
            if to_server:
                server_in.write(to_server)
            if not server_done:
                try:
                    server.do_handshake()
                    server_done = True
                except ssl.SSLWantReadError:
                    pass
                except ssl.SSLError as exc:
                    result.error = (getattr(exc, "reason", None) or type(exc).__name__).lower()
                    server_done = True
            data = server_out.read()
            sent_by_server += data
            if server_done or (client_done and not to_server):
                break
        result.client_error = getattr(client, "error", "")
        result.completed = server_done and not result.error and not result.client_error
        if result.completed:
            result.python_version = server.version()
            cipher = server.cipher()
            result.python_cipher = cipher[0] if cipher else None
            result.alpn = server.selected_alpn_protocol()
    finally:
        client.close()
        if scratch is not None:
            scratch.cleanup()
    result.client_bytes, result.server_bytes = bytes(sent_by_client), bytes(sent_by_server)
    with contextlib.suppress(TlsParseError):
        result.client_hello = parse_client_hello(bytes(sent_by_client))
    with contextlib.suppress(TlsParseError):
        result.server = observe_server(bytes(sent_by_server))
    return result


def probe_certificate(directory: Path) -> tuple[Path, Path]:
    """A throw-away ECDSA P-256 certificate for ``probe.all.invalid`` (chain and key, 0600), good for a day: the loopback probe's own, never a device key."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, PROBE_NAME)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(PROBE_NAME)]), critical=False).sign(key, hashes.SHA256()))
    chain, private = directory / "probe-chain.pem", directory / "probe-key.pem"
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    chain.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    with contextlib.suppress(OSError):
        os.chmod(private, 0o600)
    return chain, private


# ------------------------------------------------------------------------------------------------------------------------ the report

def _claim(provable: bool, evidence: str = "", reason: str = "") -> dict[str, Any]:
    return {"provable": provable, "evidence": evidence if provable else "", "reason": "" if provable else reason}


def evaluate_claims(runtime: Runtime, probes: Mapping[str, Handshake | None], minimum_ok: bool) -> dict[str, dict[str, Any]]:
    """Which claims the probes prove, each with its evidence or the closed word that says why not. The OpenSSL version gates the hybrid claim and no other."""
    default, classic, old = probes.get("hybrid_client"), probes.get("classic_client"), probes.get("tls12_client")
    claims: dict[str, dict[str, Any]] = {}
    hello = default.negotiated if default and default.completed else None
    if not runtime.has_tls13:
        for name in CLAIMS:
            claims[name] = _claim(False, reason="tls13_required")
        return claims
    claims["tls_1_3_minimum"] = (_claim(True, CLAIMS["tls_1_3_minimum"]) if minimum_ok and hello is not None and hello.version == TLS_13
                                 else _claim(False, reason="probe_failed" if hello is None else "not_tls13"))
    if old is None:
        claims["tls_1_2_refused"] = _claim(False, reason="not_probed")
    elif not old.completed and (old.server.alert is not None or old.error):
        claims["tls_1_2_refused"] = _claim(True, CLAIMS["tls_1_2_refused"])
    else:
        claims["tls_1_2_refused"] = _claim(False, reason="tls12_client_was_served" if old.completed else "inconclusive")
    claims["alpn_http_1_1"] = (_claim(True, CLAIMS["alpn_http_1_1"]) if default and default.completed and default.alpn == policy.value("terminator.tls_alpn")
                               else _claim(False, reason="probe_failed" if hello is None else "alpn_not_selected"))
    claims["forward_secrecy"] = (_claim(True, CLAIMS["forward_secrecy"]) if hello is not None and hello.version == TLS_13 and hello.group is not None
                                 else _claim(False, reason="probe_failed" if hello is None else "no_ephemeral_group"))
    if classic is None:
        claims["classical_fallback"] = _claim(False, reason="not_probed")
    elif classic.client_hello is not None and classic.client_hello.offers_hybrid:
        claims["classical_fallback"] = _claim(False, reason="openssl_conf_ignored")   # the child still offered hybrid: this runtime does not honour OPENSSL_CONF
    elif classic.completed and classic.negotiated is not None and not classic.negotiated.hybrid:
        claims["classical_fallback"] = _claim(True, CLAIMS["classical_fallback"])
    else:
        claims["classical_fallback"] = _claim(False, reason="classic_client_refused")
    if not runtime.hybrid_capable:
        claims["hybrid_x25519mlkem768"] = _claim(False, reason="openssl_older_than_3_5")
    elif default is None or default.client_hello is None or not default.client_hello.offers_hybrid:
        claims["hybrid_x25519mlkem768"] = _claim(False, reason="client_did_not_offer_hybrid")
    elif hello is not None and hello.group == GROUP_X25519_MLKEM768:
        claims["hybrid_x25519mlkem768"] = _claim(True, CLAIMS["hybrid_x25519mlkem768"])
    else:
        claims["hybrid_x25519mlkem768"] = _claim(False, reason="group_not_negotiated")
    return {name: claims[name] for name in CLAIMS}


def capability_report(*, probe: bool = True, chain_path: Path | str | None = None, key_path: Path | str | None = None, runtime: Runtime | None = None,
                      environ: Mapping[str, str] | None = None, now: float | None = None) -> dict[str, Any]:
    """The per-OS TLS report of this computer, as the JSON that feeds ``e2e-proof.json``: the runtime, the start decision, the loopback probes and the claims they
    prove (``allowed_claims``). `runtime` can be replaced to describe another library (tests); the probes always run on the real one. With ``probe=False`` nothing is
    handshaken and no claim is provable (the cheap form the status file may carry)."""
    runtime = runtime or Runtime.current()
    environ = os.environ if environ is None else environ
    decision = start_decision(runtime)
    report: dict[str, Any] = {"v": REPORT_VERSION, "kind": "tls_capability_report",
                              "generated_at": (datetime.datetime.now(datetime.timezone.utc) if now is None
                                               else datetime.datetime.fromtimestamp(now, datetime.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                              **runtime.as_dict(),
                              "policy": {"min_version": policy.value("terminator.tls_min_version"), "alpn": policy.value("terminator.tls_alpn")},
                              "terminator": {"can_start": decision["state"] == "ready", **decision},
                              "openssl_conf": {"default_on": OPENSSL_CONF_DEFAULT_ON, "switch": OPENSSL_CONF_SWITCH, "in_environment": bool(environ.get("OPENSSL_CONF")),
                                               "effective": None},
                              "probes": {}, "claims": {}, "allowed_claims": [], "never_claimed": dict(NEVER_CLAIMED)}
    probes: dict[str, Handshake | None] = {}
    if probe and runtime.has_tls13 and tls13_available():
        with tempfile.TemporaryDirectory(prefix="all-tls-report-") as scratch:
            folder = Path(scratch)
            if chain_path is None or key_path is None:
                chain_path, key_path = probe_certificate(folder)
            context = server_context(chain_path, key_path)
            minimum_ok = context.minimum_version >= ssl.TLSVersion.TLSv1_3
            for profile in (HYBRID_CLIENT, CLASSIC_CLIENT, TLS12_CLIENT):
                try:
                    probes[profile.name] = handshake(context, profile, workdir=folder)
                except Exception as exc:  # noqa: BLE001 - a probe that cannot run is reported as not proven, never a crash of the report
                    log.warning("TLS probe %s failed (%s)", profile.name, type(exc).__name__)
                    probes[profile.name] = None
        report["probes"] = {name: (shake.as_dict() if shake else {"completed": False, "error": "probe_failed"}) for name, shake in probes.items()}
        classic = probes.get("classic_client")
        if classic is not None and classic.client_hello is not None:
            if runtime.hybrid_capable:   # a library that has no hybrid group shows nothing about whether it honoured the file
                report["openssl_conf"]["effective"] = not classic.client_hello.offers_hybrid
        report["claims"] = evaluate_claims(runtime, probes, minimum_ok)
    else:
        reason = "tls13_required" if not runtime.has_tls13 else "not_probed"
        report["claims"] = {name: _claim(False, reason=reason) for name in CLAIMS}
    report["allowed_claims"] = [name for name, claim in report["claims"].items() if claim["provable"]]
    return report


def validate_report(report: Any) -> list[str]:
    """What is wrong with a capability report, as closed words (an empty list is a well-formed one): the check the gate runs before it copies a report into
    ``e2e-proof.json``, and the one the site's TLS sentences rely on."""
    problems: list[str] = []
    if not isinstance(report, dict):
        return ["not_an_object"]
    if report.get("v") != REPORT_VERSION or report.get("kind") != "tls_capability_report":
        problems.append("wrong_kind_or_version")
    for key in ("os", "python", "openssl", "policy", "terminator", "probes", "claims", "allowed_claims", "never_claimed", "generated_at"):
        if key not in report:
            problems.append("missing_" + key)
    claims = report.get("claims") if isinstance(report.get("claims"), dict) else {}
    if set(claims) != set(CLAIMS):
        problems.append("claims_not_the_known_set")
    allowed = report.get("allowed_claims")
    if not isinstance(allowed, list) or allowed != [name for name in CLAIMS if claims.get(name, {}).get("provable") is True]:
        problems.append("allowed_claims_do_not_match_claims")
    openssl = report.get("openssl") if isinstance(report.get("openssl"), dict) else {}
    if claims.get("hybrid_x25519mlkem768", {}).get("provable") and not openssl.get("hybrid_capable"):
        problems.append("hybrid_claim_without_openssl_3_5")
    if claims.get("tls_1_3_minimum", {}).get("provable") and not openssl.get("has_tls13"):
        problems.append("tls13_claim_without_tls13")
    for name, claim in claims.items():
        if not isinstance(claim, dict) or not isinstance(claim.get("provable"), bool):
            problems.append("claim_malformed")
        elif claim["provable"] and not claim.get("evidence"):
            problems.append("claim_without_evidence_" + name)
        elif not claim["provable"] and not claim.get("reason"):
            problems.append("claim_without_reason_" + name)
    return problems


def proof_section(report: Mapping[str, Any]) -> dict[str, Any]:
    """The part of a report that ``e2e-proof.json`` carries for this operating system: who it is, which library, what the loopback showed and the claims it
    allows. The blindness gate adds the ServerHello counts of the real capture next to it (``summarize``)."""
    observed = (report.get("probes", {}).get("hybrid_client") or {}).get("server")
    return {"os": report.get("os"), "python": report.get("python"), "openssl": report.get("openssl"), "terminator": report.get("terminator"),
            "loopback": observed, "allowed_claims": list(report.get("allowed_claims", [])), "generated_at": report.get("generated_at")}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["report"])
    parser.add_argument("--out", type=Path, help="write the JSON here as well")
    parser.add_argument("--no-probe", action="store_true", help="runtime facts only: no handshake, no claim proven")
    args = parser.parse_args(argv)
    report = capability_report(probe=not args.no_probe)
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if report["terminator"]["can_start"] else 3


if __name__ == "__main__":
    hide_child_consoles()  # Windows: the probe's child interpreter opens no console window
    sys.exit(main())

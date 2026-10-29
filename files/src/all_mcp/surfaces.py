"""The agent's surfaces (ALL 2.0, end-to-end encryption): who may reach what is decided by WHICH SOCKET a request came in on, never by what it says.

One inner app (the MCP stack, OAuth, the pause and tray routes) is served by up to three uvicorn servers in one event loop:

  * LOCAL   127.0.0.1:4410 (ALL_MCP_PORT). The ALL icon, the command line, the installer and the QA scripts (and the legacy relay's client while
            the lane is off). Nothing about the request changes anything: the bootstrap bearer works, the routes of the icon exist, and the paywall gate is not
            here (the old relay gates for the computers it still serves, because it can still read the request). It is the ONLY exempt surface.
  * E2E     127.0.0.1:<ephemeral port>, written to state_dir()/surfaces.json (0600, with the agent's pid and a secret that is new at every start). Only
            the computer's own TLS terminator dials it, with what ChatGPT sent. So everything that arrives here is remote, whatever it claims to be:
            it is closed by default (http only, one Host, an exact list of paths, size caps, no forwarding headers, no bootstrap bearer), the trial's
            paywall and the activation funnel always apply, and they fail closed (no answer from the control plane, or no device id: blocked).
  * RELAY   127.0.0.1:<ephemeral port>, written to state_dir()/relay-lane.json (0600, same shape as surfaces.json). Only the legacy relay's client dials it (ALL 2.0
            WP11; `ALL_MCP_RELAY_LANE`, on unless it says off). It carries what the old relay forwards, which is remote traffic that the relay terminated and can read:
            so it gets the relay's own allowlist (the paths of its DEVICE_PATH), one Host, size caps, no forwarding headers and no bootstrap bearer, and nothing else
            of LOCAL (no pause, tray, permissions or pairing-start route, no /public). The paywall gate is NOT here: the relay gates what it serves.

Every wrapper writes the surface into `scope["state"]` (the listener marks LOCAL, E2E and RELAY; no header can: `x-all-surface: local` is stripped on E2E and RELAY and
read nowhere). The authentication (middleware.AuthMiddleware) refuses the bootstrap bearer on E2E and RELAY like an unknown token, and the gate
(middleware.DeviceGateMiddleware) enforces on E2E and passes the others. A request that carries no mark (a test, a developer's `build_app()`) is LOCAL-like: only
the wrappers below put traffic in front of the app in production.

Why the identity proof: the terminator reads where to dial from surfaces.json, and a port that the agent freed (it crashed, it restarted) can be bound by
another process, which would then receive ChatGPT's tokens in clear. So, before the terminator forwards the first ChatGPT byte, it sends on that same
connection a reserved GET with an HMAC challenge built from the per-start secret; only the agent holds the secret and answers
(`prove_listener`, the terminator's half); anything else, a 404 or silence, is refused and nothing of ChatGPT's is sent.

The relay lane has the same identity proof (relay_client.RelayClient, the dialer, runs `prove_listener` against it before it trusts relay-lane.json).

The E2E listener is started lazily and supervised (SurfaceRunner): only when the rollback switch ALL_MCP_E2E is not off, ALL_MCP_REMOTE_SURFACE is not 0 and
runtime.env names an enrolled label; inside its own exception boundary, so a failure there (it cannot bind, it crashes) leaves the LOCAL surface serving; its
lifespan is off (the inner app's lifespan runs once, under LOCAL); and uvicorn runs on both with `proxy_headers` off, no trusted forwarders, a keep-alive and a
concurrency ceiling, and an h11 head cap (X-Forwarded-For is never believed: the client of a request is its socket's peer).
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import contextvars
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import socket
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from . import e2e_policy as policy
from . import state_io
from .config import runtime_values, state_dir

_LOG = logging.getLogger(__name__)

LOOPBACK = "127.0.0.1"
SURFACES_FILE = "surfaces.json"
LANE_FILE = "relay-lane.json"
# What a wrapper writes into scope["state"], and the two values it can have.
SURFACE_KEY = "all_mcp_surface"
LOCAL = "local"
E2E = "e2e"
RELAY = "relay"
# Both surfaces that carry remote traffic: what the authentication must never treat as the computer's own tools.
REMOTE = frozenset({E2E, RELAY})
# The E2E wrapper also writes the name it was started for (the device's own, from runtime.env): the origin of an E2E request is the one of that name, so the issuer,
# the resource and the OAuth store follow the listener and never the Host header a caller wrote (origins.OriginSet.for_surface).
E2E_HOST_KEY = "all_mcp_surface_host"

# The rollback switch (one name; ALL_E2E is only an alias of the developer's dev runner) and the switch that keeps the E2E listener from
# starting at all (the update candidate probe sets it so that the probe is exactly the 1.1 probe).
SWITCH = "ALL_MCP_E2E"
REMOTE_SURFACE = "ALL_MCP_REMOTE_SURFACE"
# The hardened lane of the legacy relay (WP11). ON unless it says off; ALL_MCP_REMOTE_SURFACE=0 (the update candidate probe) also keeps it from starting.
RELAY_LANE = "ALL_MCP_RELAY_LANE"
# The old route's own socket (the relay client's WebSocket to the relay). ON whenever the variable is absent or empty: a 1.0 or 1.1 runtime.env that has no encrypted-path
# keys, updated to 2.0, stays connected and answering. Only an explicit off value stops it (a later 2.x, on the owner's order, or "Cerrar la ruta antigua" on one computer).
LEGACY_RELAY = "ALL_MCP_LEGACY_RELAY"
# The canary device's mode, "certificate manager only" (the tunnel runbook, section 8): the e2e child keeps this computer's certificate issued and renewed as usual but opens no tunnel
# connection of its own, because the canary device app holds the connection to the nodes under the same label (two clients of one label evict each other for ever). The opposite
# default of the rollback switches: it is ON only when it says on, so a computer that never set it is an ordinary one. CANARY_STATUS is the canary's own --status-file, where the child
# reads whether its links are up (e2e_canary.py). Both are kept by every rewrite of runtime.env (config.E2E_RUNTIME_KEYS) and neither is ever written by an install or an update.
CERT_ONLY = "ALL_E2E_CERT_ONLY"
CANARY_STATUS = "ALL_E2E_CANARY_STATUS"
_OFF = frozenset({"0", "off", "false", "no"})
_ON = frozenset({"1", "on", "true", "yes"})
# The runtime.env file, written by the installer when the computer enrolls: the label and the host the control plane gave it (and, optionally, the zone it must be in).
LABEL_KEY, HOST_KEY, ZONE_KEY = "ALL_E2E_LABEL", "ALL_E2E_HOST", "ALL_E2E_ZONE"

# What the E2E surface answers, by exact path. Everything else is a 404: the pause, resume, pairing start, tray,
# permissions and public routes are not here even when the app has them, and `/mcp/` is served as `/mcp` (no redirect, ChatGPT keeps the slash it was given).
E2E_PATHS = frozenset({
    "/mcp", "/mcp/", "/register", "/authorize", "/token", "/pair", "/healthz",
    "/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp",
    "/.well-known/oauth-authorization-server", "/.well-known/openid-configuration",
})
# What the lane answers: the paths of the relay's DEVICE_PATH (the relay index module), which is what the old relay forwards; the relay sends "/" + the path after
# /d/<device>, so a bare /d/<device> and /d/<device>/ arrive as "/". The lane is the E2E list plus "/": no pause, tray, permissions, pairing-start or /public path is on
# it, even though the app has them. The relay lane test suite reads the relay's regex and checks both lists against each other.
LANE_PATHS = E2E_PATHS | {"/"}
# Headers that say who the caller is or how it got here: a remote caller writes them as it likes, so none of them reaches the app.
_STRIPPED_PREFIXES = (b"x-forwarded-", b"cf-", b"x-all-")
_STRIPPED_NAMES = frozenset({b"forwarded"})

# Ceilings of the two uvicorn servers that are not in the policy table: LOCAL carries the legacy relay's one connection per request, so it is far more
# generous than E2E (which gets twice the terminator's stream cap: its streams plus the identity probes in flight).
LOCAL_CONCURRENCY = 512
E2E_CONCURRENCY_FACTOR = 2
GRACEFUL_SHUTDOWN_SECONDS = 10
START_TIMEOUT_SECONDS = 10.0
WATCH_SECONDS = 5.0  # how often the runner looks again at whether the E2E listener should be running

_current: contextvars.ContextVar[str | None] = contextvars.ContextVar("all_mcp_surface", default=None)
_serving = {"e2e": False}


def current() -> str | None:
    """The surface of the request being served in this task (E2E, LOCAL), or None outside a request: what the funnel asks, because it is called deep inside
    the OAuth route and the gate, far from the ASGI scope."""
    return _current.get()


def in_e2e() -> bool:
    return _current.get() == E2E


def e2e_serving() -> bool:
    """True while this process has an E2E listener up: what keeps the paywall verdict fresh (device_access.start_refresher)."""
    return _serving["e2e"]


def surface_of(scope: dict) -> str | None:
    return (scope.get("state") or {}).get(SURFACE_KEY)


# ------------------------------------------------------------------------------------------------------------------------ is the E2E listener wanted?

def _setting(values: dict[str, str], name: str) -> str:
    return (os.environ.get(name) or values.get(name, "")).strip().lower()


@dataclass(frozen=True)
class E2EConfig:
    label: str
    host: str  # the device's full name, exactly what a caller must write in Host


def enrolled_host(values: dict[str, str] | None = None) -> E2EConfig | None:
    """The label and host this computer enrolled with, when runtime.env holds a well-formed pair (label as the policy writes it, host one label under a zone,
    and under ALL_E2E_ZONE when that is set), else None. A computer without them has no encrypted name, so nothing listens for one."""
    values = runtime_values() if values is None else values
    label, host, zone = values.get(LABEL_KEY, ""), values.get(HOST_KEY, ""), values.get(ZONE_KEY, "")
    if (not policy.anchored("identity.label_regex").fullmatch(label) or len(host) > policy.value("identity.fqdn_max_length")
            or not policy.anchored("identity.fqdn_regex").fullmatch(host) or not host.startswith(label + ".")):
        return None
    if zone and not policy.host_pattern(zone).match(host):
        return None
    return E2EConfig(label, host)


def e2e_config(values: dict[str, str] | None = None) -> E2EConfig | None:
    """What the E2E listener should serve right now, or None when it should not run: the rollback switch is off, the remote surface is off, or the runtime has
    no enrolled label. The ONE rollback variable of the migration is ALL_MCP_E2E: it stops the listener (and the tunnel, whose own code reads the same name);
    it never makes the paywall easier, because a computer that has no E2E surface has nothing the paywall would guard."""
    values = runtime_values() if values is None else values
    return None if e2e_switched_off(values) else enrolled_host(values)


def e2e_switched_off(values: dict[str, str] | None = None) -> bool:
    """True while the rollback switch (ALL_MCP_E2E) or the remote surface (ALL_MCP_REMOTE_SURFACE) is off: no E2E listener runs, so nothing that hands out the encrypted address
    (the reconnect flow, the tray's status) may either."""
    values = runtime_values() if values is None else values
    return _setting(values, SWITCH) in _OFF or _setting(values, REMOTE_SURFACE) in _OFF


def relay_lane_wanted(values: dict[str, str] | None = None) -> bool:
    """Whether the agent serves the relay lane and the relay's client dials it: ALL_MCP_RELAY_LANE is not off (it is ON when absent) and ALL_MCP_REMOTE_SURFACE is not
    off. The agent and the legacy relay's client both ask THIS, over the same runtime.env, so they never disagree (a lane the agent does not serve is a lane the client
    does not wait for). Off leaves the legacy relay on the LOCAL surface exactly as 1.1 had it."""
    values = runtime_values() if values is None else values
    return _setting(values, RELAY_LANE) not in _OFF and _setting(values, REMOTE_SURFACE) not in _OFF


def legacy_relay_wanted(values: dict[str, str] | None = None) -> bool:
    """Whether the relay client keeps the old route's WebSocket: ALL_MCP_LEGACY_RELAY is not an explicit off value. Absent, empty or anything else means ON, so that the
    absence of the 2.0 keys can never switch a computer's only working route off."""
    values = runtime_values() if values is None else values
    return _setting(values, LEGACY_RELAY) not in _OFF


def cert_only(values: dict[str, str] | None = None) -> bool:
    """Whether this computer is a canary's: ALL_E2E_CERT_ONLY says on (1, on, true or yes; absent, empty or anything else is off). The e2e child then runs the enroll, the certificate
    manager and the self-check of the public name exactly as always, and starts no tunnel (e2e_runner.ChildStages). The rollback switch still wins: ALL_MCP_E2E=off stops all of it."""
    values = runtime_values() if values is None else values
    return _setting(values, CERT_ONLY) in _ON


# ------------------------------------------------------------------------------------------------------------------------ the transport security of the inner app

_transport_settings: list[Any] = []


def adopt_transport_security(settings: Any, values: dict[str, str] | None = None) -> None:
    """The inner app's DNS-rebinding settings (mcp TransportSecuritySettings, built by mcp_server.build_app) learn the E2E host: the Host the E2E surface lets
    through must also be one the MCP transport accepts. Called when the app is built, and again by the runner when the listener starts (a computer that
    enrolls while the agent runs)."""
    _transport_settings.append(settings)
    found = enrolled_host(values)
    if found is not None:
        _allow_host(settings, found.host)


def _allow_host(settings: Any, host: str) -> None:
    for field, entry in (("allowed_hosts", host), ("allowed_origins", f"https://{host}")):
        listed = getattr(settings, field)
        if entry not in listed:
            listed.append(entry)


def _allow_everywhere(host: str) -> None:
    for settings in list(_transport_settings):
        _allow_host(settings, host)


# ------------------------------------------------------------------------------------------------------------------------ the identity proof (T14)

def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _key(secret: str) -> bytes:
    raw = base64.urlsafe_b64decode(secret + "=" * (-len(secret) % 4))
    if len(raw) != 32 or not policy.anchored("identity.attach_secret_regex").fullmatch(secret):
        raise ValueError("surface secret")
    return raw


def new_secret() -> str:
    return b64u(secrets.token_bytes(32))


def challenge_mac(secret: str, nonce: str) -> str:
    """What the terminator puts on its challenge: only a holder of the per-start secret can answer it."""
    return b64u(hmac.new(_key(secret), b"all-surface-challenge-v1\n" + nonce.encode("ascii"), hashlib.sha256).digest())


def surface_proof(secret: str, nonce: str, pid: int, port: int) -> str:
    """What the listener answers: it proves it holds the secret of the process surfaces.json names, for THIS nonce, pid and port."""
    message = b"all-surface-proof-v1\n" + nonce.encode("ascii") + b"\n" + str(pid).encode() + b"\n" + str(port).encode()
    return b64u(hmac.new(_key(secret), message, hashlib.sha256).digest())


def verify_challenge(secret: str, nonce: Any, mac: Any) -> bool:
    """The agent's check of a challenge: a nonce the policy allows, and the MAC only a holder of the secret can make (compared in constant time)."""
    try:
        return (isinstance(nonce, str) and policy.anchored("identity.nonce_regex").fullmatch(nonce) is not None and isinstance(mac, str)
                and hmac.compare_digest(challenge_mac(secret, nonce).encode(), mac.encode("ascii")))
    except (ValueError, UnicodeError):
        return False


def verify_proof(secret: str, nonce: Any, pid: int, port: int, proof: Any) -> bool:
    """The terminator's check of an answer: bound to this nonce, this pid and this port, so a proof for another challenge, process or port fails."""
    try:
        return (isinstance(nonce, str) and policy.anchored("identity.nonce_regex").fullmatch(nonce) is not None and isinstance(proof, str)
                and hmac.compare_digest(surface_proof(secret, nonce, pid, port).encode(), proof.encode("ascii")))
    except (ValueError, UnicodeError):
        return False


def identity_request(host: str, port: int, nonce: str, mac: str) -> str:
    """The exact request head the terminator sends on the connection it is about to hand to ChatGPT, before the first ChatGPT byte."""
    return (f"GET {policy.value('surface.identity_path')} HTTP/1.1\r\nHost: {host}:{port}\r\n{policy.value('surface.identity_challenge_header')}: {nonce}\r\n"
            f"{policy.value('surface.identity_mac_header')}: {mac}\r\nConnection: keep-alive\r\n\r\n")


class SurfaceIdentityError(Exception):
    """The listener could not prove it is the agent. `word` is a fixed word (never text from the network)."""

    def __init__(self, word: str):
        super().__init__(word)
        self.word = word


async def prove_listener(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, *, host: str, port: int, secret: str, pid: int,
                         timeout: float = 5.0) -> None:
    """The terminator's half of the proof: on a freshly opened connection to the surface, challenge it and check its answer; return only when it is the agent
    that holds `secret` for `pid` and `port`, with the answer consumed (the connection is kept alive for ChatGPT's bytes). Raises SurfaceIdentityError, and
    the caller then closes the connection and sends nothing of ChatGPT's."""
    nonce = secrets.token_urlsafe(policy.value("protocol.nonce_bytes"))
    try:
        writer.write(identity_request(host, port, nonce, challenge_mac(secret, nonce)).encode("ascii"))
        await asyncio.wait_for(writer.drain(), timeout)
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout)
    except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError):
        raise SurfaceIdentityError("no_answer") from None
    lines = head[:-4].split(b"\r\n")
    if lines[0] != b"HTTP/1.1 200 OK" or len(head) > 2048:
        raise SurfaceIdentityError("not_the_agent")
    seen: dict[bytes, bytes] = {}
    for line in lines[1:]:
        name, _, value = line.partition(b":")
        if name.lower() in seen:
            raise SurfaceIdentityError("not_the_agent")
        seen[name.lower()] = value.strip()
    if seen.get(b"content-length") != b"0":
        raise SurfaceIdentityError("not_the_agent")
    if not verify_proof(secret, nonce, pid, port, seen.get(policy.value("surface.identity_proof_header").encode(), b"").decode("latin-1")):
        raise SurfaceIdentityError("bad_proof")


# ------------------------------------------------------------------------------------------------------------------------ surfaces.json

@dataclass(frozen=True)
class SurfaceTarget:
    pid: int
    host: str
    port: int
    secret: str
    started_at: float


def surfaces_path() -> Path:
    return state_dir() / SURFACES_FILE


def lane_path() -> Path:
    return state_dir() / LANE_FILE


def write_surfaces_file(*, pid: int, port: int, secret: str, path: Path | None = None) -> None:
    """state_dir()/surfaces.json (0600: the secret in it is what proves the listener is the agent). Replaces whatever an earlier start left."""
    state_io.atomic_json(path or surfaces_path(), {"v": 1, "pid": pid, "host": LOOPBACK, "port": port, "secret": secret, "started_at": int(time.time())})


def remove_surfaces_file(*, pid: int, secret: str, path: Path | None = None) -> None:
    """Remove surfaces.json, but only while it still names this listener (a newer start may have written its own)."""
    path = path or surfaces_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("pid") == pid and data.get("secret") == secret:
            path.unlink()
    except (OSError, ValueError, AttributeError):
        pass


def _pid_alive(pid: int) -> bool:
    try:
        import psutil
        return bool(psutil.pid_exists(pid))
    except ImportError:
        pass
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def load_target(path: Path | None = None, *, require_alive: bool = True) -> SurfaceTarget:
    """What the terminator dials: the one validated address of the E2E listener. Raises SurfaceIdentityError("no_surface") for anything that is not a
    well-formed surfaces.json of a live agent: a missing or oversized file, a link, one other accounts can read, a bad field, a pid that is gone."""
    path = path or surfaces_path()
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 4096 or (os.name != "nt" and info.st_mode & 0o077):
            raise SurfaceIdentityError("no_surface")
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise SurfaceIdentityError("no_surface") from None
    try:
        pid, port, started = data["pid"], data["port"], data["started_at"]
        ok = (isinstance(data, dict) and set(data) == {"v", "pid", "host", "port", "secret", "started_at"} and data["v"] == 1 and data["host"] == LOOPBACK
              and type(pid) is int and 1 <= pid <= 0xFFFFFFFF and type(port) is int and 1024 <= port <= 65535
              and isinstance(data["secret"], str) and policy.anchored("identity.attach_secret_regex").fullmatch(data["secret"]) is not None
              and isinstance(started, (int, float)) and not isinstance(started, bool))
    except (KeyError, TypeError):
        ok = False
    if not ok or (require_alive and not _pid_alive(pid)):
        raise SurfaceIdentityError("no_surface")
    return SurfaceTarget(pid, LOOPBACK, port, data["secret"], float(started))


# ------------------------------------------------------------------------------------------------------------------------ the wrappers

def _marked(scope: dict, surface: str, **changes: Any) -> dict:
    state = {**(scope.get("state") or {}), SURFACE_KEY: surface}
    state.pop(E2E_HOST_KEY, None)  # only the E2E wrapper writes it, below: whatever came in with the scope is not believed
    if "host" in changes:
        state[E2E_HOST_KEY] = changes.pop("host")
    return {**scope, **changes, "state": state}


class LocalSurface:
    """The LOCAL listener's wrapper: marks every request LOCAL, otherwise changes nothing (the lifespan, which the inner app runs once, passes through)."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            await self.app(scope, receive, send)
            return
        token = _current.set(LOCAL)
        try:
            await self.app(_marked(scope, LOCAL), receive, send)
        finally:
            _current.reset(token)


async def _respond(send, status: int, body: bytes = b"", *, extra=(), head: bool = False) -> None:
    headers = [(b"cache-control", b"no-store"), (b"content-length", str(len(body)).encode())]
    if body:
        headers.append((b"content-type", b"application/json"))
    headers.extend(extra)
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": b"" if head else body})


def _values(scope, name: bytes) -> list[bytes]:
    return [value for key, value in scope.get("headers", []) if key == name]


class E2ESurface:
    """The E2E listener's wrapper: everything that arrives here is remote, so it is closed by default and the only things let through are what ChatGPT needs.
    (RelaySurface, below, is the same wrapper for the legacy relay's lane: its own mark, its own list of paths, and the Host of its own socket.)

    In order: a lifespan or websocket scope never reaches the app; the head is bounded (headers, their size, the whole head, one body length, no Upgrade); the identity
    proof answers its reserved path and nothing else does; the request names this computer, once, by its exact name (421); the path is on the list (404, and
    `/mcp/` is served as `/mcp`); `/healthz` says only that the agent is up; the headers that claim an origin are removed; the body is capped while it streams
    (413); and the request is marked E2E for the authentication and the gate. `host` is the device's full name; `secret`, `pid` and `port` are what surfaces.json
    holds."""

    surface = E2E
    paths = E2E_PATHS
    _answers_healthz = True  # E2E says only that the agent is up; the relay lane lets the app answer, as the old relay always forwarded it

    def __init__(self, app, *, host: str, secret: str, pid: int, port: int):
        self.app = app
        self.host = host.lower()
        self._secret = secret
        self._pid = pid
        self._port = port
        _key(secret)  # a secret that cannot key the proof is a start that must fail now, not at the first challenge
        self._body_max = policy.value("surface.body_max_bytes")
        self._headers_max = policy.value("surface.headers_max")
        self._value_max = policy.value("surface.header_value_max_bytes")
        self._head_max = head_cap()
        self._proof_path = policy.value("surface.identity_path")

    async def __call__(self, scope, receive, send):
        kind = scope["type"]
        if kind == "lifespan":  # E2E runs with the lifespan off; if one ever arrives it is answered here, so the inner app's lifespan never runs twice
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if kind != "http":  # a websocket (or anything else): the E2E surface has no scope but http, so nothing skips the authentication
            if kind == "websocket":
                await receive()
                await send({"type": "websocket.close", "code": 1008})
            return
        headers = scope.get("headers", [])
        if (len(headers) > self._headers_max or any(len(value) > self._value_max for _, value in headers)
                or len(scope.get("raw_path") or b"") + len(scope.get("query_string") or b"") + sum(len(key) + len(value) + 4 for key, value in headers) > self._head_max):
            await _respond(send, 431, b'{"error":"request_header_fields_too_large"}', extra=[(b"connection", b"close")])
            return
        if _values(scope, b"upgrade"):  # no websocket and no h2c upgrade: a request that asks for one is refused, not served as a plain one
            await _respond(send, 400, b'{"error":"upgrade_not_supported"}', extra=[(b"connection", b"close")])
            return
        lengths = _values(scope, b"content-length")
        if len(lengths) > 1 or (lengths and not lengths[0].isdigit()) or (lengths and _values(scope, b"transfer-encoding")):
            await _respond(send, 400, b'{"error":"invalid_request"}', extra=[(b"connection", b"close")])  # the framing a smuggler plays with
            return
        path = scope.get("path", "")
        if path == self._proof_path:
            await self._prove(scope, send)
            return
        hosts = _values(scope, b"host")
        if len(hosts) != 1 or hosts[0].lower() != self.host.encode("latin-1"):
            await _respond(send, 421, b'{"error":"misdirected_request"}')
            return
        if path not in self.paths:
            await _respond(send, 404, b'{"error":"not_found"}')
            return
        if path == "/healthz" and self._answers_healthz:
            if scope["method"] not in ("GET", "HEAD"):
                await _respond(send, 405, b'{"error":"method_not_allowed"}', extra=[(b"allow", b"GET, HEAD")])
                return
            await _respond(send, 200, b'{"ok":true}', head=scope["method"] == "HEAD")
            return
        if lengths and int(lengths[0]) > self._body_max:
            await _respond(send, 413, b'{"error":"request_too_large"}', extra=[(b"connection", b"close")])
            return
        changes: dict[str, Any] = {"headers": [(key, value) for key, value in headers
                                               if not key.startswith(_STRIPPED_PREFIXES) and key not in _STRIPPED_NAMES]}
        if path == "/mcp/":
            changes["path"], changes["raw_path"] = "/mcp", b"/mcp"
        if self.surface == E2E:  # only the E2E listener names an encrypted origin; the relay lane's requests belong to the primary one
            changes["host"] = self.host
        await self._serve(_marked(scope, self.surface, **changes), receive, send)

    async def _prove(self, scope, send) -> None:
        """The reserved identity path: answered only to a valid challenge (a 404 like any other path otherwise, so a stranger learns nothing)."""
        nonces = _values(scope, policy.value("surface.identity_challenge_header").encode())
        macs = _values(scope, policy.value("surface.identity_mac_header").encode())
        nonce = nonces[0].decode("latin-1") if len(nonces) == 1 and len(macs) == 1 else ""
        if scope["method"] != "GET" or not verify_challenge(self._secret, nonce, macs[0].decode("latin-1") if macs else ""):
            await _respond(send, 404, b'{"error":"not_found"}')
            return
        proof = surface_proof(self._secret, nonce, self._pid, self._port).encode()
        await _respond(send, 200, b"", extra=[(policy.value("surface.identity_proof_header").encode(), proof)])

    async def _serve(self, scope, receive, send) -> None:
        total = 0
        exceeded = False
        started = False

        async def capped_receive():
            nonlocal total, exceeded
            if exceeded:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                total += len(message.get("body", b""))
                if total > self._body_max:  # counted as it streams, whatever Content-Length said (or did not say)
                    exceeded = True
                    return {"type": "http.disconnect"}
            return message

        async def guarded_send(message):
            nonlocal started
            if exceeded:
                return
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        token = _current.set(self.surface)
        try:
            await self.app(scope, capped_receive, guarded_send)
        except Exception:
            if not exceeded:
                raise
        finally:
            _current.reset(token)
        if exceeded and not started:
            await _respond(send, 413, b'{"error":"request_too_large"}', extra=[(b"connection", b"close")])


class RelaySurface(E2ESurface):
    """The relay lane's wrapper (WP11): what the legacy relay's client dials. It is the E2E wrapper with the relay's own allowlist (`LANE_PATHS`), the mark RELAY, and one
    Host: the lane's own socket, `127.0.0.1:<port>`, the only name the client writes (the relay's Host is dropped and the client's HTTP library sets this one); any other
    Host is a request that did not come from the client (421). The app answers `/healthz` itself here: the installers and the site read the old relay's health through it,
    and that report is the same one 1.1 gave. What this surface never carries, wherever a request says it came from: the routes of the computer's own tools, the
    bootstrap bearer (middleware.AuthMiddleware), the paywall gate (the relay gates what it serves) and a websocket."""

    surface = RELAY
    paths = LANE_PATHS
    _answers_healthz = False

    def __init__(self, app, *, secret: str, pid: int, port: int):
        super().__init__(app, host=f"{LOOPBACK}:{port}", secret=secret, pid=pid, port=port)


# ------------------------------------------------------------------------------------------------------------------------ the listeners

def head_cap() -> int:
    """The most a request head may weigh: one header as long as the policy allows, plus an ordinary head. h11 enforces it only on a head that arrives incomplete (a
    head that comes whole in one read is parsed whatever its size), so the E2E wrapper counts it again."""
    return policy.value("surface.header_value_max_bytes") + policy.value("terminator.request_head_max_bytes")


def uvicorn_config(app, *, log_level: str, concurrency: int, ws: str = "auto", lifespan: str = "auto", **options: Any):
    """The settings both servers share (uvicorn is imported here so that importing this module stays cheap). `proxy_headers` is OFF and no address is trusted to
    forward: uvicorn would otherwise believe X-Forwarded-For from 127.0.0.1, which is every caller there is (the tunnel and the terminator are on loopback), and the
    rate-limit key and the client of a request would be whatever the remote caller wrote. Access logs are off (the request line carries OAuth and pairing
    parameters)."""
    import uvicorn
    return uvicorn.Config(app, interface="asgi3", http="h11", log_level=log_level, access_log=False, proxy_headers=False, forwarded_allow_ips="", ws=ws, lifespan=lifespan,
                          timeout_keep_alive=policy.value("surface.keep_alive_s"), limit_concurrency=concurrency,
                          h11_max_incomplete_event_size=head_cap(), **options)


def _local_server_class():
    import uvicorn

    class LocalServer(uvicorn.Server):
        """The LOCAL server. When it starts to shut down (a signal) it first tells the runner, so the E2E listener and surfaces.json go before the process does:
        uvicorn raises the signal again as soon as `serve` is done, which ends the process before anything after it could run."""

        def __init__(self, config, before_shutdown: Callable[[], Any]):
            super().__init__(config)
            self._before_shutdown = before_shutdown

        async def shutdown(self, sockets=None):
            try:
                await self._before_shutdown()
            except Exception:  # noqa: BLE001
                _LOG.warning("e2e surface did not stop cleanly", exc_info=False)
            await super().shutdown(sockets=sockets)

    return LocalServer


def _server_class():
    import uvicorn

    class QuietServer(uvicorn.Server):
        """The E2E server: it does not take over SIGINT and SIGTERM (the LOCAL server owns them, and stops this one)."""

        @contextlib.contextmanager
        def capture_signals(self):
            yield

    return QuietServer


def _bind_loopback() -> socket.socket:
    """A listening socket on 127.0.0.1 and an ephemeral port. On Windows it is bound exclusively (SO_EXCLUSIVEADDRUSE), so nothing can share the port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        sock.bind((LOOPBACK, 0))
        sock.listen(socket.SOMAXCONN)
        sock.setblocking(False)
    except BaseException:
        sock.close()
        raise
    return sock


@dataclass
class _Listener:
    config: E2EConfig | None  # what the E2E listener serves; None for the relay lane, which has nothing to follow
    server: Any
    task: "asyncio.Task[None]"
    pid: int
    port: int
    secret: str


class SurfaceRunner:
    """Serves the app on the LOCAL surface and, while they are wanted, on the E2E one and on the relay lane: up to three uvicorn servers in one loop. `values`, `bind`
    and `server_class` exist so the tests can drive it without a runtime.env, a real port or a real uvicorn; the defaults are the real ones (`lane_server_class` and
    `lane_path` are the lane's own, so a test that breaks the E2E server does not break the lane with it)."""

    def __init__(self, app, *, port: int, log_level: str = "info", values: Callable[[], dict[str, str]] = runtime_values,
                 bind: Callable[[], socket.socket] = _bind_loopback, server_class: Any = None, state_path: Path | None = None, watch: float = WATCH_SECONDS,
                 lane_path: Path | None = None, lane_server_class: Any = None):
        self.app = app
        self.port = port
        self.log_level = log_level
        self._values = values
        self._bind = bind
        self._server_class = server_class
        self._path = state_path
        self._watch_seconds = watch
        self._lane_file = lane_path
        self._lane_server_class = lane_server_class
        self._listener: _Listener | None = None
        self._failures = 0
        self._retry_at = 0.0
        self._lane: _Listener | None = None
        self._lane_failures = 0
        self._lane_retry_at = 0.0
        self._stopping = False
        self.local: Any = None

    # ---- the whole thing

    async def serve(self) -> None:
        """Block until the LOCAL server stops (a signal, or it could not start: then SystemExit, as `uvicorn.run` had it)."""
        self.local = self.make_local()
        watcher = asyncio.create_task(self._watch())
        try:
            await self.local.serve()
        finally:
            watcher.cancel()
            await asyncio.gather(watcher, return_exceptions=True)
            await self.stop_lane()
            await self.stop_e2e()

    def make_local(self):
        config = uvicorn_config(LocalSurface(self.app), log_level=self.log_level, concurrency=LOCAL_CONCURRENCY, host=LOOPBACK, port=self.port)
        return _local_server_class()(config, self._begin_shutdown)

    async def _begin_shutdown(self) -> None:
        self._stopping = True
        await self.stop_lane()
        await self.stop_e2e()

    async def _watch(self) -> None:
        while True:
            try:
                await self.reconcile()
            except Exception:  # noqa: BLE001 - nothing the E2E side does may take the agent down
                _LOG.warning("surface supervisor error", exc_info=False)
            await asyncio.sleep(self._watch_seconds)

    # ---- the E2E listener

    async def reconcile(self) -> None:
        """Make the E2E listener and the relay lane match what is wanted now. Each has its own boundary: one that fails never keeps the other from being looked at."""
        if self._stopping:
            return
        try:
            await self._reconcile_e2e()
        finally:
            await self._reconcile_lane()

    async def _reconcile_e2e(self) -> None:
        """Make the E2E listener match what is wanted now: start it, stop it, or start it again after it died (with a backoff)."""
        wanted = e2e_config(self._values())
        listener = self._listener
        if listener is not None and listener.task.done():
            _LOG.warning("e2e surface stopped by itself")
            await self.stop_e2e()
            self._failures += 1
            self._retry_at = time.monotonic() + min(policy.value("timing.backoff_max_s"), policy.value("timing.backoff_min_s") * 2 ** (self._failures - 1))
            listener = None
        elif listener is not None:
            self._failures = 0
        if listener is not None and listener.config != wanted:
            await self.stop_e2e()
            listener = None
        if wanted is not None and listener is None and time.monotonic() >= self._retry_at:
            try:
                await self.start_e2e(wanted)
            except Exception:  # noqa: BLE001 - one boundary: a listener that cannot start is a missing remote surface, not a dead agent
                _LOG.warning("e2e surface could not start", exc_info=False)
                await self.stop_e2e()
                self._failures += 1
                self._retry_at = time.monotonic() + min(policy.value("timing.backoff_max_s"), policy.value("timing.backoff_min_s") * 2 ** (self._failures - 1))

    async def start_e2e(self, wanted: E2EConfig) -> None:
        sock = self._bind()
        try:
            port = sock.getsockname()[1]
            secret = new_secret()
            pid = os.getpid()
            surface = E2ESurface(self.app, host=wanted.host, secret=secret, pid=pid, port=port)
            config = uvicorn_config(surface, log_level=self.log_level, concurrency=policy.value("terminator.max_streams") * E2E_CONCURRENCY_FACTOR,
                                    lifespan="off", ws="none", timeout_graceful_shutdown=GRACEFUL_SHUTDOWN_SECONDS)
            server = (self._server_class or _server_class())(config)
            task = asyncio.create_task(self._guard(server, sock))
        except BaseException:
            sock.close()
            raise
        self._listener = _Listener(wanted, server, task, pid, port, secret)
        deadline = time.monotonic() + START_TIMEOUT_SECONDS
        while not getattr(server, "started", False) and not task.done():
            if time.monotonic() > deadline:
                raise RuntimeError("e2e surface did not start")
            await asyncio.sleep(0.02)
        if task.done() or self._stopping or self._listener is None:
            raise RuntimeError("e2e surface did not start")
        _allow_everywhere(wanted.host)  # a computer that enrolled while the agent ran: the MCP transport must accept the name too
        write_surfaces_file(pid=pid, port=port, secret=secret, path=self._path)
        _serving["e2e"] = True

    # ---- the relay lane

    async def _reconcile_lane(self) -> None:
        """The same loop for the lane the legacy relay's client dials (WP11): up while `relay_lane_wanted`, down when it is not, up again after it died (with the
        backoff of the E2E listener). It needs no label: a computer that has never enrolled is exactly who the old relay serves."""
        if self._stopping:
            return
        wanted = relay_lane_wanted(self._values())
        listener = self._lane
        if listener is not None and listener.task.done():
            _LOG.warning("relay lane stopped by itself")
            await self.stop_lane()
            self._lane_failures += 1
            self._lane_retry_at = time.monotonic() + min(policy.value("timing.backoff_max_s"), policy.value("timing.backoff_min_s") * 2 ** (self._lane_failures - 1))
            listener = None
        elif listener is not None:
            self._lane_failures = 0
        if listener is not None and not wanted:
            await self.stop_lane()
            listener = None
        if wanted and listener is None and time.monotonic() >= self._lane_retry_at:
            try:
                await self.start_lane()
            except Exception:  # noqa: BLE001 - one boundary: a lane that cannot start is a legacy route that answers "unavailable" and is retried, not a dead agent
                _LOG.warning("relay lane could not start", exc_info=False)
                await self.stop_lane()
                self._lane_failures += 1
                self._lane_retry_at = time.monotonic() + min(policy.value("timing.backoff_max_s"),
                                                             policy.value("timing.backoff_min_s") * 2 ** (self._lane_failures - 1))

    async def start_lane(self) -> None:
        sock = self._bind()
        try:
            port = sock.getsockname()[1]
            secret = new_secret()
            pid = os.getpid()
            surface = RelaySurface(self.app, secret=secret, pid=pid, port=port)
            config = uvicorn_config(surface, log_level=self.log_level, concurrency=policy.value("terminator.max_streams") * E2E_CONCURRENCY_FACTOR,
                                    lifespan="off", ws="none", timeout_graceful_shutdown=GRACEFUL_SHUTDOWN_SECONDS)
            server = (self._lane_server_class or _server_class())(config)
            task = asyncio.create_task(self._guard(server, sock))
        except BaseException:
            sock.close()
            raise
        self._lane = _Listener(None, server, task, pid, port, secret)
        deadline = time.monotonic() + START_TIMEOUT_SECONDS
        while not getattr(server, "started", False) and not task.done():
            if time.monotonic() > deadline:
                raise RuntimeError("relay lane did not start")
            await asyncio.sleep(0.02)
        if task.done() or self._stopping or self._lane is None:
            raise RuntimeError("relay lane did not start")
        write_surfaces_file(pid=pid, port=port, secret=secret, path=self._lane_file or lane_path())

    async def stop_lane(self) -> None:
        listener, self._lane = self._lane, None
        if listener is None:
            return
        remove_surfaces_file(pid=listener.pid, secret=listener.secret, path=self._lane_file or lane_path())  # first: the client must not dial a port that is going away
        await self._stop(listener)

    async def _stop(self, listener: _Listener) -> None:
        listener.server.should_exit = True
        done, _ = await asyncio.wait({listener.task}, timeout=GRACEFUL_SHUTDOWN_SECONDS + 5)
        if not done:
            listener.server.force_exit = True
            listener.task.cancel()
            await asyncio.gather(listener.task, return_exceptions=True)

    async def _guard(self, server, sock: socket.socket) -> None:
        """The E2E server's boundary. uvicorn exits with SystemExit when it cannot start, and asyncio would carry that out of the event loop and end the agent."""
        try:
            await server.serve(sockets=[sock])
        except (Exception, SystemExit) as exc:  # noqa: BLE001
            _LOG.warning("e2e surface failed: %s", type(exc).__name__)
        finally:
            # A server that died before its own shutdown (cancelled, crashed) still has its listening socket registered with the loop: close the asyncio servers
            # first, or the next listener that is given the same file descriptor number would be served by this dead one.
            for listening in getattr(server, "servers", None) or []:
                listening.close()
            sock.close()

    async def stop_e2e(self) -> None:
        listener, self._listener = self._listener, None
        _serving["e2e"] = False
        if listener is None:
            return
        remove_surfaces_file(pid=listener.pid, secret=listener.secret, path=self._path)  # first: nothing may dial a port that is going away
        await self._stop(listener)


def run(app, *, port: int, log_level: str = "info") -> None:
    """`uvicorn.run(app, host="127.0.0.1", port=port)` of the agent, now with the two surfaces. Blocks."""
    asyncio.run(SurfaceRunner(app, port=port, log_level=log_level).serve())

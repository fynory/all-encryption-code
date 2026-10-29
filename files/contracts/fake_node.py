"""A Python fake tunnel node for protocol v2 (ALL 2.0): the node side of the contract as a pure state machine.

It is what WP13 (the device's tunnel client) is tested against, and the golden transcripts of contracts/vectors/transcripts.json are its
output: a generator outside this set feeds it the scripted inputs of each scenario and writes down what it did, and the contract test suite
checks that it still does exactly that and that the contract checker (e2e_contracts.check_transcript, the same one the Go and TypeScript
suites run) accepts it. No sockets here: `handle(event)` takes one input event and returns the output events, so a test drives it with a
fake clock, and `FakeNodeServer` (below) is the thin asyncio wrapper that speaks the same lines over real sockets.

Input events  (what happens TO the node)         Output events (what the node does)
  recv        {conn, line}   a line from a device      send       {conn, line}   a line to a device
  cp_reply    {conn, status, body}  the control plane  cp         {conn, call, body}   a call to the control plane
  client_hello {sni, complete, peer_ip, class}         tls_alert  {sni}   the node answers a client with a TLS alert
  attach      {conn, line}   a data connection         attach     {conn, line, result}  ok, or err (with the ERR line in `reply`)
  tick        {}             time passes               (send CLOSE expired, ...)
  end         {}             the scenario is over
Every event carries `t`, the node's clock in seconds. Randomness (nonce, stream id, attach secret) is injected so a scenario is deterministic.
"""
from __future__ import annotations

import asyncio
import os
import time
from collections import deque
from typing import Any, Awaitable, Callable

import e2e_contracts as c

# The word the node answers a device with, per reason the contract checker found.
_ERR_FOR = {"malformed_token": "bad_hello", "not_yet_valid": "clock_skew", "stale_proof": "clock_skew", "wrong_audience": "auth", "expired": "auth"}


def err_for(code: str, default: str = "auth") -> str:
    return _ERR_FOR.get(code, default)


class FakeNode:
    def __init__(self, *, node_id: str, node_url: str, jwks: dict[str, Any], skew: int, randoms: dict[str, list[str]]):
        self.node_id = node_id
        self.node_url = node_url
        self.keys = c.parse_jwks(jwks)
        self.skew = skew
        # injected randomness first (a scenario is deterministic), fresh random words once it runs out (a live fake node)
        self.nonces = deque(randoms.get("nonces", []))
        self.stream_ids = deque(randoms.get("stream_ids", []))
        self.secrets = deque(randoms.get("secrets", []))
        self.conns: dict[str, dict[str, Any]] = {}
        self.seen: set[str] = set()
        self.streams: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------------------------------------------------------------------ plumbing

    def _conn(self, name: str) -> dict[str, Any]:
        return self.conns.setdefault(name, {"phase": "new", "claims": None, "session": None, "kind": "hello", "nonce": None, "waiting": False,
                                            "host": None, "status": None, "valid_until": 0, "sub": None, "hints": []})

    @staticmethod
    def _send(t: int, conn: str, line: str) -> dict[str, Any]:
        return {"t": t, "conn": conn, "ev": "send", "line": line}

    def _err(self, t: int, conn: str, code: str) -> list[dict[str, Any]]:
        return [self._send(t, conn, c.format_line("ERR", code=code))]

    # ------------------------------------------------------------------------------------------------------------ the entry point

    def handle(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        t = event["t"]
        kind = event["ev"]
        if kind == "recv":
            return self._recv(t, event["conn"], event["line"])
        if kind == "cp_reply":
            return self._cp_reply(t, event["conn"], event["status"], event["body"])
        if kind == "client_hello":
            return self._client_hello(t, event)
        if kind == "attach":
            return self._attach(t, event)
        if kind == "tick":
            return self._tick(t)
        return []

    # ------------------------------------------------------------------------------------------------------------ device lines

    def _recv(self, t: int, name: str, line: str) -> list[dict[str, Any]]:
        conn = self._conn(name)
        try:
            message = c.parse_line(line, "d2n")
        except c.ProtocolError as error:
            return self._err(t, name, error.code)
        verb = message["verb"]
        if verb in ("HELLO", "RENEW"):
            if conn["phase"] != ("new" if verb == "HELLO" else "ready"):  # RENEW only on a live connection: not mid-handshake, not after a CLOSE
                return self._err(t, name, "bad_command")
            result = c.verify_session(message["session"], now=t, audience=c.pol("identity.aud_tunnel"), keys=self.keys, skew=self.skew)
            if not result.ok:
                return self._err(t, name, err_for(result.error or ""))
            if verb == "RENEW" and result.claims["sub"] != conn["sub"]:
                return self._err(t, name, "auth")
            conn.update(session=message["session"], claims=result.claims, kind="hello" if verb == "HELLO" else "renew", waiting=False)
            if verb == "HELLO":
                conn["phase"] = "hello"
            conn["nonce"] = self.nonces.popleft() if self.nonces else c.b64u_encode(os.urandom(c.pol("protocol.nonce_bytes")))
            return [self._send(t, name, c.format_line("CHALLENGE", nonce=conn["nonce"]))]
        if verb == "PROOF":
            if conn["nonce"] is None:
                return self._err(t, name, "bad_command")
            result = c.verify_proof(message["proof"], now=t, session_token=conn["session"], session_claims=conn["claims"], nonce=conn["nonce"],
                                    htu=self.node_url, skew=self.skew, seen=self.seen)
            conn["nonce"] = None
            if not result.ok:
                return self._err(t, name, err_for(result.error or "", "bad_proof") if result.error != "replayed_jti" else "bad_proof")
            self.seen.add(result.jti or "")
            conn["waiting"] = True
            body = {"v": 1, "device_id": conn["claims"]["sub"], "session_jti": conn["claims"]["jti"], "reason": conn["kind"], "node": self.node_id}
            return [{"t": t, "conn": name, "ev": "cp", "call": "authorize", "body": body}]
        if verb == "PING":
            return [self._send(t, name, c.format_line("PONG"))]
        if verb == "HINT":
            conn["hints"] = message["addresses"]
            return []
        if verb == "CLOSE":
            conn["phase"] = "closed"
            return []
        return self._err(t, name, "bad_command")

    def _cp_reply(self, t: int, name: str, status: int, body: dict[str, Any]) -> list[dict[str, Any]]:
        conn = self._conn(name)
        if not conn["waiting"]:
            return []
        conn["waiting"] = False
        if status != 200:
            word = body.get("error") if isinstance(body, dict) else None
            known = {"license_inactive": "license_inactive", "device_revoked": "device_revoked", "paused": "paused"}
            return self._err(t, name, known.get(word, "control_unavailable" if status >= 500 or status == 429 else "auth"))
        if c.SCHEMAS.validate("authorize-response.schema.json", body) or body["device_id"] != conn["claims"]["sub"]:
            return self._err(t, name, "control_unavailable")
        out: list[dict[str, Any]] = []
        ok_body = {"v": 2, "node": self.node_id, "host": body["host"], "status": body["status"], "valid_until": body["valid_until"],
                   "server_time": body["server_time"], "policy": body["policy"]}
        out.append(self._send(t, name, c.format_line("OK", body=ok_body)))
        conn.update(phase="ready", host=body["host"], status=body["status"], valid_until=body["valid_until"], sub=conn["claims"]["sub"])
        for other_name, other in self.conns.items():
            if other_name != name and other["phase"] == "ready" and other["sub"] == conn["sub"]:
                other["phase"] = "closed"
                out.append(self._send(t, other_name, c.format_line("CLOSE", reason="replaced")))
        return out

    # ------------------------------------------------------------------------------------------------------------ clients and streams

    def _client_hello(self, t: int, event: dict[str, Any]) -> list[dict[str, Any]]:
        sni = event["sni"]
        if not event["complete"]:
            return [{"t": t, "ev": "tls_alert", "sni": sni}]
        for name, conn in self.conns.items():
            if conn["phase"] == "ready" and conn["host"] == sni and conn["status"] != "paused" and t < conn["valid_until"]:
                stream_id = self.stream_ids.popleft() if self.stream_ids else os.urandom(c.pol("protocol.stream_id_bytes")).hex()
                secret = self.secrets.popleft() if self.secrets else c.b64u_encode(os.urandom(c.pol("protocol.attach_secret_bytes")))
                self.streams[stream_id] = {"secret": secret, "t": t, "consumed": False}
                line = c.format_line("OPEN", stream_id=stream_id, secret=secret, peer_ip=event["peer_ip"], **{"class": event["class"]})
                return [self._send(t, name, line)]
        return [{"t": t, "ev": "tls_alert", "sni": sni}]

    def _attach(self, t: int, event: dict[str, Any]) -> list[dict[str, Any]]:
        out = {"t": t, "conn": event["conn"], "ev": "attach", "line": event["line"], "result": "err"}
        try:
            message = c.parse_line(event["line"], "d2n")
        except c.ProtocolError:
            return [out]
        known = self.streams.get(message["stream_id"])
        if (known is not None and known["secret"] == message["secret"] and not known["consumed"]
                and t - known["t"] <= c.pol("protocol.attach_timeout_s")):
            known["consumed"] = True
            out["result"] = "ok"
        return [out]

    def _tick(self, t: int) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for name, conn in self.conns.items():
            if conn["phase"] == "ready" and t >= conn["valid_until"]:
                conn["phase"] = "closed"
                out.append(self._send(t, name, c.format_line("CLOSE", reason="expired")))
        return out


INPUT_EVENTS = ("recv", "cp_reply", "client_hello", "attach", "tick", "end")


def split_transcript(events: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(inputs, outputs) of a golden transcript: what was done to the node and what it did. An `attach` is an input without its result."""
    inputs: list[dict[str, Any]] = []
    outputs: list[dict[str, Any]] = []
    for event in events:
        if event["ev"] in INPUT_EVENTS:
            inputs.append({k: v for k, v in event.items() if k != "result"} if event["ev"] == "attach" else event)
        if event["ev"] in ("send", "cp", "tls_alert") or event["ev"] == "attach":
            outputs.append(event)
    return inputs, outputs


def replay(ctx: dict[str, Any], events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Run the fake node over the inputs of a transcript and return the outputs it produced, in order."""
    inputs, _ = split_transcript(events)
    node = FakeNode(node_id=ctx["node_id"], node_url=ctx["node_url"], jwks=ctx["jwks"], skew=ctx["skew"], randoms=ctx["randoms"])
    produced: list[dict[str, Any]] = []
    for event in inputs:
        produced.extend(node.handle(event))
    return produced


def rebuild(ctx: dict[str, Any], inputs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The full transcript (inputs and outputs interleaved as they happened) for scripted inputs: what the transcript generator stores."""
    node = FakeNode(node_id=ctx["node_id"], node_url=ctx["node_url"], jwks=ctx["jwks"], skew=ctx["skew"], randoms=ctx["randoms"])
    events: list[dict[str, Any]] = []
    for event in inputs:
        outs = node.handle(event)
        if event["ev"] == "attach":
            events.extend(outs)  # the node's own record of the attach carries the result
        else:
            events.append(event)
            events.extend(outs)
    return events


# ---------------------------------------------------------------------------------------------------------------------------------- sockets

ControlPlane = Callable[[dict[str, Any]], "tuple[int, dict[str, Any]] | Awaitable[tuple[int, dict[str, Any]]]"]


class OpenedStream:
    """A client stream the fake node opened for a device: `stream_id` and `secret` are what the device's ATTACH must carry; `attached` resolves
    to (reader, writer) of the node's end of the data connection once the device attached (bytes written go to the device, bytes read come from it)."""

    def __init__(self, stream_id: str, secret: str, peer_ip: str, cls: str, attached: "asyncio.Future[tuple[asyncio.StreamReader, asyncio.StreamWriter]]"):
        self.stream_id, self.secret, self.peer_ip, self.cls, self.attached = stream_id, secret, peer_ip, cls, attached


class FakeNodeServer:
    """The fake node over real sockets: a TCP (or TLS, with `ssl_context`) listener that speaks protocol v2 lines, the state machine above behind it.

    `control_plane(body)` answers the node's authorize call (it is given the request body, returns (status, body); sync or async). `clock()` is the
    node's time in whole seconds. `open_stream(sni, ...)` plays a client that connected to :443 with that SNI: when the node opens a stream for it,
    the result says so and its `attached` future resolves when the device dials back with the right ATTACH. Nothing here is used by an installed ALL.
    """

    def __init__(self, *, node_id: str, node_url: str, jwks: dict[str, Any], control_plane: ControlPlane, skew: int | None = None,
                 clock: Callable[[], int] | None = None, tick_interval: float = 1.0):
        self.node = FakeNode(node_id=node_id, node_url=node_url, jwks=jwks, skew=c.pol("authorization.node_skew_s") if skew is None else skew, randoms={})
        self.control_plane = control_plane
        self.clock = clock or (lambda: int(time.time()))
        self.tick_interval = tick_interval
        self.writers: dict[str, asyncio.StreamWriter] = {}
        self.lines: list[tuple[str, str, str]] = []  # (direction, connection, line): what crossed the wire, for the tests
        self._opened: dict[str, OpenedStream] = {}
        self._open_writers: set[asyncio.StreamWriter] = set()  # every accepted connection, control and data
        self._count = 0
        self._server: asyncio.AbstractServer | None = None
        self._ticker: asyncio.Task[None] | None = None
        self.port = 0

    async def start(self, host: str = "127.0.0.1", port: int = 0, ssl_context: Any = None) -> int:
        limit = c.pol("protocol.statement_line_max_bytes") + 16
        self._server = await asyncio.start_server(self._serve, host, port, ssl=ssl_context, limit=limit)
        self.port = self._server.sockets[0].getsockname()[1]
        self._ticker = asyncio.create_task(self._tick_loop())
        return self.port

    async def stop(self) -> None:
        if self._ticker:
            self._ticker.cancel()
        for writer in list(self._open_writers):
            writer.close()
        if self._server:
            self._server.close()
            try:
                await asyncio.wait_for(self._server.wait_closed(), 2)
            except asyncio.TimeoutError:
                pass

    async def _tick_loop(self) -> None:
        while True:
            await asyncio.sleep(self.tick_interval)
            await self.tick()

    async def tick(self) -> None:
        await self._dispatch(self.node.handle({"t": self.clock(), "ev": "tick"}))

    def drop_control(self, name: str) -> None:
        """Cut one control connection (a node restart, a network drop)."""
        writer = self.writers.pop(name, None)
        if writer:
            writer.close()

    async def open_stream(self, sni: str, *, peer_ip: str = "203.0.113.9", cls: str = "anon", complete: bool = True) -> OpenedStream | None:
        """A client with this SNI arrives. None when the node would send a TLS alert (unknown name, paused, expired, incomplete ClientHello)."""
        outputs = self.node.handle({"t": self.clock(), "ev": "client_hello", "sni": sni, "complete": complete, "peer_ip": peer_ip, "class": cls})
        opened = None
        for event in outputs:
            if event["ev"] == "send" and event["line"].startswith("OPEN "):
                message = c.parse_line(event["line"], "n2d")
                opened = OpenedStream(message["stream_id"], message["secret"], peer_ip, cls, asyncio.get_running_loop().create_future())
                self._opened[opened.stream_id] = opened
        await self._dispatch(outputs)
        return opened

    async def _dispatch(self, outputs: list[dict[str, Any]]) -> None:
        pending = list(outputs)
        while pending:
            event = pending.pop(0)
            if event["ev"] == "send":
                writer = self.writers.get(event["conn"])
                line = event["line"]
                self.lines.append(("send", event["conn"], line))
                if writer is None:
                    continue
                writer.write(line.encode("ascii") + b"\n")
                await writer.drain()
                refused = line.startswith("ERR ") and self.node.conns[event["conn"]]["phase"] == "new"
                if line.startswith("CLOSE ") or refused:
                    writer.close()
                    self.writers.pop(event["conn"], None)
            elif event["ev"] == "cp":
                reply = self.control_plane(event["body"])
                if asyncio.iscoroutine(reply):
                    reply = await reply
                status, body = reply
                pending.extend(self.node.handle({"t": self.clock(), "ev": "cp_reply", "conn": event["conn"], "status": status, "body": body}))

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._count += 1
        name = f"c{self._count}"
        self._open_writers.add(writer)
        try:
            first = await asyncio.wait_for(self._read(reader), c.pol("protocol.first_line_timeout_s"))
            if first is None:
                return
            if first.startswith("ATTACH "):
                await self._data(name, first, reader, writer)
                return
            self.writers[name] = writer
            line: str | None = first
            while line is not None:
                self.lines.append(("recv", name, line))
                await self._dispatch(self.node.handle({"t": self.clock(), "ev": "recv", "conn": name, "line": line}))
                if name not in self.writers:
                    break
                line = await self._read(reader)
        except (asyncio.TimeoutError, ConnectionError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            pass
        finally:
            self._open_writers.discard(writer)
            if self.writers.get(name) is writer:
                self.writers.pop(name, None)
                writer.close()

    @staticmethod
    async def _read(reader: asyncio.StreamReader) -> str | None:
        try:
            raw = await reader.readuntil(b"\n")
        except asyncio.IncompleteReadError:
            return None
        return raw[:-1].decode("ascii", errors="replace")

    async def _data(self, name: str, line: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        outputs = self.node.handle({"t": self.clock(), "ev": "attach", "conn": name, "line": line})
        if outputs[0]["result"] != "ok":
            writer.write(b"ERR auth\n")
            await writer.drain()
            writer.close()
            return
        message = c.parse_line(line, "d2n")
        opened = self._opened.get(message["stream_id"])
        if opened is not None and not opened.attached.done():
            opened.attached.set_result((reader, writer))

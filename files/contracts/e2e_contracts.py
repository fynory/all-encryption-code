"""ALL 2.0 contracts, Python reference verifier (the contract).

The spec is `contracts/policy.json` (every constant), `contracts/schemas/` (shapes, line grammar) and `contracts/vectors/` (golden inputs and the
verdict every verifier must give). This module is the Python implementation of the checks the vectors exercise; the Go one is
`tunnel/contracts_test.go` and the TypeScript one is `contracts/ts/verify.ts`. All three give the same verdict AND the same error word for
every vector (the contract test suite, tunnel/contracts_test.go, the Worker contract test). It is a reference for tests and
for the Python fake node (fake_node.py): production code is written by the packages that own it, and reads the numbers from policy.json.

What it checks, in this order of failure (the first failing step names the error):
  * lines     parse_line / format_line (the wire grammar of schemas/wire-v2.grammar.json)
  * bodies    Schemas.validate (the JSON Schema subset the schemas use) and check_feed (the cross-field rules of the feed)
  * tokens    verify_session, verify_proof (DPoP), verify_node_assertion, verify_statement, parse_jwks, parse_node_keys
  * surface   surface_mac / surface_proof (the HMAC identity proof of the E2E listener)
  * names     label_ok / fqdn_ok
  * nodes     check_transcript (does a recorded node behave as the contract demands: renew re-authorizes, host from the control plane only...)
Pure functions: the clock, the replay set and the key sets are arguments, never globals.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parent
POLICY_PATH = ROOT / "policy.json"
SCHEMA_DIR = ROOT / "schemas"
VECTOR_DIR = ROOT / "vectors"


def load_policy(path: Path | None = None) -> dict[str, Any]:
    return json.loads((path or POLICY_PATH).read_text(encoding="utf-8"))


POLICY = load_policy()


def pol(dotted: str, policy: dict[str, Any] | None = None) -> Any:
    """`pol("protocol.line_max_bytes")`: the one way this module reads a number."""
    value: Any = POLICY if policy is None else policy
    for part in dotted.split("."):
        value = value[part]
    return value


# ------------------------------------------------------------------------------------------------------------------------ regular expressions

def compile_anchored(pattern: str) -> re.Pattern[str]:
    """Every pattern of the contracts is written ^...$ and means "the whole string": Python's `$` also matches before a final newline, so the
    anchors are dropped and `fullmatch` is used (JavaScript and Go anchor strictly by themselves)."""
    if not (pattern.startswith("^") and pattern.endswith("$")):
        raise ValueError("contract patterns are anchored: " + pattern)
    return re.compile(pattern[1:-1])


LABEL_RE = compile_anchored(pol("identity.label_regex"))
FQDN_RE = compile_anchored(pol("identity.fqdn_regex"))
DEVICE_ID_RE = compile_anchored(pol("identity.device_id_regex"))
STREAM_ID_RE = compile_anchored(pol("identity.stream_id_regex"))
ATTACH_SECRET_RE = compile_anchored(pol("identity.attach_secret_regex"))
NONCE_RE = compile_anchored(pol("identity.nonce_regex"))
JTI_RE = compile_anchored(pol("identity.jti_regex"))
KID_RE = compile_anchored(pol("identity.kid_regex"))


def label_ok(value: Any) -> bool:
    return isinstance(value, str) and LABEL_RE.fullmatch(value) is not None


def host_pattern(zone: str) -> re.Pattern[str]:
    """The detector a device (or a node) builds for ITS OWN address in a zone: the policy's label pattern, one dot, the zone. The label part is
    never typed again anywhere (the lint refuses a copy of it). Anchored with \\A and \\Z (not `$`, which also matches before a final newline), so
    match, search and fullmatch all give the verdict the Go and TypeScript detectors give."""
    return re.compile(r"\A" + pol("identity.label_regex")[1:-1] + r"\." + re.escape(zone) + r"\Z")


def fqdn_ok(value: Any, zones: list[str] | None = None) -> bool:
    """A device host: <label>.<zone>. With `zones`, the part after the label must be one of them (several zones are allowed by the contract)."""
    if not isinstance(value, str) or len(value) > pol("identity.fqdn_max_length") or FQDN_RE.fullmatch(value) is None:
        return False
    return zones is None or value.split(".", 1)[1] in zones


# ------------------------------------------------------------------------------------------------------------------------ base64url, JSON

def b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


_B64U = re.compile(r"[A-Za-z0-9_-]+")


def b64u_decode(text: str) -> bytes:
    """Strict: the URL alphabet only, no padding, and the canonical encoding (re-encoding gives the same text)."""
    if not isinstance(text, str) or not _B64U.fullmatch(text):
        raise ValueError("base64url")
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if b64u_encode(raw) != text:
        raise ValueError("base64url")
    return raw


def sha256_b64u(data: bytes | str) -> str:
    return b64u_encode(hashlib.sha256(data.encode("utf-8") if isinstance(data, str) else data).digest())


def canonical_json(value: Any) -> str:
    """The form of a JSON body on a wire line: keys sorted, no whitespace, ASCII only. Bodies hold integers, never floats."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _no_floats(value: Any) -> Any:
    if isinstance(value, float):
        if value.is_integer():
            return int(value)
        raise ValueError("float")
    if isinstance(value, dict):
        return {k: _no_floats(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_no_floats(v) for v in value]
    return value


def loads(text: str) -> Any:
    """json.loads that refuses duplicate keys, NaN and Infinity (a body with a repeated key is ambiguous between implementations)."""
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, item in items:
            if key in out:
                raise ValueError("duplicate key")
            out[key] = item
        return out

    def constant(_: str) -> Any:
        raise ValueError("constant")

    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)


# ------------------------------------------------------------------------------------------------------------------------ JSON Schema subset

def valid_ip(value: Any) -> bool:
    """`format: ip`: a textual IPv4 or IPv6 address, lower case, no zone, no brackets, no spaces."""
    if not isinstance(value, str) or not value or value != value.lower() or any(c in value for c in "%[] \t\r\n/"):
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _type_ok(kind: str, value: Any) -> bool:
    if kind == "string":
        return isinstance(value, str)
    if kind == "boolean":
        return isinstance(value, bool)
    if kind == "null":
        return value is None
    if kind == "object":
        return isinstance(value, dict)
    if kind == "array":
        return isinstance(value, list)
    if kind == "integer":
        return (isinstance(value, int) and not isinstance(value, bool)) or (isinstance(value, float) and value.is_integer())
    if kind == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return False


def _equal(a: Any, b: Any) -> bool:
    """JSON equality: 1 is not true, 1 == 1.0, objects by content."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_equal(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_equal(x, y) for x, y in zip(a, b))
    return type(a) is type(b) and a == b


class Schemas:
    """The schemas of contracts/schemas/ by file name, and a validator for the keywords they use: $ref, type, const, enum, pattern, format
    (ip), minLength, maxLength, minimum, maximum, required, properties, additionalProperties (false), items, minItems, maxItems, uniqueItems,
    oneOf. Anything else in a schema is ignored (titles, $comment, $id), so a keyword added later must be added to all three validators."""

    def __init__(self, directory: Path | None = None):
        self.docs: dict[str, Any] = {}
        for path in sorted((directory or SCHEMA_DIR).glob("*.schema.json")):
            self.docs[path.name] = json.loads(path.read_text(encoding="utf-8"))
        self._patterns: dict[str, re.Pattern[str]] = {}

    def validate(self, name: str, instance: Any) -> list[str]:
        errors: list[str] = []
        self._check(name, self.docs[name], instance, "", errors)
        return errors

    def _resolve(self, doc: str, ref: str) -> tuple[str, Any]:
        file, _, pointer = ref.partition("#")
        target = file or doc
        node: Any = self.docs[target]
        if pointer:
            for part in pointer.lstrip("/").split("/"):
                node = node[part.replace("~1", "/").replace("~0", "~")]
        return target, node

    def _pattern(self, text: str) -> re.Pattern[str]:
        if text not in self._patterns:
            self._patterns[text] = compile_anchored(text)
        return self._patterns[text]

    def _check(self, doc: str, schema: Any, value: Any, path: str, errors: list[str]) -> None:
        if "$ref" in schema:
            target, node = self._resolve(doc, schema["$ref"])
            self._check(target, node, value, path, errors)
        if "const" in schema and not _equal(value, schema["const"]):
            errors.append(f"{path or '/'}: const")
        if "enum" in schema and not any(_equal(value, item) for item in schema["enum"]):
            errors.append(f"{path or '/'}: enum")
        if "type" in schema:
            kinds = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
            if not any(_type_ok(kind, value) for kind in kinds):
                errors.append(f"{path or '/'}: type")
                return
        if "oneOf" in schema:
            hits = 0
            for option in schema["oneOf"]:
                trial: list[str] = []
                self._check(doc, option, value, path, trial)
                hits += not trial
            if hits != 1:
                errors.append(f"{path or '/'}: oneOf")
        if isinstance(value, str):
            if "minLength" in schema and len(value) < schema["minLength"]:
                errors.append(f"{path or '/'}: minLength")
            if "maxLength" in schema and len(value) > schema["maxLength"]:
                errors.append(f"{path or '/'}: maxLength")
            if "pattern" in schema and self._pattern(schema["pattern"]).fullmatch(value) is None:
                errors.append(f"{path or '/'}: pattern")
            if schema.get("format") == "ip" and not valid_ip(value):
                errors.append(f"{path or '/'}: format")
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if "minimum" in schema and value < schema["minimum"]:
                errors.append(f"{path or '/'}: minimum")
            if "maximum" in schema and value > schema["maximum"]:
                errors.append(f"{path or '/'}: maximum")
        if isinstance(value, dict):
            for key in schema.get("required", []):
                if key not in value:
                    errors.append(f"{path}/{key}: required")
            props = schema.get("properties", {})
            for key, item in value.items():
                if key in props:
                    self._check(doc, props[key], item, f"{path}/{key}", errors)
                elif schema.get("additionalProperties") is False:
                    errors.append(f"{path}/{key}: additionalProperties")
        if isinstance(value, list):
            if "minItems" in schema and len(value) < schema["minItems"]:
                errors.append(f"{path or '/'}: minItems")
            if "maxItems" in schema and len(value) > schema["maxItems"]:
                errors.append(f"{path or '/'}: maxItems")
            if schema.get("uniqueItems") and any(_equal(a, b) for i, a in enumerate(value) for b in value[i + 1:]):
                errors.append(f"{path or '/'}: uniqueItems")
            if "items" in schema:
                for index, item in enumerate(value):
                    self._check(doc, schema["items"], item, f"{path}/{index}", errors)


# ------------------------------------------------------------------------------------------------------------------------ the wire grammar

class ProtocolError(Exception):
    """A line that is not valid. `code` is one of protocol.error_codes: the word the node answers with (ERR <code>)."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


GRAMMAR = json.loads((SCHEMA_DIR / "wire-v2.grammar.json").read_text(encoding="utf-8"))
SCHEMAS = Schemas()


def _field_ok(kind: str, token: str) -> bool:
    spec = GRAMMAR["types"][kind]
    if "max_bytes_from" in spec and len(token) > pol(spec["max_bytes_from"]):
        return False
    if "pattern" in spec and compile_anchored(spec["pattern"]).fullmatch(token) is None:
        return False
    if spec.get("format") == "ip" and not valid_ip(token):
        return False
    if "enum_from" in spec and token not in pol(spec["enum_from"]):
        return False
    return True


def parse_line(line: str, direction: str) -> dict[str, Any]:
    """Parse one protocol line (the text before the LF) travelling in `direction` ("d2n" or "n2d"). Returns {"verb": ..., <field>: ...}; HINT
    gives "addresses", OK gives "body". Raises ProtocolError."""
    if not isinstance(line, str) or any(not 0x20 <= ord(c) <= 0x7E for c in line):
        raise ProtocolError("bad_command")
    verb, space, rest = line.partition(" ")
    spec = GRAMMAR["verbs"].get(verb)
    cap = pol(spec["max"]) if spec and "max" in spec else pol("protocol.line_max_bytes")
    if len(line) + 1 > cap:
        raise ProtocolError("line_too_long")
    if spec is None or spec["dir"] not in (direction, "both") or line == "" or (space and rest == ""):
        raise ProtocolError("bad_command")
    out: dict[str, Any] = {"verb": verb}
    if "json" in spec:
        if not space:
            raise ProtocolError("bad_command")
        try:
            body = _no_floats(loads(rest))
        except ValueError:
            raise ProtocolError("bad_command") from None
        if SCHEMAS.validate(spec["json"], body):
            raise ProtocolError("bad_command")
        out["body"] = body
        return out
    tokens = rest.split(" ") if space else []
    if any(token == "" for token in tokens):
        raise ProtocolError("bad_command")
    if "repeat" in spec:
        rule = spec["repeat"]
        if not rule["min"] <= len(tokens) <= pol(rule["max_from"]) or not all(_field_ok(rule["type"], t) for t in tokens):
            raise ProtocolError("bad_command")
        out["addresses"] = tokens
        return out
    fields = spec.get("fields", [])
    optional = spec.get("optional", [])
    if not len(fields) <= len(tokens) <= len(fields) + len(optional):
        raise ProtocolError("bad_command")
    for rule, token in zip(fields + optional, tokens):
        if "equals" in rule and token != rule["equals"]:
            raise ProtocolError(rule["error_if_number"] if _field_ok(rule["type"], token) else "bad_command")
        if not _field_ok(rule["type"], token):
            raise ProtocolError(rule.get("error", "bad_command"))
        out[rule["name"]] = token
    return out


def format_line(verb: str, **fields: Any) -> str:
    """The canonical line for a message (the inverse of parse_line, which it is checked against): the field values in grammar order; OK takes
    `body`, HINT takes `addresses`. Raises ProtocolError when the result would not parse."""
    spec = GRAMMAR["verbs"][verb]
    if "json" in spec:
        line = f"{verb} {canonical_json(fields['body'])}"
    elif "repeat" in spec:
        line = " ".join([verb, *fields["addresses"]])
    else:
        names = [rule["name"] for rule in spec.get("fields", []) + spec.get("optional", []) if rule["name"] in fields]
        line = " ".join([verb, *(str(fields[name]) for name in names)])
    direction = "d2n" if spec["dir"] == "both" else spec["dir"]
    parse_line(line, direction)
    return line


# ------------------------------------------------------------------------------------------------------------------------ tokens

@dataclass
class Result:
    ok: bool
    error: str | None = None
    claims: dict[str, Any] = field(default_factory=dict)
    jti: str | None = None

    @staticmethod
    def fail(code: str) -> "Result":
        return Result(False, code)


class Reject(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _jws_parts(token: Any, max_bytes: int) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    try:
        if not isinstance(token, str) or not token.isascii() or len(token) > max_bytes:
            raise ValueError()
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError()
        header = loads(b64u_decode(parts[0]).decode("utf-8"))
        claims = loads(b64u_decode(parts[1]).decode("utf-8"))
        signature = b64u_decode(parts[2]) if parts[2] else b""
        if not isinstance(header, dict) or not isinstance(claims, dict):
            raise ValueError()
        if any(name in header for name in ("crit", "b64", "jku", "x5u", "x5c")):
            raise ValueError()
        claims = _no_floats(claims)
    except (ValueError, UnicodeError):
        raise Reject("malformed_token") from None
    return header, claims, signature, f"{parts[0]}.{parts[1]}".encode("ascii")


def _ed25519_ok(x: str, signature: bytes, signing_input: bytes) -> bool:
    """Ed25519 verification; a signature that is not 64 bytes is simply not valid."""
    if len(signature) != 64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(b64u_decode(x)).verify(signature, signing_input)
        return True
    except (InvalidSignature, ValueError):
        return False


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _jwk_x(value: Any) -> str:
    """The `x` of a public Ed25519 JWK (kty OKP, crv Ed25519, no private part), or a Reject."""
    if (not isinstance(value, dict) or value.get("kty") != "OKP" or value.get("crv") != "Ed25519" or "d" in value
            or not isinstance(value.get("x"), str) or len(value["x"]) != 43):
        raise Reject("malformed_token")
    try:
        if len(b64u_decode(value["x"])) != 32:
            raise ValueError()
    except ValueError:
        raise Reject("malformed_token") from None
    return value["x"]


def parse_jwks(jwks: Any) -> dict[str, str]:
    """kid -> x of the control plane's keys (schemas/jwks.schema.json, at most policy.jwks.max_keys, no repeated kid), or Reject("bad_jwks")."""
    if SCHEMAS.validate("jwks.schema.json", jwks):
        raise Reject("bad_jwks")
    keys: dict[str, str] = {}
    for key in jwks["keys"]:
        if key["kid"] in keys:
            raise Reject("bad_jwks")
        keys[key["kid"]] = key["x"]
    return keys


def parse_node_keys(doc: Any) -> dict[str, tuple[str, str]]:
    """kid -> (node id, x) of TUNNEL_NODE_KEYS, or Reject("bad_node_keys")."""
    if SCHEMAS.validate("node-keys.schema.json", doc):
        raise Reject("bad_node_keys")
    keys: dict[str, tuple[str, str]] = {}
    for key in doc["keys"]:
        if key["kid"] in keys:
            raise Reject("bad_node_keys")
        keys[key["kid"]] = (key["node"], key["x"])
    return keys


def _signed_by_jwks(token: Any, keys: dict[str, str], typ: str) -> tuple[dict[str, Any], dict[str, Any]]:
    header, claims, signature, signing_input = _jws_parts(token, pol("protocol.statement_line_max_bytes"))
    if header.get("alg") != "EdDSA":
        raise Reject("bad_alg")
    kid = header.get("kid")
    if not isinstance(kid, str) or KID_RE.fullmatch(kid) is None or kid not in keys:
        raise Reject("unknown_kid")
    if not _ed25519_ok(keys[kid], signature, signing_input):
        raise Reject("bad_signature")
    if header.get("typ") != typ or claims.get("typ") != typ:
        raise Reject("wrong_type")
    return header, claims


def _claim_ok(claims: dict[str, Any], schema: str, ignore: tuple[str, ...] = ()) -> bool:
    """Shape of the claims by their schema, without the keywords checked earlier under their own error word."""
    errors = SCHEMAS.validate(schema, claims)
    return not [e for e in errors if not any(e.startswith(f"/{name}:") for name in ignore)]


def verify_session(token: Any, *, now: int, audience: str, keys: dict[str, str], skew: int) -> Result:
    """A device session (typ device-session, ver 2) as the node must accept it at HELLO and RENEW. Order of failure: malformed_token, bad_alg,
    unknown_kid, bad_signature, wrong_type, wrong_issuer, wrong_audience, bad_claims, bad_lifetime, not_yet_valid, expired."""
    try:
        if not isinstance(token, str) or len(token) > pol("protocol.jwt_max_bytes"):
            raise Reject("malformed_token")
        _, claims = _signed_by_jwks(token, keys, "device-session")
        if claims.get("ver") != 2 or isinstance(claims.get("ver"), bool):
            raise Reject("wrong_type")
        if claims.get("iss") != pol("identity.issuer"):
            raise Reject("wrong_issuer")
        if claims.get("aud") != audience:
            raise Reject("wrong_audience")
        if not _claim_ok(claims, "session-claims.schema.json", ("aud",)):
            raise Reject("bad_claims")
        if claims["exp"] - claims["iat"] != pol("authorization.session_ttl_s"):
            raise Reject("bad_lifetime")
        if claims["iat"] > now + skew:
            raise Reject("not_yet_valid")
        if claims["exp"] <= now:
            raise Reject("expired")
        return Result(True, claims=claims, jti=claims["jti"])
    except Reject as reject:
        return Result.fail(reject.code)


def verify_proof(proof: Any, *, now: int, session_token: str, session_claims: dict[str, Any], nonce: str, htu: str, skew: int,
                 seen: set[str] | frozenset[str]) -> Result:
    """The DPoP proof of PROOF. Order of failure: malformed_token, bad_alg, wrong_type, wrong_key, bad_signature, wrong_subject,
    wrong_audience, wrong_htm, wrong_htu, wrong_ath, wrong_nonce, bad_claims, not_yet_valid, stale_proof, replayed_jti."""
    try:
        if not isinstance(proof, str) or len(proof) > pol("protocol.jwt_max_bytes"):
            raise Reject("malformed_token")
        header, claims, signature, signing_input = _jws_parts(proof, pol("protocol.jwt_max_bytes"))
        if header.get("alg") != "EdDSA":
            raise Reject("bad_alg")
        if header.get("typ") != "dpop+jwt":
            raise Reject("wrong_type")
        x = _jwk_x(header.get("jwk"))
        if x != session_claims["cnf"]["jwk"]["x"]:
            raise Reject("wrong_key")
        if not _ed25519_ok(x, signature, signing_input):
            raise Reject("bad_signature")
        if claims.get("sub") != session_claims["sub"]:
            raise Reject("wrong_subject")
        if claims.get("aud") != pol("identity.aud_tunnel"):
            raise Reject("wrong_audience")
        if claims.get("htm") != pol("protocol.proof_htm"):
            raise Reject("wrong_htm")
        if claims.get("htu") != htu:
            raise Reject("wrong_htu")
        if claims.get("ath") != sha256_b64u(session_token):
            raise Reject("wrong_ath")
        if claims.get("nonce") != nonce:
            raise Reject("wrong_nonce")
        if not _claim_ok(claims, "proof-claims.schema.json", ("htu",)):
            raise Reject("bad_claims")
        if claims["iat"] > now + skew:
            raise Reject("not_yet_valid")
        if claims["iat"] + pol("authorization.proof_ttl_s") <= now:
            raise Reject("stale_proof")
        if claims["jti"] in seen:
            raise Reject("replayed_jti")
        return Result(True, claims=claims, jti=claims["jti"])
    except Reject as reject:
        return Result.fail(reject.code)


def verify_node_assertion(token: Any, *, now: int, keys: dict[str, tuple[str, str]], method: str, url: str, body: bytes, skew: int,
                          seen: set[str] | frozenset[str]) -> Result:
    """A node's request authentication (header x-all-node-assertion). Order of failure: malformed_token, bad_alg, unknown_kid, bad_signature,
    wrong_type, wrong_audience, wrong_subject, wrong_htm, wrong_htu, bad_claims, bad_lifetime, not_yet_valid, expired, wrong_body_hash,
    replayed_jti."""
    try:
        header, claims, signature, signing_input = _jws_parts(token, pol("protocol.jwt_max_bytes"))
        if header.get("alg") != "EdDSA":
            raise Reject("bad_alg")
        kid = header.get("kid")
        if not isinstance(kid, str) or KID_RE.fullmatch(kid) is None or kid not in keys:
            raise Reject("unknown_kid")
        node, x = keys[kid]
        if not _ed25519_ok(x, signature, signing_input):
            raise Reject("bad_signature")
        if header.get("typ") != "node-assertion" or claims.get("typ") != "node-assertion" or claims.get("ver") != 1:
            raise Reject("wrong_type")
        if claims.get("aud") != pol("identity.aud_node_assertion"):
            raise Reject("wrong_audience")
        if claims.get("sub") != node:
            raise Reject("wrong_subject")
        if claims.get("htm") != method:
            raise Reject("wrong_htm")
        if claims.get("htu") != url:
            raise Reject("wrong_htu")
        if not _claim_ok(claims, "node-assertion-claims.schema.json", ("htm", "htu", "aud", "sub")):
            raise Reject("bad_claims")
        if claims["exp"] - claims["iat"] != pol("authorization.node_assertion_ttl_s"):
            raise Reject("bad_lifetime")
        if claims["iat"] > now + skew:
            raise Reject("not_yet_valid")
        if claims["exp"] <= now:
            raise Reject("expired")
        if claims["bh"] != sha256_b64u(body):
            raise Reject("wrong_body_hash")
        if claims["jti"] in seen:
            raise Reject("replayed_jti")
        return Result(True, claims=claims, jti=claims["jti"])
    except Reject as reject:
        return Result.fail(reject.code)


def verify_statement(token: Any, *, now: int, keys: dict[str, str], device_id: str, last_seq: int) -> Result:
    """The control plane's signed access statement as the device must accept it (STATEMENT, authorize). Order of failure: malformed_token,
    bad_alg, unknown_kid, bad_signature, wrong_type, wrong_issuer, wrong_audience, wrong_subject, bad_claims, bad_lifetime, not_yet_valid,
    stale_seq. A statement that has merely EXPIRED still verifies (a stored paywall keeps gating): the caller compares exp with its own clock.
    last_seq is the highest seq accepted so far (0 for none); the same seq again is accepted (idempotent), a lower one is stale_seq."""
    try:
        _, claims = _signed_by_jwks(token, keys, "device-access")
        if claims.get("ver") != 1 or isinstance(claims.get("ver"), bool):
            raise Reject("wrong_type")
        if claims.get("iss") != pol("identity.issuer"):
            raise Reject("wrong_issuer")
        if claims.get("aud") != pol("identity.aud_access"):
            raise Reject("wrong_audience")
        if claims.get("sub") != device_id:
            raise Reject("wrong_subject")
        if (not _claim_ok(claims, "statement-claims.schema.json", ("aud", "sub")) or ("paywall" in claims) != (claims["mode"] == "paywall")
                or ("paused" in claims and "resumed" in claims)):
            raise Reject("bad_claims")
        ttl = claims["exp"] - claims["iat"]
        if not 0 < ttl <= pol("authorization.access_ttl_paywall_s" if claims["mode"] == "paywall" else "authorization.access_ttl_paid_s"):
            raise Reject("bad_lifetime")
        if claims["iat"] > now + pol("authorization.access_future_slack_s"):
            raise Reject("not_yet_valid")
        if claims["seq"] < last_seq:
            raise Reject("stale_seq")
        return Result(True, claims=claims, jti=claims["jti"])
    except Reject as reject:
        return Result.fail(reject.code)


# ------------------------------------------------------------------------------------------------------------------------ the feed

def check_feed(body: Any, since: int) -> list[str]:
    """Schema plus the rules a schema cannot say: events strictly increasing, all after `since`, epoch not below the last event, and the two
    global events (kill, kill_clear) carry no device, every other event carries both device and label."""
    errors = SCHEMAS.validate("feed-response.schema.json", body)
    if errors:
        return errors
    previous = since
    for index, event in enumerate(body["events"]):
        if event["epoch"] <= previous:
            errors.append(f"/events/{index}: order")
        previous = max(previous, event["epoch"])
        is_global = event["type"] in ("kill", "kill_clear")
        if is_global != (event["device_id"] is None and event["label"] is None):
            errors.append(f"/events/{index}: scope")
        if (event["device_id"] is None) != (event["label"] is None):
            errors.append(f"/events/{index}: scope")
    if body["epoch"] < previous:
        errors.append("/epoch: behind events")
    return errors


# ------------------------------------------------------------------------------------------------------------------------ surface identity proof

def _surface_key(secret: str) -> bytes:
    raw = b64u_decode(secret)
    if len(raw) != 32:
        raise ValueError("secret")
    return raw


def surface_mac(secret: str, nonce: str) -> str:
    """The MAC the terminator puts on its challenge: only a holder of the per-start secret (the agent) gets an answer; anybody else gets a 404."""
    return b64u_encode(hmac.new(_surface_key(secret), b"all-surface-challenge-v1\n" + nonce.encode("ascii"), hashlib.sha256).digest())


def surface_proof(secret: str, nonce: str, pid: int, port: int) -> str:
    """What the listener answers: it proves it holds the secret of the process surfaces.json names, for this nonce, pid and port."""
    message = b"all-surface-proof-v1\n" + nonce.encode("ascii") + b"\n" + str(pid).encode() + b"\n" + str(port).encode()
    return b64u_encode(hmac.new(_surface_key(secret), message, hashlib.sha256).digest())


def verify_surface_challenge(secret: str, nonce: str, mac: Any) -> Result:
    try:
        if not isinstance(nonce, str) or NONCE_RE.fullmatch(nonce) is None or not isinstance(mac, str):
            return Result.fail("bad_challenge")
        return Result(True) if hmac.compare_digest(surface_mac(secret, nonce), mac) else Result.fail("bad_challenge")
    except ValueError:
        return Result.fail("bad_challenge")


def verify_surface_proof(secret: str, nonce: str, pid: int, port: int, proof: Any) -> Result:
    try:
        if not isinstance(proof, str) or not isinstance(nonce, str) or NONCE_RE.fullmatch(nonce) is None:
            return Result.fail("bad_proof")
        return Result(True) if hmac.compare_digest(surface_proof(secret, nonce, pid, port), proof) else Result.fail("bad_proof")
    except ValueError:
        return Result.fail("bad_proof")


def identity_request(host: str, port: int, nonce: str, mac: str) -> str:
    """The exact request head the terminator sends on the connection it is about to hand to ChatGPT (before the first ChatGPT byte)."""
    return (f"GET {pol('surface.identity_path')} HTTP/1.1\r\nHost: {host}:{port}\r\n{pol('surface.identity_challenge_header')}: {nonce}\r\n"
            f"{pol('surface.identity_mac_header')}: {mac}\r\nConnection: keep-alive\r\n\r\n")


# ------------------------------------------------------------------------------------------------------------------------ node behaviour

@dataclass
class _Conn:
    phase: str = "new"          # new, hello, ready, closed
    session: str | None = None
    claims: dict[str, Any] | None = None
    session_ok: bool = False
    kind: str = "hello"
    nonce: str | None = None
    proof: str = "none"         # none, ok, replayed, invalid
    authorized: bool = False
    reply: dict[str, Any] | None = None
    host: str | None = None
    status: str | None = None
    valid_until: int = 0
    superseded: bool = False
    sub: str | None = None


def _violation(code: str) -> Result:
    return Result(False, code)


def check_transcript(doc: dict[str, Any]) -> Result:
    """Does the recorded behaviour of ONE node obey the contract? `doc` is {"ctx": {...}, "events": [...]} .
    Returns ok, or the first violation word. The rules, each with its word:
      handshake   challenge_for_invalid_session, ok_without_proof, ok_with_invalid_proof, replayed_proof_accepted, ok_without_authorize,
                  renew_without_authorize, bad_authorize_request, host_not_from_control_plane, ok_mismatch_control_plane, bad_line
      streams     open_before_ok, open_when_paused, open_after_valid_until, open_without_client_hello, open_wrong_host, open_wrong_client,
                  duplicate_stream
      attach      attach_unknown_accepted, attach_wrong_secret_accepted, attach_secret_reused, attach_after_timeout, attach_refused_good_secret
      lifetime    no_close_at_valid_until, replaced_not_closed (both are judged at the `end` event: a recording without one is transcript_without_end)
    """
    ctx = doc["ctx"]
    keys = parse_jwks(ctx["jwks"])
    skew = ctx["skew"]
    conns: dict[str, _Conn] = {}
    seen: set[str] = set()
    streams: dict[str, dict[str, Any]] = {}
    secrets_used: set[str] = set()
    hellos: dict[str, list[tuple[str, str]]] = {}   # per host: the (peer_ip, class) of each complete ClientHello still waiting for its OPEN
    ended = False
    now = 0

    for event in doc["events"]:
        now = event["t"]
        kind = event["ev"]
        conn = conns.setdefault(event["conn"], _Conn()) if "conn" in event and kind in ("recv", "send", "cp", "cp_reply") else None
        if kind == "client_hello":
            if event["complete"]:
                hellos.setdefault(event["sni"], []).append((event["peer_ip"], event["class"]))
        elif kind == "recv":
            assert conn is not None
            try:
                message = parse_line(event["line"], "d2n")
            except ProtocolError:
                continue
            verb = message["verb"]
            if verb in ("HELLO", "RENEW") and (conn.phase == "new" if verb == "HELLO" else conn.phase == "ready"):
                result = verify_session(message["session"], now=now, audience=pol("identity.aud_tunnel"), keys=keys, skew=skew)
                conn.session_ok = result.ok and (verb == "HELLO" or result.claims["sub"] == conn.sub)
                conn.session = message["session"]
                conn.claims = result.claims if result.ok else None
                conn.kind = "hello" if verb == "HELLO" else "renew"
                conn.nonce = None
                conn.proof, conn.authorized, conn.reply = "none", False, None
                if verb == "HELLO":
                    conn.phase = "hello"
            elif verb == "PROOF" and conn.session_ok and conn.nonce is not None:
                result = verify_proof(message["proof"], now=now, session_token=conn.session, session_claims=conn.claims, nonce=conn.nonce,
                                      htu=ctx["node_url"], skew=skew, seen=seen)
                conn.proof = "ok" if result.ok else ("replayed" if result.error == "replayed_jti" else "invalid")
                conn.authorized, conn.reply = False, None
                if result.ok and result.jti is not None:
                    seen.add(result.jti)
        elif kind == "cp":
            assert conn is not None and event["call"] == "authorize"
            body = event["body"]
            if (SCHEMAS.validate("authorize-request.schema.json", body) or conn.claims is None or body["device_id"] != conn.claims["sub"]
                    or body["session_jti"] != conn.claims["jti"] or body["reason"] != conn.kind or body["node"] != ctx["node_id"]):
                return _violation("bad_authorize_request")
            if conn.proof == "ok":
                conn.authorized = True
        elif kind == "cp_reply":
            assert conn is not None
            conn.reply = event if conn.authorized else None
        elif kind == "send":
            assert conn is not None
            try:
                message = parse_line(event["line"], "n2d")
            except ProtocolError:
                return _violation("bad_line")
            verb = message["verb"]
            if verb == "CHALLENGE":
                if not conn.session_ok or conn.phase not in ("hello", "ready"):
                    return _violation("challenge_for_invalid_session")
                conn.nonce = message["nonce"]
            elif verb == "OK":
                if event["line"] != "OK " + canonical_json(message["body"]):
                    return _violation("bad_line")  # the node sends the canonical form (the device's parser is lenient: see docs section 2)
                if conn.proof == "none":
                    return _violation("ok_without_proof")
                if conn.proof == "replayed":
                    return _violation("replayed_proof_accepted")
                if conn.proof != "ok":
                    return _violation("ok_with_invalid_proof")
                reply = conn.reply
                if not conn.authorized or reply is None or reply["status"] != 200:
                    return _violation("renew_without_authorize" if conn.kind == "renew" else "ok_without_authorize")
                body = message["body"]
                answer = reply["body"]
                if body["host"] != answer["host"]:
                    return _violation("host_not_from_control_plane")
                if (body["status"] != answer["status"] or body["valid_until"] != answer["valid_until"] or body["policy"] != answer["policy"]
                        or body["node"] != ctx["node_id"]):
                    return _violation("ok_mismatch_control_plane")
                conn.phase, conn.host, conn.status, conn.valid_until, conn.sub = "ready", body["host"], body["status"], body["valid_until"], conn.claims["sub"]
                conn.proof, conn.authorized, conn.reply = "none", False, None
                for other_name, other in conns.items():
                    if other is not conn and other.phase == "ready" and other.sub == conn.sub:
                        other.superseded = True
            elif verb == "OPEN":
                if conn.phase != "ready" or conn.status is None:
                    return _violation("open_before_ok")
                if conn.status == "paused":
                    return _violation("open_when_paused")
                if now >= conn.valid_until:
                    return _violation("open_after_valid_until")
                pending = hellos.get(conn.host or "", [])
                if not pending:
                    return _violation("open_wrong_host" if any(hellos.values()) else "open_without_client_hello")
                if (message["peer_ip"], message["class"]) not in pending:
                    return _violation("open_wrong_client")
                if message["stream_id"] in streams or message["secret"] in secrets_used:
                    return _violation("duplicate_stream")
                pending.remove((message["peer_ip"], message["class"]))
                streams[message["stream_id"]] = {"secret": message["secret"], "t": now, "consumed": False}
                secrets_used.add(message["secret"])
            elif verb == "CLOSE":
                conn.phase = "closed"
        elif kind == "attach":
            try:
                message = parse_line(event["line"], "d2n")
            except ProtocolError:
                continue
            known = streams.get(message["stream_id"])
            good = known is not None and hmac.compare_digest(known["secret"], message["secret"])
            fresh = good and not known["consumed"] and now - known["t"] <= pol("protocol.attach_timeout_s")
            if event["result"] == "ok":
                if known is None:
                    return _violation("attach_unknown_accepted")
                if not good:
                    return _violation("attach_wrong_secret_accepted")
                if known["consumed"]:
                    return _violation("attach_secret_reused")
                if not fresh:
                    return _violation("attach_after_timeout")
                known["consumed"] = True
            elif fresh:
                return _violation("attach_refused_good_secret")
        elif kind == "end":
            ended = True
            for other in conns.values():
                if other.phase == "ready" and other.superseded:
                    return _violation("replaced_not_closed")
                if other.phase == "ready" and now > other.valid_until:
                    return _violation("no_close_at_valid_until")
    return Result(True) if ended else _violation("transcript_without_end")

"""ALL 1.1 end-to-end experiment (plan-all-1.1.md, 2.9.1): the device's OWN TLS certificate.

The private key is generated here, on the device, written 0600 under ``state_dir()/tls/`` and never leaves it. Only a CSR (public key and a
name) goes to the certificate authority, over ACME HTTP-01 (RFC 8555): the CA asks ``http://<name>/.well-known/acme-challenge/<token>`` on
port 80, the tunnel server forwards that plain HTTP request to this device through the tunnel, and the device answers it
(e2e_tunnel_v1.py, ChallengeStore). The CA never sees the key, and neither does the tunnel server.

Pieces
  * ChallengeStore  the tokens the ACME responder of the tunnel may answer (thread-safe, short-lived).
  * AcmeClient      a minimal RFC 8555 client (account, order, http-01, finalize, download) written with ``httpx`` and ``cryptography``, which
                    the agent already depends on: the experiment adds no package to uv.lock (no ``acme``, no ``josepy``).
  * CertManager     key + CSR + issue + renew + store. ``ensure()`` reuses a stored certificate until two thirds of its life have passed
                    (60 days of 90, the plan's rule: the ratio, not a day count, so shorter lifetimes keep working) and then asks for a new one.

The CA is one of: ``staging`` and ``production`` (Let's Encrypt), a directory URL (tests, Pebble), or ``selfsigned`` (a local development
mode with no network at all: the runner's ``--local`` and the tests). A certificate is stored together with the CA it came from, so a
staging certificate is never served as if it were a production one and the other way round.

ALL 2.0 adds DeviceCertManager (below): a NEW key for every issuance, kept in a generation folder (tls_store.py), DNS-01 through the control plane's
broker (reserve first, confirm after), ARI, the CA's own clock, rate-limit back-off, revokeCert at uninstall. HTTP-01 and CertManager stay for the
experiment's runner and tunnel v1 only.

Accepting the CA's terms of service is a decision of the person running the experiment: an account is created only with agree_tos=True
(the runner's --agree-tos). Nothing here runs at import time and nothing here touches the network unless issue() is called.
"""
from __future__ import annotations

import asyncio
import contextlib
import datetime
import hashlib
import json
import logging
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit
from email.utils import parsedate_to_datetime

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from . import state_io
from .config import state_dir
from ._device_storage import LockTimeout
from .tls_store import (CertInfo, Generation, TlsStore, TlsStoreError, b64url, certificate_policy, chain_matches_key,  # noqa: F401  (some are re-exported)
                        inspect_chain, key_pem, leaf_der, parse_chain, policy as tls_policy, spki_sha256)

log = logging.getLogger("all_mcp.e2e_cert")

ACME_DIRECTORIES = {
    "staging": "https://acme-staging-v02.api.letsencrypt.org/directory",
    "production": "https://acme-v02.api.letsencrypt.org/directory",
}
SELF_SIGNED = "selfsigned"
USER_AGENT = "all-mcp-e2e-experiment/1.1 (+https://all-mcp.fyi)"
KEY_TYPES = ("ec", "rsa")
CHALLENGE_TTL_SECONDS = 1800.0
TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{1,128}")
HOSTNAME_RE = re.compile(r"(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+")
MAX_ACME_BODY = 256 * 1024


class AcmeError(Exception):
    """The CA refused or the flow could not finish. ``type`` is the ACME problem type (urn:ietf:params:acme:error:...), when there was one."""

    def __init__(self, message: str, *, type: str = "", status: int = 0, retry_after: float | None = None):
        super().__init__(message)
        self.type = type
        self.status = status
        self.retry_after = retry_after


# ---------------------------------------------------------------------------------------------------------------- files, keys, CSR

def tls_dir() -> Path:
    return state_dir() / "tls"


def _is_windows() -> bool:
    return os.name == "nt"


def _windows_owner_only(path: Path, *, directory: bool) -> None:
    """On Windows ``os.chmod`` and ``mkdir(mode=)`` restrict nothing: the folder or file would keep the ACL it inherits (Users can read it). Cut the
    inheritance and grant only the current user and SYSTEM (the service may run as either): ``icacls /inheritance:r /grant:r``. A failure is raised:
    a private key must not be left readable because the lock-down did not work."""
    import subprocess
    flags = 0x08000000   # CREATE_NO_WINDOW
    who = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, timeout=15, creationflags=flags)
    match = re.search(r"S-1-[0-9-]+", who.stdout or "")
    if who.returncode != 0 or not match:
        raise OSError("could not tell which user this is, so the key's folder was not locked to it")
    rights = "(OI)(CI)F" if directory else "F"
    done = subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", f"*{match.group(0)}:{rights}", f"*S-1-5-18:{rights}"],
                          capture_output=True, text=True, timeout=30, creationflags=flags)
    if done.returncode != 0:
        raise OSError(f"icacls could not lock {path.name} to its owner: {(done.stdout or done.stderr or '').strip()[:200]}")


def _private_dir(path: Path) -> Path:
    """The folder is created 0700 (on Windows: owner-only ACL); one that already exists keeps its mode (it may not be ours to change), the files inside are private anyway."""
    made = [folder for folder in (path, *path.parents) if not folder.exists()]   # mkdir(parents=True) makes tls/ as well as gen-<n>/: both are ours
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    for folder in reversed(made):
        if _is_windows():
            _windows_owner_only(folder, directory=True)
        elif folder == path:
            os.chmod(folder, 0o700)   # mkdir's mode is cut by the umask
    return path


def write_private(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` atomically and readable by this user only from the first byte: the file is CREATED 0600, so there is no moment
    in which a private key sits on disk with wider permissions (a chmod after a write would leave one)."""
    _private_dir(path.parent)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if _is_windows():
            _windows_owner_only(temporary, directory=False)
        state_io.replace_retrying(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def ensure_private_mode(path: Path) -> None:
    """A key file that is readable by group or others (copied, restored from a backup, a bad umask) is tightened to 0600 and logged."""
    if _is_windows():
        _windows_owner_only(path, directory=False)   # no mode bits to read there: set the ACL again, it is idempotent
        return
    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        log.warning("%s was readable by others (mode %o): set to 0600", path.name, mode)
        os.chmod(path, 0o600)


def generate_key(key_type: str = "ec"):
    if key_type == "ec":
        return ec.generate_private_key(ec.SECP256R1())
    if key_type == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    raise ValueError(f"key type must be one of {KEY_TYPES}")


def load_or_create_key(path: Path, key_type: str = "ec"):
    """The device key. Created once (0600) and kept: a restart reuses it, so the stored certificate keeps matching it."""
    if path.exists():
        ensure_private_mode(path)
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    key = generate_key(key_type)
    write_private(path, key_pem(key))
    return key


def make_csr(key, hostname: str) -> bytes:
    """DER CSR for one name. It carries the public key and the name, nothing else; the CA never receives the private key."""
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)] if len(hostname) <= 64 else [])
    builder = (x509.CertificateSigningRequestBuilder().subject_name(subject)
               .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False))
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def self_signed(key, hostname: str, *, days: int = 30, now: float | None = None) -> bytes:
    """A self-signed certificate (PEM) for local development and tests. Never what ChatGPT trusts: only the runner's --local mode uses it."""
    moment = datetime.datetime.fromtimestamp(now if now is not None else time.time(), datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname[:64])])
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(moment - datetime.timedelta(minutes=5)).not_valid_after(moment + datetime.timedelta(days=days))
                   .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                   .sign(key, hashes.SHA256()))
    return certificate.public_bytes(serialization.Encoding.PEM)


# ---------------------------------------------------------------------------------------------------------------- the responder's tokens

class ChallengeStore:
    """HTTP-01 answers the device's port-80 responder may give: token -> key authorization. Shared between the thread that runs ACME and the
    event loop that answers the CA, so it is locked; entries die after CHALLENGE_TTL_SECONDS even if nobody removes them."""

    def __init__(self, ttl: float = CHALLENGE_TTL_SECONDS, clock: Callable[[], float] = time.monotonic):
        self._ttl = ttl
        self._clock = clock
        self._lock = threading.Lock()
        self._items: dict[str, tuple[str, float]] = {}

    def publish(self, token: str, key_authorization: str) -> None:
        if not TOKEN_RE.fullmatch(token):
            raise ValueError("invalid ACME token")
        with self._lock:
            self._items[token] = (key_authorization, self._clock() + self._ttl)

    def unpublish(self, token: str) -> None:
        with self._lock:
            self._items.pop(token, None)

    def get(self, token: str) -> str | None:
        with self._lock:
            row = self._items.get(token)
            if row is None:
                return None
            if row[1] <= self._clock():
                del self._items[token]
                return None
            return row[0]

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)


# ---------------------------------------------------------------------------------------------------------------- ACME (RFC 8555)

def jwk_of(public_key: ec.EllipticCurvePublicKey) -> dict[str, str]:
    numbers = public_key.public_numbers()
    return {"crv": "P-256", "kty": "EC", "x": b64url(numbers.x.to_bytes(32, "big")), "y": b64url(numbers.y.to_bytes(32, "big"))}


def jwk_thumbprint(jwk: dict[str, str]) -> str:
    """RFC 7638: SHA-256 of the required members in lexicographic order, no whitespace."""
    canonical = json.dumps({k: jwk[k] for k in ("crv", "kty", "x", "y")}, sort_keys=True, separators=(",", ":"))
    return b64url(hashlib.sha256(canonical.encode("ascii")).digest())


def key_authorization(token: str, jwk: dict[str, str]) -> str:
    return f"{token}.{jwk_thumbprint(jwk)}"


def _es256(key: ec.EllipticCurvePrivateKey, signing_input: bytes) -> bytes:
    r, s = decode_dss_signature(key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")   # JWS wants the raw pair, not DER


def _retry_after(response: httpx.Response) -> float | None:
    """Retry-After is a number of seconds or an HTTP date (then measured from the CA's own Date header, not from this computer's clock)."""
    value = response.headers.get("retry-after", "").strip()
    if value.isascii() and value.isdigit():   # str.isdigit() is also true for "²", which float() refuses
        return float(value)
    moment, now = _http_date(value), _http_date(response.headers.get("date", ""))
    return max(0.0, moment - now) if moment is not None and now is not None else None


def _http_date(value: str) -> float | None:
    try:
        return parsedate_to_datetime(value).timestamp() if value else None
    except (TypeError, ValueError):
        return None


def _problem(response: httpx.Response) -> AcmeError:
    kind, detail = "", ""
    try:
        document = response.json()
        if isinstance(document, dict):
            kind = str(document.get("type") or "")[:200]
            detail = str(document.get("detail") or "")[:300]
    except ValueError:
        pass
    return AcmeError(f"ACME {response.status_code} {kind.rsplit(':', 1)[-1] or 'error'}: {detail or response.reason_phrase}".strip(),
                     type=kind, status=response.status_code, retry_after=_retry_after(response))


class AcmeClient:
    """RFC 8555 over a synchronous httpx client. One instance, one thread at a time (CertManager calls it from a worker thread so the event loop
    stays free to answer the CA through the tunnel while it validates)."""

    def __init__(self, directory_url: str, account_key: ec.EllipticCurvePrivateKey, *, http: httpx.Client | None = None, email: str | None = None,
                 agree_tos: bool = False, account_url: str | None = None, on_account: Callable[[str], None] | None = None,
                 sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic,
                 poll_interval: float = 2.0, poll_timeout: float = 180.0, on_date: Callable[[float], None] | None = None):
        if urlsplit(directory_url).scheme not in {"https", "http"}:
            raise ValueError("invalid ACME directory URL")
        self.directory_url = directory_url
        self._key = account_key
        self._jwk = jwk_of(account_key.public_key())
        self._http = http or httpx.Client(timeout=httpx.Timeout(30.0), headers={"User-Agent": USER_AGENT}, follow_redirects=False)
        self._email = email
        self._agree = agree_tos
        self.account_url = account_url
        self._on_account = on_account
        self._sleep = sleep
        self._clock = clock
        self._poll_interval = poll_interval
        self._poll_timeout = poll_timeout
        self._on_date = on_date
        self.last_date: float | None = None   # the CA's own clock, from the Date header of its last answer
        # True from the moment an order of this client may have a certificate (its authorizations are valid, so the CSR is sent or the order is already valid) until
        # the next obtain(): an order that failed before that moment can have no certificate, and the broker is told so (HttpBroker.abandon).
        self.order_may_be_issued = False
        self._directory: dict | None = None
        self._nonce: str | None = None

    # -- transport
    def _seen(self, response: httpx.Response) -> None:
        moment = _http_date(response.headers.get("date", ""))
        if moment is not None:
            self.last_date = moment
            if self._on_date:
                self._on_date(moment)

    def _get(self, url: str) -> httpx.Response:
        response = self._http.get(url)
        self._seen(response)
        if response.status_code >= 400:
            raise _problem(response)
        return response

    def directory(self) -> dict:
        if self._directory is None:
            document = self._get(self.directory_url).json()
            for name in ("newNonce", "newAccount", "newOrder"):
                if not isinstance(document, dict) or not isinstance(document.get(name), str):
                    raise AcmeError(f"ACME directory has no {name}")
            self._directory = document
        return self._directory

    def _fresh_nonce(self) -> str:
        response = self._http.head(self.directory()["newNonce"])
        self._seen(response)
        nonce = response.headers.get("replay-nonce")
        if response.status_code >= 400 or not nonce:
            raise AcmeError("ACME server gave no nonce", status=response.status_code)
        return nonce

    def _post(self, url: str, payload: dict | None, *, use_account: bool = True, accept: str | None = None) -> httpx.Response:
        """A signed POST. ``payload`` None is POST-as-GET. A badNonce answer carries a fresh nonce and is retried, as the RFC asks."""
        for attempt in range(4):
            nonce, self._nonce = self._nonce or self._fresh_nonce(), None
            protected: dict = {"alg": "ES256", "nonce": nonce, "url": url}
            if use_account:
                if not self.account_url:
                    raise AcmeError("ACME account not created yet")
                protected["kid"] = self.account_url
            else:
                protected["jwk"] = self._jwk
            protected64 = b64url(json.dumps(protected, separators=(",", ":")).encode())
            payload64 = "" if payload is None else b64url(json.dumps(payload, separators=(",", ":")).encode())
            signature = _es256(self._key, f"{protected64}.{payload64}".encode("ascii"))
            body = json.dumps({"protected": protected64, "payload": payload64, "signature": b64url(signature)})
            headers = {"Content-Type": "application/jose+json"}
            if accept:
                headers["Accept"] = accept
            response = self._http.post(url, content=body, headers=headers)
            self._seen(response)
            if len(response.content) > MAX_ACME_BODY:
                raise AcmeError("ACME answer too large")
            self._nonce = response.headers.get("replay-nonce") or None
            if response.status_code < 400:
                return response
            problem = _problem(response)
            if problem.type.endswith(":badNonce") and attempt < 3:
                continue
            raise problem
        raise AcmeError("ACME badNonce repeated")

    # -- account
    def ensure_account(self) -> str:
        if self.account_url:
            return self.account_url
        if not self._agree:
            raise AcmeError("the CA's terms of service were not accepted (agree_tos=False): nothing was sent to the CA")
        payload: dict = {"termsOfServiceAgreed": True}
        if self._email:
            payload["contact"] = [f"mailto:{self._email}"]
        response = self._post(self.directory()["newAccount"], payload, use_account=False)
        location = response.headers.get("location")
        if not location:
            raise AcmeError("ACME account has no Location")
        self.account_url = location
        if self._on_account:
            self._on_account(location)
        return location

    # -- order
    def _poll(self, url: str, done: tuple[str, ...], what: str) -> dict:
        deadline = self._clock() + self._poll_timeout
        while True:
            document = self._post(url, None).json()
            status = document.get("status")
            if status in done:
                return document
            if status == "invalid":
                detail = ""
                for challenge in document.get("challenges") or []:
                    error = challenge.get("error") or {}
                    if error:
                        detail = f" ({str(error.get('type', '')).rsplit(':', 1)[-1]}: {str(error.get('detail', ''))[:200]})"
                raise AcmeError(f"ACME {what} became invalid{detail}", type="invalid")
            if self._clock() >= deadline:
                raise AcmeError(f"ACME {what} did not finish in {self._poll_timeout:.0f}s (status {status})", type="timeout")
            self._sleep(self._poll_interval)

    def _authorize(self, url: str, publish: Callable[[str, str], None], unpublish: Callable[[str], None], challenge_type: str = "http-01") -> None:
        authorization = self._post(url, None).json()
        if authorization.get("status") == "valid":
            return
        challenge = next((c for c in authorization.get("challenges") or [] if c.get("type") == challenge_type), None)
        if challenge is None:
            raise AcmeError(f"the CA offered no {challenge_type} challenge")
        token = str(challenge.get("token") or "")
        if not TOKEN_RE.fullmatch(token):
            raise AcmeError("the CA sent an invalid challenge token")
        authorized = key_authorization(token, self._jwk)
        # http-01 publishes the key authorization itself; dns-01 publishes its SHA-256 (RFC 8555 8.4), the 43-character TXT value
        proof = authorized if challenge_type == "http-01" else b64url(hashlib.sha256(authorized.encode("ascii")).digest())
        try:
            publish(token, proof)
            self._post(str(challenge["url"]), {})   # "I am ready": the CA now looks (through the tunnel, or at the TXT record)
            self._poll(url, ("valid",), "authorization")
        finally:
            unpublish(token)

    def obtain(self, hostname: str, csr_der: bytes, publish: Callable[[str, str], None], unpublish: Callable[[str], None], *,
               challenge: str = "http-01", profile: str | None = None, replaces: str | None = None) -> bytes:
        """Order, prove control of ``hostname``, finalize with the CSR and return the PEM chain (leaf first). ``publish(token, proof)`` puts the proof where
        the CA will look (http-01: the key authorization on the responder; dns-01: the TXT value) and ``unpublish(token)`` takes it away, always.
        ``profile`` and ``replaces`` (the ARI certificate id of the certificate this order renews) go into the order when given."""
        self.ensure_account()
        self.order_may_be_issued = False
        order_request: dict = {"identifiers": [{"type": "dns", "value": hostname}]}
        if profile:
            order_request["profile"] = profile
        if replaces:
            order_request["replaces"] = replaces
        response = self._post(self.directory()["newOrder"], order_request)
        order, order_url = response.json(), response.headers.get("location")
        if not order_url:
            raise AcmeError("ACME order has no Location")
        for authorization_url in order.get("authorizations") or []:
            self._authorize(str(authorization_url), publish, unpublish, challenge)
        order = self._poll(order_url, ("ready", "valid"), "order")
        self.order_may_be_issued = True
        if order.get("status") != "valid":
            self._post(str(order["finalize"]), {"csr": b64url(csr_der)})
            order = self._poll(order_url, ("valid",), "order")
        certificate_url = order.get("certificate")
        if not certificate_url:
            raise AcmeError("ACME order is valid but has no certificate")
        pem = self._post(str(certificate_url), None, accept="application/pem-certificate-chain").content
        parse_chain(pem)
        return pem

    # -- ALL 2.0
    def sync_time(self) -> float | None:
        """The CA's clock now: one HEAD on its nonce endpoint, read from the Date header. None when the CA sends no Date."""
        self._nonce = self._fresh_nonce()
        return self.last_date

    def offered_profile(self, preferred: str, fallback: str) -> str | None:
        """``preferred`` when the directory lists it among its profiles, else ``fallback`` when listed, else None (no profile in the order)."""
        profiles = (self.directory().get("meta") or {}).get("profiles")
        if isinstance(profiles, dict):
            for name in (preferred, fallback):
                if name in profiles:
                    return name
        return None

    def renewal_info(self, certificate_id: str) -> "RenewalWindow | None":
        """ARI (RFC 9773): when the CA suggests renewing the certificate. None when the CA has no ARI or does not know the certificate."""
        base = self.directory().get("renewalInfo")
        if not isinstance(base, str):
            return None
        try:
            response = self._get(base.rstrip("/") + "/" + certificate_id)
        except AcmeError as exc:
            if exc.status == 404:
                return None
            raise
        document = response.json()
        window = document.get("suggestedWindow") if isinstance(document, dict) else None
        try:
            start, end = _rfc3339(window["start"]), _rfc3339(window["end"])
        except (TypeError, KeyError, ValueError):
            raise AcmeError("the CA's renewal information is malformed") from None
        if end <= start:   # RFC 9773 4.2: an end that equals or precedes the start is invalid
            raise AcmeError("the CA's renewal window ends before it starts")
        return RenewalWindow(start=start, end=end, retry_after=_retry_after(response))

    def revoke(self, certificate_der: bytes, reason: int = 5) -> None:
        """revokeCert signed with the ACCOUNT key (RFC 8555 7.6). Reason 5 is cessationOfOperation (uninstall). A certificate that is already revoked
        is not an error."""
        url = self.directory().get("revokeCert")
        if not isinstance(url, str):
            raise AcmeError("the CA offers no revokeCert")
        try:
            self._post(url, {"certificate": b64url(certificate_der), "reason": reason})
        except AcmeError as exc:
            if not exc.type.endswith(":alreadyRevoked"):
                raise


def _rfc3339(text: str) -> float:
    return datetime.datetime.fromisoformat(str(text).replace("Z", "+00:00")).timestamp()


@dataclass(frozen=True)
class RenewalWindow:
    start: float
    end: float
    retry_after: float | None


def certificate_id(pem: bytes) -> str:
    """The ARI certificate identifier: base64url of the issuer's key identifier (the leaf's Authority Key Identifier), a dot, and base64url of the
    serial number as DER integer content (RFC 9773 4.1). It is the value of ``replaces`` and the tail of the renewalInfo URL."""
    leaf = parse_chain(pem)[0]
    try:
        key_id = leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier
    except x509.ExtensionNotFound:
        key_id = None
    if not key_id:
        raise ValueError("the certificate has no Authority Key Identifier")
    serial = leaf.serial_number
    return f"{b64url(key_id)}.{b64url(serial.to_bytes((serial.bit_length() + 8) // 8, 'big'))}"


# ---------------------------------------------------------------------------------------------------------------- the device's certificate

@dataclass(frozen=True)
class CertState:
    chain_path: Path
    key_path: Path
    info: CertInfo
    ca: str
    issued_now: bool
    generation: int = 0   # the tls/gen-<n>/ it lives in (DeviceCertManager); 0 for the 1.1 flat layout

    @property
    def renew_at(self) -> float:
        return self.info.renew_at


class CertManager:
    """LEGACY (the 1.1 experiment: one key kept for good, flat files in tls/, HTTP-01 through the tunnel; the tunnel v1 tests still build on it). The 2.0
    device uses DeviceCertManager below, which keeps the same call names (ensure, current, due, needs_terms, issue) over generations.

    Key, CSR, issue, renew and store the device's certificate. Everything lives in ``directory`` (default state_dir()/tls/):
    device.key (0600), fullchain.pem, certificate.json (which CA, which name), acme-account-<ca>.key and .json."""

    def __init__(self, hostname: str, *, ca: str = "staging", directory: Path | None = None, key_type: str = "ec", email: str | None = None,
                 agree_tos: bool = False, challenges: ChallengeStore | None = None, http: httpx.Client | None = None,
                 clock: Callable[[], float] = time.time, sleep: Callable[[float], None] = time.sleep,
                 poll_interval: float = 2.0, poll_timeout: float = 180.0):
        hostname = hostname.strip().lower().rstrip(".")
        if not HOSTNAME_RE.fullmatch(hostname):
            raise ValueError("invalid host name")
        if key_type not in KEY_TYPES:
            raise ValueError(f"key type must be one of {KEY_TYPES}")
        self.hostname = hostname
        self.ca = ca
        self.directory_url = ACME_DIRECTORIES.get(ca, ca if ca != SELF_SIGNED else "")
        if ca != SELF_SIGNED and not self.directory_url.startswith(("https://", "http://")):
            raise ValueError("ca must be staging, production, selfsigned or an ACME directory URL")
        self.dir = directory or tls_dir()
        self.key_type = key_type
        self.email = email
        self.agree_tos = agree_tos
        self.challenges = challenges if challenges is not None else ChallengeStore()   # an EMPTY store is falsy (__len__): never `or`
        self._http = http
        self._clock = clock
        self._sleep = sleep
        self._poll_interval = poll_interval
        self._poll_timeout = poll_timeout
        self.key_path = self.dir / "device.key"
        self.chain_path = self.dir / "fullchain.pem"
        self.meta_path = self.dir / "certificate.json"
        self._ca_tag = ca if ca in ACME_DIRECTORIES or ca == SELF_SIGNED else "custom-" + hashlib.sha256(ca.encode()).hexdigest()[:8]
        self._lock = threading.Lock()

    # -- what is stored
    def _stored_ca(self) -> str | None:
        try:
            document = json.loads(self.meta_path.read_text(encoding="utf-8"))
            return str(document.get("ca")) if isinstance(document, dict) else None
        except (OSError, ValueError):
            return None

    def current(self) -> CertState | None:
        """The stored certificate when it is usable now: it covers the name, matches the key, comes from the configured CA and has not expired.
        Anything else is None (and a new one is issued)."""
        try:
            pem = self.chain_path.read_bytes()
            key = serialization.load_pem_private_key(self.key_path.read_bytes(), password=None)
            info = inspect_chain(pem)
            if (self.hostname not in info.names or not chain_matches_key(pem, key) or self._stored_ca() != self._ca_tag
                    or not info.not_before - 600 <= self._clock() < info.not_after):
                return None
            ensure_private_mode(self.key_path)
            return CertState(self.chain_path, self.key_path, info, self._ca_tag, False)
        except (OSError, ValueError):
            return None

    def due(self, state: CertState | None = None) -> bool:
        state = state or self.current()
        return state is None or self._clock() >= state.renew_at

    def needs_terms(self) -> bool:
        """True when the next certificate needs a NEW account at the CA, i.e. someone has to accept the CA's terms first (never for selfsigned or when a
        stored certificate is still good, and never when an account of this CA already exists here)."""
        if self.ca == SELF_SIGNED:
            return False
        state = self.current()
        if state is not None and not self.due(state):
            return False
        return not (self.dir / f"acme-account-{self._ca_tag}.json").exists()

    # -- issuing
    def _account(self) -> AcmeClient:
        key_path = self.dir / f"acme-account-{self._ca_tag}.key"
        url_path = self.dir / f"acme-account-{self._ca_tag}.json"
        _private_dir(self.dir)
        account_key = load_or_create_key(key_path, "ec")
        url = None
        try:
            document = json.loads(url_path.read_text(encoding="utf-8"))
            url = str(document["url"]) if isinstance(document, dict) and document.get("url") else None
        except (OSError, ValueError, KeyError):
            pass

        def remember(location: str) -> None:
            write_private(url_path, json.dumps({"url": location, "directory": self.directory_url}).encode())

        return AcmeClient(self.directory_url, account_key, http=self._http, email=self.email, agree_tos=self.agree_tos, account_url=url,
                          on_account=remember, sleep=self._sleep, poll_interval=self._poll_interval, poll_timeout=self._poll_timeout)

    def issue(self) -> CertState:
        """Always asks for a new certificate (ensure() decides when). The device key is created on first use and kept."""
        with self._lock:
            _private_dir(self.dir)
            key = load_or_create_key(self.key_path, self.key_type)
            if self.ca == SELF_SIGNED:
                pem = self_signed(key, self.hostname, now=self._clock())
            else:
                log.info("asking %s for a certificate for %s", urlsplit(self.directory_url).netloc, self.hostname)
                csr = make_csr(key, self.hostname)
                try:
                    pem = self._account().obtain(self.hostname, csr, self.challenges.publish, self.challenges.unpublish)
                except AcmeError as exc:
                    if not exc.type.endswith(":accountDoesNotExist"):
                        raise
                    # the CA no longer knows our account (Let's Encrypt staging is reset now and then): forget it and register again
                    log.warning("the CA does not know the stored account any more: registering a new one")
                    (self.dir / f"acme-account-{self._ca_tag}.json").unlink(missing_ok=True)
                    pem = self._account().obtain(self.hostname, csr, self.challenges.publish, self.challenges.unpublish)
            info = inspect_chain(pem)
            if self.hostname not in info.names or not chain_matches_key(pem, key):
                raise AcmeError("the certificate does not match this device's key and name")
            write_private(self.chain_path, pem)
            write_private(self.meta_path, json.dumps({"ca": self._ca_tag, "hostname": self.hostname, "issued_at": int(self._clock()),
                                                      "not_after": int(info.not_after)}).encode())
            return CertState(self.chain_path, self.key_path, info, self._ca_tag, True)

    def ensure(self) -> CertState:
        """The certificate to serve with: the stored one while it is not due for renewal, otherwise a new one. A stored certificate that
        is still valid but due is replaced only if the new one is obtained: a failed renewal raises and the old one keeps working until it expires."""
        state = self.current()
        if state is not None and not self.due(state):
            return state
        try:
            return self.issue()
        except Exception:
            if state is not None:
                expires = datetime.datetime.fromtimestamp(state.info.not_after, datetime.timezone.utc).isoformat()
                log.warning("renewal failed; the current certificate stays in use until %s", expires)
            raise


# ================================================================================================================ ALL 2.0
# The device's certificate manager, version 2: DNS-01 through the control plane's broker, a new key for every issuance in a generation folder
# (tls_store.py), ARI, the CA's clock for every decision, a persisted attempt counter with back-off, rate limits that keep the current certificate.
# Plan 2.0 sections 2 and 4. Every number comes from contracts/policy.json (tls_store.policy()).

BACKOFF_CEILING_S = 86400.0          # consecutive failures wait 6 h, 12 h, 24 h and then 24 h (the plan names the 6 h floor and the doubling)
SOFT_RETRY_FLOOR_S = 30.0            # a failure that cost nothing (no connection, a 5xx before any reservation) is retried soon: 30 s, doubling to 30 min
SOFT_RETRY_CEILING_S = 1800.0
BLOCK_CEILING_S = 7 * 86400.0        # no answer of a server can keep this device quiet for longer than this
CLOCK_SYNC_EVERY_S = 600.0
DIRECTORY_TTL_S = 86400.0
DAY_S = 86400.0
STATE_VERSION = 1
BROKER_BODY_MAX = 65536
WORD_RE = re.compile(r"[a-z_]{1,48}")
RESERVATION_RE = re.compile(r"[0-9a-f]{32}")
SPKI_RE = re.compile(r"[A-Za-z0-9_-]{43}")
ACME_PATH = "/v1/devices/acme/"


# ---------------------------------------------------------------------------------------------------------------- the broker

class BrokerError(Exception):
    """The broker (or the way to it) refused. ``word`` is the closed word of its error answer ("label_retired", "dns_rate_limited", ...) or one of
    ours: broker_unreachable, credentials_unavailable, bad_answer. ``status`` is the HTTP status (0: no answer at all)."""

    def __init__(self, word: str, *, status: int = 0, retry_after: float | None = None):
        super().__init__(word)
        self.word = word
        self.status = status
        self.retry_after = retry_after

    @property
    def soft(self) -> bool:
        """A failure that says nothing against this device: nobody answered, the control plane is busy or down, or it asks to wait."""
        return self.status in (0, 429) or self.status >= 500


@dataclass(frozen=True)
class Reservation:
    id: str
    klass: str
    expires_at: float
    server_time: float


@dataclass(frozen=True)
class Deferral:
    """Over budget is never an error: come back at ``enroll_after`` (the broker's jitter is already in it)."""
    enroll_after: float
    server_time: float


@dataclass(frozen=True)
class DnsAnswer:
    name: str
    type: str
    ttl: int


class HttpBroker:
    """The device's side of POST /v1/devices/acme/{reserve,dns,confirm,release}. Every call carries the device's own
    control session and proof (``headers(url, method)``, device_credentials.control_headers by default). The answers are checked against the
    contract's shapes; an answer that does not fit is ``bad_answer``, never trusted."""

    def __init__(self, base_url: str, *, headers: Callable[[str, str], dict[str, str]] | None = None, http: httpx.Client | None = None,
                 timeout: float = 20.0):
        if urlsplit(base_url).scheme not in {"https", "http"}:
            raise ValueError("invalid control plane URL")
        self.base = base_url.rstrip("/")
        self._headers = headers or _control_headers
        self._http = http or httpx.Client(timeout=httpx.Timeout(timeout), headers={"User-Agent": USER_AGENT}, follow_redirects=False)

    def _call(self, method: str, operation: str, body: dict | None = None) -> dict:
        url = f"{self.base}{ACME_PATH}{operation}"
        try:
            headers = {"Accept": "application/json", **self._headers(url, method)}
        except Exception:   # the credentials are not there (yet): nothing was sent, and nothing about it is worth more than a closed word
            raise BrokerError("credentials_unavailable") from None
        content = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            content = json.dumps(body, separators=(",", ":")).encode("utf-8")
        try:
            response = self._http.request(method, url, content=content, headers=headers)
        except httpx.HTTPError:
            raise BrokerError("broker_unreachable") from None
        if len(response.content) > BROKER_BODY_MAX:
            raise BrokerError("bad_answer", status=response.status_code)
        try:
            document = response.json()
        except ValueError:
            document = None
        if response.status_code >= 400:
            word = document.get("error") if isinstance(document, dict) else None
            wait = document.get("retry_after_s") if isinstance(document, dict) else None
            raise BrokerError(word if isinstance(word, str) and WORD_RE.fullmatch(word) else "broker_error", status=response.status_code,
                              retry_after=float(wait) if type(wait) is int else _retry_after(response))
        if not isinstance(document, dict) or document.get("ok") is not True:
            raise BrokerError("bad_answer", status=response.status_code)
        return document

    @staticmethod
    def _seconds(document: dict, key: str) -> float:
        value = document.get(key)
        if type(value) is not int or value < 0:
            raise BrokerError("bad_answer")
        return float(value)

    def reserve(self, spki_sha256: str, purpose: str) -> Reservation | Deferral:
        document = self._call("POST", "reserve", {"v": 1, "spki_sha256": spki_sha256, "purpose": purpose})
        stamp = self._seconds(document, "server_time")
        if document.get("status") == "deferred":
            return Deferral(self._seconds(document, "enroll_after"), stamp)
        reservation_id, klass = document.get("reservation_id"), document.get("class")
        if (document.get("status") != "granted" or not isinstance(reservation_id, str) or not RESERVATION_RE.fullmatch(reservation_id)
                or klass not in tls_policy()["enums"]["budget_class"]):
            raise BrokerError("bad_answer")
        return Reservation(reservation_id, klass, self._seconds(document, "expires_at"), stamp)

    def _dns(self, reservation_id: str, body: dict) -> DnsAnswer:
        document = self._call("POST", "dns", {"v": 1, "reservation_id": reservation_id, **body})
        name, ttl = document.get("name"), document.get("ttl")
        if not isinstance(name, str) or document.get("type") != "TXT" or type(ttl) is not int or not 1 <= ttl <= 3600:
            raise BrokerError("bad_answer")
        return DnsAnswer(name, "TXT", ttl)

    def set_txt(self, reservation_id: str, value: str) -> DnsAnswer:
        return self._dns(reservation_id, {"action": "set", "value": value})

    def clear_txt(self, reservation_id: str) -> DnsAnswer:
        return self._dns(reservation_id, {"action": "clear"})

    def confirm(self, reservation_id: str, spki_sha256: str, not_before: int, not_after: int) -> float:
        document = self._call("POST", "confirm", {"v": 1, "reservation_id": reservation_id, "spki_sha256": spki_sha256, "not_before": int(not_before),
                                                  "not_after": int(not_after)})
        return self._seconds(document, "server_time")

    def abandon(self, reservation_id: str) -> None:
        """The order for this reservation ended before the CSR was sent: no certificate can exist for its key, and the broker frees the slot."""
        self._call("POST", "abandon", {"v": 1, "reservation_id": reservation_id})

    def release(self, reason: str) -> None:
        self._call("POST", "release", {"v": 1, "reason": reason})

    def status(self) -> dict:
        return self._call("GET", "status")


def _control_headers(url: str, method: str) -> dict[str, str]:
    from .device_credentials import control_headers
    return control_headers(url, method)


def control_plane_url(values: dict[str, str] | None = None) -> str:
    from .config import runtime_values
    values = runtime_values() if values is None else values
    return (values.get("ALL_CONTROL_PLANE_URL") or values.get("ALL_AI_PROXY_URL") or "https://api.all-mcp.fyi").rstrip("/")


# ---------------------------------------------------------------------------------------------------------------- the CA's clock

class CaClock:
    """Time as the CA tells it. The device's own clock can be a year off (a dead battery, a wrong time zone, a VM resumed from an old snapshot); a
    certificate that "expired" on that clock must not be renewed over and over. ``observe`` takes the CA's Date header (or the broker's server_time);
    from then on ``now`` is that moment plus the time elapsed on the MONOTONIC clock, so a later jump of the wall clock changes nothing."""

    def __init__(self, wall: Callable[[], float] = time.time, monotonic: Callable[[], float] = time.monotonic):
        self._wall = wall
        self._monotonic = monotonic
        self._remote: float | None = None
        self._at = 0.0

    def observe(self, remote: float) -> None:
        self._remote, self._at = float(remote), self._monotonic()

    def observe_if_stale(self, remote: float, maximum_age: float) -> None:
        """A second source (the broker's server_time, whole seconds) fills in only when the CA's own Date is not recent."""
        if self.age() >= maximum_age:
            self.observe(remote)

    @property
    def synced(self) -> bool:
        return self._remote is not None

    def age(self) -> float:
        """Seconds since the last observation (infinite before the first)."""
        return self._monotonic() - self._at if self._remote is not None else float("inf")

    def now(self) -> float:
        return self._remote + (self._monotonic() - self._at) if self._remote is not None else self._wall()

    @property
    def offset(self) -> float | None:
        """The CA's time minus this computer's clock, in seconds; None while the CA has not been heard."""
        return self.now() - self._wall() if self._remote is not None else None


# ---------------------------------------------------------------------------------------------------------------- the manager

@dataclass(frozen=True)
class PassResult:
    """What one pass of the manager did. ``action``: valid (nothing to do), issued, adopted (a certificate a crash left unnamed was put in service),
    waiting (due, but not allowed yet: ``reason`` and ``wait_until``), failed (``error`` is the closed word), terms (the CA's terms are not accepted
    yet, nothing was sent), offline (the CA could not be reached to learn the time), busy (another pass runs), unsafe (the storage is not trusted)."""
    action: str
    generation: int | None = None
    wait_until: float | None = None
    reason: str = ""
    error: str = ""

    @property
    def issued(self) -> bool:
        return self.action in ("issued", "adopted")


class CertUnavailable(AcmeError):
    """ensure() has no certificate to give: none was ever issued and the pass could not issue one now (``retry_after`` says how long to wait)."""


def _snake(word: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", word).lower()


def error_word(exc: BaseException) -> str:
    """The closed word that stands for a failure in the status file and the fleet heartbeat: never text from the network."""
    if isinstance(exc, BrokerError):
        return exc.word
    if isinstance(exc, AcmeError):
        tail = _snake(exc.type.rsplit(":", 1)[-1]) if exc.type else "acme_error"
        return {"invalid": "validation_failed", "timeout": "acme_timeout"}.get(tail, tail if WORD_RE.fullmatch(tail) else "acme_error")
    if isinstance(exc, TlsStoreError):
        return exc.word
    if isinstance(exc, httpx.HTTPError):
        return "ca_unreachable"
    if isinstance(exc, OSError):
        return "storage_error"
    return "internal_error"


class DeviceCertManager:
    """The device's TLS certificate, from first issuance to uninstall.

    ``run_once()`` is one decision pass, safe to call at any time, from any process (a second one at the same moment answers ``busy``). It never
    raises for an expected condition and never touches the serving certificate unless a new one is complete and validated. The rules (plan section 4):

      * the CA decides what time it is (its Date header); the device's clock only breaks ties when the CA cannot be reached;
      * a certificate is due when ARI says so (checked twice a day), or when a third of its life is left (the backstop, with or without ARI), or when it
        has expired;
      * an attempt is counted (and written to disk) when a reservation is granted; at least min_attempt_gap_s between attempts, back-off doubling after
        failures, at most max_issuances_per_day successes in 24 hours; a rate limit or an ``enroll_after`` keeps the current certificate and waits;
      * every issuance: new EC P-256 key -> its SPKI hash reserved at the broker BEFORE the order -> DNS-01 through the broker -> chain written beside
        the key in tls/gen-<n>/ -> validated as a pair -> pointer swapped atomically -> issuance confirmed at the broker.

    Modes: ``dns-01`` (a broker is given: production), ``http-01`` (``dev_http01=True`` and no broker: the experiment's runner through its tunnel) and
    ``selfsigned`` (ca="selfsigned": local development and tests, no network).
    """

    def __init__(self, hostname: str, *, ca: str = "staging", directory: Path | None = None, broker=None, email: str | None = None,
                 agree_tos: bool = False, dev_http01: bool = False, challenges: ChallengeStore | None = None, http: httpx.Client | None = None,
                 clock: Callable[[], float] = time.time, monotonic: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep, poll_interval: float = 2.0, poll_timeout: float = 180.0, dns_settle: float = 5.0,
                 key_type: str = "ec", faults: Callable[[str], None] | None = None, rng: Callable[[], float] = secrets.SystemRandom().random):
        hostname = hostname.strip().lower().rstrip(".")
        if not HOSTNAME_RE.fullmatch(hostname):
            raise ValueError("invalid host name")
        if key_type != "ec":
            raise ValueError("device keys are EC P-256")
        self.hostname = hostname
        self.ca = ca
        self.directory_url = ACME_DIRECTORIES.get(ca, ca if ca != SELF_SIGNED else "")
        if ca != SELF_SIGNED and not self.directory_url.startswith(("https://", "http://")):
            raise ValueError("ca must be staging, production, selfsigned or an ACME directory URL")
        if ca == SELF_SIGNED:
            self.mode = "selfsigned"
        elif broker is not None:
            if dev_http01:
                raise ValueError("a broker and HTTP-01 together: choose one (HTTP-01 is for development only)")
            if not re.fullmatch(tls_policy()["identity"]["fqdn_regex"], hostname):
                raise ValueError("a device host is one label under the devices zone")
            self.mode = "dns-01"
        elif dev_http01:
            self.mode = "http-01"
        else:
            raise ValueError("a broker is required: DNS-01 through the control plane is the way a device gets its certificate "
                             "(HTTP-01 exists only for development: dev_http01=True)")
        self.broker = broker
        self.email = email
        self.agree_tos = agree_tos
        self.challenges = challenges if challenges is not None else ChallengeStore()   # an EMPTY store is falsy (__len__): never `or`
        self.store = TlsStore(directory, faults=faults)
        self.dir = self.store.dir
        self.clock = CaClock(clock, monotonic)
        self._wall = clock
        self._http = http
        self._sleep = sleep
        self._poll_interval = poll_interval
        self._poll_timeout = poll_timeout
        self._dns_settle = dns_settle
        self._rng = rng
        self._policy = certificate_policy()
        self._ca_tag = ca if ca in ACME_DIRECTORIES or ca == SELF_SIGNED else "custom-" + hashlib.sha256(ca.encode()).hexdigest()[:8]
        self._client_cache: AcmeClient | None = None
        self._mutex = threading.Lock()   # two passes of the SAME process; across processes it is the file lock

    # -- paths a consumer wants (the active generation's; before any issuance they point where the first one will not be)
    @property
    def chain_path(self) -> Path:
        generation = self._active()
        return generation.chain_path if generation else self.dir / "fullchain.pem"

    @property
    def key_path(self) -> Path:
        generation = self._active()
        return generation.key_path if generation else self.dir / "device.key"

    def _active(self) -> Generation | None:
        try:
            return self.store.active()
        except TlsStoreError:
            return None

    # -- the CA
    def _account_files(self) -> tuple[str, str]:
        return f"acme-account-{self._ca_tag}.key", f"acme-account-{self._ca_tag}.json"

    def _account_url(self) -> str | None:
        raw = self.store.read_file(self._account_files()[1])
        try:
            document = json.loads(raw.decode("utf-8")) if raw else None
        except (ValueError, UnicodeError):
            return None
        return str(document["url"]) if isinstance(document, dict) and document.get("url") else None

    def _acme(self) -> AcmeClient:
        """The CA client for this pass. The account key is created on first use (0600, in tls/) and only ever used to register and to revoke."""
        if self._client_cache is not None:
            return self._client_cache
        key_file, url_file = self._account_files()
        raw = self.store.read_file(key_file)
        if raw:
            account_key = serialization.load_pem_private_key(raw, password=None)
        else:
            account_key = generate_key("ec")
            self.store.write_file(key_file, key_pem(account_key))

        def remember(location: str) -> None:
            self.store.write_file(url_file, json.dumps({"url": location, "directory": self.directory_url}).encode())

        self._client_cache = AcmeClient(self.directory_url, account_key, http=self._http, email=self.email, agree_tos=self.agree_tos,
                                        account_url=self._account_url(), on_account=remember, sleep=self._sleep, poll_interval=self._poll_interval,
                                        poll_timeout=self._poll_timeout, on_date=self.clock.observe)
        return self._client_cache

    def needs_terms(self) -> bool:
        """True when the next certificate needs a NEW account at the CA, i.e. someone has to accept the CA's terms first."""
        if self.mode == "selfsigned" or self._account_url() is not None:
            return False
        return self._due_reason(self._active(), self.clock.now()) is not None

    # -- the pass
    def run_once(self, *, force: bool = False) -> PassResult:
        """One decision pass (see the class). ``force`` skips only the question "is it due"; every wait still applies."""
        if not self._mutex.acquire(blocking=False):
            return PassResult("busy")
        try:
            with self.store.exclusive(0.0):
                return self._pass(force)
        except LockTimeout:
            return PassResult("busy")
        except TlsStoreError as exc:
            if exc.word == "storage_error":   # the disk, not the folder: full, read-only, an I/O error
                log.warning("the TLS folder could not be written (%s)", exc.word)
                return PassResult("failed", error=exc.word)
            log.warning("the TLS folder is not trusted (%s): nothing was changed", exc.word)
            with contextlib.suppress(Exception):
                self.store.write_status(self._status_document(None, {}, self.clock.now(), "unsafe", error=exc.word))
            return PassResult("unsafe", error=exc.word)
        finally:
            self._mutex.release()

    def _pass(self, force: bool) -> PassResult:
        self._client_cache = None
        self.store.key_storage()   # writes the descriptor on first use; refuses a descriptor that says something this version cannot honor
        state = self._load_state()
        if self.mode != "selfsigned" and self._account_url() is None and not self.agree_tos:
            # A new account needs the person's agreement to the CA's terms (the installer's flag): until then nothing at all is sent to the CA
            active = self._active()
            self._save(state, active, self.clock.now(), "waiting" if active is None else "valid", reason="terms_required")
            return PassResult("terms", generation=active.number if active else None, reason="terms_required")
        trusted = self._sync_clock()
        now = self.clock.now()
        adopted = self._adopt(now, state)
        for name in self.store.gc():
            log.info("removed %s", name)
        active = self.store.active()   # storage the checks refuse raises here: nothing is repaired or replaced behind a planted link or a foreign file
        self._flush_confirm(state, active)
        if self.mode != "selfsigned" and active is not None and not trusted:
            self._save(state, active, now, "valid", reason="ca_unreachable")
            return PassResult("offline", generation=active.number, reason="ca_unreachable")
        if active is not None and self.mode != "selfsigned":
            self._refresh_ari(state, active, now)
        reason = "forced" if force else self._due_reason(active, now, state)
        if reason is None:
            self._save(state, active, now, "valid")
            return PassResult("adopted" if adopted else "valid", generation=active.number if active else None)
        wait = self._wait(state, now) if self.mode != "selfsigned" else None
        if wait is not None:
            self._save(state, active, now, "waiting", reason=wait[1], wait_until=wait[0])
            return PassResult("waiting", generation=active.number if active else None, wait_until=wait[0], reason=wait[1])
        return self._issue(state, active, reason, now)

    # -- the clock
    def _sync_clock(self) -> bool:
        """Learn the CA's time (one HEAD request) unless it was learned a moment ago. False when it could not be learned and was never learned."""
        if self.mode == "selfsigned" or self.clock.age() < CLOCK_SYNC_EVERY_S:
            return True
        try:
            self._acme().sync_time()
        except (AcmeError, httpx.HTTPError, ValueError) as exc:
            log.info("the CA's clock could not be read (%s)", error_word(exc))
        return self.clock.synced and self.clock.age() < CLOCK_SYNC_EVERY_S * 6

    # -- state
    def _load_state(self) -> dict[str, Any]:
        try:
            state = self.store.read_state()
        except TlsStoreError as exc:
            if exc.word != "file_invalid":
                raise
            state = None
            corrupted = True
        else:
            corrupted = False
        state = dict(state) if isinstance(state, dict) and state.get("v") == STATE_VERSION else {"v": STATE_VERSION}
        if corrupted:   # a record that cannot be read must not reset the counters to "never tried": the gap starts now
            state["last_attempt"] = self.clock.now()
        for key, default in (("attempt_count", 0), ("failures", 0), ("soft_failures", 0)):
            state[key] = state[key] if type(state.get(key)) is int and state[key] >= 0 else default
        return state

    def _persist(self, state: dict[str, Any]) -> None:
        self.store.write_state(state)

    # -- deciding
    def _due_reason(self, active: Generation | None, now: float, state: dict[str, Any] | None = None) -> str | None:
        if active is None:
            return "none"
        if active.ca != self._ca_tag or self.hostname not in active.info.names:
            return "other_ca"
        if now >= active.info.not_after:
            return "expired"
        if now >= active.info.renew_at:
            return "backstop"
        ari = (state or {}).get("ari") or {}
        if ari.get("fp") == active.info.fingerprint and "start" in ari and now >= ari["start"] + ari["frac"] * (ari["end"] - ari["start"]):
            return "ari"
        return None

    def _refresh_ari(self, state: dict[str, Any], active: Generation, now: float) -> None:
        """Ask the CA when it suggests renewing, twice a day. A CA without ARI, a failure or a malformed answer changes nothing: the backstop stays."""
        ari = state.get("ari") if isinstance(state.get("ari"), dict) else {}
        same = ari.get("fp") == active.info.fingerprint
        if same and now < ari.get("next_check", 0):
            return
        if now >= active.info.not_after:
            return   # RFC 9773 4.3: never ask about a certificate that has expired
        interval = DAY_S / self._policy["ari_checks_per_day"]
        record: dict[str, Any] = {"fp": active.info.fingerprint, "next_check": now + interval, "frac": ari["frac"] if same and "frac" in ari else self._rng()}
        try:
            window = self._acme().renewal_info(certificate_id(active.chain_pem))
        except (AcmeError, httpx.HTTPError, ValueError) as exc:
            log.info("ARI: %s", error_word(exc))
            record.update({key: ari[key] for key in ("checked_at", "start", "end") if same and key in ari})   # keep the last window it gave
        else:
            if window is not None:
                record.update(checked_at=now, start=window.start, end=window.end, next_check=now + max(interval, min(window.retry_after or 0.0, DAY_S)))   # the policy's twice a day is the floor; a day the ceiling (RFC 9773 4.3.2)
        state["ari"] = record
        self._persist(state)

    def _backoff(self, failures: int) -> float:
        gap = float(self._policy["min_attempt_gap_s"])
        return min(BACKOFF_CEILING_S, gap * 2 ** max(0, failures - 1)) if failures else gap

    def _wait(self, state: dict[str, Any], now: float) -> tuple[float, str] | None:
        """The earliest moment an issuance is allowed again and why, or None when one is allowed now."""
        waits: list[tuple[float, str]] = []
        blocked = state.get("blocked_until")
        if type(blocked) in (int, float) and blocked > now:
            waits.append((min(float(blocked), now + BLOCK_CEILING_S), str(state.get("blocked_reason") or "blocked")))
        soft = state.get("soft_until")
        if type(soft) in (int, float) and soft > now:
            waits.append((min(float(soft), now + BLOCK_CEILING_S), "retry_soon"))
        last = state.get("last_attempt")
        if type(last) in (int, float):
            if last > now:   # the clock went back: the gap starts again from now, so a wrong clock can delay but never loop
                last = state["last_attempt"] = now
            gap = self._backoff(state.get("failures", 0))
            if last + gap > now:
                waits.append((last + gap, "backoff" if state.get("failures") else "gap"))
        issued = [min(float(t), now) for t in state.get("issuances", []) if type(t) in (int, float) and t > now - DAY_S]
        if len(issued) >= self._policy["max_issuances_per_day"]:
            waits.append((min(issued) + DAY_S, "daily_cap"))
        return max(waits) if waits else None

    # -- issuing
    def _issue(self, state: dict[str, Any], active: Generation | None, reason: str, now: float) -> PassResult:
        self._save(state, active, now, "issuing", reason=reason)
        number: int | None = None
        attempted = False
        reservation: Reservation | None = None
        client: AcmeClient | None = None
        try:
            if self.mode == "selfsigned":
                number, key = self.store.new_generation()
                chain = self_signed(key, self.hostname, now=now)
                profile = None
            else:
                client = self._acme()
                client.ensure_account()          # a new-account limit (per IP) ends here, before anything was reserved
                number, key = self.store.new_generation()
                spki = spki_sha256(key.public_key())
                if self.mode == "dns-01":
                    answer = self.broker.reserve(spki, "renewal" if state.get("confirmed_once") else "first")
                    self.clock.observe_if_stale(answer.server_time, CLOCK_SYNC_EVERY_S)
                    now = self.clock.now()
                    if isinstance(answer, Deferral):
                        self.store.discard(number)
                        state["blocked_until"], state["blocked_reason"] = min(answer.enroll_after, now + BLOCK_CEILING_S), "enroll_after"
                        self._save(state, active, now, "waiting", reason="enroll_after", wait_until=state["blocked_until"])
                        return PassResult("waiting", generation=active.number if active else None, wait_until=state["blocked_until"], reason="enroll_after")
                    reservation = answer
                client.order_may_be_issued = False
                state["attempt_count"] += 1
                state["last_attempt"] = now
                state["soft_failures"], state["soft_until"] = 0, None
                self._persist(state)   # counted BEFORE the order: a crash from here on still leaves the attempt on record
                attempted = True
                chain, profile = self._order(client, key, reservation, active, now)
                self.store.hit("after_ca")
            now = self.clock.now()
            generation = self.store.write_chain(number, chain, self.hostname, {"ca": self._ca_tag, "profile": profile, "issued_at": int(now),
                                                                              "reason": reason})
            if not (generation.info.not_before - 600 <= now < generation.info.not_after):
                raise TlsStoreError("chain_invalid", "the CA's certificate is not valid now")
            # Written BEFORE the swap, so a crash on either side of it knows what to confirm and that the CA counted this issuance (the daily cap
            # errs on the side of counting an issuance that never went into service).
            issued = [t for t in state.get("issuances", []) if type(t) in (int, float) and now - DAY_S < t <= now]
            state.update(issuances=[*issued, now], failures=0, blocked_until=None, blocked_reason=None, soft_until=None, soft_failures=0, last_error=None,
                         ari=None)
            if self.mode == "dns-01":
                state["pending_confirm"] = {"reservation_id": reservation.id, "spki": generation.spki, "gen": number,
                                            "not_before": int(generation.info.not_before), "not_after": int(generation.info.not_after)}
            self._persist(state)
            self.store.hit("before_swap")
            self.store.activate(number)
            self.store.hit("after_swap")
        except (AcmeError, BrokerError, TlsStoreError, httpx.HTTPError, OSError) as exc:
            self._abandon(reservation, client)
            return self._failed(state, active, exc, number, attempted)
        except Exception as exc:   # a bug must not take the process down, and must not repeat at once either
            log.warning("certificate pass failed: %s", type(exc).__name__, exc_info=True)
            self._abandon(reservation, client)
            return self._failed(state, active, exc, number, attempted)
        # from here the new certificate is serving: confirming and the status file only, nothing below may undo it
        active = self._active()
        self._flush_confirm(state, active)
        self._save(state, active, now, "valid")
        return PassResult("issued", generation=number)

    def _abandon(self, reservation: Reservation | None, client: AcmeClient | None) -> None:
        """Tell the broker that the order of this reservation failed before the CSR was sent, so that the slot it keeps for an order that may have been issued is
        freed (a validation that failed, a CA that was down). An order that got as far as the CSR is not abandoned: a certificate may exist, and only the CT
        reconciliation can lift that hold. Best effort: a broker that cannot be reached leaves the slot to the reconciliation."""
        if reservation is None or client is None or client.order_may_be_issued:
            return
        try:
            self.broker.abandon(reservation.id)
        except BrokerError as exc:
            log.info("the abandoned order could not be reported (%s)", exc.word)

    def _order(self, client: AcmeClient, key, reservation: Reservation | None, active: Generation | None, now: float) -> tuple[bytes, str | None]:
        policy_c = self._policy
        profile = client.offered_profile(policy_c["profile"], policy_c["profile_fallback"])
        replaces = None
        if active is not None and active.ca == self._ca_tag and now < active.info.not_after and "renewalInfo" in client.directory():
            with contextlib.suppress(ValueError):
                replaces = certificate_id(active.chain_pem)
        csr = make_csr(key, self.hostname)
        challenge = "dns-01" if self.mode == "dns-01" else "http-01"
        publish, unpublish = (self._txt_hooks(reservation) if reservation is not None else (self.challenges.publish, self.challenges.unpublish))
        while True:
            try:
                return client.obtain(self.hostname, csr, publish, unpublish, challenge=challenge, profile=profile, replaces=replaces), profile
            except AcmeError as exc:
                if replaces and (exc.type.endswith(":alreadyReplaced") or exc.status in (400, 403, 404, 409)
                                 and not exc.type.endswith((":rateLimited", ":badNonce", ":invalidProfile", ":accountDoesNotExist"))):
                    # alreadyReplaced (409): another order already replaces that certificate. Boulder also REFUSES the whole order (it does not fall back to a
                    # plain one) when `replaces` is malformed, names a certificate it does not know, or one issued to another account (an account that was
                    # registered again): all of them renew as a plain order, once.
                    replaces = None
                elif profile and exc.type.endswith(":invalidProfile"):
                    profile = None
                elif exc.type.endswith(":accountDoesNotExist") and self._account_url():
                    # the CA no longer knows our account (a test CA was reset): forget it and register again, which needs the terms to be accepted
                    log.warning("the CA does not know the stored account any more: registering a new one")
                    self.store.write_file(self._account_files()[1], b"{}")
                    self._client_cache = None
                    client = self._acme()
                else:
                    raise

    def _txt_hooks(self, reservation: Reservation):
        """publish/unpublish for DNS-01 through the broker. The answer is CHECKED: the broker must say it wrote a TXT at _acme-challenge.<our host>;
        anything else (a record of another name, another type) aborts the order and takes back what was written."""
        expected = "_acme-challenge." + self.hostname
        ttl = self._policy["txt_ttl_s"]

        def publish(_token: str, proof: str) -> None:
            if not SPKI_RE.fullmatch(proof):
                raise BrokerError("bad_answer")
            answer = self.broker.set_txt(reservation.id, proof)
            if answer.name != expected or answer.type != "TXT" or answer.ttl != ttl:
                raise BrokerError("dns_mismatch")
            if self._dns_settle:
                self._sleep(self._dns_settle)

        def unpublish(_token: str) -> None:
            try:
                self.broker.clear_txt(reservation.id)
            except BrokerError as exc:   # the broker also clears it on confirm and when the reservation times out
                log.info("the TXT could not be cleared now (%s)", exc.word)

        return publish, unpublish

    def _failed(self, state: dict[str, Any], active: Generation | None, exc: BaseException, number: int | None, attempted: bool) -> PassResult:
        """Whatever went wrong, the serving certificate was not touched. The generation that never served is removed, the failure is counted (when an
        order had been started) and the next attempt waits: at least the gap, doubling, and as long as a rate limit or the broker asks."""
        now = self.clock.now()
        word = error_word(exc)
        if number is not None:
            with contextlib.suppress(TlsStoreError):
                self.store.discard(number)
        state["last_error"] = word
        wait = 0.0
        # Boulder: a rate limit is 429 rateLimited; the per-IP request limits of its load balancers are a bare 503 with Retry-After
        rate_limited = isinstance(exc, AcmeError) and (exc.type.endswith(":rateLimited") or exc.status == 429
                                                       or (exc.status == 503 and exc.retry_after is not None))
        if attempted:
            state["failures"] = state.get("failures", 0) + 1
        elif not rate_limited and not (isinstance(exc, BrokerError) and not exc.soft):
            state["soft_failures"] = state.get("soft_failures", 0) + 1
            state["soft_until"] = now + min(SOFT_RETRY_CEILING_S, SOFT_RETRY_FLOOR_S * 2 ** (state["soft_failures"] - 1))
        retry = getattr(exc, "retry_after", None)
        if rate_limited or (isinstance(exc, BrokerError) and (exc.status == 429 or exc.word in ("label_retired", "license_inactive"))):
            # a limit (the CA's, a new-account-per-IP one, the broker's) is a wait, never a hard failure: the certificate in use keeps serving
            wait = retry if retry else float(self._policy["min_attempt_gap_s"])
            state["blocked_until"] = now + min(wait, BLOCK_CEILING_S)
            state["blocked_reason"] = "rate_limited" if rate_limited else word
        elif isinstance(exc, BrokerError) and not exc.soft and not attempted:
            state["blocked_until"], state["blocked_reason"] = now + float(self._policy["min_attempt_gap_s"]), word
        log.info("issuance did not complete (%s)", word)
        waiting = self._wait(state, now)
        until = waiting[0] if waiting else None
        self._save(state, active, now, "waiting" if active is None or now < active.info.not_after else "expired", reason=word, wait_until=until)
        return PassResult("failed", generation=active.number if active else None, error=word, wait_until=until)

    # -- confirming and adopting
    def _flush_confirm(self, state: dict[str, Any], active: Generation | None) -> None:
        pending = state.get("pending_confirm")
        if not pending or self.broker is None:
            state.pop("pending_confirm", None)
            return
        if (not isinstance(pending, dict) or not isinstance(pending.get("reservation_id"), str) or not isinstance(pending.get("spki"), str)
                or type(pending.get("not_before")) is not int or type(pending.get("not_after")) is not int):
            pending = {}   # a record that is not ours to read: dropped below with the ones that have nothing to confirm
        if active is None or pending.get("gen") != active.number:
            state.pop("pending_confirm", None)   # the certificate it was for never went into service: there is nothing to confirm
            self._persist(state)
            return
        try:
            stamp = self.broker.confirm(pending["reservation_id"], pending["spki"], pending["not_before"], pending["not_after"])
            self.clock.observe_if_stale(stamp, CLOCK_SYNC_EVERY_S)
        except BrokerError as exc:
            if exc.soft:
                log.info("the confirmation will be sent later (%s)", exc.word)
                return
            log.warning("the broker refused the confirmation (%s)", exc.word)   # an expired or closed reservation keeps its slot without it
        state.pop("pending_confirm", None)
        state["confirmed_once"] = True
        self._persist(state)

    def _adopt(self, now: float, state: dict[str, Any]) -> Generation | None:
        """A crash between "chain written" and "pointer swapped" leaves a complete, valid generation that nothing names. If this device made its key and
        it is newer than the serving one, put it in service: the CA already counted it and the broker may already hold its reservation."""
        if self.mode == "selfsigned":
            return None
        known = {row["spki_sha256"] for row in self.store.spki_log()}
        active = self.store.active()
        for generation in self.store.resumable(self.hostname):
            if generation.ca != self._ca_tag or generation.spki not in known or generation.info.not_after <= now:
                continue
            if active is None or generation.info.not_before > active.info.not_before:
                self.store.activate(generation.number)
                log.info("generation %s was complete but not in service: now it is", generation.number)
                return generation
            break
        return None

    # -- the status file
    def _status_document(self, active: Generation | None, state: dict[str, Any], now: float, word: str, *, reason: str = "", error: str = "",
                         wait_until: float | None = None) -> dict[str, Any]:
        offset = self.clock.offset
        try:
            pointer = self.store.pointer()
        except TlsStoreError:
            pointer = None
        ari = state.get("ari") or {}
        document: dict[str, Any] = {
            "v": 1, "state": word, "reason": reason or None, "mode": self.mode, "host": self.hostname, "ca": self._ca_tag,
            "updated_at": int(now), "generation": active.number if active else None, "previous_generation": pointer.get("previous") if pointer else None,
            "served": bool(pointer and pointer["served"]), "spki_sha256": active.spki if active else None,
            "not_before": int(active.info.not_before) if active else None, "not_after": int(active.info.not_after) if active else None,
            "profile": active.meta.get("profile") if active else None,
            "attempts_total": state.get("attempt_count", 0), "failures": state.get("failures", 0),
            "last_attempt_at": int(state["last_attempt"]) if type(state.get("last_attempt")) in (int, float) else None,
            "next_attempt_at": int(wait_until) if wait_until else None,
            "last_error": error or state.get("last_error") or None,
            "clock_offset_s": round(offset, 1) if offset is not None else None,
            "clock_skew": bool(offset is not None and abs(offset) > tls_policy()["authorization"]["node_skew_max_s"]),
            "ari_window": [int(ari["start"]), int(ari["end"])] if "start" in ari else None,
            "confirm_pending": bool(state.get("pending_confirm")),
        }
        return document

    def _save(self, state: dict[str, Any], active: Generation | None, now: float, word: str, *, reason: str = "", wait_until: float | None = None) -> None:
        self._persist(state)
        status = self._status_document(active, state, now, word, reason=reason, wait_until=wait_until)
        try:
            status["key_storage"] = self.store.key_storage()
        except TlsStoreError as exc:
            status["key_storage"] = {"error": exc.word}
        self.store.write_status(status)

    def status(self) -> dict[str, Any] | None:
        try:
            return self.store.read_status()
        except TlsStoreError:
            return None

    # -- what the 1.1 runner and the tunnel client already call
    def current(self) -> CertState | None:
        """The serving certificate when it is usable now: it covers the name, comes from the configured CA and is within its validity."""
        generation = self._active()
        if generation is None or generation.ca != self._ca_tag or self.hostname not in generation.info.names:
            return None
        if not generation.info.not_before - 600 <= self.clock.now() < generation.info.not_after:
            return None
        return CertState(generation.chain_path, generation.key_path, generation.info, self._ca_tag, False, generation.number)

    def due(self, state: CertState | None = None) -> bool:
        return self._due_reason(self._active(), self.clock.now(), self._load_state_quiet()) is not None

    def _load_state_quiet(self) -> dict[str, Any]:
        try:
            return self.store.read_state() or {}
        except TlsStoreError:
            return {}

    def ensure(self, *, force: bool = False) -> CertState:
        result = self.run_once(force=force)
        state = self.current()
        if state is None:
            wait = max(0.0, (result.wait_until or 0.0) - self.clock.now()) if result.wait_until else None
            raise CertUnavailable(f"no certificate yet ({result.reason or result.error or result.action})", type=result.error, retry_after=wait)
        return replace(state, issued_now=result.issued)

    def issue(self) -> CertState:
        return self.ensure(force=True)

    def next_wake(self) -> float:
        """Seconds until a pass can change anything: the earliest of the renewal moment, the next ARI check, the end of a wait, a confirmation to
        retry. Between 60 s and an hour, so a changed clock or a changed file is noticed."""
        now = self.clock.now()
        state = self._load_state_quiet()
        active = self._active()
        moments = [now + 3600.0]
        if active is not None:
            moments.append(active.info.renew_at)
            ari = state.get("ari") or {}
            if ari.get("fp") == active.info.fingerprint:
                moments.append(float(ari.get("next_check", now + 3600.0)))
                if "start" in ari:
                    moments.append(ari["start"] + ari["frac"] * (ari["end"] - ari["start"]))
        if state.get("pending_confirm"):
            moments.append(now + 300.0)
        wait = self._wait(state, now)
        if wait is not None and (active is None or self._due_reason(active, now, state) is not None):
            moments.append(wait[0])
        return max(60.0, min(m for m in moments) - now) if len(moments) > 1 else 3600.0

    # -- uninstall
    def uninstall(self, *, revoke: bool = True) -> dict[str, Any]:
        """Plan section 4, in this order: the keys and certificates go FIRST, at once, with no network; then revokeCert, signed with the ACME account key
        (read into memory before the folder was removed), for every certificate that was still in service; best effort. Releasing the label and the TXT
        at the broker is the installer's next step (HttpBroker.release("uninstall")), after this one."""
        evidence: dict[str, Any] = {"wiped": False, "revoked": 0, "revoke_errors": []}
        leaves: list[bytes] = []
        account_key = account_url = None
        with contextlib.suppress(TlsStoreError):
            for number in self.store.generations():
                generation = self.store.generation(number)
                if generation is not None and generation.ca == self._ca_tag:
                    leaves.append(leaf_der(generation.chain_pem))
            raw = self.store.read_file(self._account_files()[0])
            account_key = serialization.load_pem_private_key(raw, password=None) if raw else None
            account_url = self._account_url()
        self.store.destroy()
        evidence["wiped"] = not self.dir.exists() or not any(self.dir.iterdir())
        if not revoke or self.mode == "selfsigned" or not leaves or account_key is None or not account_url:
            return evidence
        client = AcmeClient(self.directory_url, account_key, http=self._http, account_url=account_url, sleep=self._sleep)
        for der in leaves:
            try:
                client.revoke(der)
                evidence["revoked"] += 1
            except (AcmeError, httpx.HTTPError) as exc:
                evidence["revoke_errors"].append(error_word(exc))
        return evidence


async def renew_then_connect(manager: DeviceCertManager, connect: Callable[[], Any], *, wait: float | None = None) -> PassResult:
    """The order a device starts in: the certificate FIRST, the tunnel SECOND. A computer that was off for 100 days wakes with an expired certificate; the
    tunnel can be up in a second, but ChatGPT would meet a certificate that fails, so the pass runs first (at most ``wait`` seconds, by default
    policy.certificates.wait_after_install_s) and the tunnel connects afterwards whatever the pass said: a certificate that is not due, one that is
    waiting for a rate limit and one that could not be issued still leave the connection worth making (the control channel is not the certificate)."""
    limit = float(tls_policy()["certificates"]["wait_after_install_s"]) if wait is None else wait
    try:
        result = await asyncio.wait_for(asyncio.to_thread(manager.run_once), limit)
    except asyncio.TimeoutError:
        result = PassResult("failed", error="pass_timeout")
    outcome = connect()
    if asyncio.iscoroutine(outcome):
        await outcome
    return result

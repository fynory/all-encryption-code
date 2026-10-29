"""ALL 2.0 WP36: the device watches Certificate Transparency for ITS OWN name (plan section 4, "Mala emisión detectable, con ancla en el dispositivo").

The two other detectors (the site Worker's cron and the independent ct_watch.py) compare CT with what the control plane's registry says, so a compromised control plane
could rewrite the registry and keep them quiet. This one cannot be rewritten from there: the only list it trusts is ``tls/spki-log`` (tls_store.py), one line for every key
THIS computer ever made, written before the key is used and never changed. Once a day, and ten minutes after each issuance, it asks CT what certificates exist for this
computer's own name and raises an alert for

  unknown_key   a certificate for the name whose key this computer never made (nobody else can have one honestly: an ACME order proves the key with a signature), and
  bad_issuer    a certificate for the name from anyone but Let's Encrypt, whatever its key.

Everything else is silent: our own certificates, and their precertificates (the same key and the same issuance: CT lists the pair, Cert Spotter as one entry and crt.sh as
two), so the pair is never counted twice and never alarms. The comparison does not look at serials, dates or the control plane.

What is asked, and of whom. Cert Spotter first (``/v1/issuances`` for the exact name, wildcards that cover it included), crt.sh when Cert Spotter cannot be read whole. The
request holds the name and fixed words and nothing else: no key, no licence, no device id, no cookie, no body; a redirect is refused. The name is public anyway (it is in CT);
the zone is never asked about alone, so a wildcard issued for the zone shows here only through Cert Spotter's ``match_wildcards`` (the other two detectors watch the zone).
Whole history, every time, never a cursor: a computer that was off for 100 days reads the certificates issued meanwhile (expired ones too) in its first look, and a source
that repeats, reorders or duplicates entries changes nothing.

Honesty about being blind. When this computer serves a certificate that is more than two days old, a source that is read whole must show it (it is the canary: a page that came
back empty or an index that is behind is not an all-clear). A source that answers with a page that does not parse whole (truncated, HTML, a row without a key hash), refuses, times out or hands out
more than this device is willing to read counts as down, and so does a crt.sh listing that needs more downloads than one run allows (the ones done are kept: the next
run finishes). Neither source whole for ``certificates.ct_degraded_after_s`` (72 h) is ``monitoring: degraded``, and the tray says so; a watch that never looked is
``pending``, and only a complete look that is not older than two intervals is ``ok``. Nothing here ever turns an unread CT into "all clear".

State, in ``tls/ct-watch.json`` (0600 in the 0700 folder, so uninstall wipes it with the keys): the alerts (kind, key hash, first seen, acknowledged), the moments of the last
look, and what crt.sh downloads already told. It holds no secret. ``ct_watch_status()`` is the shape ``e2e_status.build(ct=...)`` writes into ``e2e-status.json``: ``alert`` is
the tray's persistent message (an alert nobody acknowledged: ``acknowledge()``), ``alert_open`` is the fleet block's ``ct_alert`` (also true after an acknowledgement for as
long as the certificate that raised it is still valid: a person who saw it has not made it go away).

Timing comes from contracts/policy.json (``certificates.ct_check_interval_s``, ``ct_degraded_after_s``); this file only holds the pacing of its own retries.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import random
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from . import e2e_policy as policy
from .tls_store import TlsStore, TlsStoreError, b64url

log = logging.getLogger("all_mcp.e2e_ct_watch")

STATE_FILE = "ct-watch.json"
LOCK_FILE = "ct-watch.lock"
SCHEMA_VERSION = 1
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"
CRTSH_URL = "https://crt.sh/"
USER_AGENT = "all-mcp-ct-selfwatch/2"
KINDS = ("unknown_key", "bad_issuer")
SOURCES = ("certspotter", "crtsh")
CANARY_AFTER_S = 172800.0           # a certificate older than this is expected to show in every CT source
CHECK_AFTER_ISSUANCE_S = 600.0       # a new certificate has reached the logs by now (the precertificate went in before the CA issued)
FETCH_TIMEOUT_S = 20.0
JSON_MAX_BYTES = 4 * 1024 * 1024     # a page of CT rows for one name; more than this is not read
PEM_MAX_BYTES = 64 * 1024
CERTSPOTTER_MAX_PAGES = 20
CRTSH_DOWNLOADS_PER_RUN = 12
RETRY_FIRST_S = 900.0                # a look that failed is retried after 15 min, 1 h, 4 h, 16 h, and then at the usual interval
RETRY_FACTOR = 4.0
INTERVAL_JITTER = 0.1                # a device looks between 0 and 10 % after the interval, so the fleet does not ask a source at the same moment
STALE_INTERVALS = 2                  # a complete look older than this many intervals is no longer "ok"
ALERTS_KEPT = 64
CRTSH_KEPT = 256
_WORD = re.compile(r"[a-z0-9_]{1,48}")
_SPKI = re.compile(r"[A-Za-z0-9_-]{43}")
_ROW_ID = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_CRTSH_ID = re.compile(r"[0-9]{1,20}")
_HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
_LETS_ENCRYPT = re.compile(r"let['’]s encrypt", re.IGNORECASE)


class CtSourceError(Exception):
    """A source of CT that could not be read whole. ``word`` is a closed word (never text of the network) the state and the status may carry."""

    def __init__(self, word: str):
        super().__init__(word)
        self.word = word


# ------------------------------------------------------------------------------------------------------------------------ certificates and the comparison

@dataclass(frozen=True)
class CtCert:
    """A certificate reduced to what the comparison needs, from whichever source. ``spki`` is the base64url SHA-256 of the SubjectPublicKeyInfo, the form of ``spki-log``."""
    key: str
    names: tuple[str, ...]
    spki: str
    issuer: str
    not_after: int | None
    source: str


@dataclass(frozen=True)
class Finding:
    kind: str
    spki: str
    not_after: int | None

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.spki}"


def normalize(name: Any) -> str:
    return name.strip().lower().rstrip(".") if isinstance(name, str) else ""


def covers(names: tuple[str, ...] | list[str], host: str) -> bool:
    """Whether a certificate with these names is one for ``host``: the name itself, or a wildcard that covers it (``*.zone`` covers exactly one label)."""
    for name in names:
        if name == host:
            return True
        if name.startswith("*.") and "." in host and host.split(".", 1)[1] == name[2:]:
            return True
    return False


def is_lets_encrypt(issuer: str) -> bool:
    return _LETS_ENCRYPT.search(issuer) is not None


def evaluate(host: str, certs: list[CtCert], known: set[str]) -> list[Finding]:
    """What is wrong among the certificates CT showed for ``host``: against the keys THIS computer made (``known``), and against the issuer. One finding per (kind, key)."""
    found: dict[str, Finding] = {}
    for cert in certs:
        if not covers(cert.names, host):
            continue
        if cert.spki not in known:
            finding = Finding("unknown_key", cert.spki, cert.not_after)
            found.setdefault(finding.key, finding)
        if not is_lets_encrypt(cert.issuer):
            finding = Finding("bad_issuer", cert.spki, cert.not_after)
            found.setdefault(finding.key, finding)
    return list(found.values())


def _seconds(text: Any) -> int | None:
    if not isinstance(text, str):
        return None
    import datetime
    candidate = text.strip().replace(" ", "T")
    candidate = candidate if re.search(r"(Z|[+-]\d\d:?\d\d)$", candidate) else candidate + "Z"
    try:
        return int(datetime.datetime.fromisoformat(candidate.replace("Z", "+00:00")).timestamp())
    except ValueError:
        return None


def certs_from_certspotter(rows: Any, host: str) -> list[CtCert]:
    """Cert Spotter ``/v1/issuances`` rows (expand=dns_names, issuer). ``pubkey_sha256`` is the hex digest of the SPKI. A row that cannot be compared (no id, no key hash) makes
    the page unusable: skipping it would be a certificate nobody looked at."""
    if not isinstance(rows, list):
        raise CtSourceError("bad_body")
    certs = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str) or _ROW_ID.fullmatch(row["id"]) is None:
            raise CtSourceError("bad_body")
        digest = str(row.get("pubkey_sha256", "")).lower()
        if _HEX_SHA256.fullmatch(digest) is None:
            raise CtSourceError("bad_body")
        issuer = row.get("issuer") if isinstance(row.get("issuer"), dict) else {}
        names = tuple(normalize(name) for name in row["dns_names"] if isinstance(name, str)) if isinstance(row.get("dns_names"), list) else (host,)   # asked for this name: no list, no doubt
        certs.append(CtCert(key=str(row.get("tbs_sha256") or row["id"]), names=names, spki=b64url(bytes.fromhex(digest)),
                            issuer=" ".join(str(part) for part in (issuer.get("friendly_name"), issuer.get("name")) if isinstance(part, str)),
                            not_after=_seconds(row.get("not_after")), source="certspotter"))
    return certs


def crtsh_groups(rows: Any) -> list[dict[str, Any]]:
    """crt.sh lists an issuance twice, as a precertificate and as the final certificate: same serial, same issuer, the same key. One row of each pair is enough (the rows of one
    group are ``ids``, so a pair already read is known by either id)."""
    if not isinstance(rows, list):
        raise CtSourceError("bad_body")
    groups: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or _CRTSH_ID.fullmatch(str(row.get("id", ""))) is None:
            raise CtSourceError("bad_body")
        serial = str(row.get("serial_number", "")).lower()
        identity = f"{serial}|{row.get('issuer_ca_id')}" if serial else f"id|{row['id']}"
        group = groups.setdefault(identity, {"ids": []})
        group["ids"].append(str(row["id"]))
    return list(groups.values())


def read_certificate(pem: bytes) -> tuple[tuple[str, ...], str, str, int | None]:
    """(names, SPKI hash, issuer, not_after) of a PEM certificate or precertificate. A key this cannot hash is not hidden: its hash is of the whole certificate, which no key of
    this computer's list can equal, so it is an unknown key."""
    try:
        certificate = x509.load_pem_x509_certificate(pem)
    except ValueError:
        raise CtSourceError("bad_certificate") from None
    try:
        names = tuple(certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        names = ()
    if not names:
        names = tuple(attribute.value for attribute in certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME) if isinstance(attribute.value, str))
    try:
        spki = b64url(hashlib.sha256(certificate.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).digest())
    except Exception:  # noqa: BLE001 - an algorithm this library does not know
        spki = b64url(hashlib.sha256(b"unreadable-key|" + certificate.fingerprint(hashes.SHA256())).digest())
    try:
        not_after: int | None = int(certificate.not_valid_after_utc.timestamp())
    except AttributeError:  # cryptography < 42
        import datetime
        not_after = int(certificate.not_valid_after.replace(tzinfo=datetime.timezone.utc).timestamp())
    return tuple(normalize(name) for name in names), spki, certificate.issuer.rfc4514_string(), not_after


# ------------------------------------------------------------------------------------------------------------------------ the two sources

class CtSources:
    """The questions, and nothing else. Every request is a GET to one of two fixed addresses with the device's own name (or a crt.sh certificate number) in the query and the
    two fixed headers below; the name is checked against the contract's pattern first. Blocking: run it in a thread."""

    def __init__(self, host: str, *, transport: httpx.BaseTransport | None = None):
        if policy.anchored("identity.fqdn_regex").fullmatch(host) is None:
            raise ValueError("not a device name")
        self.host = host
        self._http = httpx.Client(timeout=httpx.Timeout(FETCH_TIMEOUT_S), headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
                                  follow_redirects=False, trust_env=False, transport=transport)

    def _get(self, url: str, limit: int) -> bytes:
        try:
            with self._http.stream("GET", url) as response:
                status = response.status_code
                if status == 429:
                    raise CtSourceError("rate_limited")
                if status != 200:
                    raise CtSourceError("redirect" if 300 <= status < 400 else f"http_{status // 100}xx")
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > limit:
                        raise CtSourceError("too_large")
                return bytes(body)
        except httpx.TimeoutException:
            raise CtSourceError("timeout") from None
        except httpx.HTTPError:
            raise CtSourceError("unreachable") from None

    def _json(self, url: str) -> Any:
        try:
            return json.loads(self._get(url, JSON_MAX_BYTES).decode("utf-8"))
        except (ValueError, UnicodeError):
            raise CtSourceError("bad_body") from None   # a page cut short, an HTML error page

    def certspotter(self) -> list[CtCert]:
        """Every issuance Cert Spotter knows for this name, from the first, page after page until an empty one."""
        certs: dict[str, CtCert] = {}
        after = ""
        for _ in range(CERTSPOTTER_MAX_PAGES):
            query = [("domain", self.host), ("include_subdomains", "false"), ("match_wildcards", "true"), ("expand", "dns_names"), ("expand", "issuer")]
            if after:
                query.append(("after", after))
            rows = self._json(f"{CERTSPOTTER_URL}?{urllib.parse.urlencode(query)}")
            if not isinstance(rows, list):
                raise CtSourceError("bad_body")
            if not rows:
                return list(certs.values())
            fresh = [cert for cert in certs_from_certspotter(rows, self.host) if cert.key not in certs]
            if not fresh:
                return list(certs.values())   # a server that ignores `after` and repeats a page has nothing more to say
            certs.update((cert.key, cert) for cert in fresh)
            after = rows[-1]["id"]
        raise CtSourceError("too_many_pages")     # never compare against part of the history

    def crtsh(self, cache: dict[str, dict[str, Any]]) -> tuple[list[CtCert], dict[str, dict[str, Any]], bool]:
        """(certificates, what was downloaded this time, complete). ``cache`` is what earlier runs downloaded, by crt.sh id: only the groups not in it cost a request."""
        groups = crtsh_groups(self._json(f"{CRTSH_URL}?{urllib.parse.urlencode([('q', self.host), ('output', 'json')])}"))
        certs: list[CtCert] = []
        fresh: dict[str, dict[str, Any]] = {}
        downloads = 0
        complete = True
        for group in groups:
            entry = next((cache[i] for i in group["ids"] if i in cache), None)
            if entry is None:
                if downloads >= CRTSH_DOWNLOADS_PER_RUN:
                    complete = False
                    continue
                downloads += 1
                names, spki, issuer, not_after = read_certificate(self._get(f"{CRTSH_URL}?{urllib.parse.urlencode([('d', group['ids'][0])])}", PEM_MAX_BYTES))
                entry = {"names": list(names), "spki": spki, "issuer": issuer, "na": not_after}
                fresh[group["ids"][0]] = entry
            certs.append(CtCert(key=group["ids"][0], names=tuple(entry["names"]), spki=entry["spki"], issuer=entry["issuer"], not_after=entry["na"], source="crtsh"))
        return certs, fresh, complete


# ------------------------------------------------------------------------------------------------------------------------ the state

def word(value: Any, default: str = "") -> str:
    return value if isinstance(value, str) and _WORD.fullmatch(value) else default


def _int(value: Any) -> int | None:
    return value if type(value) is int and 0 <= value < 10 ** 11 else None


def host_tag(host: str) -> str:
    return hashlib.sha256(b"all-ct-selfwatch-v1/" + host.encode("ascii", "replace")).hexdigest()[:16]


def empty_state(tag: str, now: float) -> dict[str, Any]:
    return {"v": SCHEMA_VERSION, "host": tag, "started_at": int(now), "next_check_at": None, "last_attempt_at": None, "last_ok_at": None, "fail_since": None,
            "failures": 0, "source": "", "last_error": "", "alerts": {}, "crtsh": {}}


def clean_state(document: Any, tag: str | None, now: float) -> dict[str, Any]:
    """The state as read, shaped (a value of the wrong type is the default, nothing else is kept). A state of another name, or one that is not a state, starts again: CT is
    read whole every time, so what it showed is raised again by the next look."""
    if not isinstance(document, dict) or document.get("v") != SCHEMA_VERSION or (tag is not None and document.get("host") != tag):
        return empty_state(tag or "", now)
    state = empty_state(str(document.get("host", "")), now)
    for key in ("started_at", "next_check_at", "last_attempt_at", "last_ok_at", "fail_since"):
        state[key] = _int(document.get(key))
    state["started_at"] = state["started_at"] if state["started_at"] is not None else int(now)
    state["failures"] = min(_int(document.get("failures")) or 0, 1000)
    state["source"] = word(document.get("source")) if document.get("source") in SOURCES else ""
    state["last_error"] = word(document.get("last_error"))
    alerts = document.get("alerts")
    for key, alert in (alerts.items() if isinstance(alerts, dict) else ()):
        if (isinstance(alert, dict) and alert.get("kind") in KINDS and isinstance(alert.get("spki"), str) and _SPKI.fullmatch(alert["spki"])
                and key == f"{alert['kind']}:{alert['spki']}" and _int(alert.get("raised_at")) is not None):
            state["alerts"][key] = {"kind": alert["kind"], "spki": alert["spki"], "raised_at": alert["raised_at"], "ack_at": _int(alert.get("ack_at")),
                                    "not_after": _int(alert.get("not_after"))}
    cache = document.get("crtsh")
    for key, entry in (cache.items() if isinstance(cache, dict) else ()):
        if (_CRTSH_ID.fullmatch(str(key)) and isinstance(entry, dict) and isinstance(entry.get("spki"), str) and isinstance(entry.get("issuer"), str)
                and isinstance(entry.get("names"), list) and all(isinstance(name, str) for name in entry["names"])):
            state["crtsh"][str(key)] = {"names": entry["names"][:100], "spki": entry["spki"][:64], "issuer": entry["issuer"][:300], "na": _int(entry.get("na"))}
    return state


def monitoring(state: dict[str, Any], now: float) -> str:
    """``degraded`` once the looks have failed for the policy's 72 h, ``ok`` only for a complete look that is recent and not followed by a failure, ``pending`` otherwise
    (never looked, a catch-up after a long sleep, a retry after one failure). Never ``ok`` by default."""
    degraded_after = policy.value("certificates.ct_degraded_after_s")
    interval = policy.value("certificates.ct_check_interval_s")
    if state["fail_since"] is not None and now - state["fail_since"] >= degraded_after:
        return "degraded"
    if state["last_ok_at"] is not None and state["fail_since"] is None and now - state["last_ok_at"] <= STALE_INTERVALS * interval:
        return "ok"
    return "pending"


def summarize(state: dict[str, Any], now: float) -> dict[str, Any]:
    """The block ``e2e_status.build(ct=...)`` writes. ``alert``: some alert is not acknowledged. ``alert_open``: some alert is not acknowledged or its certificate is still
    valid (or its end is not known): the fleet block's ``ct_alert``."""
    alerts = list(state["alerts"].values())
    waiting = [alert for alert in alerts if alert["ack_at"] is None]
    open_ = [alert for alert in alerts if alert["ack_at"] is None or alert["not_after"] is None or alert["not_after"] > now]
    return {"monitoring": monitoring(state, now), "alert": bool(waiting), "alert_open": bool(open_), "kinds": sorted({alert["kind"] for alert in open_}),
            "count": len(alerts), "unacknowledged": len(waiting), "since": min((alert["raised_at"] for alert in waiting), default=None),
            "last_ok_at": state["last_ok_at"], "last_check_at": state["last_attempt_at"], "next_check_at": state["next_check_at"], "fail_since": state["fail_since"],
            "source": state["source"], "last_error": state["last_error"]}


def _unavailable(error: str) -> dict[str, Any]:
    """The block when the state cannot be read (an unsafe folder, a full disk): not green, not silent."""
    return {"monitoring": "degraded", "alert": False, "alert_open": False, "kinds": [], "count": 0, "unacknowledged": 0, "since": None, "last_ok_at": None,
            "last_check_at": None, "next_check_at": None, "fail_since": None, "source": "", "last_error": word(error, "storage_error")}


@dataclass
class CheckResult:
    """What one look did. ``ok`` is a complete comparison; ``new`` are the alerts raised by THIS look (never the ones already standing)."""
    ok: bool
    source: str = ""
    error: str = ""
    seen: int = 0
    new: list[Finding] = field(default_factory=list)


# ------------------------------------------------------------------------------------------------------------------------ the watch

class CtWatch:
    def __init__(self, host: str, *, store: TlsStore | None = None, sources: CtSources | None = None, clock: Callable[[], float] = time.time,
                 jitter: Callable[[], float] = random.random):
        self.host = host
        self.tag = host_tag(host)
        self.store = store or TlsStore()
        self.sources = sources or CtSources(host)
        self.clock = clock
        self.jitter = jitter

    # -- the state
    def _load(self) -> dict[str, Any]:
        raw = self.store.read_file(STATE_FILE)
        try:
            document = json.loads(raw.decode("utf-8")) if raw else None
        except (ValueError, UnicodeError):
            document = None
        return clean_state(document, self.tag, self.clock())

    def _update(self, change: Callable[[dict[str, Any]], Any]) -> Any:
        with self.store.locked(LOCK_FILE):
            state = self._load()
            outcome = change(state)
            self.store.write_file(STATE_FILE, json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        return outcome

    def status(self) -> dict[str, Any]:
        """The block for ``e2e-status.json``; one cheap read of the state file."""
        try:
            return summarize(self._load(), self.clock())
        except TlsStoreError as error:
            return _unavailable(error.word)

    def due_in(self) -> float:
        """Seconds until the next look (0 when it is due, or when the state cannot be read: the look itself says why)."""
        try:
            state = self._load()
        except TlsStoreError:
            return 0.0
        now = self.clock()
        interval = float(policy.value("certificates.ct_check_interval_s"))
        due = state["next_check_at"]
        if due is None:
            return 0.0
        return max(0.0, min(due - now, interval * (1 + INTERVAL_JITTER)))   # a clock that went back cannot push the look further than one interval

    def nudge(self, after_s: float = CHECK_AFTER_ISSUANCE_S) -> None:
        """A certificate was just issued: look in ``after_s`` seconds unless a look is due sooner."""
        def change(state: dict[str, Any]) -> None:
            soon = int(self.clock() + after_s)
            state["next_check_at"] = soon if state["next_check_at"] is None else min(state["next_check_at"], soon)
        with contextlib.suppress(TlsStoreError, OSError):
            self._update(change)

    def acknowledge(self) -> int:
        return acknowledge(self.store, self.clock)

    def _canary(self) -> str | None:
        """The key of the certificate this computer serves, once it is old enough to be in CT everywhere: a source that is read whole shows it. One that does not has an
        incomplete view (a page that came back empty, an index that is behind), and an empty or short answer is never taken for an all-clear."""
        try:
            active = self.store.active()
        except TlsStoreError:
            return None
        if active is None or self.clock() - active.info.not_before < CANARY_AFTER_S:
            return None
        return active.spki

    # -- one look
    def check(self) -> CheckResult:
        """Ask CT for this name and compare. Blocking. Never raises for what a source or the disk does: the outcome is in the result and in the state."""
        try:
            known = {row["spki_sha256"] for row in self.store.spki_log() if _SPKI.fullmatch(str(row.get("spki_sha256", "")))}
            cache = self._load()["crtsh"]
        except TlsStoreError as error:
            return CheckResult(False, error=word(error.word, "storage_error"))
        canary = self._canary()
        certs: list[CtCert] = []
        fresh: dict[str, dict[str, Any]] = {}
        ok, source, errors = False, "", []
        for name in SOURCES:
            try:
                if name == "certspotter":
                    got, complete = self.sources.certspotter(), True
                else:
                    got, fresh, complete = self.sources.crtsh(cache)
            except CtSourceError as error:
                errors.append(error.word)
                continue
            except Exception as error:  # noqa: BLE001 - a bug in a parser is a source that cannot be read, never a crashed watch
                log.warning("CT source %s failed: %s", name, type(error).__name__)
                errors.append("source_error")
                continue
            certs.extend(got)    # what any source showed is compared, even when the look as a whole is not complete
            if not complete:
                errors.append("incomplete")
            elif canary is not None and canary not in {cert.spki for cert in got}:
                errors.append("canary_missing")
            else:
                ok, source = True, name
                break
        findings = evaluate(self.host, certs, known)
        error = "" if ok else (errors[-1] if errors else "source_error")
        result = CheckResult(ok, source, error, len(certs or []))

        def record(state: dict[str, Any]) -> None:
            now = int(self.clock())
            interval = float(policy.value("certificates.ct_check_interval_s"))
            for finding in findings:
                if finding.key not in state["alerts"]:
                    state["alerts"][finding.key] = {"kind": finding.kind, "spki": finding.spki, "raised_at": now, "ack_at": None, "not_after": finding.not_after}
                    result.new.append(finding)
            if len(state["alerts"]) > ALERTS_KEPT:   # a flood of foreign certificates cannot grow the file: what nobody has seen stays, the oldest acknowledged go
                ranked = sorted(state["alerts"].items(), key=lambda item: (item[1]["ack_at"] is None, item[1]["raised_at"]))
                state["alerts"] = dict(ranked[-ALERTS_KEPT:])
            state["crtsh"] = dict(list({**state["crtsh"], **fresh}.items())[-CRTSH_KEPT:])
            state["last_attempt_at"] = now
            if ok:
                state.update(last_ok_at=now, fail_since=None, failures=0, source=source, last_error="")
                state["next_check_at"] = int(now + interval * (1 + INTERVAL_JITTER * self.jitter()))
            else:
                state["failures"] = min(state["failures"] + 1, 1000)
                state["fail_since"] = state["fail_since"] if state["fail_since"] is not None else now
                state["last_error"] = word(error, "source_error")
                state["next_check_at"] = int(now + min(interval, RETRY_FIRST_S * RETRY_FACTOR ** (state["failures"] - 1)))
        try:
            self._update(record)
        except (TlsStoreError, OSError) as failure:
            result.ok, result.error = False, word(getattr(failure, "word", ""), "storage_error")   # the alerts of this look are in the result, the caller logs them
        for finding in result.new:
            log.error("CT shows a certificate for this computer's name that it did not make (%s)", finding.kind)
        return result


def acknowledge(store: TlsStore | None = None, clock: Callable[[], float] = time.time) -> int:
    """The person has seen the alerts: the tray's message goes away until a NEW alert is raised. Returns how many were acknowledged. Callable from any process (the tray, a
    command): the state is changed under its own lock."""
    store = store or TlsStore()
    with store.locked(LOCK_FILE):
        raw = store.read_file(STATE_FILE)
        try:
            document = json.loads(raw.decode("utf-8")) if raw else None
        except (ValueError, UnicodeError):
            document = None
        state = clean_state(document, None, clock())
        count = 0
        for alert in state["alerts"].values():
            if alert["ack_at"] is None:
                alert["ack_at"] = int(clock())
                count += 1
        if count:
            store.write_file(STATE_FILE, json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    return count


def stored_status(host: str, *, store: TlsStore | None = None, clock: Callable[[], float] = time.time) -> dict[str, Any] | None:
    """What the state file says without a watch running (the child is idle or the kill switch is on): None when there is no state, so nothing is said that was not seen.
    An alert that stands is shown in every state of the encrypted path."""
    store = store or TlsStore()
    try:
        raw = store.read_file(STATE_FILE)
        document = json.loads(raw.decode("utf-8")) if raw else None
    except (TlsStoreError, ValueError, UnicodeError):
        return None
    if not isinstance(document, dict) or document.get("host") != host_tag(host):
        return None
    return summarize(clean_state(document, host_tag(host), clock()), clock())

"""ALL 2.0: the device's TLS key and certificate chain on disk, as GENERATIONS (plan 2.0, sections 2 and 4).

Every issuance makes a NEW EC P-256 key and writes it, together with the chain the CA returns for it, into its own folder ``tls/gen-<n>/``.
Which generation serves is a tiny file, ``tls/current``, that is only ever replaced by an atomic rename. So:

  * the key that is serving is never overwritten, and the pointer never names a generation whose chain is not on disk and matches its key;
  * a crash at any moment leaves the previous pointer (and so the previous certificate) in force, plus at worst a folder that nothing names;
  * the previous generation is kept until the new one has served a handshake (``mark_served``), so a certificate that turns out not to work can
    still be gone back to;
  * nothing here follows a link: every file goes through ``_device_storage.PrivateStore`` (no symbolic links, one hard link, this user's, 0600,
    in a 0700 folder; an owner-only DACL on Windows), exactly like the device identity.

Layout of ``tls/`` (the folder is 0700, every file 0600):
  current           {"v":1,"gen":n,"previous":m|null,"served":bool}                      the pointer
  gen-<n>/          device.key, fullchain.pem, meta.json (host, CA, validity, SPKI hash)
  state.json        what the certificate manager remembers between runs (attempts, back-off, ARI, a confirmation still to send)
  status.json       what the tray, the runner and the fleet heartbeat read (no secret, never a TXT value)
  spki-log          append-only, one JSON line per key this device ever made: the anchor of the device's own CT self-watch (WP36)
  ct-watch.json     what the CT self-watch remembers: its alerts, their acknowledgements, the last look at CT (e2e_ct_watch.py; ct-watch.lock is its lock)
  key-storage.json  how the keys are kept (a file today) and whether a native store could hold them; it never changes by itself
  acme-account.key, acme-account.json, manager.lock

Constants come from contracts/policy.json (the copy in e2e_policy.json), never from here.
"""
from __future__ import annotations

import base64
import datetime
import errno
import functools
import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import ssl
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import tls_policy
from ._device_storage import CredentialStorageError, LockTimeout, PrivateStore, held_lock
from .config import state_dir

log = logging.getLogger("all_mcp.tls_store")

POINTER = "current"
STATE = "state.json"
STATUS = "status.json"
SPKI_LOG = "spki-log"
KEY_FILE = "device.key"
CHAIN_FILE = "fullchain.pem"
META_FILE = "meta.json"
KEY_STORAGE = "key-storage.json"
LOCK_FILE = "manager.lock"
GENERATION_RE = re.compile(r"gen-([1-9][0-9]{0,8})")
TEMPORARY_PREFIX = ".tmp-"
SCHEMA_VERSION = 1
MAX_POINTER_BYTES = 4096
UNSAFE_ERRNOS = {errno.ELOOP, errno.ENOTDIR, errno.EISDIR, errno.EPERM, errno.EACCES}


class TlsStoreError(Exception):
    """``word`` is a closed word (never text from the network) the status file and the heartbeat may carry."""

    def __init__(self, word: str, message: str = ""):
        super().__init__(message or word)
        self.word = word


@functools.lru_cache(maxsize=1)
def policy() -> dict[str, Any]:
    """The device's copy of contracts/policy.json (the contract generator sync keeps it byte-identical)."""
    return json.loads(Path(__file__).with_name("e2e_policy.json").read_text(encoding="utf-8"))


def certificate_policy() -> dict[str, Any]:
    return policy()["certificates"]


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------------------------------------------------- reading a chain

@dataclass(frozen=True)
class CertInfo:
    names: tuple[str, ...]
    not_before: float
    not_after: float
    fingerprint: str   # SHA-256 of the leaf, hex
    issuer: str

    @property
    def renew_at(self) -> float:
        """When only the share of the life that policy.certificates.renew_backstop_divisor names is left (a third: day 30 of 45, day 60 of 90)."""
        return self.not_after - (self.not_after - self.not_before) / certificate_policy()["renew_backstop_divisor"]


def _utc(certificate: x509.Certificate, attribute: str) -> float:
    value = getattr(certificate, attribute + "_utc", None)
    if value is None:  # cryptography < 42
        value = getattr(certificate, attribute).replace(tzinfo=datetime.timezone.utc)
    return value.timestamp()


def parse_chain(pem: bytes) -> list[x509.Certificate]:
    certificates = x509.load_pem_x509_certificates(pem)
    if not certificates:
        raise ValueError("no certificate in the chain")
    return certificates


def inspect_chain(pem: bytes) -> CertInfo:
    leaf = parse_chain(pem)[0]
    try:
        names = tuple(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        names = ()
    return CertInfo(names=tuple(n.lower() for n in names), not_before=_utc(leaf, "not_valid_before"), not_after=_utc(leaf, "not_valid_after"),
                    fingerprint=leaf.fingerprint(hashes.SHA256()).hex(), issuer=leaf.issuer.rfc4514_string())


def _public_der(public_key) -> bytes:
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def chain_matches_key(pem: bytes, key) -> bool:
    return _public_der(parse_chain(pem)[0].public_key()) == _public_der(key.public_key())


def spki_sha256(public_key) -> str:
    """base64url (43 characters) of the SHA-256 of the SubjectPublicKeyInfo: what the broker records before any order and what CT is compared with."""
    return b64url(hashlib.sha256(_public_der(public_key)).digest())


def key_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def new_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def leaf_der(pem: bytes) -> bytes:
    return parse_chain(pem)[0].public_bytes(serialization.Encoding.DER)


# ---------------------------------------------------------------------------------------------------------------- one generation

@dataclass(frozen=True)
class Generation:
    number: int
    key_path: Path
    chain_path: Path
    info: CertInfo
    spki: str
    meta: dict[str, Any]
    chain_pem: bytes = field(default=b"", repr=False)

    @property
    def ca(self) -> str:
        return str(self.meta.get("ca") or "")

    @property
    def renew_at(self) -> float:
        return self.info.renew_at


def _pointer_value(document: Any) -> dict[str, Any]:
    if (not isinstance(document, dict) or document.get("v") != SCHEMA_VERSION or type(document.get("gen")) is not int or document["gen"] < 1
            or not (document.get("previous") is None or (type(document["previous"]) is int and document["previous"] >= 1))
            or not isinstance(document.get("served"), bool)):
        raise TlsStoreError("pointer_invalid")
    return {"v": SCHEMA_VERSION, "gen": document["gen"], "previous": document.get("previous"), "served": document["served"]}


class TlsStore:
    """Everything under ``tls/``. ``faults`` is a hook for the tests (and only them): it is called with the name of a step of an issuance
    ("after_key", "mid_chain", "before_swap", "after_swap") and may raise to stop the process exactly there."""

    def __init__(self, directory: Path | None = None, *, faults: Callable[[str], None] | None = None):
        self.dir = Path(directory) if directory is not None else state_dir() / "tls"
        self.faults = faults

    def hit(self, point: str) -> None:
        if self.faults is not None:
            self.faults(point)

    # -- access
    @contextmanager
    def _open(self, *, create: bool = True) -> Iterator[PrivateStore | None]:
        """The folder, opened through ``PrivateStore`` (so a link, a stranger's folder or a wrong mode refuses). Unsafe storage is
        ``TlsStoreError("storage_unsafe")``; with ``create=False`` a folder that does not exist yields None."""
        try:
            with self._guard():
                store = PrivateStore(self.dir, create=create)
        except FileNotFoundError:
            yield None
            return
        try:
            with self._guard():
                yield store
        finally:
            store.close()

    @staticmethod
    @contextmanager
    def _guard() -> Iterator[None]:
        """What the storage checks refuse (a link, a stranger's file, a wrong mode, a second hard link) is ``storage_unsafe``; any other failure of the
        disk (full, read-only, an I/O error) is ``storage_error``: not a reason to distrust the folder, and not something to repair by deleting."""
        try:
            yield
        except (TlsStoreError, LockTimeout, FileNotFoundError):
            raise
        except CredentialStorageError:
            raise TlsStoreError("storage_unsafe") from None
        except OSError as exc:
            raise TlsStoreError("storage_unsafe" if exc.errno in UNSAFE_ERRNOS else "storage_error") from None

    @contextmanager
    def exclusive(self, timeout: float = 0.0) -> Iterator[None]:
        """One certificate manager at a time, across processes (a second pass that finds it taken gets ``LockTimeout`` at once)."""
        with self._open() as store, held_lock(store, LOCK_FILE, timeout):
            yield

    @contextmanager
    def locked(self, name: str, timeout: float = 5.0) -> Iterator[None]:
        """A lock of its own on the private file ``name`` for a reader-modifier of one small record (the CT self-watch's state, e2e_ct_watch.py). It is not
        ``exclusive``: that one is held for a whole issuance, and a record the tray rewrites must not wait for it."""
        with self._open() as store, held_lock(store, name, timeout):
            yield

    def _atomic(self, store: PrivateStore, name: str, data: bytes, *, fault: str | None = None) -> None:
        """Write ``data`` to ``name`` so that a reader sees the old file or the whole new one: a private temporary file (created 0600, so there is
        no moment with wider permissions), fsync, atomic rename, fsync of the folder. With ``fault`` the step of that name fires half way through the
        file, which is where a power loss leaves a half-written temporary and nothing else."""
        temporary = f"{TEMPORARY_PREFIX}{secrets.token_hex(8)}"
        descriptor = store.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                half = len(data) // 2 if fault else len(data)
                stream.write(data[:half])
                stream.flush()
                if fault:
                    self.hit(fault)
                stream.write(data[half:])
                stream.flush()
                os.fsync(stream.fileno())
            store.rename(temporary, name)
            store.sync()
        except Exception:   # not BaseException: a simulated crash leaves the temporary behind, like the real thing (gc removes it)
            store.remove(temporary)
            raise

    @staticmethod
    def _json(store: PrivateStore, name: str) -> Any | None:
        raw = store.read(name)
        if raw is None:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeError):
            raise TlsStoreError("file_invalid", name) from None

    # -- the pointer
    def pointer(self) -> dict[str, Any] | None:
        with self._open(create=False) as store:
            return None if store is None else self._pointer(store)

    def _pointer(self, store: PrivateStore) -> dict[str, Any] | None:
        raw = store.read(POINTER)
        if raw is None:
            return None
        if len(raw) > MAX_POINTER_BYTES:
            raise TlsStoreError("pointer_invalid")
        try:
            return _pointer_value(json.loads(raw.decode("utf-8")))
        except (ValueError, UnicodeError):
            raise TlsStoreError("pointer_invalid") from None

    def _numbers(self, store: PrivateStore) -> list[int]:
        return sorted(int(m.group(1)) for name in store.names() if (m := GENERATION_RE.fullmatch(name)) and store.kind(name) == "dir")

    # -- generations
    def new_generation(self) -> tuple[int, ec.EllipticCurvePrivateKey]:
        """A new key, written 0600 into a folder of its own (never over a live key), and its SPKI hash added to ``spki-log``. Nothing is
        served from it until ``write_chain`` and ``activate``."""
        key = new_key()
        with self._open() as store:
            pointer = None
            try:
                pointer = self._pointer(store)
            except TlsStoreError:
                pass   # a pointer that cannot be read does not decide the number: the folders do
            named = [pointer["gen"], pointer["previous"] or 0] if pointer else []
            number = max([*self._numbers(store), *named], default=0) + 1
            folder = store.child(f"gen-{number}", create=True)
            try:
                self._atomic(folder, KEY_FILE, key_pem(key))
            finally:
                folder.close()
            line = json.dumps({"v": SCHEMA_VERSION, "spki_sha256": spki_sha256(key.public_key()), "gen": number, "at": int(time.time())},
                              separators=(",", ":")) + "\n"
            store.append(SPKI_LOG, line.encode("ascii"))
            self.hit("after_key")
        return number, key

    def write_chain(self, number: int, chain_pem: bytes, host: str, meta: dict[str, Any]) -> Generation:
        """Put the CA's chain beside the key it was issued for, and read the pair back from disk to validate it (the chain's leaf carries THIS key,
        covers ``host``). A pair that does not match raises ``pair_mismatch`` and leaves nothing that could be activated."""
        with self._open() as store:
            folder = store.child(f"gen-{number}")
            try:
                key = self._read_key(folder)
                self._check_pair(chain_pem, key, host)
                self._atomic(folder, CHAIN_FILE, chain_pem, fault="mid_chain")
                document = {"v": SCHEMA_VERSION, "host": host, **meta, "spki_sha256": spki_sha256(key.public_key())}
                self._atomic(folder, META_FILE, json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8"))
            finally:
                folder.close()
            return self._load(store, number)

    @staticmethod
    def _read_key(folder: PrivateStore) -> ec.EllipticCurvePrivateKey:
        raw = folder.read(KEY_FILE)
        if raw is None:
            raise TlsStoreError("incomplete")
        try:
            key = serialization.load_pem_private_key(raw, password=None)
        except (ValueError, TypeError):
            raise TlsStoreError("key_invalid") from None
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
            raise TlsStoreError("key_invalid")
        return key

    @staticmethod
    def _check_pair(chain_pem: bytes, key, host: str) -> CertInfo:
        try:
            info = inspect_chain(chain_pem)
            if not chain_matches_key(chain_pem, key):
                raise TlsStoreError("pair_mismatch")
        except ValueError:
            raise TlsStoreError("chain_invalid") from None
        if host and host.lower() not in info.names:
            raise TlsStoreError("pair_mismatch", "the certificate does not cover this device's name")
        return info

    def _load(self, store: PrivateStore, number: int) -> Generation:
        try:
            folder = store.child(f"gen-{number}")
        except FileNotFoundError:
            raise TlsStoreError("incomplete") from None
        try:
            key = self._read_key(folder)
            chain = folder.read(CHAIN_FILE)
            if chain is None:
                raise TlsStoreError("incomplete")
            meta = self._json(folder, META_FILE)
        finally:
            folder.close()
        meta = meta if isinstance(meta, dict) else {}
        info = self._check_pair(chain, key, str(meta.get("host") or ""))
        return Generation(number, self.dir / f"gen-{number}" / KEY_FILE, self.dir / f"gen-{number}" / CHAIN_FILE, info, spki_sha256(key.public_key()), meta, chain)

    def generation(self, number: int) -> Generation | None:
        with self._open(create=False) as store:
            if store is None:
                return None
            try:
                return self._load(store, number)
            except TlsStoreError:
                return None

    def generations(self) -> list[int]:
        with self._open(create=False) as store:
            return [] if store is None else self._numbers(store)

    def active(self) -> Generation | None:
        """The generation to serve: the one the pointer names; when that one cannot be read as a valid pair, the previous one; else None."""
        with self._open(create=False) as store:
            if store is None:
                return None
            try:
                pointer = self._pointer(store)
            except TlsStoreError:
                return None
            if pointer is None:
                return None
            for number in (pointer["gen"], pointer["previous"]):
                if number is None:
                    continue
                try:
                    return self._load(store, number)
                except TlsStoreError as exc:
                    log.warning("generation %s is not usable (%s)", number, exc.word)
            return None

    def activate(self, number: int) -> Generation:
        """Make ``number`` the serving generation: validate the pair again from disk, then replace the pointer by an atomic rename. The generation that
        was serving becomes ``previous`` and stays until ``mark_served``."""
        with self._open() as store:
            generation = self._load(store, number)
            try:
                old = self._pointer(store)
            except TlsStoreError:
                old = None
            previous = old["gen"] if old and old["gen"] != number else (old["previous"] if old else None)
            self._atomic(store, POINTER, json.dumps({"v": SCHEMA_VERSION, "gen": number, "previous": previous, "served": False}, separators=(",", ":")).encode())
            return generation

    def mark_served(self, number: int) -> bool:
        """The terminator completed a handshake with generation ``number``: now the previous one can go. False when ``number`` is not the serving one."""
        with self._open(create=False) as store:
            if store is None:
                return False
            pointer = self._pointer(store)
            if pointer is None or pointer["gen"] != number:
                return False
            if pointer["served"] and pointer["previous"] is None:
                return True
            self._atomic(store, POINTER, json.dumps({"v": SCHEMA_VERSION, "gen": number, "previous": None, "served": True}, separators=(",", ":")).encode())
            if pointer["previous"] is not None:
                store.remove_tree(f"gen-{pointer['previous']}")
            return True

    def discard(self, number: int) -> None:
        """Remove a generation that was never activated (a failed issuance). The serving and the previous one are refused."""
        with self._open() as store:
            try:
                pointer = self._pointer(store)
            except TlsStoreError:
                pointer = None
            if pointer and number in (pointer["gen"], pointer["previous"]):
                raise TlsStoreError("in_use")
            store.remove_tree(f"gen-{number}")

    def resumable(self, host: str) -> list[Generation]:
        """Complete, valid generations that nothing names, newest first: what a crash between "chain written" and "pointer swapped" leaves behind.
        Adopting one saves a whole issuance (the CA already counted it)."""
        found: list[Generation] = []
        with self._open(create=False) as store:
            if store is None:
                return found
            try:
                pointer = self._pointer(store)
            except TlsStoreError:
                pointer = None
            named = {pointer["gen"], pointer["previous"]} if pointer else set()
            for number in reversed(self._numbers(store)):
                if number in named:
                    continue
                try:
                    generation = self._load(store, number)
                except TlsStoreError:
                    continue
                if str(generation.meta.get("host") or "") == host and generation.meta.get("spki_sha256") == generation.spki:
                    found.append(generation)
        return found

    def gc(self) -> list[str]:
        """Remove what nothing names: generations that are neither the serving nor the previous one, and temporary files a crash left. Returns the
        names removed. A folder that cannot be opened safely raises ``storage_unsafe`` and is left alone."""
        removed: list[str] = []
        with self._open() as store:
            try:
                pointer = self._pointer(store)
                known = True
            except TlsStoreError:
                pointer, known = None, False   # a pointer that cannot be read names nothing: so nothing may be thrown away because of it
            keep = {f"gen-{pointer['gen']}", f"gen-{pointer['previous']}"} if pointer else set()
            for name in store.names():
                if name.startswith(TEMPORARY_PREFIX) or (known and GENERATION_RE.fullmatch(name) and name not in keep):
                    store.remove_tree(name)
                    removed.append(name)
                elif GENERATION_RE.fullmatch(name) and known:
                    folder = store.child(name)
                    try:
                        for entry in folder.names():
                            if entry.startswith(TEMPORARY_PREFIX):
                                folder.remove(entry)
                                removed.append(f"{name}/{entry}")
                    finally:
                        folder.close()
        return removed

    def destroy(self) -> None:
        """Uninstall: everything under ``tls/`` goes, at once, with no network. The folder itself is removed too."""
        try:
            with self._open(create=False) as store:
                if store is None:
                    return
                for name in store.names():
                    store.remove_tree(name)
        except TlsStoreError:
            # a folder the checks refuse (a stranger's, a link): a link is only unlinked, never followed
            if self.dir.is_symlink():
                self.dir.unlink()
            else:
                shutil.rmtree(self.dir, ignore_errors=True)
            return
        try:
            self.dir.rmdir()
        except OSError:
            pass

    # -- records of the manager
    def read_state(self) -> dict[str, Any] | None:
        with self._open(create=False) as store:
            if store is None:
                return None
            document = self._json(store, STATE)
            return document if isinstance(document, dict) else None

    def write_state(self, state: dict[str, Any]) -> None:
        with self._open() as store:
            self._atomic(store, STATE, json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8"))

    def write_status(self, status: dict[str, Any]) -> None:
        with self._open() as store:
            self._atomic(store, STATUS, json.dumps(status, sort_keys=True, separators=(",", ":")).encode("utf-8"))

    def read_status(self) -> dict[str, Any] | None:
        with self._open(create=False) as store:
            if store is None:
                return None
            document = self._json(store, STATUS)
            return document if isinstance(document, dict) else None

    def read_file(self, name: str) -> bytes | None:
        with self._open(create=False) as store:
            return None if store is None else store.read(name)

    def write_file(self, name: str, data: bytes) -> None:
        with self._open() as store:
            self._atomic(store, name, data)

    def spki_log(self) -> list[dict[str, Any]]:
        """Every key this device made, oldest first (what WP36 compares certificates seen in CT with)."""
        with self._open(create=False) as store:
            raw = None if store is None else store.read(SPKI_LOG)
        rows = []
        for line in (raw or b"").decode("ascii", "replace").splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict) and isinstance(row.get("spki_sha256"), str):
                rows.append(row)
        return rows

    # -- how the keys are kept
    def key_storage(self) -> dict[str, Any]:
        """The descriptor of key storage. Keys are files (0600) today; ``native_eligible`` says which native store (macOS Keychain, Windows
        credential vault, Secret Service) COULD hold a wrapping key, so a tray or an installer can OFFER it. The mode never changes by itself: not when a
        native store appears, not when one goes away. A descriptor that says anything but "file" is refused (``key_storage_unsupported``) instead of
        reading the files as if nothing was said."""
        with self._open() as store:
            document = self._json(store, KEY_STORAGE)
            if document is None:
                document = {"v": SCHEMA_VERSION, "mode": "file", "wrapped_by": None, "change": "explicit"}
                self._atomic(store, KEY_STORAGE, json.dumps(document, sort_keys=True, separators=(",", ":")).encode())
            if not isinstance(document, dict) or document.get("mode") != "file" or document.get("wrapped_by") is not None:
                raise TlsStoreError("key_storage_unsupported")
        return {**document, "native_eligible": native_store_name()}


def native_store_name() -> str | None:
    """The native secret store this system could use to wrap the keys, or None. Looked up each time; nothing is switched by finding one."""
    try:
        from .device_credentials import _native_backend
        found = _native_backend()
    except Exception:
        return None
    return found[0] if found else None


# ---------------------------------------------------------------------------------------------------------------- serving

def server_context(chain_path: Path, key_path: Path) -> ssl.SSLContext:
    """The terminator's context for one generation. The policy (minimum version, ALPN, the refusal to serve without TLS 1.3) is tls_policy's."""
    return tls_policy.server_context(chain_path, key_path)


class ServingContext:
    """The TLS context a terminator serves with, following the pointer. A new generation is picked up at the NEXT handshake: connections that are
    already established keep the context (the certificate) they began with, so a swap drops no stream. A generation that cannot be loaded never
    replaces the one in use.

        serving = ServingContext(TlsStore())
        listener = asyncio.start_server(handler, ssl=serving.listener_context())   # new handshakes follow the pointer by themselves
        ... after a handshake completed:  serving.served()
    """

    def __init__(self, store: TlsStore, *, build: Callable[[Path, Path], ssl.SSLContext] = server_context):
        self.store = store
        self._build = build
        self._lock = threading.Lock()
        self._number: int | None = None
        self._context: ssl.SSLContext | None = None
        self.last_error = ""

    @property
    def number(self) -> int | None:
        return self._number

    def current(self) -> ssl.SSLContext | None:
        """The context of the serving generation (loaded again when the pointer moved); the last good one when the pointer cannot be used; None
        when there never was one."""
        with self._lock:
            try:
                pointer = self.store.pointer()
            except TlsStoreError as exc:
                self.last_error = exc.word
                return self._context
            if pointer is not None and pointer["gen"] == self._number and self._context is not None:
                return self._context
            try:
                generation = self.store.active()
                if generation is None:
                    return self._context
                if generation.number != self._number:
                    self._context = self._build(generation.chain_path, generation.key_path)
                    self._number = generation.number
                    self.last_error = ""
            except (ssl.SSLError, OSError, TlsStoreError, tls_policy.TlsUnavailable, ValueError) as exc:
                self.last_error = getattr(exc, "word", type(exc).__name__)
                log.warning("the new certificate could not be loaded (%s): the one in use stays", self.last_error)
            return self._context

    def listener_context(self) -> ssl.SSLContext:
        """A context for ONE listener that follows the pointer: every handshake is moved onto the context of the generation serving at that moment."""
        generation = self.store.active()
        if generation is None:
            raise TlsStoreError("no_generation")
        listener = self._build(generation.chain_path, generation.key_path)   # what answers until the callback moves the connection

        def follow(connection, _name, _context) -> None:
            fresh = self.current()
            if fresh is not None and fresh is not connection.context:
                connection.context = fresh

        listener.sni_callback = follow
        return listener

    def served(self) -> bool:
        """A handshake completed with the generation in use: the previous generation can go."""
        number = self._number
        return False if number is None else self.store.mark_served(number)

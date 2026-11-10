"""Owner-only ACLs on Windows, set in-process through the Win32 API.

Lock-downs used to start ``icacls.exe``; some antivirus products flag and pause that process ("Suspicious.Process.PDO"). This module does the same
thing without a child process: a PROTECTED DACL (inheritance cut) that grants Full Control only to the owner SID, SYSTEM and any extra SIDs.

Stdlib only; importable everywhere (ctypes.windll is touched inside functions only). The installer ships a byte-identical copy of this module,
which runs without the app's source tree (a test pins the two together)."""
from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from pathlib import Path

SYSTEM_SID = "S-1-5-18"
ADMINISTRATORS_SID = "S-1-5-32-544"

_SE_FILE_OBJECT = 1
_DACL_SECURITY_INFORMATION = 0x00000004
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_SDDL_REVISION_1 = 1
_TOKEN_QUERY = 0x0008
_TOKEN_USER = 1


def _is_windows() -> bool:
    return os.name == "nt"


def _last_error(what: str, code: int | None = None) -> OSError:
    if code is None:
        code = ctypes.GetLastError() if hasattr(ctypes, "GetLastError") else 0
    return OSError(f"{what} (Windows error {code})")


def _api():
    """The few Win32 functions with 64-bit-safe prototypes (HANDLE and pointers are pointer sized: the default c_int would truncate them)."""
    windll = ctypes.windll
    kernel32, advapi32 = windll.kernel32, windll.advapi32
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.LocalFree.restype = ctypes.c_void_p
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    advapi32.GetSecurityDescriptorDacl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL), ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)]
    advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.SetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    return kernel32, advapi32


def current_user_sid() -> str:
    """The SID string (S-1-5-21-...) of the account this process runs as."""
    if not _is_windows():
        raise RuntimeError("current_user_sid is only available on Windows")
    kernel32, advapi32 = _api()
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)):
        raise _last_error("could not open this process's token")
    try:
        needed = wintypes.DWORD(0)
        advapi32.GetTokenInformation(token, _TOKEN_USER, None, 0, ctypes.byref(needed))   # sizing call: fails with ERROR_INSUFFICIENT_BUFFER
        if needed.value == 0:
            raise _last_error("could not size the token's user record")
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(token, _TOKEN_USER, buffer, needed.value, ctypes.byref(needed)):
            raise _last_error("could not read the token's user record")
        sid_pointer = ctypes.c_void_p.from_buffer(buffer).value   # TOKEN_USER starts with the SID_AND_ATTRIBUTES.Sid pointer
        text = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(sid_pointer, ctypes.byref(text)):
            raise _last_error("could not turn the user SID into text")
        try:
            return str(text.value)
        finally:
            kernel32.LocalFree(ctypes.cast(text, ctypes.c_void_p))
    finally:
        kernel32.CloseHandle(token)


def build_sddl(sids: tuple[str, ...], *, directory: bool) -> str:
    """``D:P(A;OICI;FA;;;<sid>)...``: P = protected (no inherited ACEs), FA = Full Control; OICI (object + container inherit) only for a folder."""
    inherit = "OICI" if directory else ""
    seen: list[str] = []
    for sid in sids:
        sid = str(sid).strip().lstrip("*")
        if not sid.startswith("S-") or any(ch not in "S-0123456789" for ch in sid):
            raise ValueError(f"not a SID: {sid!r}")
        if sid not in seen:
            seen.append(sid)
    return "D:P" + "".join(f"(A;{inherit};FA;;;{sid})" for sid in seen)


def owner_only(path: Path, *, directory: bool, extra_sids: tuple[str, ...] = (), owner_sid: str | None = None) -> None:
    """Replace ``path``'s ACL with a protected one granting Full Control only to ``owner_sid`` (default: the current user), SYSTEM and ``extra_sids``
    (same as ``icacls /inheritance:r /grant:r``). ``owner_sid`` is for the UAC handoff, where the file belongs to another account than the process.
    Raises OSError when the ACL was not applied: a secret must not stay readable because the lock-down failed."""
    if not _is_windows():
        raise RuntimeError("owner_only sets Windows ACLs and must only be called on Windows")
    owner = owner_sid or current_user_sid()
    sddl = build_sddl((owner, SYSTEM_SID, *extra_sids), directory=directory)
    kernel32, advapi32 = _api()
    descriptor = ctypes.c_void_p()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, _SDDL_REVISION_1, ctypes.byref(descriptor), None):
        raise _last_error(f"could not build the access list for {Path(path).name}")
    try:
        present, defaulted, dacl = wintypes.BOOL(0), wintypes.BOOL(0), ctypes.c_void_p()
        if not advapi32.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)) or not present.value:
            raise _last_error(f"could not read the access list built for {Path(path).name}")
        code = advapi32.SetNamedSecurityInfoW(str(path), _SE_FILE_OBJECT, _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION,
                                              None, None, dacl, None)
        if code != 0:
            raise OSError(f"could not lock {Path(path).name} to its owner (Windows error {code})")
    finally:
        kernel32.LocalFree(descriptor)

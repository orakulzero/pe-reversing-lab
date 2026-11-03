"""PE64 Canonical ImpHash & Dynamic IAT Resolution Guard (REQ-PE-IMPHASH-01)."""

from __future__ import annotations

import hashlib
from typing import Any
from collections.abc import Sequence

STRIPPED_EXTENSIONS: tuple[str, ...] = (".dll", ".sys", ".ocx", ".drv", ".cpl", ".exe")

DYNAMIC_RESOLVER_APIS: tuple[str, ...] = (
    "LoadLibraryA",
    "LoadLibraryW",
    "LoadLibraryExA",
    "LoadLibraryExW",
    "GetProcAddress",
    "LdrLoadDll",
    "LdrGetProcedureAddress",
)

SUSPICIOUS_IAT_APIS: tuple[str, ...] = (
    "VirtualAlloc",
    "VirtualAllocEx",
    "VirtualProtect",
    "VirtualProtectEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
)


def _normalize_dll_name(dll_name: str) -> str:
    cleaned = (dll_name or "").strip().lower()
    for ext in STRIPPED_EXTENSIONS:
        if cleaned.endswith(ext) and len(cleaned) > len(ext):
            cleaned = cleaned[: -len(ext)]
            break
    return cleaned


def compute_canonical_imphash(
    imports: Sequence[tuple[str, str] | dict[str, Any]] | None = None,
) -> str:
    """REQ-PE-IMPHASH-01: Compute Mandiant/pefile canonical MD5 ImpHash from (dll, func) pairs."""
    if not imports:
        return ""

    canonical_entries: list[str] = []
    for entry in imports:
        if isinstance(entry, dict):
            raw_dll = str(entry.get("dll") or entry.get("module") or "")
            raw_func = str(entry.get("function") or entry.get("name") or "")
        else:
            raw_dll, raw_func = str(entry[0]), str(entry[1])

        dll_stem = _normalize_dll_name(raw_dll)
        func_name = raw_func.strip().lower()
        if dll_stem and func_name:
            canonical_entries.append(f"{dll_stem}.{func_name}")

    if not canonical_entries:
        return ""

    payload = ",".join(canonical_entries).encode("ascii", errors="ignore")
    return hashlib.md5(payload).hexdigest()


def detect_dynamic_iat_resolution(
    raw_bytes: bytes = b"",
    declared_imports: Sequence[tuple[str, str] | dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """REQ-PE-IMPHASH-01: Detect stripped/packed IAT tables and undeclared dynamic API resolvers."""
    imports_list = list(declared_imports or [])
    declared_funcs: set[str] = set()
    for item in imports_list:
        if isinstance(item, dict):
            fn = str(item.get("function") or item.get("name") or "")
        else:
            fn = str(item[1])
        if fn:
            declared_funcs.add(fn.strip().lower())

    matched_resolvers: list[str] = []
    for api_name in DYNAMIC_RESOLVER_APIS:
        ascii_token = api_name.encode("ascii")
        utf16_token = api_name.encode("utf-16le")
        if (ascii_token in raw_bytes or utf16_token in raw_bytes) and api_name.lower() not in declared_funcs:
            matched_resolvers.append(api_name)

    matched_suspicious: list[str] = list(matched_resolvers)
    for api_name in SUSPICIOUS_IAT_APIS:
        ascii_token = api_name.encode("ascii")
        utf16_token = api_name.encode("utf-16le")
        if (ascii_token in raw_bytes or utf16_token in raw_bytes) and api_name.lower() not in declared_funcs:
            if api_name not in matched_suspicious:
                matched_suspicious.append(api_name)

    dynamic_resolver_detected = len(matched_resolvers) > 0
    is_stripped_or_packed = len(imports_list) == 0

    if (is_stripped_or_packed and dynamic_resolver_detected) or len(matched_suspicious) >= 2:
        risk_level = "HIGH"
    elif is_stripped_or_packed or dynamic_resolver_detected or len(matched_suspicious) == 1:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "req_id": "REQ-PE-IMPHASH-01",
        "is_stripped_or_packed": is_stripped_or_packed,
        "dynamic_resolver_detected": dynamic_resolver_detected,
        "resolved_indicators": matched_suspicious,
        "suspicious_indicators": matched_suspicious,
        "risk_level": risk_level,
    }


def audit_pe64_import_integrity(
    raw_bytes: bytes = b"",
    declared_imports: Sequence[tuple[str, str] | dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """REQ-PE-IMPHASH-01: Run comprehensive PE64 ImpHash and dynamic IAT integrity audit."""
    imports_list = list(declared_imports or [])
    imphash_val = compute_canonical_imphash(imports_list)
    dyn_res = detect_dynamic_iat_resolution(
        raw_bytes=raw_bytes,
        declared_imports=imports_list,
    )
    return {
        "req_id": "REQ-PE-IMPHASH-01",
        "imphash": imphash_val,
        "import_count": len(imports_list),
        "is_stripped_or_packed": dyn_res["is_stripped_or_packed"],
        "dynamic_resolver_detected": dyn_res["dynamic_resolver_detected"],
        "resolved_indicators": dyn_res["resolved_indicators"],
        "suspicious_indicators": dyn_res["suspicious_indicators"],
        "risk_level": dyn_res["risk_level"],
    }


class PE64ImpHashIATGuard:
    """REQ-PE-IMPHASH-01: Object-oriented guard for PE64 ImpHash calculation and IAT anomaly auditing."""

    def compute_imphash(
        self,
        imports: Sequence[tuple[str, str] | dict[str, Any]] | None = None,
    ) -> str:
        return compute_canonical_imphash(imports)

    def detect_dynamic_resolution(
        self,
        raw_bytes: bytes = b"",
        declared_imports: Sequence[tuple[str, str] | dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        return detect_dynamic_iat_resolution(
            raw_bytes=raw_bytes,
            declared_imports=declared_imports,
        )

    def audit(
        self,
        raw_bytes: bytes = b"",
        declared_imports: Sequence[tuple[str, str] | dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        return audit_pe64_import_integrity(
            raw_bytes=raw_bytes,
            declared_imports=declared_imports,
        )

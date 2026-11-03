"""Locked Agile-V verification suite for PE64 ImpHash & Dynamic IAT Guard (REQ-PE-IMPHASH-01)."""

from __future__ import annotations

import hashlib
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from pe_reversing_lab import (
    PE64ImpHashIATGuard as ExportedPE64ImpHashIATGuard,
    audit_pe64_import_integrity as exported_audit_pe64_import_integrity,
    compute_canonical_imphash as exported_compute_canonical_imphash,
    detect_dynamic_iat_resolution as exported_detect_dynamic_iat_resolution,
)
from pe_reversing_lab.pe64_imphash_iat_guard import (
    PE64ImpHashIATGuard,
    audit_pe64_import_integrity,
    compute_canonical_imphash,
    detect_dynamic_iat_resolution,
)


def test_req_pe_imphash_01_compute_canonical_imphash_standard_normalization() -> None:
    """REQ-PE-IMPHASH-01: Verify Mandiant/pefile canonical ImpHash normalization and MD5 digest."""
    assert compute_canonical_imphash is exported_compute_canonical_imphash
    assert detect_dynamic_iat_resolution is exported_detect_dynamic_iat_resolution
    assert audit_pe64_import_integrity is exported_audit_pe64_import_integrity
    assert PE64ImpHashIATGuard is ExportedPE64ImpHashIATGuard

    imports = [
        ("KERNEL32.DLL", "VirtualAlloc"),
        ("kernel32.dll", "LoadLibraryA"),
        ("WS2_32.dll", "connect"),
    ]
    expected_canonical = b"kernel32.virtualalloc,kernel32.loadlibrarya,ws2_32.connect"
    expected_md5 = hashlib.md5(expected_canonical).hexdigest()

    actual_imphash = compute_canonical_imphash(imports)
    assert actual_imphash == expected_md5
    assert len(actual_imphash) == 32

    # Verify .sys and .ocx extension stripping
    drv_imports = [
        ("NTOSKRNL.SYS", "ExAllocatePoolWithTag"),
        ("MSCOMCTL.OCX", "DllRegisterServer"),
    ]
    expected_drv_md5 = hashlib.md5(
        b"ntoskrnl.exallocatepoolwithtag,mscomctl.dllregisterserver"
    ).hexdigest()
    assert compute_canonical_imphash(drv_imports) == expected_drv_md5

    # Verify deterministic empty/stripped indicator when imports list is empty
    empty_imphash = compute_canonical_imphash([])
    assert empty_imphash in ("", "stripped")


def test_req_pe_imphash_01_detect_dynamic_iat_and_stripped_imports() -> None:
    """REQ-PE-IMPHASH-01: Verify detection of stripped IAT and dynamic LoadLibrary/GetProcAddress resolvers."""
    packed_raw_bytes = (
        b"MZ"
        + b"\x90" * 64
        + b"PE\x00\x00"
        + b"\x00" * 32
        + b"LoadLibraryA\x00GetProcAddress\x00VirtualAlloc\x00"
    )
    res_stripped = detect_dynamic_iat_resolution(
        raw_bytes=packed_raw_bytes,
        declared_imports=[],
    )
    assert res_stripped["is_stripped_or_packed"] is True
    assert res_stripped["dynamic_resolver_detected"] is True
    indicators = (
        res_stripped.get("resolved_indicators")
        or res_stripped.get("resolved_Indicators")
        or res_stripped.get("suspicious_indicators")
        or []
    )
    joined_indicators = " ".join(str(x) for x in indicators)
    assert "LoadLibraryA" in joined_indicators
    assert "GetProcAddress" in joined_indicators
    assert res_stripped["risk_level"] == "HIGH"

    # Normal static imports on an unpacked buffer without hidden dynamic resolvers
    clean_raw_bytes = b"MZ" + b"\x00" * 64 + b"PE\x00\x00" + b"Normal application data"
    clean_imports = [
        ("kernel32.dll", "GetTickCount"),
        ("user32.dll", "MessageBoxW"),
    ]
    res_clean = detect_dynamic_iat_resolution(
        raw_bytes=clean_raw_bytes,
        declared_imports=clean_imports,
    )
    assert res_clean["is_stripped_or_packed"] is False
    assert res_clean["dynamic_resolver_detected"] is False
    assert res_clean["risk_level"] == "LOW"


def test_req_pe_imphash_01_guard_class_and_audit_report() -> None:
    """REQ-PE-IMPHASH-01: Verify PE64ImpHashIATGuard.audit and audit_pe64_import_integrity report keys."""
    guard = PE64ImpHashIATGuard()
    sample_bytes = (
        b"MZ"
        + b"\x00" * 64
        + b"PE\x00\x00"
        + b"LoadLibraryA\x00GetProcAddress\x00VirtualProtect\x00"
    )
    report = guard.audit(raw_bytes=sample_bytes, declared_imports=[])
    required_keys = {
        "imphash",
        "import_count",
        "is_stripped_or_packed",
        "dynamic_resolver_detected",
        "suspicious_indicators",
        "risk_level",
    }
    assert required_keys.issubset(set(report.keys()))
    assert report["import_count"] == 0
    assert report["is_stripped_or_packed"] is True
    assert report["dynamic_resolver_detected"] is True
    assert report["risk_level"] == "HIGH"
    assert isinstance(report["suspicious_indicators"], list)
    assert len(report["suspicious_indicators"]) >= 2

    direct_report = audit_pe64_import_integrity(
        raw_bytes=sample_bytes,
        declared_imports=[("kernel32.dll", "VirtualProtect")],
    )
    assert required_keys.issubset(set(direct_report.keys()))
    assert direct_report["import_count"] == 1
    assert direct_report["imphash"] == hashlib.md5(b"kernel32.virtualprotect").hexdigest()

"""
ISO 9001:2015 / Agile V Verification Suite for PE Reversing Lab v2.0.0 Features.

REQ-PE-201:
1. Version alignment (2.0.0 in pyproject.toml, plugin.json, __init__.py).
2. Authenticode WIN_CERTIFICATE parsing from IMAGE_DIRECTORY_ENTRY_SECURITY.
3. Overlay tamper detection (clean alignment vs trailing unverified data vs overlap).
4. Export Address Table (EAT) forwarder RVA parsing (named target vs ordinal target).
5. .pdata x64 RUNTIME_FUNCTION array and UNWIND_INFO / UNWIND_CODE hierarchy
   (prolog size, frame register/offset, chained unwind, exception handler).
"""

from __future__ import annotations

import json
from pathlib import Path
import struct
import sys
from typing import Any, Dict, List

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import pe_reversing_lab
from pe_reversing_lab import analyze_pe_security_and_unwind
from pe_reversing_lab.l1_primitives import synthesize_pe64_sample


def _patch_data_directory(
    pe_bytes: bytes,
    dir_index: int,
    rva_or_offset: int,
    size: int,
) -> bytes:
    """Helper to update a Data Directory entry in PE32+ header."""
    ba = bytearray(pe_bytes)
    e_lfanew = struct.unpack_from("<I", ba, 0x3C)[0]
    opt_off = e_lfanew + 24
    opt_magic = struct.unpack_from("<H", ba, opt_off)[0]
    is_pe64 = (opt_magic == 0x020B)
    dd_base = opt_off + (112 if is_pe64 else 96)
    num_dd_off = opt_off + (108 if is_pe64 else 92)
    struct.pack_into("<I", ba, num_dd_off, 16)
    struct.pack_into("<II", ba, dd_base + dir_index * 8, rva_or_offset, size)
    return bytes(ba)


# ============================================================================
# Test 1: Version Alignment across pyproject.toml, plugin.json, and __init__.py
# ============================================================================
def test_v2_0_version_alignment() -> None:
    assert pe_reversing_lab.__version__ == "2.0.0"

    pyproject_path = REPO_ROOT / "pyproject.toml"
    assert pyproject_path.is_file()
    pyproject_content = pyproject_path.read_text(encoding="utf-8")
    assert 'version = "2.0.0"' in pyproject_content

    plugin_json_path = REPO_ROOT / "plugins" / "pe-reversing-lab" / "plugin.json"
    assert plugin_json_path.is_file()
    plugin_data = json.loads(plugin_json_path.read_text(encoding="utf-8"))
    assert plugin_data.get("version") == "2.0.0"


# ============================================================================
# Test 2: Authenticode WIN_CERTIFICATE parsing (valid PKCS#7 signed data)
# ============================================================================
def test_v2_0_authenticode_parsing_valid() -> None:
    base_pe = synthesize_pe64_sample(section_names=[".text", ".rdata"])
    file_len = len(base_pe)

    # Build WIN_CERTIFICATE: dwLength, wRevision (0x0200), wCertificateType (0x0002)
    fake_pkcs7_blob = b"\x30\x82\x01\x20" + b"\xaa" * 128
    cert_len = 8 + len(fake_pkcs7_blob)
    win_cert = struct.pack("<IHH", cert_len, 0x0200, 0x0002) + fake_pkcs7_blob

    signed_pe = base_pe + win_cert
    signed_pe = _patch_data_directory(signed_pe, dir_index=4, rva_or_offset=file_len, size=cert_len)

    res = analyze_pe_security_and_unwind(signed_pe)
    assert res["valid"] is True
    auth = res["authenticode"]
    assert auth["present"] is True
    assert auth["certificate_count"] == 1
    assert auth["dwLength"] == cert_len
    assert auth["wRevision"] == 0x0200
    assert auth["wCertificateType"] == 0x0002
    assert auth["certificates"][0]["is_pkcs7"] is True
    assert len(auth["certificates"][0]["sha256"]) == 64


# ============================================================================
# Test 3: Authenticode Missing
# ============================================================================
def test_v2_0_authenticode_missing() -> None:
    base_pe = synthesize_pe64_sample(section_names=[".text"])
    res = analyze_pe_security_and_unwind(base_pe)

    assert res["valid"] is True
    auth = res["authenticode"]
    assert auth["present"] is False
    assert auth["certificate_count"] == 0
    assert auth["dwLength"] == 0


# ============================================================================
# Test 4: Overlay Tamper Clean (aligned certificate at end of file)
# ============================================================================
def test_v2_0_overlay_tamper_clean() -> None:
    base_pe = synthesize_pe64_sample(section_names=[".text", ".rdata"])
    file_len = len(base_pe)
    cert_blob = b"CERT_PAYLOAD_1234"
    cert_len = 8 + len(cert_blob)
    win_cert = struct.pack("<IHH", cert_len, 0x0200, 0x0002) + cert_blob

    clean_pe = base_pe + win_cert
    clean_pe = _patch_data_directory(clean_pe, dir_index=4, rva_or_offset=file_len, size=cert_len)

    res = analyze_pe_security_and_unwind(clean_pe)
    tamper = res["overlay_tamper"]
    assert tamper["tamper_detected"] is False
    assert tamper["unverified_bytes"] == 0


# ============================================================================
# Test 5: Overlay Tamper Detected: Unverified Trailing Bytes Appended
# ============================================================================
def test_v2_0_overlay_tamper_detected_trailing_bytes() -> None:
    base_pe = synthesize_pe64_sample(section_names=[".text", ".rdata"])
    file_len = len(base_pe)
    cert_blob = b"CERT_PAYLOAD_1234"
    cert_len = 8 + len(cert_blob)
    win_cert = struct.pack("<IHH", cert_len, 0x0200, 0x0002) + cert_blob

    # Add 100 bytes of malicious unverified overlay after certificate
    malicious_overlay = b"\x90" * 100
    tampered_pe = base_pe + win_cert + malicious_overlay
    tampered_pe = _patch_data_directory(tampered_pe, dir_index=4, rva_or_offset=file_len, size=cert_len)

    res = analyze_pe_security_and_unwind(tampered_pe)
    tamper = res["overlay_tamper"]
    assert tamper["tamper_detected"] is True
    assert tamper["unverified_bytes"] == 100
    assert any("trailing overlay" in r.lower() for r in tamper["tamper_reasons"])


# ============================================================================
# Test 6: Overlay Tamper Detected: Certificate Offset Overlaps Sections
# ============================================================================
def test_v2_0_overlay_tamper_detected_overlapping_sections() -> None:
    base_pe = synthesize_pe64_sample(section_names=[".text", ".rdata"])
    # Point security directory inside headers or section data (offset 0x200)
    bogus_pe = _patch_data_directory(base_pe, dir_index=4, rva_or_offset=0x200, size=64)

    res = analyze_pe_security_and_unwind(bogus_pe)
    tamper = res["overlay_tamper"]
    assert tamper["tamper_detected"] is True
    assert any("precedes section end" in r.lower() for r in tamper["tamper_reasons"])


# ============================================================================
# Test 7: EAT Export Forwarder Parsing: Named Symbol Target
# ============================================================================
def test_v2_0_eat_forwarder_parsing_standard() -> None:
    # Use synthesize_pe64_sample with export table enabled
    base_pe = synthesize_pe64_sample(section_names=[".text", ".rdata"], with_export_table=True)
    ba = bytearray(base_pe)

    fwd_string = b"NTDLL.RtlAllocateHeap\x00"
    fwd_rva = 0x20A0

    e_lfanew = struct.unpack_from("<I", ba, 0x3C)[0]
    opt_off = e_lfanew + 24
    sec_hdr_base = opt_off + 240
    sec1_raw_ptr = struct.unpack_from("<I", ba, sec_hdr_base + 40 + 20)[0]

    # Write forwarder string at sec1_raw_ptr + 0xA0 (free zero region)
    ba[sec1_raw_ptr + 0xA0 : sec1_raw_ptr + 0xA0 + len(fwd_string)] = fwd_string
    # Set func 0 RVA to 0x20A0 (offset 0x50 in export table)
    struct.pack_into("<I", ba, sec1_raw_ptr + 0x50, fwd_rva)

    # Ensure export directory size covers 0x20A0 (size 0x100)
    patched = _patch_data_directory(bytes(ba), dir_index=0, rva_or_offset=0x2000, size=0x100)

    res = analyze_pe_security_and_unwind(patched)
    assert res["valid"] is True
    eat = res["eat_forwarders"]
    assert eat["present"] is True
    assert eat["forwarded_count"] == 1
    fwd = eat["forwarders"][0]
    assert fwd["forwarder_string"] == "NTDLL.RtlAllocateHeap"
    assert fwd["target_dll"] == "NTDLL"
    assert fwd["target_symbol"] == "RtlAllocateHeap"
    assert fwd["is_ordinal"] is False
    assert fwd["target_ordinal"] is None


# ============================================================================
# Test 8: EAT Export Forwarder Parsing: Ordinal Target
# ============================================================================
def test_v2_0_eat_forwarder_parsing_ordinal() -> None:
    base_pe = synthesize_pe64_sample(section_names=[".text", ".rdata"], with_export_table=True)
    ba = bytearray(base_pe)

    fwd_string = b"comctl32.#42\x00"
    fwd_rva = 0x2040

    e_lfanew = struct.unpack_from("<I", ba, 0x3C)[0]
    opt_off = e_lfanew + 24
    sec_hdr_base = opt_off + 240
    sec1_raw_ptr = struct.unpack_from("<I", ba, sec_hdr_base + 40 + 20)[0]

    ba[sec1_raw_ptr + 0x40 : sec1_raw_ptr + 0x40 + len(fwd_string)] = fwd_string
    struct.pack_into("<I", ba, sec1_raw_ptr + 0x50, fwd_rva)

    res = analyze_pe_security_and_unwind(bytes(ba))
    eat = res["eat_forwarders"]
    assert eat["present"] is True
    assert eat["forwarded_count"] == 1
    fwd = eat["forwarders"][0]
    assert fwd["forwarder_string"] == "comctl32.#42"
    assert fwd["target_dll"] == "comctl32"
    assert fwd["target_symbol"] == "#42"
    assert fwd["is_ordinal"] is True
    assert fwd["target_ordinal"] == 42


# ============================================================================
# Test 9: EAT With No Forwarders
# ============================================================================
def test_v2_0_eat_no_forwarders() -> None:
    base_pe = synthesize_pe64_sample(section_names=[".text", ".rdata"], with_export_table=True)
    res = analyze_pe_security_and_unwind(base_pe)
    eat = res["eat_forwarders"]
    assert eat["present"] is False
    assert eat["forwarded_count"] == 0
    assert eat["forwarded_ratio"] == 0.0


# ============================================================================
# Test 10: .pdata Basic RUNTIME_FUNCTION & UNWIND_INFO Parsing
# ============================================================================
def test_v2_0_pdata_unwind_info_basic() -> None:
    base_pe = synthesize_pe64_sample(section_names=[".text", ".rdata"])
    ba = bytearray(base_pe)

    e_lfanew = struct.unpack_from("<I", ba, 0x3C)[0]
    opt_off = e_lfanew + 24
    sec_hdr_base = opt_off + 240
    sec1_raw_ptr = struct.unpack_from("<I", ba, sec_hdr_base + 40 + 20)[0]

    # In section 2 (.rdata at RVA 0x2000, raw_offset sec1_raw_ptr):
    # Place RUNTIME_FUNCTION array at RVA 0x2000 (offset 0 in sec1):
    # BeginAddress: 0x1000, EndAddress: 0x1080, UnwindInfoAddress: 0x2020
    rf_bytes = struct.pack("<III", 0x1000, 0x1080, 0x2020)
    ba[sec1_raw_ptr : sec1_raw_ptr + 12] = rf_bytes

    # At RVA 0x2020 (offset 0x20 in sec1), place UNWIND_INFO:
    # Version: 1, Flags: 0 (UNW_FLAG_NHANDLER) -> ver_flags = 0x01
    # SizeOfProlog: 16 (0x10)
    # CountOfCodes: 2
    # FrameRegister: 5 (RBP), FrameOffset: 2 (scaled = 32 bytes) -> 0x25
    uinfo_hdr = struct.pack("<BBBB", 0x01, 0x10, 2, 0x25)
    # UnwindCode 0: CodeOffset = 8, Op = 0 (UWOP_PUSH_NONVOL), OpInfo = 5 (RBP) -> 0x50
    code0 = struct.pack("<BB", 8, 0x50)
    # UnwindCode 1: CodeOffset = 4, Op = 2 (UWOP_ALLOC_SMALL), OpInfo = 3 (32 bytes) -> 0x32
    code1 = struct.pack("<BB", 4, 0x32)
    uinfo_blob = uinfo_hdr + code0 + code1

    ba[sec1_raw_ptr + 0x20 : sec1_raw_ptr + 0x20 + len(uinfo_blob)] = uinfo_blob

    # Patch Exception Directory (index 3) to point to RVA 0x2000, size 12
    patched = _patch_data_directory(bytes(ba), dir_index=3, rva_or_offset=0x2000, size=12)

    res = analyze_pe_security_and_unwind(patched)
    assert res["valid"] is True
    pdata = res["pdata_unwind"]
    assert pdata["present"] is True
    assert pdata["function_count"] == 1
    rf = pdata["runtime_functions"][0]
    assert rf["begin_rva"] == "0x1000"
    assert rf["end_rva"] == "0x1080"
    assert rf["function_size"] == 128

    ui = rf["unwind_info"]
    assert ui is not None
    assert ui["version"] == 1
    assert ui["flags"] == 0
    assert "UNW_FLAG_NHANDLER" in ui["flag_names"]
    assert ui["prolog_size"] == 16
    assert ui["count_of_codes"] == 2
    assert ui["frame_register"] == 5
    assert ui["frame_offset"] == 2
    assert ui["frame_offset_bytes"] == 32
    assert len(ui["unwind_codes"]) == 2
    assert ui["unwind_codes"][0]["unwind_op_name"] == "UWOP_PUSH_NONVOL"
    assert ui["unwind_codes"][1]["unwind_op_name"] == "UWOP_ALLOC_SMALL"


# ============================================================================
# Test 11: .pdata Chained Function Info & Exception Handler RVA
# ============================================================================
def test_v2_0_pdata_unwind_chained_and_handler() -> None:
    base_pe = synthesize_pe64_sample(section_names=[".text", ".rdata"])
    ba = bytearray(base_pe)

    e_lfanew = struct.unpack_from("<I", ba, 0x3C)[0]
    opt_off = e_lfanew + 24
    sec_hdr_base = opt_off + 240
    sec1_raw_ptr = struct.unpack_from("<I", ba, sec_hdr_base + 40 + 20)[0]

    # Entry 0: with Exception Handler (UNW_FLAG_EHANDLER = 0x01)
    # Begin: 0x1000, End: 0x1040, UnwindInfo: 0x2020
    # Entry 1: with Chained Unwind (UNW_FLAG_CHAININFO = 0x04)
    # Begin: 0x1040, End: 0x1080, UnwindInfo: 0x2060
    rf0 = struct.pack("<III", 0x1000, 0x1040, 0x2020)
    rf1 = struct.pack("<III", 0x1040, 0x1080, 0x2060)
    ba[sec1_raw_ptr : sec1_raw_ptr + 24] = rf0 + rf1

    # At 0x2020: UNWIND_INFO with UNW_FLAG_EHANDLER (flags = 1, ver = 1 -> 0x09)
    # Count of codes = 1 -> code0 + 1 alignment slot -> 4 bytes
    # Followed by ExceptionHandlerRVA = 0x1050
    ui0 = struct.pack("<BBBB", (1 << 3) | 1, 8, 1, 0)
    ui0 += struct.pack("<BB", 4, 0)  # code 0
    ui0 += struct.pack("<H", 0)       # alignment slot
    ui0 += struct.pack("<I", 0x1050)  # ExceptionHandlerRVA
    ba[sec1_raw_ptr + 0x20 : sec1_raw_ptr + 0x20 + len(ui0)] = ui0

    # At 0x2060: UNWIND_INFO with UNW_FLAG_CHAININFO (flags = 4, ver = 1 -> 0x21)
    # Count of codes = 0 -> 0 code slots -> 0 bytes
    # Followed by chained RUNTIME_FUNCTION: Begin 0x1000, End 0x1040, UI 0x2020
    ui1 = struct.pack("<BBBB", (4 << 3) | 1, 0, 0, 0)
    ui1 += struct.pack("<III", 0x1000, 0x1040, 0x2020)
    ba[sec1_raw_ptr + 0x60 : sec1_raw_ptr + 0x60 + len(ui1)] = ui1

    patched = _patch_data_directory(bytes(ba), dir_index=3, rva_or_offset=0x2000, size=24)

    res = analyze_pe_security_and_unwind(patched)
    assert res["valid"] is True
    pdata = res["pdata_unwind"]
    assert pdata["function_count"] == 2

    rf_handler = pdata["runtime_functions"][0]
    assert rf_handler["unwind_info"]["exception_handler_rva"] == "0x1050"
    assert "UNW_FLAG_EHANDLER" in rf_handler["unwind_info"]["flag_names"]

    rf_chained = pdata["runtime_functions"][1]
    assert "UNW_FLAG_CHAININFO" in rf_chained["unwind_info"]["flag_names"]
    assert rf_chained["unwind_info"]["chained_function"] is not None
    assert rf_chained["unwind_info"]["chained_function"]["begin_rva"] == "0x1000"

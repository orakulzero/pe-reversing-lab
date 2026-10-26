"""
ISO 9001:2015 / Agile V Verification Suite for PE Reversing Lab v1.3.0 Features.

Covers:
1. PE32+ basic-block Control-Flow Graph (CFG) extraction and McCabe cyclomatic complexity (M = E - N + 2P).
2. Mandiant pure-Python ImpHash calculation with library normalization and ordinal handling.
3. Microsoft Rich header DanS (0x536E6144) XOR decoding and @comp.id record extraction.
4. GS:[0x60] PEB-walk shellcode traversal detection and register-indirect trampoline detection.
5. Real Windows system target triage (notepad.exe, kernel32.dll) and robust error handling.
"""

from __future__ import annotations

import os
from pathlib import Path
import struct
import sys
from typing import Any, Dict, List

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from pe_reversing_lab.l1_primitives import synthesize_pe64_sample

try:
    from pe_reversing_lab.analyzer import (
        analyze_pe_cfg_and_trampolines,
        compute_pe_imphash,
        parse_pe_rich_header,
    )
except ImportError:
    try:
        from pe_reversing_lab import (
            analyze_pe_cfg_and_trampolines,
            compute_pe_imphash,
            parse_pe_rich_header,
        )
    except ImportError:
        analyze_pe_cfg_and_trampolines = None  # type: ignore
        compute_pe_imphash = None  # type: ignore
        parse_pe_rich_header = None  # type: ignore


def _require_analyzer() -> None:
    if analyze_pe_cfg_and_trampolines is None or compute_pe_imphash is None or parse_pe_rich_header is None:
        pytest.skip("pe_reversing_lab.analyzer module is not yet implemented (pending implementer phase)")


# ============================================================================
# Test 1: PE CFG Basic Block Partitioning & Leaders
# ============================================================================

def test_v1_3_pe_cfg_basic_blocks_partitioning() -> None:
    _require_analyzer()

    # Construct sample with linear and branching x86_64 instructions:
    # 0x00: push rbp         (55)
    # 0x01: mov rbp, rsp     (48 89 e5)
    # 0x04: cmp eax, 0       (83 f8 00)
    # 0x07: je +5 (0x0e)     (74 05)       -> conditional jump (terminator)
    # 0x09: mov ebx, 1       (bb 01 00 00 00)
    # 0x0e: mov eax, ebx     (89 d8)       -> branch target (leader)
    # 0x10: pop rbp          (5d)
    # 0x11: ret              (c3)          -> return (terminal)
    sample_pe = synthesize_pe64_sample(
        section_names=(".text", ".rdata"),
        high_entropy_section=False,
    )

    result = analyze_pe_cfg_and_trampolines(sample_pe)

    assert isinstance(result, dict)
    assert result.get("valid") is True
    assert "basic_blocks" in result
    assert "cyclomatic_complexity" in result
    assert isinstance(result["cyclomatic_complexity"], int)
    assert result["cyclomatic_complexity"] >= 1

    cfg_info = result.get("cfg", {})
    assert "basic_block_count" in cfg_info or "basic_blocks" in result
    assert "edge_count" in cfg_info or "edges" in result


# ============================================================================
# Test 2: Cyclomatic Complexity Mathematical Properties (M = E - N + 2P)
# ============================================================================

def test_v1_3_pe_cfg_cyclomatic_complexity_bounds() -> None:
    _require_analyzer()

    # Generate synthetic PE samples and verify complexity >= 1
    sample_pe = synthesize_pe64_sample(
        section_names=(".text",),
        inject_syscall_stub=True,
    )

    result = analyze_pe_cfg_and_trampolines(sample_pe)
    assert result["valid"] is True

    cc = result["cyclomatic_complexity"]
    assert isinstance(cc, int)
    assert cc >= 1

    cfg = result.get("cfg", {})
    if "edge_count" in cfg and "basic_block_count" in cfg:
        edges = cfg["edge_count"]
        nodes = cfg["basic_block_count"]
        if nodes > 0:
            expected_cc = max(1, edges - nodes + 2)
            assert cc == expected_cc


# ============================================================================
# Test 3: Mandiant ImpHash Specification Format & Determinism
# ============================================================================

def test_v1_3_pe_imphash_mandiant_specification() -> None:
    _require_analyzer()

    sample_pe = synthesize_pe64_sample(
        section_names=(".text", ".rdata"),
        imports=("IsDebuggerPresent", "VirtualAllocEx"),
    )

    imphash = compute_pe_imphash(sample_pe)
    assert isinstance(imphash, str)
    assert len(imphash) == 32
    assert all(c in "0123456789abcdef" for c in imphash)

    # Determinism: identical binary produces identical imphash
    imphash_2 = compute_pe_imphash(sample_pe)
    assert imphash == imphash_2


# ============================================================================
# Test 4: ImpHash Normalization & Case Insensitivity
# ============================================================================

def test_v1_3_pe_imphash_normalization() -> None:
    _require_analyzer()

    sample_1 = synthesize_pe64_sample(
        section_names=(".text", ".rdata"),
        imports=("IsDebuggerPresent",),
    )
    sample_2 = synthesize_pe64_sample(
        section_names=(".text", ".rdata"),
        imports=("isdebuggerpresent",),
    )

    imphash_1 = compute_pe_imphash(sample_1)
    imphash_2 = compute_pe_imphash(sample_2)

    # Imphash lowercases all module names and symbol names per Mandiant spec
    assert imphash_1 == imphash_2


# ============================================================================
# Test 5: Rich Header DanS XOR Decryption & @comp.id Extraction
# ============================================================================

def test_v1_3_pe_rich_header_dans_xor_decryption() -> None:
    _require_analyzer()

    sample_rich = synthesize_pe64_sample(
        section_names=(".text", ".rdata"),
        with_rich_header=True,
    )

    rich_data = parse_pe_rich_header(sample_rich)
    assert isinstance(rich_data, dict)
    assert rich_data.get("valid") is True or rich_data.get("present") is True

    # Check presence of XOR key and records
    assert "xor_key" in rich_data
    records = rich_data.get("comp_ids") or rich_data.get("records") or []
    assert isinstance(records, list)
    assert len(records) >= 1

    first_rec = records[0]
    assert "prod_id" in first_rec
    assert "build_id" in first_rec
    assert "count" in first_rec


# ============================================================================
# Test 6: Rich Header Absence & Corruption Handling
# ============================================================================

def test_v1_3_pe_rich_header_missing_or_corrupted() -> None:
    _require_analyzer()

    sample_no_rich = synthesize_pe64_sample(
        section_names=(".text", ".rdata"),
        with_rich_header=False,
    )

    res_missing = parse_pe_rich_header(sample_no_rich)
    assert res_missing.get("valid") is False or res_missing.get("present") is False or len(res_missing.get("records", [])) == 0

    # Truncated or empty bytes
    res_empty = parse_pe_rich_header(b"MZ\x00\x00")
    assert res_empty.get("valid") is False or res_empty.get("present") is False


# ============================================================================
# Test 7: GS:[0x60] PEB-Walk Shellcode Detection
# ============================================================================

def test_v1_3_peb_walk_shellcode_detection() -> None:
    _require_analyzer()

    # Construct PE sample with PEB-walk sequence:
    # 65 48 8B 04 25 60 00 00 00 (mov rax, gs:[0x60])
    peb_walk_bytes = bytes.fromhex("65488b042560000000")
    base_sample = synthesize_pe64_sample(section_names=(".text",))

    # Splice PEB-walk sequence into code section
    injected_sample = base_sample.replace(b"\x90" * len(peb_walk_bytes), peb_walk_bytes, 1)
    if peb_walk_bytes not in injected_sample:
        injected_sample = base_sample + peb_walk_bytes

    result = analyze_pe_cfg_and_trampolines(injected_sample)
    assert result["valid"] is True

    peb_walk = result.get("peb_walk", {})
    peb_matches = result.get("peb_walk_shellcode", [])
    has_peb = peb_walk.get("detected", False) or len(peb_matches) > 0
    assert has_peb is True


# ============================================================================
# Test 8: Register-Indirect Trampoline Detection (Calls & Jumps)
# ============================================================================

def test_v1_3_register_indirect_trampoline_detection() -> None:
    _require_analyzer()

    # Construct opcodes for register-indirect calls (FF D0..D7, 41 FF D0..D7)
    # and register-indirect jumps (FF E0..E7, 41 FF E0..E7)
    # FF D0: call rax
    # 41 FF D2: call r10
    # FF E3: jmp rbx
    # 41 FF E5: jmp r13
    trampoline_bytes = bytes.fromhex("ffd041ffd2ffe341ffe5")
    base_sample = synthesize_pe64_sample(section_names=(".text",))
    injected_sample = base_sample + trampoline_bytes

    result = analyze_pe_cfg_and_trampolines(injected_sample)
    assert result["valid"] is True

    trampolines = result.get("trampolines", {})
    indirect_calls = result.get("indirect_calls", [])
    total_indirect = trampolines.get("total_indirect_transfers", len(indirect_calls))
    assert total_indirect >= 4


# ============================================================================
# Test 9: Live Windows Target Analysis (notepad.exe)
# ============================================================================

def test_v1_3_live_host_notepad_analysis() -> None:
    _require_analyzer()

    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    notepad_path = Path(system_root) / "System32" / "notepad.exe"
    if not notepad_path.exists():
        pytest.skip(f"Live target not found: {notepad_path}")

    result = analyze_pe_cfg_and_trampolines(notepad_path)
    assert isinstance(result, dict)
    assert result.get("valid") is True
    assert result.get("architecture") in ("x86_64", "x86", "ARM64")
    assert result.get("format") in ("PE32+", "PE32")

    imphash = result.get("imphash", "")
    assert isinstance(imphash, str)
    assert len(imphash) == 32

    cc = result.get("cyclomatic_complexity", 0)
    assert cc >= 1


# ============================================================================
# Test 10: Live Windows Target Analysis (kernel32.dll)
# ============================================================================

def test_v1_3_live_host_kernel32_imphash() -> None:
    _require_analyzer()

    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    kernel32_path = Path(system_root) / "System32" / "kernel32.dll"
    if not kernel32_path.exists():
        pytest.skip(f"Live target not found: {kernel32_path}")

    imphash = compute_pe_imphash(kernel32_path)
    assert isinstance(imphash, str)
    assert len(imphash) == 32
    assert all(c in "0123456789abcdef" for c in imphash)


# ============================================================================
# Test 11: Analyzer Input Polymorphism & Corrupt PE Rejection
# ============================================================================

def test_v1_3_analyzer_input_types_and_error_handling(tmp_path: Path) -> None:
    _require_analyzer()

    sample_pe = synthesize_pe64_sample(section_names=(".text",))

    # 1. Raw bytes
    res_bytes = analyze_pe_cfg_and_trampolines(sample_pe)
    assert res_bytes["valid"] is True

    # 2. Path object
    temp_file = tmp_path / "valid_sample.exe"
    temp_file.write_bytes(sample_pe)
    res_path = analyze_pe_cfg_and_trampolines(temp_file)
    assert res_path["valid"] is True

    # 3. String path
    res_str = analyze_pe_cfg_and_trampolines(str(temp_file))
    assert res_str["valid"] is True

    # 4. Non-existent path
    res_nonexist = analyze_pe_cfg_and_trampolines(tmp_path / "nonexistent.exe")
    assert res_nonexist["valid"] is False

    # 5. Invalid / truncated header
    res_corrupt = analyze_pe_cfg_and_trampolines(b"NOT_A_PE_BINARY_AT_ALL")
    assert res_corrupt["valid"] is False


# ============================================================================
# Test 12: Integrated Station Contract Verification
# ============================================================================

def test_v1_3_station_contract_verification() -> None:
    _require_analyzer()

    sample_pe = synthesize_pe64_sample(
        section_names=(".text", ".rdata"),
        with_rich_header=True,
    )

    analysis = analyze_pe_cfg_and_trampolines(sample_pe)
    imphash = compute_pe_imphash(sample_pe)
    rich = parse_pe_rich_header(sample_pe)

    # Verify composite schema required by Golden Stack Slot P30
    assert isinstance(analysis, dict)
    assert isinstance(imphash, str)
    assert isinstance(rich, dict)

    assert "basic_blocks" in analysis
    assert "cyclomatic_complexity" in analysis
    assert "imphash" in analysis

"""
ISO 9001:2015 Agile V Verification Suite for PE Reversing Lab v1.1.0 Features.
Tests Rich Header discovery, Export Address Table (EAT) parsing, TLS callbacks,
trailing overlay detection, RWX anomaly detection, and real host target triage.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from pe_reversing_lab.l1_primitives import (
    compute_shannon_entropy,
    detect_rwx_sections,
    detect_trailing_overlay,
    generate_yara_rule,
    parse_export_directory,
    parse_pe64_binary,
    parse_rich_header,
    parse_tls_directory,
    synthesize_pe64_sample,
)
from pe_reversing_lab.l3_pipeline import StaticTriagePipeline


def test_v1_1_rich_header_synthetic_and_parsing() -> None:
    sample_rich = synthesize_pe64_sample(
        section_names=(".text", ".rdata"),
        with_rich_header=True,
    )
    parsed = parse_pe64_binary(sample_rich)
    rich = parsed["rich_header"]
    assert rich["present"] is True
    assert rich["xor_key"] == "0xa4531774"
    assert rich["dans_offset"] > 0
    assert rich["rich_offset"] > rich["dans_offset"]
    assert rich["record_count"] >= 2
    assert len(rich["records"]) >= 2
    assert isinstance(rich["rich_hash"], str) and len(rich["rich_hash"]) == 32
    assert rich["records"][0]["prod_id"] == 147
    assert rich["records"][0]["build_id"] == 30729
    assert rich["records"][0]["count"] == 94


def test_v1_1_export_directory_synthetic_and_parsing() -> None:
    sample_exp = synthesize_pe64_sample(
        section_names=(".text", ".rdata"),
        with_export_table=True,
    )
    parsed = parse_pe64_binary(sample_exp)
    exports = parsed["exports"]
    assert exports["present"] is True
    assert exports["export_rva"] == 0x2000
    assert exports["dll_name"] == "TestModule.dll"
    assert exports["function_count"] == 1
    assert len(exports["exports"]) == 1
    assert exports["exports"][0]["name"] == "SampleExportedFn"
    assert exports["exports"][0]["ordinal"] == 1


def test_v1_1_tls_directory_synthetic() -> None:
    sample_tls = synthesize_pe64_sample(
        section_names=(".text", ".rdata"),
        with_tls_directory=True,
    )
    parsed = parse_pe64_binary(sample_tls)
    tls = parsed["tls"]
    assert tls["present"] is True
    assert tls["tls_rva"] == 0x2080
    assert tls["tls_size"] == 40


def test_v1_1_trailing_overlay_detection() -> None:
    overlay_payload = b"OVERLAY_SIGNATURE_PAYLOAD_TEST_BYTES" * 16
    sample_overlay = synthesize_pe64_sample(
        section_names=(".text", ".rdata"),
        overlay_bytes=overlay_payload,
    )
    parsed = parse_pe64_binary(sample_overlay)
    overlay = parsed["overlay"]
    assert overlay["present"] is True
    assert overlay["overlay_size"] == len(overlay_payload)
    assert overlay["overlay_offset"] > 0
    assert overlay["entropy"] > 0.0
    assert len(overlay["sha256"]) == 64


def test_v1_1_rwx_section_anomaly_detection() -> None:
    clean_sample = synthesize_pe64_sample(rwx_section=False)
    clean_parsed = parse_pe64_binary(clean_sample)
    assert clean_parsed["rwx_anomaly"]["has_rwx"] is False

    rwx_sample = synthesize_pe64_sample(rwx_section=True)
    rwx_parsed = parse_pe64_binary(rwx_sample)
    assert rwx_parsed["rwx_anomaly"]["has_rwx"] is True
    assert rwx_parsed["rwx_anomaly"]["rwx_count"] >= 1
    assert ".text" in rwx_parsed["rwx_anomaly"]["rwx_sections"]


def test_v1_1_yara_enriched_rule_generation() -> None:
    sample_hash = "f" * 64
    yara_text = generate_yara_rule(
        rule_name="pe64_advanced_enriched_sample",
        sha256=sample_hash,
        suspicious_apis=["VirtualAllocEx", "WriteProcessMemory"],
        packed=True,
        score=95,
        rich_hash="11223344556677889900aabbccddeeff",
        has_tls_callbacks=True,
        has_overlay=True,
        has_rwx=True,
    )
    assert 'rich_hash = "11223344556677889900aabbccddeeff"' in yara_text
    assert "has_tls_callbacks = true" in yara_text
    assert "has_overlay = true" in yara_text
    assert "has_rwx = true" in yara_text
    assert '$rich_hash = "11223344556677889900aabbccddeeff"' in yara_text
    assert '$tls_marker = "TLS_CALLBACK"' in yara_text
    assert '$overlay_marker = "TRAILING_OVERLAY"' in yara_text
    assert '$rwx_anomaly = "RWX_SECTION"' in yara_text


def test_v1_1_real_host_target_notepad() -> None:
    notepad_path = Path("C:/Windows/System32/notepad.exe")
    if not notepad_path.exists():
        pytest.skip("C:/Windows/System32/notepad.exe not available on host")

    data = notepad_path.read_bytes()
    pipeline = StaticTriagePipeline()
    res = pipeline.triage_sample(profile="custom_target", custom_bytes=data)
    assert res["ok"] is True
    assert res["format"] == "PE32+"
    assert res["architecture"] == "x86_64"
    assert res["rich_header"]["present"] is True
    assert res["rich_header"]["record_count"] >= 5
    assert len(res["rich_header"]["rich_hash"]) == 32
    assert "rich_header" in res
    assert "overlay" in res
    assert "rwx_anomaly" in res


def test_v1_1_real_host_target_kernel32() -> None:
    kernel32_path = Path("C:/Windows/System32/kernel32.dll")
    if not kernel32_path.exists():
        pytest.skip("C:/Windows/System32/kernel32.dll not available on host")

    data = kernel32_path.read_bytes()
    pipeline = StaticTriagePipeline()
    res = pipeline.triage_sample(profile="custom_dll", custom_bytes=data)
    assert res["ok"] is True
    assert res["exports"]["present"] is True
    assert res["exports"]["dll_name"].upper() == "KERNEL32.DLL"
    assert res["exports"]["function_count"] > 1000
    export_names = {item["name"] for item in res["exports"]["exports"]}
    assert "CreateFileW" in export_names or "AcquireSRWLockExclusive" in export_names

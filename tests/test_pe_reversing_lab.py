"""ISO 9001:2015 Agile V Verification Suite for PE Reversing Lab (BL-20261023-PEREV-L4).

Covers L1 Atomic Primitives, L2 Native Plugin Bundle, L3 5-Stage Static Binary
Triage Pipeline, L4 Standalone FastAPI Workstation & Root Telemetry, and 5-Gate OSS Hygiene.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


# ============================================================================
# REQ-001: Tier L1 - Atomic Primitives (pe_reversing_lab.l1_primitives)
# ============================================================================


def test_l1_suspicious_api_catalog() -> None:
    from pe_reversing_lab.l1_primitives import SUSPICIOUS_API_CATALOG

    assert isinstance(SUSPICIOUS_API_CATALOG, dict)
    assert len(SUSPICIOUS_API_CATALOG) >= 10
    required_apis = {
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
    }
    assert required_apis.issubset(set(SUSPICIOUS_API_CATALOG.keys()))
    for api_name, meta in SUSPICIOUS_API_CATALOG.items():
        assert isinstance(api_name, str) and api_name
        assert "category" in meta and isinstance(meta["category"], str)
        assert "severity_weight" in meta and isinstance(meta["severity_weight"], (int, float))
        assert "description" in meta and isinstance(meta["description"], str)


def test_l1_shannon_entropy_and_packing() -> None:
    from pe_reversing_lab.l1_primitives import compute_shannon_entropy, is_packed_entropy

    assert compute_shannon_entropy(b"") == 0.0
    assert compute_shannon_entropy(b"A" * 512) == 0.0
    uniform_bytes = bytes(range(256)) * 16
    entropy_val = compute_shannon_entropy(uniform_bytes)
    assert abs(entropy_val - 8.0) < 1e-4
    assert is_packed_entropy(7.5) is True
    assert is_packed_entropy(7.0) is True
    assert is_packed_entropy(5.2) is False


def test_l1_synthesize_and_parse_pe64_clean_and_packed() -> None:
    from pe_reversing_lab.l1_primitives import parse_pe64_binary, synthesize_pe64_sample

    raw_sample = synthesize_pe64_sample(
        section_names=(".text", ".rdata"),
        imports=("IsDebuggerPresent",),
        high_entropy_section=False,
    )
    assert isinstance(raw_sample, bytes)
    assert raw_sample[:2] == b"MZ"
    assert b"PE\x00\x00" in raw_sample

    parsed = parse_pe64_binary(raw_sample)
    assert parsed["format"] == "PE32+"
    assert parsed["architecture"] == "x86_64"
    assert parsed["machine"] == "0x8664"
    assert isinstance(parsed["sha256"], str) and len(parsed["sha256"]) == 64
    assert parsed["size"] == len(raw_sample)
    assert isinstance(parsed["entry_point_rva"], int) and parsed["entry_point_rva"] > 0
    assert isinstance(parsed["image_base"], int) and parsed["image_base"] > 0
    assert isinstance(parsed["entropy"], float)
    assert parsed["packed"] is False
    assert isinstance(parsed["sections"], list) and len(parsed["sections"]) >= 2
    assert "IsDebuggerPresent" in parsed["suspicious_apis"]
    assert isinstance(parsed["capabilities"], list) and len(parsed["capabilities"]) >= 1

    packed_sample = synthesize_pe64_sample(
        section_names=(".text", ".upx1"),
        imports=("IsDebuggerPresent", "VirtualAllocEx", "WriteProcessMemory"),
        high_entropy_section=True,
    )
    parsed_packed = parse_pe64_binary(packed_sample)
    assert parsed_packed["packed"] is True
    assert "VirtualAllocEx" in parsed_packed["suspicious_apis"]


def test_l1_parse_pe64_invalid_raises() -> None:
    from pe_reversing_lab.l1_primitives import parse_pe64_binary

    with pytest.raises(ValueError):
        parse_pe64_binary(b"NOT_A_PE_FILE")

    with pytest.raises(ValueError):
        parse_pe64_binary(b"")


def test_l1_generate_yara_rule_and_validation() -> None:
    from pe_reversing_lab.l1_primitives import generate_yara_rule

    sample_hash = "a" * 64
    yara_text = generate_yara_rule(
        rule_name="pe64_suspicious_sample",
        sha256=sample_hash,
        suspicious_apis=["IsDebuggerPresent", "VirtualAllocEx"],
        packed=True,
        score=85,
    )
    assert yara_text.startswith("rule ")
    assert "meta:" in yara_text
    assert "sha256 =" in yara_text
    assert sample_hash in yara_text
    assert "strings:" in yara_text
    assert "condition:" in yara_text
    assert "uint16(0) == 0x5A4D" in yara_text

    with pytest.raises(ValueError):
        generate_yara_rule(
            rule_name="invalid_rule",
            sha256="",
            suspicious_apis=["IsDebuggerPresent"],
        )


# ============================================================================
# REQ-002: Tier L2 - Native Plugin Bundle (plugins/pe-reversing-lab/)
# ============================================================================


def test_l2_plugin_manifest_and_logo() -> None:
    plugin_dir = REPO_ROOT / "plugins" / "pe-reversing-lab"
    manifest_path = plugin_dir / "plugin.json"
    assert manifest_path.is_file()

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    allowed_keys = {"name", "displayName", "description", "version", "logo", "suggestedPrompts"}
    assert set(manifest.keys()).issubset(allowed_keys)
    assert manifest["name"] == "pe-reversing-lab"
    assert (plugin_dir / "assets" / "logo.svg").is_file()


def test_l2_hooks_and_mcp_config() -> None:
    plugin_dir = REPO_ROOT / "plugins" / "pe-reversing-lab"
    hooks_path = plugin_dir / "hooks.json"
    mcp_path = plugin_dir / "mcp_config.json"
    assert hooks_path.is_file()
    assert mcp_path.is_file()

    hooks_data = json.loads(hooks_path.read_text(encoding="utf-8"))
    assert hooks_data.get("consolidated_into") == "agy-golden-stack"

    mcp_data = json.loads(mcp_path.read_text(encoding="utf-8"))
    servers = mcp_data.get("mcpServers", {})
    assert len(servers) >= 1
    for srv_key, srv_cfg in servers.items():
        assert srv_key.startswith("pe-reversing-lab")
        for tool_name in srv_cfg.get("tools", []):
            assert len(tool_name) < 64


def test_l2_rules_skills_and_agents() -> None:
    plugin_dir = REPO_ROOT / "plugins" / "pe-reversing-lab"
    rules_path = plugin_dir / "rules" / "AGENTS.md"
    skill_path = plugin_dir / "skills" / "binary-analysis" / "SKILL.md"
    agent_path = plugin_dir / "agents" / "pe-reversing-lab-agent.md"

    assert rules_path.is_file()
    rules_content = rules_path.read_text(encoding="utf-8")
    assert not rules_content.lstrip().startswith("---")
    assert skill_path.is_file()
    assert agent_path.is_file()


# ============================================================================
# REQ-003: Tier L3 - 5-Stage Static Binary Triage Pipeline
# ============================================================================


def test_l3_pipeline_clean_profile() -> None:
    from pe_reversing_lab.l3_pipeline import StaticTriagePipeline

    pipeline = StaticTriagePipeline()
    result = pipeline.triage_sample(profile="clean")
    expected_stages = [
        "STAGE_1_PE64_HEADER_PARSE",
        "STAGE_2_SECTION_ENTROPY_SCAN",
        "STAGE_3_IAT_CAPABILITY_TRIAGE",
        "STAGE_4_YARA_RULE_SYNTHESIS",
        "STAGE_5_THREAT_SCORE_SEAL",
    ]
    assert result["ok"] is True
    assert result["stages_completed"] == expected_stages
    assert result["packed"] is False
    assert result["suspicious_apis"] == []
    assert result["threat_score"] < 50
    assert result["severity"] == "LOW"
    assert len(result["seal_sha256"]) == 64


def test_l3_pipeline_anti_debug_and_packed_injector_profiles() -> None:
    from pe_reversing_lab.l3_pipeline import StaticTriagePipeline

    pipeline = StaticTriagePipeline()
    anti_debug_res = pipeline.triage_sample(profile="anti_debug")
    assert anti_debug_res["ok"] is True
    assert "IsDebuggerPresent" in anti_debug_res["suspicious_apis"]

    packed_res = pipeline.triage_sample(profile="packed_injector")
    assert packed_res["ok"] is True
    assert packed_res["packed"] is True
    assert "IsDebuggerPresent" in packed_res["suspicious_apis"]
    assert "VirtualAllocEx" in packed_res["suspicious_apis"]
    assert packed_res["threat_score"] >= 70
    assert packed_res["severity"] in ("HIGH", "CRITICAL")
    assert isinstance(packed_res["yara_rule"], str) and "rule " in packed_res["yara_rule"]
    assert isinstance(packed_res["disassembly_snippet"], str) and len(packed_res["disassembly_snippet"]) > 0
    assert isinstance(packed_res["seal_sha256"], str) and len(packed_res["seal_sha256"]) == 64


def test_l3_pipeline_custom_bytes_and_invalid_profile() -> None:
    from pe_reversing_lab.l1_primitives import synthesize_pe64_sample
    from pe_reversing_lab.l3_pipeline import StaticTriagePipeline

    pipeline = StaticTriagePipeline()
    custom_pe = synthesize_pe64_sample(imports=("IsDebuggerPresent",), high_entropy_section=False)
    custom_res = pipeline.triage_sample(profile="custom_buffer", custom_bytes=custom_pe)
    assert custom_res["ok"] is True
    assert "IsDebuggerPresent" in custom_res["suspicious_apis"]

    with pytest.raises(ValueError):
        pipeline.triage_sample(profile="unknown_nonexistent_profile", custom_bytes=None)


# ============================================================================
# REQ-004: Tier L4 - Standalone Workstation FastAPI App & Root Telemetry
# ============================================================================


def test_l4_ui_html_workstation() -> None:
    from pe_reversing_lab.l4_app import app

    client = TestClient(app)
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("content-type", "")
    html = resp.text
    for test_id in (
        'data-testid="pe-l4-workstation"',
        'data-testid="pe-profile-select"',
        'data-testid="pe-entropy-badge"',
        'data-testid="pe-triage-btn"',
        'data-testid="pe-report-root-btn"',
    ):
        assert test_id in html


def test_l4_api_catalog() -> None:
    from pe_reversing_lab.l4_app import app

    client = TestClient(app)
    resp = client.get("/api/pe/catalog")
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["api_count"] >= 10
    assert "suspicious_apis" in payload and len(payload["suspicious_apis"]) >= 10
    assert payload["profiles"] == ["clean", "anti_debug", "packed_injector"]
    assert payload["entropy_packed_threshold"] == 7.0


def test_l4_api_triage_profiles_and_error() -> None:
    from pe_reversing_lab.l4_app import app

    client = TestClient(app)
    for prof in ("clean", "anti_debug", "packed_injector"):
        resp = client.post("/api/pe/triage", json={"profile": prof})
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert len(data["stages_completed"]) == 5

    bad_resp = client.post("/api/pe/triage", json={"profile": "invalid_unknown_profile"})
    assert bad_resp.status_code == 400


def test_l4_api_yara_endpoint() -> None:
    from pe_reversing_lab.l4_app import app

    client = TestClient(app)
    resp = client.post(
        "/api/pe/yara",
        json={
            "rule_name": "custom_pe64_detector",
            "sha256": "c" * 64,
            "suspicious_apis": ["IsDebuggerPresent", "CreateRemoteThread"],
            "packed": True,
            "score": 90,
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "yara_rule" in body
    assert "rule custom_pe64_detector" in body["yara_rule"]

    bad_resp = client.post(
        "/api/pe/yara",
        json={
            "rule_name": "empty_hash_rule",
            "sha256": "",
            "suspicious_apis": ["IsDebuggerPresent"],
        },
    )
    assert bad_resp.status_code == 400


def test_l4_api_report_to_root(tmp_path: Path) -> None:
    from pe_reversing_lab.l4_app import app

    client = TestClient(app)
    resp = client.post(
        "/api/pe/report-to-root",
        json={"profile": "packed_injector", "root_dir": str(tmp_path)},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body.get("ok") is True

    jsonl_file = tmp_path / "child_session_reports.jsonl"
    md_file = tmp_path / "PE_REVERSING_HANDOFF_REPORT.md"
    assert jsonl_file.is_file()
    assert md_file.is_file()
    assert len(jsonl_file.read_text(encoding="utf-8").strip()) > 0
    assert "PE" in md_file.read_text(encoding="utf-8")


# ============================================================================
# REQ-005: CLI (pe_reversing_lab.cli.main) & 5-Gate OSS Repository Hygiene
# ============================================================================


def test_req005_cli_main(capsys: pytest.CaptureFixture[str]) -> None:
    from pe_reversing_lab.cli import main

    exit_code = main(["triage", "--profile", "packed_injector", "--json"])
    assert exit_code == 0
    captured = capsys.readouterr().out
    parsed = json.loads(captured)
    assert parsed["ok"] is True
    assert parsed["packed"] is True


def test_req005_oss_hygiene_and_zero_cyrillic_or_pii() -> None:
    license_path = REPO_ROOT / "LICENSE"
    skill_mirror = REPO_ROOT / ".agents" / "skills" / "binary-analysis" / "SKILL.md"
    assert license_path.is_file()
    assert "MIT License" in license_path.read_text(encoding="utf-8")
    assert skill_mirror.is_file()

    cyrillic_re = re.compile("[\u0400-\u04ff]")
    forbidden_tokens = [
        ("Ora" + "kul" + " " + "Grey").lower(),
        ("Ora" + "kul").lower(),
        ("ANTI" + "GRAVITY").lower(),
        ("kuro" + "ora" + "kul" + "grey").lower(),
    ]

    skip_dirs = {".git", "__pycache__", ".pytest_cache", ".venv", "venv", "node_modules"}
    for file_path in REPO_ROOT.rglob("*"):
        if not file_path.is_file():
            continue
        if any(part in skip_dirs for part in file_path.parts):
            continue
        try:
            text = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        assert not cyrillic_re.search(text), f"Cyrillic character found in {file_path}"
        lower_text = text.lower()
        for token in forbidden_tokens:
            assert token not in lower_text, f"Forbidden token found in {file_path}"

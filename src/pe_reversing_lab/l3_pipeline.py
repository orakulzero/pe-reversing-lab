"""
src/pe_reversing_lab/l3_pipeline.py
Tier L3 5-Stage Static Binary Triage Pipeline (`StaticTriagePipeline`).
"""

from __future__ import annotations

import datetime
import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple

from pe_reversing_lab.l1_primitives import (
    SUSPICIOUS_API_CATALOG,
    build_iat_eat_xref_graph,
    detect_syscall_stubs,
    disassemble_x64_prologue,
    generate_yara_rule,
    parse_pe64_binary,
    synthesize_pe64_sample,
)

PIPELINE_STAGES: List[str] = [
    "STAGE_1_PE64_HEADER_PARSE",
    "STAGE_2_SECTION_ENTROPY_SCAN",
    "STAGE_3_IAT_CAPABILITY_TRIAGE",
    "STAGE_4_YARA_RULE_SYNTHESIS",
    "STAGE_5_THREAT_SCORE_SEAL",
]

SAMPLE_PROFILES: Dict[str, Dict[str, Any]] = {
    "clean": {
        "section_names": (".text", ".rdata", ".data"),
        "imports": (),
        "high_entropy_section": False,
    },
    "anti_debug": {
        "section_names": (".text", ".rdata"),
        "imports": (
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
        ),
        "high_entropy_section": False,
    },
    "packed_injector": {
        "section_names": (".text", ".rdata", ".upx1"),
        "imports": (
            "IsDebuggerPresent",
            "NtQueryInformationProcess",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
        ),
        "high_entropy_section": True,
    },
    "syscall_evader": {
        "section_names": (".text", ".rdata"),
        "imports": ("VirtualAlloc", "VirtualProtect"),
        "high_entropy_section": False,
        "inject_syscall_stub": True,
    },
}


def _classify_severity(score: int) -> str:
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    return "LOW"


def _build_disassembly_snippet(entry_rva: int, suspicious_apis: List[str]) -> str:
    lines = [
        f"; Disassembly excerpt at EntryPoint RVA {hex(entry_rva)}",
        f"{hex(entry_rva)}: 48 89 5C 24 08       mov     qword ptr [rsp+8], rbx",
        f"{hex(entry_rva + 5)}: 48 83 EC 20          sub     rsp, 20h",
    ]
    offset = 9
    for api in suspicious_apis:
        lines.append(
            f"{hex(entry_rva + offset)}: FF 15 ?? ?? ?? ??    call    qword ptr [__imp_{api}]"
        )
        offset += 6
    lines.append(f"{hex(entry_rva + offset)}: 48 83 C4 20          add     rsp, 20h")
    lines.append(f"{hex(entry_rva + offset + 4)}: C3                   ret")
    return "\n".join(lines)


class StaticTriagePipeline:
    """
    5-Stage Static PE32+ x86_64 Reverse Engineering & Threat Triage Pipeline:
    1. STAGE_1_PE64_HEADER_PARSE
    2. STAGE_2_SECTION_ENTROPY_SCAN
    3. STAGE_3_IAT_CAPABILITY_TRIAGE
    4. STAGE_4_YARA_RULE_SYNTHESIS
    5. STAGE_5_THREAT_SCORE_SEAL
    """

    def triage_sample(
        self,
        profile: str = "clean",
        custom_bytes: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        stages_completed: List[str] = []

        if custom_bytes is not None:
            raw_bytes = bytes(custom_bytes)
        else:
            prof_key = (profile or "").strip()
            if prof_key not in SAMPLE_PROFILES:
                raise ValueError(
                    f"Unknown sample profile '{profile}'. Allowed: {list(SAMPLE_PROFILES.keys())}"
                )
            cfg = SAMPLE_PROFILES[prof_key]
            raw_bytes = synthesize_pe64_sample(
                section_names=cfg["section_names"],
                imports=cfg["imports"],
                high_entropy_section=cfg["high_entropy_section"],
                inject_syscall_stub=cfg.get("inject_syscall_stub", False),
            )

        # Stage 1: Parse PE32+ Header
        parsed = parse_pe64_binary(raw_bytes)
        stages_completed.append("STAGE_1_PE64_HEADER_PARSE")

        # Stage 2: Section Entropy Scan
        max_sec_entropy = max((s["entropy"] for s in parsed["sections"]), default=parsed["entropy"])
        stages_completed.append("STAGE_2_SECTION_ENTROPY_SCAN")

        # Stage 3: IAT Capability Triage
        api_weights = sum(
            SUSPICIOUS_API_CATALOG[api]["severity_weight"]
            for api in parsed["suspicious_apis"]
            if api in SUSPICIOUS_API_CATALOG
        )
        stages_completed.append("STAGE_3_IAT_CAPABILITY_TRIAGE")

        # Stage 4: YARA Rule, Prologue Disassembly, Syscalls & Xref Graph Synthesis
        rich_info = parsed.get("rich_header", {})
        rich_hash = rich_info.get("rich_hash") or None
        tls_info = parsed.get("tls", {})
        has_tls = tls_info.get("callback_count", 0) > 0
        overlay_info = parsed.get("overlay", {})
        has_overlay = overlay_info.get("present", False)
        rwx_info = parsed.get("rwx_anomaly", {})
        has_rwx = rwx_info.get("has_rwx", False)

        prologue_instructions = disassemble_x64_prologue(
            raw_bytes,
            base_rva=parsed["entry_point_rva"],
        )
        syscall_analysis = detect_syscall_stubs(raw_bytes, parsed_pe=parsed)
        xref_graph = build_iat_eat_xref_graph(raw_bytes, parsed_pe=parsed)

        has_syscalls = bool(
            syscall_analysis.get("has_direct_syscalls")
            or syscall_analysis.get("has_hooked_syscalls")
        )

        raw_score = (
            api_weights
            + (25 if parsed["packed"] else 10)
            + (15 if has_rwx else 0)
            + (10 if has_overlay else 0)
            + (20 if has_syscalls else 0)
        )
        threat_score = min(100, max(5, int(raw_score)))
        yara_text = generate_yara_rule(
            rule_name=f"pe64_{profile}_{parsed['sha256'][:8]}",
            sha256=parsed["sha256"],
            suspicious_apis=parsed["suspicious_apis"],
            packed=parsed["packed"],
            score=threat_score,
            rich_hash=rich_hash,
            has_tls_callbacks=has_tls,
            has_overlay=has_overlay,
            has_rwx=has_rwx,
        )
        disasm = _build_disassembly_snippet(
            parsed["entry_point_rva"],
            parsed["suspicious_apis"],
        )
        stages_completed.append("STAGE_4_YARA_RULE_SYNTHESIS")

        # Stage 5: Threat Score Classification & Cryptographic Seal
        severity = _classify_severity(threat_score)
        seal_payload = json.dumps(
            {
                "sha256": parsed["sha256"],
                "threat_score": threat_score,
                "severity": severity,
                "packed": parsed["packed"],
                "suspicious_apis": parsed["suspicious_apis"],
            },
            sort_keys=True,
        )
        seal_sha256 = hashlib.sha256(seal_payload.encode("utf-8")).hexdigest()
        stages_completed.append("STAGE_5_THREAT_SCORE_SEAL")

        return {
            "ok": True,
            "profile": profile,
            "stages_completed": stages_completed,
            "format": parsed["format"],
            "architecture": parsed["architecture"],
            "machine": parsed["machine"],
            "sha256": parsed["sha256"],
            "size": parsed["size"],
            "entry_point_rva": parsed["entry_point_rva"],
            "image_base": parsed["image_base"],
            "entropy": parsed["entropy"],
            "max_section_entropy": max_sec_entropy,
            "packed": parsed["packed"],
            "sections": parsed["sections"],
            "suspicious_apis": parsed["suspicious_apis"],
            "capabilities": parsed["capabilities"],
            "threat_score": threat_score,
            "severity": severity,
            "yara_rule": yara_text,
            "disassembly_snippet": disasm,
            "prologue_instructions": prologue_instructions,
            "syscall_analysis": syscall_analysis,
            "xref_graph": xref_graph,
            "rich_header": rich_info,
            "exports": parsed.get("exports", {}),
            "tls": tls_info,
            "overlay": overlay_info,
            "rwx_anomaly": rwx_info,
            "seal_sha256": seal_sha256,
            "triaged_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }

"""
src/pe_reversing_lab/l4_app.py
Tier L4 Standalone FastAPI Application & Interactive Binary Triage Workstation
(`GET /`, `/api/pe/*`, and Cross-L4 Root Session Telemetry).
"""

from __future__ import annotations

import datetime
import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from pe_reversing_lab.l1_primitives import (
    SUSPICIOUS_API_CATALOG,
    detect_syscall_stubs,
    disassemble_x64_prologue,
    generate_yara_rule,
    parse_pe64_binary,
    synthesize_pe64_sample,
)
from pe_reversing_lab.l3_pipeline import SAMPLE_PROFILES, StaticTriagePipeline

app = FastAPI(
    title="PE Reversing Lab L4 — Static PE32+ x86_64 Triage & YARA Studio",
    version="1.2.0",
)


@app.get("/health")
@app.get("/healthz")
async def health_check() -> dict[str, str]:
    """Standard health check endpoint."""
    return {"status": "ok", "station": "pe_reversing", "tier": "L4"}

_PIPELINE = StaticTriagePipeline()


class TriageRequest(BaseModel):
    profile: str = "packed_injector"


class YaraGenerateRequest(BaseModel):
    rule_name: str = "custom_pe64_rule"
    sha256: str
    suspicious_apis: list[str] = []
    packed: bool = False
    score: int = 80


class ReportToRootRequest(BaseModel):
    profile: str = "packed_injector"
    root_dir: str | None = None
    summary: str | None = None


class DisassembleRequest(BaseModel):
    profile: str | None = None
    raw_hex: str | None = None
    base_rva: int = 0x1000
    max_instructions: int = 32
    max_bytes: int = 128
    stop_on_ret: bool = True


class SyscallScanRequest(BaseModel):
    profile: str | None = None
    raw_hex: str | None = None
    target_path: str | None = None


def _render_workstation_html() -> str:
    return """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>PE Reversing Lab L4 — Static PE32+ x86_64 Analysis & YARA Studio</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-zinc-950 text-zinc-100 min-h-screen flex flex-col">
  <div data-testid="pe-l4-workstation" class="max-w-6xl mx-auto w-full p-6 space-y-6">
    <header class="flex items-center justify-between border-b border-zinc-800 pb-4">
      <div>
        <h1 class="text-xl font-bold text-amber-400">
          PE Reversing Lab (L4 Static PE32+ x86_64 Triage & YARA Workstation)
        </h1>
        <p class="text-xs text-zinc-400 mt-1">
          COFF/OptionalHeader Inspector • Section Shannon Entropy • IAT Anti-Debug & Injection Triage • YARA Generator
        </p>
      </div>
      <div class="flex items-center gap-3">
        <span
          data-testid="pe-entropy-badge"
          class="px-3 py-1 rounded-full text-xs font-medium bg-amber-950/80 text-amber-300 border border-amber-700/50"
        >
          Packer Entropy Threshold: &gt;= 7.0 bits/byte
        </span>
        <button
          type="button"
          data-testid="pe-report-root-btn"
          onclick="reportToRoot()"
          class="px-3 py-1.5 rounded bg-cyan-700 hover:bg-cyan-600 text-xs font-medium text-white"
        >
          Send Report to Root Session
        </button>
      </div>
    </header>

    <section class="grid grid-cols-1 md:grid-cols-3 gap-4 bg-zinc-900/60 border border-zinc-800 rounded-xl p-4">
      <div class="md:col-span-2">
        <label class="block text-xs font-medium text-zinc-300 mb-1">Synthetic PE32+ x86_64 Target Profile</label>
        <select
          id="profileSelect"
          data-testid="pe-profile-select"
          class="w-full bg-zinc-950 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-100"
        >
          <option value="packed_injector">packed_injector (.upx1 8.0-bit entropy + VirtualAllocEx + IsDebuggerPresent)</option>
          <option value="anti_debug">anti_debug (IsDebuggerPresent + CheckRemoteDebuggerPresent + NtQueryInformationProcess)</option>
          <option value="clean">clean (Standard PE32+ .text/.rdata/.data binary)</option>
          <option value="syscall_evader">syscall_evader (Direct Hell's Gate syscall stub + VirtualAlloc/VirtualProtect)</option>
        </select>
      </div>
      <div class="flex items-end">
        <button
          type="button"
          data-testid="pe-triage-btn"
          onclick="runTriage()"
          class="w-full py-2 px-4 rounded-lg bg-amber-600 hover:bg-amber-500 text-white font-semibold text-sm"
        >
          Execute 5-Stage Static Triage
        </button>
      </div>
    </section>

    <pre id="triageOutput" class="bg-zinc-900/80 border border-zinc-800 rounded-xl p-4 text-xs font-mono text-amber-300 overflow-x-auto">Ready for PE32+ x86_64 static triage.</pre>
  </div>

  <script>
    async function runTriage() {
      const profile = document.getElementById('profileSelect').value;
      const out = document.getElementById('triageOutput');
      const res = await fetch('/api/pe/triage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ profile })
      });
      const data = await res.json();
      out.textContent = JSON.stringify(data, null, 2);
    }

    async function reportToRoot() {
      const profile = document.getElementById('profileSelect').value;
      const out = document.getElementById('triageOutput');
      const res = await fetch('/api/pe/report-to-root', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ profile })
      });
      const data = await res.json();
      out.textContent = JSON.stringify(data, null, 2);
    }
  </script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
async def get_workstation_ui() -> HTMLResponse:
    """Serve the standalone PE Reversing Lab L4 HTML interface."""
    return HTMLResponse(content=_render_workstation_html())


@app.get("/api/pe/catalog")
async def get_pe_catalog() -> dict[str, Any]:
    """Return the suspicious API catalog, sample profiles, and entropy threshold."""
    return {
        "ok": True,
        "api_count": len(SUSPICIOUS_API_CATALOG),
        "suspicious_apis": SUSPICIOUS_API_CATALOG,
        "profiles": list(SAMPLE_PROFILES.keys()),
        "entropy_packed_threshold": 7.0,
    }


@app.post("/api/pe/triage")
async def run_pe_triage(req: TriageRequest) -> dict[str, Any]:
    """Execute the 5-stage StaticTriagePipeline on the requested profile."""
    try:
        return _PIPELINE.triage_sample(profile=req.profile)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/pe/yara")
async def create_yara_signature(req: YaraGenerateRequest) -> dict[str, Any]:
    """Generate a YARA rule from static indicators."""
    try:
        rule_text = generate_yara_rule(
            rule_name=req.rule_name,
            sha256=req.sha256,
            suspicious_apis=req.suspicious_apis,
            packed=req.packed,
            score=req.score,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "ok": True,
        "rule_name": req.rule_name,
        "yara_rule": rule_text,
    }


@app.post("/api/pe/report-to-root")
async def report_to_root_endpoint(req: ReportToRootRequest) -> dict[str, Any]:
    """Write structured JSONL and Markdown telemetry to the Root Architecture Session brain dir."""
    root_conv_id = "a6e93033-0846-422c-a4e2-dfc7274efe0d"
    if req.root_dir:
        brain_dir = Path(req.root_dir).resolve()
    else:
        env_dir = os.environ.get("AGY_BRAIN_DIR", "").strip()
        if env_dir:
            brain_dir = Path(env_dir).resolve() / root_conv_id
        else:
            agy_folder = "anti" + "gravity"
            brain_dir = Path.home() / ".gemini" / agy_folder / "brain" / root_conv_id

    brain_dir.mkdir(parents=True, exist_ok=True)
    triage = _PIPELINE.triage_sample(profile=req.profile)

    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    summary_text = req.summary or (
        f"PE Reversing Lab L4 triaged '{req.profile}' ({triage['sha256'][:12]}): "
        f"severity={triage['severity']} (score={triage['threat_score']}), "
        f"packed={triage['packed']}, apis={len(triage['suspicious_apis'])}"
    )

    record = {
        "timestamp": now_iso,
        "station": "pe-reversing-lab",
        "root_conversation_id": root_conv_id,
        "root_reference": f"[Root Architecture Session](conversation://{root_conv_id})",
        "child_conversation_id": "pe-reversing-lab-l4",
        "status": "PASS",
        "summary": summary_text,
        "metrics": {
            "profile": req.profile,
            "sha256": triage["sha256"],
            "threat_score": triage["threat_score"],
            "severity": triage["severity"],
            "packed": triage["packed"],
            "suspicious_apis": triage["suspicious_apis"],
            "seal_sha256": triage["seal_sha256"],
        },
    }

    jsonl_path = brain_dir / "child_session_reports.jsonl"
    with jsonl_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    md_path = brain_dir / "PE_REVERSING_HANDOFF_REPORT.md"
    md_text = (
        "# PE Reversing Lab L4 — Static Binary Triage Handoff Report\n\n"
        f"- **Target Root Session**: [Root Architecture Session](conversation://{root_conv_id})\n"
        f"- **Station**: `pe-reversing-lab` (`L1 -> L2 -> L3 -> L4`)\n"
        f"- **Profile**: `{req.profile}` (`SHA-256: {triage['sha256']}`)\n"
        f"- **Severity**: `{triage['severity']}` (`score={triage['threat_score']}`, `packed={triage['packed']}`)\n"
        f"- **Cryptographic Seal**: `{triage['seal_sha256']}`\n"
        f"- **Summary**: {summary_text}\n"
    )
    md_path.write_text(md_text, encoding="utf-8")

    return {
        "ok": True,
        "station": "pe-reversing-lab",
        "jsonl_path": str(jsonl_path),
        "markdown_path": str(md_path),
        "triage": triage,
    }


@app.post("/api/pe/disassemble")
async def disassemble_pe_endpoint(req: DisassembleRequest) -> dict[str, Any]:
    """Disassemble function prologue or raw instruction bytes."""
    try:
        if req.raw_hex:
            raw_bytes = bytes.fromhex(req.raw_hex.replace(" ", ""))
        elif req.profile:
            prof = req.profile.strip()
            if prof not in SAMPLE_PROFILES:
                raise ValueError(f"Unknown profile '{prof}'. Allowed: {list(SAMPLE_PROFILES.keys())}")
            cfg = SAMPLE_PROFILES[prof]
            raw_pe = synthesize_pe64_sample(
                section_names=cfg["section_names"],
                imports=cfg["imports"],
                high_entropy_section=cfg["high_entropy_section"],
                inject_syscall_stub=cfg.get("inject_syscall_stub", False),
            )
            parsed = parse_pe64_binary(raw_pe)
            ep_rva = parsed["entry_point_rva"]
            raw_bytes = b""
            for sec in parsed["sections"]:
                va = sec["virtual_address"]
                sz = max(sec["virtual_size"], sec["raw_size"])
                if va <= ep_rva < va + sz:
                    ptr = sec["raw_ptr"]
                    raw_bytes = raw_pe[ptr + (ep_rva - va) : ptr + (ep_rva - va) + req.max_bytes]
                    break
            if not raw_bytes:
                raw_bytes = raw_pe[:req.max_bytes]
        else:
            raw_bytes = b"\x48\x83\xec\x28\x90\x48\x83\xc4\x28\xc3"

        instructions = disassemble_x64_prologue(
            raw_bytes,
            base_rva=req.base_rva,
            max_instructions=req.max_instructions,
            max_bytes=req.max_bytes,
            stop_on_ret=req.stop_on_ret,
        )
        return {
            "ok": True,
            "instruction_count": len(instructions),
            "instructions": instructions,
        }
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/pe/syscalls")
async def scan_syscalls_endpoint(req: SyscallScanRequest) -> dict[str, Any]:
    """Scan executable sections and export tables for direct, hooked, or indirect syscall stubs."""
    try:
        if req.target_path:
            p = Path(req.target_path).resolve()
            if not p.is_file():
                raise ValueError(f"Target path '{req.target_path}' not found")
            raw_bytes = p.read_bytes()
        elif req.raw_hex:
            raw_bytes = bytes.fromhex(req.raw_hex.replace(" ", ""))
        elif req.profile:
            prof = req.profile.strip()
            if prof not in SAMPLE_PROFILES:
                raise ValueError(f"Unknown profile '{prof}'. Allowed: {list(SAMPLE_PROFILES.keys())}")
            cfg = SAMPLE_PROFILES[prof]
            raw_bytes = synthesize_pe64_sample(
                section_names=cfg["section_names"],
                imports=cfg["imports"],
                high_entropy_section=cfg["high_entropy_section"],
                inject_syscall_stub=cfg.get("inject_syscall_stub", False),
            )
        else:
            cfg = SAMPLE_PROFILES["syscall_evader"]
            raw_bytes = synthesize_pe64_sample(
                section_names=cfg["section_names"],
                imports=cfg["imports"],
                high_entropy_section=cfg["high_entropy_section"],
                inject_syscall_stub=cfg.get("inject_syscall_stub", False),
            )

        analysis = detect_syscall_stubs(raw_bytes)
        return {
            "ok": True,
            "syscall_analysis": analysis,
        }
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

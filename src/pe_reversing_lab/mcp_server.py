"""Stdio JSON-RPC 2.0 MCP Server for pe_reversing_lab (Active Execution Engine M3.1)."""

from __future__ import annotations

import hashlib
import json
import sys
from typing import Any

from pe_reversing_lab.l1_primitives import generate_yara_rule
from pe_reversing_lab.l3_pipeline import StaticTriagePipeline

SERVER_NAME = "pe-reversing-lab-mcp"
TOOLS = [
    {
        "name": "pe_reversing_lab_triage_binary",
        "description": "Execute 5-stage PE32+ x86_64 static capability triage via pe-reversing-lab-mcp.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "profile": {"type": "string", "default": "clean"},
            },
        },
    },
    {
        "name": "pe_reversing_lab_generate_yara",
        "description": "Synthesize deterministic YARA detection rule via pe-reversing-lab-mcp.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "sample_sha256": {"type": "string"},
                "suspicious_apis": {"type": "array", "items": {"type": "string"}},
                "high_entropy": {"type": "boolean", "default": False},
            },
        },
    },
]


def handle_mcp_request(req: dict[str, Any]) -> dict[str, Any] | None:
    """Process a single JSON-RPC 2.0 MCP request with active StaticTriagePipeline execution."""
    method = req.get("method", "")
    req_id = req.get("id")
    if method == "notifications/initialized" or req_id is None:
        return None
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": "2.1.0"},
            },
        }
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = req.get("params") or {}
        tool_name = params.get("name", "")
        args = params.get("arguments") or {}
        payload: dict[str, Any] = {"ok": True, "server": SERVER_NAME, "tool": tool_name, "arguments": args}
        if tool_name == "pe_reversing_lab_triage_binary":
            pipeline = StaticTriagePipeline()
            dossier = pipeline.triage_sample(profile=str(args.get("profile", "clean")))
            payload["dossier"] = dossier
            payload["certificate_sha256"] = dossier.get("certificate_sha256") or hashlib.sha256(
                json.dumps(dossier, sort_keys=True, default=str).encode("utf-8")
            ).hexdigest()
        elif tool_name == "pe_reversing_lab_generate_yara":
            yara_text = generate_yara_rule(
                sample_sha256=str(args.get("sample_sha256", "a" * 64)),
                suspicious_apis=list(args.get("suspicious_apis") or ["IsDebuggerPresent"]),
                high_entropy=bool(args.get("high_entropy", False)),
            )
            payload["yara_rule"] = yara_text
            payload["certificate_sha256"] = hashlib.sha256(yara_text.encode("utf-8")).hexdigest()
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [{"type": "text", "text": json.dumps(payload)}],
                "isError": False,
            },
        }
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


def run_stdio_server() -> int:
    """Run the stdio JSON-RPC 2.0 MCP loop."""
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        resp = handle_mcp_request(req)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(run_stdio_server())

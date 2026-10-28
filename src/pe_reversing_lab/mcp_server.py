"""Stdio JSON-RPC 2.0 MCP Server for pe_reversing_lab."""

from __future__ import annotations

import json
import sys
from typing import Any

SERVER_NAME = 'pe-reversing-lab-mcp'
TOOLS = [
    {
        "name": "pe_reversing_lab_triage_binary",
        "description": "Execute pe_reversing_lab_triage_binary via pe-reversing-lab-mcp.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "pe_reversing_lab_generate_yara",
        "description": "Execute pe_reversing_lab_generate_yara via pe-reversing-lab-mcp.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    }
]


def handle_mcp_request(req: dict[str, Any]) -> dict[str, Any] | None:
    """Process a single JSON-RPC 2.0 MCP request."""
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
                "serverInfo": {"name": SERVER_NAME, "version": "2.0.0"},
            },
        }
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = req.get("params") or {}
        tool_name = params.get("name", "")
        args = params.get("arguments") or {}
        payload = {"ok": True, "server": SERVER_NAME, "tool": tool_name, "arguments": args}
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

"""Local Loopback, Named Pipe, WebSocket & JSON-RPC IPC Packet Sniffer (REQ-PE-IPCSNIFF-01)."""

from __future__ import annotations

import json
import re
from typing import Any, Sequence

from pe_reversing_lab.l1_primitives import compute_shannon_entropy

HTTP_REQ_RE = re.compile(
    rb"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+(HTTP/\d\.\d)\r?\n"
)
HTTP_RESP_RE = re.compile(rb"^(HTTP/\d\.\d)\s+(\d{3})\s+([^\r\n]*)\r?\n")

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("BEARER_TOKEN", re.compile(rb"Authorization:\s*Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.I)),
    ("JWT_TOKEN", re.compile(rb"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{4,}")),
    ("API_KEY", re.compile(rb"(?:api[_-]?key|token|secret)\"\s*:\s*\"[^\"]{8,}\"|sk-[A-Za-z0-9\-_]{12,}", re.I)),
    ("PRIVATE_KEY", re.compile(rb"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
)


def _detect_secrets(payload: bytes) -> list[str]:
    found: list[str] = []
    for label, pattern in SECRET_PATTERNS:
        if pattern.search(payload) and label not in found:
            found.append(label)
    return found


def _is_websocket_frame(payload: bytes) -> tuple[bool, int, bytes]:
    if len(payload) < 2:
        return False, 0, b""
    first_byte = payload[0]
    second_byte = payload[1]
    fin = (first_byte & 0x80) != 0
    rsv = (first_byte & 0x70) >> 4
    opcode = first_byte & 0x0F
    masked = (second_byte & 0x80) != 0
    length = second_byte & 0x7F
    if rsv != 0 or opcode not in (0x1, 0x2, 0x8, 0x9, 0xA):
        return False, 0, b""
    header_len = 2 + (4 if masked else 0)
    if length < 126 and len(payload) == header_len + length and (fin or opcode in (0x1, 0x2)):
        body = payload[header_len : header_len + length]
        return True, opcode, body
    return False, 0, b""


def inspect_ipc_packet(
    payload: bytes,
    channel_name: str = "",
    high_entropy_threshold: float = 7.0,
) -> dict[str, Any]:
    """REQ-PE-IPCSNIFF-01: Dissect local IPC packet (HTTP/1.1, JSON-RPC, WebSocket, Named Pipe)."""
    raw = bytes(payload or b"")
    entropy = compute_shannon_entropy(raw)
    is_high_entropy = entropy >= float(high_entropy_threshold)
    secrets = _detect_secrets(raw)

    protocol = "RAW_BINARY"
    method = ""
    path_or_target = channel_name or ""

    m_req = HTTP_REQ_RE.match(raw)
    m_resp = HTTP_RESP_RE.match(raw)
    if m_req:
        method = m_req.group(1).decode("ascii", errors="replace")
        path_or_target = m_req.group(2).decode("ascii", errors="replace")
        protocol = m_req.group(3).decode("ascii", errors="replace")
    elif m_resp:
        protocol = m_resp.group(1).decode("ascii", errors="replace")
        method = m_resp.group(2).decode("ascii", errors="replace")
    else:
        stripped = raw.strip()
        parsed_json: dict[str, Any] | None = None
        if stripped.startswith(b"{") and stripped.endswith(b"}"):
            try:
                candidate = json.loads(stripped.decode("utf-8", errors="replace"))
                if isinstance(candidate, dict):
                    parsed_json = candidate
            except ValueError:
                parsed_json = None

        if parsed_json is not None and ("jsonrpc" in parsed_json or "method" in parsed_json):
            protocol = "JSON-RPC"
            method = str(parsed_json.get("method", ""))
            path_or_target = channel_name or method
        else:
            is_ws, opcode, _ws_body = _is_websocket_frame(raw)
            if is_ws:
                protocol = "WEBSOCKET"
                method = f"OPCODE_{opcode}"
            elif channel_name.startswith("\\\\.\\pipe\\"):
                protocol = "NAMED_PIPE"

    return {
        "requirement_id": "REQ-PE-IPCSNIFF-01",
        "protocol": protocol,
        "method": method,
        "path_or_target": path_or_target,
        "channel_name": channel_name,
        "size_bytes": len(raw),
        "shannon_entropy": entropy,
        "is_high_entropy": is_high_entropy,
        "detected_secrets": secrets,
    }


class LocalIpcPacketSniffer:
    """REQ-PE-IPCSNIFF-01: Stateful local IPC and Named Pipe packet sniffer and stream analyzer."""

    def __init__(self, high_entropy_threshold: float = 7.0) -> None:
        self.high_entropy_threshold = float(high_entropy_threshold)

    def inspect_packet(self, payload: bytes, channel_name: str = "") -> dict[str, Any]:
        return inspect_ipc_packet(
            payload=payload,
            channel_name=channel_name,
            high_entropy_threshold=self.high_entropy_threshold,
        )

    def inspect_stream(
        self,
        packets: Sequence[bytes],
        channel_name: str = "",
    ) -> dict[str, Any]:
        results: list[dict[str, Any]] = []
        protocol_counts: dict[str, int] = {}
        all_secrets: list[str] = []
        high_entropy_packets = 0

        for pkt in packets:
            info = self.inspect_packet(pkt, channel_name=channel_name)
            results.append(info)
            proto = str(info["protocol"])
            protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
            if info["is_high_entropy"]:
                high_entropy_packets += 1
            for sec in info["detected_secrets"]:
                if sec not in all_secrets:
                    all_secrets.append(sec)

        return {
            "requirement_id": "REQ-PE-IPCSNIFF-01",
            "total_packets": len(results),
            "protocol_counts": protocol_counts,
            "high_entropy_packets": high_entropy_packets,
            "detected_secrets": all_secrets,
            "packets": results,
        }

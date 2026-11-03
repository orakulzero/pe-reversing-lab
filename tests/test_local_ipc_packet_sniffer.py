"""ISO 9001:2015 Agile V Verification Suite for Local IPC Packet Sniffer (REQ-PE-IPCSNIFF-01)."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


def test_req_pe_ipcsniff_01_http_and_jsonrpc_dissection_with_secret_detection() -> None:
    import pe_reversing_lab
    from pe_reversing_lab.local_ipc_packet_sniffer import (
        LocalIpcPacketSniffer,
        inspect_ipc_packet,
    )

    assert getattr(pe_reversing_lab, "__v3_generation__", None) == "3.0.0"
    assert hasattr(pe_reversing_lab, "LocalIpcPacketSniffer")
    assert hasattr(pe_reversing_lab, "inspect_ipc_packet")

    http_buf = (
        b"POST /v1/rpc HTTP/1.1\r\n"
        b"Host: 127.0.0.1:8080\r\n"
        b"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test\r\n\r\n"
        b'{"jsonrpc":"2.0","method":"wallet.sign","id":7}'
    )
    res_http = inspect_ipc_packet(http_buf)
    assert res_http["requirement_id"] == "REQ-PE-IPCSNIFF-01"
    assert res_http["protocol"] == "HTTP/1.1"
    assert res_http["method"] == "POST"
    assert res_http["path_or_target"] == "/v1/rpc"
    assert "BEARER_TOKEN" in res_http["detected_secrets"]

    rpc_buf = (
        b'{"jsonrpc": "2.0", "method": "debug.eval", '
        b'"params": {"api_key": "sk-live-1234567890abcdef12345678"}, "id": 42}'
    )
    pipe_name = r"\\.\pipe\local_agent_rpc"
    sniffer = LocalIpcPacketSniffer()
    res_rpc = sniffer.inspect_packet(rpc_buf, channel_name=pipe_name)
    assert res_rpc["requirement_id"] == "REQ-PE-IPCSNIFF-01"
    assert res_rpc["protocol"] == "JSON-RPC"
    assert res_rpc["method"] == "debug.eval"
    assert res_rpc["channel_name"] == pipe_name
    assert "API_KEY" in res_rpc["detected_secrets"]


def test_req_pe_ipcsniff_01_websocket_and_high_entropy_binary_stream() -> None:
    from pe_reversing_lab.local_ipc_packet_sniffer import (
        LocalIpcPacketSniffer,
        inspect_ipc_packet,
    )

    ws_frame = b"\x81\x05hello"
    res_ws = inspect_ipc_packet(ws_frame)
    assert res_ws["requirement_id"] == "REQ-PE-IPCSNIFF-01"
    assert res_ws["protocol"] == "WEBSOCKET"

    high_entropy_buf = bytes(range(256))
    c2_pipe = r"\\.\pipe\c2_frame"
    res_bin = inspect_ipc_packet(high_entropy_buf, channel_name=c2_pipe)
    assert res_bin["protocol"] in ("NAMED_PIPE", "RAW_BINARY")
    assert res_bin["shannon_entropy"] >= 7.5
    assert res_bin["is_high_entropy"] is True

    pkt1 = (
        b"POST /v1/rpc HTTP/1.1\r\n"
        b"Host: 127.0.0.1:8080\r\n"
        b"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test\r\n\r\n"
    )
    pkt2 = ws_frame
    stream_summary = LocalIpcPacketSniffer().inspect_stream([pkt1, pkt2])
    assert stream_summary["requirement_id"] == "REQ-PE-IPCSNIFF-01"
    assert stream_summary["total_packets"] == 2
    assert stream_summary["protocol_counts"]["HTTP/1.1"] == 1
    assert stream_summary["protocol_counts"]["WEBSOCKET"] == 1
    assert "BEARER_TOKEN" in stream_summary["detected_secrets"]

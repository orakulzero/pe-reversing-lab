import pytest
from fastapi.testclient import TestClient

from pe_reversing_lab.l4_app import app


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(app)


def test_disassemble_with_profile_and_raw_hex_prefers_raw_hex(client: TestClient) -> None:
    """When both `profile` and `raw_hex` are supplied, raw_hex must take precedence."""
    payload = {
        "profile": "clean",
        "raw_hex": "48 83 ec 28 90 48 83 c4 28 c3",
        "base_rva": 0x1000,
        "max_instructions": 16,
        "max_bytes": 64,
        "stop_on_ret": True,
    }
    resp = client.post("/api/pe/disassemble", json=payload)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    assert isinstance(body["instructions"], list)
    assert body["instruction_count"] == len(body["instructions"])
    assert body["instruction_count"] > 0


def test_disassemble_profile_only_returns_instructions(client: TestClient) -> None:
    resp = client.post(
        "/api/pe/disassemble",
        json={"profile": "packed_injector", "max_instructions": 8},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    assert body["instruction_count"] > 0


def test_disassemble_unknown_profile_returns_400(client: TestClient) -> None:
    resp = client.post("/api/pe/disassemble", json={"profile": "does_not_exist"})
    assert resp.status_code == 400
    assert "Unknown profile" in resp.json()["detail"]

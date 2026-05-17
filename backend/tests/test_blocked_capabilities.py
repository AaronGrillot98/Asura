from fastapi.testclient import TestClient

from app.main import app
from app.security.blocked_capabilities import BLOCKED_CAPABILITIES, as_dicts


client = TestClient(app)


def test_blocked_capabilities_constant_is_non_empty() -> None:
    assert len(BLOCKED_CAPABILITIES) >= 11
    ids = {bc.id for bc in BLOCKED_CAPABILITIES}
    assert {
        "malware",
        "persistence",
        "credential_theft",
        "phishing",
        "ransomware",
        "botnet",
        "destructive_payload",
        "stealth",
        "unauthorized_exploitation",
        "data_exfiltration",
        "ddos",
    }.issubset(ids)


def test_blocked_capabilities_endpoint_exposes_constant() -> None:
    response = client.get("/api/safety/blocked")

    assert response.status_code == 200
    body = response.json()
    api_ids = {item["id"] for item in body["capabilities"]}
    constant_ids = {item["id"] for item in as_dicts()}
    assert api_ids == constant_ids
    assert body["explanation"]

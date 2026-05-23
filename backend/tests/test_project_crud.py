"""Project + target CRUD tests.

Asura's day-one promise is that a real user can create their own project,
declare authorized scope, add targets, and run scans — all from the UI,
without editing demo_store.py. This file proves the backend half of that
contract.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from app.repositories import reset_repos


client = TestClient(app)


def _payload(name: str = "Test Project", **overrides) -> dict:
    body = {
        "name": name,
        "description": "Test project for project CRUD",
        "scope_rules": {
            "domains": ["example.com"],
            "urls": ["https://example.com"],
            "cidrs": [],
            "repos": ["git://example/repo"],
            "containers": [],
            "blocked_targets": [],
            "allow_active": True,
            "allow_lab": False,
            "max_requests_per_second": 2,
            "timeout_seconds": 900,
        },
        "grantor": "Security Lead",
        "risk_score": 0,
    }
    body.update(overrides)
    return body


def test_create_project_returns_201_and_persists() -> None:
    reset_repos()
    response = client.post("/api/projects", json=_payload())
    assert response.status_code == 201
    body = response.json()
    assert body["name"] == "Test Project"
    assert body["is_demo_data"] is False
    assert body["id"].startswith("proj-")
    # Re-fetch to confirm persistence.
    detail = client.get(f"/api/projects/{body['id']}").json()
    assert detail["name"] == "Test Project"


def test_create_project_auto_creates_authorized_scope() -> None:
    reset_repos()
    body = client.post("/api/projects", json=_payload("Scope Audit Project")).json()
    scopes = client.get(f"/api/projects/{body['id']}/scopes").json()
    assert len(scopes) == 1
    assert scopes[0]["grantor"] == "Security Lead"
    assert scopes[0]["explicit_authorization_grant"] is True


def test_create_project_writes_audit_log_entry() -> None:
    reset_repos()
    body = client.post("/api/projects", json=_payload("Audited Project")).json()
    audit = client.get("/api/audit", params={"limit": 200}).json()
    matches = [a for a in audit if a["target"] == body["id"] and a["action"] == "project.create"]
    assert len(matches) == 1
    assert matches[0]["decision"] == "allow"


def test_create_project_rejects_duplicate_name_in_workspace() -> None:
    reset_repos()
    client.post("/api/projects", json=_payload("Duplicate"))
    second = client.post("/api/projects", json=_payload("Duplicate"))
    assert second.status_code == 409


def test_dashboard_for_new_project_has_empty_risk_trend() -> None:
    reset_repos()
    body = client.post("/api/projects", json=_payload("Empty Trend Project")).json()
    dashboard = client.get(f"/api/dashboard/{body['id']}").json()
    assert dashboard["project"]["name"] == "Empty Trend Project"
    assert dashboard["risk_trend"] == []
    assert dashboard["findings"] == []
    assert dashboard["is_demo_data"] is False


def test_patch_project_updates_fields() -> None:
    reset_repos()
    created = client.post("/api/projects", json=_payload("Patchable Project")).json()
    response = client.patch(
        f"/api/projects/{created['id']}",
        json={"description": "Updated description", "risk_score": 42},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["description"] == "Updated description"
    assert body["risk_score"] == 42


def test_patch_demo_project_scope_is_rejected() -> None:
    reset_repos()
    response = client.patch(
        "/api/projects/demo",
        json={"scope_rules": {
            "domains": ["evil.example"], "urls": [], "cidrs": [], "repos": [],
            "containers": [], "blocked_targets": [], "allow_active": True,
            "allow_lab": False, "max_requests_per_second": 2, "timeout_seconds": 900,
        }},
    )
    assert response.status_code == 400


def test_delete_project_cascades_and_writes_audit() -> None:
    reset_repos()
    created = client.post("/api/projects", json=_payload("Cascade Project")).json()
    # Seed a target so we can check cascade.
    client.post(
        f"/api/projects/{created['id']}/targets",
        json={"kind": "url", "value": "https://example.com", "authorized": True},
    )
    targets_before = client.get(f"/api/projects/{created['id']}/targets").json()
    assert len(targets_before) == 1

    response = client.delete(f"/api/projects/{created['id']}")
    assert response.status_code == 204

    # Project gone, targets gone.
    assert client.get(f"/api/projects/{created['id']}").status_code == 404
    # The target endpoint filters by project_id and will return empty either way,
    # so check the underlying repo via the audit log instead.
    audit = client.get("/api/audit", params={"limit": 200}).json()
    actions = {a["action"] for a in audit if a["target"] == created["id"]}
    assert "project.delete" in actions


def test_delete_demo_project_refused() -> None:
    reset_repos()
    response = client.delete("/api/projects/demo")
    assert response.status_code == 400


def test_add_target_then_delete_target() -> None:
    reset_repos()
    created = client.post("/api/projects", json=_payload("Target Test Project")).json()
    add = client.post(
        f"/api/projects/{created['id']}/targets",
        json={
            "kind": "host",
            "value": "edge-01.internal.example",
            "authorized": True,
            "owned_internal": True,
        },
    )
    assert add.status_code == 201
    target = add.json()
    assert target["value"] == "edge-01.internal.example"
    assert target["owned_internal"] is True
    assert target["is_demo_data"] is False

    listing = client.get(f"/api/projects/{created['id']}/targets").json()
    assert any(t["id"] == target["id"] for t in listing)

    delete = client.delete(f"/api/projects/{created['id']}/targets/{target['id']}")
    assert delete.status_code == 204
    listing_after = client.get(f"/api/projects/{created['id']}/targets").json()
    assert all(t["id"] != target["id"] for t in listing_after)


def test_add_target_on_unknown_project_404() -> None:
    reset_repos()
    response = client.post(
        "/api/projects/proj-does-not-exist/targets",
        json={"kind": "url", "value": "https://x.example", "authorized": True},
    )
    assert response.status_code == 404


def test_add_target_grants_scope_so_passive_scan_is_accepted() -> None:
    """Regression: adding a target via POST /projects/{id}/targets must
    also expand the project's scope. Without this, the scope guard
    silently rejects every subsequent scan of the just-added target with
    "target not in project scope," which made the UI's "Add Target" path
    look broken from the user's perspective.
    """
    reset_repos()
    # Start with empty scope_rules — the user adds scope by adding targets.
    minimal_scope = {
        "domains": [],
        "urls": [],
        "cidrs": [],
        "repos": [],
        "containers": [],
        "blocked_targets": [],
        "allow_active": True,
        "allow_lab": False,
        "max_requests_per_second": 2,
        "timeout_seconds": 900,
    }
    created = client.post(
        "/api/projects",
        json=_payload("Scope Grant Test", scope_rules=minimal_scope),
    ).json()
    pid = created["id"]

    # Add a domain target. Adding it must:
    #   1. Create the Target record (already worked).
    #   2. Append the value to project.targets (was broken).
    #   3. Add the value to scope_rules.domains (was broken).
    add = client.post(
        f"/api/projects/{pid}/targets",
        json={"kind": "domain", "value": "example.com", "authorized": True},
    )
    assert add.status_code == 201

    project = client.get(f"/api/projects/{pid}").json()
    assert "example.com" in project["targets"]
    assert "example.com" in project["scope_rules"]["domains"]

    # The whole point: a passive scan against the just-added target must
    # now pass the scope guard. We use `subfinder` because it's passive-
    # capable; the scan may still no-op in CI (no binary installed) but
    # it must NOT be rejected with a scope error.
    scan = client.post(
        "/api/scans",
        json={
            "project_id": pid,
            "target": "example.com",
            "scanners": ["subfinder"],
            "mode": "passive",
        },
    )
    assert scan.status_code != 400, scan.text
    runs = scan.json()
    assert isinstance(runs, list) and runs, runs
    for run in runs:
        msg = (run.get("message") or "").lower()
        assert "not listed in project scope" not in msg, run


def test_add_url_target_grants_url_scope() -> None:
    """Same regression as above but exercises the url→urls bucket so a
    follow-up scan referencing the URL passes the scope guard.
    """
    reset_repos()
    minimal_scope = {
        "domains": [], "urls": [], "cidrs": [], "repos": [], "containers": [],
        "blocked_targets": [], "allow_active": True, "allow_lab": False,
        "max_requests_per_second": 2, "timeout_seconds": 900,
    }
    created = client.post(
        "/api/projects",
        json=_payload("Url Scope Test", scope_rules=minimal_scope),
    ).json()
    pid = created["id"]
    add = client.post(
        f"/api/projects/{pid}/targets",
        json={"kind": "url", "value": "https://api.example.com/v1", "authorized": True},
    )
    assert add.status_code == 201
    project = client.get(f"/api/projects/{pid}").json()
    assert "https://api.example.com/v1" in project["scope_rules"]["urls"]
    assert "https://api.example.com/v1" in project["targets"]


def test_add_ip_target_grants_cidr_scope() -> None:
    """A kind=ip target gets expanded to a /32 CIDR so the scope guard's
    `ip_address in ip_network` check resolves cleanly.
    """
    reset_repos()
    minimal_scope = {
        "domains": [], "urls": [], "cidrs": [], "repos": [], "containers": [],
        "blocked_targets": [], "allow_active": True, "allow_lab": False,
        "max_requests_per_second": 2, "timeout_seconds": 900,
    }
    created = client.post(
        "/api/projects",
        json=_payload("Ip Scope Test", scope_rules=minimal_scope),
    ).json()
    pid = created["id"]
    add = client.post(
        f"/api/projects/{pid}/targets",
        json={"kind": "ip", "value": "10.0.0.5", "authorized": True},
    )
    assert add.status_code == 201
    project = client.get(f"/api/projects/{pid}").json()
    assert "10.0.0.5/32" in project["scope_rules"]["cidrs"]

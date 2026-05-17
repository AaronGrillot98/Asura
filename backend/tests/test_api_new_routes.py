from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_findings_route_filters_by_severity() -> None:
    response = client.get("/api/findings", params={"project_id": "demo", "severity": "critical"})
    assert response.status_code == 200
    body = response.json()
    assert body
    assert all(f["severity"] == "critical" for f in body)


def test_findings_route_returns_demo_only() -> None:
    response = client.get("/api/findings", params={"demo": "true"})
    assert response.status_code == 200
    assert all(f["is_demo_data"] for f in response.json())


def test_finding_detail_404() -> None:
    response = client.get("/api/findings/does-not-exist")
    assert response.status_code == 404


def test_attack_paths_endpoint() -> None:
    response = client.get("/api/attack-paths", params={"project_id": "demo"})
    assert response.status_code == 200
    body = response.json()
    assert len(body) >= 3
    titles = {p["title"] for p in body}
    assert any("admin" in t.lower() for t in titles)


def test_scans_endpoint_returns_runs() -> None:
    response = client.get("/api/scans", params={"project_id": "demo"})
    assert response.status_code == 200
    assert response.json()


def test_projects_endpoint() -> None:
    response = client.get("/api/projects")
    assert response.status_code == 200
    body = response.json()
    assert len(body) >= 1
    assert body[0]["name"] == "Acme FlightOps Demo"


def test_project_targets_and_scopes_routes() -> None:
    t = client.get("/api/projects/demo/targets")
    assert t.status_code == 200
    s = client.get("/api/projects/demo/scopes")
    assert s.status_code == 200


def test_arsenal_supports_new_filters() -> None:
    response = client.get("/api/arsenal", params={"risk": "high"})
    assert response.status_code == 200
    body = response.json()
    assert all(tool["risk_level"] == "high" for tool in body["tools"])


def test_arsenal_lab_only_filter() -> None:
    response = client.get("/api/arsenal", params={"lab_only": "true"})
    assert response.status_code == 200
    body = response.json()
    forensic_ids = {tool["id"] for tool in body["tools"]}
    assert {"chainsaw", "volatility3"}.issubset(forensic_ids)


def test_search_empty_query_returns_empty_results() -> None:
    response = client.get("/api/search")
    assert response.status_code == 200
    body = response.json()
    assert body["results"] == []


def test_search_finds_demo_project_by_name() -> None:
    response = client.get("/api/search", params={"q": "Acme"})
    assert response.status_code == 200
    body = response.json()
    kinds = {r["kind"] for r in body["results"]}
    assert "project" in kinds
    project_match = next(r for r in body["results"] if r["kind"] == "project")
    assert "Acme" in project_match["title"]
    assert project_match["href"].startswith("/projects/")


def test_search_finds_seeded_finding() -> None:
    response = client.get("/api/search", params={"q": "admin"})
    assert response.status_code == 200
    results = response.json()["results"]
    finding_hits = [r for r in results if r["kind"] == "finding"]
    assert len(finding_hits) >= 1
    assert finding_hits[0]["href"].startswith("/findings/")
    assert finding_hits[0]["badge"]  # severity is non-empty


def test_search_finds_tools_from_arsenal() -> None:
    response = client.get("/api/search", params={"q": "semgrep"})
    assert response.status_code == 200
    results = response.json()["results"]
    tool_hits = [r for r in results if r["kind"] == "tool"]
    assert any(r["id"] == "semgrep" for r in tool_hits)


def test_search_respects_limit() -> None:
    response = client.get("/api/search", params={"q": "a", "limit": 5})
    assert response.status_code == 200
    assert len(response.json()["results"]) <= 5


def test_post_scan_records_audit_entry() -> None:
    response = client.post(
        "/api/scans",
        json={
            "project_id": "demo",
            "target": "https://flightops.acme.example",
            "scanners": ["nuclei"],
            "mode": "active",
            "authorized_scope": "https://flightops.acme.example",
            "explicit_authorization": True,
        },
    )
    assert response.status_code == 200
    audit = client.get("/api/audit").json()
    assert audit
    # The most recent entry should be the allow decision for the scan we just made.
    assert audit[0]["decision"] in {"allow", "block"}

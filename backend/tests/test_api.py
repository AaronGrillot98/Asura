from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_dashboard_returns_seeded_findings() -> None:
    response = client.get("/api/dashboard/demo")

    assert response.status_code == 200
    body = response.json()
    assert body["project"]["name"] == "Acme FlightOps Demo"
    assert len(body["findings"]) >= 10
    assert len(body["attack_paths"]) >= 3
    assert body["agent_outputs"]
    assert all(finding["evidence"] for finding in body["findings"])
    assert body["fix_first"][0]["severity"] == "critical"
    assert body["is_demo_data"] is True


def test_unknown_project_returns_404() -> None:
    response = client.get("/api/dashboard/missing")

    assert response.status_code == 404


def test_active_scan_requires_authorized_scope() -> None:
    response = client.post(
        "/api/scans",
        json={
            "project_id": "demo",
            "target": "10.10.7.20",
            "scanners": ["nmap"],
            "mode": "active",
            "explicit_authorization": True,
        },
    )

    assert response.status_code == 400


def test_active_scan_blocks_out_of_scope_target() -> None:
    response = client.post(
        "/api/scans",
        json={
            "project_id": "demo",
            "target": "https://evil.example",
            "scanners": ["nuclei"],
            "mode": "active",
            "authorized_scope": "https://evil.example",
            "explicit_authorization": True,
        },
    )

    assert response.status_code == 400
    assert "outside the project allowlist" in response.json()["detail"]


def test_passive_scan_blocks_nmap() -> None:
    response = client.post(
        "/api/scans",
        json={
            "project_id": "demo",
            "target": "10.10.7.20",
            "scanners": ["nmap"],
            "mode": "passive",
        },
    )

    assert response.status_code == 200
    assert response.json()[0]["status"] == "blocked"


def test_markdown_report_exports_priority_chain() -> None:
    response = client.get("/api/reports/demo/markdown")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/markdown")
    assert "Likely admin privilege escalation chain" in response.text


def test_json_report_contains_scope_findings_and_agents() -> None:
    response = client.get("/api/reports/demo/json")

    assert response.status_code == 200
    body = response.json()
    assert body["sections"]["scope"]["allow_active"] is True
    assert body["sections"]["findings"]
    assert body["sections"]["attack_paths"]
    assert body["sections"]["agent_outputs"]


def test_arsenal_exposes_registry_and_blocked_policy() -> None:
    response = client.get("/api/arsenal")

    assert response.status_code == 200
    body = response.json()
    tool_ids = {tool["id"] for tool in body["tools"]}
    assert {"nmap", "nuclei", "semgrep", "trivy", "gitleaks", "osv-scanner", "checkov", "zap", "syft", "grype"}.issubset(tool_ids)
    assert any(tool["execution"] == "blocked" for tool in body["tools"])
    assert any(pack["name"] == "Recon Pack" for pack in body["pack_summaries"])
    assert body["blocked_policy"]


def test_arsenal_contract_endpoint_is_valid() -> None:
    response = client.get("/api/arsenal/contract")

    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is True
    assert body["errors"] == []
    assert body["tool_count"] >= 10
    assert body["core_runner_count"] >= 10
    assert body["executable_count"] >= 10
    assert body["blocked_count"] >= 1
    assert len(body["registry_hash"]) == 64


def test_arsenal_rejects_invalid_execution_filter() -> None:
    response = client.get("/api/arsenal", params={"execution": "unknown"})

    assert response.status_code == 400


def test_scanners_endpoint_exposes_locked_core_engine() -> None:
    response = client.get("/api/scanners")

    assert response.status_code == 200
    scanners = response.json()
    assert [scanner["name"] for scanner in scanners] == [
        "nmap",
        "nuclei",
        "semgrep",
        "trivy",
        "gitleaks",
        "osv-scanner",
        "checkov",
        "zap",
        "syft",
        "grype",
    ]
    assert all(scanner["parser"] for scanner in scanners)


def test_arsenal_can_filter_optional_api_pack() -> None:
    response = client.get("/api/arsenal", params={"pack": "API Security Pack", "execution": "optional_pack"})

    assert response.status_code == 200
    body = response.json()
    ids = {tool["id"] for tool in body["tools"]}
    # Schemathesis is the established API runner; the rest are catalog-only planned
    # optional_pack entries added when the catalog grew to the 90-tool spec.
    assert "schemathesis" in ids
    assert {"kiterunner", "jwt-tool", "inql", "graphql-cop", "restler"}.issubset(ids)


def test_arsenal_searches_use_cases() -> None:
    response = client.get("/api/arsenal", params={"search": "SBOM"})

    assert response.status_code == 200
    ids = {tool["id"] for tool in response.json()["tools"]}
    assert {"syft", "trivy", "grype"}.intersection(ids)


def test_arsenal_exposes_step_three_language_runners() -> None:
    response = client.get("/api/arsenal", params={"search": "dependencies"})

    assert response.status_code == 200
    ids = {tool["id"] for tool in response.json()["tools"]}
    assert {"pip-audit", "npm-audit", "cargo-audit", "govulncheck"}.issubset(ids)


def test_arsenal_exposes_recon_pipeline() -> None:
    response = client.get("/api/arsenal", params={"pack": "Recon Pack", "execution": "optional_pack"})

    assert response.status_code == 200
    ids = {tool["id"] for tool in response.json()["tools"]}
    assert {"subfinder", "amass", "httpx", "naabu", "dnsx", "katana", "gau", "waybackurls", "hakrawler", "webanalyze", "whatweb", "wafw00f", "tlsx", "shuffledns", "assetfinder"}.issubset(ids)

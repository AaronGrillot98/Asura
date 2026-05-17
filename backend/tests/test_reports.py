from fastapi.testclient import TestClient

from app.main import app
from app.repositories import get_repos
from app.services.reporting import build_report, render_markdown


client = TestClient(app)


def test_build_report_includes_all_required_sections() -> None:
    report = build_report(repos=get_repos(), project_id="demo", kind="markdown")
    sections = report.sections
    expected = {
        "engagement_summary",
        "scope",
        "authorization_statement",
        "methodology",
        "tools_used",
        "executive_summary",
        "risk_overview",
        "attack_paths",
        "findings",
        "findings_by_severity",
        "evidence",
        "remediation_roadmap",
        "scanner_runs",
        "raw_evidence_refs",
        "safety_statement",
        "scope_statement",
    }
    assert expected.issubset(sections.keys())
    assert report.scope_statement
    assert report.authorization_statement
    assert report.safety_statement
    assert report.content_hash
    assert report.pdf_status == "not_generated"


def test_markdown_render_contains_safety_section() -> None:
    report = build_report(repos=get_repos(), project_id="demo", kind="markdown")
    body = render_markdown(report)
    assert "## Safety Statement" in body
    assert "## Authorization Statement" in body
    assert "## Scope" in body
    assert "## Remediation Roadmap" in body
    assert "Asura runs only authorized" in body


def test_post_reports_persists_report() -> None:
    response = client.post("/api/reports/demo", json={"kind": "markdown"})
    assert response.status_code == 200
    body = response.json()
    assert body["kind"] == "markdown"
    assert body["safety_statement"]
    repos = get_repos()
    assert repos.reports.get(body["id"]) is not None

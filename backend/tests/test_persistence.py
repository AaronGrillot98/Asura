"""SQL persistence round-trip tests.

Boots an isolated per-test SQLite file, flips `ASURA_USE_SQL=1`, and
verifies that every persisted entity round-trips through SQLAlchemy
faithfully — i.e. what you put in, you can get back out, and what you
write before a "restart" survives a fresh `get_repos()`.

These tests are explicitly scoped to the SQL path. The wider 168-test
suite continues to use the in-memory backend (which `reset_repos()`
falls back to when `ASURA_USE_SQL` is unset).
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models.schemas import (
    AuditLog,
    Confidence,
    Evidence,
    EvidenceType,
    Finding,
    Project,
    ScannerRun,
    ScopeRules,
    Severity,
    ScanMode,
)
from app.repositories import reset_repos


client = TestClient(app)


@pytest.fixture
def sql_env(tmp_path: Path):
    """Per-test SQLite DB. Cleans up at fixture teardown."""
    db_path = tmp_path / "asura.test.db"
    env = {k: v for k, v in os.environ.items() if k not in {"ASURA_USE_SQL", "ASURA_DATABASE_URL"}}
    env["ASURA_USE_SQL"] = "1"
    env["ASURA_DATABASE_URL"] = f"sqlite:///{db_path.as_posix()}"
    with mock.patch.dict(os.environ, env, clear=True):
        # Force a fresh engine/session bound to this test's DB.
        import app.db as db_pkg
        db_pkg._ENGINE = None
        db_pkg._SESSION_FACTORY = None
        reset_repos()
        yield
        db_pkg._ENGINE = None
        db_pkg._SESSION_FACTORY = None


# ---- Smoke: seed runs idempotently --------------------------------------


def test_demo_seed_lands_in_sql_backend(sql_env) -> None:
    from app.repositories import get_repos
    repos = get_repos()
    assert repos.projects.get("demo") is not None
    assert repos.findings.count() >= 1
    assert repos.runs.count() >= 1
    # Audit log is empty until a scope decision happens — confirm the model.
    assert repos.audit.count() == 0


def test_seed_is_idempotent_across_get_repos_calls(sql_env) -> None:
    from app.repositories import get_repos
    repos = get_repos()
    findings_before = repos.findings.count()
    # Trigger another get_repos cycle (simulates app reload).
    reset_repos()
    repos2 = get_repos()
    assert repos2.findings.count() == findings_before


# ---- Round-trip every entity type ---------------------------------------


def test_project_round_trip_through_sql(sql_env) -> None:
    from app.repositories import get_repos
    repos = get_repos()
    new = Project(
        id="proj-sql-test",
        workspace_id="workspace-demo",
        name="SQL Test Project",
        description="Persistence round trip",
        scope_rules=ScopeRules(domains=["sqltest.example"], allow_active=True),
        risk_score=42,
        targets=["https://sqltest.example"],
        created_at=datetime.now(timezone.utc),
        is_demo_data=False,
    )
    repos.projects.add(new)
    fetched = repos.projects.get("proj-sql-test")
    assert fetched is not None
    assert fetched.name == "SQL Test Project"
    assert fetched.risk_score == 42
    assert "sqltest.example" in fetched.scope_rules.domains
    assert fetched.scope_rules.allow_active is True


def test_finding_with_evidence_round_trip(sql_env) -> None:
    from app.repositories import get_repos
    repos = get_repos()
    ev = Evidence(
        id="ev-sql-1",
        finding_id="f-sql-1",
        evidence_type=EvidenceType.scanner_output,
        scanner="semgrep",
        raw={"rule": "test", "file": "x.py", "line": 5},
        summary="round-trip evidence",
        source_tool="semgrep",
        captured_at=datetime.now(timezone.utc),
    )
    finding = Finding(
        id="f-sql-1",
        project_id="demo",
        asset_id="asset-repo",
        scanner="semgrep",
        title="SQL round-trip finding",
        category="code",
        severity=Severity.high,
        confidence=Confidence.medium,
        impact="Test impact",
        recommendation="Test recommendation",
        reproduction="Test reproduction",
        false_positive_reasoning="Test reasoning",
        evidence=[ev],
        is_demo_data=False,
    )
    repos.findings.add(finding)
    repos.evidence.add(ev)
    fetched = repos.findings.get("f-sql-1")
    assert fetched is not None
    assert fetched.severity == Severity.high
    assert fetched.evidence and fetched.evidence[0].summary == "round-trip evidence"
    # Evidence repo independently holds the same row.
    assert repos.evidence.get("ev-sql-1") is not None


def test_scanner_run_round_trip(sql_env) -> None:
    from app.repositories import get_repos
    repos = get_repos()
    run = ScannerRun(
        id="run-sql-1",
        project_id="demo",
        scanner="semgrep",
        mode=ScanMode.passive,
        status="completed",
        target="git://x",
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
        message="round-trip",
        args=["semgrep", "-r", "."],
        exit_code=0,
        evidence_ids=["ev-sql-1"],
        findings_created=1,
        is_demo_data=False,
    )
    repos.runs.add(run)
    fetched = repos.runs.get("run-sql-1")
    assert fetched is not None
    assert fetched.args == ["semgrep", "-r", "."]
    assert fetched.exit_code == 0
    assert fetched.findings_created == 1


def test_audit_log_round_trip(sql_env) -> None:
    from app.repositories import get_repos
    repos = get_repos()
    row = AuditLog(
        id="audit-sql-1",
        workspace_id="workspace-demo",
        actor="tester",
        action="scope.allow",
        event_type="scope_decision",
        target="https://x",
        result="allow",
        decision="allow",
        reason=None,
        reason_code="passive_in_scope",
        payload={"mode": "passive"},
        timestamp=datetime.now(timezone.utc),
    )
    repos.audit.add(row)
    fetched = repos.audit.get("audit-sql-1")
    assert fetched is not None
    assert fetched.decision == "allow"
    assert fetched.payload == {"mode": "passive"}


# ---- "Restart survives" test --------------------------------------------


def test_data_survives_session_recreation(sql_env) -> None:
    """Adding a project, dropping the singleton, getting a new container
    should return the same project. Simulates a full process restart."""
    from app.repositories import get_repos
    repos = get_repos()
    new = Project(
        id="proj-persistence",
        workspace_id="workspace-demo",
        name="Survives restart",
        description="",
        scope_rules=ScopeRules(domains=["x"]),
        risk_score=10,
        targets=[],
        created_at=datetime.now(timezone.utc),
        is_demo_data=False,
    )
    repos.projects.add(new)

    # Reset the singleton WITHOUT resetting the DB (simulate restart).
    import app.repositories as r
    r._REPOS = None
    fresh = get_repos()
    assert fresh.projects.get("proj-persistence") is not None


# ---- Filtering works on indexed columns ---------------------------------


def test_list_filters_by_predicate_after_sql_round_trip(sql_env) -> None:
    from app.repositories import get_repos
    repos = get_repos()
    seeded = repos.findings.list(lambda f: f.project_id == "demo")
    assert all(f.project_id == "demo" for f in seeded)
    assert len(seeded) >= 1


# ---- API integration ----------------------------------------------------


def test_api_dashboard_works_with_sql_backend(sql_env) -> None:
    response = client.get("/api/dashboard/demo")
    assert response.status_code == 200
    body = response.json()
    assert body["project"]["name"] == "Acme FlightOps Demo"
    assert len(body["findings"]) >= 1


def test_creating_project_via_api_persists_to_sql(sql_env) -> None:
    response = client.post(
        "/api/projects",
        json={
            "name": "SQL API project",
            "description": "Created via API",
            "scope_rules": {
                "domains": ["api.sqltest.example"],
                "urls": [], "cidrs": [], "repos": [], "containers": [],
                "blocked_targets": [], "allow_active": False, "allow_lab": False,
                "max_requests_per_second": 2, "timeout_seconds": 900,
            },
            "grantor": "tester",
        },
    )
    assert response.status_code == 201
    project_id = response.json()["id"]

    # Drop singleton; fetch again (simulates restart). Should still be there.
    import app.repositories as r
    r._REPOS = None
    response2 = client.get(f"/api/projects/{project_id}")
    assert response2.status_code == 200
    assert response2.json()["name"] == "SQL API project"

"""Repository layer for Asura.

Two backends behind one interface:

- `InMemoryRepository[T]` (default) — fast, ephemeral, ideal for tests
  and the seeded demo flow.
- `SqlRepository[T]` — backed by SQLAlchemy (SQLite by default, Postgres
  when `DATABASE_URL` is set). Survives backend restarts.

Selection happens in `get_repos()`:
- `ASURA_USE_SQL=1` → SQL backend
- otherwise → in-memory (the existing behavior, preserved verbatim so the
  168 prior tests keep passing without changes)

Templates and auth profiles continue to use their own file-system service
layer; the in-memory repos for those types are populated from disk by the
service. SQL mode does not change that.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

from app.models.schemas import (
    ApiToken,
    Asset,
    AttackPath,
    AuditLog,
    AuthProfile,
    AuthorizedScope,
    Evidence,
    Finding,
    Membership,
    NucleiTemplate,
    Project,
    RemediationTask,
    Report,
    Scan,
    ScanJob,
    ScanSchedule,
    ScannerRun,
    Target,
    User,
    Workspace,
)

from .base import InMemoryRepository

__all__ = ["Repos", "get_repos", "reset_repos", "sql_enabled"]


SQL_ENV_VAR = "ASURA_USE_SQL"


def sql_enabled() -> bool:
    return os.environ.get(SQL_ENV_VAR, "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Repos:
    workspaces: object = field(default_factory=lambda: InMemoryRepository[Workspace]())
    projects: object = field(default_factory=lambda: InMemoryRepository[Project]())
    assets: object = field(default_factory=lambda: InMemoryRepository[Asset]())
    targets: object = field(default_factory=lambda: InMemoryRepository[Target]())
    scopes: object = field(default_factory=lambda: InMemoryRepository[AuthorizedScope]())
    scans: object = field(default_factory=lambda: InMemoryRepository[Scan]())
    runs: object = field(default_factory=lambda: InMemoryRepository[ScannerRun]())
    findings: object = field(default_factory=lambda: InMemoryRepository[Finding]())
    evidence: object = field(default_factory=lambda: InMemoryRepository[Evidence]())
    attack_paths: object = field(default_factory=lambda: InMemoryRepository[AttackPath]())
    remediations: object = field(default_factory=lambda: InMemoryRepository[RemediationTask]())
    audit: object = field(default_factory=lambda: InMemoryRepository[AuditLog]())
    reports: object = field(default_factory=lambda: InMemoryRepository[Report]())
    schedules: object = field(default_factory=lambda: InMemoryRepository[ScanSchedule]())
    jobs: object = field(default_factory=lambda: InMemoryRepository[ScanJob]())
    # Templates + auth profiles always use their service-managed in-memory
    # index (the source of truth is on disk via their own service layer).
    templates: InMemoryRepository[NucleiTemplate] = field(default_factory=lambda: InMemoryRepository[NucleiTemplate]())
    auth_profiles: InMemoryRepository[AuthProfile] = field(default_factory=lambda: InMemoryRepository[AuthProfile]())
    # Auth state — always in-memory for now (a SQL-backed slice will mirror
    # the existing pattern; for the demo flow + first auth pass in-memory
    # is fine and means zero migration churn).
    users: InMemoryRepository[User] = field(default_factory=lambda: InMemoryRepository[User]())
    memberships: InMemoryRepository[Membership] = field(default_factory=lambda: InMemoryRepository[Membership]())
    api_tokens: InMemoryRepository[ApiToken] = field(default_factory=lambda: InMemoryRepository[ApiToken]())


def _build_sql_repos() -> Repos:
    """Materialise a Repos container backed by SqlRepository for every
    persisted entity. Templates + auth profiles remain in-memory."""
    from app.db import init_db
    from app.db.models import (
        AssetRow,
        AttackPathRow,
        AuditLogRow,
        AuthorizedScopeRow,
        EvidenceRow,
        FindingRow,
        ProjectRow,
        RemediationTaskRow,
        ReportRow,
        ScanJobRow,
        ScanScheduleRow,
        ScannerRunRow,
        TargetRow,
        WorkspaceRow,
    )
    from app.db.repository import SqlRepository
    # Ensure tables exist (Alembic will replace this in a follow-up slice).
    init_db()

    return Repos(
        workspaces=SqlRepository(Workspace, WorkspaceRow, {"name": "name", "created_at": "created_at"}),
        projects=SqlRepository(
            Project, ProjectRow,
            {"workspace_id": "workspace_id", "name": "name", "risk_score": "risk_score",
             "is_demo_data": "is_demo_data", "created_at": "created_at"},
        ),
        assets=SqlRepository(Asset, AssetRow, {"project_id": "project_id", "kind": "kind"}),
        targets=SqlRepository(
            Target, TargetRow,
            {"project_id": "project_id", "kind": "kind", "is_demo_data": "is_demo_data"},
        ),
        scopes=SqlRepository(
            AuthorizedScope, AuthorizedScopeRow,
            {"project_id": "project_id", "is_demo_data": "is_demo_data"},
        ),
        # `Scan` is currently an unused-in-flow record; keep it in-memory.
        scans=InMemoryRepository[Scan](),
        runs=SqlRepository(
            ScannerRun, ScannerRunRow,
            {"project_id": "project_id", "scan_id": "scan_id", "scanner": "scanner",
             "mode": "mode", "status": "status", "is_demo_data": "is_demo_data",
             "started_at": "started_at"},
        ),
        findings=SqlRepository(
            Finding, FindingRow,
            {"project_id": "project_id", "scan_id": "scan_id", "scanner": "scanner",
             "severity": "severity", "status": "status", "category": "category",
             "fingerprint_hash": "fingerprint_hash", "is_demo_data": "is_demo_data",
             "created_at": "created_at"},
        ),
        evidence=SqlRepository(
            Evidence, EvidenceRow,
            {"finding_id": "finding_id", "scanner": "scanner",
             "is_demo_data": "is_demo_data", "captured_at": "captured_at"},
        ),
        attack_paths=SqlRepository(
            AttackPath, AttackPathRow,
            {"project_id": "project_id", "is_demo_data": "is_demo_data"},
        ),
        remediations=SqlRepository(
            RemediationTask, RemediationTaskRow,
            {"project_id": "project_id", "priority": "priority", "status": "status",
             "is_demo_data": "is_demo_data"},
        ),
        audit=SqlRepository(
            AuditLog, AuditLogRow,
            {"workspace_id": "workspace_id", "action": "action", "decision": "decision",
             "target": "target", "timestamp": "timestamp"},
        ),
        reports=SqlRepository(
            Report, ReportRow,
            {"project_id": "project_id", "kind": "kind", "is_demo_data": "is_demo_data",
             "generated_at": "generated_at"},
        ),
        schedules=SqlRepository(
            ScanSchedule, ScanScheduleRow,
            {"project_id": "project_id", "enabled": "enabled", "is_demo_data": "is_demo_data"},
        ),
        jobs=SqlRepository(
            ScanJob, ScanJobRow,
            {"project_id": "project_id", "kind": "kind", "status": "status",
             "is_demo_data": "is_demo_data", "created_at": "created_at"},
        ),
    )


_REPOS: Optional[Repos] = None


def get_repos() -> Repos:
    """Return the process-wide repository container, seeded on first access.

    Reads `ASURA_USE_SQL` each time _REPOS is being initialised so tests can
    flip the env and call `reset_repos()` to rebuild.
    """
    global _REPOS
    if _REPOS is None:
        _REPOS = _build_sql_repos() if sql_enabled() else Repos()
        from .seed import seed_repos
        seed_repos(_REPOS)
    return _REPOS


def reset_repos() -> Repos:
    """Reset the global repository state.

    - In-memory mode: discard the container; the next `get_repos()` rebuilds
      and re-seeds.
    - SQL mode: drop + recreate every table, then re-seed.
    """
    global _REPOS
    if sql_enabled():
        from app.db import reset_db_for_tests
        reset_db_for_tests()
    _REPOS = None
    return get_repos()

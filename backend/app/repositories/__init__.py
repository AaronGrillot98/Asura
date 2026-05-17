"""Repository layer for Asura.

Provides a clean abstraction over persistence so routes/services do not import
the in-memory demo store directly. The current implementation is in-memory; a
SQL backend can implement the same Repository protocol later without touching
callers.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from app.models.schemas import (
    Asset,
    AttackPath,
    AuditLog,
    AuthorizedScope,
    Evidence,
    Finding,
    Project,
    RemediationTask,
    Report,
    Scan,
    ScanJob,
    ScanSchedule,
    ScannerRun,
    Target,
    Workspace,
)

from .base import InMemoryRepository

__all__ = ["Repos", "get_repos", "reset_repos"]


@dataclass
class Repos:
    workspaces: InMemoryRepository[Workspace] = field(default_factory=lambda: InMemoryRepository[Workspace]())
    projects: InMemoryRepository[Project] = field(default_factory=lambda: InMemoryRepository[Project]())
    assets: InMemoryRepository[Asset] = field(default_factory=lambda: InMemoryRepository[Asset]())
    targets: InMemoryRepository[Target] = field(default_factory=lambda: InMemoryRepository[Target]())
    scopes: InMemoryRepository[AuthorizedScope] = field(default_factory=lambda: InMemoryRepository[AuthorizedScope]())
    scans: InMemoryRepository[Scan] = field(default_factory=lambda: InMemoryRepository[Scan]())
    runs: InMemoryRepository[ScannerRun] = field(default_factory=lambda: InMemoryRepository[ScannerRun]())
    findings: InMemoryRepository[Finding] = field(default_factory=lambda: InMemoryRepository[Finding]())
    evidence: InMemoryRepository[Evidence] = field(default_factory=lambda: InMemoryRepository[Evidence]())
    attack_paths: InMemoryRepository[AttackPath] = field(default_factory=lambda: InMemoryRepository[AttackPath]())
    remediations: InMemoryRepository[RemediationTask] = field(default_factory=lambda: InMemoryRepository[RemediationTask]())
    audit: InMemoryRepository[AuditLog] = field(default_factory=lambda: InMemoryRepository[AuditLog]())
    reports: InMemoryRepository[Report] = field(default_factory=lambda: InMemoryRepository[Report]())
    schedules: InMemoryRepository[ScanSchedule] = field(default_factory=lambda: InMemoryRepository[ScanSchedule]())
    jobs: InMemoryRepository[ScanJob] = field(default_factory=lambda: InMemoryRepository[ScanJob]())


_REPOS: Optional[Repos] = None


def get_repos() -> Repos:
    """Return the process-wide repository container, seeded on first access."""
    global _REPOS
    if _REPOS is None:
        _REPOS = Repos()
        # Local import to avoid a circular dependency at module load time.
        from .seed import seed_repos

        seed_repos(_REPOS)
    return _REPOS


def reset_repos() -> Repos:
    """Reset the global repository state. Used by tests for isolation."""
    global _REPOS
    _REPOS = None
    return get_repos()

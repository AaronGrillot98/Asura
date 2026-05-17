"""Seed the repository container from the demo data set.

Kept separate from `__init__.py` to avoid import cycles and to make swapping
out the demo seed (or pointing at a SQL backend) a one-line change.
"""
from __future__ import annotations

from app.services import demo_store

from . import Repos


def seed_repos(repos: Repos) -> None:
    """Populate the given Repos container from `app.services.demo_store`."""
    repos.workspaces.add(demo_store.WORKSPACE)
    repos.projects.add(demo_store.PROJECT)
    repos.assets.add_many(demo_store.ASSETS)
    repos.findings.add_many(demo_store.FINDINGS)
    repos.attack_paths.add_many(demo_store.ATTACK_PATHS)
    repos.runs.add_many(demo_store.SCANNER_RUNS)

    # Flatten evidence out of findings into its own repo so the Evidence Vault
    # API can list/inspect them independently.
    for finding in demo_store.FINDINGS:
        for ev in finding.evidence:
            repos.evidence.add(ev)

    # Seed any extra collections the demo_store exposes (added in Phase K).
    for attr, repo in (
        ("TARGETS", repos.targets),
        ("SCOPES", repos.scopes),
        ("REMEDIATIONS", repos.remediations),
        ("SCHEDULES", repos.schedules),
    ):
        items = getattr(demo_store, attr, None)
        if items:
            repo.add_many(items)

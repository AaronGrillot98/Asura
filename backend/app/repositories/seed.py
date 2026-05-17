"""Seed the repository container from the demo data set.

Idempotent so the SQL backend doesn't duplicate seed rows on every
restart — if the demo project already exists, we leave the repo alone.
"""
from __future__ import annotations

from app.services import demo_store

from . import Repos


def seed_repos(repos: Repos) -> None:
    """Populate `repos` from `demo_store` if it isn't seeded yet."""
    # Idempotency check: if the demo project is already in the repo, assume
    # everything else is too. This is the cheapest way to make `init_db` +
    # `seed_repos` safe to call on every startup in SQL mode.
    if repos.projects.get(demo_store.PROJECT.id) is not None:
        return

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

    # Seed any extra collections the demo_store exposes.
    for attr, repo in (
        ("TARGETS", repos.targets),
        ("SCOPES", repos.scopes),
        ("REMEDIATIONS", repos.remediations),
        ("SCHEDULES", repos.schedules),
    ):
        items = getattr(demo_store, attr, None)
        if items:
            repo.add_many(items)

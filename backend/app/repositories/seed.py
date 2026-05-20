"""Seed the repository container from the demo data set.

Idempotent so the SQL backend doesn't duplicate seed rows on every
restart — if the demo project already exists, we leave the repo alone.
"""
from __future__ import annotations

from datetime import datetime, timezone

from app.models.schemas import Membership, Role, User
from app.services import demo_store

from . import Repos


# Default demo credentials so the demo flow keeps working when auth is
# enabled. Password lives in the seed data so anyone running the demo can
# log in immediately; in real deployments the first /api/auth/register
# call creates the founding owner with their own credentials.
DEMO_OWNER_EMAIL = "owner@asura.local"
DEMO_OWNER_PASSWORD = "asura"
DEMO_OWNER_ID = "user-demo-owner"


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

    # Seed the demo owner so `login owner@asura.local / asura` works on a
    # fresh checkout. Import inside the function to avoid a circular ref
    # (security.auth imports from repositories transitively).
    if repos.users.count() == 0:
        from app.security.auth import hash_password

        now = datetime.now(timezone.utc)
        repos.users.add(User(
            id=DEMO_OWNER_ID,
            email=DEMO_OWNER_EMAIL,
            display_name="Demo Owner",
            password_hash=hash_password(DEMO_OWNER_PASSWORD),
            is_active=True,
            created_at=now,
        ))
        repos.memberships.add(Membership(
            id="membership-demo-owner",
            workspace_id=demo_store.WORKSPACE.id,
            user_id=DEMO_OWNER_ID,
            role=Role.owner,
            created_at=now,
        ))

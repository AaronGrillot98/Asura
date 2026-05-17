"""Programmatic Alembic helpers.

Two entry points:

- `apply_migrations()` — run `alembic upgrade head` against the configured
  database. Used by `init_db()` when `ASURA_USE_ALEMBIC=1`, and by the CLI
  script `scripts/migrate.py` for ad-hoc upgrades.
- `current_revision()` — read the recorded revision out of `alembic_version`.
  Returns `None` if the table doesn't exist yet (fresh database).
- `migration_config()` — build an Alembic Config pointing at our
  `alembic.ini`. Reused by tests that want to drive Alembic directly.

We keep the engine factory in `app.db` as the single source of truth: the
migration env imports `database_url()` from there, so all three callers
(`uvicorn`, `pytest`, `alembic`) agree on what URL to talk to.
"""
from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect

from . import database_url, engine


_REPO_ROOT = Path(__file__).resolve().parents[2]
_ALEMBIC_INI = _REPO_ROOT / "alembic.ini"


def migration_config() -> Config:
    """Build an Alembic Config wired to our resolved database URL."""
    cfg = Config(str(_ALEMBIC_INI))
    cfg.set_main_option("script_location", str(_REPO_ROOT / "migrations"))
    cfg.set_main_option("sqlalchemy.url", database_url())
    return cfg


def apply_migrations(revision: str = "head") -> None:
    """Upgrade the database to `revision` (default: head)."""
    command.upgrade(migration_config(), revision)


def current_revision() -> str | None:
    """Return the revision recorded in `alembic_version`, or None if absent."""
    inspector = inspect(engine())
    if not inspector.has_table("alembic_version"):
        return None
    with engine().connect() as conn:
        row = conn.exec_driver_sql("SELECT version_num FROM alembic_version").first()
    return row[0] if row else None

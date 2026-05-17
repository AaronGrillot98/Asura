"""Alembic migration sanity tests.

We don't try to assert column-by-column equality against `Base.metadata`
because the JSON-payload pattern means most schema evolution happens in
Python-side Pydantic models, not in indexed SQL columns. What we DO want
to know is:

1. `alembic upgrade head` against a fresh SQLite file actually runs and
   creates every table our ORM declares.
2. `apply_migrations()` is idempotent — running it twice doesn't error
   and leaves the same set of tables.
3. `current_revision()` reports the head after upgrade.
4. The `init_db()` Alembic path produces the same set of tables as the
   `create_all` fast path — important parity check so the two boot modes
   don't drift.
5. `downgrade base` removes every Asura table cleanly.

Each test uses an isolated per-test SQLite file so they can run in any
order without leaking state.
"""
from __future__ import annotations

import os
from pathlib import Path
from unittest import mock

import pytest
from alembic import command
from sqlalchemy import inspect

from app.db import Base
from app.db import models  # noqa: F401  -- registers tables on Base.metadata
from app.db.migrate import apply_migrations, current_revision, migration_config


EXPECTED_TABLES = {
    "workspaces",
    "projects",
    "assets",
    "targets",
    "authorized_scopes",
    "scanner_runs",
    "findings",
    "evidence",
    "attack_paths",
    "remediation_tasks",
    "audit_logs",
    "reports",
    "scan_schedules",
    "scan_jobs",
}


@pytest.fixture
def isolated_sqlite(tmp_path: Path):
    """Force a fresh SQLite file + engine for each test."""
    db_path = tmp_path / "alembic.test.db"
    env = {k: v for k, v in os.environ.items() if k not in {"ASURA_USE_SQL", "ASURA_DATABASE_URL", "ASURA_USE_ALEMBIC"}}
    env["ASURA_DATABASE_URL"] = f"sqlite:///{db_path.as_posix()}"
    with mock.patch.dict(os.environ, env, clear=True):
        import app.db as db_pkg
        db_pkg._ENGINE = None
        db_pkg._SESSION_FACTORY = None
        yield db_path
        db_pkg._ENGINE = None
        db_pkg._SESSION_FACTORY = None


def _table_names() -> set[str]:
    from app.db import engine
    return set(inspect(engine()).get_table_names())


def test_upgrade_head_creates_every_table(isolated_sqlite) -> None:
    apply_migrations()
    tables = _table_names()
    assert EXPECTED_TABLES.issubset(tables), f"missing: {EXPECTED_TABLES - tables}"
    assert "alembic_version" in tables


def test_upgrade_is_idempotent(isolated_sqlite) -> None:
    apply_migrations()
    rev_first = current_revision()
    apply_migrations()
    rev_second = current_revision()
    assert rev_first == rev_second
    assert EXPECTED_TABLES.issubset(_table_names())


def test_current_revision_reports_head(isolated_sqlite) -> None:
    assert current_revision() is None
    apply_migrations()
    rev = current_revision()
    assert rev == "0001_initial_schema"


def test_create_all_and_alembic_produce_same_tables(tmp_path: Path) -> None:
    """The `init_db()` shortcut and `alembic upgrade head` must agree on
    which tables exist — otherwise the two boot modes diverge silently."""
    create_db = tmp_path / "create.db"
    migrate_db = tmp_path / "migrate.db"

    base_env = {k: v for k, v in os.environ.items() if k not in {"ASURA_USE_SQL", "ASURA_DATABASE_URL", "ASURA_USE_ALEMBIC"}}

    # 1. create_all path
    with mock.patch.dict(os.environ, {**base_env, "ASURA_DATABASE_URL": f"sqlite:///{create_db.as_posix()}"}, clear=True):
        import app.db as db_pkg
        db_pkg._ENGINE = None
        db_pkg._SESSION_FACTORY = None
        from app.db import engine
        Base.metadata.create_all(bind=engine())
        create_tables = set(inspect(engine()).get_table_names())
        db_pkg._ENGINE = None
        db_pkg._SESSION_FACTORY = None

    # 2. alembic path
    with mock.patch.dict(os.environ, {**base_env, "ASURA_DATABASE_URL": f"sqlite:///{migrate_db.as_posix()}"}, clear=True):
        import app.db as db_pkg
        db_pkg._ENGINE = None
        db_pkg._SESSION_FACTORY = None
        apply_migrations()
        from app.db import engine
        migrate_tables = set(inspect(engine()).get_table_names())
        db_pkg._ENGINE = None
        db_pkg._SESSION_FACTORY = None

    # Alembic adds its bookkeeping table; otherwise the two should match.
    assert create_tables == migrate_tables - {"alembic_version"}


def test_downgrade_base_drops_every_table(isolated_sqlite) -> None:
    apply_migrations()
    assert EXPECTED_TABLES.issubset(_table_names())

    command.downgrade(migration_config(), "base")

    remaining = _table_names()
    assert not (EXPECTED_TABLES & remaining), f"leftover tables: {EXPECTED_TABLES & remaining}"

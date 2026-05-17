"""SQLAlchemy plumbing.

- `Base` is the declarative base every ORM model inherits.
- `engine()` and `SessionLocal()` return the process-wide engine + session
  factory. Configured from `DATABASE_URL` (default `sqlite:///./asura.db`).
- `init_db()` creates tables. Used in dev / tests; production should use
  Alembic migrations (added in a follow-up slice).
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker, Session


class Base(DeclarativeBase):
    pass


_ENGINE: Engine | None = None
_SESSION_FACTORY: sessionmaker[Session] | None = None


def database_url() -> str:
    """Resolve the database URL.

    Priority:
      1. ASURA_DATABASE_URL — explicit override for tests
      2. DATABASE_URL — production / docker-compose default
      3. `sqlite:///<repo>/asura.db` — zero-config local
    """
    explicit = os.environ.get("ASURA_DATABASE_URL")
    if explicit:
        return explicit
    docker_url = os.environ.get("DATABASE_URL")
    if docker_url:
        return docker_url
    repo_root = Path(__file__).resolve().parents[3]
    return f"sqlite:///{(repo_root / 'asura.db').as_posix()}"


def engine() -> Engine:
    global _ENGINE
    if _ENGINE is None:
        url = database_url()
        # SQLite needs `check_same_thread=False` for the FastAPI thread pool +
        # background workers to share a connection.
        connect_args: dict[str, object] = {}
        if url.startswith("sqlite"):
            connect_args["check_same_thread"] = False
        _ENGINE = create_engine(url, future=True, pool_pre_ping=True, connect_args=connect_args)
    return _ENGINE


def session_factory() -> sessionmaker[Session]:
    global _SESSION_FACTORY
    if _SESSION_FACTORY is None:
        _SESSION_FACTORY = sessionmaker(
            engine(),
            autoflush=False,
            autocommit=False,
            expire_on_commit=False,
            future=True,
        )
    return _SESSION_FACTORY


def session_scope() -> Iterator[Session]:
    """Context manager helper used by repositories. Commits on success,
    rolls back on exception, always closes."""
    factory = session_factory()
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db() -> None:
    """Create every registered table. Idempotent."""
    # Import models so they register with the declarative metadata before
    # create_all walks the registry.
    from . import models  # noqa: F401

    Base.metadata.create_all(bind=engine())


def reset_db_for_tests() -> None:
    """Drop every table then recreate. Tests-only — fast SQLite path."""
    from . import models  # noqa: F401

    Base.metadata.drop_all(bind=engine())
    Base.metadata.create_all(bind=engine())

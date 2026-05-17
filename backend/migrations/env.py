"""Alembic environment for Asura.

The URL is resolved via `app.db.database_url()` so the same precedence rules
apply as at app boot: `ASURA_DATABASE_URL` > `DATABASE_URL` > local SQLite.

Importing `app.db.models` registers every ORM table on `Base.metadata`, which
is what `target_metadata` points at for autogenerate diffs.
"""
from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from app.db import Base, database_url
from app.db import models  # noqa: F401  -- registers tables on Base.metadata


config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Inject the resolved URL into the alembic config so engine_from_config picks
# it up regardless of how `alembic` was invoked.
config.set_main_option("sqlalchemy.url", database_url())

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode — emit SQL to stdout."""
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        render_as_batch=True,  # required for SQLite ALTERs
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations with a live Engine connection."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            render_as_batch=connection.dialect.name == "sqlite",
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

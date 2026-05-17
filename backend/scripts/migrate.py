"""Run Asura's database migrations.

Usage::

    py scripts/migrate.py            # upgrade to head
    py scripts/migrate.py downgrade  # downgrade one revision
    py scripts/migrate.py current    # print recorded revision

This is a thin wrapper around `alembic` that uses the same DB URL the app
boots with, so you never have to re-export `DATABASE_URL` to a separate
session.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Allow running this file directly (`py scripts/migrate.py`) without `pip
# install -e .` by putting the backend root on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from alembic import command  # noqa: E402

from app.db.migrate import apply_migrations, current_revision, migration_config  # noqa: E402


def main(argv: list[str]) -> int:
    cmd = argv[1] if len(argv) > 1 else "upgrade"

    if cmd == "upgrade":
        apply_migrations()
        print(f"upgraded to {current_revision()}")
        return 0
    if cmd == "downgrade":
        command.downgrade(migration_config(), "-1")
        print(f"downgraded to {current_revision()}")
        return 0
    if cmd == "current":
        print(current_revision() or "<none>")
        return 0
    if cmd == "history":
        command.history(migration_config())
        return 0

    print(f"unknown command: {cmd}", file=sys.stderr)
    print("usage: migrate.py [upgrade|downgrade|current|history]", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))

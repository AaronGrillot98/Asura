# Database migrations

Asura uses [Alembic](https://alembic.sqlalchemy.org/) to evolve the
persistence schema. The migration env is wired to the same engine
factory the app boots with, so the resolved database URL is identical
across `uvicorn`, `pytest`, and `alembic` invocations.

## Boot modes

`init_db()` has two paths, picked from an env var:

| `ASURA_USE_ALEMBIC` | Behavior |
|---------------------|----------|
| unset (default)     | `Base.metadata.create_all()` — fast, zero-config, used by tests + local SQLite dev |
| `1`                 | `alembic upgrade head` — used in production / docker-compose so `alembic_version` is populated and the schema is migrated through versioned revisions |

The two paths are tested for parity in [test_migrations.py](../backend/tests/test_migrations.py):
both must produce the same set of tables (Alembic adds its own
`alembic_version` bookkeeping table, otherwise they match).

## Files

```
backend/
  alembic.ini                         # config; URL is left blank — env.py fills it
  migrations/
    env.py                            # imports app.db.database_url() — single source of truth
    script.py.mako                    # template for new revisions
    versions/
      0001_initial_schema.py          # creates every indexed-column + JSON-payload table
  app/db/migrate.py                   # apply_migrations() / current_revision() / migration_config()
  scripts/migrate.py                  # CLI wrapper around the helpers above
```

## Day-to-day commands

```bash
# Upgrade to head (in-app or out-of-process — both use the same engine factory)
py scripts/migrate.py upgrade

# Check the recorded revision
py scripts/migrate.py current

# Downgrade one revision (testing a schema change before it lands)
py scripts/migrate.py downgrade

# Show the revision history
py scripts/migrate.py history
```

Or invoke Alembic directly — the `alembic.ini` resolves `script_location`
relative to the backend folder:

```bash
cd backend
alembic upgrade head
alembic current
alembic history
```

## Authoring a new revision

When you add an indexed column to an ORM model in `app/db/models.py`:

1. Auto-generate the skeleton (Alembic compares `Base.metadata` against
   the live database and emits a diff):

   ```bash
   cd backend
   alembic revision --autogenerate -m "add finding.affected_url index"
   ```

2. Inspect the generated file under `migrations/versions/`. The
   indexed-column + JSON-payload pattern means most new fields land in
   the JSON `payload` column and **do NOT** need a migration. Only
   migrate when you start indexing on the new field.

3. For SQLite-safe `ALTER`s, `env.py` is already configured with
   `render_as_batch=True`. New revisions inherit that behavior
   automatically.

4. Test the upgrade + downgrade against a throwaway SQLite database
   before opening a PR:

   ```bash
   py scripts/migrate.py upgrade
   py scripts/migrate.py downgrade
   ```

## Postgres notes

Alembic and SQLAlchemy use the same `DATABASE_URL` precedence as the
app:

1. `ASURA_DATABASE_URL` — explicit override (used by tests).
2. `DATABASE_URL` — production / docker-compose default.
3. `sqlite:///./asura.db` — zero-config local.

For Postgres, set `DATABASE_URL=postgresql+psycopg://asura:asura@db:5432/asura`
and run `py scripts/migrate.py upgrade`. The migration env disables
batch mode automatically on non-SQLite dialects, so the generated
revisions use plain `ALTER TABLE` statements.

## What the current revision captures

`0001_initial_schema` creates all 14 persisted tables with the indexed
columns Asura actually filters on (project_id, severity, status,
fingerprint_hash, is_demo_data, timestamps, …) plus a JSON `payload`
column that round-trips the full Pydantic dump.

Subsequent revisions should evolve indexes (add / drop / rename) rather
than the payload shape — new optional Pydantic fields don't need a
migration because they live inside the JSON column.

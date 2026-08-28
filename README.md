# EvoRuntime

A governed self-improvement runtime and control plane for software-engineering
agents: an evaluation and governance substrate that lets untrusted optimization
strategies propose bounded artifact improvements while a trusted authority
plane verifies, promotes, and can atomically roll back every change.

This repository is the Phase 0 (evaluation foundation) build: the trace
pipeline, agent adapter SDK, sealed dataset partitions, and matched-resource
evaluation harness every later improvement campaign stands on. See the
EvoRuntime PRD and the Phase 0 spec for the full design.

## Package layout

```
src/evoruntime/
  core/    shared schemas and types (event envelope, lineage records — D2/D4)
  server/  the FastAPI evaluation-plane service
  sdk/     the agent adapter SDK (buffered trace emission — D3)
  eval/    the evaluation harness (experiment arms, paired statistics — D6)
  db/      SQLAlchemy models, sessions, and Alembic migrations
```

Phase 0 (this PR) ships the skeleton for every subpackage above: a FastAPI
app with a liveness probe, SQLAlchemy engine/session plumbing, and an empty
Alembic baseline migration. Domain tables and business logic land in later
deliverables (D2–D8), tracked against the Phase 0 spec.

## Requirements

- Python 3.12
- [uv](https://docs.astral.sh/uv/) for dependency management
- A PostgreSQL instance for running the app or the migration tests

## Setup

```bash
uv sync
cp .env.example .env   # adjust EVORUNTIME_DATABASE_URL if needed
```

## Running the service

```bash
uv run evoruntime-server
# or: uv run python -m evoruntime.server
curl localhost:8000/healthz
```

## Database migrations

```bash
uv run alembic upgrade head
uv run alembic downgrade base
```

Alembic resolves the connection string from `EVORUNTIME_DATABASE_URL`
(`evoruntime.db.settings.DatabaseSettings`) unless a URL is set explicitly on
the `Config` object passed in — see `src/evoruntime/db/migrations/env.py`.

## Development gates

The same three gates run in CI on every PR:

```bash
uv run ruff check .      # lint
uv run ruff format .     # format
uv run mypy               # types (strict)
uv run pytest              # tests
```

`tests/test_migrations.py` runs the Alembic upgrade/downgrade round-trip
against a real PostgreSQL. It skips locally if no database is reachable at
`EVORUNTIME_TEST_DATABASE_URL` (default:
`postgresql+psycopg://postgres:postgres@localhost:5432/evoruntime_test`); CI
always provides a Postgres service, so the check is never skipped there.

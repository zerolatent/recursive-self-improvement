"""Shared fixtures for tests that need a real PostgreSQL database.

Mirrors `test_migrations.py`'s reachability check: skip (not fail) when no
PostgreSQL is reachable, so `pytest` stays usable for quick local iteration
without a database; CI always provides a `postgres` service.
"""

from __future__ import annotations

import base64
import os
from collections.abc import Generator
from pathlib import Path

import psycopg
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

REPO_ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS_DIR = REPO_ROOT / "src" / "evoruntime" / "db" / "migrations"

DEFAULT_TEST_DATABASE_URL = "postgresql+psycopg://postgres:postgres@localhost:5432/evoruntime_test"


def _test_database_url() -> str:
    return os.environ.get("EVORUNTIME_TEST_DATABASE_URL", DEFAULT_TEST_DATABASE_URL)


def _as_psycopg_dsn(sqlalchemy_url: str) -> str:
    """Strip the SQLAlchemy `+psycopg` dialect suffix for a plain psycopg connect."""
    return sqlalchemy_url.replace("postgresql+psycopg://", "postgresql://")


@pytest.fixture(scope="session")
def database_url() -> str:
    url = _test_database_url()
    try:
        with psycopg.connect(_as_psycopg_dsn(url), connect_timeout=2):
            pass
    except psycopg.OperationalError as exc:
        pytest.skip(f"no reachable PostgreSQL at {url}: {exc}")
    return url


@pytest.fixture
def db_session(database_url: str) -> Generator[Session, None, None]:
    """A SQLAlchemy session against a database freshly migrated to head.

    Re-runs `alembic upgrade head` before every test (a no-op when already
    at head) rather than migrating once per session: `test_migrations.py`
    exercises `upgrade head` -> `downgrade base` against this same shared
    database mid-suite, so a one-time session migration would leave later
    tests running against a downgraded, table-less schema.
    """
    config = Config(str(REPO_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "head")

    engine = create_engine(database_url)
    with engine.begin() as conn:
        conn.execute(
            text(
                "TRUNCATE TABLE lineage_edges, lineage_nodes, payloads, "
                "tombstones, derived_data_records RESTART IDENTITY CASCADE"
            )
        )
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = session_factory()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture(autouse=True)
def _payload_master_key(monkeypatch: pytest.MonkeyPatch) -> Generator[None, None, None]:
    """A deterministic test master key, set for every test so
    `TenantKeyProvider` never has to fall back to a real secrets store.
    Uses `monkeypatch` (not a raw `os.environ` mutation) so it's undone
    automatically, and clears `get_lineage_settings`'s cache so each test
    re-reads the environment rather than reusing a settings singleton
    built by a previous test.
    """
    from evoruntime.lineage.settings import get_lineage_settings

    monkeypatch.setenv("EVORUNTIME_PAYLOAD_MASTER_KEY", base64.b64encode(b"0" * 32).decode())
    get_lineage_settings.cache_clear()
    yield
    get_lineage_settings.cache_clear()

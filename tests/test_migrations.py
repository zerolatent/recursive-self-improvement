"""Validates the Alembic baseline migration against a real PostgreSQL.

Runs `alembic upgrade head` then `alembic downgrade base` — the acceptance
check for deliverable D1. Skips (rather than fails) when no PostgreSQL is
reachable, so `pytest` stays usable without a database for quick local
iteration; CI always provides a `postgres` service so this test is not
skipped there.
"""

from __future__ import annotations

import os
from pathlib import Path

import psycopg
import pytest
from alembic import command
from alembic.config import Config

REPO_ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS_DIR = REPO_ROOT / "src" / "evoruntime" / "db" / "migrations"

DEFAULT_TEST_DATABASE_URL = "postgresql+psycopg://postgres:postgres@localhost:5432/evoruntime_test"


def _test_database_url() -> str:
    return os.environ.get("EVORUNTIME_TEST_DATABASE_URL", DEFAULT_TEST_DATABASE_URL)


def _as_psycopg_dsn(sqlalchemy_url: str) -> str:
    """Strip the SQLAlchemy `+psycopg` dialect suffix for a plain psycopg connect."""
    return sqlalchemy_url.replace("postgresql+psycopg://", "postgresql://")


@pytest.fixture
def alembic_config() -> Config:
    database_url = _test_database_url()
    try:
        with psycopg.connect(_as_psycopg_dsn(database_url), connect_timeout=2):
            pass
    except psycopg.OperationalError as exc:
        pytest.skip(f"no reachable PostgreSQL at {database_url}: {exc}")

    config = Config(str(REPO_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def test_upgrade_head_then_downgrade_base(alembic_config: Config) -> None:
    command.upgrade(alembic_config, "head")
    command.downgrade(alembic_config, "base")

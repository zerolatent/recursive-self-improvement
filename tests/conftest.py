"""Shared fixtures for tests that need a real PostgreSQL database.

Two properties are load-bearing here, both learned the hard way:

*Schema comes from the real Alembic migrations*, never
`Base.metadata.create_all`. The lineage store's append-only guards and the
holdout ledger's are SQL triggers that only the migrations install; a suite
that created tables directly would prove the tables exist while proving
nothing about the invariants that matter.

*Migration to head is per-test, not per-session.* `test_migrations.py`
runs `upgrade head` -> `downgrade base` against this same shared database
mid-suite, so any fixture that migrated once per session would hand later
tests a table-less schema depending on collection order.

Isolation differs per domain by necessity: lineage tests truncate their
tables, while dataset tests cannot (ledger rows are undeletable by
design, which is the point) and instead scope every test to a fresh
`tenant_id` and assert only on their own rows. Trace-ingest tests (D2)
follow the same pattern: each test picks its own tenant_id and asserts
only on rows it wrote.
"""

from __future__ import annotations

import base64
import os
import uuid
from collections.abc import Callable, Generator, Iterator
from decimal import Decimal
from pathlib import Path

import psycopg
import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from evoruntime.core.principal import Principal
from evoruntime.datasets.partitions import PartitionKind
from evoruntime.datasets.schemas import IssuedHoldoutHandle, PartitionSummary
from evoruntime.datasets.service import DatasetService, HoldoutService
from evoruntime.db.base import build_session_factory
from evoruntime.security.identities import WorkloadIdentity, WorkloadRole
from evoruntime.server.app import create_app
from evoruntime.server.dependencies import get_session_factory

REPO_ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS_DIR = REPO_ROOT / "src" / "evoruntime" / "db" / "migrations"

DEFAULT_TEST_DATABASE_URL = "postgresql+psycopg://postgres:postgres@localhost:5432/evoruntime_test"

AuthHeaders = Callable[[Principal], dict[str, str]]
"""Signature of the `auth_headers` fixture, for annotating test parameters."""


def _test_database_url() -> str:
    return os.environ.get("EVORUNTIME_TEST_DATABASE_URL", DEFAULT_TEST_DATABASE_URL)


def _as_psycopg_dsn(sqlalchemy_url: str) -> str:
    """Strip the SQLAlchemy `+psycopg` dialect suffix for a plain psycopg connect."""
    return sqlalchemy_url.replace("postgresql+psycopg://", "postgresql://")


def _upgrade_to_head(database_url: str) -> None:
    """Run `alembic upgrade head` against the test database (no-op at head)."""
    config = Config(str(REPO_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "head")


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
    """A SQLAlchemy session against a database freshly migrated to head."""
    _upgrade_to_head(database_url)

    engine = create_engine(database_url)
    with engine.begin() as conn:
        conn.execute(
            text(
                "TRUNCATE TABLE lineage_edges, lineage_nodes, payloads, "
                "tombstones, derived_data_records, memory_entries RESTART IDENTITY CASCADE"
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


@pytest.fixture
def session_factory(database_url: str) -> Iterator[sessionmaker[Session]]:
    """Session factory for dataset and trace-ingest tests, against a database
    migrated to head.

    Function-scoped for the same reason `db_session` is: a session-scoped
    factory would survive `test_migrations.py`'s downgrade-to-base and hand
    every subsequent test a schema with no tables.
    """
    _upgrade_to_head(database_url)
    engine = create_engine(database_url)
    try:
        yield build_session_factory(engine)
    finally:
        engine.dispose()


@pytest.fixture
def tenant_id() -> str:
    """A tenant unique to this test, so rows never collide across tests."""
    return f"tnt_{uuid.uuid4().hex[:12]}"


def _principal(role: WorkloadRole, subject: str, tenant_id: str) -> Principal:
    return Principal(identity=WorkloadIdentity(role=role, subject=subject), tenant_id=tenant_id)


@pytest.fixture
def evaluator(tenant_id: str) -> Principal:
    """An evaluation-plane caller inside the trust boundary."""
    return _principal(WorkloadRole.EVALUATOR, "svc_evaluator_1", tenant_id)


@pytest.fixture
def candidate_runner(tenant_id: str) -> Principal:
    """A candidate-execution caller: the identity that must never read holdout content."""
    return _principal(WorkloadRole.CANDIDATE_RUNNER, "svc_candidate_1", tenant_id)


@pytest.fixture
def foreign_evaluator() -> Principal:
    """An evaluator for a *different* tenant — right role, wrong data."""
    return _principal(WorkloadRole.EVALUATOR, "svc_evaluator_x", f"tnt_{uuid.uuid4().hex[:12]}")


@pytest.fixture
def dataset_service(session_factory: sessionmaker[Session]) -> DatasetService:
    """Partition service under test."""
    return DatasetService(session_factory)


@pytest.fixture
def holdout_service(session_factory: sessionmaker[Session]) -> HoldoutService:
    """Sealed-holdout service under test."""
    return HoldoutService(session_factory)


@pytest.fixture
def sealed_partition(dataset_service: DatasetService, evaluator: Principal) -> PartitionSummary:
    """A holdout partition owned by the evaluator's tenant."""
    return dataset_service.create_partition(
        evaluator,
        dataset_id="ds_repo_repair_v1",
        name="repo-repair-holdout",
        kind=PartitionKind.HOLDOUT,
        owner="eval-team",
        content_locator="object://evaluation-plane/holdout/repo-repair-v1",
        content_digest="sha256:" + "a" * 64,
        item_count=40,
    )


@pytest.fixture
def issued_handle(
    holdout_service: HoldoutService, evaluator: Principal, sealed_partition: PartitionSummary
) -> IssuedHoldoutHandle:
    """A live handle with room for exactly four resolutions."""
    return holdout_service.issue_handle(
        evaluator,
        partition_id=sealed_partition.id,
        owner="eval-team",
        alpha_budget_total=Decimal("0.04"),
        alpha_per_query=Decimal("0.01"),
        freshness_window_days=30,
        rotation_plan="rotate-quarterly",
        contamination_audit={"source": "github-issues-2026-q2", "contaminated": False},
    )


@pytest.fixture
def client(session_factory: sessionmaker[Session]) -> Iterator[TestClient]:
    """API client wired to the test database."""
    app = create_app()
    app.dependency_overrides[get_session_factory] = lambda: session_factory
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _auth_headers(principal: Principal) -> dict[str, str]:
    """Workload-identity headers the API's dependency layer expects."""
    return {
        "x-evoruntime-identity": principal.identity_id,
        "x-evoruntime-role": principal.role.value,
        "x-evoruntime-tenant": principal.tenant_id,
    }


@pytest.fixture
def auth_headers() -> AuthHeaders:
    """Build workload-identity headers for a principal.

    Exposed as a fixture rather than an importable helper so test modules
    never import from `conftest` — that import only resolves under
    pytest's rootdir path insertion and breaks under other runners.
    """
    return _auth_headers

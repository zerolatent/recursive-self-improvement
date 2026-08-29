"""H8 concurrent-candidate load harness (§17.3 row 9) — CI profile.

Drives 8 concurrent candidate executions (4 worker processes × 2 threads)
through a *real* evaluation-plane HTTP server (uvicorn subprocess of
``evoruntime.server.app:create_app`` against real Postgres), each emitting
via the adapter SDK's production ingest path, and measures the row-9
thresholds at CI scale:

- ingest p99 ≤2s (client-side, per batch, over every batch in the run);
- loss ≤0.01% (emitted vs delivered, including the recovery kill);
- single-worker recovery: SIGKILL one worker mid-run, respawn it with the
  same journals, and measure wall-clock back to first delivery.

The full soak (1,000 concurrent executions × 10M events, 24h horizon,
recovery deadline 10 minutes) uses the same runner with
``LOAD_SOAK_PROFILE`` — runbook and recorded numbers in
docs/phase4-verification.md.
"""

from __future__ import annotations

import os
from collections.abc import Generator
from pathlib import Path

import psycopg
import pytest
from sqlalchemy import Engine

from evoruntime.harness.load import run_load_probe
from evoruntime.harness.profiles import LOAD_CI_PROFILE
from tests.conftest import DEFAULT_TEST_DATABASE_URL, _upgrade_to_head


def _database_url() -> str:
    return os.environ.get("EVORUNTIME_TEST_DATABASE_URL", DEFAULT_TEST_DATABASE_URL)


@pytest.fixture
def harness_db() -> Generator[Engine, None, None]:
    """Real Postgres, migrated to head, for the server and worker subprocesses."""
    from evoruntime.db.base import build_engine

    database_url = _database_url()
    try:
        with psycopg.connect(
            database_url.replace("postgresql+psycopg://", "postgresql://"), connect_timeout=2
        ):
            pass
    except psycopg.OperationalError as exc:
        pytest.skip(f"no reachable PostgreSQL at {database_url}: {exc}")

    _upgrade_to_head(database_url)
    engine = build_engine(database_url)
    try:
        yield engine
    finally:
        engine.dispose()


def test_concurrent_candidates_meet_p99_loss_and_recovery_thresholds(
    harness_db: Engine, tmp_path: Path
) -> None:
    result = run_load_probe(
        database_url=_database_url(),
        profile=LOAD_CI_PROFILE,
        workdir=tmp_path,
    )

    assert result.concurrent_executions == LOAD_CI_PROFILE.concurrent_executions
    # Every emitted event must have been delivered — the adapter journals
    # before send and replays on respawn, so even the SIGKILLed worker's
    # events arrive.
    assert result.emitted_events == LOAD_CI_PROFILE.total_sdk_events
    # Replay may deliver a few events journaled during the progress
    # reporter's lag window, so delivered can slightly exceed the fsync'd
    # emitted count — but it may never fall short of it.
    assert result.delivered_events >= result.emitted_events
    assert result.lost_events == 0
    assert result.loss_rate <= LOAD_CI_PROFILE.max_loss_rate
    # §17.3 row 9: ingest p99 ≤2s at the ingest boundary.
    assert result.ingest_p99_s <= LOAD_CI_PROFILE.max_ingest_p99_s
    # The recovery probe must have fired and recovered inside the deadline.
    assert result.recovery_s is not None
    assert result.recovery_s <= LOAD_CI_PROFILE.recovery_deadline_s
    assert result.within_thresholds(LOAD_CI_PROFILE)

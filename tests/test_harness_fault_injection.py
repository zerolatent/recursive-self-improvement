"""H8 fault-injection loss-rate runner (§17.3 row 1) — CI profile.

Extends the D2 single-writer SIGKILL test (``tests/test_fault_injection.py``)
into the sustained N-writer × M-event runner: 4 writers × 2,500 events
(10k total — the D2 fixture size) through the real per-event-commit ingest
path, with the runner SIGKILLing each writer twice mid-run and resuming it
with the same fixture. The measured claim is the row-1 threshold itself:
delivered/expected loss ≤0.01%, with every tenant's hash chain intact.

The full 10M-event soak (8 writers × 1.25M events) uses the same runner
with ``FAULT_INJECTION_SOAK_PROFILE`` — see docs/phase4-verification.md
for the runbook and recorded numbers.
"""

from __future__ import annotations

import os
from collections.abc import Generator
from pathlib import Path

import psycopg
import pytest
from sqlalchemy import Engine

from evoruntime.harness.fault_injection import run_loss_rate_probe
from evoruntime.harness.profiles import FAULT_INJECTION_CI_PROFILE
from tests.conftest import DEFAULT_TEST_DATABASE_URL, _upgrade_to_head

MAX_LOSS_RATE = 0.0001  # §17.3 row 1: ≤0.01%


def _database_url() -> str:
    return os.environ.get("EVORUNTIME_TEST_DATABASE_URL", DEFAULT_TEST_DATABASE_URL)


@pytest.fixture
def harness_db() -> Generator[Engine, None, None]:
    """Real Postgres, migrated to head — same convention as the D2 test.

    The runner's writers are subprocesses with their own connections, so
    schema setup must complete first; teardown deletes only this run's
    rows (the runner already cleans its own tenants, this is the safety
    net for a failed run).
    """
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


def test_sustained_writers_with_periodic_kills_meet_loss_slo(
    harness_db: Engine, tmp_path: Path
) -> None:
    result = run_loss_rate_probe(
        database_url=_database_url(),
        profile=FAULT_INJECTION_CI_PROFILE,
        workdir=tmp_path,
    )

    assert result.writers == FAULT_INJECTION_CI_PROFILE.writers
    assert result.expected_events == FAULT_INJECTION_CI_PROFILE.total_events
    # The kill schedule must actually have fired — a run with zero kills
    # proves nothing about resume behavior.
    assert result.kills_executed == (
        FAULT_INJECTION_CI_PROFILE.writers * FAULT_INJECTION_CI_PROFILE.max_kills_per_writer
    )
    assert result.delivered_events == result.expected_events
    assert result.lost_events == 0
    assert result.loss_rate <= MAX_LOSS_RATE
    assert result.within_slo(MAX_LOSS_RATE)
    # The tamper-evident chain must survive kills + resumes on every tenant.
    assert result.chain_valid

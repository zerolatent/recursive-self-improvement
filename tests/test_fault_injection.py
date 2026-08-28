"""Fault injection (spec D2 acceptance): SIGKILL the ingest writer mid-batch
on a 10k-event fixture and prove event loss stays within the ≤0.01% bound.

Two properties, both required:

1. **Immediate, mid-crash bound.** `ingest_envelope` commits one event per
   transaction, so a kill can strand at most the single event that was
   in-flight when the signal landed — never more. Checked right after the
   kill, before anything resumes.
2. **Eventual loss after resume.** A restarted writer given the same
   fixture is idempotent (duplicates are skipped, not re-inserted) and
   completes the remaining events, so total loss across the full 10k-event
   delivery is exactly 0 — comfortably inside the ≤0.01% (≤1 event) SLO.

Runs the writer as a real subprocess (never imported) so `SIGKILL` bypasses
all Python-level cleanup, exactly like an operator killing a crashed
process; only what Postgres itself durably committed can survive.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from collections.abc import Generator
from pathlib import Path

import psycopg
import pytest
from sqlalchemy import Engine, delete
from sqlalchemy.orm import sessionmaker

from evoruntime.db.chain_verification import verify_chain
from evoruntime.db.models.events import Event
from tests.conftest import DEFAULT_TEST_DATABASE_URL, _upgrade_to_head
from tests.support.factories import make_raw_batch

FAULT_INJECTION_TENANT_ID = "tnt_faultinjection"

FIXTURE_SIZE = 10_000
MAX_LOSS_FRACTION = 0.0001  # spec D2: ≤0.01%
WRITER_SCRIPT = Path(__file__).parent / "support" / "fault_injection_writer.py"

# Kill once the writer has durably committed at least this many events —
# comfortably mid-batch, not a race against process startup.
KILL_AFTER_AT_LEAST = 1_000
POLL_INTERVAL_S = 0.02
POLL_TIMEOUT_S = 60.0


def _database_url() -> str:
    return os.environ.get("EVORUNTIME_TEST_DATABASE_URL", DEFAULT_TEST_DATABASE_URL)


def _write_fixture(path: Path, tenant_id: str) -> None:
    with path.open("w", encoding="utf-8") as f:
        for raw in make_raw_batch(FIXTURE_SIZE, tenant_id=tenant_id):
            f.write(json.dumps(raw))
            f.write("\n")


def _read_progress_count(progress_path: Path) -> int:
    """Last (largest) processed-count the writer recorded, or 0 if none yet."""
    if not progress_path.exists():
        return 0
    lines = [line for line in progress_path.read_text(encoding="utf-8").splitlines() if line]
    return int(lines[-1]) if lines else 0


def _run_writer(
    *, database_url: str, fixture_path: Path, progress_path: Path
) -> subprocess.Popen[bytes]:
    return subprocess.Popen(  # noqa: S603 - fixed argv, no shell, test-only
        [
            sys.executable,
            str(WRITER_SCRIPT),
            f"--database-url={database_url}",
            f"--fixture-path={fixture_path}",
            f"--progress-path={progress_path}",
        ]
    )


def _wait_for_progress_at_least(progress_path: Path, threshold: int) -> int:
    deadline = time.monotonic() + POLL_TIMEOUT_S
    while time.monotonic() < deadline:
        count = _read_progress_count(progress_path)
        if count >= threshold:
            return count
        time.sleep(POLL_INTERVAL_S)
    raise TimeoutError(
        f"writer never reached {threshold} committed events within {POLL_TIMEOUT_S}s"
    )


@pytest.fixture
def fault_injection_db() -> Generator[Engine, None, None]:
    """Real Postgres, migrated to head via Alembic — reused across this module's tests.

    Must go through the real migrations, not `Base.metadata.create_all`/
    `drop_all` (see `tests/conftest.py`'s module docstring): this table is
    shared with every other deliverable's models, so a raw `drop_all` here
    would wipe D4/D5/D7's tables too, while leaving `alembic_version`
    stamped at head — silently turning every later test's idempotent
    upgrade-to-head into a no-op against a tableless database. Teardown
    only deletes this fixture's own rows, scoped by tenant_id, the same
    isolation convention every other D2 test follows.

    Separate from the shared `db_session`/`session_factory` fixtures: the
    writer runs as a subprocess against the same database over its own
    connection, so table setup must happen before that subprocess starts
    and must not be torn down by an unrelated fixture mid-test.
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
        with engine.begin() as conn:
            conn.execute(delete(Event).where(Event.tenant_id == FAULT_INJECTION_TENANT_ID))
        engine.dispose()


def test_sigkill_mid_batch_loses_at_most_one_event_and_resume_loses_none(
    fault_injection_db: Engine, tmp_path: Path
) -> None:
    database_url = _database_url()
    tenant_id = FAULT_INJECTION_TENANT_ID
    fixture_path = tmp_path / "fixture.jsonl"
    progress_path = tmp_path / "progress.log"
    _write_fixture(fixture_path, tenant_id)

    # --- Run 1: kill mid-batch. ---
    proc = _run_writer(
        database_url=database_url, fixture_path=fixture_path, progress_path=progress_path
    )
    try:
        progress_at_kill = _wait_for_progress_at_least(progress_path, KILL_AFTER_AT_LEAST)
        os.kill(proc.pid, signal.SIGKILL)
        proc.wait(timeout=10)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)

    assert progress_at_kill < FIXTURE_SIZE, (
        "writer finished before it could be killed mid-batch — not a valid fault injection run"
    )

    session_factory = sessionmaker(bind=fault_injection_db, autoflush=False, expire_on_commit=False)
    with session_factory() as session:
        result_after_kill = verify_chain(session, tenant_id)

    # The chain itself must never be corrupted by the crash...
    assert result_after_kill.valid
    # ...and the DB can be at most one event ahead of the writer's last
    # fsync'd progress record (commit-then-record-progress ordering means a
    # kill can land between the two) — never behind it, never more than one.
    assert progress_at_kill <= result_after_kill.event_count <= progress_at_kill + 1

    # --- Run 2: resume with the same fixture; duplicates are skipped. ---
    resume_progress_path = tmp_path / "progress_resume.log"
    resume_proc = _run_writer(
        database_url=database_url, fixture_path=fixture_path, progress_path=resume_progress_path
    )
    exit_code = resume_proc.wait(timeout=120)
    assert exit_code == 0

    with session_factory() as session:
        result_after_resume = verify_chain(session, tenant_id)

    assert result_after_resume.valid
    assert result_after_resume.violations == ()

    lost = FIXTURE_SIZE - result_after_resume.event_count
    assert lost == 0
    assert lost / FIXTURE_SIZE <= MAX_LOSS_FRACTION

"""Crash-flush conformance: SIGKILL an emitting agent, count what survived.

Spec D3 / PRD §17.3: a SIGKILL mid-stream may lose at most 100 buffered
events or 1s of events, whichever is smaller. This is tested against a real
OS process death — `SIGKILL` cannot be caught, so no shutdown hook, `atexit`
handler, or `finally` block runs. Simulating the crash in-process would test
the simulation, not the guarantee.

The child emits at a paced rate, so "1s of events" is a known quantity and
the binding bound is the 100-event one (see `LOSS_BOUND_EVENTS`).
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from evoruntime.sdk.journal import RECORD_KIND_EVENT, recover
from tests.sdk.crash_child import read_counter
from tests.sdk.support import RecordingTransport, make_adapter

CHILD = Path(__file__).parent / "crash_child.py"

EMIT_RATE_HZ = 1_000.0
"""Paced so one second of events (1000) is far above the 100-event bound,
making the count the binding constraint — the harder half of "whichever
smaller"."""

LOSS_BOUND_EVENTS = 100
MIN_EMITTED_BEFORE_KILL = 600
STARTUP_TIMEOUT_S = 30.0


def count_journaled_events(path: Path) -> int:
    """How many events survived, acknowledged or not.

    Counts every event record in the file rather than `recover()`'s replay
    set: an acked record was already delivered to ingest, so it is equally
    "not lost" — filtering it out would overstate loss.
    """
    if not path.exists():
        return 0
    seen: set[str] = set()
    with path.open("rb") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                record = json.loads(stripped)
            except json.JSONDecodeError:
                continue  # the torn tail record, by construction
            if record.get("k") == RECORD_KIND_EVENT:
                seen.add(record["event"]["event_id"])
    return len(seen)


@pytest.fixture
def crashed_agent(tmp_path: Path) -> tuple[Path, int]:
    """Run an emitting agent, SIGKILL it mid-stream, return (journal, emitted)."""
    journal_path = tmp_path / "events.journal"
    counter_path = tmp_path / "emitted.count"

    process = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
        [sys.executable, str(CHILD), str(journal_path), str(counter_path), str(EMIT_RATE_HZ)],
    )
    try:
        deadline = time.monotonic() + STARTUP_TIMEOUT_S
        while time.monotonic() < deadline:
            if counter_path.exists() and read_counter(counter_path) >= MIN_EMITTED_BEFORE_KILL:
                break
            if process.poll() is not None:
                pytest.fail(f"crash child exited early with code {process.returncode}")
            time.sleep(0.02)
        else:
            pytest.fail("crash child never reached the minimum emit count")

        process.kill()  # SIGKILL: uncatchable, so nothing in the SDK can clean up
        process.wait(timeout=10)
    finally:
        if process.poll() is None:  # pragma: no cover - only on an assertion above
            process.kill()
            process.wait(timeout=10)

    assert process.returncode == -9, "the child must have died by SIGKILL, not exited"
    return journal_path, read_counter(counter_path)


def test_sigkill_loses_no_more_than_the_conformance_bound(
    crashed_agent: tuple[Path, int],
) -> None:
    journal_path, emitted = crashed_agent

    survived = count_journaled_events(journal_path)
    lost = emitted - survived

    assert emitted >= MIN_EMITTED_BEFORE_KILL
    assert survived > 0, "nothing reached the journal — crash-flush is not working at all"
    assert lost <= LOSS_BOUND_EVENTS, (
        f"lost {lost} events (emitted {emitted}, survived {survived}); "
        f"PRD §17.3 allows at most {LOSS_BOUND_EVENTS} at this emit rate"
    )


def test_survivors_are_a_prefix_not_a_random_sample(crashed_agent: tuple[Path, int]) -> None:
    """Loss must be a truncated tail. A trace with holes in the middle is not
    a shorter trace — it is a misleading one."""
    journal_path, _ = crashed_agent

    recovered = recover(journal_path)
    seqs = [record.seq for record in recovered.records]

    assert seqs == list(range(seqs[0], seqs[0] + len(seqs)))
    assert recovered.corrupt_lines <= 1, "at most the final record may be torn"


def test_a_restarted_adapter_replays_what_the_crash_left(
    crashed_agent: tuple[Path, int], tmp_path: Path
) -> None:
    """Durability is only worth something if the next run delivers it."""
    journal_path, _ = crashed_agent
    outstanding = recover(journal_path).records
    assert outstanding, "the crash should have left undelivered events behind"

    transport = RecordingTransport()
    adapter = make_adapter(tmp_path, transport, journal_name=journal_path.name)
    try:
        assert adapter.flush(30.0)
    finally:
        adapter.close(timeout_s=30.0)

    replayed = {envelope.event_id for envelope in transport.envelopes}
    assert {record.envelope.event_id for record in outstanding} <= replayed


def test_replayed_events_are_cleared_from_the_journal(
    crashed_agent: tuple[Path, int], tmp_path: Path
) -> None:
    """Otherwise every restart would replay the whole history forever."""
    journal_path, _ = crashed_agent

    transport = RecordingTransport()
    adapter = make_adapter(tmp_path, transport, journal_name=journal_path.name)
    try:
        assert adapter.flush(30.0)
    finally:
        adapter.close(timeout_s=30.0)

    assert recover(journal_path).records == ()

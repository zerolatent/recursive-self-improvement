"""Write-ahead journal: durability, recovery, and the fsync policy.

The journal is what turns "the process died" into a bounded loss instead of
an unbounded one, so these tests care most about the ugly cases — a record
torn in half by the crash, a stale ack, a second process reaching for the
same file.
"""

from __future__ import annotations

import os
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest

from evoruntime.sdk.journal import (
    DEFAULT_FSYNC_INTERVAL_S,
    EventJournal,
    JournalLockedError,
    compact,
    recover,
)
from evoruntime.sdk.records import BuiltEvent, PendingEvent, build_event
from tests.sdk.support import MODEL, ZERO, make_context


def built(index: int) -> BuiltEvent:
    return build_event(
        make_context(),
        PendingEvent(
            occurred_at=datetime.now(UTC),
            trace_id=f"trc_{index:012d}",
            task_id=f"tsk_{index:012d}",
            type="tool.completed",
            model=MODEL,
            cost=ZERO,
            artifact_digests=(),
            details={"index": index},
        ),
    )


@pytest.fixture
def journal_path(tmp_path: Path) -> Path:
    return tmp_path / "events.journal"


def test_append_assigns_sequential_numbers(journal_path: Path) -> None:
    journal = EventJournal(journal_path)
    try:
        assert journal.append([built(0), built(1)]) == [1, 2]
        assert journal.append([built(2)]) == [3]
    finally:
        journal.close()


def test_appended_events_survive_and_replay_verbatim(journal_path: Path) -> None:
    events = [built(i) for i in range(3)]
    journal = EventJournal(journal_path)
    journal.append(events)
    journal.close()

    recovered = recover(journal_path)

    assert [record.seq for record in recovered.records] == [1, 2, 3]
    assert [record.envelope.event_id for record in recovered.records] == [
        event.envelope.event_id for event in events
    ]
    assert [record.payload_body for record in recovered.records] == [
        event.payload_body for event in events
    ]
    assert recovered.corrupt_lines == 0
    assert recovered.next_seq == 4


def test_acknowledged_events_are_not_replayed(journal_path: Path) -> None:
    journal = EventJournal(journal_path)
    journal.append([built(i) for i in range(5)])
    journal.ack(3)
    journal.close()

    recovered = recover(journal_path)

    assert recovered.acked_through == 3
    assert [record.seq for record in recovered.records] == [4, 5]


def test_replay_prefers_a_duplicate_over_a_hole(journal_path: Path) -> None:
    """A crash between send and ack replays already-delivered events. That is
    the safe direction: D2 rejects duplicates by event id, but nothing can
    reconstruct an event that was never written."""
    journal = EventJournal(journal_path)
    journal.append([built(0)])
    # Delivered, but the process died before `ack` was called.
    journal.close()

    recovered = recover(journal_path)

    assert len(recovered.records) == 1
    assert recovered.acked_through == 0


def test_a_torn_final_record_costs_only_that_record(journal_path: Path) -> None:
    """The exact shape of a crash mid-write: the last line is half there."""
    journal = EventJournal(journal_path)
    journal.append([built(i) for i in range(4)])
    journal.close()
    with journal_path.open("r+b") as handle:
        handle.truncate(journal_path.stat().st_size - 40)

    recovered = recover(journal_path)

    assert [record.seq for record in recovered.records] == [1, 2, 3]
    assert recovered.corrupt_lines == 1


def test_recovery_counts_unknown_record_kinds_as_damage(journal_path: Path) -> None:
    journal = EventJournal(journal_path)
    journal.append([built(0)])
    journal.close()
    with journal_path.open("ab") as handle:
        handle.write(b'{"k":"?","seq":99}\n')

    recovered = recover(journal_path)

    assert recovered.corrupt_lines == 1
    assert [record.seq for record in recovered.records] == [1]


def test_recovery_of_a_missing_journal_is_an_empty_start(tmp_path: Path) -> None:
    recovered = recover(tmp_path / "never-written.journal")

    assert recovered.records == ()
    assert recovered.next_seq == 1
    assert recovered.corrupt_lines == 0


def test_two_live_adapters_cannot_share_one_journal(journal_path: Path) -> None:
    """Interleaved sequence numbers would make recovery ambiguous — better to
    fail at construction than during the crash we were preparing for."""
    first = EventJournal(journal_path)
    try:
        with pytest.raises(JournalLockedError):
            EventJournal(journal_path)
    finally:
        first.close()

    EventJournal(journal_path).close()  # lock released on close


def test_fsync_fires_on_the_event_count_policy(journal_path: Path) -> None:
    journal = EventJournal(journal_path, fsync_max_events=5, fsync_interval_s=3600.0)
    try:
        baseline = journal.fsync_count
        journal.append([built(i) for i in range(4)])
        assert journal.fsync_count == baseline

        journal.append([built(4)])
        assert journal.fsync_count == baseline + 1
        assert journal.last_synced_seq == 5
    finally:
        journal.close()


def test_explicit_sync_marks_everything_durable(journal_path: Path) -> None:
    journal = EventJournal(journal_path, fsync_max_events=1000, fsync_interval_s=3600.0)
    try:
        journal.append([built(i) for i in range(3)])
        journal.sync()
        assert journal.last_synced_seq == 3
    finally:
        journal.close()


def test_close_syncs_and_is_idempotent(journal_path: Path) -> None:
    journal = EventJournal(journal_path, fsync_max_events=1000, fsync_interval_s=3600.0)
    journal.append([built(0)])

    journal.close()
    journal.close()

    assert journal.last_synced_seq == 1


def test_appending_to_a_closed_journal_is_an_error(journal_path: Path) -> None:
    journal = EventJournal(journal_path)
    journal.close()

    with pytest.raises(RuntimeError, match="closed"):
        journal.append([built(0)])
    with pytest.raises(RuntimeError, match="closed"):
        journal.ack(1)


def test_empty_append_is_a_no_op(journal_path: Path) -> None:
    journal = EventJournal(journal_path)
    try:
        assert journal.append([]) == []
    finally:
        journal.close()


def test_journal_is_owner_readable_only(journal_path: Path) -> None:
    """Journal records hold raw tool arguments — the same trace content the
    PRD encrypts at rest server-side."""
    journal = EventJournal(journal_path)
    journal.close()

    assert stat.S_IMODE(journal_path.stat().st_mode) == 0o600


def test_compaction_keeps_outstanding_work_and_renumbers(journal_path: Path) -> None:
    journal = EventJournal(journal_path)
    journal.append([built(i) for i in range(4)])
    journal.ack(2)
    journal.close()
    recovered = recover(journal_path)

    compact(journal_path, recovered.records)

    after = recover(journal_path)
    assert [record.seq for record in after.records] == [1, 2]
    assert [record.envelope.event_id for record in after.records] == [
        record.envelope.event_id for record in recovered.records
    ]
    assert after.acked_through == 0
    assert after.next_seq == 3


def test_compaction_to_nothing_leaves_an_empty_journal(journal_path: Path) -> None:
    journal = EventJournal(journal_path)
    journal.append([built(0)])
    journal.ack(1)
    journal.close()

    compact(journal_path, recover(journal_path).records)

    assert journal_path.stat().st_size == 0
    assert recover(journal_path).records == ()


def test_compaction_leaves_no_temporary_file_behind(journal_path: Path) -> None:
    journal = EventJournal(journal_path)
    journal.append([built(0)])
    journal.close()

    compact(journal_path, recover(journal_path).records)

    assert sorted(os.listdir(journal_path.parent)) == [journal_path.name]


def test_start_seq_continues_a_recovered_journal(journal_path: Path) -> None:
    journal = EventJournal(journal_path, start_seq=7)
    try:
        assert journal.append([built(0)]) == [7]
    finally:
        journal.close()

    assert recover(journal_path).next_seq == 8


@pytest.mark.parametrize(
    "kwargs",
    [{"fsync_max_events": 0}, {"fsync_max_events": -1}, {"fsync_interval_s": 0.0}],
)
def test_invalid_fsync_policy_is_rejected(journal_path: Path, kwargs: dict[str, float]) -> None:
    with pytest.raises(ValueError):
        EventJournal(journal_path, **kwargs)  # type: ignore[arg-type]


def test_default_fsync_interval_is_sub_second() -> None:
    """The PRD's crash-flush bound is ≤1s of events; a default at or above
    one second could not meet it under host loss."""
    assert DEFAULT_FSYNC_INTERVAL_S < 1.0

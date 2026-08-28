"""Write-ahead journal: the SDK's crash-flush durability mechanism.

PRD §17.3 bounds what a SIGKILL'd agent may lose to 100 buffered events or
one second of events, whichever is smaller. Two distinct failure modes hide
behind that one sentence, and they need different mechanisms:

*Process death* (SIGKILL, an agent that segfaults, a container OOM-kill).
Everything already handed to the kernel survives — the page cache outlives
the process. What is lost is whatever never left the SDK's in-memory buffer,
so the bound is met by *writing early and often*: the flusher is woken by
volume as well as by its timer (see `EventBuffer.high_water`), so the
unwritten backlog stays bounded by a count no matter how fast the agent
emits.

*Host death* (power loss, a hypervisor pull). Now the page cache is gone too,
and only `fsync` counts. That is what the `fsync_max_events` /
`fsync_interval_s` policy here is for: whichever bound trips first forces the
data to stable storage, so the same ≤100-events/≤1s envelope holds when the
machine, not just the process, disappears.

The journal is append-only and self-describing. Two record kinds share one
file: `e` (an event, with its envelope and out-of-line detail body) and `a`
(an acknowledgement — every event at or below this sequence number reached
the ingest API). Recovery replays the events the acks do not cover. Replay
can produce duplicates when a crash lands between delivery and ack; that is
the safe direction, because D2's ingest rejects duplicates by event id
(`duplicate_event`) while nothing can recover an event that was never
written.
"""

from __future__ import annotations

import fcntl
import json
import logging
import os
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from evoruntime.core.events import EventEnvelope, parse_wire_envelope
from evoruntime.sdk.records import BuiltEvent

logger = logging.getLogger(__name__)

DEFAULT_FSYNC_MAX_EVENTS = 50
DEFAULT_FSYNC_INTERVAL_S = 0.25

RECORD_KIND_EVENT = "e"
RECORD_KIND_ACK = "a"

_JOURNAL_FILE_MODE = 0o600
"""Owner-only. Journal records carry raw tool arguments and outcome details,
which are exactly the trace content the PRD classifies and encrypts at rest
server-side; a world-readable file in /tmp would be the cheapest possible
way to leak it."""


class JournalLockedError(RuntimeError):
    """Another live process already owns this journal file.

    Two adapters appending to one journal would interleave sequence numbers
    and make recovery ambiguous. Failing loudly at construction beats
    discovering the corruption during the crash we were preparing for.
    """


@dataclass(frozen=True, slots=True)
class JournalRecord:
    """One journaled event, as read back during recovery."""

    seq: int
    envelope: EventEnvelope
    payload_body: bytes


@dataclass(frozen=True, slots=True)
class RecoveredJournal:
    """What a previous process left behind."""

    records: tuple[JournalRecord, ...]
    """Events written but never acknowledged — the replay set."""

    acked_through: int
    corrupt_lines: int
    """Unparseable lines, almost always a single torn final record from a
    write interrupted by the crash. Counted rather than ignored: a nonzero
    value anywhere but the tail is evidence of real corruption."""

    next_seq: int


def encode_event_record(seq: int, built: BuiltEvent) -> bytes:
    """Serialize one event record as a single JSON line.

    Embeds the envelope's own canonical bytes verbatim instead of
    re-serializing the model, so what recovery replays is byte-identical to
    what the original process would have sent.
    """
    payload = json.dumps(built.payload_body.decode("utf-8")).encode("utf-8")
    return (
        b'{"k":"'
        + RECORD_KIND_EVENT.encode("ascii")
        + b'","seq":'
        + str(seq).encode("ascii")
        + b',"payload_body":'
        + payload
        + b',"event":'
        + built.envelope.canonical_bytes()
        + b"}\n"
    )


def encode_ack_record(seq: int) -> bytes:
    """Serialize an acknowledgement covering every event through ``seq``."""
    return f'{{"k":"{RECORD_KIND_ACK}","seq":{seq}}}\n'.encode("ascii")


def recover(path: Path) -> RecoveredJournal:
    """Read a journal left by a previous process.

    Never raises on damaged input: a crash mid-write leaves a partial final
    line by construction, and a recovery routine that dies on the very
    condition it exists to handle is worse than useless. Damaged lines are
    counted and logged.
    """
    if not path.exists():
        return RecoveredJournal(records=(), acked_through=0, corrupt_lines=0, next_seq=1)

    events: list[JournalRecord] = []
    acked_through = 0
    corrupt = 0
    highest_seq = 0

    with path.open("rb") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                kind = record["k"]
                seq = int(record["seq"])
                if kind == RECORD_KIND_ACK:
                    acked_through = max(acked_through, seq)
                elif kind == RECORD_KIND_EVENT:
                    events.append(
                        JournalRecord(
                            seq=seq,
                            envelope=parse_wire_envelope(record["event"]),
                            payload_body=record["payload_body"].encode("utf-8"),
                        )
                    )
                else:
                    corrupt += 1
                    continue
                highest_seq = max(highest_seq, seq)
            except Exception:  # noqa: BLE001 - any malformed line is just a damaged record
                corrupt += 1

    if corrupt:
        logger.warning(
            "evoruntime sdk: %d damaged record(s) in journal %s were skipped during recovery",
            corrupt,
            path,
        )

    unacked = tuple(record for record in events if record.seq > acked_through)
    return RecoveredJournal(
        records=unacked,
        acked_through=acked_through,
        corrupt_lines=corrupt,
        next_seq=highest_seq + 1,
    )


class EventJournal:
    """Append-only, fsync-policied event log backing one adapter session.

    Writes go through `os.write` on an ``O_APPEND`` descriptor with no
    userspace buffering: a Python-level buffer would mean data the SDK
    believes is written is still only in the dying process's heap, which is
    precisely the loss this class exists to bound.
    """

    def __init__(
        self,
        path: Path | str,
        *,
        fsync_max_events: int = DEFAULT_FSYNC_MAX_EVENTS,
        fsync_interval_s: float = DEFAULT_FSYNC_INTERVAL_S,
        start_seq: int = 1,
    ) -> None:
        if fsync_max_events < 1:
            raise ValueError("fsync_max_events must be >= 1")
        if fsync_interval_s <= 0:
            raise ValueError("fsync_interval_s must be > 0")

        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._fsync_max_events = fsync_max_events
        self._fsync_interval_s = fsync_interval_s
        self._lock = threading.Lock()
        self._next_seq = start_seq
        self._unsynced = 0
        self._last_sync = time.monotonic()
        self._fsync_count = 0
        self._last_synced_seq = start_seq - 1
        self._closed = False

        self._fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, _JOURNAL_FILE_MODE)
        try:
            fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(self._fd)
            raise JournalLockedError(f"journal {self._path} is locked by another process") from exc
        self._fsync_dir()

    @property
    def path(self) -> Path:
        return self._path

    @property
    def fsync_count(self) -> int:
        """How many times the journal has been forced to stable storage."""
        with self._lock:
            return self._fsync_count

    @property
    def last_synced_seq(self) -> int:
        """Highest sequence number known to be on stable storage."""
        with self._lock:
            return self._last_synced_seq

    def append(self, events: Sequence[BuiltEvent]) -> list[int]:
        """Journal a batch of events, returning their sequence numbers.

        The whole batch goes out in one `os.write`, which keeps the window
        in which a crash can tear a record to a single record at the tail
        rather than one per event.
        """
        if not events:
            return []
        with self._lock:
            self._require_open()
            seqs = list(range(self._next_seq, self._next_seq + len(events)))
            blob = b"".join(
                encode_event_record(seq, event) for seq, event in zip(seqs, events, strict=True)
            )
            self._write(blob)
            self._next_seq += len(events)
            self._unsynced += len(events)
            self._maybe_sync_locked(highest_seq=seqs[-1])
        return seqs

    def ack(self, through_seq: int) -> None:
        """Record that every event through ``through_seq`` reached ingest.

        Not synced on its own schedule: a lost ack costs a duplicate on
        replay (which ingest rejects idempotently), while a lost *event*
        costs data — so only events drive the fsync policy.
        """
        with self._lock:
            self._require_open()
            self._write(encode_ack_record(through_seq))

    def sync(self) -> None:
        """Force everything written so far to stable storage."""
        with self._lock:
            self._require_open()
            self._sync_locked(highest_seq=self._next_seq - 1)

    def close(self) -> None:
        """Sync, release the file lock, and close. Idempotent."""
        with self._lock:
            if self._closed:
                return
            self._sync_locked(highest_seq=self._next_seq - 1)
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            os.close(self._fd)
            self._closed = True

    def _require_open(self) -> None:
        if self._closed:
            raise RuntimeError(f"journal {self._path} is closed")

    def _write(self, blob: bytes) -> None:
        """Write every byte, tolerating short writes."""
        view = memoryview(blob)
        while view:
            written = os.write(self._fd, view)
            view = view[written:]

    def _maybe_sync_locked(self, *, highest_seq: int) -> None:
        elapsed = time.monotonic() - self._last_sync
        if self._unsynced >= self._fsync_max_events or elapsed >= self._fsync_interval_s:
            self._sync_locked(highest_seq=highest_seq)

    def _sync_locked(self, *, highest_seq: int) -> None:
        os.fsync(self._fd)
        self._unsynced = 0
        self._last_sync = time.monotonic()
        self._fsync_count += 1
        self._last_synced_seq = max(self._last_synced_seq, highest_seq)

    def _fsync_dir(self) -> None:
        """Persist the journal's directory entry, not just its contents.

        A freshly created file whose directory entry is still only in the
        page cache can vanish entirely on host loss, taking every fsync'd
        byte with it.
        """
        dir_fd = os.open(self._path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)


def compact(path: Path, records: Sequence[JournalRecord]) -> None:
    """Rewrite ``path`` containing only ``records``, renumbered from 1.

    Called after recovery so a restarted adapter continues from a journal
    holding exactly the outstanding work. Written to a temporary file and
    moved into place with `os.replace`, so a crash during compaction leaves
    the original intact rather than a half-written replacement.
    """
    tmp_path = path.with_suffix(path.suffix + ".compact")
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, _JOURNAL_FILE_MODE)
    try:
        blob = b"".join(
            encode_event_record(
                seq,
                BuiltEvent(envelope=record.envelope, payload_body=record.payload_body),
            )
            for seq, record in enumerate(records, start=1)
        )
        view = memoryview(blob)
        while view:
            view = view[os.write(fd, view) :]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp_path, path)
    dir_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)

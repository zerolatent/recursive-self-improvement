"""The background flush worker: drain, validate, journal, deliver, acknowledge.

Everything expensive in the SDK happens on this one thread, which is the
point — the agent thread's only job is to drop a `PendingEvent` into a
bounded buffer and keep working (PRD FR-001).

The ordering is not arbitrary. Events are journaled *before* they are sent
and acknowledged *after* the ingest API confirms them, so the only state a
crash can produce is "already durable, possibly not yet delivered" — which
recovery resolves by replaying. The reverse order (send, then journal) would
produce "delivered, not recorded", which is unrecoverable and silently lossy.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass
from itertools import islice

from pydantic import ValidationError

from evoruntime.core.events import EventEnvelope
from evoruntime.sdk.buffer import EventBuffer
from evoruntime.sdk.journal import EventJournal
from evoruntime.sdk.records import BuiltEvent, PendingEvent, TraceContext, build_event
from evoruntime.sdk.transport import IngestTransport, TransportError

logger = logging.getLogger(__name__)

INITIAL_RETRY_BACKOFF_S = 0.25
MAX_RETRY_BACKOFF_S = 5.0
MAX_TICK_S = 0.05
MIN_TICK_S = 0.001

_OutboxEntry = tuple[int | None, EventEnvelope]


@dataclass(frozen=True, slots=True)
class FlushCounters:
    """Delivery-side counts. Paired with `BufferCounters` in `AdapterStats`."""

    journaled: int
    sent: int
    rejected: int
    invalid: int
    send_failures: int
    evicted: int
    cycle_errors: int
    outbox: int


def resolve_tick_s(flush_interval_s: float, journal_fsync_interval_s: float) -> float:
    """Choose how often the flusher wakes on its own.

    Bounded above by `MAX_TICK_S` so the journal's time-based fsync policy
    is actually honored (a 1s flush interval must not mean 1s of unsynced
    events), and below by `MIN_TICK_S` so a tiny configured interval cannot
    turn the flusher into a spin loop.
    """
    return min(max(min(flush_interval_s, journal_fsync_interval_s) / 2, MIN_TICK_S), MAX_TICK_S)


class FlushWorker:
    """Owns the SDK's background thread and everything it touches."""

    def __init__(
        self,
        *,
        buffer: EventBuffer,
        context: TraceContext,
        transport: IngestTransport,
        journal: EventJournal | None,
        wake: threading.Event,
        flush_interval_s: float,
        batch_max_events: int,
        max_outbox_events: int,
        tick_s: float,
    ) -> None:
        self._buffer = buffer
        self._context = context
        self._transport = transport
        self._journal = journal
        self._wake = wake
        self._flush_interval_s = flush_interval_s
        self._batch_max_events = batch_max_events
        self._max_outbox_events = max_outbox_events
        self._tick_s = tick_s

        self._cond = threading.Condition()
        self._outbox: deque[_OutboxEntry] = deque()
        self._stopping = threading.Event()
        self._force = False
        self._sending = False
        self._backoff_s = 0.0
        self._backoff_until = 0.0
        self._last_send = time.monotonic()

        self._journaled = 0
        self._sent = 0
        self._rejected = 0
        self._invalid = 0
        self._send_failures = 0
        self._evicted = 0
        self._cycle_errors = 0

        self._thread = threading.Thread(
            target=self._run, name="evoruntime-sdk-flusher", daemon=True
        )

    def start(self) -> None:
        self._thread.start()

    def enqueue(self, envelopes: Sequence[_OutboxEntry]) -> None:
        """Queue already-journaled envelopes for delivery (recovery replay)."""
        if not envelopes:
            return
        with self._cond:
            self._outbox.extend(envelopes)
            self._evict_locked()
            self._cond.notify_all()
        self._wake.set()

    def flush(self, timeout_s: float) -> bool:
        """Block until everything buffered has been delivered, or time out.

        Returns ``False`` on timeout rather than raising: a caller that
        cannot reach the ingest API still needs to finish its task, and the
        undelivered events remain journaled for the next run to replay.
        """
        deadline = time.monotonic() + timeout_s
        with self._cond:
            self._force = True
        self._wake.set()
        with self._cond:
            while self._outbox or self._sending or len(self._buffer):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._cond.wait(remaining)
            return True

    def stop(self, timeout_s: float) -> None:
        """Stop the thread after one final drain-and-deliver cycle."""
        self._stopping.set()
        self._wake.set()
        self._thread.join(timeout_s)
        if self._thread.is_alive():
            logger.warning(
                "evoruntime sdk: flusher did not stop within %.1fs; "
                "undelivered events remain in the journal for replay",
                timeout_s,
            )

    def counters(self) -> FlushCounters:
        with self._cond:
            return FlushCounters(
                journaled=self._journaled,
                sent=self._sent,
                rejected=self._rejected,
                invalid=self._invalid,
                send_failures=self._send_failures,
                evicted=self._evicted,
                cycle_errors=self._cycle_errors,
                outbox=len(self._outbox),
            )

    # -- thread body ---------------------------------------------------

    def _run(self) -> None:
        while not self._stopping.is_set():
            self._wake.wait(self._tick_s)
            self._wake.clear()
            self._guarded_cycle(final=False)
        self._guarded_cycle(final=True)

    def _guarded_cycle(self, *, final: bool) -> None:
        """Run one cycle, surviving any error it raises.

        A flusher thread that dies takes all telemetry with it and leaves no
        trace of why — so the exception is logged with its traceback and
        counted in `cycle_errors` (which the harness can assert on) rather
        than being allowed to kill the thread. This is the one place broad
        exception handling is correct, and it reports rather than hides.
        """
        try:
            self._cycle(final=final)
        except Exception:
            with self._cond:
                self._cycle_errors += 1
                self._cond.notify_all()
            logger.exception("evoruntime sdk: flush cycle failed")
            time.sleep(self._tick_s)

    def _cycle(self, *, final: bool) -> None:
        drained = self._buffer.drain()
        if drained:
            built = self._build(drained)
            if built:
                seqs = self._journal.append(built) if self._journal else [None] * len(built)
                with self._cond:
                    self._journaled += len(built)
                    self._outbox.extend(
                        (seq, event.envelope) for seq, event in zip(seqs, built, strict=True)
                    )
                    self._evict_locked()
        self._deliver(final=final)
        with self._cond:
            self._cond.notify_all()

    def _build(self, pending: Sequence[PendingEvent]) -> list[BuiltEvent]:
        built: list[BuiltEvent] = []
        for event in pending:
            try:
                built.append(build_event(self._context, event))
            except ValidationError as exc:
                with self._cond:
                    self._invalid += 1
                logger.error(
                    "evoruntime sdk: event failed envelope validation and was not recorded "
                    "(type=%s task=%s): %s",
                    event.type,
                    event.task_id,
                    exc,
                )
        return built

    def _deliver(self, *, final: bool) -> None:
        if not self._due(final=final):
            return
        while True:
            with self._cond:
                if not self._outbox:
                    self._force = False
                    self._last_send = time.monotonic()
                    self._cond.notify_all()
                    return
                chunk = list(islice(self._outbox, 0, self._batch_max_events))
                self._sending = True
            try:
                result = self._transport.send([envelope for _, envelope in chunk])
            except TransportError as exc:
                with self._cond:
                    self._sending = False
                    self._send_failures += 1
                    self._backoff_s = min(
                        max(self._backoff_s * 2, INITIAL_RETRY_BACKOFF_S), MAX_RETRY_BACKOFF_S
                    )
                    self._backoff_until = time.monotonic() + self._backoff_s
                    self._cond.notify_all()
                logger.warning(
                    "evoruntime sdk: delivery of %d event(s) failed, retrying in %.2fs: %s",
                    len(chunk),
                    self._backoff_s,
                    exc,
                )
                return

            for rejection in result.rejected:
                logger.error(
                    "evoruntime sdk: ingest rejected event at batch index %d (%s): %s",
                    rejection.index,
                    rejection.error_type,
                    rejection.message,
                )

            highest_seq = max((seq for seq, _ in chunk if seq is not None), default=None)
            with self._cond:
                for _ in range(len(chunk)):
                    self._outbox.popleft()
                self._sending = False
                self._sent += len(result.accepted_event_ids)
                self._rejected += len(result.rejected)
                self._backoff_s = 0.0
                self._backoff_until = 0.0
                self._last_send = time.monotonic()
                self._cond.notify_all()
            if highest_seq is not None and self._journal is not None:
                self._journal.ack(highest_seq)

    def _due(self, *, final: bool) -> bool:
        """Is a delivery attempt warranted right now?"""
        with self._cond:
            if not self._outbox:
                self._force = False
                return False
            now = time.monotonic()
            if now < self._backoff_until and not final:
                return False
            return (
                final
                or self._force
                or len(self._outbox) >= self._batch_max_events
                or (now - self._last_send) >= self._flush_interval_s
            )

    def _evict_locked(self) -> None:
        """Bound the retry queue when ingest stays unreachable.

        Events evicted here are already journaled and unacknowledged, so
        with a journal configured they are deferred (the next run replays
        them), not lost. Without one they are genuinely gone — which is why
        `Adapter` warns loudly when no journal path is set.
        """
        overflow = len(self._outbox) - self._max_outbox_events
        if overflow <= 0:
            return
        for _ in range(overflow):
            self._outbox.popleft()
        self._evicted += overflow
        logger.warning(
            "evoruntime sdk: retry queue full, evicted %d event(s) from memory (journaled: %s)",
            overflow,
            self._journal is not None,
        )

"""The adapter and trace handle — the only surface a coding-agent author touches.

Usage follows the Phase 0 spec's sample verbatim in shape::

    with Adapter(endpoint=..., agent_id=..., release_id=..., ...) as adapter:
        with adapter.trace(task_id="tsk_...") as trace:
            trace.model_call(provider="openai", model="gpt-5.3-codex",
                             input_tokens=1234, output_tokens=456)
            trace.tool_call(name="repo_patch", args_digest="sha256:...",
                            result_digest="sha256:...")
            trace.artifact_loaded(digest="sha256:...", kind="skill_package")
            trace.claim_outcome(success=True)

`tenant_id`, `environment_digest` and `model` are required beyond the spec's
illustrative sample because the D2 event envelope (PRD §18.3) requires them
on *every* event. They are not defaulted: an SDK that invents a tenant id or
an environment digest would write authoritative-looking rows that attribute
a trace to the wrong tenant or to an environment that was never measured.

What this class refuses to do is block. `Trace.model_call` and friends return
a bool (queued / dropped) and never wait on the network, on a disk, or on a
consumer thread. The one thing they *do* raise on is a malformed argument the
caller can fix — a bad digest or task id — because failing at the call site
beats a background rejection the agent author never sees.
"""

from __future__ import annotations

import logging
import re
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType

from evoruntime.core.events import (
    SHA256_DIGEST_PATTERN,
    TASK_ID_PATTERN,
    CostInfo,
    DataClassification,
    EventEnvelope,
    ModelInfo,
)
from evoruntime.core.ids import new_id
from evoruntime.sdk.buffer import EventBuffer
from evoruntime.sdk.flusher import FlushWorker, resolve_tick_s
from evoruntime.sdk.journal import (
    DEFAULT_FSYNC_INTERVAL_S,
    DEFAULT_FSYNC_MAX_EVENTS,
    EventJournal,
    compact,
    recover,
)
from evoruntime.sdk.records import ZERO_COST, Details, PendingEvent, TraceContext
from evoruntime.sdk.transport import HttpIngestTransport, IngestTransport
from evoruntime.security.identities import WorkloadIdentity, WorkloadRole

logger = logging.getLogger(__name__)

DEFAULT_BUFFER_MAX_EVENTS = 10_000
DEFAULT_FLUSH_INTERVAL_S = 1.0
DEFAULT_BATCH_MAX_EVENTS = 500
"""Half of D2's 1000-event request cap, leaving room for the endpoint's limit
to tighten without the SDK immediately overflowing it."""

DEFAULT_CLOSE_TIMEOUT_S = 5.0

EVENT_TRACE_STARTED = "trace.started"
EVENT_TRACE_ENDED = "trace.ended"
EVENT_MODEL_COMPLETED = "model.completed"
EVENT_TOOL_COMPLETED = "tool.completed"
EVENT_ARTIFACT_LOADED = "artifact.loaded"
EVENT_OUTCOME_CLAIMED = "outcome.claimed"

UNSPECIFIED_MODEL_VERSION = "unspecified"
"""Recorded when a caller reports a model call without a version. Deliberately
not inherited from the adapter's declared model: silently attributing one
model's version to another call would corrupt the per-release attribution the
evaluation plane depends on."""

# Compiled from the envelope's own patterns so agent-thread validation and
# background envelope validation can never disagree about what is valid.
_TASK_ID_RE = re.compile(TASK_ID_PATTERN)
_DIGEST_RE = re.compile(SHA256_DIGEST_PATTERN)


@dataclass(frozen=True, slots=True)
class AdapterStats:
    """One snapshot of everything the adapter knows about its own health.

    `dropped_events` is the number the PRD's backpressure requirement names:
    events the agent emitted that the SDK refused because the buffer was
    full. It is a counter, never a log line only, so a harness can assert on
    it and a campaign can disqualify a run whose telemetry was truncated.
    """

    emitted: int
    dropped_events: int
    buffered: int
    journaled: int
    sent: int
    rejected: int
    invalid: int
    send_failures: int
    evicted: int
    cycle_errors: int
    outbox: int


class Trace:
    """One task's event stream. Not thread-safe to close, safe to emit from
    multiple threads."""

    def __init__(self, adapter: Adapter, *, trace_id: str, task_id: str) -> None:
        self._adapter = adapter
        self._trace_id = trace_id
        self._task_id = task_id
        self._closed = False

    @property
    def id(self) -> str:
        """The trace id events are grouped by, and what an attestation binds to."""
        return self._trace_id

    @property
    def task_id(self) -> str:
        return self._task_id

    def model_call(
        self,
        *,
        provider: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        usd: float = 0.0,
        version: str | None = None,
    ) -> bool:
        """Record a completed model call and what it cost."""
        return self._emit(
            EVENT_MODEL_COMPLETED,
            model=ModelInfo(
                provider=provider, name=model, version=version or UNSPECIFIED_MODEL_VERSION
            ),
            cost=CostInfo(input_tokens=input_tokens, output_tokens=output_tokens, usd=float(usd)),
            details={"provider": provider, "model": model},
        )

    def tool_call(
        self, *, name: str, args_digest: str, result_digest: str, ok: bool = True
    ) -> bool:
        """Record a completed tool call by digest, never by content.

        Arguments and results are referenced by digest so the trace stream
        stays free of raw repository content, credentials, and anything else
        a tool happened to touch — the content itself belongs in the payload
        store under its own classification and deletion policy.
        """
        self._require_digest("args_digest", args_digest)
        self._require_digest("result_digest", result_digest)
        return self._emit(
            EVENT_TOOL_COMPLETED,
            details={
                "name": name,
                "args_digest": args_digest,
                "result_digest": result_digest,
                "ok": ok,
            },
        )

    def artifact_loaded(self, *, digest: str, kind: str) -> bool:
        """Record that the agent loaded a content-addressed artifact.

        The digest also lands in the envelope's `artifact_digests`, which is
        what lets a campaign answer "which release actually ran with this
        skill package" without re-reading payloads.
        """
        self._require_digest("digest", digest)
        return self._emit(
            EVENT_ARTIFACT_LOADED,
            artifact_digests=(digest,),
            details={"kind": kind, "digest": digest},
        )

    def claim_outcome(self, *, success: bool) -> bool:
        """Record the agent's *claimed* outcome — untrusted by construction.

        A candidate reporting its own success is exactly the signal an
        optimizer would learn to game, so nothing downstream may treat this
        as the result. The authoritative outcome comes from an external
        verifier via `OutcomeAttestation` (see `evoruntime.sdk.attestation`),
        which is signed with a key the candidate identity cannot read.
        """
        return self._emit(EVENT_OUTCOME_CLAIMED, details={"claimed_success": success})

    def __enter__(self) -> Trace:
        self._emit(EVENT_TRACE_STARTED, details={})
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._emit(
            EVENT_TRACE_ENDED,
            details={"ok": exc_type is None, "error_type": exc_type.__name__ if exc_type else None},
        )
        self._closed = True

    def _emit(
        self,
        event_type: str,
        *,
        details: Details,
        model: ModelInfo | None = None,
        cost: CostInfo | None = None,
        artifact_digests: tuple[str, ...] = (),
    ) -> bool:
        if self._closed:
            raise RuntimeError(f"trace {self._trace_id} is closed; open a new trace to emit")
        return self._adapter.offer(
            PendingEvent(
                occurred_at=datetime.now(UTC),
                trace_id=self._trace_id,
                task_id=self._task_id,
                type=event_type,
                model=model or self._adapter.model,
                cost=cost or ZERO_COST,
                artifact_digests=artifact_digests,
                details=details,
            )
        )

    @staticmethod
    def _require_digest(field: str, value: str) -> None:
        if not _DIGEST_RE.match(value):
            raise ValueError(f"{field} must look like 'sha256:<64 hex chars>', got {value!r}")


class Adapter:
    """A buffered, non-blocking client for the trace ingest API."""

    def __init__(
        self,
        *,
        endpoint: str,
        agent_id: str,
        release_id: str,
        tenant_id: str,
        environment_digest: str,
        model: ModelInfo,
        campaign_id: str | None = None,
        data_classification: DataClassification = DataClassification.INTERNAL,
        buffer_max_events: int = DEFAULT_BUFFER_MAX_EVENTS,
        flush_interval_s: float = DEFAULT_FLUSH_INTERVAL_S,
        batch_max_events: int = DEFAULT_BATCH_MAX_EVENTS,
        journal_path: Path | str | None = None,
        journal_fsync_max_events: int = DEFAULT_FSYNC_MAX_EVENTS,
        journal_fsync_interval_s: float = DEFAULT_FSYNC_INTERVAL_S,
        transport: IngestTransport | None = None,
        identity: WorkloadIdentity | None = None,
        recover_on_start: bool = True,
    ) -> None:
        if flush_interval_s <= 0:
            raise ValueError("flush_interval_s must be > 0")
        if batch_max_events < 1:
            raise ValueError("batch_max_events must be >= 1")

        self._model = model
        self._closed = False
        self._context = TraceContext(
            tenant_id=tenant_id,
            agent_id=agent_id,
            release_id=release_id,
            environment_digest=environment_digest,
            data_classification=data_classification,
            campaign_id=campaign_id,
        )
        # The agent process runs as a candidate — never as the evaluator.
        # Defaulting anywhere else would hand candidate execution an
        # identity that can reach holdout content and evaluator keys.
        self._identity = identity or WorkloadIdentity(
            role=WorkloadRole.CANDIDATE_RUNNER, subject=agent_id
        )
        self._transport = transport or HttpIngestTransport(
            endpoint, tenant_id=tenant_id, identity=self._identity
        )

        self._wake = threading.Event()
        self._buffer = EventBuffer(
            buffer_max_events, high_water=journal_fsync_max_events, wake=self._wake
        )
        self._journal, replay = self._open_journal(
            journal_path,
            fsync_max_events=journal_fsync_max_events,
            fsync_interval_s=journal_fsync_interval_s,
            recover_on_start=recover_on_start,
        )
        self._worker = FlushWorker(
            buffer=self._buffer,
            context=self._context,
            transport=self._transport,
            journal=self._journal,
            wake=self._wake,
            flush_interval_s=flush_interval_s,
            batch_max_events=batch_max_events,
            max_outbox_events=buffer_max_events,
            tick_s=resolve_tick_s(flush_interval_s, journal_fsync_interval_s),
        )
        self._worker.start()
        self._worker.enqueue(replay)

    @property
    def model(self) -> ModelInfo:
        """The agent's declared model, carried by events that are not model calls."""
        return self._model

    @property
    def identity(self) -> WorkloadIdentity:
        return self._identity

    @property
    def dropped_events(self) -> int:
        """Events refused because the buffer was full (PRD FR-001 backpressure)."""
        return self._buffer.counters().dropped

    @property
    def stats(self) -> AdapterStats:
        buffer = self._buffer.counters()
        flush = self._worker.counters()
        return AdapterStats(
            emitted=buffer.accepted,
            dropped_events=buffer.dropped,
            buffered=buffer.size,
            journaled=flush.journaled,
            sent=flush.sent,
            rejected=flush.rejected,
            invalid=flush.invalid,
            send_failures=flush.send_failures,
            evicted=flush.evicted,
            cycle_errors=flush.cycle_errors,
            outbox=flush.outbox,
        )

    def trace(self, task_id: str) -> Trace:
        """Open a trace for one task.

        The task id is validated here — once, on the agent thread — rather
        than per event, so a typo surfaces at the call that made it instead
        of as a stream of background validation failures.
        """
        if self._closed:
            raise RuntimeError("adapter is closed")
        if not _TASK_ID_RE.match(task_id):
            raise ValueError(f"task_id must match 'tsk_<alphanumeric>', got {task_id!r}")
        return Trace(self, trace_id=new_id("trc"), task_id=task_id)

    def offer(self, event: PendingEvent) -> bool:
        """Queue an event. Never blocks on I/O; returns False if dropped."""
        return self._buffer.offer(event)

    def flush(self, timeout_s: float = DEFAULT_CLOSE_TIMEOUT_S) -> bool:
        """Deliver everything queued, returning False if it could not within
        ``timeout_s``."""
        return self._worker.flush(timeout_s)

    def close(self, timeout_s: float = DEFAULT_CLOSE_TIMEOUT_S) -> None:
        """Flush, stop the background thread, and release the journal.

        Idempotent. A process that exits without calling this (or without
        using the adapter as a context manager) still keeps its journaled
        events: that is what recovery is for. What it loses is whatever was
        still in the in-memory buffer — bounded, but not zero.
        """
        if self._closed:
            return
        self._closed = True
        self._worker.flush(timeout_s)
        self._worker.stop(timeout_s)
        if self._journal is not None:
            self._journal.close()
        self._transport.close()

    def __enter__(self) -> Adapter:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def _open_journal(
        self,
        journal_path: Path | str | None,
        *,
        fsync_max_events: int,
        fsync_interval_s: float,
        recover_on_start: bool,
    ) -> tuple[EventJournal | None, list[tuple[int | None, EventEnvelope]]]:
        if journal_path is None:
            logger.warning(
                "evoruntime sdk: no journal_path configured — crash-flush durability is "
                "disabled and events buffered at process death will be lost"
            )
            return None, []

        path = Path(journal_path)
        recovered = recover(path)
        if recover_on_start:
            # Compaction renumbers the surviving records from 1, so the
            # replay entries must carry their *new* sequence numbers or the
            # first ack would acknowledge the wrong rows.
            compact(path, recovered.records)
            start_seq = len(recovered.records) + 1
            replay: list[tuple[int | None, EventEnvelope]] = [
                (seq, record.envelope) for seq, record in enumerate(recovered.records, start=1)
            ]
            if replay:
                logger.info(
                    "evoruntime sdk: replaying %d unacknowledged event(s) from %s",
                    len(replay),
                    path,
                )
        else:
            start_seq = recovered.next_seq
            replay = []

        journal = EventJournal(
            path,
            fsync_max_events=fsync_max_events,
            fsync_interval_s=fsync_interval_s,
            start_seq=start_seq,
        )
        return journal, replay

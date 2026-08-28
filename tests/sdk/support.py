"""Test doubles for the adapter SDK.

The transports here stand in for D2's ingest API. Everything they record is
guarded by a lock because the flush worker calls `send` from its own thread
while the test asserts from the main one — an unsynchronized list would make
these tests flaky in exactly the way concurrency tests must not be.
"""

from __future__ import annotations

import threading
from collections.abc import Sequence
from pathlib import Path

from evoruntime.core.events import CostInfo, DataClassification, EventEnvelope, ModelInfo
from evoruntime.sdk.adapter import Adapter
from evoruntime.sdk.records import TraceContext
from evoruntime.sdk.transport import IngestResult, RejectedEventInfo, TransportError

TENANT_ID = "tnt_test"
AGENT_ID = "agt_test"
RELEASE_ID = "rel_test"
ENVIRONMENT_DIGEST = f"sha256:{'ab' * 32}"
MODEL = ModelInfo(provider="scripted", name="scripted-agent", version="2026-08-27")

ZERO = CostInfo(input_tokens=0, output_tokens=0, usd=0.0)


def digest(seed: int) -> str:
    """A syntactically valid, deterministic content digest."""
    return f"sha256:{seed:064x}"


def make_context() -> TraceContext:
    return TraceContext(
        tenant_id=TENANT_ID,
        agent_id=AGENT_ID,
        release_id=RELEASE_ID,
        environment_digest=ENVIRONMENT_DIGEST,
        data_classification=DataClassification.INTERNAL,
    )


class RecordingTransport:
    """Accepts every batch and remembers what it saw."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._envelopes: list[EventEnvelope] = []
        self.closed = False

    def send(self, envelopes: Sequence[EventEnvelope]) -> IngestResult:
        with self._lock:
            self._envelopes.extend(envelopes)
        return IngestResult(accepted_event_ids=tuple(e.event_id for e in envelopes))

    def close(self) -> None:
        self.closed = True

    @property
    def envelopes(self) -> list[EventEnvelope]:
        with self._lock:
            return list(self._envelopes)

    def types(self) -> list[str]:
        return [envelope.type for envelope in self.envelopes]


class BlockingTransport:
    """Blocks inside `send` until released.

    Models the case backpressure exists for: ingest is reachable but slow,
    so the SDK's queues fill while the agent keeps emitting.
    """

    def __init__(self) -> None:
        self.release = threading.Event()
        self.entered = threading.Event()
        self.closed = False

    def send(self, envelopes: Sequence[EventEnvelope]) -> IngestResult:
        self.entered.set()
        self.release.wait(timeout=30)
        return IngestResult(accepted_event_ids=tuple(e.event_id for e in envelopes))

    def close(self) -> None:
        self.closed = True


class FailingTransport:
    """Fails the first ``failures`` batches, then records normally."""

    def __init__(self, failures: int) -> None:
        self._lock = threading.Lock()
        self._remaining = failures
        self.attempts = 0
        self.delivered: list[EventEnvelope] = []
        self.closed = False

    def send(self, envelopes: Sequence[EventEnvelope]) -> IngestResult:
        with self._lock:
            self.attempts += 1
            if self._remaining > 0:
                self._remaining -= 1
                raise TransportError("ingest unreachable (simulated)")
            self.delivered.extend(envelopes)
            return IngestResult(accepted_event_ids=tuple(e.event_id for e in envelopes))

    def close(self) -> None:
        self.closed = True


class RejectingTransport:
    """Accepts the batch but refuses every event in it, as D2 does for a
    duplicate or schema-invalid event."""

    def __init__(self) -> None:
        self.batches = 0

    def send(self, envelopes: Sequence[EventEnvelope]) -> IngestResult:
        self.batches += 1
        return IngestResult(
            rejected=tuple(
                RejectedEventInfo(index=i, error_type="duplicate_event", message="already ingested")
                for i, _ in enumerate(envelopes)
            )
        )

    def close(self) -> None:
        return None


def make_adapter(
    tmp_path: Path,
    transport: object,
    *,
    buffer_max_events: int = 10_000,
    flush_interval_s: float = 0.01,
    batch_max_events: int = 500,
    journal_name: str = "events.journal",
    **kwargs: object,
) -> Adapter:
    """An adapter wired to a test transport and a journal under ``tmp_path``."""
    return Adapter(
        endpoint="http://ingest.invalid",
        agent_id=AGENT_ID,
        release_id=RELEASE_ID,
        tenant_id=TENANT_ID,
        environment_digest=ENVIRONMENT_DIGEST,
        model=MODEL,
        buffer_max_events=buffer_max_events,
        flush_interval_s=flush_interval_s,
        batch_max_events=batch_max_events,
        journal_path=tmp_path / journal_name,
        transport=transport,  # type: ignore[arg-type]
        **kwargs,  # type: ignore[arg-type]
    )

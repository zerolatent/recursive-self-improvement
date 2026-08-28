"""The public adapter surface, end to end against a stand-in ingest API.

Covers what an agent author can observe: the events a trace produces, the
envelope fields they carry, the errors a caller gets for a mistake they can
fix, and the two guarantees the PRD's conformance profile names — emit never
blocks, and a full buffer drops with a counter.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from evoruntime.core.events import DataClassification
from evoruntime.sdk.adapter import (
    EVENT_ARTIFACT_LOADED,
    EVENT_MODEL_COMPLETED,
    EVENT_OUTCOME_CLAIMED,
    EVENT_TOOL_COMPLETED,
    EVENT_TRACE_ENDED,
    EVENT_TRACE_STARTED,
    UNSPECIFIED_MODEL_VERSION,
    Adapter,
)
from evoruntime.security.identities import WorkloadRole
from tests.sdk.support import (
    AGENT_ID,
    ENVIRONMENT_DIGEST,
    MODEL,
    RELEASE_ID,
    TENANT_ID,
    BlockingTransport,
    FailingTransport,
    RecordingTransport,
    RejectingTransport,
    digest,
    make_adapter,
)

FLUSH_TIMEOUT_S = 10.0
EMIT_BLOCK_BUDGET_S = 0.001


def test_trace_emits_the_spec_sample_event_stream(tmp_path: Path) -> None:
    transport = RecordingTransport()

    with make_adapter(tmp_path, transport) as adapter:
        with adapter.trace(task_id="tsk_repair001") as trace:
            trace.model_call(
                provider="openai", model="gpt-5.3-codex", input_tokens=1234, output_tokens=456
            )
            trace.tool_call(name="repo_patch", args_digest=digest(1), result_digest=digest(2))
            trace.artifact_loaded(digest=digest(3), kind="skill_package")
            trace.claim_outcome(success=True)
        assert adapter.flush(FLUSH_TIMEOUT_S)

    assert transport.types() == [
        EVENT_TRACE_STARTED,
        EVENT_MODEL_COMPLETED,
        EVENT_TOOL_COMPLETED,
        EVENT_ARTIFACT_LOADED,
        EVENT_OUTCOME_CLAIMED,
        EVENT_TRACE_ENDED,
    ]


def test_every_event_carries_the_adapter_context(tmp_path: Path) -> None:
    transport = RecordingTransport()

    with make_adapter(tmp_path, transport) as adapter:
        with adapter.trace(task_id="tsk_repair001") as trace:
            trace.claim_outcome(success=False)
        assert adapter.flush(FLUSH_TIMEOUT_S)

    envelopes = transport.envelopes
    assert envelopes
    for envelope in envelopes:
        assert envelope.tenant_id == TENANT_ID
        assert envelope.agent_id == AGENT_ID
        assert envelope.release_id == RELEASE_ID
        assert envelope.environment_digest == ENVIRONMENT_DIGEST
        assert envelope.data_classification is DataClassification.INTERNAL
        assert envelope.task_id == "tsk_repair001"
        assert envelope.trace_id.startswith("trc_")
        assert envelope.payload_digest is not None
        assert envelope.payload_uri is not None


def test_model_call_records_cost_and_model_identity(tmp_path: Path) -> None:
    transport = RecordingTransport()

    with make_adapter(tmp_path, transport) as adapter:
        trace = adapter.trace(task_id="tsk_repair001")
        trace.model_call(
            provider="openai",
            model="gpt-5.3-codex",
            input_tokens=1234,
            output_tokens=456,
            usd=0.12,
            version="2026-08-01",
        )
        assert adapter.flush(FLUSH_TIMEOUT_S)

    (envelope,) = transport.envelopes
    assert envelope.cost.input_tokens == 1234
    assert envelope.cost.output_tokens == 456
    assert envelope.cost.usd == pytest.approx(0.12)
    assert envelope.model.provider == "openai"
    assert envelope.model.name == "gpt-5.3-codex"
    assert envelope.model.version == "2026-08-01"


def test_unversioned_model_call_is_marked_not_inherited(tmp_path: Path) -> None:
    """Attributing the adapter's version to a different model would silently
    corrupt per-release attribution."""
    transport = RecordingTransport()

    with make_adapter(tmp_path, transport) as adapter:
        trace = adapter.trace(task_id="tsk_repair001")
        trace.model_call(provider="anthropic", model="claude", input_tokens=1, output_tokens=1)
        assert adapter.flush(FLUSH_TIMEOUT_S)

    (envelope,) = transport.envelopes
    assert envelope.model.version == UNSPECIFIED_MODEL_VERSION
    assert envelope.model.version != MODEL.version


def test_non_model_events_cost_zero_rather_than_nothing(tmp_path: Path) -> None:
    """The harness sums cost across a trace to enforce equal-budget arms, so
    a tool call needs a real zero, not an absent field."""
    transport = RecordingTransport()

    with make_adapter(tmp_path, transport) as adapter:
        trace = adapter.trace(task_id="tsk_repair001")
        trace.tool_call(name="pytest", args_digest=digest(4), result_digest=digest(5))
        assert adapter.flush(FLUSH_TIMEOUT_S)

    (envelope,) = transport.envelopes
    assert envelope.cost.input_tokens == 0
    assert envelope.cost.output_tokens == 0
    assert envelope.cost.usd == 0.0


def test_artifact_digest_lands_in_the_envelope(tmp_path: Path) -> None:
    transport = RecordingTransport()

    with make_adapter(tmp_path, transport) as adapter:
        trace = adapter.trace(task_id="tsk_repair001")
        trace.artifact_loaded(digest=digest(7), kind="skill_package")
        assert adapter.flush(FLUSH_TIMEOUT_S)

    (envelope,) = transport.envelopes
    assert envelope.artifact_digests == (digest(7),)


def test_trace_exit_records_an_exception_without_swallowing_it(tmp_path: Path) -> None:
    transport = RecordingTransport()

    with make_adapter(tmp_path, transport) as adapter:
        with (
            pytest.raises(RuntimeError, match="agent exploded"),
            adapter.trace(task_id="tsk_repair001"),
        ):
            raise RuntimeError("agent exploded")
        assert adapter.flush(FLUSH_TIMEOUT_S)

    ended = [e for e in transport.envelopes if e.type == EVENT_TRACE_ENDED]
    assert len(ended) == 1


def test_emit_after_trace_close_is_a_loud_error(tmp_path: Path) -> None:
    transport = RecordingTransport()

    with make_adapter(tmp_path, transport) as adapter:
        with adapter.trace(task_id="tsk_repair001") as trace:
            pass
        with pytest.raises(RuntimeError, match="closed"):
            trace.claim_outcome(success=True)


@pytest.mark.parametrize("task_id", ["", "repair001", "tsk-repair", "tsk_repair!"])
def test_malformed_task_id_fails_at_the_call_site(tmp_path: Path, task_id: str) -> None:
    transport = RecordingTransport()

    with make_adapter(tmp_path, transport) as adapter, pytest.raises(ValueError, match="task_id"):
        adapter.trace(task_id=task_id)


@pytest.mark.parametrize("bad", ["", "deadbeef", "sha256:zz", "sha1:" + "a" * 40])
def test_malformed_digest_fails_at_the_call_site(tmp_path: Path, bad: str) -> None:
    transport = RecordingTransport()

    with make_adapter(tmp_path, transport) as adapter:
        trace = adapter.trace(task_id="tsk_repair001")
        with pytest.raises(ValueError, match="args_digest"):
            trace.tool_call(name="x", args_digest=bad, result_digest=digest(1))
        with pytest.raises(ValueError, match="result_digest"):
            trace.tool_call(name="x", args_digest=digest(1), result_digest=bad)
        with pytest.raises(ValueError, match="digest"):
            trace.artifact_loaded(digest=bad, kind="skill_package")


def test_adapter_defaults_to_the_candidate_runner_identity(tmp_path: Path) -> None:
    """Instrumentation must never be a path to evaluator privileges."""
    transport = RecordingTransport()

    with make_adapter(tmp_path, transport) as adapter:
        assert adapter.identity.role is WorkloadRole.CANDIDATE_RUNNER
        assert adapter.identity.subject == AGENT_ID


def test_full_buffer_drops_with_a_counter_and_never_blocks_emit(tmp_path: Path) -> None:
    """The D3 acceptance row, through the public surface: with delivery
    stalled the buffer fills, and every emit still returns in under 1ms."""
    transport = BlockingTransport()
    adapter = make_adapter(tmp_path, transport, buffer_max_events=32, batch_max_events=1)
    try:
        trace = adapter.trace(task_id="tsk_repair001")
        # One event to get the worker into `send`, where it stays until released.
        trace.claim_outcome(success=True)
        assert transport.entered.wait(timeout=5)

        durations = []
        for _ in range(4_000):
            start = time.perf_counter()
            trace.claim_outcome(success=True)
            durations.append(time.perf_counter() - start)

        stats = adapter.stats
        assert stats.dropped_events > 0, "a 32-event buffer must overflow under a stalled transport"
        assert stats.emitted + stats.dropped_events == 4_001
        durations.sort()
        assert durations[int(len(durations) * 0.95)] < EMIT_BLOCK_BUDGET_S
        assert max(durations) < EMIT_BLOCK_BUDGET_S * 20, "no emit may stall on the transport"
    finally:
        transport.release.set()
        adapter.close(timeout_s=FLUSH_TIMEOUT_S)


def test_delivery_retries_after_a_transport_failure(tmp_path: Path) -> None:
    transport = FailingTransport(failures=1)

    with make_adapter(tmp_path, transport) as adapter:
        trace = adapter.trace(task_id="tsk_repair001")
        trace.claim_outcome(success=True)
        deadline = time.monotonic() + FLUSH_TIMEOUT_S
        while not transport.delivered and time.monotonic() < deadline:
            adapter.flush(0.5)

    assert transport.attempts >= 2
    assert [e.type for e in transport.delivered] == [EVENT_OUTCOME_CLAIMED]
    assert adapter.stats.send_failures >= 1


def test_rejected_events_are_counted_not_retried_forever(tmp_path: Path) -> None:
    transport = RejectingTransport()

    with make_adapter(tmp_path, transport) as adapter:
        trace = adapter.trace(task_id="tsk_repair001")
        trace.claim_outcome(success=True)
        assert adapter.flush(FLUSH_TIMEOUT_S)

    stats = adapter.stats
    assert stats.rejected >= 1
    assert stats.sent == 0
    assert stats.outbox == 0


def test_close_is_idempotent_and_releases_the_transport(tmp_path: Path) -> None:
    transport = RecordingTransport()
    adapter = make_adapter(tmp_path, transport)

    adapter.close()
    adapter.close()

    assert transport.closed is True
    with pytest.raises(RuntimeError, match="closed"):
        adapter.trace(task_id="tsk_repair001")


def test_missing_journal_path_warns_that_durability_is_off(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Running without a journal is allowed but never silent — it disables
    the crash-flush guarantee the PRD requires."""
    transport = RecordingTransport()

    with caplog.at_level("WARNING"):
        adapter = Adapter(
            endpoint="http://ingest.invalid",
            agent_id=AGENT_ID,
            release_id=RELEASE_ID,
            tenant_id=TENANT_ID,
            environment_digest=ENVIRONMENT_DIGEST,
            model=MODEL,
            journal_path=None,
            transport=transport,
        )
    adapter.close()

    assert any("crash-flush durability is disabled" in record.message for record in caplog.records)


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"flush_interval_s": 0}, "flush_interval_s"),
        ({"flush_interval_s": -1.0}, "flush_interval_s"),
        ({"batch_max_events": 0}, "batch_max_events"),
    ],
)
def test_invalid_adapter_configuration_is_rejected(
    tmp_path: Path, kwargs: dict[str, float | int], match: str
) -> None:
    with pytest.raises(ValueError, match=match):
        make_adapter(tmp_path, RecordingTransport(), **kwargs)  # type: ignore[arg-type]

"""Emit overhead: the price instrumentation charges the agent thread.

Spec D3 / PRD §17.3: p95 emit overhead below 3% of the scripted fixture
workload. "Overhead" is only meaningful against a unit of agent work, so the
fixture here does a calibrated slice of deterministic CPU work per step —
roughly a tool call's worth — and every step is measured twice: once for the
work, once for the instrumentation wrapped around it.

Measuring the two phases inside a single loop, rather than comparing two
separate runs, is what makes the number trustworthy on a shared CI runner:
both samples meet the same scheduler, the same cache state, and the same
noise, so the ratio survives conditions that would wreck an A/B wall-clock
comparison.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Sequence
from pathlib import Path

import pytest

from evoruntime.sdk.adapter import Adapter, Trace
from evoruntime.sdk.transport import DiscardingIngestTransport
from tests.sdk.support import digest, make_adapter

OVERHEAD_BUDGET = 0.03
"""PRD §17.3: emitting must cost under 3% of the workload it observes."""

EMIT_BLOCK_BUDGET_S = 0.001
"""The companion bound from the same row — no emit may block the agent
thread for more than a millisecond."""

TARGET_STEP_S = 0.0015
"""Per-step work, chosen to sit near a fast tool call. Small enough to keep
the suite quick; large enough that a step is not just measurement noise."""

MEASURED_STEPS = 400
WARMUP_STEPS = 50
EVENTS_PER_STEP = 3

_PAYLOAD = b"evoruntime scripted fixture payload" * 8


def scripted_step_work(rounds: int) -> str:
    """One step of the scripted fixture agent: deterministic, allocation-light.

    A hash chain, not a sleep: sleeping would yield the CPU and hand the flush
    worker a free thread, flattering the very overhead this test measures.
    """
    accumulator = hashlib.sha256(_PAYLOAD)
    for _ in range(rounds):
        accumulator = hashlib.sha256(accumulator.digest())
    return accumulator.hexdigest()


def calibrate_rounds(target_s: float) -> int:
    """Size the step so it takes ~``target_s`` on *this* machine.

    A fixed round count would mean a fast runner measures overhead against a
    trivially small step and fails a bound it actually meets.
    """
    rounds = 64
    while rounds < 1_000_000:
        start = time.perf_counter()
        scripted_step_work(rounds)
        if time.perf_counter() - start >= target_s:
            return rounds
        rounds *= 2
    raise RuntimeError("unable to calibrate the scripted fixture step")  # pragma: no cover


def emit_step(trace: Trace, index: int) -> None:
    """The event shape a D8 coding fixture produces per step."""
    trace.model_call(
        provider="scripted",
        model="scripted-agent",
        input_tokens=1234,
        output_tokens=456,
    )
    trace.tool_call(
        name="repo_patch",
        args_digest=digest(index),
        result_digest=digest(index + 1),
    )
    trace.artifact_loaded(digest=digest(index + 2), kind="skill_package")


def percentile(samples: Sequence[float], fraction: float) -> float:
    ordered = sorted(samples)
    index = min(int(len(ordered) * fraction), len(ordered) - 1)
    return ordered[index]


@pytest.fixture(scope="module")
def rounds() -> int:
    return calibrate_rounds(TARGET_STEP_S)


def test_p95_emit_overhead_stays_under_the_budget(tmp_path: Path, rounds: int) -> None:
    adapter = make_adapter(tmp_path, DiscardingIngestTransport(), buffer_max_events=100_000)
    work_samples: list[float] = []
    emit_samples: list[float] = []

    try:
        with adapter.trace(task_id="tsk_overhead0001") as trace:
            for index in range(WARMUP_STEPS):
                scripted_step_work(rounds)
                emit_step(trace, index)

            for index in range(MEASURED_STEPS):
                start = time.perf_counter()
                scripted_step_work(rounds)
                worked = time.perf_counter()
                emit_step(trace, index)
                emitted = time.perf_counter()
                work_samples.append(worked - start)
                emit_samples.append(emitted - worked)
    finally:
        adapter.close(timeout_s=30.0)

    assert adapter.stats.dropped_events == 0, (
        "the buffer overflowed, so this measured the cheap drop path"
    )
    p95_work = percentile(work_samples, 0.95)
    p95_emit = percentile(emit_samples, 0.95)
    overhead = p95_emit / p95_work

    assert overhead < OVERHEAD_BUDGET, (
        f"p95 emit overhead {overhead:.2%} exceeds the {OVERHEAD_BUDGET:.0%} budget "
        f"(p95 emit {p95_emit * 1e6:.1f}µs over {EVENTS_PER_STEP} events, "
        f"p95 step work {p95_work * 1e6:.1f}µs)"
    )


def test_no_single_emit_blocks_the_agent_thread(tmp_path: Path, rounds: int) -> None:
    """A p95 within budget still permits a pathological tail — the agent
    thread must never stall on the flush worker, so bound the maximum too."""
    adapter = make_adapter(tmp_path, DiscardingIngestTransport(), buffer_max_events=100_000)
    samples: list[float] = []

    try:
        with adapter.trace(task_id="tsk_overhead0002") as trace:
            for index in range(WARMUP_STEPS):
                emit_step(trace, index)
            for index in range(MEASURED_STEPS):
                scripted_step_work(rounds)
                start = time.perf_counter()
                emit_step(trace, index)
                samples.append(time.perf_counter() - start)
    finally:
        adapter.close(timeout_s=30.0)

    assert max(samples) < EMIT_BLOCK_BUDGET_S, (
        f"slowest step of {EVENTS_PER_STEP} emits took {max(samples) * 1e3:.3f}ms"
    )


def test_instrumentation_does_not_slow_the_workload_end_to_end(tmp_path: Path, rounds: int) -> None:
    """The paired test proves the per-call cost; this one guards the whole
    pipeline. If the flush worker ever starved the agent thread — a lock held
    across a send, say — the per-emit numbers could stay small while total
    runtime blew up. A loose bound, because wall-clock A/B on a shared runner
    is noisy; it exists to catch a gross regression, not to grade one."""
    steps = 200

    baseline_start = time.perf_counter()
    for _ in range(steps):
        scripted_step_work(rounds)
    baseline = time.perf_counter() - baseline_start

    adapter = make_adapter(tmp_path, DiscardingIngestTransport(), buffer_max_events=100_000)
    try:
        instrumented_start = time.perf_counter()
        with adapter.trace(task_id="tsk_overhead0003") as trace:
            for index in range(steps):
                scripted_step_work(rounds)
                emit_step(trace, index)
        instrumented = time.perf_counter() - instrumented_start
    finally:
        adapter.close(timeout_s=30.0)

    assert instrumented < baseline * 1.25, (
        f"instrumented run took {instrumented:.3f}s against a {baseline:.3f}s baseline"
    )


def test_the_adapter_under_test_is_the_real_one(tmp_path: Path) -> None:
    """Guards the benchmark itself: if `make_adapter` ever returned something
    inert, every number above would be meaninglessly good."""
    adapter = make_adapter(tmp_path, DiscardingIngestTransport())
    try:
        assert isinstance(adapter, Adapter)
        with adapter.trace(task_id="tsk_overhead0004") as trace:
            emit_step(trace, 0)
        assert adapter.flush(30.0)
        assert adapter.stats.emitted >= EVENTS_PER_STEP
    finally:
        adapter.close(timeout_s=30.0)

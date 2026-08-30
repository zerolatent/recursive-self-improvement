"""§17.3 adapter-overhead harness, re-run around the fixture agent's real step loop.

The D3 harness (``tests/sdk/test_emit_overhead.py``) measured instrumentation
cost against a calibrated work slice standing in for a step. H1 names the
workload that row was waiting for: this harness keeps the same paired
measurement — work and instrumentation sampled inside one loop, so both meet
the same scheduler and cache state — but the emit side is now the fixture
agent's *actual* recording path: the per-step model call with the
prompt-version details convention and the tool call by digest, executed
through ``FixtureAgent.execute_step``/``record_step`` rather than a
test-local emit helper.

The work side pairs the calibrated model-call slice (what dominates a real
coding-agent step) with the agent's real tool work — a file read inside the
sandbox workspace — so the denominator is the workload, not a stub.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from evoruntime.core.events import CostInfo
from evoruntime.fixture_agent import FixtureAgent, ReadStep
from evoruntime.sdk.adapter import Adapter
from evoruntime.sdk.transport import DiscardingIngestTransport
from tests.sdk.support import make_adapter
from tests.sdk.test_emit_overhead import (
    BLOCK_TRIALS,
    EMIT_BLOCK_BUDGET_S,
    MEASURED_STEPS,
    OVERHEAD_BUDGET,
    TARGET_STEP_S,
    WARMUP_STEPS,
    calibrate_rounds,
    percentile,
    scripted_step_work,
)

PROMPT_VERSION = "fixture-prompt-v1"
STEP_COST = CostInfo(input_tokens=1200, output_tokens=340, usd=0.0021)
LOOP_FILE = "notes.txt"
LOOP_FILE_CONTENT = "the fixture agent's per-step read workload\n" * 8


@pytest.fixture(scope="module")
def rounds() -> int:
    return calibrate_rounds(TARGET_STEP_S)


def make_loop_agent(journal_dir: Path, transport: object) -> tuple[FixtureAgent, Adapter]:
    workspace = journal_dir / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / LOOP_FILE).write_text(LOOP_FILE_CONTENT)
    adapter = make_adapter(journal_dir, transport, buffer_max_events=100_000)
    agent = FixtureAgent(adapter, workspace, prompt_version=PROMPT_VERSION, step_cost=STEP_COST)
    return agent, adapter


def test_p95_step_overhead_stays_under_the_budget(tmp_path: Path, rounds: int) -> None:
    agent, adapter = make_loop_agent(tmp_path / "run", DiscardingIngestTransport())
    step = ReadStep(path=LOOP_FILE)
    work_samples: list[float] = []
    record_samples: list[float] = []

    try:
        with adapter.trace(task_id="tsk_overheadh101") as trace:
            for _ in range(WARMUP_STEPS):
                scripted_step_work(rounds)
                observation = agent.execute_step(step)
                agent.record_step(trace, step, observation)

            for _ in range(MEASURED_STEPS):
                start = time.perf_counter()
                scripted_step_work(rounds)
                observation = agent.execute_step(step)
                worked = time.perf_counter()
                agent.record_step(trace, step, observation)
                recorded = time.perf_counter()
                work_samples.append(worked - start)
                record_samples.append(recorded - worked)
    finally:
        adapter.close(timeout_s=30.0)

    assert adapter.stats.dropped_events == 0, (
        "the buffer overflowed, so this measured the cheap drop path"
    )
    p95_work = percentile(work_samples, 0.95)
    p95_record = percentile(record_samples, 0.95)
    overhead = p95_record / p95_work

    assert overhead < OVERHEAD_BUDGET, (
        f"p95 recording overhead {overhead:.2%} exceeds the {OVERHEAD_BUDGET:.0%} budget "
        f"(p95 record {p95_record * 1e6:.1f}µs, p95 step work {p95_work * 1e6:.1f}µs)"
    )


def test_no_single_record_blocks_the_agent_thread(tmp_path: Path, rounds: int) -> None:
    """Same best-of-trials bound as the D3 harness: emit never waits on the
    flush worker, so a real regression (a lock held across a send, a
    synchronous fsync on the emit path) breaches 1ms in every trial while
    scheduler jitter breaches it only in some."""
    trial_maxes: list[float] = []

    for trial in range(BLOCK_TRIALS):
        agent, adapter = make_loop_agent(tmp_path / f"trial-{trial}", DiscardingIngestTransport())
        samples: list[float] = []
        try:
            with adapter.trace(task_id="tsk_overheadh102") as trace:
                step = ReadStep(path=LOOP_FILE)
                for _ in range(WARMUP_STEPS):
                    observation = agent.execute_step(step)
                    agent.record_step(trace, step, observation)
                for _ in range(MEASURED_STEPS):
                    scripted_step_work(rounds)
                    observation = agent.execute_step(step)
                    start = time.perf_counter()
                    agent.record_step(trace, step, observation)
                    samples.append(time.perf_counter() - start)
        finally:
            adapter.close(timeout_s=30.0)

        assert adapter.stats.dropped_events == 0, (
            "the buffer overflowed, so this measured the cheap drop path"
        )
        trial_maxes.append(max(samples))

    best = min(trial_maxes)
    assert best < EMIT_BLOCK_BUDGET_S, (
        f"slowest step's recording took {best * 1e3:.3f}ms at best across {BLOCK_TRIALS} "
        f"trials (per-trial maxes: {[f'{m * 1e3:.3f}ms' for m in trial_maxes]})"
    )


def test_the_agent_under_test_is_the_real_one(tmp_path: Path) -> None:
    """Guards the harness: the recording path must be the agent's own, on a
    real adapter with a real journal — not an inert stand-in."""
    agent, adapter = make_loop_agent(tmp_path / "run", DiscardingIngestTransport())
    try:
        assert isinstance(adapter, Adapter)
        with adapter.trace(task_id="tsk_overheadh103") as trace:
            step = ReadStep(path=LOOP_FILE)
            observation = agent.execute_step(step)
            agent.record_step(trace, step, observation)
        assert adapter.flush(30.0)
        assert adapter.stats.emitted >= 2
    finally:
        adapter.close(timeout_s=30.0)

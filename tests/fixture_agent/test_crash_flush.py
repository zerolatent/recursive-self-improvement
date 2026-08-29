"""Crash-flush under the fixture agent's workload: §17.3 row 1 against the H1 harness.

The D3 crash-flush suite (``tests/sdk/test_crash_flush.py``) proved the
≤100-event / ≤1s loss bound against a bare emit loop. This suite re-proves it
against the workload that row actually names: the fixture agent's real step
loop — execute a tool, record the model call and the tool call — SIGKILLed
mid-stream as a real OS process, because a simulated crash would test the
simulation, not the guarantee.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest

from evoruntime.sdk.journal import recover
from tests.sdk.crash_child import read_counter
from tests.sdk.test_crash_flush import (
    LOSS_BOUND_EVENTS,
    MIN_EMITTED_BEFORE_KILL,
    count_journaled_events,
)

CHILD = Path(__file__).parent / "crash_child.py"

EMIT_RATE_HZ = 1_000.0
"""Paced so one second of events (1000) is far above the 100-event bound,
making the count the binding constraint — the harder half of "whichever
smaller"."""

STARTUP_TIMEOUT_S = 30.0


@pytest.fixture
def crashed_agent(tmp_path: Path) -> tuple[Path, int]:
    """Run the fixture agent's step loop, SIGKILL it mid-stream, return (journal, emitted)."""
    journal_path = tmp_path / "events.journal"
    counter_path = tmp_path / "emitted.count"
    workspace_root = tmp_path / "workspace"

    process = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
        [
            sys.executable,
            str(CHILD),
            str(journal_path),
            str(counter_path),
            str(EMIT_RATE_HZ),
            str(workspace_root),
        ],
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


def test_survivors_carry_the_agent_step_shape(crashed_agent: tuple[Path, int]) -> None:
    """The crash test must exercise the agent's workload, not a bare emit
    loop: the surviving events include the per-step model call and tool call
    the loop emits."""
    journal_path, _ = crashed_agent

    recovered = recover(journal_path)
    types = {record.envelope.type for record in recovered.records}

    assert {"model.completed", "tool.completed"} <= types

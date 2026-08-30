"""The fixture agent's step loop, run until SIGKILLed — crash-flush under the agent's workload.

Run as a subprocess by ``test_crash_flush.py`` (the fixture-agent one). The
same rules as ``tests/sdk/crash_child.py`` apply: SIGKILL runs no shutdown
hooks, so the emitted-event count must be readable after the process no
longer exists — an mmap'd counter, not a pipe or a print.

The workload is the agent's real step loop (execute + record per step, two
events per step: the model call with the prompt-version details body and the
tool call by digest), not a bare emit loop, so the loss bound is measured
against the workload §17.3 row 1 names.
"""

from __future__ import annotations

import mmap
import struct
import sys
import time
from pathlib import Path

from evoruntime.core.events import CostInfo, ModelInfo
from evoruntime.fixture_agent import FixtureAgent, ReadStep
from evoruntime.sdk import Adapter
from evoruntime.sdk.transport import DiscardingIngestTransport

# Self-contained by design: the child runs as a bare subprocess with no
# `tests` package on its path, so it shares nothing with the test modules —
# only the counter wire format, duplicated here deliberately.
COUNTER_STRUCT = struct.Struct("<Q")

MODEL = ModelInfo(provider="scripted", name="fixture-agent", version="2026-08-29")
ENVIRONMENT_DIGEST = f"sha256:{'ef' * 32}"
PROMPT_VERSION = "fixture-prompt-v1"
STEP_COST = CostInfo(input_tokens=1200, output_tokens=340, usd=0.0021)
EVENTS_PER_STEP = 2
LOOP_FILE = "notes.txt"
LOOP_FILE_CONTENT = "the fixture agent's per-step read workload\n" * 8


def main() -> int:
    journal_path = Path(sys.argv[1])
    counter_path = Path(sys.argv[2])
    target_rate = float(sys.argv[3])
    workspace_root = Path(sys.argv[4])

    counter_path.write_bytes(b"\x00" * COUNTER_STRUCT.size)
    with counter_path.open("r+b") as handle:
        counter = mmap.mmap(handle.fileno(), COUNTER_STRUCT.size)

    workspace_root.mkdir(parents=True, exist_ok=True)
    (workspace_root / LOOP_FILE).write_text(LOOP_FILE_CONTENT)

    adapter = Adapter(
        endpoint="http://ingest.invalid",
        agent_id="agt_crash",
        release_id="rel_crash",
        tenant_id="tnt_crash",
        environment_digest=ENVIRONMENT_DIGEST,
        model=MODEL,
        journal_path=journal_path,
        transport=DiscardingIngestTransport(),
    )
    agent = FixtureAgent(
        adapter, workspace_root, prompt_version=PROMPT_VERSION, step_cost=STEP_COST
    )
    step = ReadStep(path=LOOP_FILE)

    emitted = 0
    interval = 1.0 / target_rate
    next_emit = time.monotonic()
    with adapter.trace(task_id="tsk_crashh10001") as trace:
        while True:
            observation = agent.execute_step(step)
            agent.record_step(trace, step, observation)
            emitted += EVENTS_PER_STEP
            COUNTER_STRUCT.pack_into(counter, 0, emitted)
            next_emit += interval
            delay = next_emit - time.monotonic()
            if delay > 0:
                time.sleep(delay)


if __name__ == "__main__":  # pragma: no cover - executed only as a subprocess
    raise SystemExit(main())

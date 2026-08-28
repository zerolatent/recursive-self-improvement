"""An instrumented agent that emits until it is killed.

Run as a subprocess by `test_crash_flush.py`. Nothing here may assume a clean
shutdown: the whole point is that the process is SIGKILLed mid-stream, so the
emitted-event count has to be readable by the parent *after* the process no
longer exists.

That count lives in an mmap'd file rather than a stream or a pipe. A dirty
page of a shared file mapping belongs to the kernel's page cache, which
outlives the process that dirtied it — so the last count written before the
kill is exactly what the parent reads, with no flush the dying process never
got to perform. Writing the count through the SDK's own machinery would be
circular; writing it with `print` would buffer it into oblivion.
"""

from __future__ import annotations

import mmap
import struct
import sys
import time
from pathlib import Path

from evoruntime.core.events import ModelInfo
from evoruntime.sdk import Adapter
from evoruntime.sdk.transport import DiscardingIngestTransport

COUNTER_STRUCT = struct.Struct("<Q")
COUNTER_SIZE = COUNTER_STRUCT.size

MODEL = ModelInfo(provider="scripted", name="scripted-agent", version="2026-08-27")
ENVIRONMENT_DIGEST = f"sha256:{'cd' * 32}"


def read_counter(path: Path) -> int:
    """Read the emitted-event count a killed child left behind."""
    return int(COUNTER_STRUCT.unpack_from(path.read_bytes(), 0)[0])


def main() -> int:
    journal_path = Path(sys.argv[1])
    counter_path = Path(sys.argv[2])
    target_rate = float(sys.argv[3])

    counter_path.write_bytes(b"\x00" * COUNTER_SIZE)
    with counter_path.open("r+b") as handle:
        counter = mmap.mmap(handle.fileno(), COUNTER_SIZE)

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
    trace = adapter.trace(task_id="tsk_crash000001")

    emitted = 0
    interval = 1.0 / target_rate
    next_emit = time.monotonic()
    digest = f"sha256:{7:064x}"
    while True:
        trace.tool_call(name="repo_patch", args_digest=digest, result_digest=digest)
        emitted += 1
        COUNTER_STRUCT.pack_into(counter, 0, emitted)
        next_emit += interval
        delay = next_emit - time.monotonic()
        if delay > 0:
            time.sleep(delay)


if __name__ == "__main__":  # pragma: no cover - executed only as a subprocess
    raise SystemExit(main())

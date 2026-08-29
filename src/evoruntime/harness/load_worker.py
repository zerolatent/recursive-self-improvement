"""Candidate-execution worker subprocess for the H8 load harness.

One worker process hosts ``--executions`` concurrent candidate executions
(threads). Each execution owns an adapter SDK ``Adapter`` with its own
journal and drives ``tool_call`` emissions through the real HTTP ingest
endpoint served by a real evaluation-plane process — the same path a
fixture coding agent (H1) uses.

Recovery semantics: every event is journaled (fsync'd) before it is sent
and acknowledged after the server confirms, so a worker the parent
SIGKILLs loses at most the un-journaled buffer window (tightened to ~one
event via ``fsync_max_events=1``). A respawned worker with the same
``--journal-dir`` replays every journaled-but-unacknowledged event at
adapter construction and emits only the not-yet-emitted remainder (read
from the fsync'd progress file), so the parent's delivered-vs-emitted
accounting counts the kill's true loss and nothing else.

Progress accounting uses the SDK's durability boundary, not the emit
call site: an event is "emitted" once the adapter has fsync'd it to the
journal (``Adapter.stats.journaled``), because that is the point the
SDK's crash-flush contract protects. Counting ``trace.tool_call()``
invocations instead would race the background flusher — under load the
buffer holds hundreds of not-yet-journaled events, and a SIGKILL there
would look like ingest loss when it is buffer loss the SDK never
promised. A reporter thread publishes the journaled total to the
progress file every ``PROGRESS_INTERVAL_S``; the parent's kill probe and
emitted accounting read only that file.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from collections.abc import Sequence
from pathlib import Path

from evoruntime.core.events import EventEnvelope, ModelInfo
from evoruntime.sdk.adapter import Adapter
from evoruntime.sdk.transport import HttpIngestTransport, IngestResult
from evoruntime.security.identities import WorkloadIdentity, WorkloadRole

PROGRESS_INTERVAL_S = 0.05
MODEL = ModelInfo(provider="scripted", name="h8-load-worker", version="2026-08-29")
ENVIRONMENT_DIGEST = f"sha256:{'ab' * 32}"


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--subject", required=True)
    parser.add_argument("--events", required=True, type=int)
    parser.add_argument("--executions", required=True, type=int)
    parser.add_argument("--journal-dir", required=True, type=Path)
    parser.add_argument("--latency-path", required=True, type=Path)
    parser.add_argument("--progress-path", required=True, type=Path)
    return parser.parse_args(argv)


class TimedTransport(HttpIngestTransport):
    """Ingest transport that records per-batch client-side latency.

    The latency record is what the parent's ingest-p99 measurement reads;
    ``ts`` is wall-clock so the parent can attribute entries to the worker
    generation that wrote them (pre- vs post-kill).
    """

    def __init__(
        self,
        endpoint: str,
        *,
        tenant_id: str,
        identity: WorkloadIdentity,
        latency_path: Path,
        lock: threading.Lock,
    ) -> None:
        super().__init__(endpoint, tenant_id=tenant_id, identity=identity)
        self._latency_path = latency_path
        self._lock = lock

    def send(self, envelopes: Sequence[EventEnvelope]) -> IngestResult:
        started = time.perf_counter()
        result = super().send(envelopes)
        latency_s = time.perf_counter() - started
        line = json.dumps({"ts": time.time(), "latency_s": latency_s, "batch": len(envelopes)})
        with self._lock, self._latency_path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
        return result


def _read_progress(progress_path: Path) -> int:
    if not progress_path.exists():
        return 0
    lines = [line for line in progress_path.read_text(encoding="utf-8").splitlines() if line]
    return int(lines[-1]) if lines else 0


def _append_progress(progress_path: Path, emitted: int) -> None:
    with progress_path.open("a", encoding="utf-8") as f:
        f.write(f"{emitted}\n")
        f.flush()
        os.fsync(f.fileno())


def main(argv: list[str]) -> int:
    args = _parse_args(argv)
    args.journal_dir.mkdir(parents=True, exist_ok=True)

    emitted_before = _read_progress(args.progress_path)
    remaining = args.events - emitted_before

    identity = WorkloadIdentity(role=WorkloadRole.CANDIDATE_RUNNER, subject=args.subject)
    latency_lock = threading.Lock()
    adapters: list[Adapter] = []
    adapters_lock = threading.Lock()
    closed_journaled = 0
    closed_lock = threading.Lock()
    stop_reporter = threading.Event()

    def make_adapter(execution_index: int) -> Adapter:
        adapter = Adapter(
            endpoint=args.endpoint,
            agent_id=args.agent_id,
            release_id="rel_H8Load",
            tenant_id=args.tenant_id,
            environment_digest=ENVIRONMENT_DIGEST,
            model=MODEL,
            buffer_max_events=2_000,
            flush_interval_s=0.05,
            # Small batches keep per-request latency representative of an
            # interactive candidate: the server commits each event in its
            # own transaction, so a 100-event batch spends ~0.4s in service
            # and 8 concurrent workers queue behind each other into p99
            # territory that reflects client batching, not ingest speed.
            batch_max_events=25,
            journal_path=args.journal_dir / f"exec_{execution_index}.journal",
            journal_fsync_max_events=1,
            journal_fsync_interval_s=0.01,
            transport=TimedTransport(
                args.endpoint,
                tenant_id=args.tenant_id,
                identity=identity,
                latency_path=args.latency_path,
                lock=latency_lock,
            ),
        )
        with adapters_lock:
            adapters.append(adapter)
        return adapter

    def durable_emitted() -> int:
        """Events this worker generation has fsync'd to its journals."""
        with adapters_lock:
            open_total = sum(a.stats.journaled for a in adapters)
        with closed_lock:
            return closed_journaled + open_total

    def report_progress() -> None:
        while not stop_reporter.is_set():
            _append_progress(args.progress_path, emitted_before + durable_emitted())
            stop_reporter.wait(PROGRESS_INTERVAL_S)

    def run_execution(execution_index: int, count: int) -> None:
        # Even a zero-share execution must construct its adapter: journal
        # replay of a killed prior generation happens at construction.
        nonlocal closed_journaled
        adapter = make_adapter(execution_index)
        try:
            if count <= 0:
                return
            with adapter.trace(f"tsk_exec{execution_index}") as trace:
                for i in range(count):
                    trace.tool_call(
                        name="load_probe_step",
                        args_digest=f"sha256:{(execution_index * 1_000_003 + i):064x}",
                        result_digest=f"sha256:{(execution_index * 1_000_003 + i + 1):064x}",
                    )
        finally:
            adapter.close()
            with closed_lock:
                closed_journaled += adapter.stats.journaled
            with adapters_lock:
                adapters.remove(adapter)

    # Split the remaining events across executions; the remainder goes to
    # the first threads so the total is exact.
    base = remaining // args.executions
    extra = remaining - base * args.executions
    shares = [base + (1 if i < extra else 0) for i in range(args.executions)]

    reporter = threading.Thread(target=report_progress, name="h8-progress")
    reporter.start()
    threads = [
        threading.Thread(target=run_execution, args=(i, shares[i]), name=f"h8-exec-{i}")
        for i in range(args.executions)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    stop_reporter.set()
    reporter.join()

    _append_progress(args.progress_path, emitted_before + durable_emitted())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

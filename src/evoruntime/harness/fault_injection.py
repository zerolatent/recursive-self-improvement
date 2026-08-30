"""Sustained fault-injection loss-rate runner (§17.3 row 1, H8).

Extends the D2 fault-injection test's structure (real Postgres, SIGKILL,
idempotent resume) into a sustained N-writer × M-event run with periodic
kills, measuring the delivered/expected loss rate against the ≤0.01% SLO.
Each writer owns one tenant (its own hash chain, its own advisory-lock
serialization lane) and ingests a per-writer JSONL fixture through the
real ``ingest_envelope`` path as a genuine OS subprocess.

Kill policy: once a live writer has durably committed
``kill_every_committed_events`` more events since its last kill (and it
still has kills left), the runner SIGKILLs it and immediately respawns it
with the same fixture — the writer's duplicate-skip makes the resume
idempotent, so the measured loss is exactly what the durability model
predicts: at most the one in-flight event per kill, and zero after resume.

The run fails loudly if the deadline passes before every event is
delivered — a loss number computed over an incomplete run would
understate delivery, so it is never reported.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import delete

from evoruntime.db.base import build_engine, build_session_factory
from evoruntime.db.chain_verification import verify_chain
from evoruntime.db.models.events import Event
from evoruntime.harness.profiles import FaultInjectionProfile

POLL_INTERVAL_S = 0.05
#: A SIGKILLed writer must exit promptly; anything else means the kill did
#: not land and the run is invalid.
KILL_WAIT_S = 10.0
#: Progress files only ever grow by appends, so the last line lives in the
#: final few KiB — tail-reading keeps per-poll cost constant even when a
#: soak writer has logged over a million progress records.
PROGRESS_TAIL_BYTES = 4096


class LossRateRunError(RuntimeError):
    """The runner could not complete a valid measurement."""


@dataclass(frozen=True)
class LossRateResult:
    """Measured outcome of one sustained fault-injection run."""

    profile_name: str
    writers: int
    expected_events: int
    delivered_events: int
    lost_events: int
    loss_rate: float
    kills_executed: int
    chain_valid: bool
    duration_s: float

    def within_slo(self, max_loss_rate: float = 0.0001) -> bool:
        """True when the measured loss rate is inside the ≤0.01% SLO."""
        return self.loss_rate <= max_loss_rate


def make_raw_event(index: int, *, tenant_id: str, writer_index: int) -> dict[str, Any]:
    """A valid raw envelope, unique per (writer, index) across runs.

    Mirrors the D2 test factory's shape (``tests`` is not importable from
    ``src``). The event id folds in the writer index and a per-run nonce so
    concurrent writers — and repeated runs against the shared database —
    never collide on the globally-unique ``event_id``.
    """
    digest = f"sha256:{index:064x}"
    tenant_suffix = "".join(ch for ch in tenant_id if ch.isalnum())
    return {
        "event_id": f"evt_{tenant_suffix}w{writer_index:03d}e{index:010d}",
        "occurred_at": (datetime(2026, 8, 29, tzinfo=UTC) + timedelta(seconds=index)).isoformat(),
        "tenant_id": tenant_id,
        "agent_id": "agt_h8load",
        "release_id": "rel_h8soak",
        "campaign_id": None,
        "trace_id": f"trc_w{writer_index:03d}e{index:010d}",
        "task_id": f"tsk_w{writer_index:03d}e{index:010d}",
        "type": "tool.completed",
        "schema_version": 1,
        "artifact_digests": [digest],
        "model": {"provider": "scripted", "name": "h8-writer", "version": "2026-08-29"},
        "environment_digest": digest,
        "cost": {"input_tokens": 10, "output_tokens": 5, "usd": 0.0},
        "data_classification": "internal",
        "payload_uri": f"object://traces/w{writer_index}/{index}",
        "payload_digest": digest,
    }


def _write_fixture(
    path: Path, *, tenant_id: str, writer_index: int, run_nonce: str, count: int
) -> None:
    with path.open("w", encoding="utf-8") as f:
        for i in range(count):
            raw = make_raw_event(i, tenant_id=tenant_id, writer_index=writer_index)
            # The nonce keeps event ids unique across runs even if a prior
            # run crashed before its cleanup deleted its rows.
            raw["event_id"] = raw["event_id"].replace("evt_", f"evt_{run_nonce}", 1)
            f.write(json.dumps(raw))
            f.write("\n")


def _read_progress(progress_path: Path) -> int:
    """Last (largest) processed count the writer fsync'd, or 0 if none yet."""
    if not progress_path.exists():
        return 0
    with progress_path.open("rb") as f:
        f.seek(0, os.SEEK_END)
        f.seek(max(0, f.tell() - PROGRESS_TAIL_BYTES))
        tail = f.read().decode("utf-8", errors="replace")
    lines = [line for line in tail.splitlines() if line.strip()]
    return int(lines[-1]) if lines else 0


def _spawn_writer(
    *, database_url: str, fixture_path: Path, progress_path: Path
) -> subprocess.Popen[bytes]:
    return subprocess.Popen(  # noqa: S603 - fixed argv, no shell, harness-controlled
        [
            sys.executable,
            "-m",
            "evoruntime.harness.writer",
            f"--database-url={database_url}",
            f"--fixture-path={fixture_path}",
            f"--progress-path={progress_path}",
        ]
    )


def run_loss_rate_probe(
    *,
    database_url: str,
    profile: FaultInjectionProfile,
    workdir: Path,
    tenant_prefix: str | None = None,
    cleanup: bool = True,
) -> LossRateResult:
    """Run the sustained N×M fault-injection probe and measure event loss.

    Writes one fixture per writer under ``workdir``, drives all writers
    with periodic SIGKILL + resume until every event is delivered (the
    profile's deadline raises ``LossRateRunError`` instead of reporting a
    partial number), then counts delivered events per tenant and verifies
    each tenant's hash chain.
    """
    started = time.monotonic()
    engine = build_engine(database_url)
    session_factory = build_session_factory(engine)
    nonce = uuid.uuid4().hex[:8]
    prefix = tenant_prefix or f"tnt_H8fi{nonce}"
    tenants = [f"{prefix}{i}" for i in range(profile.writers)]
    procs: list[subprocess.Popen[bytes]] = []

    try:
        fixtures: list[Path] = []
        progress_paths: list[Path] = []
        for i, tenant_id in enumerate(tenants):
            fixture_path = workdir / f"fixture_{i}.jsonl"
            _write_fixture(
                fixture_path,
                tenant_id=tenant_id,
                writer_index=i,
                run_nonce=nonce,
                count=profile.events_per_writer,
            )
            fixtures.append(fixture_path)
            progress_paths.append(workdir / f"progress_{i}.log")

        procs = [
            _spawn_writer(
                database_url=database_url,
                fixture_path=fixtures[i],
                progress_path=progress_paths[i],
            )
            for i in range(profile.writers)
        ]
        kills_done = [0] * profile.writers
        total_kills = 0
        finished = [False] * profile.writers

        deadline = started + profile.deadline_s
        while not all(finished):
            if time.monotonic() > deadline:
                raise LossRateRunError(
                    f"fault-injection run exceeded its {profile.deadline_s}s deadline; "
                    f"{finished.count(False)} writer(s) unfinished"
                )
            for i, proc in enumerate(procs):
                if finished[i]:
                    continue
                code = proc.poll()
                if code is not None:
                    if code != 0:
                        raise LossRateRunError(
                            f"writer {i} exited with code {code} without a harness kill — "
                            "the runner only tolerates harness-injected kills"
                        )
                    finished[i] = True
                    continue

                committed = _read_progress(progress_paths[i])
                next_kill_threshold = (kills_done[i] + 1) * profile.kill_every_committed_events
                due_for_kill = (
                    kills_done[i] < profile.max_kills_per_writer
                    and committed >= next_kill_threshold
                    # Never kill a writer that has already finished its
                    # fixture — that would not be a mid-batch kill.
                    and committed < profile.events_per_writer
                )
                if due_for_kill:
                    os.kill(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=KILL_WAIT_S)
                    kills_done[i] += 1
                    total_kills += 1
                    procs[i] = _spawn_writer(
                        database_url=database_url,
                        fixture_path=fixtures[i],
                        progress_path=progress_paths[i],
                    )
            time.sleep(POLL_INTERVAL_S)

        duration_s = time.monotonic() - started

        delivered = 0
        chain_valid = True
        with session_factory() as session:
            for tenant_id in tenants:
                result = verify_chain(session, tenant_id)
                chain_valid = chain_valid and result.valid
                delivered += result.event_count

        expected = profile.total_events
        lost = expected - delivered
        return LossRateResult(
            profile_name=profile.name,
            writers=profile.writers,
            expected_events=expected,
            delivered_events=delivered,
            lost_events=lost,
            loss_rate=lost / expected if expected else 0.0,
            kills_executed=total_kills,
            chain_valid=chain_valid,
            duration_s=duration_s,
        )
    finally:
        for proc in procs:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=KILL_WAIT_S)
        if cleanup:
            with engine.begin() as conn:
                conn.execute(delete(Event).where(Event.tenant_id.in_(tenants)))
        engine.dispose()

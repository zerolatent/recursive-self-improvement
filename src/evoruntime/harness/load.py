"""Concurrent-candidate load harness (§17.3 row 9, H8).

Drives ``candidate_processes × executions_per_process`` concurrent
candidate executions against a *real* evaluation-plane HTTP server, each
emitting through the adapter SDK's production path (journal → HTTP ingest
→ per-tenant hash chain), and measures the three row-9 quantities:

- **ingest p99** — client-side per-batch latency at the ingest boundary
  (send → server ack), nearest-rank percentile over every batch;
- **loss** — emitted (worker progress at the SDK's journal durability
  boundary, fsync'd) vs delivered (server-side event count), including
  any loss the recovery probe's SIGKILL caused. Replay can deliver a few
  events journaled during the progress reporter's lag window, so
  delivered may slightly exceed emitted; that is recovery working, not
  negative loss, and the accounting clamps at zero.
- **single-worker recovery** — wall-clock from SIGKILL of one worker to
  its respawned replacement delivering again (journal replay), against
  the ≤10-minute threshold.

The server is a genuine ``uvicorn`` subprocess of
``evoruntime.server.app:create_app`` against the configured database, so
the measured latency includes HTTP, validation, and the per-event-commit
ingest path — not an in-process test double.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

from sqlalchemy import delete, func, select

from evoruntime.db.base import build_engine, build_session_factory
from evoruntime.db.models.events import Event
from evoruntime.harness.profiles import LoadProfile

POLL_INTERVAL_S = 0.05
HEALTH_TIMEOUT_S = 60.0
KILL_WAIT_S = 10.0


class LoadRunError(RuntimeError):
    """The load run could not complete a valid measurement."""


@dataclass(frozen=True)
class LoadResult:
    """Measured outcome of one concurrent-candidate load run."""

    profile_name: str
    concurrent_executions: int
    emitted_events: int
    delivered_events: int
    lost_events: int
    loss_rate: float
    ingest_p50_s: float
    ingest_p99_s: float
    recovery_s: float | None
    duration_s: float

    def within_thresholds(self, profile: LoadProfile) -> bool:
        """True when p99, loss, and recovery are inside the §17.3 bounds."""
        p99_ok = self.ingest_p99_s <= profile.max_ingest_p99_s
        loss_ok = self.loss_rate <= profile.max_loss_rate
        recovery_ok = profile.kill_worker_index is None or (
            self.recovery_s is not None and self.recovery_s <= profile.recovery_deadline_s
        )
        return p99_ok and loss_ok and recovery_ok


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_health(endpoint: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urlopen(endpoint + "/healthz", timeout=2.0) as response:  # noqa: S310 - fixed localhost URL
                if response.status == 200:
                    return
        except (URLError, OSError) as exc:
            last_error = exc
        time.sleep(0.1)
    raise LoadRunError(f"evaluation-plane server never became healthy: {last_error}")


def _read_progress(progress_path: Path) -> int:
    if not progress_path.exists():
        return 0
    lines = [line for line in progress_path.read_text(encoding="utf-8").splitlines() if line]
    return int(lines[-1]) if lines else 0


def _read_latencies(latency_path: Path) -> list[float]:
    if not latency_path.exists():
        return []
    return [
        float(json.loads(line)["latency_s"])
        for line in latency_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _first_latency_after(latency_path: Path, wall_clock: float) -> float | None:
    """Timestamp of the first batch the worker delivered after ``wall_clock``."""
    if not latency_path.exists():
        return None
    for line in latency_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        if float(record["ts"]) >= wall_clock:
            return float(record["ts"])
    return None


def _nearest_rank(values: list[float], percentile: float) -> float:
    if not values:
        raise LoadRunError("no latency samples recorded — cannot compute a percentile")
    ordered = sorted(values)
    rank = max(1, -(-int(percentile * 100) * len(ordered) // 100))
    return ordered[min(rank, len(ordered)) - 1]


def _spawn_worker(
    *,
    endpoint: str,
    tenant_id: str,
    worker_index: int,
    profile: LoadProfile,
    workdir: Path,
) -> subprocess.Popen[bytes]:
    return subprocess.Popen(  # noqa: S603 - fixed argv, no shell, harness-controlled
        [
            sys.executable,
            "-m",
            "evoruntime.harness.load_worker",
            f"--endpoint={endpoint}",
            f"--tenant-id={tenant_id}",
            f"--agent-id=agt_H8Load{worker_index}",
            f"--subject=svc_h8_worker_{worker_index}",
            f"--events={profile.events_per_execution * profile.executions_per_process}",
            f"--executions={profile.executions_per_process}",
            f"--journal-dir={workdir / f'journals_{worker_index}'}",
            f"--latency-path={workdir / f'latency_{worker_index}.jsonl'}",
            f"--progress-path={workdir / f'progress_{worker_index}.log'}",
        ]
    )


def run_load_probe(
    *,
    database_url: str,
    profile: LoadProfile,
    workdir: Path,
    tenant_prefix: str | None = None,
    cleanup: bool = True,
) -> LoadResult:
    """Run the concurrent-candidate load probe and measure p99/loss/recovery."""
    started = time.monotonic()
    nonce = uuid.uuid4().hex[:8]
    prefix = tenant_prefix or f"tnt_H8load{nonce}"
    tenants = [f"{prefix}{i}" for i in range(profile.candidate_processes)]
    port = _free_port()
    endpoint = f"http://127.0.0.1:{port}"

    server_env = dict(os.environ)
    server_env["EVORUNTIME_DATABASE_URL"] = database_url
    server = subprocess.Popen(  # noqa: S603 - fixed argv, no shell, harness-controlled
        [
            sys.executable,
            "-m",
            "uvicorn",
            "evoruntime.server.app:create_app",
            "--factory",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        env=server_env,
    )
    workers: list[subprocess.Popen[bytes]] = []
    killed = False
    kill_time = 0.0
    respawn_time = 0.0

    try:
        _wait_for_health(endpoint, HEALTH_TIMEOUT_S)

        workers = [
            _spawn_worker(
                endpoint=endpoint,
                tenant_id=tenants[i],
                worker_index=i,
                profile=profile,
                workdir=workdir,
            )
            for i in range(profile.candidate_processes)
        ]
        finished = [False] * profile.candidate_processes
        deadline = started + profile.deadline_s

        while not all(finished):
            if time.monotonic() > deadline:
                raise LoadRunError(
                    f"load run exceeded its {profile.deadline_s}s deadline; "
                    f"{finished.count(False)} worker(s) unfinished"
                )
            for i, worker in enumerate(workers):
                if finished[i]:
                    continue
                code = worker.poll()
                if code is not None:
                    if code != 0:
                        raise LoadRunError(
                            f"worker {i} exited with code {code} without a harness kill"
                        )
                    finished[i] = True
                    continue

                # Single-worker recovery probe: SIGKILL the designated
                # worker mid-run, then respawn it with the same journals.
                if (
                    profile.kill_worker_index == i
                    and not killed
                    and _read_progress(workdir / f"progress_{i}.log") >= profile.kill_after_events
                ):
                    kill_time = time.time()
                    os.kill(worker.pid, signal.SIGKILL)
                    worker.wait(timeout=KILL_WAIT_S)
                    workers[i] = _spawn_worker(
                        endpoint=endpoint,
                        tenant_id=tenants[i],
                        worker_index=i,
                        profile=profile,
                        workdir=workdir,
                    )
                    respawn_time = time.time()
                    killed = True
            time.sleep(POLL_INTERVAL_S)

        duration_s = time.monotonic() - started

        if profile.kill_worker_index is not None and not killed:
            raise LoadRunError(
                f"recovery probe never fired: worker {profile.kill_worker_index} never "
                f"reached {profile.kill_after_events} emitted events"
            )

        latencies: list[float] = []
        for i in range(profile.candidate_processes):
            latencies.extend(_read_latencies(workdir / f"latency_{i}.jsonl"))
        ingest_p50_s = _nearest_rank(latencies, 0.50)
        ingest_p99_s = _nearest_rank(latencies, 0.99)

        recovery_s: float | None = None
        if killed:
            first_delivery = _first_latency_after(
                workdir / f"latency_{profile.kill_worker_index}.jsonl", respawn_time
            )
            if first_delivery is None:
                raise LoadRunError("respawned worker never delivered a batch after recovery")
            recovery_s = first_delivery - kill_time

        emitted = sum(
            _read_progress(workdir / f"progress_{i}.log")
            for i in range(profile.candidate_processes)
        )

        engine = build_engine(database_url)
        try:
            with build_session_factory(engine)() as session:
                delivered = int(
                    session.execute(
                        select(func.count()).select_from(Event).where(Event.tenant_id.in_(tenants))
                    ).scalar_one()
                )
        finally:
            engine.dispose()

        # Delivered can exceed the progress-file emitted count by the few
        # events journaled between the reporter's last write and a SIGKILL —
        # replay recovers them. That is not negative loss.
        lost = max(0, emitted - delivered)
        return LoadResult(
            profile_name=profile.name,
            concurrent_executions=profile.concurrent_executions,
            emitted_events=emitted,
            delivered_events=delivered,
            lost_events=lost,
            loss_rate=lost / emitted if emitted else 0.0,
            ingest_p50_s=ingest_p50_s,
            ingest_p99_s=ingest_p99_s,
            recovery_s=recovery_s,
            duration_s=duration_s,
        )
    finally:
        for worker in workers:
            if worker.poll() is None:
                worker.kill()
                worker.wait(timeout=KILL_WAIT_S)
        if server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=KILL_WAIT_S)
            except subprocess.TimeoutExpired:  # pragma: no cover - defensive
                server.kill()
                server.wait(timeout=KILL_WAIT_S)
        if cleanup:
            engine = build_engine(database_url)
            try:
                with engine.begin() as conn:
                    conn.execute(delete(Event).where(Event.tenant_id.in_(tenants)))
            finally:
                engine.dispose()

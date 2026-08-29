"""The dev-evaluate execution worker (H4): the sandbox's first production
construction site.

The worker is orchestration, not policy: the lifecycle rules, the isolation
tiers, and the attestation semantics all live in the planes it composes
(the E3 machine, the F1 sandbox, the E1 payload store). What the worker adds
is what a long-lived *process* needs and a one-shot test call does not:

* **Backend selection at construction** (H9 seam). The backend is resolved
  exactly once — from the explicit environment name, or from
  ``EVO_ISOLATION_BACKEND`` when none is given — and a known-but-unavailable
  or unknown environment refuses at construction. The worker never comes up
  able to run unisolated.

* **Stale-workspace reclamation.** A worker killed mid-run leaves its staged
  workspace behind. The worker stages into its *own* scratch root and, at
  the start of every run, sweeps that root for workspaces older than a TTL —
  reclaiming crashed runs' disk without ever touching a workspace another
  live run may be using (fresh entries are left alone).

* **Egress-proxy lifecycle verification.** For brokered runs the attestation
  records the proxy's loopback port; the worker's report is the place an
  operator (and the conformance slice) confirms the proxy that mediated the
  run is gone when the run ends.

* **Capture-partial-failure policy.** The backend records per-path capture
  failures instead of discarding the attestation; the worker owns the
  policy: a partial capture is never a success — the run reports
  ``capture_partial_failure`` and :func:`dev_evaluate_verdict` maps it to a
  failing dev-evaluate outcome. Fail-closed at the layer that decides.

Refusals are surfaced, never swallowed: a fail-closed sandbox refusal
(:class:`ExecutionRefusedError` and subclasses) reports as ``refused`` with
the reason intact — the worker's job is to make the refusal *operational*
(a report an operator can act on), not to retry past it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from evoruntime.plugins.protocol import CheckpointStore
from evoruntime.sandbox.backend import IsolationBackend
from evoruntime.sandbox.profile import (
    ExecutionRefusedError,
    ExecutionRequest,
    ExecutionResult,
    SandboxError,
)
from evoruntime.sandbox.selection import resolve_isolation_backend
from evoruntime.sandbox.staging import STAGED_WORKSPACE_PREFIX, PayloadReader, StagedWorkspace

#: Default age at which a scratch-root entry is considered abandoned. A
#: workspace younger than this may belong to a concurrently running worker —
#: sweeping it would pull the floor out from under a live run.
DEFAULT_STALE_WORKSPACE_TTL_SECONDS = 3600.0


class WorkerOutcome(StrEnum):
    """What one worker run concluded."""

    COMPLETED = "completed"
    CAPTURE_PARTIAL_FAILURE = "capture_partial_failure"
    REFUSED = "refused"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class WorkerRunReport:
    """The operational record of one worker run.

    ``result`` is present whenever the sandbox executed the request (even a
    partial capture executed); ``error`` carries the surfaced refusal or
    failure reason when it did not. ``reclaimed_workspaces`` names the
    scratch-root entries reclaimed as stale before this run staged.
    """

    outcome: WorkerOutcome
    result: ExecutionResult | None
    error: str | None
    reclaimed_workspaces: tuple[str, ...]

    @property
    def attestation_digest(self) -> str | None:
        """The run's attestation digest, when the sandbox executed."""
        return self.result.attestation_digest if self.result is not None else None


def sweep_stale_workspaces(
    scratch_root: Path,
    *,
    max_age_seconds: float,
    now: float | None = None,
) -> tuple[str, ...]:
    """Reclaim staged workspaces abandoned by crashed runs.

    Only entries under ``scratch_root`` carrying the staged-workspace prefix
    and older than ``max_age_seconds`` (by mtime) are removed — anything
    fresh may be a live run's workspace, and sweeping it would be the
    worker sabotaging itself. Returns the reclaimed directory names.
    """
    current = time.time() if now is None else now
    reclaimed: list[str] = []
    if not scratch_root.is_dir():
        return tuple(reclaimed)
    for entry in scratch_root.iterdir():
        if not entry.name.startswith(STAGED_WORKSPACE_PREFIX) or not entry.is_dir():
            continue
        try:
            age = current - entry.stat().st_mtime
        except OSError:
            continue  # raced with a concurrent sweep; the next pass re-checks
        if age >= max_age_seconds:
            StagedWorkspace(entry).cleanup()
            reclaimed.append(entry.name)
    return tuple(reclaimed)


def dev_evaluate_verdict(report: WorkerRunReport) -> tuple[str, dict[str, float]]:
    """Map a worker report to the dev-evaluate outcome it should record.

    The harness-facing glue: the E3 machine's ``dev_evaluate`` phase records
    a pass/fail outcome with metrics, and this is the single place the
    worker's operational outcomes become that verdict. Fail-closed by
    construction: only a completed run with exit 0, no capture failures, and
    no timeout records ``pass`` — everything else fails, with the reason in
    the metrics where the attestation trail can be followed.
    """
    result = report.result
    if report.outcome is not WorkerOutcome.COMPLETED or result is None:
        metrics = {"worker_failure": 1.0}
        if result is not None:
            metrics["capture_failures"] = float(len(result.capture_failures))
        return "fail", metrics
    exit_ok = result.exit_code == 0 and result.signal_name is None and not result.timed_out
    if not exit_ok or result.capture_failures:
        return "fail", {
            "exit_code": float(result.exit_code if result.exit_code is not None else -1),
            "capture_failures": float(len(result.capture_failures)),
            "timed_out": 1.0 if result.timed_out else 0.0,
        }
    return "pass", {"duration_seconds": result.duration_seconds}


class DevEvaluateWorker:
    """The service-side worker driving dev-evaluate through the sandbox.

    Constructed with the E1 payload reader and checkpoint store the sandbox
    composes around, plus a scratch root it owns. The isolation backend is
    resolved once, at construction, through the H9 seam — a deployment that
    cannot construct its declared backend fails here, at startup, not at
    the first candidate.
    """

    def __init__(
        self,
        *,
        payloads: PayloadReader,
        checkpoints: CheckpointStore,
        scratch_root: Path,
        backend_environment: str | None = None,
        stale_workspace_ttl_seconds: float = DEFAULT_STALE_WORKSPACE_TTL_SECONDS,
    ) -> None:
        self._payloads = payloads
        self._checkpoints = checkpoints
        self._scratch_root = scratch_root
        self._stale_workspace_ttl_seconds = stale_workspace_ttl_seconds
        scratch_root.mkdir(parents=True, exist_ok=True)
        # The H9 seam: environment → backend, fail-closed in both directions
        # (unknown name refuses; known-but-unavailable refuses). This is the
        # single production construction point for an isolation backend;
        # ``None`` defers to EVO_ISOLATION_BACKEND inside the seam.
        self._backend: IsolationBackend = resolve_isolation_backend(
            backend_environment,
            payloads=payloads,
            checkpoints=checkpoints,
        )

    @property
    def scratch_root(self) -> Path:
        """The worker-owned scratch root its staged workspaces live under."""
        return self._scratch_root

    @property
    def backend(self) -> IsolationBackend:
        """The resolved isolation backend (exposed for the conformance slice)."""
        return self._backend

    def run(self, request: ExecutionRequest) -> WorkerRunReport:
        """Run one sandboxed execution, handling the operational failure modes.

        Stale workspaces are reclaimed first, the run is driven through the
        resolved backend, and every terminal state — completed, partial
        capture, refused, failed — is reported, never swallowed.
        """
        reclaimed = sweep_stale_workspaces(
            self._scratch_root, max_age_seconds=self._stale_workspace_ttl_seconds
        )
        try:
            result = self._backend.run(request)
        except SandboxError as exc:
            # Fail-closed refusals (text-only tier, unavailable enforcement)
            # and staging failures are surfaced, not swallowed: the report
            # carries the reason and the caller records the failure.
            outcome = (
                WorkerOutcome.REFUSED
                if isinstance(exc, ExecutionRefusedError)
                else WorkerOutcome.FAILED
            )
            return WorkerRunReport(
                outcome=outcome,
                result=None,
                error=f"{type(exc).__name__}: {exc}",
                reclaimed_workspaces=reclaimed,
            )
        outcome = (
            WorkerOutcome.COMPLETED
            if not result.capture_failures
            else WorkerOutcome.CAPTURE_PARTIAL_FAILURE
        )
        return WorkerRunReport(
            outcome=outcome,
            result=result,
            error=None,
            reclaimed_workspaces=reclaimed,
        )

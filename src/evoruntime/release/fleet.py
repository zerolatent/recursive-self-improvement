"""The FleetAdapter interface and the in-process fleet simulator.

Phase 1 defines the fleet abstraction — resolve manifest, report digest,
pin session, invalidate caches — and ships an in-process simulator as its
reference implementation and test harness. Real fleet wiring (Kubernetes
rollout, edge cache invalidation) is deployment-specific and out of scope
(locked decision #5); the machinery it must satisfy is fully built here
and exercised by the simulator.

The simulator models what FR-012's thresholds are measured against:

- **workers with stale caches** — each worker holds a cached manifest
  digest and re-resolves only after its own convergence latency elapses
  past a cache invalidation, so convergence is a distribution, not an
  instant, and p99 convergence is a measurable quantity.
- **sessions pinned to one manifest** — a session is pinned at creation
  and refuses to re-pin; mid-flight it keeps resolving its pinned digest
  even after the pointer moves.
- **digest reporting** — every session reports the digest it resolved,
  and a report contradicting the session's own resolution is refused:
  the fleet's honesty check, not just telemetry.
- **namespaced candidate state** — sessions carry an arm; candidate
  sessions write into the candidate namespace only, and an attempt to
  write incumbent memory from a candidate session is refused.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Literal, Protocol

from evoruntime.release.clock import MonotonicClock
from evoruntime.release.errors import (
    DigestReportingError,
    NamespaceViolationError,
    SessionPinError,
    UnknownSessionError,
)

SessionArm = Literal["incumbent", "candidate"]
"""Which side of the canary a session serves. The arm decides the session's
memory namespace: candidate sessions write candidate state only."""

INCUMBENT_NAMESPACE = "incumbent"
CANDIDATE_NAMESPACE = "candidate"


def _arm_namespace(arm: SessionArm) -> str:
    """The only memory namespace a session of ``arm`` may write into."""
    return CANDIDATE_NAMESPACE if arm == "candidate" else INCUMBENT_NAMESPACE


class FleetAdapter(Protocol):
    """The fleet abstraction the release plane deploys through.

    Four operations, exactly the ones the spec names: resolve the
    manifest a session serves, report the digest a session resolved, pin
    a session to one manifest for its lifetime, and invalidate caches so
    workers re-resolve after a pointer move. Real fleet adapters implement
    this protocol; the simulator below is the reference implementation.
    """

    def resolve_manifest(self, session_id: str) -> str:
        """The manifest digest the session currently resolves."""
        ...

    def report_digest(self, session_id: str, manifest_digest: str) -> None:
        """The session reports the digest it resolved (100% coverage)."""
        ...

    def pin_session(
        self, session_id: str, manifest_digest: str, *, arm: SessionArm = "incumbent"
    ) -> None:
        """Pin the session to one manifest for its lifetime."""
        ...

    def invalidate_caches(self, manifest_digest: str) -> None:
        """Drop cached manifests fleet-wide; workers re-resolve to the
        digest now current on the active release pointer."""
        ...


@dataclass(slots=True)
class _Worker:
    worker_id: str
    convergence_latency: float
    """Seconds from cache invalidation until this worker re-resolves."""
    cached_digest: str | None = None
    resolves_at: float | None = None
    """Logical time at which the pending re-resolution completes."""


@dataclass(slots=True)
class _Session:
    session_id: str
    pinned_digest: str
    arm: SessionArm


@dataclass(slots=True)
class DigestReport:
    """One session's digest report — the fleet's honesty ledger."""

    session_id: str
    reported_digest: str
    reported_at: float


@dataclass
class InProcessFleetSimulator:
    """In-process fleet simulator: the reference FleetAdapter and the
    harness every FR-012 threshold test runs against."""

    worker_count: int
    latency_sampler: Callable[[], float]
    """Draws each worker's convergence latency in seconds. Realistic
    fleets converge in tens of seconds with a tail; the sampler makes the
    distribution explicit and the p99 measurable."""
    clock: MonotonicClock
    _workers: list[_Worker] = field(init=False)
    _sessions: dict[str, _Session] = field(default_factory=dict)
    _reports: list[DigestReport] = field(default_factory=list)
    _memory: dict[tuple[str, str], object] = field(default_factory=dict)
    _active_digest: str | None = None
    _invalidated_at: float | None = None

    def __post_init__(self) -> None:
        if self.worker_count <= 0:
            raise ValueError(f"worker_count must be positive, got {self.worker_count}")
        self._workers = [
            _Worker(worker_id=f"worker-{i}", convergence_latency=self.latency_sampler())
            for i in range(self.worker_count)
        ]

    # ------------------------------------------------------------------
    # FleetAdapter operations
    # ------------------------------------------------------------------

    def set_active(self, manifest_digest: str) -> None:
        """Record the digest now current on the active release pointer.

        Called by the canary harness immediately after a successful CAS —
        the simulator never moves the pointer itself; it only follows it.
        """
        self._active_digest = manifest_digest

    def pin_session(
        self, session_id: str, manifest_digest: str, *, arm: SessionArm = "incumbent"
    ) -> None:
        """Pin the session to one manifest for its lifetime.

        Re-pinning to a *different* manifest is refused (SessionPinError):
        a session that could switch manifests mid-flight would serve a mix
        of two releases. Re-pinning to the same digest is a no-op.
        """
        existing = self._sessions.get(session_id)
        if existing is not None:
            if existing.pinned_digest != manifest_digest:
                raise SessionPinError(session_id, existing.pinned_digest, manifest_digest)
            return
        self._sessions[session_id] = _Session(
            session_id=session_id, pinned_digest=manifest_digest, arm=arm
        )

    def resolve_manifest(self, session_id: str) -> str:
        """The manifest digest the session currently serves.

        A pinned session always resolves its pinned digest — that is what
        pinning means — even mid-convergence, even after a rollback.
        """
        session = self._require_session(session_id, "resolve manifest")
        return session.pinned_digest

    def report_digest(self, session_id: str, manifest_digest: str) -> None:
        """Record the session's digest report.

        A report contradicting the session's own resolution is refused
        (DigestReportingError): digest reporting exists so the control
        plane can *verify* what the fleet serves, and a contradictory
        report is tampering with that verification.
        """
        resolved = self.resolve_manifest(session_id)
        if manifest_digest != resolved:
            raise DigestReportingError(session_id, manifest_digest, resolved)
        self._reports.append(
            DigestReport(
                session_id=session_id,
                reported_digest=manifest_digest,
                reported_at=self.clock.seconds(),
            )
        )

    def invalidate_caches(self, manifest_digest: str) -> None:
        """Drop cached manifests fleet-wide and schedule re-resolution.

        Each worker re-resolves to ``manifest_digest`` after its own
        convergence latency — the model behind the p99 ≤5min threshold.
        """
        now = self.clock.seconds()
        self._active_digest = manifest_digest
        self._invalidated_at = now
        for worker in self._workers:
            worker.cached_digest = None
            worker.resolves_at = now + worker.convergence_latency

    # ------------------------------------------------------------------
    # Convergence and reporting metrics (FR-012 measurement)
    # ------------------------------------------------------------------

    def tick(self) -> None:
        """Complete every worker whose re-resolution time has elapsed."""
        now = self.clock.seconds()
        for worker in self._workers:
            if worker.resolves_at is not None and worker.resolves_at <= now:
                worker.cached_digest = self._active_digest
                worker.resolves_at = None

    def converged_workers(self) -> int:
        """Workers whose cache now holds the active digest."""
        self.tick()
        return sum(1 for w in self._workers if w.cached_digest == self._active_digest)

    def converged_fraction(self) -> float:
        return self.converged_workers() / self.worker_count

    def p99_convergence_seconds(self) -> float:
        """The 99th-percentile convergence latency of the last invalidation.

        Measured, not assumed: the latency each worker actually took from
        invalidation to re-resolution, 99th percentile across the fleet.
        The FR-012 threshold is that this stays ≤5 minutes.
        """
        if self._invalidated_at is None:
            raise RuntimeError("no cache invalidation has occurred — nothing to measure")
        latencies = sorted(w.convergence_latency for w in self._workers)
        rank = max(1, math.ceil(0.99 * len(latencies)))
        return latencies[rank - 1]

    def digest_reports(self) -> tuple[DigestReport, ...]:
        return tuple(self._reports)

    def digest_report_coverage(self, *, expected_sessions: set[str] | None = None) -> float:
        """Fraction of sessions that reported the digest they resolved.

        FR-012 requires 100% of reachable workers to report; the harness
        computes this over the sessions it created unless an explicit set
        is given.
        """
        sessions = expected_sessions if expected_sessions is not None else set(self._sessions)
        if not sessions:
            return 1.0
        reported = {r.session_id for r in self._reports}
        return len(reported & sessions) / len(sessions)

    # ------------------------------------------------------------------
    # Namespaced candidate state
    # ------------------------------------------------------------------

    def write_state(self, session_id: str, key: str, value: object, *, namespace: str) -> None:
        """Write session state into ``namespace``.

        The namespace a session may write into is fixed by its arm:
        candidate sessions write candidate state only, incumbent sessions
        incumbent state only. A candidate session attempting to write
        incumbent memory is refused with NamespaceViolationError — the
        namespacing that keeps a misbehaving candidate from corrupting
        the runtime it is being compared against.
        """
        session = self._require_session(session_id, "write state")
        allowed = _arm_namespace(session.arm)
        if namespace != allowed:
            raise NamespaceViolationError(session_id, namespace, allowed)
        self._memory[(namespace, key)] = value

    def read_state(self, key: str, *, namespace: str) -> object | None:
        """Read one namespaced state entry (test and assertion surface)."""
        return self._memory.get((namespace, key))

    def memory_keys(self, *, namespace: str) -> tuple[str, ...]:
        """Keys currently held in one namespace."""
        return tuple(sorted(k for (ns, k) in self._memory if namespace == ns))

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _require_session(self, session_id: str, operation: str) -> _Session:
        session = self._sessions.get(session_id)
        if session is None:
            raise UnknownSessionError(session_id, operation)
        return session

    def __iter__(self) -> Iterator[_Worker]:
        return iter(self._workers)


__all__ = [
    "CANDIDATE_NAMESPACE",
    "INCUMBENT_NAMESPACE",
    "DigestReport",
    "FleetAdapter",
    "InProcessFleetSimulator",
    "SessionArm",
]

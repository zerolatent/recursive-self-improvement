"""Harness profiles: scaled CI vs full-scale soak (§17.3 rows 1, 6, 9).

The spec's locked decision (structural risk 4): scale thresholds get
harnesses with a scaled CI profile plus a documented soak run, not
full-scale CI. Every profile here states its reduction explicitly so
``docs/phase4-verification.md`` can map each threshold to the profile that
measured it and the reduction CI applies.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FaultInjectionProfile:
    """N-writer × M-event sustained fault-injection run (§17.3 row 1).

    Each writer ingests its own tenant's fixture through the real
    per-event-commit path; the runner SIGKILLs a writer every
    ``kill_every_committed_events`` (up to ``max_kills_per_writer``) and
    resumes it with the same fixture, measuring delivered/expected at the
    end.
    """

    name: str
    writers: int
    events_per_writer: int
    kill_every_committed_events: int
    max_kills_per_writer: int
    #: Hard wall-clock budget; exceeding it fails the run rather than
    #: reporting a loss number from an incomplete delivery.
    deadline_s: float

    @property
    def total_events(self) -> int:
        return self.writers * self.events_per_writer


@dataclass(frozen=True)
class SecrecyProfile:
    """Canary-token leak-scan suite size (§17.3 row 6).

    The threshold itself is ≥10,000 adversarial emissions, which is
    CPU-bound and cheap enough to run natively in CI — no reduction needed.
    """

    name: str
    emissions: int
    holdout_items: int


@dataclass(frozen=True)
class LoadProfile:
    """Concurrent-candidate load run (§17.3 row 9).

    ``candidate_processes × executions_per_process`` is the concurrent
    candidate-execution count; each execution emits
    ``events_per_execution`` events through the real HTTP ingest endpoint
    served by a real evaluation-plane process. ``kill_worker_index``
    selects the worker the recovery probe SIGKILLs mid-run (``None``
    disables the probe).
    """

    name: str
    candidate_processes: int
    executions_per_process: int
    events_per_execution: int
    kill_worker_index: int | None
    kill_after_events: int
    recovery_deadline_s: float
    max_ingest_p99_s: float
    max_loss_rate: float
    deadline_s: float

    @property
    def concurrent_executions(self) -> int:
        return self.candidate_processes * self.executions_per_process

    @property
    def total_events(self) -> int:
        return self.concurrent_executions * self.events_per_execution

    @property
    def total_sdk_events(self) -> int:
        """Events the SDK journals, including trace lifecycle events.

        Each execution's ``adapter.trace()`` context emits one
        ``trace.started`` and one ``trace.ended`` alongside its
        ``events_per_execution`` tool-call events, and the load worker's
        progress accounting measures the SDK's journal durability
        boundary — which sees all three. The §17.3 loss SLO is computed
        over this number, not ``total_events``.
        """
        return self.total_events + 2 * self.concurrent_executions


#: CI: 4 writers × 2,500 events (10k total — the D2 fixture size) with 2
#: kills per writer. Same code path as the soak; ~8× the original
#: single-writer test's coverage at comparable CI cost.
FAULT_INJECTION_CI_PROFILE = FaultInjectionProfile(
    name="ci",
    writers=4,
    events_per_writer=2_500,
    kill_every_committed_events=800,
    max_kills_per_writer=2,
    deadline_s=600.0,
)

#: Soak: 8 writers × 1.25M events = the full 10M-event threshold, with
#: periodic kills throughout. Runbook in docs/phase4-verification.md.
FAULT_INJECTION_SOAK_PROFILE = FaultInjectionProfile(
    name="soak-10m",
    writers=8,
    events_per_writer=1_250_000,
    kill_every_committed_events=250_000,
    max_kills_per_writer=4,
    deadline_s=14_400.0,
)

#: Secrecy: the §17.3 row 6 threshold runs natively in CI.
SECRECY_PROFILE = SecrecyProfile(name="ci", emissions=10_000, holdout_items=100)

#: CI: 8 concurrent candidate executions (4 processes × 2 threads) × 250
#: events through a real HTTP ingest, with a single-worker kill/recovery
#: probe. Thresholds (p99 ≤2s, loss ≤0.01%) are the real §17.3 values —
#: only the scale is reduced.
LOAD_CI_PROFILE = LoadProfile(
    name="ci",
    candidate_processes=4,
    executions_per_process=2,
    events_per_execution=250,
    kill_worker_index=1,
    kill_after_events=400,
    recovery_deadline_s=120.0,
    max_ingest_p99_s=2.0,
    max_loss_rate=0.0001,
    deadline_s=900.0,
)

#: Soak: 1,000 concurrent candidate executions (25 processes × 40 threads)
#: emitting 10M events — the §17.3 row 9 shape (10M events/day sustained,
#: 24h horizon). Recovery deadline is the full ≤10-minute threshold.
LOAD_SOAK_PROFILE = LoadProfile(
    name="soak-1000x10m",
    candidate_processes=25,
    executions_per_process=40,
    events_per_execution=10_000,
    kill_worker_index=0,
    kill_after_events=50_000,
    recovery_deadline_s=600.0,
    max_ingest_p99_s=2.0,
    max_loss_rate=0.0001,
    deadline_s=86_400.0,
)

"""The fixed-horizon canary harness (FR-012, §17.3 P0 thresholds).

A canary is a randomized, fixed-horizon comparison: the candidate
manifest is activated atomically, a randomized slice of new sessions —
never more than 5% — is pinned to it while the rest stay pinned to the
incumbent, and at least the power-analysis sample of paired eligible
tasks (≥200) runs over a minimum 24-hour observation. The horizon is
fixed *before* the canary starts: the harness stops when the horizon is
reached, not when the candidate looks good — early stopping on a
favorable trend is how noise gets promoted.

One event overrides the horizon: a deterministic severity-1 guardrail
event stops the canary immediately and rolls back to the prior release.
No grace period, no further tasks — severity-1 means the candidate is
actively harmful, and every additional task under it is harm.

Time is injected: tests run a :class:`CompressedClock` (24 hours of
observation in 24 advanced seconds); the verification run uses the real
clock. The harness code is identical under both.
"""

from __future__ import annotations

import math
import random
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum

from evoruntime.campaign.compensation import (
    CompensationExecutor,
    ExecutionSink,
    SignedCompensationPlan,
    assert_promotion_allowed,
    execute_rollback_compensations,
)
from evoruntime.campaign.errors import UnexecutedCompensationError
from evoruntime.release.clock import WallClock
from evoruntime.release.controller import ReleaseController
from evoruntime.release.errors import InvalidCanaryConfigError, NoActiveReleaseError
from evoruntime.release.fleet import (
    CANDIDATE_NAMESPACE,
    INCUMBENT_NAMESPACE,
    InProcessFleetSimulator,
    SessionArm,
)
from evoruntime.release.manifest import SignedReleaseManifest

#: The §17.3 P0 floors. A canary configured below any of them cannot
#: detect what it exists to detect, so the config is refused.
MIN_PAIRED_TASKS = 200
MAX_CANDIDATE_ALLOCATION = 0.05
MIN_OBSERVATION = timedelta(hours=24)

SEVERITY_1 = 1


class CanaryOutcome(StrEnum):
    """How the canary ended. Only COMPLETED leaves the candidate active."""

    COMPLETED = "completed"
    ROLLED_BACK = "rolled_back"


@dataclass(frozen=True, slots=True)
class CanaryConfig:
    """The canary's preregistered shape: fixed horizon, capped allocation.

    Validation enforces the §17.3 P0 floors at construction — an
    underpowered canary is a refusal, not a warning.
    """

    min_paired_tasks: int = MIN_PAIRED_TASKS
    max_candidate_allocation: float = MAX_CANDIDATE_ALLOCATION
    observation_horizon: timedelta = MIN_OBSERVATION
    seed: int = 0
    """Seeds allocation randomization — the horizon is fixed, the slice
    is randomized, and the randomization is reproducible."""

    def __post_init__(self) -> None:
        if self.min_paired_tasks < MIN_PAIRED_TASKS:
            raise InvalidCanaryConfigError(
                f"min_paired_tasks {self.min_paired_tasks} is below the §17.3 P0 "
                f"floor of {MIN_PAIRED_TASKS} paired eligible tasks"
            )
        if not 0 < self.max_candidate_allocation <= MAX_CANDIDATE_ALLOCATION:
            raise InvalidCanaryConfigError(
                f"max_candidate_allocation {self.max_candidate_allocation} must be "
                f"in (0, {MAX_CANDIDATE_ALLOCATION}] — candidate allocation may "
                "never exceed 5%"
            )
        if self.observation_horizon < MIN_OBSERVATION:
            raise InvalidCanaryConfigError(
                f"observation_horizon {self.observation_horizon} is below the "
                f"§17.3 P0 minimum of {MIN_OBSERVATION}"
            )


@dataclass(frozen=True, slots=True)
class GuardrailEvent:
    """One guardrail observation during the canary.

    Severity 1 is the stop-everything tier: deterministic, immediate
    rollback. Severities 2–4 are recorded and left to the promotion
    decision; they do not stop the horizon.
    """

    severity: int
    kind: str
    task_index: int
    detail: str = ""

    def __post_init__(self) -> None:
        if self.severity not in (1, 2, 3, 4):
            raise ValueError(f"severity must be 1-4, got {self.severity}")

    @property
    def is_severity_one(self) -> bool:
        return self.severity == SEVERITY_1


@dataclass(frozen=True, slots=True)
class CanaryResult:
    """What the canary did, with the FR-012 measurements attached."""

    outcome: CanaryOutcome
    paired_tasks: int
    total_sessions: int
    candidate_sessions: int
    candidate_allocation: float
    """The realized candidate share — must be ≤ the configured cap."""
    stopped_reason: str | None
    rolled_back_to: str | None
    digest_report_coverage: float
    p99_convergence_seconds: float | None
    observation_elapsed: timedelta
    guardrail_events: tuple[GuardrailEvent, ...]


class CanaryHarness:
    """Runs the fixed-horizon canary against the fleet simulator.

    The harness orchestrates; the authority stays where it belongs: the
    pointer moves only through the release controller's CAS, the fleet
    converges only through cache invalidation, and candidate state lands
    only in the candidate namespace.
    """

    def __init__(
        self,
        *,
        config: CanaryConfig,
        controller: ReleaseController,
        fleet: InProcessFleetSimulator,
        clock: WallClock,
        compensation_plan: SignedCompensationPlan | None = None,
        compensation_executions: ExecutionSink | None = None,
        compensation_executor: CompensationExecutor | None = None,
    ) -> None:
        self._config = config
        self._controller = controller
        self._fleet = fleet
        self._clock = clock
        # F5: when the campaign declared a compensation plan, the canary
        # enforces it — promotion is refused while a requires-execution
        # compensation is unexecuted, and a severity-1 rollback executes
        # the declared compensations in declared order. CAS compensations
        # need no extra execution: the controller's pointer rollback
        # (the only CAS path to the active release pointer) covers them.
        self._compensation_plan = compensation_plan
        self._compensation_executions = compensation_executions
        self._compensation_executor = compensation_executor

    def run(
        self,
        candidate: SignedReleaseManifest,
        guardrail_events: Sequence[GuardrailEvent] = (),
    ) -> CanaryResult:
        """Execute the fixed-horizon canary for ``candidate``.

        Steps: activate the candidate through the controller's CAS,
        invalidate fleet caches, pin a randomized ≤5% slice of new
        sessions to the candidate (the rest to the incumbent), run the
        paired tasks with 100% digest reporting, and stop either at the
        horizon or immediately on a severity-1 event — rolling back
        through the controller in the latter case.
        """
        incumbent_digest = self._controller.active_digest()
        if incumbent_digest is None:
            raise NoActiveReleaseError(
                "no active release — a canary compares a candidate against an "
                "incumbent, and there is no incumbent to compare against"
            )
        if candidate.manifest_digest == incumbent_digest:
            raise InvalidCanaryConfigError(
                "the candidate manifest is the currently active release — a canary "
                "compares a change against the incumbent, not the incumbent with itself"
            )

        events_by_task = _events_by_task(guardrail_events)
        started_at = self._clock.now()

        # Activate the whole candidate manifest atomically, then let the
        # fleet start converging toward it.
        self._controller.activate(candidate)
        self._fleet.invalidate_caches(candidate.manifest_digest)

        # Randomized allocation under the cap: the candidate slice is
        # drawn fresh per canary (seeded, so reruns reproduce it) but is
        # never allowed to exceed the configured maximum.
        rng = random.Random(self._config.seed)
        allocation = rng.uniform(0.0, self._config.max_candidate_allocation)
        total = self._config.min_paired_tasks
        candidate_count = math.floor(total * allocation)
        candidate_arm: SessionArm = "candidate"
        incumbent_arm: SessionArm = "incumbent"
        arms: list[SessionArm] = [candidate_arm] * candidate_count + [incumbent_arm] * (
            total - candidate_count
        )
        rng.shuffle(arms)

        all_sessions: list[str] = []
        candidate_sessions: list[str] = []
        fired: list[GuardrailEvent] = []
        stopped_reason: str | None = None
        rolled_back_to: str | None = None
        tasks_run = 0

        per_task_seconds = self._config.observation_horizon.total_seconds() / total
        for index in range(total):
            self._clock.advance(per_task_seconds)
            arm = arms[index]
            session_id = f"canary-session-{index}"
            pinned = candidate.manifest_digest if arm == "candidate" else incumbent_digest
            self._fleet.pin_session(session_id, pinned, arm=arm)
            resolved = self._fleet.resolve_manifest(session_id)
            self._fleet.report_digest(session_id, resolved)
            self._fleet.write_state(
                session_id,
                f"canary-task-{index}",
                {"task_index": index, "manifest": resolved},
                namespace=CANDIDATE_NAMESPACE if arm == "candidate" else INCUMBENT_NAMESPACE,
            )
            all_sessions.append(session_id)
            tasks_run = index + 1
            if arm == "candidate":
                candidate_sessions.append(session_id)

            for event in events_by_task.get(index, ()):
                fired.append(event)
                if event.is_severity_one:
                    # Deterministic severity-1: stop immediately, roll
                    # back now — no further tasks under a harmful release.
                    stopped_reason = f"severity-1 guardrail event: {event.kind}"
                    break

            if stopped_reason is not None:
                break

        if stopped_reason is not None:
            rolled_back_to = incumbent_digest
            # F5: execute the declared compensations in declared order
            # before the pointer rollback lands — CAS actions ride the
            # rollback itself, requires-execution actions run here with
            # their evidence recorded.
            if self._compensation_plan is not None and self._compensation_executor is not None:
                for record in execute_rollback_compensations(
                    self._compensation_plan, self._compensation_executor
                ):
                    if self._compensation_executions is not None:
                        self._compensation_executions.append(record)
            self._controller.rollback(candidate)
            self._fleet.invalidate_caches(incumbent_digest)

        if stopped_reason is None and self._compensation_plan is not None:
            # F5 promotion gate: the canary completed, so the candidate is
            # about to be promoted — a declared requires-execution
            # compensation with no execution record refuses promotion. The
            # refusal restores the incumbent before surfacing.
            try:
                assert_promotion_allowed(
                    self._compensation_plan,
                    (
                        ()
                        if self._compensation_executions is None
                        else self._compensation_executions.all()
                    ),
                )
            except UnexecutedCompensationError:
                self._controller.rollback(candidate)
                self._fleet.invalidate_caches(incumbent_digest)
                raise

        return CanaryResult(
            outcome=(
                CanaryOutcome.ROLLED_BACK if stopped_reason is not None else CanaryOutcome.COMPLETED
            ),
            paired_tasks=tasks_run,
            total_sessions=total,
            candidate_sessions=len(candidate_sessions),
            candidate_allocation=len(candidate_sessions) / total,
            stopped_reason=stopped_reason,
            rolled_back_to=rolled_back_to,
            digest_report_coverage=self._fleet.digest_report_coverage(
                expected_sessions=set(all_sessions)
            ),
            p99_convergence_seconds=self._fleet.p99_convergence_seconds(),
            observation_elapsed=self._clock.now() - started_at,
            guardrail_events=tuple(fired),
        )


def _events_by_task(
    events: Sequence[GuardrailEvent],
) -> Mapping[int, tuple[GuardrailEvent, ...]]:
    """Group guardrail events by the task index that fires them."""
    grouped: dict[int, list[GuardrailEvent]] = {}
    for event in events:
        grouped.setdefault(event.task_index, []).append(event)
    return {index: tuple(found) for index, found in grouped.items()}


__all__ = [
    "MAX_CANDIDATE_ALLOCATION",
    "MIN_OBSERVATION",
    "MIN_PAIRED_TASKS",
    "SEVERITY_1",
    "CanaryConfig",
    "CanaryHarness",
    "CanaryOutcome",
    "CanaryResult",
    "GuardrailEvent",
]

"""What the harness runs, and what it records about each run.

One `TaskRun` per (arm, task, seed) cell: the unit the statistics later
resample. Every field here exists because some downstream claim depends
on it — `stop_reason` so an exhausted budget is distinguishable from a
genuine failure, `attempts` so a retry arm's equal-compute story is
auditable rather than asserted, `budget` so a reader can verify after the
fact that the arms really did run under the same ceiling.

`claimed_success` is named for what it is. An agent reporting its own
outcome is evidence, not a verdict; the PRD makes the external verifier
authoritative and D3's outcome attestation is what binds a run to a
verified result. Phase 0's `ClaimedOutcomeVerifier` trusts the claim
because the scripted backend's claim *is* the fixture's ground truth —
that is a property of the fixture, not a general licence to trust agents.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from evoruntime.eval.budgets import BudgetUsage, TaskBudget


@dataclass(frozen=True, slots=True)
class EvalTask:
    """One unit of work handed to an agent backend.

    Deliberately thin. A coding fixture's issue text, repo snapshot, and
    test command differ per dataset and per fixture format (D8's manifest
    is one such format); the harness only needs a stable id to pair on and
    a prompt to hand over, so everything else rides in `metadata` rather
    than growing a field the harness does not read.
    """

    id: str
    prompt: str
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("task id must be non-empty")
        # Copy so a caller's later mutation cannot retroactively change what
        # a recorded run says it was given.
        object.__setattr__(self, "metadata", dict(self.metadata))


class StopReason(StrEnum):
    """Why an arm stopped working on a task.

    The distinction is load-bearing for interpretation: an arm that fails
    tasks because it exhausts its budget is telling you something about
    the budget, while one that fails inside its budget is telling you
    something about the agent.
    """

    COMPLETED = "completed"
    """The strategy finished its attempts with budget left."""

    BUDGET_EXHAUSTED = "budget_exhausted"
    """A charge would have crossed a ceiling; the attempt was cut short."""

    BACKEND_ERROR = "backend_error"
    """The agent backend raised. Recorded as a failed task, never hidden."""


@dataclass(frozen=True, slots=True)
class AttemptRecord:
    """One attempt at one task by one arm."""

    attempt: int
    claimed_success: bool
    usage: BudgetUsage
    output: str = ""


@dataclass(frozen=True, slots=True)
class TaskRun:
    """The result of one (arm, task, seed) cell — the paired-statistics unit."""

    arm_id: str
    task_id: str
    seed_index: int
    seed: int
    success: bool
    attempts: tuple[AttemptRecord, ...]
    usage: BudgetUsage
    budget: TaskBudget
    stop_reason: StopReason
    error: str | None = None

    @property
    def attempt_count(self) -> int:
        """How many attempts the arm actually spent."""
        return len(self.attempts)

    @property
    def score(self) -> float:
        """The run's primary metric as a number the statistics can average."""
        return 1.0 if self.success else 0.0


class OutcomeVerifier(Protocol):
    """Decides the authoritative outcome of a run from its attempts."""

    def verify(self, task: EvalTask, attempts: tuple[AttemptRecord, ...]) -> bool:
        """Return the run's true success, given what the agent claimed."""
        ...


class ClaimedOutcomeVerifier:
    """Phase 0 verifier: takes the last attempt's claim at face value.

    Valid only because Phase 0 runs deterministic fixtures whose scripted
    claim is ground truth by construction. A real backend needs D3's
    outcome attestation — an external verifier signing the raw result —
    and this class is the seam that will be replaced by it, deliberately
    left as an injectable dependency rather than an inlined `attempts[-1]`.
    """

    def verify(self, task: EvalTask, attempts: tuple[AttemptRecord, ...]) -> bool:
        """Return the final attempt's claimed outcome (False when none ran)."""
        if not attempts:
            return False
        return attempts[-1].claimed_success


class MajorityVoteVerifier:
    """Self-consistency verifier: the modal claim across completed attempts.

    Used by the retry arm, where the point is agreement across samples
    rather than the luck of the last one. Ties resolve to failure — a
    2-2 split is not consistency, and rounding ties up would inflate every
    even-attempt retry arm.
    """

    def verify(self, task: EvalTask, attempts: tuple[AttemptRecord, ...]) -> bool:
        """Return True when a strict majority of attempts claimed success."""
        if not attempts:
            return False
        successes = sum(1 for attempt in attempts if attempt.claimed_success)
        return successes * 2 > len(attempts)


__all__ = [
    "AttemptRecord",
    "ClaimedOutcomeVerifier",
    "EvalTask",
    "MajorityVoteVerifier",
    "OutcomeVerifier",
    "StopReason",
    "TaskRun",
]

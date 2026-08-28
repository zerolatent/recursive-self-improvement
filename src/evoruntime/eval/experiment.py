"""The preregistered experiment: arms, seeds, and the envelope they share.

An experiment is declared before it runs and validated at construction,
because every failure this module catches is a failure that would
otherwise be discovered *after* the run — when the only options left are
to discard the results or to quietly reinterpret them. Two arms with the
same id, a missing incumbent, one seed instead of three: each of those
produces numbers, and numbers that look fine are the expensive kind of
wrong.

The three arm kinds are the spec's (PRD §11.2, §12.4): the incumbent as
it ships today, an equal-compute retry baseline, and a one-shot control
with no iteration. They exist so a Phase 1 optimizer has something to
beat that is not a strawman — the PRD's own kill condition is that an
equal-compute retry arm matches whatever the optimizer produces.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum

from evoruntime.datasets.partitions import PartitionKind, is_sealed
from evoruntime.eval.budgets import TaskBudget, resolve_budget_profile
from evoruntime.eval.errors import ExperimentDefinitionError
from evoruntime.eval.statistics import (
    DEFAULT_ALPHA,
    DEFAULT_BOOTSTRAP_ITERATIONS,
    MIN_BOOTSTRAP_ITERATIONS,
    MultiplicityMethod,
)

MIN_SEEDS = 3
"""PRD §12.5 floor. Three seeds is not enough to characterize variance —
it is the minimum at which reporting variance is even meaningful, which is
why the spec calls it a floor rather than a guarantee."""

DEFAULT_RETRY_ATTEMPTS = 3
"""Attempts a retry arm may make *within the shared budget*, not on top of it."""

DEFAULT_BOOTSTRAP_SEED = 20_260_827
"""Fixed so an experiment's intervals reproduce byte-for-byte on re-analysis."""


class ArmKind(StrEnum):
    """The three preregistered Phase 0 arms."""

    INCUMBENT = "incumbent"
    """The agent configuration currently in production. The baseline everything pairs against."""

    RETRY_SELF_CONSISTENCY = "retry-self-consistency"
    """Repeated attempts under one budget, scored by majority vote across attempts."""

    ONE_SHOT_CONTROL = "one-shot-control"
    """A single pass with no tool iteration — the floor a real agent must clear."""

    STRATEGY = "strategy"
    """The campaign's optimizer arm (PRD §11.2): candidates proposed by the
    strategy plugin from redacted evidence. The three Phase 0 arms above are
    the control frame this arm is measured against — an optimizer that cannot
    beat retry-self-consistency under the same envelope has found nothing."""


@dataclass(frozen=True, slots=True)
class Arm:
    """One arm of an experiment.

    `max_attempts` is the only per-arm knob, and it deliberately does not
    touch resources: attempts are drawn from the same envelope every other
    arm gets, so raising it buys more tries at a smaller each, never more
    compute.
    """

    id: str
    kind: ArmKind
    max_attempts: int = 1

    def __post_init__(self) -> None:
        if not self.id:
            raise ExperimentDefinitionError("arm id must be non-empty")
        if self.max_attempts < 1:
            raise ExperimentDefinitionError(
                f"arm {self.id!r}: max_attempts must be at least 1, got {self.max_attempts}"
            )
        if self.kind is not ArmKind.RETRY_SELF_CONSISTENCY and self.max_attempts != 1:
            raise ExperimentDefinitionError(
                f"arm {self.id!r}: only a {ArmKind.RETRY_SELF_CONSISTENCY.value} arm may "
                f"retry (kind={self.kind.value}, max_attempts={self.max_attempts})"
            )

    @classmethod
    def retry(cls, arm_id: str, *, max_attempts: int = DEFAULT_RETRY_ATTEMPTS) -> Arm:
        """Build a retry-self-consistency arm with the default attempt cap."""
        return cls(id=arm_id, kind=ArmKind.RETRY_SELF_CONSISTENCY, max_attempts=max_attempts)


@dataclass(frozen=True, slots=True)
class Experiment:
    """A preregistered comparison: what runs, on what data, under what budget.

    Everything the analysis needs is fixed here, before any task executes:
    the arms, the dataset partition, the resource envelope, the seed count,
    the alpha, and the multiplicity correction. Preregistration is not
    ceremony — a comparison whose alpha is chosen after seeing the deltas
    has no error rate at all.
    """

    name: str
    dataset: str
    task_budget_profile: str
    arms: Sequence[Arm]
    seeds: int = MIN_SEEDS
    partition: PartitionKind = PartitionKind.DEV
    alpha: float = DEFAULT_ALPHA
    multiplicity: MultiplicityMethod = MultiplicityMethod.BONFERRONI
    bootstrap_iterations: int = DEFAULT_BOOTSTRAP_ITERATIONS
    bootstrap_seed: int = DEFAULT_BOOTSTRAP_SEED
    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "arms", tuple(self.arms))
        object.__setattr__(self, "metadata", dict(self.metadata))

        if not self.name:
            raise ExperimentDefinitionError("experiment name must be non-empty")
        if not self.dataset:
            raise ExperimentDefinitionError("experiment dataset must be non-empty")
        self._validate_arms()
        self._validate_partition()
        self._validate_statistics()
        # Resolving here (and discarding the result) turns an unknown profile
        # name into a construction-time error instead of a run-time one.
        resolve_budget_profile(self.task_budget_profile)

    def _validate_arms(self) -> None:
        if not self.arms:
            raise ExperimentDefinitionError("an experiment needs at least one arm")

        ids = [arm.id for arm in self.arms]
        duplicates = sorted({arm_id for arm_id in ids if ids.count(arm_id) > 1})
        if duplicates:
            raise ExperimentDefinitionError(f"duplicate arm ids: {', '.join(duplicates)}")

        incumbents = [arm for arm in self.arms if arm.kind is ArmKind.INCUMBENT]
        if len(incumbents) != 1:
            raise ExperimentDefinitionError(
                "an experiment needs exactly one incumbent arm to pair against, "
                f"found {len(incumbents)}"
            )

    def _validate_partition(self) -> None:
        if is_sealed(self.partition):
            raise ExperimentDefinitionError(
                f"the harness cannot run against the {self.partition.value} partition: "
                "sealed content stays inside the evaluation plane's storage identity and "
                "is reachable only through a ledgered handle resolution. Baselines run on "
                f"{PartitionKind.DEV.value}."
            )

    def _validate_statistics(self) -> None:
        if self.seeds < MIN_SEEDS:
            raise ExperimentDefinitionError(
                f"seeds must be at least {MIN_SEEDS} (PRD §12.5 floor), got {self.seeds}"
            )
        if not 0.0 < self.alpha < 1.0:
            raise ExperimentDefinitionError(f"alpha must be in (0, 1), got {self.alpha!r}")
        if self.bootstrap_iterations < MIN_BOOTSTRAP_ITERATIONS:
            raise ExperimentDefinitionError(
                f"bootstrap_iterations must be at least {MIN_BOOTSTRAP_ITERATIONS}, "
                f"got {self.bootstrap_iterations}"
            )

    @property
    def incumbent(self) -> Arm:
        """The baseline arm every candidate is paired against."""
        return next(arm for arm in self.arms if arm.kind is ArmKind.INCUMBENT)

    @property
    def candidate_arms(self) -> tuple[Arm, ...]:
        """Every arm that is not the incumbent, in declaration order."""
        return tuple(arm for arm in self.arms if arm.kind is not ArmKind.INCUMBENT)

    @property
    def budget(self) -> TaskBudget:
        """The single envelope every arm in this experiment runs under."""
        return resolve_budget_profile(self.task_budget_profile)


def derive_seed(experiment_name: str, task_id: str, seed_index: int) -> int:
    """Derive the RNG seed for one (task, seed) cell.

    The arm id is deliberately *not* an input. Every arm therefore starts
    the same task from the same random stream — common random numbers,
    the standard variance reduction for a matched-pairs design. Two arms
    that behave identically produce an exactly zero difference instead of
    two independent coin flips, so the interval measures the arms rather
    than the noise between two RNG draws. Streams diverge on their own as
    arms consume them differently (a retry arm draws once per attempt).

    BLAKE2b rather than `hash()`: Python's string hashing is salted per
    process, and a seed that changes between runs is not a seed.
    """
    material = f"{experiment_name}\x00{task_id}\x00{seed_index}".encode()
    return int.from_bytes(hashlib.blake2b(material, digest_size=8).digest(), "big")


__all__ = [
    "DEFAULT_BOOTSTRAP_SEED",
    "DEFAULT_RETRY_ATTEMPTS",
    "MIN_SEEDS",
    "Arm",
    "ArmKind",
    "Experiment",
    "derive_seed",
]

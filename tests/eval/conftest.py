"""Fixtures for the evaluation-harness suite.

Every fixture here is deterministic on purpose. The harness's job is to
produce a number a reviewer can defend, so its tests must fail for
exactly one reason — a bug — and never because a clock ticked or a
process-salted hash landed differently. Hence a frozen clock by default
and scripted backends whose outcomes are written down in the test.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

import pytest

from evoruntime.datasets.partitions import PartitionKind
from evoruntime.eval import (
    TASK_BUDGET_V1,
    Arm,
    ArmKind,
    AttemptCost,
    Clock,
    EvalTask,
    Experiment,
    FrozenClock,
    InMemoryTaskSource,
    MultiplicityMethod,
    ScriptedAgent,
    ScriptedStep,
    TaskBudget,
)
from evoruntime.eval.experiment import MIN_SEEDS
from evoruntime.eval.statistics import DEFAULT_ALPHA, DEFAULT_BOOTSTRAP_ITERATIONS

TASK_COUNT = 12
"""Enough tasks for a paired comparison to say something, small enough to stay fast."""


def make_tasks(count: int = TASK_COUNT, *, prefix: str = "tsk") -> tuple[EvalTask, ...]:
    """Build a deterministic task set with stable, sortable ids."""
    return tuple(
        EvalTask(
            id=f"{prefix}_{index:03d}",
            prompt=f"repair the failing test in module_{index}.py",
            metadata={"category": "localization" if index % 2 == 0 else "dependency_misuse"},
        )
        for index in range(count)
    )


def scripted_outcomes(
    tasks: Sequence[EvalTask],
    successes: int,
    *,
    cost: AttemptCost | None = None,
) -> dict[str, tuple[ScriptedStep, ...]]:
    """A script where the first `successes` tasks succeed and the rest fail.

    Deterministic per task rather than per run, so an arm's success rate
    is a property of the script and any deviation is the harness's doing.
    """
    step_cost = cost if cost is not None else AttemptCost()
    return {
        task.id: (ScriptedStep(claimed_success=index < successes, cost=step_cost),)
        for index, task in enumerate(tasks)
    }


def frozen_clock() -> Clock:
    """A clock that advances only by what a backend declares it spent."""
    return FrozenClock()


def three_arm_experiment(
    *,
    name: str = "harness-suite-baseline",
    dataset: str = "ds_repo_repair_dev_v1",
    task_budget_profile: str = "task-budget-v1",
    seeds: int = MIN_SEEDS,
    retry_attempts: int = 3,
    partition: PartitionKind = PartitionKind.DEV,
    alpha: float = DEFAULT_ALPHA,
    multiplicity: MultiplicityMethod = MultiplicityMethod.BONFERRONI,
    bootstrap_iterations: int = DEFAULT_BOOTSTRAP_ITERATIONS,
) -> Experiment:
    """The spec's three preregistered arms, ready to run."""
    return Experiment(
        name=name,
        dataset=dataset,
        task_budget_profile=task_budget_profile,
        arms=[
            Arm(id="incumbent", kind=ArmKind.INCUMBENT),
            Arm.retry("retry", max_attempts=retry_attempts),
            Arm(id="one-shot", kind=ArmKind.ONE_SHOT_CONTROL),
        ],
        seeds=seeds,
        partition=partition,
        alpha=alpha,
        multiplicity=multiplicity,
        bootstrap_iterations=bootstrap_iterations,
    )


def uniform_backends(
    tasks: Sequence[EvalTask], arms_to_successes: Mapping[str, int]
) -> dict[str, ScriptedAgent]:
    """One scripted backend per arm, each with a known success count."""
    return {
        arm_id: ScriptedAgent(scripted_outcomes(tasks, successes))
        for arm_id, successes in arms_to_successes.items()
    }


@pytest.fixture
def tasks() -> tuple[EvalTask, ...]:
    """A twelve-task fixture set."""
    return make_tasks()


@pytest.fixture
def task_source(tasks: tuple[EvalTask, ...]) -> InMemoryTaskSource:
    """An in-memory dev-partition task source over `tasks`."""
    return InMemoryTaskSource(tasks)


@pytest.fixture
def budget() -> TaskBudget:
    """The `task-budget-v1` envelope every arm shares."""
    return TASK_BUDGET_V1


@pytest.fixture
def experiment() -> Experiment:
    """The three-arm baseline experiment at the seed floor."""
    return three_arm_experiment()

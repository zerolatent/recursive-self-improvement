"""The task runner: every arm, every seed, every task, one envelope.

The runner's entire job is to make the comparison fair and then get out of
the way. Three properties do that work.

*One budget object, every arm.* The envelope is resolved once from the
experiment's named profile and handed to every meter, so "matched
resources" is a structural fact rather than a convention three call sites
have to remember. `ExperimentResult.budgets_are_matched` re-derives it
from the recorded runs, which is the assertion the D6 acceptance row asks
for.

*One meter per (arm, task, seed).* A retry arm's attempts share a meter —
three tries out of one envelope, not three envelopes. Arms differ in how
they *spend*, never in how much they *have*.

*Arms differ only in strategy.* `strategy_for` is the whole difference
between the three preregistered arms: attempt count, whether a tool loop
is permitted, and how attempts are turned into an outcome. Anything else
that varied between arms would be a confound the statistics cannot see.

Iteration order is arm-major, then seed, then task, and every cell's RNG
seed comes from `derive_seed`, which excludes the arm id. Reordering the
loops or reordering the task set therefore cannot change a single
outcome — a property the determinism test pins.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from evoruntime.eval.backends import AgentBackend, AgentRequest
from evoruntime.eval.budgets import BudgetMeter, BudgetUsage, Clock, MonotonicClock, TaskBudget
from evoruntime.eval.errors import BudgetExceededError, EvalError, ExperimentDefinitionError
from evoruntime.eval.experiment import Arm, ArmKind, Experiment, derive_seed
from evoruntime.eval.results import ExperimentResult, summarize_experiment
from evoruntime.eval.sources import TaskSource
from evoruntime.eval.tasks import (
    AttemptRecord,
    ClaimedOutcomeVerifier,
    EvalTask,
    MajorityVoteVerifier,
    OutcomeVerifier,
    StopReason,
    TaskRun,
)

ClockFactory = Callable[[], Clock]
"""Builds the clock for one run's meter — injectable so tests can freeze time."""


@dataclass(frozen=True, slots=True)
class ArmStrategy:
    """How one arm spends its identical envelope.

    Every field here is about *behaviour*, never about resources. That
    separation is the point: a knob that changed an arm's budget would
    make the comparison meaningless, so no such knob exists.
    """

    max_attempts: int
    allow_tools: bool
    verifier: OutcomeVerifier


def strategy_for(arm: Arm) -> ArmStrategy:
    """Map an arm to its execution strategy.

    - incumbent: one attempt, tools on, claimed outcome taken at face value.
    - retry-self-consistency: `max_attempts` attempts, tools on, majority vote.
    - one-shot-control: one attempt, no tool loop — the floor a real agent
      must clear, and the arm that shows how much of a result is the
      scaffolding rather than the model.
    """
    match arm.kind:
        case ArmKind.INCUMBENT:
            return ArmStrategy(max_attempts=1, allow_tools=True, verifier=ClaimedOutcomeVerifier())
        case ArmKind.RETRY_SELF_CONSISTENCY:
            return ArmStrategy(
                max_attempts=arm.max_attempts, allow_tools=True, verifier=MajorityVoteVerifier()
            )
        case ArmKind.ONE_SHOT_CONTROL:
            return ArmStrategy(max_attempts=1, allow_tools=False, verifier=ClaimedOutcomeVerifier())
        case ArmKind.STRATEGY:
            # The strategy arm must mirror the incumbent's envelope exactly:
            # the comparison is over the artifact, so the only allowed delta
            # is the artifact itself.
            return ArmStrategy(max_attempts=1, allow_tools=True, verifier=ClaimedOutcomeVerifier())


def usage_delta(before: BudgetUsage, after: BudgetUsage) -> BudgetUsage:
    """What one attempt consumed, as the difference between two meter reads."""
    return BudgetUsage(
        input_tokens=after.input_tokens - before.input_tokens,
        output_tokens=after.output_tokens - before.output_tokens,
        tool_calls=after.tool_calls - before.tool_calls,
        wall_clock_s=after.wall_clock_s - before.wall_clock_s,
    )


def run_task(
    *,
    arm: Arm,
    task: EvalTask,
    backend: AgentBackend,
    budget: TaskBudget,
    seed_index: int,
    seed: int,
    strategy: ArmStrategy | None = None,
    clock: Clock | None = None,
) -> TaskRun:
    """Run one arm against one task under one budget, and record what happened.

    A retry arm does not stop early on a success: self-consistency is
    agreement across samples, and stopping at the first one would score a
    single lucky attempt as consensus while quietly returning budget an
    equal-compute baseline is supposed to spend.

    Backend failures inside the harness's own error taxonomy are recorded
    as `BACKEND_ERROR` runs with their message preserved. Anything else
    propagates: a `TypeError` in a backend is a bug, and sixty runs
    silently recorded as failures would turn that bug into a regression
    verdict about the agent.
    """
    resolved = strategy if strategy is not None else strategy_for(arm)
    meter = BudgetMeter(budget, clock=clock)
    attempts: list[AttemptRecord] = []
    stop_reason = StopReason.COMPLETED
    error: str | None = None

    for attempt in range(1, resolved.max_attempts + 1):
        before = meter.usage
        try:
            if attempt > 1:
                # Time passed between attempts without being charged; find
                # out here rather than halfway through the next call.
                meter.checkpoint()
            response = backend.run(
                AgentRequest(
                    task=task,
                    attempt=attempt,
                    seed=seed,
                    remaining=meter.remaining(),
                    allow_tools=resolved.allow_tools,
                ),
                meter,
            )
        except BudgetExceededError as exc:
            stop_reason = StopReason.BUDGET_EXHAUSTED
            error = str(exc)
            break
        except EvalError as exc:
            stop_reason = StopReason.BACKEND_ERROR
            error = f"{type(exc).__name__}: {exc}"
            break

        attempts.append(
            AttemptRecord(
                attempt=attempt,
                claimed_success=response.claimed_success,
                usage=usage_delta(before, meter.usage),
                output=response.output,
            )
        )

    frozen_attempts = tuple(attempts)
    # A backend error voids the run's outcome: partial attempts describe an
    # agent that never finished, and scoring them as a verdict would credit
    # or blame the agent for the harness's failure to reach it.
    success = (
        False
        if stop_reason is StopReason.BACKEND_ERROR
        else resolved.verifier.verify(task, frozen_attempts)
    )

    return TaskRun(
        arm_id=arm.id,
        task_id=task.id,
        seed_index=seed_index,
        seed=seed,
        success=success,
        attempts=frozen_attempts,
        usage=meter.usage,
        budget=budget,
        stop_reason=stop_reason,
        error=error,
    )


def run_arm(
    *,
    experiment: Experiment,
    arm: Arm,
    backend: AgentBackend,
    tasks: Sequence[EvalTask],
    clock_factory: ClockFactory,
) -> list[TaskRun]:
    """Run one arm over every task and every seed replicate."""
    budget = experiment.budget
    strategy = strategy_for(arm)
    runs: list[TaskRun] = []
    for seed_index in range(experiment.seeds):
        for task in tasks:
            runs.append(
                run_task(
                    arm=arm,
                    task=task,
                    backend=backend,
                    budget=budget,
                    seed_index=seed_index,
                    seed=derive_seed(experiment.name, task.id, seed_index),
                    strategy=strategy,
                    clock=clock_factory(),
                )
            )
    return runs


def run_experiment(
    experiment: Experiment,
    *,
    backends: Mapping[str, AgentBackend],
    task_source: TaskSource,
    clock_factory: ClockFactory | None = None,
) -> ExperimentResult:
    """Execute a preregistered experiment and return its statistics.

    Args:
        experiment: the preregistered comparison. Validated at
            construction, including its refusal to name a sealed partition.
        backends: arm id to the backend that arm runs. Every declared arm
            needs one; an unmatched key is a typo that would otherwise
            leave an arm silently unrun.
        task_source: where tasks come from. Loaded once and shared by
            every arm, so all arms see the same tasks in the same order.
        clock_factory: builds each run's clock. Defaults to real monotonic
            time; tests inject a frozen clock for deterministic wall-clock
            accounting.

    Raises:
        ExperimentDefinitionError: an arm has no backend, or a backend
            names an arm the experiment does not declare.
        SealedPartitionError: the task source was pointed at sealed data.
    """
    _validate_backends(experiment, backends)

    tasks = task_source.load(experiment.dataset, experiment.partition)
    factory = clock_factory if clock_factory is not None else MonotonicClock

    runs: list[TaskRun] = []
    for arm in experiment.arms:
        runs.extend(
            run_arm(
                experiment=experiment,
                arm=arm,
                backend=backends[arm.id],
                tasks=tasks,
                clock_factory=factory,
            )
        )
    return summarize_experiment(experiment, runs)


def _validate_backends(experiment: Experiment, backends: Mapping[str, AgentBackend]) -> None:
    """Fail before any task runs when the arm/backend wiring is wrong."""
    declared = {arm.id for arm in experiment.arms}
    missing = sorted(declared - set(backends))
    if missing:
        raise ExperimentDefinitionError(f"no backend supplied for arm(s): {', '.join(missing)}")
    unexpected = sorted(set(backends) - declared)
    if unexpected:
        raise ExperimentDefinitionError(
            f"backend(s) supplied for undeclared arm(s): {', '.join(unexpected)}"
        )


__all__ = [
    "ArmStrategy",
    "ClockFactory",
    "run_arm",
    "run_experiment",
    "run_task",
    "strategy_for",
    "usage_delta",
]

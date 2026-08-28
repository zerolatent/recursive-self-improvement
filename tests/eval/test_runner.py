"""Execution under matched budgets — the equal-compute claim, tested.

The spec's D6 row makes two demands of the runner: arms run under
identical budgets (asserted, not assumed), and a regression arm is
flagged. Both are end-to-end properties, so this file runs whole
experiments over scripted backends and inspects the recorded runs —
never a mock of the runner itself.
"""

from __future__ import annotations

import pytest

from evoruntime.eval import (
    Arm,
    ArmKind,
    AttemptCost,
    BudgetExceededError,
    EvalError,
    EvalTask,
    ExperimentDefinitionError,
    ScriptedAgent,
    ScriptedStep,
    StopReason,
    run_arm,
    run_experiment,
    run_task,
    strategy_for,
)
from tests.eval.conftest import frozen_clock, scripted_outcomes, three_arm_experiment

HEAVY_COST = AttemptCost(input_tokens=50_000, output_tokens=5_000, tool_calls=10, wall_clock_s=60.0)
"""One attempt of this costs a third of the task-budget-v1 token envelope."""


class _FailingBackend:
    """A backend that fails on every task with an EvalError."""

    def __init__(self, message: str) -> None:
        self._message = message

    def run(self, request: object, meter: object) -> object:
        raise EvalError(self._message)


def backend_error_agent(message: str = "provider 500") -> _FailingBackend:
    return _FailingBackend(message)


class TestRunTask:
    """One (arm, task, seed) cell."""

    def test_retry_arm_spends_every_attempt_even_after_success(self) -> None:
        """Self-consistency is agreement across samples, not first-success-wins.

        Stopping at the first success would score one lucky sample as
        consensus and quietly refund budget an equal-compute baseline
        spends — the exact asymmetry the harness exists to prevent.
        """
        task = EvalTask(id="tsk_001", prompt="fix it")
        arm = Arm.retry("retry", max_attempts=3)
        backend = ScriptedAgent(
            {"tsk_001": (ScriptedStep(claimed_success=True),)}, default=ScriptedStep(False)
        )

        run = run_task(
            arm=arm,
            task=task,
            backend=backend,
            budget=three_arm_experiment().budget,
            seed_index=0,
            seed=1,
            clock=frozen_clock(),
        )

        assert run.attempt_count == 3
        assert run.stop_reason is StopReason.COMPLETED

    def test_majority_vote_decides_the_retry_verdict(self) -> None:
        """Two of three agreeing successes beat one dissenting failure."""
        task = EvalTask(id="tsk_001", prompt="fix it")
        arm = Arm.retry("retry", max_attempts=3)
        backend = ScriptedAgent(
            {
                "tsk_001": (
                    ScriptedStep(claimed_success=False),
                    ScriptedStep(claimed_success=True),
                    ScriptedStep(claimed_success=True),
                )
            }
        )

        run = run_task(
            arm=arm,
            task=task,
            backend=backend,
            budget=three_arm_experiment().budget,
            seed_index=0,
            seed=1,
            clock=frozen_clock(),
        )

        assert run.success is True

    def test_budget_exhaustion_stops_the_arm_and_records_why(self) -> None:
        """A charge that would cross a ceiling ends the run as BUDGET_EXHAUSTED.

        The distinction matters for interpretation: an arm failing here is
        telling you about the budget, not the agent.
        """
        task = EvalTask(id="tsk_001", prompt="fix it")
        arm = Arm.retry("retry", max_attempts=5)
        # Two heavy attempts fit under the ceiling; the third would cross it.
        backend = ScriptedAgent(
            {"tsk_001": tuple(ScriptedStep(False, cost=HEAVY_COST) for _ in range(4))}
        )

        run = run_task(
            arm=arm,
            task=task,
            backend=backend,
            budget=three_arm_experiment().budget,
            seed_index=0,
            seed=1,
            clock=frozen_clock(),
        )

        assert run.stop_reason is StopReason.BUDGET_EXHAUSTED
        assert run.error is not None
        assert run.success is False
        assert run.attempt_count == 2

    def test_budget_exhaustion_records_nothing_it_did_not_spend(self) -> None:
        """A refused charge leaves the meter untouched — no phantom spend."""
        task = EvalTask(id="tsk_001", prompt="fix it")
        arm = Arm.retry("retry", max_attempts=5)
        backend = ScriptedAgent(
            {"tsk_001": tuple(ScriptedStep(False, cost=HEAVY_COST) for _ in range(4))}
        )

        run = run_task(
            arm=arm,
            task=task,
            backend=backend,
            budget=three_arm_experiment().budget,
            seed_index=0,
            seed=1,
            clock=frozen_clock(),
        )

        assert run.usage.input_tokens == 2 * HEAVY_COST.input_tokens
        assert run.usage.input_tokens <= run.budget.max_input_tokens

    def test_backend_error_voids_the_outcome_but_is_recorded(self) -> None:
        """A failing backend is a failed run with its message preserved.

        Sixty runs silently recorded as successes would turn a harness
        bug into a verdict about the agent; the error string keeps the
        diagnosis one report away.
        """
        task = EvalTask(id="tsk_001", prompt="fix it")

        run = run_task(
            arm=Arm(id="incumbent", kind=ArmKind.INCUMBENT),
            task=task,
            backend=backend_error_agent("provider 500"),
            budget=three_arm_experiment().budget,
            seed_index=0,
            seed=1,
            clock=frozen_clock(),
        )

        assert run.stop_reason is StopReason.BACKEND_ERROR
        assert run.success is False
        assert run.error is not None
        assert "provider 500" in run.error
        assert run.attempts == ()

    def test_one_shot_control_is_not_charged_for_a_tool_loop(self) -> None:
        """The control has no tools, so its recorded cost must show none."""
        task = EvalTask(id="tsk_001", prompt="fix it")
        backend = ScriptedAgent({"tsk_001": (ScriptedStep(True, cost=AttemptCost(tool_calls=4)),)})

        run = run_task(
            arm=Arm(id="one-shot", kind=ArmKind.ONE_SHOT_CONTROL),
            task=task,
            backend=backend,
            budget=three_arm_experiment().budget,
            seed_index=0,
            seed=1,
            clock=frozen_clock(),
        )

        assert run.usage.tool_calls == 0

    def test_frozen_clock_makes_wall_clock_a_property_of_the_script(self) -> None:
        """With a frozen clock, recorded wall clock is exactly what was declared."""
        task = EvalTask(id="tsk_001", prompt="fix it")
        backend = ScriptedAgent(
            {"tsk_001": (ScriptedStep(True, cost=AttemptCost(wall_clock_s=12.5)),)}
        )

        run = run_task(
            arm=Arm(id="incumbent", kind=ArmKind.INCUMBENT),
            task=task,
            backend=backend,
            budget=three_arm_experiment().budget,
            seed_index=0,
            seed=1,
            clock=frozen_clock(),
        )

        assert run.usage.wall_clock_s == pytest.approx(12.5)


class TestStrategyMapping:
    """Arm kind to execution strategy — behaviour only, never resources."""

    def test_incumbent_is_one_tool_enabled_attempt(self) -> None:
        strategy = strategy_for(Arm(id="incumbent", kind=ArmKind.INCUMBENT))

        assert strategy.max_attempts == 1
        assert strategy.allow_tools is True

    def test_retry_carries_its_attempt_count(self) -> None:
        strategy = strategy_for(Arm.retry("retry", max_attempts=4))

        assert strategy.max_attempts == 4
        assert strategy.allow_tools is True

    def test_one_shot_is_one_attempt_without_tools(self) -> None:
        strategy = strategy_for(Arm(id="one-shot", kind=ArmKind.ONE_SHOT_CONTROL))

        assert strategy.max_attempts == 1
        assert strategy.allow_tools is False


class TestRunArm:
    """One arm across the full task set and every seed replicate."""

    def test_run_count_is_tasks_times_seeds(self, tasks: tuple[EvalTask, ...]) -> None:
        """The paired-statistics grid is complete: no cell silently skipped."""
        experiment = three_arm_experiment(seeds=3)
        backend = ScriptedAgent(scripted_outcomes(tasks, 6))

        runs = run_arm(
            experiment=experiment,
            arm=experiment.incumbent,
            backend=backend,
            tasks=tasks,
            clock_factory=frozen_clock,
        )

        assert len(runs) == len(tasks) * 3

    def test_every_cell_gets_its_own_derived_seed(self, tasks: tuple[EvalTask, ...]) -> None:
        """Replicates must be independent streams, not three copies of one."""
        experiment = three_arm_experiment(seeds=3)
        backend = ScriptedAgent(scripted_outcomes(tasks, 6))

        runs = run_arm(
            experiment=experiment,
            arm=experiment.incumbent,
            backend=backend,
            tasks=tasks,
            clock_factory=frozen_clock,
        )

        assert len({run.seed for run in runs}) == len(runs)


class TestRunExperiment:
    """The whole preregistered comparison, end to end."""

    def test_arms_run_under_identical_budgets(
        self, task_source: object, tasks: tuple[EvalTask, ...]
    ) -> None:
        """The D6 acceptance row, asserted on recorded runs.

        Every run in every arm carries the same budget object — the same
        token, tool-call, and wall-clock ceilings. If an arm could widen
        its own envelope, every delta the harness reports would be
        uninterpretable, so this is the assertion the equal-compute claim
        stands on.
        """
        experiment = three_arm_experiment()
        backends = {
            "incumbent": ScriptedAgent(scripted_outcomes(tasks, 8)),
            "retry": ScriptedAgent(scripted_outcomes(tasks, 9)),
            "one-shot": ScriptedAgent(scripted_outcomes(tasks, 6)),
        }

        result = run_experiment(
            experiment, backends=backends, task_source=task_source, clock_factory=frozen_clock
        )

        assert result.budgets_are_matched is True
        budgets = {run.budget for summary in result.primary.values() for run in summary.runs}
        assert len(budgets) == 1
        (budget,) = budgets
        assert budget.max_input_tokens == experiment.budget.max_input_tokens
        assert budget.max_output_tokens == experiment.budget.max_output_tokens
        assert budget.max_tool_calls == experiment.budget.max_tool_calls
        assert budget.max_wall_clock_s == experiment.budget.max_wall_clock_s

    def test_identical_backends_produce_an_exactly_zero_delta(
        self, task_source: object, tasks: tuple[EvalTask, ...]
    ) -> None:
        """Common random numbers: same script, same seeds, no difference at all.

        This is the sharpest null the harness can produce. A nonzero
        interval here would mean the arms were not actually run under the
        same conditions — a harness bug, not a finding.
        """
        experiment = three_arm_experiment()
        shared = ScriptedAgent(scripted_outcomes(tasks, 7))
        backends = {"incumbent": shared, "retry": shared, "one-shot": shared}

        result = run_experiment(
            experiment, backends=backends, task_source=task_source, clock_factory=frozen_clock
        )

        for comparison in result.delta.values():
            assert comparison.bootstrap.observed_delta == 0.0
            assert comparison.verdict.value == "inconclusive"

    def test_a_worse_arm_is_flagged_as_a_regression(
        self, task_source: object, tasks: tuple[EvalTask, ...]
    ) -> None:
        """The D6 acceptance row: a regression arm is flagged.

        The one-shot control is scripted to fail nearly every task while
        the incumbent succeeds on most — a planted regression the harness
        must name, not bury in an average.
        """
        experiment = three_arm_experiment()
        backends = {
            "incumbent": ScriptedAgent(scripted_outcomes(tasks, 10)),
            "retry": ScriptedAgent(scripted_outcomes(tasks, 10)),
            "one-shot": ScriptedAgent(scripted_outcomes(tasks, 2)),
        }

        result = run_experiment(
            experiment, backends=backends, task_source=task_source, clock_factory=frozen_clock
        )

        assert "one-shot" in result.regressions
        assert result.delta["one-shot"].bootstrap.ci_high < 0.0
        assert result.delta["one-shot"].is_regression

    def test_a_better_arm_is_flagged_as_an_improvement(
        self, task_source: object, tasks: tuple[EvalTask, ...]
    ) -> None:
        """The mirror case: the interval must sit entirely above parity."""
        experiment = three_arm_experiment()
        backends = {
            "incumbent": ScriptedAgent(scripted_outcomes(tasks, 4)),
            "retry": ScriptedAgent(scripted_outcomes(tasks, 11)),
            "one-shot": ScriptedAgent(scripted_outcomes(tasks, 4)),
        }

        result = run_experiment(
            experiment, backends=backends, task_source=task_source, clock_factory=frozen_clock
        )

        assert "retry" in result.improvements
        assert result.delta["retry"].bootstrap.ci_low > 0.0

    def test_missing_backend_for_a_declared_arm_fails_before_any_run(
        self, task_source: object, tasks: tuple[EvalTask, ...]
    ) -> None:
        """An unrun arm must be a loud construction error, not an empty row."""
        experiment = three_arm_experiment()
        backends = {
            "incumbent": ScriptedAgent(scripted_outcomes(tasks, 6)),
            "retry": ScriptedAgent(scripted_outcomes(tasks, 6)),
            # "one-shot" deliberately missing.
        }

        with pytest.raises(ExperimentDefinitionError, match="one-shot"):
            run_experiment(
                experiment, backends=backends, task_source=task_source, clock_factory=frozen_clock
            )

    def test_backend_for_an_undeclared_arm_is_a_typo_refused_loudly(
        self, task_source: object, tasks: tuple[EvalTask, ...]
    ) -> None:
        """A backend keyed to an arm the experiment never declared would
        otherwise run work nobody preregistered."""
        experiment = three_arm_experiment()
        backends = {
            "incumbent": ScriptedAgent(scripted_outcomes(tasks, 6)),
            "retry": ScriptedAgent(scripted_outcomes(tasks, 6)),
            "one-shot": ScriptedAgent(scripted_outcomes(tasks, 6)),
            "one-shott": ScriptedAgent(scripted_outcomes(tasks, 6)),
        }

        with pytest.raises(ExperimentDefinitionError, match="one-shott"):
            run_experiment(
                experiment, backends=backends, task_source=task_source, clock_factory=frozen_clock
            )

    def test_sealed_partition_is_refused_at_construction(self, tasks: tuple[EvalTask, ...]) -> None:
        """The first refusal is at experiment construction — a holdout arm is
        never even preregistered. The task source refuses again at load time
        (tests/eval/test_sources.py): the boundary holds at both layers."""
        from evoruntime.datasets.partitions import PartitionKind

        with pytest.raises(ExperimentDefinitionError, match="holdout partition"):
            three_arm_experiment(partition=PartitionKind.HOLDOUT)

    def test_experiment_result_carries_the_canonical_task_order(
        self, task_source: object, tasks: tuple[EvalTask, ...]
    ) -> None:
        """Paired statistics are only valid if every arm aligned to one order."""
        experiment = three_arm_experiment()
        backends = {arm.id: ScriptedAgent(scripted_outcomes(tasks, 6)) for arm in experiment.arms}

        result = run_experiment(
            experiment, backends=backends, task_source=task_source, clock_factory=frozen_clock
        )

        assert result.task_ids == tuple(task.id for task in tasks)

    def test_budget_exhaustion_shows_up_in_the_arm_summary(
        self, task_source: object, tasks: tuple[EvalTask, ...]
    ) -> None:
        """An arm starved by its envelope is visible in the primary metrics."""
        experiment = three_arm_experiment()
        # Costs sized so a retry arm's third attempt crosses the tool-call
        # ceiling: the retry arm exhausts, the single-attempt arms do not.
        starved = ScriptedAgent(scripted_outcomes(tasks, 6, cost=AttemptCost(tool_calls=15)))
        backends = {
            "incumbent": ScriptedAgent(scripted_outcomes(tasks, 6)),
            "retry": starved,
            "one-shot": ScriptedAgent(scripted_outcomes(tasks, 6)),
        }

        result = run_experiment(
            experiment, backends=backends, task_source=task_source, clock_factory=frozen_clock
        )

        assert result.primary["retry"].budget_exhausted_runs > 0
        assert result.primary["incumbent"].budget_exhausted_runs == 0


class TestBudgetMeterRefusal:
    """The meter refuses a charge that would cross a ceiling, atomically."""

    def test_charge_across_a_ceiling_raises_and_records_nothing(self) -> None:
        from evoruntime.eval import TASK_BUDGET_V1, BudgetMeter

        meter = BudgetMeter(TASK_BUDGET_V1, clock=frozen_clock())

        with pytest.raises(BudgetExceededError):
            meter.charge(input_tokens=TASK_BUDGET_V1.max_input_tokens + 1)

        assert meter.usage.input_tokens == 0

    def test_charges_up_to_the_ceiling_exactly_are_allowed(self) -> None:
        from evoruntime.eval import TASK_BUDGET_V1, BudgetMeter

        meter = BudgetMeter(TASK_BUDGET_V1, clock=frozen_clock())

        meter.charge(input_tokens=TASK_BUDGET_V1.max_input_tokens)

        assert meter.usage.input_tokens == TASK_BUDGET_V1.max_input_tokens

    def test_refund_returns_output_headroom(self) -> None:
        """Reserve-then-reconcile needs its refund: reserved output the
        model did not generate goes back before the next attempt."""
        from evoruntime.eval import BudgetMeter, TaskBudget

        budget = TaskBudget(
            max_input_tokens=1_000, max_output_tokens=500, max_tool_calls=10, max_wall_clock_s=60.0
        )
        meter = BudgetMeter(budget, clock=frozen_clock())

        meter.charge(output_tokens=500)
        meter.refund_output_tokens(200)

        assert meter.usage.output_tokens == 300
        assert meter.remaining().output_tokens == 200

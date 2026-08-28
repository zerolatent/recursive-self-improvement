"""Aggregation: turning run records into numbers a reviewer can read.

The results layer is where a harness most easily lies by omission — a
variance number nobody prints, a comparison silently pairing the wrong
tasks, a report that hides budget exhaustion behind a mean. These tests
pin the aggregation to the recorded runs, including the alignment rule
that makes the paired statistics valid at all.
"""

from __future__ import annotations

import pytest

from evoruntime.eval import (
    TASK_BUDGET_V1,
    BudgetUsage,
    EvalTask,
    ScriptedAgent,
    StatisticsError,
    StopReason,
    TaskRun,
    run_experiment,
)
from evoruntime.eval.results import (
    aligned_scores,
    build_arm_summary,
    build_variance_report,
    summarize_experiment,
)
from evoruntime.eval.statistics import sample_stdev
from tests.eval.conftest import frozen_clock, scripted_outcomes, three_arm_experiment


def make_run(
    *,
    arm_id: str = "incumbent",
    task_id: str = "tsk_001",
    seed_index: int = 0,
    success: bool = True,
    stop_reason: StopReason = StopReason.COMPLETED,
) -> TaskRun:
    """A minimal TaskRun with only the fields a test actually varies."""
    return TaskRun(
        arm_id=arm_id,
        task_id=task_id,
        seed_index=seed_index,
        seed=seed_index,
        success=success,
        attempts=(),
        usage=BudgetUsage(input_tokens=100, output_tokens=20, tool_calls=1, wall_clock_s=1.0),
        budget=TASK_BUDGET_V1,
        stop_reason=stop_reason,
    )


class TestVarianceReport:
    """Per-seed success rates and their spread — the honesty check on any delta."""

    def test_reports_one_rate_per_seed(self) -> None:
        runs = [
            make_run(seed_index=0, success=True),
            make_run(seed_index=0, success=False),
            make_run(seed_index=1, success=True),
            make_run(seed_index=1, success=True),
        ]

        report = build_variance_report(runs)

        assert report.per_seed_success_rate == pytest.approx((0.5, 1.0))
        assert report.mean == pytest.approx(0.75)
        assert report.minimum == pytest.approx(0.5)
        assert report.maximum == pytest.approx(1.0)
        assert report.spread == pytest.approx(0.5)

    def test_stdev_is_bessel_corrected_across_seeds(self) -> None:
        """Population stdev would understate seed-to-seed spread at the n=3 floor."""
        runs = [make_run(seed_index=index, success=index < 2) for index in range(3)]

        report = build_variance_report(runs)

        assert report.stdev == pytest.approx(sample_stdev([1.0, 1.0, 0.0]))

    def test_no_runs_is_an_error_not_a_zero(self) -> None:
        """Zero variance for an arm that never ran would be a confident lie."""
        with pytest.raises(StatisticsError, match="no runs"):
            build_variance_report([])


class TestArmSummary:
    """One arm's primary metrics."""

    def test_counts_budget_exhausted_and_backend_error_runs(self) -> None:
        runs = [
            make_run(task_id="tsk_001", stop_reason=StopReason.COMPLETED),
            make_run(task_id="tsk_002", stop_reason=StopReason.BUDGET_EXHAUSTED),
            make_run(task_id="tsk_003", stop_reason=StopReason.BACKEND_ERROR),
        ]

        summary = build_arm_summary("incumbent", "incumbent", 3, runs)

        assert summary.budget_exhausted_runs == 1
        assert summary.backend_error_runs == 1

    def test_success_rate_averages_scores_across_all_runs(self) -> None:
        runs = [
            make_run(task_id="tsk_001", seed_index=0, success=True),
            make_run(task_id="tsk_001", seed_index=1, success=False),
            make_run(task_id="tsk_002", seed_index=0, success=True),
            make_run(task_id="tsk_002", seed_index=1, success=True),
        ]

        summary = build_arm_summary("incumbent", "incumbent", 2, runs)

        assert summary.success_rate == pytest.approx(0.75)

    def test_mean_costs_come_from_the_recorded_usage(self) -> None:
        """Cost metrics are means over runs, not sums — per-run numbers."""
        runs = [
            make_run(task_id="tsk_001", seed_index=0),
            make_run(task_id="tsk_001", seed_index=1),
        ]

        summary = build_arm_summary("incumbent", "incumbent", 2, runs)

        assert summary.mean_input_tokens == pytest.approx(100.0)
        assert summary.mean_output_tokens == pytest.approx(20.0)
        assert summary.mean_total_tokens == pytest.approx(120.0)
        assert summary.mean_tool_calls == pytest.approx(1.0)

    def test_no_runs_is_an_error(self) -> None:
        with pytest.raises(StatisticsError, match="produced no runs"):
            build_arm_summary("ghost", "incumbent", 3, [])


class TestAlignedScores:
    """The pairing contract underneath every bootstrap interval."""

    def test_scores_come_back_in_the_requested_order(self) -> None:
        runs = [
            make_run(task_id="tsk_002", success=False),
            make_run(task_id="tsk_001", success=True),
        ]
        summary = build_arm_summary("incumbent", "incumbent", 1, runs)

        scores = aligned_scores(summary, ("tsk_001", "tsk_002"))

        assert scores == (1.0, 0.0)

    def test_a_missing_task_is_an_error_not_a_shorter_vector(self) -> None:
        """A silently shorter vector would pair task i with task i+1 and
        report the resulting nonsense with a confidence interval on it."""
        runs = [make_run(task_id="tsk_001")]
        summary = build_arm_summary("incumbent", "incumbent", 1, runs)

        with pytest.raises(StatisticsError, match="tsk_002"):
            aligned_scores(summary, ("tsk_001", "tsk_002"))


class TestSummarizeExperiment:
    """The full aggregation, from runs to comparisons."""

    def test_delta_is_computed_against_the_incumbent_only(
        self, task_source: object, tasks: tuple[EvalTask, ...]
    ) -> None:
        """Candidate arms are compared to the baseline; the baseline to nothing."""
        experiment = three_arm_experiment()
        backends = {arm.id: ScriptedAgent(scripted_outcomes(tasks, 6)) for arm in experiment.arms}

        result = run_experiment(
            experiment, backends=backends, task_source=task_source, clock_factory=frozen_clock
        )

        assert set(result.delta) == {"retry", "one-shot"}
        assert experiment.incumbent.id not in result.delta

    def test_per_comparison_alpha_is_the_family_alpha_split(
        self, task_source: object, tasks: tuple[EvalTask, ...]
    ) -> None:
        """Two candidates against one incumbent: each interval gets alpha/2."""
        experiment = three_arm_experiment()
        backends = {arm.id: ScriptedAgent(scripted_outcomes(tasks, 6)) for arm in experiment.arms}

        result = run_experiment(
            experiment, backends=backends, task_source=task_source, clock_factory=frozen_clock
        )

        assert result.per_comparison_alpha == pytest.approx(0.025)

    def test_render_report_names_every_arm_and_the_budget_claim(
        self, task_source: object, tasks: tuple[EvalTask, ...]
    ) -> None:
        """The human-readable artifact must carry the numbers it summarizes."""
        experiment = three_arm_experiment()
        backends = {arm.id: ScriptedAgent(scripted_outcomes(tasks, 6)) for arm in experiment.arms}

        result = run_experiment(
            experiment, backends=backends, task_source=task_source, clock_factory=frozen_clock
        )

        report = result.render_report()

        assert experiment.name in report
        assert "budgets matched: True" in report
        for arm_id in ("incumbent", "retry", "one-shot"):
            assert arm_id in report

    def test_unknown_arm_in_runs_is_refused(self, tasks: tuple[EvalTask, ...]) -> None:
        """A run from an arm the experiment never declared is corrupt data."""
        experiment = three_arm_experiment()
        runs = [make_run(arm_id="phantom", task_id=tasks[0].id)]

        with pytest.raises(StatisticsError, match="phantom"):
            summarize_experiment(experiment, runs)

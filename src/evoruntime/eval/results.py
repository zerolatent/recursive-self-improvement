"""Turning runs into a defensible answer.

Everything here is a pure function of the `TaskRun` records the runner
produced, which is the point: the aggregation and the statistics can be
tested against hand-written runs with known properties, without executing
an agent. If the numbers are wrong, they are wrong in a function you can
call in a unit test.

Two reporting decisions are load-bearing.

*Pairing is by task, averaged over seeds.* Each arm's score for a task is
its mean over the seed replicates, and the bootstrap resamples tasks —
not task-seed cells. Cells from the same task are correlated (same
prompt, same repo, same failure mode), and resampling them independently
would treat one hard task measured three times as three independent
pieces of evidence, narrowing every interval by roughly the square root
of the seed count. Seeds buy variance *reporting*, not extra n.

*The interval is the decision rule, not the p-value.* Each candidate's
interval is built at the multiplicity-adjusted per-comparison alpha, so
an interval that excludes parity has already paid for the family of
comparisons. Holm-adjusted p-values are reported alongside because they
are strictly more powerful than Bonferroni and reviewers ask for them,
but no verdict is read off them.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

from evoruntime.eval.budgets import TaskBudget
from evoruntime.eval.errors import StatisticsError
from evoruntime.eval.experiment import Experiment
from evoruntime.eval.statistics import (
    PairedBootstrapResult,
    Verdict,
    holm_adjusted_p_values,
    mean,
    paired_bootstrap,
    per_comparison_alpha,
    sample_stdev,
)
from evoruntime.eval.tasks import StopReason, TaskRun


@dataclass(frozen=True, slots=True)
class VarianceReport:
    """How much an arm's success rate moved across seed replicates.

    Reported per arm because it is the cheapest available check on
    whether a headline difference is worth believing: an arm whose own
    success rate swings 20 points between seeds has not earned a claim
    about a 5-point improvement, whatever the interval says.
    """

    per_seed_success_rate: tuple[float, ...]
    mean: float
    stdev: float
    minimum: float
    maximum: float

    @property
    def spread(self) -> float:
        """Max minus min — the blunt version of the same warning."""
        return self.maximum - self.minimum


@dataclass(frozen=True, slots=True)
class ArmSummary:
    """One arm's primary metrics over the whole task set."""

    arm_id: str
    arm_kind: str
    budget: TaskBudget
    seeds: int
    task_scores: Mapping[str, float]
    success_rate: float
    variance: VarianceReport
    mean_input_tokens: float
    mean_output_tokens: float
    mean_tool_calls: float
    mean_wall_clock_s: float
    budget_exhausted_runs: int
    backend_error_runs: int
    runs: tuple[TaskRun, ...]

    @property
    def mean_total_tokens(self) -> float:
        """Input plus output, per run — the headline cost number."""
        return self.mean_input_tokens + self.mean_output_tokens


@dataclass(frozen=True, slots=True)
class ArmComparison:
    """A candidate arm measured against the incumbent."""

    arm_id: str
    bootstrap: PairedBootstrapResult
    adjusted_p_value: float

    @property
    def verdict(self) -> Verdict:
        """Improvement, regression, or inconclusive — read off the interval."""
        return self.bootstrap.verdict

    @property
    def is_regression(self) -> bool:
        """True when the whole interval sits below parity."""
        return self.verdict is Verdict.REGRESSION

    @property
    def is_improvement(self) -> bool:
        """True when the whole interval sits above parity."""
        return self.verdict is Verdict.IMPROVEMENT


@dataclass(frozen=True, slots=True)
class ExperimentResult:
    """Everything a reviewer needs to accept or reject the comparison."""

    experiment: Experiment
    task_ids: tuple[str, ...]
    primary: Mapping[str, ArmSummary]
    delta: Mapping[str, ArmComparison]
    per_comparison_alpha: float

    @property
    def regressions(self) -> tuple[str, ...]:
        """Ids of candidate arms whose interval lies entirely below parity."""
        return tuple(
            arm_id for arm_id, comparison in self.delta.items() if comparison.is_regression
        )

    @property
    def improvements(self) -> tuple[str, ...]:
        """Ids of candidate arms whose interval lies entirely above parity."""
        return tuple(
            arm_id for arm_id, comparison in self.delta.items() if comparison.is_improvement
        )

    @property
    def budgets_are_matched(self) -> bool:
        """True when every run in every arm ran under one identical budget.

        The equal-compute claim in one boolean. A campaign that cannot
        answer this yes has not run a controlled comparison, and the PRD's
        kill condition — "equal-compute retry matches the optimizer" —
        cannot be evaluated at all.
        """
        budgets = {run.budget for summary in self.primary.values() for run in summary.runs}
        return len(budgets) == 1

    def render_report(self) -> str:
        """A plain-text summary of the primary metrics and the deltas."""
        lines = [
            f"experiment: {self.experiment.name}",
            f"dataset: {self.experiment.dataset} ({self.experiment.partition.value})",
            f"budget profile: {self.experiment.task_budget_profile}",
            f"tasks: {len(self.task_ids)}  seeds: {self.experiment.seeds}",
            f"budgets matched: {self.budgets_are_matched}",
            "",
            "primary:",
        ]
        for arm_id, summary in self.primary.items():
            lines.append(
                f"  {arm_id}: success={summary.success_rate:.3f} "
                f"(seed sd={summary.variance.stdev:.3f}, spread={summary.variance.spread:.3f}) "
                f"tokens={summary.mean_total_tokens:.0f} "
                f"tools={summary.mean_tool_calls:.1f} "
                f"wall={summary.mean_wall_clock_s:.1f}s "
                f"budget_exhausted={summary.budget_exhausted_runs} "
                f"errors={summary.backend_error_runs}"
            )
        lines.extend(
            [
                "",
                f"delta vs {self.experiment.incumbent.id} "
                f"(alpha/comparison={self.per_comparison_alpha:.4f}):",
            ]
        )
        for arm_id, comparison in self.delta.items():
            bootstrap = comparison.bootstrap
            lines.append(
                f"  {arm_id}: {bootstrap.observed_delta:+.3f} "
                f"[{bootstrap.ci_low:+.3f}, {bootstrap.ci_high:+.3f}] "
                f"p_adj={comparison.adjusted_p_value:.4f} -> {comparison.verdict.value}"
            )
        return "\n".join(lines)


def build_variance_report(runs: Sequence[TaskRun]) -> VarianceReport:
    """Success rate per seed replicate, plus its spread.

    Raises:
        StatisticsError: no runs were supplied.
    """
    if not runs:
        raise StatisticsError("cannot report variance for an arm with no runs")

    by_seed: dict[int, list[float]] = {}
    for run in runs:
        by_seed.setdefault(run.seed_index, []).append(run.score)
    rates = tuple(mean(by_seed[index]) for index in sorted(by_seed))
    return VarianceReport(
        per_seed_success_rate=rates,
        mean=mean(rates),
        stdev=sample_stdev(rates),
        minimum=min(rates),
        maximum=max(rates),
    )


def build_arm_summary(
    arm_id: str, arm_kind: str, seeds: int, runs: Sequence[TaskRun]
) -> ArmSummary:
    """Aggregate one arm's runs into its primary metrics.

    Raises:
        StatisticsError: the arm produced no runs.
    """
    if not runs:
        raise StatisticsError(f"arm {arm_id!r} produced no runs")

    scores_by_task: dict[str, list[float]] = {}
    for run in runs:
        scores_by_task.setdefault(run.task_id, []).append(run.score)
    task_scores = {task_id: mean(scores) for task_id, scores in scores_by_task.items()}

    return ArmSummary(
        arm_id=arm_id,
        arm_kind=arm_kind,
        budget=runs[0].budget,
        seeds=seeds,
        task_scores=MappingProxyType(task_scores),
        success_rate=mean([run.score for run in runs]),
        variance=build_variance_report(runs),
        mean_input_tokens=mean([float(run.usage.input_tokens) for run in runs]),
        mean_output_tokens=mean([float(run.usage.output_tokens) for run in runs]),
        mean_tool_calls=mean([float(run.usage.tool_calls) for run in runs]),
        mean_wall_clock_s=mean([run.usage.wall_clock_s for run in runs]),
        budget_exhausted_runs=sum(
            1 for run in runs if run.stop_reason is StopReason.BUDGET_EXHAUSTED
        ),
        backend_error_runs=sum(1 for run in runs if run.stop_reason is StopReason.BACKEND_ERROR),
        runs=tuple(runs),
    )


def aligned_scores(summary: ArmSummary, task_ids: Sequence[str]) -> tuple[float, ...]:
    """An arm's per-task scores in the experiment's canonical task order.

    Raises:
        StatisticsError: the arm is missing a task the comparison needs.
            A silently shorter vector would pair task *i* of one arm with
            task *i+1* of another and report the resulting nonsense with
            a confidence interval around it.
    """
    missing = [task_id for task_id in task_ids if task_id not in summary.task_scores]
    if missing:
        raise StatisticsError(
            f"arm {summary.arm_id!r} has no score for {len(missing)} task(s): "
            f"{', '.join(missing[:5])}"
        )
    return tuple(summary.task_scores[task_id] for task_id in task_ids)


def summarize_experiment(experiment: Experiment, runs: Sequence[TaskRun]) -> ExperimentResult:
    """Aggregate every arm and compare each candidate to the incumbent.

    Raises:
        StatisticsError: an arm produced no runs, or the arms disagree
            about which tasks they ran.
    """
    runs_by_arm: dict[str, list[TaskRun]] = {arm.id: [] for arm in experiment.arms}
    for run in runs:
        if run.arm_id not in runs_by_arm:
            raise StatisticsError(f"run references unknown arm {run.arm_id!r}")
        runs_by_arm[run.arm_id].append(run)

    primary = {
        arm.id: build_arm_summary(arm.id, arm.kind.value, experiment.seeds, runs_by_arm[arm.id])
        for arm in experiment.arms
    }

    incumbent = primary[experiment.incumbent.id]
    # Canonical task order comes from the incumbent's first-seen runs, so
    # every arm is aligned to the same sequence rather than to its own
    # dict ordering.
    task_ids = tuple(dict.fromkeys(run.task_id for run in runs_by_arm[experiment.incumbent.id]))
    baseline = aligned_scores(incumbent, task_ids)

    candidates = experiment.candidate_arms
    comparison_alpha = per_comparison_alpha(
        experiment.alpha, len(candidates), experiment.multiplicity
    )

    bootstraps = {
        arm.id: paired_bootstrap(
            baseline,
            aligned_scores(primary[arm.id], task_ids),
            iterations=experiment.bootstrap_iterations,
            alpha=comparison_alpha,
            seed=experiment.bootstrap_seed,
        )
        for arm in candidates
    }
    adjusted = holm_adjusted_p_values(
        {arm_id: result.p_value for arm_id, result in bootstraps.items()}
    )
    delta = {
        arm_id: ArmComparison(arm_id=arm_id, bootstrap=result, adjusted_p_value=adjusted[arm_id])
        for arm_id, result in bootstraps.items()
    }

    return ExperimentResult(
        experiment=experiment,
        task_ids=task_ids,
        primary=MappingProxyType(primary),
        delta=MappingProxyType(delta),
        per_comparison_alpha=comparison_alpha,
    )


__all__ = [
    "ArmComparison",
    "ArmSummary",
    "ExperimentResult",
    "VarianceReport",
    "aligned_scores",
    "build_arm_summary",
    "build_variance_report",
    "summarize_experiment",
]

"""Cost/latency slice reporting (H10): the H5 archive's aggregation input.

The contract under test: runs plus task metadata aggregate into
deterministic, sorted per-slice summaries over the attested cost
vocabulary — and a task that does not declare a slice key contributes to
no slice for that key, rather than blurring an "everything else" bucket.
"""

from __future__ import annotations

import pytest

from evoruntime.core.metrics import COST_METRIC_KEYS
from evoruntime.eval import BudgetUsage, EvalTask, StopReason, TaskBudget, TaskRun
from evoruntime.eval.results import build_arm_summary
from evoruntime.eval.slices import (
    SLICE_COST_METRICS,
    SLICE_DIFFICULTY,
    SLICE_FIXTURE_ID,
    SLICE_KEYS,
    SLICE_TASK_TYPE,
    SliceAggregate,
    arm_slice_report,
    experiment_slice_report,
    render_slice_report,
    slice_aggregates,
    task_slice_index,
)

BUDGET = TaskBudget(
    max_input_tokens=10_000, max_output_tokens=2_000, max_tool_calls=10, max_wall_clock_s=120.0
)

TASKS = (
    EvalTask(
        id="t-easy",
        prompt="easy fix",
        metadata={SLICE_TASK_TYPE: "bugfix", SLICE_DIFFICULTY: "easy", SLICE_FIXTURE_ID: "fx-1"},
    ),
    EvalTask(
        id="t-hard",
        prompt="hard fix",
        metadata={SLICE_TASK_TYPE: "bugfix", SLICE_DIFFICULTY: "hard", SLICE_FIXTURE_ID: "fx-2"},
    ),
    EvalTask(id="t-bare", prompt="no annotations"),  # declares no slice keys
)


def _run(
    task_id: str,
    *,
    success: bool,
    input_tokens: int = 100,
    output_tokens: int = 50,
    wall_clock_s: float = 2.0,
) -> TaskRun:
    return TaskRun(
        arm_id="incumbent",
        task_id=task_id,
        seed_index=0,
        seed=1,
        success=success,
        attempts=(),
        usage=BudgetUsage(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            tool_calls=1,
            wall_clock_s=wall_clock_s,
        ),
        budget=BUDGET,
        stop_reason=StopReason.COMPLETED,
    )


class TestSliceVocabulary:
    """The vocabulary and its tie to the attested cost metrics."""

    def test_slice_cost_metrics_are_attested_keys(self) -> None:
        """Every reported cost metric is a member of COST_METRIC_KEYS."""
        assert set(SLICE_COST_METRICS) <= COST_METRIC_KEYS

    def test_vocabulary_is_the_closed_five_key_set(self) -> None:
        """The H5 contract: five keys, fixed order."""
        assert SLICE_KEYS == (
            "task_type",
            "difficulty",
            "language",
            "failure_category",
            "fixture_id",
        )


class TestTaskSliceIndex:
    """The task_id → slice-annotation index."""

    def test_only_declared_keys_are_indexed(self) -> None:
        """A task missing a key contributes to no slice for that key."""
        index = task_slice_index(TASKS)

        assert index["t-easy"] == {
            "task_type": "bugfix",
            "difficulty": "easy",
            "fixture_id": "fx-1",
        }
        assert "difficulty" not in index["t-bare"]

    def test_unannotated_task_maps_to_an_empty_dict(self) -> None:
        """No silent 'everything else' bucket for unannotated tasks."""
        index = task_slice_index([TASKS[2]])

        assert index == {"t-bare": {}}


class TestSliceAggregates:
    """The pure aggregation from runs to per-slice summaries."""

    def test_runs_group_by_declared_slice_values(self) -> None:
        """Two difficulty slices, each with its own cost/latency summary."""
        runs = [
            _run("t-easy", success=True, input_tokens=100, output_tokens=50, wall_clock_s=2.0),
            _run("t-easy", success=False, input_tokens=200, output_tokens=100, wall_clock_s=4.0),
            _run("t-hard", success=False, input_tokens=300, output_tokens=150, wall_clock_s=6.0),
        ]

        aggregates = slice_aggregates(runs, task_slice_index(TASKS))

        assert [(a.slice_key, a.slice_value, a.runs) for a in aggregates] == [
            ("task_type", "bugfix", 3),
            ("difficulty", "easy", 2),
            ("difficulty", "hard", 1),
            ("fixture_id", "fx-1", 2),
            ("fixture_id", "fx-2", 1),
        ]
        easy = next(a for a in aggregates if a.slice_value == "easy")
        assert easy.success_rate == pytest.approx(0.5)
        assert easy.mean_input_tokens == pytest.approx(150.0)
        assert easy.mean_total_tokens == pytest.approx(225.0)
        assert easy.mean_wall_clock_s == pytest.approx(3.0)

    def test_unannotated_tasks_contribute_to_no_slice(self) -> None:
        """A run whose task declares no keys appears in no aggregate."""
        aggregates = slice_aggregates([_run("t-bare", success=True)], task_slice_index(TASKS))

        assert aggregates == ()

    def test_empty_runs_yield_no_aggregates(self) -> None:
        """No runs, no slices — not an error, an empty report."""
        assert slice_aggregates([], task_slice_index(TASKS)) == ()

    def test_output_is_sorted_deterministically(self) -> None:
        """Same runs, same order — key order first, then value."""
        runs = [
            _run("t-hard", success=True),
            _run("t-easy", success=True),
        ]
        first = slice_aggregates(runs, task_slice_index(TASKS))
        second = slice_aggregates(list(reversed(runs)), task_slice_index(TASKS))

        assert first == second

    def test_subset_of_keys_narrows_the_report(self) -> None:
        """A caller can slice on fewer keys than the full vocabulary."""
        runs = [_run("t-easy", success=True)]

        aggregates = slice_aggregates(runs, task_slice_index(TASKS), keys=(SLICE_DIFFICULTY,))

        assert [a.slice_key for a in aggregates] == ["difficulty"]

    def test_run_from_an_unknown_task_is_a_key_error(self) -> None:
        """Runs from a different task set are a caller bug, surfaced loudly."""
        with pytest.raises(KeyError):
            slice_aggregates([_run("t-unknown", success=True)], task_slice_index(TASKS))


class TestArmAndExperimentReports:
    """The arm- and experiment-level wrappers over the same aggregation."""

    def test_arm_slice_report_slices_the_arm_runs(self) -> None:
        """The arm's runs, sliced — built through the real summary builder."""
        runs = [
            _run("t-easy", success=True),
            _run("t-hard", success=False),
        ]
        arm = build_arm_summary("incumbent", "incumbent", seeds=1, runs=runs)

        aggregates = arm_slice_report(arm, TASKS)

        assert {(a.slice_key, a.slice_value) for a in aggregates} == {
            ("task_type", "bugfix"),
            ("difficulty", "easy"),
            ("difficulty", "hard"),
            ("fixture_id", "fx-1"),
            ("fixture_id", "fx-2"),
        }

    def test_experiment_report_covers_every_arm_in_id_order(self) -> None:
        """The H5 input: one slice report per arm, arms sorted by id."""
        incumbent_runs = [_run("t-easy", success=True)]
        candidate_runs = [
            TaskRun(
                arm_id="candidate",
                task_id="t-easy",
                seed_index=0,
                seed=1,
                success=True,
                attempts=(),
                usage=BudgetUsage(input_tokens=10, output_tokens=5, wall_clock_s=0.5),
                budget=BUDGET,
                stop_reason=StopReason.COMPLETED,
            )
        ]
        incumbent = build_arm_summary("incumbent", "incumbent", seeds=1, runs=incumbent_runs)
        candidate = build_arm_summary(
            "candidate", "retry-self-consistency", seeds=1, runs=candidate_runs
        )

        class _Result:
            primary = {"incumbent": incumbent, "candidate": candidate}

        report = experiment_slice_report(_Result(), TASKS)  # type: ignore[arg-type]

        assert list(report) == ["candidate", "incumbent"]
        assert report["incumbent"][0].slice_value == "bugfix"

    def test_render_is_deterministic_text(self) -> None:
        """Same report, same bytes — the archive's rendering is stable."""
        runs = [_run("t-easy", success=True), _run("t-hard", success=False)]
        arm = build_arm_summary("incumbent", "incumbent", seeds=1, runs=runs)
        report = {"incumbent": arm_slice_report(arm, TASKS)}

        text = render_slice_report(report)

        assert text == (
            "arm incumbent:\n"
            "  task_type=bugfix: runs=2 success=0.500 tokens=150.0 wall=2.00s\n"
            "  difficulty=easy: runs=1 success=1.000 tokens=150.0 wall=2.00s\n"
            "  difficulty=hard: runs=1 success=0.000 tokens=150.0 wall=2.00s\n"
            "  fixture_id=fx-1: runs=1 success=1.000 tokens=150.0 wall=2.00s\n"
            "  fixture_id=fx-2: runs=1 success=0.000 tokens=150.0 wall=2.00s"
        )
        assert render_slice_report(report) == text


def test_slice_aggregate_is_frozen() -> None:
    """A slice summary is a value, not a mutable accumulator."""
    aggregate = SliceAggregate(
        slice_key="difficulty",
        slice_value="easy",
        runs=1,
        success_rate=1.0,
        mean_input_tokens=10.0,
        mean_output_tokens=5.0,
        mean_tool_calls=0.0,
        mean_wall_clock_s=1.0,
    )

    with pytest.raises(AttributeError):
        aggregate.runs = 2  # type: ignore[misc]

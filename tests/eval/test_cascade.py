"""Cascade semantics (F6): ordering, short-circuit, early-exit pairing, tagging.

Each test pins one property the acceptance row names: a cheap-stage failure
must stop the cascade before any expensive stage runs, an early exit must
leave the paired comparison defensible (failure outcome for the candidate
arm, pairing preserved), metrics must stay attributable per stage, and the
stage order must be a total order the runner cannot silently reorder.
"""

from __future__ import annotations

import pytest

from evoruntime.campaign.spec import EvaluatorBinding
from evoruntime.eval import (
    CascadeDefinitionError,
    CascadeResult,
    CascadeStage,
    EvaluatorCostClass,
    StageOutcome,
    holdout_purpose,
    parse_holdout_purpose,
    run_cascade,
    stage_from_binding,
    stage_tagged_metrics,
)


class RecordingEvaluator:
    """Runs stages in a scripted pass/fail order, recording what it was asked."""

    def __init__(self, failing_stages: set[str]) -> None:
        self._failing = failing_stages
        self.called: list[str] = []

    def __call__(self, stage: CascadeStage) -> StageOutcome:
        self.called.append(stage.name)
        passed = stage.name not in self._failing
        return StageOutcome(
            passed=passed,
            metrics={"success_rate": 1.0 if passed else 0.0},
        )


def make_stages() -> tuple[CascadeStage, ...]:
    """The canonical three-tier cascade: cheap lint, standard tests, expensive full."""
    return (
        CascadeStage(name="full-holdout", stage=2, cost_class=EvaluatorCostClass.EXPENSIVE),
        CascadeStage(name="test-suite", stage=1, cost_class=EvaluatorCostClass.STANDARD),
        CascadeStage(name="lint", stage=0, cost_class=EvaluatorCostClass.CHEAP),
    )


def test_stages_run_in_ascending_stage_order_regardless_of_declaration_order() -> None:
    evaluator = RecordingEvaluator(failing_stages=set())
    result = run_cascade(make_stages(), evaluator)

    # Declared expensive-first; the runner must still run cheap -> expensive.
    assert evaluator.called == ["lint", "test-suite", "full-holdout"]
    assert result.completed
    assert result.short_circuited_at is None
    assert result.skipped_stages == ()


def test_cheap_stage_failure_stops_the_cascade_and_expensive_stages_never_run() -> None:
    evaluator = RecordingEvaluator(failing_stages={"lint"})
    result = run_cascade(make_stages(), evaluator)

    # The expensive evaluator was never called — not "ran and failed", never ran.
    assert evaluator.called == ["lint"]
    assert not result.completed
    assert result.short_circuited_at == "lint"
    assert [stage.name for stage in result.skipped_stages] == ["test-suite", "full-holdout"]


def test_standard_stage_failure_also_short_circuits_the_expensive_tier() -> None:
    evaluator = RecordingEvaluator(failing_stages={"test-suite"})
    result = run_cascade(make_stages(), evaluator)

    assert evaluator.called == ["lint", "test-suite"]
    assert result.short_circuited_at == "test-suite"
    assert [stage.name for stage in result.skipped_stages] == ["full-holdout"]


def test_short_circuit_cleared_lets_the_cascade_continue_past_a_failure() -> None:
    informational = CascadeStage(
        name="lint",
        stage=0,
        cost_class=EvaluatorCostClass.CHEAP,
        short_circuit=False,
    )
    stages = make_stages()  # (full-holdout, test-suite, lint) — drop the short-circuiting lint
    evaluator = RecordingEvaluator(failing_stages={"lint"})
    result = run_cascade((informational, stages[1], stages[0]), evaluator)

    # The lint failure is recorded but does not gate the expensive tier.
    assert evaluator.called == ["lint", "test-suite", "full-holdout"]
    assert result.completed
    assert result.short_circuited_at is None


def test_duplicate_stage_numbers_are_a_definition_error() -> None:
    stages = (
        CascadeStage(name="a", stage=1, cost_class=EvaluatorCostClass.CHEAP),
        CascadeStage(name="b", stage=1, cost_class=EvaluatorCostClass.EXPENSIVE),
    )
    with pytest.raises(CascadeDefinitionError, match="duplicate cascade stage"):
        run_cascade(stages, RecordingEvaluator(failing_stages=set()))


def test_empty_cascade_is_a_definition_error() -> None:
    with pytest.raises(CascadeDefinitionError, match="at least one stage"):
        run_cascade((), RecordingEvaluator(failing_stages=set()))


def test_early_exit_scores_are_a_failure_outcome_that_preserves_pairing() -> None:
    evaluator = RecordingEvaluator(failing_stages={"lint"})
    result = run_cascade(make_stages(), evaluator)

    scores = result.candidate_scores(tasks=12)
    # One score per task — the pairing with the incumbent arm is intact —
    # and every score is a failure, because the candidate never cleared a
    # stage. An early exit is a measured failure, not a shorter sample.
    assert len(scores) == 12
    assert scores == (0.0,) * 12


def test_completed_cascade_scores_from_the_final_stage() -> None:
    passed = run_cascade(make_stages(), RecordingEvaluator(failing_stages=set()))
    failed_final = run_cascade(make_stages(), RecordingEvaluator(failing_stages={"full-holdout"}))

    assert passed.candidate_scores(tasks=4) == (1.0,) * 4
    assert failed_final.candidate_scores(tasks=4) == (0.0,) * 4


def test_early_exit_pairing_feeds_a_defensible_paired_bootstrap() -> None:
    """The full pairing story: incumbent completes, candidate exits early."""
    from evoruntime.eval.statistics import Verdict, paired_bootstrap

    incumbent = run_cascade(make_stages(), RecordingEvaluator(failing_stages=set()))
    candidate = run_cascade(make_stages(), RecordingEvaluator(failing_stages={"lint"}))

    incumbent_scores = incumbent.candidate_scores(tasks=8)
    candidate_scores = candidate.candidate_scores(tasks=8)
    assert len(incumbent_scores) == len(candidate_scores)  # pairing preserved

    result = paired_bootstrap(
        incumbent_scores, candidate_scores, iterations=200, alpha=0.05, seed=7
    )
    # The candidate's early exit counts against it: the interval sits below
    # parity, a regression verdict — not an error and not a missing sample.
    assert result.verdict is Verdict.REGRESSION


def test_stage_metrics_are_tagged_per_stage() -> None:
    stage = CascadeStage(name="test-suite", stage=1, cost_class=EvaluatorCostClass.STANDARD)
    outcome = StageOutcome(passed=True, metrics={"success_rate": 0.75})

    tagged = stage_tagged_metrics(stage, outcome)

    assert tagged["stage_1.stage_index"] == 1.0
    assert tagged["stage_1.passed"] == 1.0
    assert tagged["stage_1.success_rate"] == 0.75


def test_stage_run_records_carry_their_own_tagged_metrics() -> None:
    evaluator = RecordingEvaluator(failing_stages=set())
    result = run_cascade(make_stages(), evaluator)

    lint_run = result.stage_runs[0]
    assert lint_run.stage.name == "lint"
    assert lint_run.metrics["stage_0.passed"] == 1.0
    assert lint_run.metrics["stage_0.success_rate"] == 1.0
    expensive_run = result.stage_runs[2]
    assert expensive_run.stage.cost_class is EvaluatorCostClass.EXPENSIVE
    assert expensive_run.metrics["stage_2.passed"] == 1.0


def test_holdout_purpose_is_stable_and_parseable() -> None:
    purpose = holdout_purpose(1, "test-suite")
    assert purpose == "cascade.stage.1:test-suite"
    assert parse_holdout_purpose(purpose) == (1, "test-suite")
    # Non-cascade purposes (the ledger holds many callers') parse to None.
    assert parse_holdout_purpose("baseline.dev-eval") is None


def test_stage_from_binding_projects_the_spec_vocabulary() -> None:
    binding = EvaluatorBinding(
        name="test-suite",
        pinned_image="registry.test/evaluator@sha256:" + "b" * 64,
        stage=1,
        cost_class=EvaluatorCostClass.STANDARD,
        short_circuit=True,
    )

    stage = stage_from_binding(binding)

    assert stage.name == "test-suite"
    assert stage.stage == 1
    assert stage.cost_class is EvaluatorCostClass.STANDARD
    assert stage.short_circuit is True


def test_cascade_result_candidate_scores_reject_nonpositive_tasks() -> None:
    result = CascadeResult(stage_runs=(), skipped_stages=())
    with pytest.raises(CascadeDefinitionError, match="at least one task"):
        result.candidate_scores(tasks=0)

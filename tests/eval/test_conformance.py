"""Self-edit conformance evaluator tests (Phase 3, G2): the pinned stage-0
identity, the zero-regression rule, and early exit scored as measured failure.

The evaluator's semantics are the point of G2's conformance deliverable, so
every not-proven-safe path is tested through the real interpreter — a
conformance gate that could pass on a timeout or an unparseable summary
would be a gate that could be talked out of gating.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from evoruntime.eval.cascade import CascadeStage, EvaluatorCostClass
from evoruntime.eval.conformance import (
    CONFORMANCE_STAGE_NAME,
    CONFORMANCE_STAGE_NUMBER,
    SelfEditConformanceEvaluator,
    SuiteRunResult,
    parse_pytest_summary,
    run_self_edit_conformance,
)
from evoruntime.eval.errors import CascadeDefinitionError


@dataclass(frozen=True)
class _ScriptedRunner:
    """A ConformanceSuiteRunner that replays a canned SuiteRunResult."""

    result: SuiteRunResult

    def run(self, command: tuple[str, ...]) -> SuiteRunResult:
        return self.result


def _evaluator(result: SuiteRunResult) -> SelfEditConformanceEvaluator:
    return SelfEditConformanceEvaluator(
        suite_command=("uv", "run", "pytest", "tests/conformance"),
        runner=_ScriptedRunner(result),
    )


GREEN = SuiteRunResult(returncode=0, stdout="118 passed in 2.31s\n")
REGRESSION = SuiteRunResult(returncode=1, stdout="3 failed, 115 passed in 2.31s\n")
TIMEOUT = SuiteRunResult(returncode=None, stdout="", timed_out=True)
CRASH = SuiteRunResult(returncode=None, stdout="", stderr="sandbox killed\n")
NO_SUMMARY = SuiteRunResult(returncode=0, stdout="collected 0 items\n")
ONLY_FAILURES = SuiteRunResult(returncode=1, stdout="3 failed in 1.02s\n")


class TestPinnedStage:
    def test_stage_is_pinned_at_zero_with_short_circuit(self) -> None:
        evaluator = _evaluator(GREEN)
        assert evaluator.stage.stage == CONFORMANCE_STAGE_NUMBER == 0
        assert evaluator.stage.short_circuit is True
        assert evaluator.stage.name == CONFORMANCE_STAGE_NAME

    def test_stage_is_the_cheapest_cost_class(self) -> None:
        evaluator = _evaluator(GREEN)
        assert evaluator.stage.cost_class is EvaluatorCostClass.CHEAP

    def test_empty_suite_command_is_refused(self) -> None:
        with pytest.raises(CascadeDefinitionError, match="non-empty suite command"):
            SelfEditConformanceEvaluator(suite_command=(), runner=_ScriptedRunner(GREEN))

    def test_refuses_to_evaluate_a_foreign_stage(self) -> None:
        evaluator = _evaluator(GREEN)
        foreign = CascadeStage(
            name="holdout_scoring", stage=2, cost_class=EvaluatorCostClass.EXPENSIVE
        )
        with pytest.raises(CascadeDefinitionError, match="pinned to stage"):
            evaluator.evaluate(foreign)


class TestZeroRegressions:
    def test_green_suite_passes_with_regressions_at_zero(self) -> None:
        evaluator = _evaluator(GREEN)
        outcome = evaluator.evaluate(evaluator.stage)
        assert outcome.passed is True
        assert outcome.metrics["regressions"] == 0.0
        assert outcome.metrics["tests_passed"] == 118.0

    def test_one_regression_fails_the_stage(self) -> None:
        evaluator = _evaluator(REGRESSION)
        outcome = evaluator.evaluate(evaluator.stage)
        assert outcome.passed is False
        assert outcome.metrics["regressions"] == 3.0
        assert outcome.metrics["failure_reason"] == 4.0

    def test_a_single_failure_summary_also_fails(self) -> None:
        evaluator = _evaluator(ONLY_FAILURES)
        outcome = evaluator.evaluate(evaluator.stage)
        assert outcome.passed is False
        assert outcome.metrics["regressions"] == 3.0
        assert outcome.metrics["tests_passed"] == 0.0


class TestEarlyExitIsMeasuredFailure:
    def test_timeout_is_a_measured_failure_not_a_skip(self) -> None:
        evaluator = _evaluator(TIMEOUT)
        outcome = evaluator.evaluate(evaluator.stage)
        assert outcome.passed is False
        assert outcome.metrics["suite_timed_out"] == 1.0
        assert outcome.metrics["failure_reason"] == 1.0

    def test_crash_without_exit_is_a_measured_failure(self) -> None:
        evaluator = _evaluator(CRASH)
        outcome = evaluator.evaluate(evaluator.stage)
        assert outcome.passed is False
        assert outcome.metrics["failure_reason"] == 2.0

    def test_unparseable_output_is_a_measured_failure(self) -> None:
        evaluator = _evaluator(NO_SUMMARY)
        outcome = evaluator.evaluate(evaluator.stage)
        assert outcome.passed is False
        assert outcome.metrics["suite_summary_parsed"] == 0.0
        assert outcome.metrics["failure_reason"] == 3.0

    def test_zero_tests_collected_is_a_measured_failure(self) -> None:
        empty = SuiteRunResult(returncode=5, stdout="no tests ran in 0.01s\n")
        evaluator = _evaluator(empty)
        outcome = evaluator.evaluate(evaluator.stage)
        assert outcome.passed is False
        assert outcome.metrics["failure_reason"] == 5.0

    def test_exit_code_and_summary_disagreement_fails_closed(self) -> None:
        lying = SuiteRunResult(returncode=1, stdout="118 passed in 2.31s\n")
        evaluator = _evaluator(lying)
        outcome = evaluator.evaluate(evaluator.stage)
        assert outcome.passed is False
        assert outcome.metrics["failure_reason"] == 6.0


class TestRunnerWiring:
    def test_the_pinned_command_is_what_the_runner_receives(self) -> None:
        seen: list[tuple[str, ...]] = []

        @dataclass(frozen=True)
        class _Recording:
            result: SuiteRunResult

            def run(self, command: tuple[str, ...]) -> SuiteRunResult:
                seen.append(command)
                return self.result

        evaluator = SelfEditConformanceEvaluator(
            suite_command=("uv", "run", "pytest", "tests/conformance"),
            runner=_Recording(GREEN),
        )
        evaluator.evaluate(evaluator.stage)
        assert seen == [("uv", "run", "pytest", "tests/conformance")]


class TestSummaryParsing:
    def test_both_counts(self) -> None:
        assert parse_pytest_summary("3 failed, 115 passed in 2.31s") == (3, 115)

    def test_passed_only(self) -> None:
        assert parse_pytest_summary("118 passed in 2.31s") == (0, 118)

    def test_failed_only(self) -> None:
        assert parse_pytest_summary("3 failed in 1.02s") == (3, 0)

    def test_no_summary_returns_none(self) -> None:
        assert parse_pytest_summary("no tests ran in 0.01s") is None
        assert parse_pytest_summary("") is None


def test_single_stage_run_matches_cascade_shape() -> None:
    stage, outcome = run_self_edit_conformance(_evaluator(GREEN))
    assert stage.stage == 0
    assert stage.name == CONFORMANCE_STAGE_NAME
    assert outcome.passed is True

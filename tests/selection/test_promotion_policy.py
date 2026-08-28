"""Promotion policy tests (E4): the six §12.5 conditions, the failing-
conditions matrix, protected-slice fail-closed behavior, and tier-3+
rejection."""

from __future__ import annotations

import pytest

from evoruntime.selection import (
    ARTIFACT_OPTIMIZATION_LABEL,
    CONDITION_BUDGET,
    CONDITION_NO_CRITICAL_FAILURE,
    CONDITION_NO_INTEGRITY_FINDINGS,
    CONDITION_PROTECTED_SLICES,
    CONDITION_STATISTICAL,
    CONDITION_TRANSFER_SCOPE,
    ConditionResult,
    InvalidPromotionPolicyError,
    PairedScores,
    PromotionDecision,
    PromotionEvidence,
    PromotionPolicyDocument,
    ResolvedRelease,
    TierRejectedError,
    evaluate_promotion,
)

N_PAIRS = 40
SEED = 20_260_827


def _paired(gain_per_task: float) -> PairedScores:
    """Deterministic paired scores: candidate = baseline + gain per task."""
    baseline = tuple(0.5 + 0.01 * i for i in range(N_PAIRS))
    candidate = tuple(min(1.0, b + gain_per_task) for b in baseline)
    return PairedScores(
        task_ids=tuple(f"task-{i:03d}" for i in range(N_PAIRS)),
        baseline=baseline,
        candidate=candidate,
    )


def _evidence(**overrides: object) -> PromotionEvidence:
    """A candidate that passes every condition by default."""
    values: dict[str, object] = {
        "arm_id": "arm-candidate",
        "heldout": _paired(gain_per_task=0.15),
        "success_gain": 0.15,
        "cost_reduction": 0.0,
        "p95_latency_regression": 0.02,
        "severity1_regressions": 0,
        "critical_failures": (),
        "budget_pass": True,
        "integrity_findings": (),
        "claimed_transfer_scope": ("python",),
        "evaluated_transfer_scope": ("python",),
        "bootstrap_iterations": 2_000,
        "bootstrap_seed": SEED,
    }
    values.update(overrides)
    return PromotionEvidence(**values)  # type: ignore[arg-type]


def _policy(**overrides: object) -> PromotionPolicyDocument:
    values: dict[str, object] = {"policy_id": "mvp-gates-v1"}
    values.update(overrides)
    return PromotionPolicyDocument(**values)  # type: ignore[arg-type]


def _release(**overrides: object) -> ResolvedRelease:
    values: dict[str, object] = {"artifact_classes": ("prompt_bundle",)}
    values.update(overrides)
    return ResolvedRelease(**values)  # type: ignore[arg-type]


def _condition(decision: PromotionDecision, name: str) -> ConditionResult:
    return next(c for c in decision.conditions if c.condition == name)


class TestPassingCandidate:
    def test_all_six_conditions_pass(self) -> None:
        decision = evaluate_promotion(_policy(), _evidence(), release=_release())
        assert decision.eligible
        assert decision.failed_conditions() == ()
        assert decision.tier == 1
        assert decision.label == ARTIFACT_OPTIMIZATION_LABEL
        assert decision.ci_low > 0.0

    def test_preregistered_non_inferiority_path_passes(self) -> None:
        """Cost-reduction path: success non-inferior, 20%+ cheaper."""
        decision = evaluate_promotion(
            _policy(),
            _evidence(
                heldout=_paired(gain_per_task=0.0),
                success_gain=0.0,
                cost_reduction=0.25,
                preregistered_non_inferiority=True,
            ),
            release=_release(),
        )
        statistical = _condition(decision, CONDITION_STATISTICAL)
        assert statistical.passed
        assert "non-inferiority" in statistical.detail
        assert decision.eligible

    def test_unpreregistered_non_inferiority_path_is_refused(self) -> None:
        """The cost path only exists if the campaign preregistered it."""
        decision = evaluate_promotion(
            _policy(),
            _evidence(
                heldout=_paired(gain_per_task=0.0),
                success_gain=0.0,
                cost_reduction=0.25,
                preregistered_non_inferiority=False,
            ),
            release=_release(),
        )
        assert not _condition(decision, CONDITION_STATISTICAL).passed
        assert not decision.eligible


class TestFailingConditionsMatrix:
    """Each condition, failed one at a time, names itself in the rejection."""

    def test_statistical_condition_fails_on_null_effect(self) -> None:
        decision = evaluate_promotion(
            _policy(),
            _evidence(heldout=_paired(gain_per_task=0.0), success_gain=0.0),
            release=_release(),
        )
        assert not _condition(decision, CONDITION_STATISTICAL).passed
        assert CONDITION_STATISTICAL in decision.failed_conditions()

    def test_statistical_condition_fails_when_gain_below_mvp_bar(self) -> None:
        decision = evaluate_promotion(
            _policy(),
            _evidence(heldout=_paired(gain_per_task=0.05), success_gain=0.05),
            release=_release(),
        )
        assert not _condition(decision, CONDITION_STATISTICAL).passed

    def test_protected_slice_below_margin_fails(self) -> None:
        decision = evaluate_promotion(
            _policy(protected_slice_margins={"security-tasks": 0.05}),
            _evidence(protected_slices={"security-tasks": _paired(gain_per_task=-0.20)}),
            release=_release(),
        )
        slice_condition = _condition(decision, CONDITION_PROTECTED_SLICES)
        assert not slice_condition.passed
        assert "security-tasks" in slice_condition.detail

    def test_protected_slice_without_data_fails_closed(self) -> None:
        decision = evaluate_promotion(
            _policy(protected_slice_margins={"security-tasks": 0.05}),
            _evidence(),
            release=_release(),
        )
        slice_condition = _condition(decision, CONDITION_PROTECTED_SLICES)
        assert not slice_condition.passed
        assert "no paired data" in slice_condition.detail

    def test_protected_slice_above_margin_passes(self) -> None:
        decision = evaluate_promotion(
            _policy(protected_slice_margins={"security-tasks": 0.05}),
            _evidence(protected_slices={"security-tasks": _paired(gain_per_task=0.12)}),
            release=_release(),
        )
        assert _condition(decision, CONDITION_PROTECTED_SLICES).passed

    def test_severity1_regression_fails_condition_three(self) -> None:
        decision = evaluate_promotion(
            _policy(), _evidence(severity1_regressions=1), release=_release()
        )
        assert not _condition(decision, CONDITION_NO_CRITICAL_FAILURE).passed

    def test_critical_failure_fails_condition_three(self) -> None:
        decision = evaluate_promotion(
            _policy(), _evidence(critical_failures=("sandbox-escape",)), release=_release()
        )
        assert not _condition(decision, CONDITION_NO_CRITICAL_FAILURE).passed

    def test_budget_failure_fails_condition_four(self) -> None:
        decision = evaluate_promotion(_policy(), _evidence(budget_pass=False), release=_release())
        assert not _condition(decision, CONDITION_BUDGET).passed

    def test_integrity_finding_fails_condition_five(self) -> None:
        decision = evaluate_promotion(
            _policy(), _evidence(integrity_findings=("holdout-leak",)), release=_release()
        )
        assert not _condition(decision, CONDITION_NO_INTEGRITY_FINDINGS).passed

    def test_unevaluated_transfer_scope_fails_condition_six(self) -> None:
        decision = evaluate_promotion(
            _policy(),
            _evidence(
                claimed_transfer_scope=("python", "rust"),
                evaluated_transfer_scope=("python",),
            ),
            release=_release(),
        )
        assert not _condition(decision, CONDITION_TRANSFER_SCOPE).passed

    def test_every_condition_failing_at_once_reports_all(self) -> None:
        decision = evaluate_promotion(
            _policy(protected_slice_margins={"security-tasks": 0.05}),
            _evidence(
                heldout=_paired(gain_per_task=0.0),
                success_gain=0.0,
                protected_slices={"security-tasks": _paired(gain_per_task=-0.2)},
                severity1_regressions=2,
                critical_failures=("evaluator-key-touch",),
                budget_pass=False,
                integrity_findings=("holdout-leak",),
                claimed_transfer_scope=("python",),
                evaluated_transfer_scope=(),
            ),
            release=_release(),
        )
        assert not decision.eligible
        assert set(decision.failed_conditions()) == {
            CONDITION_STATISTICAL,
            CONDITION_PROTECTED_SLICES,
            CONDITION_NO_CRITICAL_FAILURE,
            CONDITION_BUDGET,
            CONDITION_NO_INTEGRITY_FINDINGS,
            CONDITION_TRANSFER_SCOPE,
        }


class TestTierRejection:
    def test_tier3_release_is_rejected_before_any_condition(self) -> None:
        with pytest.raises(TierRejectedError, match="elevated authority"):
            evaluate_promotion(
                _policy(),
                _evidence(),
                release=_release(contains_executable_content=True),
            )

    def test_tier4_harness_touching_release_is_rejected(self) -> None:
        with pytest.raises(TierRejectedError, match="elevated authority"):
            evaluate_promotion(_policy(), _evidence(), release=_release(touches_harness=True))

    def test_direct_memory_write_release_is_rejected(self) -> None:
        with pytest.raises(TierRejectedError):
            evaluate_promotion(_policy(), _evidence(), release=_release(memory_write_mode="direct"))

    def test_unknown_artifact_class_fails_closed_at_tier3(self) -> None:
        with pytest.raises(TierRejectedError):
            evaluate_promotion(
                _policy(), _evidence(), release=_release(artifact_classes=("mystery-class",))
            )


class TestPolicyValidation:
    def test_impossible_thresholds_refused_at_construction(self) -> None:
        with pytest.raises(InvalidPromotionPolicyError, match="min_success_gain"):
            _policy(min_success_gain=1.5)

    def test_negative_severity1_allowance_refused(self) -> None:
        with pytest.raises(InvalidPromotionPolicyError, match="max_severity1_regressions"):
            _policy(max_severity1_regressions=-1)

    def test_empty_tier_allowlist_refused(self) -> None:
        with pytest.raises(InvalidPromotionPolicyError, match="allowed_authority_tiers"):
            _policy(allowed_authority_tiers=())

    def test_canonical_form_is_stable(self) -> None:
        first = _policy(protected_slice_margins={"b": 0.1, "a": 0.2})
        second = _policy(protected_slice_margins={"a": 0.2, "b": 0.1})
        assert first.to_canonical_dict() == second.to_canonical_dict()

    def test_paired_scores_must_stay_paired(self) -> None:
        with pytest.raises(InvalidPromotionPolicyError, match="lost the pairing"):
            PairedScores(task_ids=("t1", "t2"), baseline=(0.5,), candidate=(0.6, 0.7))

"""§12.6 recursive-claim gate tests: the four conditions and locked
decision #8 — Phase 1 labels are 'artifact optimization', never
'recursive improvement'."""

from __future__ import annotations

import pytest

from evoruntime.selection import (
    ARTIFACT_OPTIMIZATION_LABEL,
    RECURSIVE_CLAIM_ENABLED,
    RECURSIVE_IMPROVEMENT_LABEL,
    RecursiveClaimDeniedError,
    RecursiveClaimEvidence,
    assert_label_allowed,
    claim_label,
    evaluate_recursive_claim,
)


def _evidence(**overrides: object) -> RecursiveClaimEvidence:
    values: dict[str, object] = {
        "successive_promoted_generations": True,
        "shared_error_budget": True,
        "causal_inheritance": True,
        "matched_compute_one_shot_advantage": True,
        "no_inheritance_control_arm": True,
    }
    values.update(overrides)
    return RecursiveClaimEvidence(**values)  # type: ignore[arg-type]


class TestGateConditions:
    def test_all_conditions_satisfied(self) -> None:
        verdict = evaluate_recursive_claim(_evidence())
        assert verdict.satisfied
        assert len(verdict.conditions) == 4
        assert all(c.passed for c in verdict.conditions)

    def test_each_missing_condition_fails_the_gate(self) -> None:
        for field in (
            "successive_promoted_generations",
            "shared_error_budget",
            "causal_inheritance",
            "matched_compute_one_shot_advantage",
            "no_inheritance_control_arm",
        ):
            verdict = evaluate_recursive_claim(_evidence(**{field: False}))
            assert not verdict.satisfied, f"gate passed without {field}"


class TestLabeling:
    """Locked decision #8: the label switch stays off in Phase 1."""

    def test_phase1_switch_is_off(self) -> None:
        assert RECURSIVE_CLAIM_ENABLED is False

    def test_satisfied_gate_still_labels_artifact_optimization(self) -> None:
        verdict = evaluate_recursive_claim(_evidence())
        assert claim_label(verdict) == ARTIFACT_OPTIMIZATION_LABEL
        assert claim_label(verdict) != RECURSIVE_IMPROVEMENT_LABEL

    def test_failed_gate_labels_artifact_optimization(self) -> None:
        verdict = evaluate_recursive_claim(_evidence(causal_inheritance=False))
        assert claim_label(verdict) == ARTIFACT_OPTIMIZATION_LABEL

    def test_no_verdict_labels_artifact_optimization(self) -> None:
        assert claim_label(None) == ARTIFACT_OPTIMIZATION_LABEL

    def test_recursive_improvement_label_is_refused_in_phase1(self) -> None:
        verdict = evaluate_recursive_claim(_evidence())
        with pytest.raises(RecursiveClaimDeniedError, match="locked"):
            assert_label_allowed(RECURSIVE_IMPROVEMENT_LABEL, verdict)

    def test_artifact_optimization_label_always_allowed(self) -> None:
        assert_label_allowed(ARTIFACT_OPTIMIZATION_LABEL, None)

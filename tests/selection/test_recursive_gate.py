"""§12.6 recursive-claim gate tests: the five conditions — the four
Phase 1 conditions plus the G4 RI-3/RI-4 fixed-editor advantage — and the
per-environment enablement policy that replaced the compile-time switch
(locked decision #8: a label is earned by policy data plus evidence,
never asserted)."""

from __future__ import annotations

import uuid

import pytest

from evoruntime.selection import (
    ARTIFACT_OPTIMIZATION_LABEL,
    RECURSIVE_IMPROVEMENT_LABEL,
    RecursiveClaimDeniedError,
    RecursiveClaimEvidence,
    assert_label_allowed,
    claim_label,
    evaluate_recursive_claim,
)
from evoruntime.tenancy.environment import TenantEnvironment
from evoruntime.tenancy.errors import TenantPolicyError
from evoruntime.tenancy.policy import TenantPolicyDocument


def _evidence(**overrides: object) -> RecursiveClaimEvidence:
    values: dict[str, object] = {
        "successive_promoted_generations": True,
        "shared_error_budget": True,
        "causal_inheritance": True,
        "matched_compute_one_shot_advantage": True,
        "no_inheritance_control_arm": True,
        "fixed_editor_control_arm": True,
        "fixed_editor_advantage": 0.08,
        "fixed_editor_minimum_effect": 0.05,
        "fixed_editor_holm_significant": True,
    }
    values.update(overrides)
    return RecursiveClaimEvidence(**values)  # type: ignore[arg-type]


def _policy(
    *,
    environment: TenantEnvironment = TenantEnvironment.RESEARCH,
    recursive_claims_enabled: bool = True,
) -> TenantPolicyDocument:
    return TenantPolicyDocument(
        tenant_id=f"tnt_{uuid.uuid4().hex[:8]}",
        policy_id=f"pol_{uuid.uuid4().hex[:8]}",
        environment=environment,
        allowed_authority_tiers=(1, 2, 3, 4)
        if environment is TenantEnvironment.RESEARCH
        else (1, 2, 3),
        recursive_claims_enabled=recursive_claims_enabled,
    )


class TestGateConditions:
    def test_all_conditions_satisfied(self) -> None:
        verdict = evaluate_recursive_claim(_evidence())
        assert verdict.satisfied
        assert len(verdict.conditions) == 5
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


class TestFixedEditorAdvantageCondition:
    """§12.6 RI-3/RI-4: a numeric fixed-editor advantage above the
    preregistered minimum effect, inside the shared Holm family."""

    def test_condition_passes_with_numeric_advantage(self) -> None:
        verdict = evaluate_recursive_claim(_evidence())
        condition = next(c for c in verdict.conditions if c.condition == "fixed_editor_advantage")
        assert condition.passed

    def test_gate_refused_without_the_fixed_editor_control_arm(self) -> None:
        verdict = evaluate_recursive_claim(_evidence(fixed_editor_control_arm=False))
        assert not verdict.satisfied

    def test_gate_refused_without_a_numeric_advantage(self) -> None:
        """`None` means never measured — and unmeasured is not an advantage."""
        verdict = evaluate_recursive_claim(_evidence(fixed_editor_advantage=None))
        assert not verdict.satisfied

    def test_gate_refused_when_advantage_is_nan(self) -> None:
        verdict = evaluate_recursive_claim(_evidence(fixed_editor_advantage=float("nan")))
        assert not verdict.satisfied

    def test_gate_refused_when_advantage_is_infinite(self) -> None:
        verdict = evaluate_recursive_claim(_evidence(fixed_editor_advantage=float("inf")))
        assert not verdict.satisfied

    def test_gate_refused_below_the_preregistered_minimum_effect(self) -> None:
        verdict = evaluate_recursive_claim(
            _evidence(fixed_editor_advantage=0.04, fixed_editor_minimum_effect=0.05)
        )
        assert not verdict.satisfied

    def test_gate_refused_at_exactly_the_minimum_effect(self) -> None:
        """The condition is *above* the minimum, not at it."""
        verdict = evaluate_recursive_claim(
            _evidence(fixed_editor_advantage=0.05, fixed_editor_minimum_effect=0.05)
        )
        assert not verdict.satisfied

    def test_gate_refused_without_a_preregistered_minimum_effect(self) -> None:
        """An unpinned threshold defaults to failing, never to passing."""
        verdict = evaluate_recursive_claim(_evidence(fixed_editor_minimum_effect=None))
        assert not verdict.satisfied

    def test_gate_refused_outside_the_shared_holm_family(self) -> None:
        verdict = evaluate_recursive_claim(_evidence(fixed_editor_holm_significant=False))
        assert not verdict.satisfied


class TestPerEnvironmentEnablement:
    """The enablement matrix: policy data on the tenant's document, not a
    module constant. Research + enabled earns the label; every other cell
    is 'artifact optimization' or a refusal."""

    def test_research_policy_with_claims_enabled_earns_the_label(self) -> None:
        verdict = evaluate_recursive_claim(_evidence())
        assert claim_label(verdict, tenant_policy=_policy()) == RECURSIVE_IMPROVEMENT_LABEL

    def test_research_policy_without_claims_enabled_is_artifact_optimization(self) -> None:
        verdict = evaluate_recursive_claim(_evidence())
        policy = _policy(recursive_claims_enabled=False)
        assert claim_label(verdict, tenant_policy=policy) == ARTIFACT_OPTIMIZATION_LABEL
        with pytest.raises(RecursiveClaimDeniedError, match="research-only"):
            assert_label_allowed(RECURSIVE_IMPROVEMENT_LABEL, verdict, tenant_policy=policy)

    def test_unmapped_tenant_is_production_fail_closed(self) -> None:
        verdict = evaluate_recursive_claim(_evidence())
        assert claim_label(verdict, tenant_policy=None) == ARTIFACT_OPTIMIZATION_LABEL
        with pytest.raises(RecursiveClaimDeniedError, match="research-only"):
            assert_label_allowed(RECURSIVE_IMPROVEMENT_LABEL, verdict, tenant_policy=None)

    def test_production_tenant_cannot_enable_claims_at_all(self) -> None:
        """The policy document's own validation is the first gate: a
        production document with the claim enabled is refused at
        construction, so no production policy data can ever reach the
        label gate with enablement on."""
        with pytest.raises(TenantPolicyError, match="recursive"):
            _policy(environment=TenantEnvironment.PRODUCTION, recursive_claims_enabled=True)

    def test_failed_gate_labels_artifact_optimization_even_when_enabled(self) -> None:
        verdict = evaluate_recursive_claim(_evidence(causal_inheritance=False))
        assert claim_label(verdict, tenant_policy=_policy()) == ARTIFACT_OPTIMIZATION_LABEL

    def test_no_verdict_labels_artifact_optimization(self) -> None:
        assert claim_label(None, tenant_policy=_policy()) == ARTIFACT_OPTIMIZATION_LABEL
        assert claim_label(None) == ARTIFACT_OPTIMIZATION_LABEL

    def test_recursive_improvement_label_is_refused_without_policy(self) -> None:
        verdict = evaluate_recursive_claim(_evidence())
        with pytest.raises(RecursiveClaimDeniedError, match="research-only"):
            assert_label_allowed(RECURSIVE_IMPROVEMENT_LABEL, verdict)

    def test_artifact_optimization_label_always_allowed(self) -> None:
        assert_label_allowed(ARTIFACT_OPTIMIZATION_LABEL, None)

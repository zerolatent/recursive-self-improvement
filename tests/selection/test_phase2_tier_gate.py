"""Phase 2 tier gate tests (F2): tier resolution per executable class,
two-person approval for tier 3, human sign-off + manual initiation for
tier 4, and fail-closed behavior for unknown classes."""

from __future__ import annotations

import pytest
from tests.selection.test_promotion_policy import _evidence, _policy, _release

from evoruntime.plugins.manifest import PluginArtifactType
from evoruntime.selection import (
    AuthorityTier,
    ResolvedRelease,
    TierApprovalEvidence,
    TierRejectedError,
    assert_phase2_admissible,
    evaluate_promotion,
    resolve_authority_tier,
)

TIER_3_CLASSES = (
    PluginArtifactType.WORKFLOW_GRAPH,
    PluginArtifactType.TOOL_SPEC,
    PluginArtifactType.SKILL_SCRIPT,
    PluginArtifactType.ALGORITHM,
)


class TestTierResolutionPerNewClass:
    """PRD §13.3 mapping: workflow/tool/skill/algorithm → 3, harness → 4."""

    @pytest.mark.parametrize("artifact_type", TIER_3_CLASSES)
    def test_tier3_classes_resolve_to_tier3(self, artifact_type: PluginArtifactType) -> None:
        release = ResolvedRelease(artifact_classes=(artifact_type.value,))
        assert resolve_authority_tier(release) is AuthorityTier.TIER_3

    def test_harness_patch_resolves_to_tier4(self) -> None:
        release = ResolvedRelease(artifact_classes=(PluginArtifactType.HARNESS_PATCH.value,))
        assert resolve_authority_tier(release) is AuthorityTier.TIER_4

    def test_mixed_release_tiers_at_the_maximum(self) -> None:
        release = ResolvedRelease(
            artifact_classes=(
                PluginArtifactType.PROMPT_BUNDLE.value,
                PluginArtifactType.HARNESS_PATCH.value,
            )
        )
        assert resolve_authority_tier(release) is AuthorityTier.TIER_4

    def test_executable_content_trigger_still_dominates(self) -> None:
        """The E4 classifier is untouched: executable content is tier 3 even
        when the resolved classes look low-risk."""
        release = ResolvedRelease(
            artifact_classes=(PluginArtifactType.PROMPT_BUNDLE.value,),
            contains_executable_content=True,
        )
        assert resolve_authority_tier(release) is AuthorityTier.TIER_3


class TestTier3TwoPersonApproval:
    def test_rejected_without_any_approval(self) -> None:
        with pytest.raises(TierRejectedError, match="two-person approval"):
            assert_phase2_admissible(AuthorityTier.TIER_3)

    def test_rejected_with_a_single_approver(self) -> None:
        evidence = TierApprovalEvidence(approvers=("alice",))
        with pytest.raises(TierRejectedError, match="two-person approval"):
            assert_phase2_admissible(AuthorityTier.TIER_3, evidence)

    def test_rejected_with_duplicate_approvers(self) -> None:
        evidence = TierApprovalEvidence(approvers=("alice", "Alice"))
        with pytest.raises(TierRejectedError, match="distinct approvers"):
            assert_phase2_admissible(AuthorityTier.TIER_3, evidence)

    def test_self_approval_is_refused(self) -> None:
        evidence = TierApprovalEvidence(approvers=("alice", "bob"), requested_by="BOB")
        with pytest.raises(TierRejectedError, match="self-approval"):
            assert_phase2_admissible(AuthorityTier.TIER_3, evidence)

    def test_admitted_with_two_distinct_approvers(self) -> None:
        evidence = TierApprovalEvidence(approvers=("alice", "bob"), requested_by="carol")
        assert assert_phase2_admissible(AuthorityTier.TIER_3, evidence) is None


class TestTier4HumanSignoff:
    def test_rejected_without_any_evidence(self) -> None:
        with pytest.raises(TierRejectedError, match="human sign-off"):
            assert_phase2_admissible(AuthorityTier.TIER_4)

    def test_rejected_with_signoff_but_automated_initiation(self) -> None:
        evidence = TierApprovalEvidence(human_signoff=True, manually_initiated=False)
        with pytest.raises(TierRejectedError, match="manual initiation"):
            assert_phase2_admissible(AuthorityTier.TIER_4, evidence)

    def test_rejected_with_manual_initiation_but_no_signoff(self) -> None:
        evidence = TierApprovalEvidence(human_signoff=False, manually_initiated=True)
        with pytest.raises(TierRejectedError, match="human sign-off"):
            assert_phase2_admissible(AuthorityTier.TIER_4, evidence)

    def test_admitted_with_signoff_and_manual_initiation(self) -> None:
        evidence = TierApprovalEvidence(human_signoff=True, manually_initiated=True)
        assert assert_phase2_admissible(AuthorityTier.TIER_4, evidence) is None


class TestFailClosed:
    def test_unknown_class_resolves_to_tier3_and_is_rejected(self) -> None:
        release = ResolvedRelease(artifact_classes=("mystery-class",))
        tier = resolve_authority_tier(release)
        assert tier is AuthorityTier.TIER_3
        with pytest.raises(TierRejectedError):
            assert_phase2_admissible(tier)

    def test_tier1_and_tier2_need_no_approval_evidence(self) -> None:
        assert assert_phase2_admissible(AuthorityTier.TIER_1) is None
        assert assert_phase2_admissible(AuthorityTier.TIER_2) is None


class TestPromotionPolicyIntegration:
    def test_tier3_release_rejected_without_approvals(self) -> None:
        with pytest.raises(TierRejectedError, match="two-person approval"):
            evaluate_promotion(
                _policy(),
                _evidence(),
                release=_release(artifact_classes=(PluginArtifactType.SKILL_SCRIPT.value,)),
            )

    def test_tier3_release_admitted_with_two_person_approval(self) -> None:
        decision = evaluate_promotion(
            _policy(),
            _evidence(),
            release=_release(artifact_classes=(PluginArtifactType.SKILL_SCRIPT.value,)),
            tier_approvals=TierApprovalEvidence(approvers=("alice", "bob"), requested_by="carol"),
        )
        assert decision.tier == 3
        assert decision.eligible

    def test_tier4_release_rejected_without_signoff(self) -> None:
        with pytest.raises(TierRejectedError, match="human sign-off"):
            evaluate_promotion(
                _policy(),
                _evidence(),
                release=_release(artifact_classes=(PluginArtifactType.HARNESS_PATCH.value,)),
            )

    def test_tier4_release_admitted_with_signoff_and_manual_initiation(self) -> None:
        decision = evaluate_promotion(
            _policy(),
            _evidence(),
            release=_release(artifact_classes=(PluginArtifactType.HARNESS_PATCH.value,)),
            tier_approvals=TierApprovalEvidence(human_signoff=True, manually_initiated=True),
        )
        assert decision.tier == 4
        assert decision.eligible

    def test_tier1_release_still_promotes_without_evidence(self) -> None:
        decision = evaluate_promotion(_policy(), _evidence(), release=_release())
        assert decision.tier == 1
        assert decision.eligible

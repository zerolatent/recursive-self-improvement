"""H11 generation-2 campaign tooling tests (PRD §17.1 step 10).

The generation-2 spec is *derived*, not hand-written: its incumbent binding
resolves to the generation-1 promoted release, and its holdout handle is a
fresh capability minted after the generation-1 handle was rotated — the
rotate-then-issue semantics that keep the two generations from ever
resolving through the same live credential.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from evoruntime.campaign.generation2 import (
    derive_generation2_spec,
    prepare_generation2_holdouts,
    resolve_generation2_incumbent,
)
from evoruntime.campaign.spec import CampaignSpec, InvalidCampaignSpecError
from evoruntime.core.principal import Principal
from evoruntime.datasets.errors import HandleNotFoundError
from evoruntime.datasets.schemas import IssuedHoldoutHandle, PartitionSummary
from evoruntime.datasets.service import HoldoutService
from tests.support.factories import make_campaign_spec_mapping

GEN1_PROMOTED = "sha256:" + "1" * 64


def _generation1_spec() -> CampaignSpec:
    return CampaignSpec.from_mapping(make_campaign_spec_mapping())


class TestIncumbentResolution:
    def test_binding_pins_the_generation1_promoted_release(self) -> None:
        binding = resolve_generation2_incumbent(GEN1_PROMOTED, artifact_type="prompt_bundle")
        assert binding.release_manifest_digest == GEN1_PROMOTED
        assert binding.artifact_type == "prompt_bundle"

    def test_binding_refuses_a_non_digest(self) -> None:
        with pytest.raises(InvalidCampaignSpecError):
            resolve_generation2_incumbent("not-a-digest", artifact_type="prompt_bundle")


class TestSpecDerivation:
    def test_derived_spec_inherits_everything_but_the_binding(self) -> None:
        generation1 = _generation1_spec()
        derived = derive_generation2_spec(
            generation1,
            generation1_promoted_digest=GEN1_PROMOTED,
            holdout_handle="holdout://ledger/gen2-fresh",
        )
        assert derived.name == f"{generation1.name}-gen2"
        assert derived.incumbent.release_manifest_digest == GEN1_PROMOTED
        assert derived.datasets.holdout_handle == "holdout://ledger/gen2-fresh"
        # Everything a new generation must not change is inherited verbatim.
        assert derived.mutable_artifacts == generation1.mutable_artifacts
        assert derived.strategy_plugin == generation1.strategy_plugin
        assert derived.arms == generation1.arms
        assert derived.budgets == generation1.budgets
        assert derived.statistics == generation1.statistics

    def test_derived_spec_records_its_lineage_in_metadata(self) -> None:
        generation1 = _generation1_spec()
        derived = derive_generation2_spec(
            generation1,
            generation1_promoted_digest=GEN1_PROMOTED,
            holdout_handle="holdout://ledger/gen2-fresh",
        )
        assert derived.metadata["generation"] == "2"
        assert derived.metadata["derived_from"] == generation1.name
        # Inherited metadata rides along, not replaced.
        assert derived.metadata["owner"] == generation1.metadata["owner"]

    def test_derived_spec_is_a_valid_campaign_spec(self) -> None:
        """Construction is validation: the derived spec passes the full
        validator, so it is trustworthy exactly as a hand-written one is."""
        derived = derive_generation2_spec(
            _generation1_spec(),
            generation1_promoted_digest=GEN1_PROMOTED,
            holdout_handle="holdout://ledger/gen2-fresh",
        )
        assert isinstance(derived, CampaignSpec)

    def test_derivation_with_a_broken_digest_is_refused(self) -> None:
        """A typo'd digest is the drift this module exists to prevent."""
        with pytest.raises(InvalidCampaignSpecError):
            derive_generation2_spec(
                _generation1_spec(),
                generation1_promoted_digest="sha256:short",
                holdout_handle="holdout://ledger/gen2-fresh",
            )

    def test_derived_name_can_be_pinned(self) -> None:
        derived = derive_generation2_spec(
            _generation1_spec(),
            generation1_promoted_digest=GEN1_PROMOTED,
            holdout_handle="holdout://ledger/gen2-fresh",
            name="gen2-explicit",
        )
        assert derived.name == "gen2-explicit"


class TestRotatedHoldouts:
    """The §17.1 step 10 rotation semantics: rotate, then issue."""

    def test_rotate_then_issue_gives_generation2_its_own_credential(
        self,
        holdout_service: HoldoutService,
        evaluator: Principal,
        issued_handle: IssuedHoldoutHandle,
        sealed_partition: PartitionSummary,
    ) -> None:
        holdouts = prepare_generation2_holdouts(
            holdout_service,
            evaluator,
            generation1_handle_uri=issued_handle.handle_uri,
            owner="eval-team",
            alpha_budget_total=Decimal("0.04"),
            alpha_per_query=Decimal("0.01"),
            freshness_window_days=30,
            rotation_plan="rotate-quarterly",
        )
        # The generation-1 handle was rotated: same handle id, new token,
        # one rotation on the clock.
        assert holdouts.generation1_handle.handle_id == issued_handle.metadata.handle_id
        assert holdouts.generation1_handle.rotation_count == 1
        # The generation-2 handle is a fresh capability over the same
        # sealed partition, with its own unspent budget.
        assert holdouts.generation2_handle.handle_uri != issued_handle.handle_uri
        assert holdouts.generation2_handle.metadata.partition_id == sealed_partition.id
        assert holdouts.generation2_handle.metadata.rotation_count == 0
        assert holdouts.generation2_handle.metadata.alpha_budget.spent == Decimal("0")

    def test_generation1_token_is_dead_after_the_handoff(
        self,
        holdout_service: HoldoutService,
        evaluator: Principal,
        issued_handle: IssuedHoldoutHandle,
    ) -> None:
        """The two generations can never resolve through the same live
        credential — the §17.1 step 10 rotation guarantee."""
        prepare_generation2_holdouts(
            holdout_service,
            evaluator,
            generation1_handle_uri=issued_handle.handle_uri,
            owner="eval-team",
            alpha_budget_total=Decimal("0.04"),
            alpha_per_query=Decimal("0.01"),
            freshness_window_days=30,
            rotation_plan="rotate-quarterly",
        )
        with pytest.raises(HandleNotFoundError):
            holdout_service.resolve(
                evaluator,
                issued_handle.handle_uri,
                purpose="generation-1-token-after-handoff",
            )

    def test_generation2_incumbent_resolves_on_rotated_holdouts(
        self,
        holdout_service: HoldoutService,
        evaluator: Principal,
        issued_handle: IssuedHoldoutHandle,
        sealed_partition: PartitionSummary,
    ) -> None:
        """The full step-10 chain: rotate, issue, derive the generation-2
        spec whose incumbent binding is the generation-1 promoted release
        and whose holdout handle is the fresh credential."""
        holdouts = prepare_generation2_holdouts(
            holdout_service,
            evaluator,
            generation1_handle_uri=issued_handle.handle_uri,
            owner="eval-team",
            alpha_budget_total=Decimal("0.04"),
            alpha_per_query=Decimal("0.01"),
            freshness_window_days=30,
            rotation_plan="rotate-quarterly",
        )
        derived = derive_generation2_spec(
            _generation1_spec(),
            generation1_promoted_digest=GEN1_PROMOTED,
            holdout_handle=holdouts.generation2_handle.handle_uri,
        )
        assert derived.incumbent.release_manifest_digest == GEN1_PROMOTED
        assert derived.datasets.holdout_handle == holdouts.generation2_handle.handle_uri
        # The fresh handle's contamination audit names its descent.
        audit = holdouts.generation2_handle.metadata.contamination_audit
        assert audit["generation"] == 2
        assert audit["rotated_from_handle_id"] == issued_handle.metadata.handle_id
        assert audit["prior_rotation_count"] == 1

    def test_fresh_handle_resolves_the_sealed_content(
        self,
        holdout_service: HoldoutService,
        evaluator: Principal,
        issued_handle: IssuedHoldoutHandle,
        sealed_partition: PartitionSummary,
    ) -> None:
        holdouts = prepare_generation2_holdouts(
            holdout_service,
            evaluator,
            generation1_handle_uri=issued_handle.handle_uri,
            owner="eval-team",
            alpha_budget_total=Decimal("0.04"),
            alpha_per_query=Decimal("0.01"),
            freshness_window_days=30,
            rotation_plan="rotate-quarterly",
        )
        resolved = holdout_service.resolve(
            evaluator,
            holdouts.generation2_handle.handle_uri,
            purpose="generation-2-holdout-evaluation",
        )
        assert resolved.partition_id == sealed_partition.id

    def test_unknown_generation1_handle_refuses_before_issuing(
        self,
        holdout_service: HoldoutService,
        evaluator: Principal,
    ) -> None:
        """Rotation refuses before anything is issued — no orphaned
        generation-2 credential over a handle that never existed."""
        with pytest.raises(HandleNotFoundError):
            prepare_generation2_holdouts(
                holdout_service,
                evaluator,
                generation1_handle_uri="holdout://does-not-exist",
                owner="eval-team",
                alpha_budget_total=Decimal("0.04"),
                alpha_per_query=Decimal("0.01"),
                freshness_window_days=30,
                rotation_plan="rotate-quarterly",
            )

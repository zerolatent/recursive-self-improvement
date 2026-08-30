"""Generation-2 campaign tooling (H11, PRD §17.1 step 10).

The recursive-claim gate needs two *successive* promoted generations, and
until now nothing derived the second campaign from the first: an operator
assembled the generation-2 spec by hand, which is exactly where the
incumbent binding drifts — a typo'd digest and generation 2 silently
starts from the wrong release, and the inheritance the claim rests on is
fiction. This module makes the derivation code:

- :func:`resolve_generation2_incumbent` pins the generation-2 incumbent
  binding to the generation-1 promoted release manifest digest.
- :func:`derive_generation2_spec` rebuilds the generation-1 spec with that
  binding and a fresh holdout handle. Construction is validation: the
  derived spec passes through the full ``CampaignSpec`` validator, so a
  derived spec is trustworthy in exactly the way a hand-written one is.
- :func:`prepare_generation2_holdouts` performs the §17.1 step 10
  rotation semantics — *rotate, then issue*. Rotating the generation-1
  handle retires its token (the generation-1 credential stops resolving;
  its ledger keeps the generation-1 spend history), and issuing a fresh
  handle over the same sealed partition mints the generation-2 credential
  with its own preregistered alpha budget. Each generation resolves
  through its own handle, and the fresh handle's contamination audit
  records which handle — and how many rotations — it descends from.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from evoruntime.campaign.spec import CampaignSpec, IncumbentBinding
from evoruntime.core.principal import Principal
from evoruntime.datasets.schemas import HoldoutHandleMetadata, IssuedHoldoutHandle
from evoruntime.datasets.service import HoldoutService


@dataclass(frozen=True, slots=True)
class Generation2Holdouts:
    """The holdout handoff between two generations.

    The generation-1 handle's metadata is the *rotated* state: its old
    token is dead, its ledger intact. The generation-2 handle is a fresh
    capability over the same sealed partition.
    """

    generation1_handle: HoldoutHandleMetadata
    generation2_handle: IssuedHoldoutHandle


def resolve_generation2_incumbent(
    generation1_promoted_digest: str, *, artifact_type: str
) -> IncumbentBinding:
    """Pin the generation-2 incumbent to the generation-1 promoted release.

    Raises:
        InvalidCampaignSpecError: the digest is not a sha256 digest or the
            artifact type is not a known class (via ``IncumbentBinding``).
    """
    return IncumbentBinding(
        release_manifest_digest=generation1_promoted_digest, artifact_type=artifact_type
    )


def derive_generation2_spec(
    generation1: CampaignSpec,
    *,
    generation1_promoted_digest: str,
    holdout_handle: str,
    name: str | None = None,
) -> CampaignSpec:
    """Derive the generation-2 campaign spec from the generation-1 spec.

    Everything is inherited except what a new generation must change: the
    incumbent binding (now the generation-1 promoted release), the holdout
    handle (now the fresh handle minted after rotation), and the name
    (suffixed ``-gen2`` unless the caller pins one). The metadata records
    the derivation so the lineage is readable from the spec itself.

    Raises:
        InvalidCampaignSpecError: the derived spec fails any campaign
            validation — the same refusal a hand-written spec would earn.
    """
    metadata: dict[str, str] = {
        **generation1.metadata,
        "generation": "2",
        "derived_from": generation1.name,
    }
    return CampaignSpec(
        schema_version=generation1.schema_version,
        name=name if name is not None else f"{generation1.name}-gen2",
        incumbent=resolve_generation2_incumbent(
            generation1_promoted_digest, artifact_type=generation1.incumbent.artifact_type
        ),
        mutable_artifacts=generation1.mutable_artifacts,
        strategy_plugin=generation1.strategy_plugin,
        arms=generation1.arms,
        datasets=type(generation1.datasets)(
            dev_partition=generation1.datasets.dev_partition,
            selection_partition=generation1.datasets.selection_partition,
            holdout_handle=holdout_handle,
        ),
        evaluators=generation1.evaluators,
        budgets=generation1.budgets,
        promotion_policy=generation1.promotion_policy,
        statistics=generation1.statistics,
        stopping_rules=generation1.stopping_rules,
        compensation_plan=generation1.compensation_plan,
        mutation_classes=generation1.mutation_classes,
        metadata=metadata,
        environment=generation1.environment,
        tier4_policy_digest=generation1.tier4_policy_digest,
    )


def prepare_generation2_holdouts(
    holdout_service: HoldoutService,
    principal: Principal,
    *,
    generation1_handle_uri: str,
    owner: str,
    alpha_budget_total: Decimal,
    alpha_per_query: Decimal,
    freshness_window_days: int,
    rotation_plan: str,
) -> Generation2Holdouts:
    """Rotate the generation-1 handle, then issue the generation-2 handle.

    The rotation is the §17.1 step 10 semantics: the generation-1 token is
    retired *before* the generation-2 credential exists, so the two
    generations can never resolve through the same live capability. The
    fresh handle is issued over the same sealed partition the generation-1
    handle sealed, with its own alpha budget and a contamination audit
    that names the handle it descends from.

    Raises:
        HoldoutAccessDeniedError: the caller is not an evaluator, or the
            handle is revoked/expired — rotation refuses before anything
            is issued.
        HandleNotFoundError: no such handle.
    """
    rotated = holdout_service.rotate_handle(principal, generation1_handle_uri)
    fresh = holdout_service.issue_handle(
        principal,
        partition_id=rotated.metadata.partition_id,
        owner=owner,
        alpha_budget_total=alpha_budget_total,
        alpha_per_query=alpha_per_query,
        freshness_window_days=freshness_window_days,
        rotation_plan=rotation_plan,
        contamination_audit={
            "generation": 2,
            "rotated_from_handle_id": rotated.metadata.handle_id,
            "prior_rotation_count": rotated.metadata.rotation_count,
        },
    )
    return Generation2Holdouts(generation1_handle=rotated.metadata, generation2_handle=fresh)


__all__ = [
    "Generation2Holdouts",
    "derive_generation2_spec",
    "prepare_generation2_holdouts",
    "resolve_generation2_incumbent",
]

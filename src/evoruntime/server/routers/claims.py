"""Recursive-claim decision HTTP API (H11).

The operator path for §12.6 claim labels: a research-tenant operator
submits assembled evidence, the gate decides the label, and the decision
— issued or refused — is recorded append-only. The endpoint never takes a
label: a caller who submits unsatisfied evidence earns a 403 whose body
carries the decision id of the recorded refusal.
"""

from __future__ import annotations

from fastapi import APIRouter, status
from pydantic import BaseModel

from evoruntime.api.schemas import ClaimDecisionView
from evoruntime.selection.recursive_gate import RecursiveClaimEvidence
from evoruntime.server.dependencies import ClaimServiceDep, PrincipalDep

router = APIRouter(prefix="/v1/claims", tags=["claims"])


class ClaimEvidenceRequest(BaseModel):
    """The assembled §12.6 evidence, as the adapter emits it."""

    successive_promoted_generations: bool
    shared_error_budget: bool
    causal_inheritance: bool
    matched_compute_one_shot_advantage: bool
    no_inheritance_control_arm: bool
    fixed_editor_control_arm: bool = False
    fixed_editor_advantage: float | None = None
    fixed_editor_minimum_effect: float | None = None
    fixed_editor_holm_significant: bool = False


class IssueClaimRequest(ClaimEvidenceRequest):
    """Claim-label issuance: evidence plus the provenance context."""

    campaign_id: str | None = None
    generation1_release_digest: str | None = None
    generation2_release_digest: str | None = None


@router.post("/label", status_code=status.HTTP_201_CREATED)
def issue_claim_label(
    principal: PrincipalDep, service: ClaimServiceDep, request: IssueClaimRequest
) -> ClaimDecisionView:
    """Decide and record the §12.6 claim label for submitted evidence."""
    evidence = RecursiveClaimEvidence(
        **request.model_dump(
            exclude={"campaign_id", "generation1_release_digest", "generation2_release_digest"}
        )
    )
    return service.issue_claim_label(
        principal,
        evidence=evidence,
        campaign_id=request.campaign_id,
        generation1_release_digest=request.generation1_release_digest,
        generation2_release_digest=request.generation2_release_digest,
    )


@router.get("")
def list_claim_decisions(
    principal: PrincipalDep, service: ClaimServiceDep
) -> list[ClaimDecisionView]:
    """The tenant's claim decisions, oldest first."""
    return service.list_claim_decisions(principal)


@router.get("/{decision_id}")
def get_claim_decision(
    principal: PrincipalDep, service: ClaimServiceDep, decision_id: str
) -> ClaimDecisionView:
    """One claim decision, tenant-scoped."""
    return service.get_claim_decision(principal, decision_id)

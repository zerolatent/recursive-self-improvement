"""Campaign lifecycle HTTP API (FR-014).

Campaigns are resources, not optimizer-specific actions: creating one
pins and signs its spec, and every lifecycle move goes through the E3
state machine, so the API can never take an edge the machine forbids.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, status
from pydantic import BaseModel

from evoruntime.api.schemas import (
    ApprovalView,
    CampaignDetail,
    CampaignSpecValidation,
    CampaignSummary,
    ParetoArchiveReport,
    ParetoReport,
)
from evoruntime.server.dependencies import CampaignServiceDep, PrincipalDep

router = APIRouter(prefix="/v1/campaigns", tags=["campaigns"])


class CreateCampaignRequest(BaseModel):
    """A full campaign spec mapping (validated and signed server-side)."""

    spec: dict[str, Any]


@router.post("/validate", response_model=CampaignSpecValidation)
def validate_campaign_spec(
    principal: PrincipalDep, service: CampaignServiceDep, request: CreateCampaignRequest
) -> CampaignSpecValidation:
    """Dry-run the plan step's validation without registering anything (H4)."""
    return service.validate_campaign_spec(principal, request.spec)


class TransitionRequest(BaseModel):
    """One lifecycle move. Pause, cancel, and resume are transitions too."""

    to_phase: str
    reason: str = ""


@router.post("", status_code=status.HTTP_201_CREATED)
def create_campaign(
    principal: PrincipalDep, service: CampaignServiceDep, request: CreateCampaignRequest
) -> CampaignDetail:
    """Validate, pin, sign, and persist a campaign spec (the `plan` step)."""
    return service.create_campaign(principal, request.spec)


@router.get("")
def list_campaigns(principal: PrincipalDep, service: CampaignServiceDep) -> list[CampaignSummary]:
    """The caller's tenant's campaigns, oldest first."""
    return service.list_campaigns(principal)


@router.get("/{campaign_id}")
def get_campaign(
    principal: PrincipalDep, service: CampaignServiceDep, campaign_id: str
) -> CampaignDetail:
    """One campaign with its full transition history."""
    return service.get_campaign(principal, campaign_id)


@router.post("/{campaign_id}/transitions")
def transition_campaign(
    principal: PrincipalDep,
    service: CampaignServiceDep,
    campaign_id: str,
    request: TransitionRequest,
) -> CampaignDetail:
    """Move the campaign one lifecycle step (the `run` step)."""
    return service.transition_campaign(
        principal, campaign_id, request.to_phase, reason=request.reason
    )


@router.get("/{campaign_id}/pareto")
def campaign_pareto(
    principal: PrincipalDep, service: CampaignServiceDep, campaign_id: str
) -> ParetoReport:
    """Every candidate in the campaign compared against its parent."""
    return service.pareto(principal, campaign_id)


@router.get("/{campaign_id}/pareto-archive")
def campaign_pareto_archive(
    principal: PrincipalDep, service: CampaignServiceDep, campaign_id: str
) -> ParetoArchiveReport:
    """The campaign's Pareto archive across slices (H5)."""
    return service.pareto_archive(principal, campaign_id)


@router.get("/{campaign_id}/approvals")
def campaign_approvals(
    principal: PrincipalDep, service: CampaignServiceDep, campaign_id: str
) -> list[ApprovalView]:
    """Approval decisions recorded for the campaign's candidates."""
    return service.list_approvals(principal, campaign_id)

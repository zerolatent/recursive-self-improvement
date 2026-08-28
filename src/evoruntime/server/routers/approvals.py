"""Approval decision HTTP API (FR-014).

An approval is an E1 status event on the candidate's artifact — the same
append-only, signed record the rest of the runtime trusts — not a
control-plane-only annotation.
"""

from __future__ import annotations

from fastapi import APIRouter, status
from pydantic import BaseModel

from evoruntime.api.schemas import ApprovalView
from evoruntime.server.dependencies import CampaignServiceDep, PrincipalDep

router = APIRouter(prefix="/v1/approvals", tags=["approvals"])


class RecordApprovalRequest(BaseModel):
    """Record an approval decision on a campaign candidate."""

    campaign_id: str
    proposal_id: str
    decision: str
    reason: str | None = None


@router.post("", status_code=status.HTTP_201_CREATED)
def record_approval(
    principal: PrincipalDep, service: CampaignServiceDep, request: RecordApprovalRequest
) -> ApprovalView:
    """Record an approval decision as an E1 status event."""
    return service.record_approval(
        principal,
        campaign_id=request.campaign_id,
        proposal_id=request.proposal_id,
        decision=request.decision,
        reason=request.reason,
    )

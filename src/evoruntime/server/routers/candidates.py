"""Candidate artifact HTTP API (FR-014).

A candidate is a proposed artifact plus its proposal record; the semantic
diff endpoint is the only one that touches the E2 adapter process, and
its command comes from deployment settings — never from a request.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query, status
from pydantic import BaseModel

from evoruntime.api.schemas import CandidateView, DiffView
from evoruntime.server.dependencies import CampaignServiceDep, PrincipalDep

router = APIRouter(prefix="/v1/candidates", tags=["candidates"])


class RegisterCandidateRequest(BaseModel):
    """Register a candidate artifact and its proposal record."""

    artifact_type: str
    canonical_bytes_b64: str
    strategy_id: str
    campaign_id: str | None = None
    parent_digest: str | None = None
    proposal_metadata: dict[str, Any] | None = None


@router.post("", status_code=status.HTTP_201_CREATED)
def register_candidate(
    principal: PrincipalDep, service: CampaignServiceDep, request: RegisterCandidateRequest
) -> CandidateView:
    """Register a candidate artifact and its proposal record."""
    return service.register_candidate(
        principal,
        artifact_type=request.artifact_type,
        canonical_bytes_b64=request.canonical_bytes_b64,
        strategy_id=request.strategy_id,
        campaign_id=request.campaign_id,
        parent_digest=request.parent_digest,
        proposal_metadata=request.proposal_metadata,
    )


@router.get("")
def list_candidates(
    principal: PrincipalDep,
    service: CampaignServiceDep,
    campaign_id: str | None = Query(default=None),
) -> list[CandidateView]:
    """The tenant's candidate proposals, optionally scoped to a campaign."""
    return service.list_candidates(principal, campaign_id=campaign_id)


@router.get("/{proposal_id}")
def get_candidate(
    principal: PrincipalDep, service: CampaignServiceDep, proposal_id: str
) -> CandidateView:
    """One candidate proposal with its artifact status."""
    return service.get_candidate(principal, proposal_id)


@router.get("/{proposal_id}/diff")
def candidate_diff(
    principal: PrincipalDep, service: CampaignServiceDep, proposal_id: str
) -> DiffView:
    """Semantic diff against the candidate's parent via the E2 adapter."""
    return service.semantic_diff(principal, proposal_id)

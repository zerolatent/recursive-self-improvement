"""Evidence bundle HTTP API (FR-014).

Bundles arrive already redacted (E8's RedactedEvidenceBundle shape); this
API stores and serves them, it never re-derives redaction.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query, status
from pydantic import BaseModel

from evoruntime.api.schemas import EvidenceView
from evoruntime.server.dependencies import CampaignServiceDep, PrincipalDep

router = APIRouter(prefix="/v1/evidence", tags=["evidence"])


class RecordEvidenceRequest(BaseModel):
    """Store an already-redacted evidence bundle."""

    redacted_items: list[dict[str, Any]]
    campaign_id: str | None = None
    artifact_digest: str | None = None
    bundle_id: str | None = None


@router.post("", status_code=status.HTTP_201_CREATED)
def record_evidence(
    principal: PrincipalDep, service: CampaignServiceDep, request: RecordEvidenceRequest
) -> EvidenceView:
    """Store an already-redacted evidence bundle."""
    return service.record_evidence(
        principal,
        redacted_items=request.redacted_items,
        campaign_id=request.campaign_id,
        artifact_digest=request.artifact_digest,
        bundle_id=request.bundle_id,
    )


@router.get("")
def list_evidence(
    principal: PrincipalDep,
    service: CampaignServiceDep,
    campaign_id: str | None = Query(default=None),
    artifact_digest: str | None = Query(default=None),
) -> list[EvidenceView]:
    """The tenant's evidence bundles, optionally filtered."""
    return service.list_evidence(
        principal, campaign_id=campaign_id, artifact_digest=artifact_digest
    )


@router.get("/{bundle_id}")
def get_evidence(
    principal: PrincipalDep, service: CampaignServiceDep, bundle_id: str
) -> EvidenceView:
    """One evidence bundle."""
    return service.get_evidence(principal, bundle_id)

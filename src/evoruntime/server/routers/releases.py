"""Release lifecycle HTTP API (FR-014): canary, promote, rollback status.

A release manifest is signed and verified through the FR-003 boundary
before any activation state is recorded, and promotion from canary is the
only route to `active` through the API.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, status
from pydantic import BaseModel

from evoruntime.api.schemas import ReleaseView, RollbackStatusView
from evoruntime.server.dependencies import CampaignServiceDep, PrincipalDep

router = APIRouter(prefix="/v1/releases", tags=["releases"])


class CreateReleaseRequest(BaseModel):
    """Sign a release manifest and record its activation state."""

    artifact_digests: list[str]
    adapter_versions: dict[str, Any]
    model_routes: dict[str, Any]
    policies: dict[str, Any]
    prior_release_digest: str | None = None
    status: str = "canary"


@router.post("", status_code=status.HTTP_201_CREATED)
def create_release(
    principal: PrincipalDep, service: CampaignServiceDep, request: CreateReleaseRequest
) -> ReleaseView:
    """Sign a release manifest, verify it, and record its activation."""
    return service.create_release(
        principal,
        artifact_digests=request.artifact_digests,
        adapter_versions=request.adapter_versions,
        model_routes=request.model_routes,
        policies=request.policies,
        prior_release_digest=request.prior_release_digest,
        status=request.status,
    )


@router.get("")
def list_releases(principal: PrincipalDep, service: CampaignServiceDep) -> list[ReleaseView]:
    """The tenant's release manifests with their latest activation state."""
    return service.list_releases(principal)


@router.post("/{manifest_digest}/promote")
def promote_release(
    principal: PrincipalDep, service: CampaignServiceDep, manifest_digest: str
) -> ReleaseView:
    """Move a canary release to active, superseding the prior active."""
    return service.promote_release(principal, manifest_digest)


@router.post("/{manifest_digest}/rollback")
def rollback_release(
    principal: PrincipalDep, service: CampaignServiceDep, manifest_digest: str
) -> RollbackStatusView:
    """Roll a release back to its prior release."""
    return service.rollback_release(principal, manifest_digest)


@router.get("/{manifest_digest}/rollback-status")
def rollback_status(
    principal: PrincipalDep, service: CampaignServiceDep, manifest_digest: str
) -> RollbackStatusView:
    """Where a release stands with respect to rollback."""
    return service.rollback_status(principal, manifest_digest)

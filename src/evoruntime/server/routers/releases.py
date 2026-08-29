"""Release lifecycle HTTP API (FR-014): canary, promote, rollback status.

A release manifest is signed and verified through the FR-003 boundary
before any activation state is recorded, and promotion from canary is the
only route to `active` through the API. The canary endpoints (H6) are the
operational surface of the fixed-horizon canary: admission runs the
eligibility predicate over the release's resolved artifact classes, the
run's measurements land in the append-only canary_runs ledger, and a
severity-1 outcome drives the release rollback path before the response
is returned.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from fastapi import APIRouter, status
from pydantic import BaseModel, Field

from evoruntime.api.schemas import (
    CanaryRunView,
    CanaryStatusView,
    ReleaseView,
    RollbackStatusView,
)
from evoruntime.release import CanaryConfig, GuardrailEvent
from evoruntime.server.dependencies import (
    CampaignServiceDep,
    CanaryServiceDep,
    PrincipalDep,
)

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


class GuardrailEventPayload(BaseModel):
    """One guardrail observation fed to the canary by the monitoring
    pipeline. Severity 1 stops the horizon and rolls the release back."""

    severity: int = Field(ge=1, le=4)
    kind: str
    task_index: int = 0
    detail: str = ""


class StartCanaryRequest(BaseModel):
    """Admit and run one fixed-horizon canary.

    Config overrides are optional; the deployment's preregistered canary
    shape is the default. Guardrail events are the observations the
    monitoring pipeline collected during the horizon.
    """

    min_paired_tasks: int | None = None
    max_candidate_allocation: float | None = None
    observation_horizon_seconds: float | None = None
    seed: int | None = None
    guardrail_events: list[GuardrailEventPayload] = []


@router.post("/{manifest_digest}/canary/start", status_code=status.HTTP_201_CREATED)
def start_canary(
    principal: PrincipalDep,
    service: CanaryServiceDep,
    manifest_digest: str,
    request: StartCanaryRequest | None = None,
) -> CanaryRunView:
    """Admit and run one fixed-horizon canary for the release.

    Refuses a release that is not in canary status, and refuses a release
    whose resolved artifact classes are not canary-eligible (read-only or
    transactionally reversible). A severity-1 outcome rolls the release
    back through the release rollback path before this returns.
    """
    body = request or StartCanaryRequest()
    overrides: dict[str, Any] = {}
    if body.min_paired_tasks is not None:
        overrides["min_paired_tasks"] = body.min_paired_tasks
    if body.max_candidate_allocation is not None:
        overrides["max_candidate_allocation"] = body.max_candidate_allocation
    if body.observation_horizon_seconds is not None:
        overrides["observation_horizon"] = timedelta(seconds=body.observation_horizon_seconds)
    if body.seed is not None:
        overrides["seed"] = body.seed
    config = CanaryConfig(**overrides) if overrides else None
    events = [
        GuardrailEvent(severity=e.severity, kind=e.kind, task_index=e.task_index, detail=e.detail)
        for e in body.guardrail_events
    ]
    return service.start_canary(principal, manifest_digest, config=config, guardrail_events=events)


@router.get("/{manifest_digest}/canary-status")
def canary_status(
    principal: PrincipalDep, service: CanaryServiceDep, manifest_digest: str
) -> CanaryStatusView:
    """Where a release stands with respect to its canary runs."""
    return service.canary_status(principal, manifest_digest)

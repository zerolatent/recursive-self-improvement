"""Evaluation outcome HTTP API (FR-014).

Recording an outcome mints a signed attestation under the evaluation
plane's key, and the endpoint is evaluator-role-only: a candidate runner
cannot mint outcomes for its own candidate.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query, status
from pydantic import BaseModel

from evoruntime.api.schemas import EvaluationView
from evoruntime.server.dependencies import CampaignServiceDep, PrincipalDep

router = APIRouter(prefix="/v1/evaluations", tags=["evaluations"])


class RecordEvaluationRequest(BaseModel):
    """Record a signed evaluation outcome for an artifact."""

    artifact_digest: str
    outcome: str
    metrics: dict[str, Any]


@router.post("", status_code=status.HTTP_201_CREATED)
def record_evaluation(
    principal: PrincipalDep, service: CampaignServiceDep, request: RecordEvaluationRequest
) -> EvaluationView:
    """Sign and record an evaluation outcome for an artifact."""
    return service.record_evaluation(
        principal,
        artifact_digest=request.artifact_digest,
        outcome=request.outcome,
        metrics=request.metrics,
    )


@router.get("")
def list_evaluations(
    principal: PrincipalDep,
    service: CampaignServiceDep,
    artifact_digest: str | None = Query(default=None),
) -> list[EvaluationView]:
    """The tenant's evaluation attestations, optionally filtered."""
    return service.list_evaluations(principal, artifact_digest=artifact_digest)

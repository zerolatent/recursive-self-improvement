"""Approval HTTP API (FR-014 + F10).

Two surfaces share the `/v1/approvals` prefix because they are two
halves of one governance story:

- **Candidate approvals (FR-014)** — an approval is an E1 status event
  on the candidate's artifact, the same append-only, signed record the
  rest of the runtime trusts.
- **The review board (F10)** — tier-3/4 promotion and privileged-plugin
  admission requests judged under two-person semantics, with the signed
  admission records, compensation plans, and static-analysis reports
  surfaced read-only. The approver on every decision is the caller's
  verified workload identity, never a request field.

Errors are translated by the centralized handlers in
`evoruntime.server.errors` — this module raises, it does not render.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query, status
from pydantic import BaseModel, Field

from evoruntime.api.schemas import (
    AdmissionRecordView,
    ApprovalDecisionView,
    ApprovalRequestDetail,
    ApprovalRequestView,
    ApprovalView,
    CompensationPlanView,
    StaticAnalysisReportView,
)
from evoruntime.server.dependencies import (
    ApprovalServiceDep,
    CampaignServiceDep,
    PrincipalDep,
)

router = APIRouter(prefix="/v1/approvals", tags=["approvals"])


class RecordApprovalRequest(BaseModel):
    """One candidate approval (FR-014). The approver is the verified caller."""

    campaign_id: str
    proposal_id: str
    decision: str
    reason: str = ""


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


# ----------------------------------------------------------------------
# Review board (F10)
# ----------------------------------------------------------------------


class ApprovalRequestBody(BaseModel):
    """Open a review-board request. The requester is the verified caller."""

    kind: str = Field(description="'tier3_promotion' or 'privileged_admission'")
    justification: str = Field(min_length=1, description="why review-board approval is needed")
    campaign_id: str | None = None
    proposal_id: str | None = None
    plugin_id: str | None = None
    content_digest: str | None = None
    privileged_role: str | None = None


class DecisionBody(BaseModel):
    """Record one review-board decision. The approver is the verified caller."""

    decision: str = Field(description="'approve' or 'reject'")
    note: str = ""


class CompensationPlanBody(BaseModel):
    """Declare a compensation plan (F5 record type)."""

    actions: list[dict[str, Any]] = Field(min_length=1)
    campaign_id: str | None = None
    manifest_digest: str | None = None


@router.post(
    "/requests",
    response_model=ApprovalRequestDetail,
    status_code=status.HTTP_201_CREATED,
)
def create_approval_request(
    body: ApprovalRequestBody,
    principal: PrincipalDep,
    service: ApprovalServiceDep,
) -> ApprovalRequestDetail:
    """Open a review-board request (tier-3 promotion or privileged admission)."""
    return service.create_request(
        principal,
        kind=body.kind,
        justification=body.justification,
        campaign_id=body.campaign_id,
        proposal_id=body.proposal_id,
        plugin_id=body.plugin_id,
        content_digest=body.content_digest,
        privileged_role=body.privileged_role,
    )


@router.get("/requests", response_model=list[ApprovalRequestView])
def list_approval_requests(
    principal: PrincipalDep,
    service: ApprovalServiceDep,
    campaign_id: str | None = Query(default=None),
) -> list[ApprovalRequestView]:
    """List review-board requests in this tenant, optionally by campaign."""
    return service.list_requests(principal, campaign_id=campaign_id)


@router.get("/requests/{request_id}", response_model=ApprovalRequestDetail)
def get_approval_request(
    request_id: str, principal: PrincipalDep, service: ApprovalServiceDep
) -> ApprovalRequestDetail:
    """One review-board request with its recorded decisions."""
    return service.get_request(principal, request_id)


@router.post(
    "/requests/{request_id}/decisions",
    response_model=ApprovalDecisionView,
    status_code=status.HTTP_201_CREATED,
)
def decide_approval_request(
    request_id: str,
    body: DecisionBody,
    principal: PrincipalDep,
    service: ApprovalServiceDep,
) -> ApprovalDecisionView:
    """Record one decision by the verified caller (two-person review board)."""
    return service.decide(principal, request_id=request_id, decision=body.decision, note=body.note)


@router.post(
    "/requests/{request_id}/admission",
    response_model=AdmissionRecordView,
    status_code=status.HTTP_201_CREATED,
)
def admit_approval_request(
    request_id: str, principal: PrincipalDep, service: ApprovalServiceDep
) -> AdmissionRecordView:
    """Mint the signed admission record once the review board has approved."""
    return service.admit(principal, request_id=request_id)


@router.get("/admissions", response_model=list[AdmissionRecordView])
def list_admissions(
    principal: PrincipalDep,
    service: ApprovalServiceDep,
    request_id: str | None = Query(default=None),
) -> list[AdmissionRecordView]:
    """List signed admission records (read-only), optionally by request."""
    return service.list_admissions(principal, request_id=request_id)


@router.get("/admissions/{record_id}", response_model=AdmissionRecordView)
def get_admission(
    record_id: str, principal: PrincipalDep, service: ApprovalServiceDep
) -> AdmissionRecordView:
    """One signed admission record (read-only), signature bytes included."""
    return service.get_admission(principal, record_id)


@router.post(
    "/compensation-plans",
    response_model=CompensationPlanView,
    status_code=status.HTTP_201_CREATED,
)
def create_compensation_plan(
    body: CompensationPlanBody, principal: PrincipalDep, service: ApprovalServiceDep
) -> CompensationPlanView:
    """Declare a signed compensation plan (F5 record type)."""
    return service.record_compensation_plan(
        principal,
        actions=body.actions,
        campaign_id=body.campaign_id,
        manifest_digest=body.manifest_digest,
    )


@router.get("/compensation-plans", response_model=list[CompensationPlanView])
def list_compensation_plans(
    principal: PrincipalDep,
    service: ApprovalServiceDep,
    campaign_id: str | None = Query(default=None),
) -> list[CompensationPlanView]:
    """List signed compensation plans, optionally by campaign."""
    return service.list_compensation_plans(principal, campaign_id=campaign_id)


@router.get("/compensation-plans/{plan_id}", response_model=CompensationPlanView)
def get_compensation_plan(
    plan_id: str, principal: PrincipalDep, service: ApprovalServiceDep
) -> CompensationPlanView:
    """One signed compensation plan, signature bytes included."""
    return service.get_compensation_plan(principal, plan_id)


@router.get("/analysis-reports", response_model=list[StaticAnalysisReportView])
def list_analysis_reports(
    principal: PrincipalDep,
    service: CampaignServiceDep,
    candidate_digest: str | None = Query(default=None),
    campaign_id: str | None = Query(default=None),
) -> list[StaticAnalysisReportView]:
    """The tenant's F3 static-analysis verdicts, optionally scoped."""
    return service.list_analysis_reports(
        principal, candidate_digest=candidate_digest, campaign_id=campaign_id
    )


@router.get("/analysis-reports/{report_id}", response_model=StaticAnalysisReportView)
def get_analysis_report(
    report_id: str, principal: PrincipalDep, service: CampaignServiceDep
) -> StaticAnalysisReportView:
    """One F3 static-analysis verdict (read path over the F3 record type)."""
    return service.get_analysis_report(principal, report_id)

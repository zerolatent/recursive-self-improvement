"""Discovery report HTTP API (deliverable H3, PRD §17.1 step 3).

Runs failure clustering over the H2 trace reads and serves the signed
reports back. Reports ride the analysis-report path
(``db/models/analysis.py``) — this router is the operator surface that
makes §17.1 step 3 reachable without Python.

Every handler is `Principal`-scoped like every `CampaignApiService`
method: a report id that exists but belongs to another tenant renders as
the same 404 as one that never existed.
"""

from __future__ import annotations

from fastapi import APIRouter, Query, status
from pydantic import BaseModel

from evoruntime.api.schemas import DiscoveryReportView
from evoruntime.server.dependencies import CampaignServiceDep, PrincipalDep

router = APIRouter(prefix="/v1/discovery", tags=["discovery"])


class RunDiscoveryRequest(BaseModel):
    """Scope filters for one discovery run — all optional, all narrowing."""

    campaign_id: str | None = None
    agent_id: str | None = None
    release_id: str | None = None


@router.post("", status_code=status.HTTP_201_CREATED, response_model=DiscoveryReportView)
def run_discovery(
    principal: PrincipalDep, service: CampaignServiceDep, request: RunDiscoveryRequest
) -> DiscoveryReportView:
    """Cluster the tenant's trace failures into a signed discovery report."""
    return service.run_discovery(
        principal,
        campaign_id=request.campaign_id,
        agent_id=request.agent_id,
        release_id=request.release_id,
    )


@router.get("", response_model=list[DiscoveryReportView])
def list_discovery_reports(
    principal: PrincipalDep,
    service: CampaignServiceDep,
    campaign_id: str | None = Query(default=None),
) -> list[DiscoveryReportView]:
    """The tenant's signed discovery reports, optionally scoped."""
    return service.list_discovery_reports(principal, campaign_id=campaign_id)


@router.get("/{report_id}", response_model=DiscoveryReportView)
def get_discovery_report(
    principal: PrincipalDep, service: CampaignServiceDep, report_id: str
) -> DiscoveryReportView:
    """One signed discovery report, signature-verified before serving."""
    return service.get_discovery_report(principal, report_id)

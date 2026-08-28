"""Agent registration HTTP API (FR-014)."""

from __future__ import annotations

from fastapi import APIRouter, status
from pydantic import BaseModel

from evoruntime.api.schemas import AgentView
from evoruntime.server.dependencies import CampaignServiceDep, PrincipalDep

router = APIRouter(prefix="/v1/agents", tags=["agents"])


class RegisterAgentRequest(BaseModel):
    """Record an agent plugin registration."""

    plugin_id: str
    kind: str
    pinned_image: str
    artifact_types: list[str]
    agent_id: str | None = None


@router.post("", status_code=status.HTTP_201_CREATED)
def register_agent(
    principal: PrincipalDep, service: CampaignServiceDep, request: RegisterAgentRequest
) -> AgentView:
    """Record an agent plugin registration (the `agent register` step)."""
    return service.register_agent(
        principal,
        plugin_id=request.plugin_id,
        kind=request.kind,
        pinned_image=request.pinned_image,
        artifact_types=request.artifact_types,
        agent_id=request.agent_id,
    )


@router.get("")
def list_agents(principal: PrincipalDep, service: CampaignServiceDep) -> list[AgentView]:
    """The tenant's registered agents, oldest first."""
    return service.list_agents(principal)


@router.get("/{agent_id}")
def get_agent(principal: PrincipalDep, service: CampaignServiceDep, agent_id: str) -> AgentView:
    """One agent registration."""
    return service.get_agent(principal, agent_id)

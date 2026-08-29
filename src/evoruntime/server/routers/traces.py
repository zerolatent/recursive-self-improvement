"""Tenant-scoped trace read API (deliverable H2, PRD §17.1 steps 2–3).

The §17.1 loop begins with traces, but until H2 the ingest plane was
write-only. These endpoints are read-only over the existing event tables:
list the tenant's traces, and reconstruct one trace's event sequence with
per-event hash-integrity verdicts (via `evoruntime.db.trace_reads`, which
reuses the D2 chain machinery).

Every handler is `Principal`-scoped like every `CampaignApiService` method:
queries run against `principal.tenant_id` only, and a trace id that exists
but belongs to another tenant renders as the same 404 as a missing one —
a caller must not be able to enumerate other tenants' trace ids.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status

from evoruntime.db.trace_reads import MAX_TRACE_PAGE_SIZE, list_traces, reconstruct_trace
from evoruntime.server.dependencies import PrincipalDep, SessionFactoryDep
from evoruntime.server.schemas import (
    TraceEventView,
    TraceReconstructionResponse,
    TraceSummaryResponse,
)

router = APIRouter(prefix="/v1/traces", tags=["traces"])


@router.get("", response_model=list[TraceSummaryResponse])
def list_tenant_traces(
    principal: PrincipalDep,
    session_factory: SessionFactoryDep,
    agent_id: str | None = Query(default=None),
    campaign_id: str | None = Query(default=None),
    release_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=MAX_TRACE_PAGE_SIZE),
    offset: int = Query(default=0, ge=0),
) -> list[TraceSummaryResponse]:
    """The caller's tenant's traces, newest activity first, optionally filtered."""
    with session_factory() as session:
        summaries = list_traces(
            session,
            principal.tenant_id,
            agent_id=agent_id,
            campaign_id=campaign_id,
            release_id=release_id,
            limit=limit,
            offset=offset,
        )
    return [
        TraceSummaryResponse(
            trace_id=s.trace_id,
            task_id=s.task_id,
            agent_id=s.agent_id,
            release_id=s.release_id,
            campaign_id=s.campaign_id,
            event_count=s.event_count,
            first_occurred_at=s.first_occurred_at,
            last_occurred_at=s.last_occurred_at,
        )
        for s in summaries
    ]


@router.get("/{trace_id}/events", response_model=TraceReconstructionResponse)
def get_trace_events(
    principal: PrincipalDep, session_factory: SessionFactoryDep, trace_id: str
) -> TraceReconstructionResponse:
    """One trace's events in `chain_seq` order, each with its integrity verdict."""
    with session_factory() as session:
        reconstruction = reconstruct_trace(session, principal.tenant_id, trace_id)

    if reconstruction is None:
        # Same 404 for "no such trace" and "another tenant's trace": the
        # distinction would let a caller enumerate foreign trace ids.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    return TraceReconstructionResponse(
        trace_id=reconstruction.trace_id,
        event_count=len(reconstruction.events),
        valid=reconstruction.valid,
        events=[
            TraceEventView(
                chain_seq=e.chain_seq,
                event_id=e.event_id,
                type=e.event_type,
                occurred_at=e.occurred_at,
                event_hash=e.event_hash,
                hash_valid=e.hash_valid,
                envelope=e.envelope.model_dump(mode="json"),
            )
            for e in reconstruction.events
        ],
    )

"""Batched trace event ingest API (deliverable D2, PRD §18.3/FR-002).

Accepts a batch of raw event payloads, validates each independently against
the `EventEnvelope` schema, and persists valid ones one at a time (see
`evoruntime.db.ingest.ingest_envelope`) so a crash mid-batch can only ever
lose the single event that was in flight. Malformed events are rejected
individually with a typed error — one bad event in a batch of 1000 does not
fail the other 999 (PRD FR-001 conformance profile: the ingest path never
turns one bad record into a whole-batch loss).
"""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import ValidationError

from evoruntime.core.events import parse_wire_envelope
from evoruntime.db.base import session_scope
from evoruntime.db.chain_verification import verify_chain
from evoruntime.db.ingest import DuplicateEventError, ingest_envelope
from evoruntime.server.dependencies import SessionFactoryDep
from evoruntime.server.schemas import (
    ChainVerificationResponse,
    ChainViolationResponse,
    IngestBatchRequest,
    IngestBatchResponse,
    RejectedEvent,
)

router = APIRouter(tags=["ingest"])


@router.post("/v1/events:ingest", response_model=IngestBatchResponse)
def ingest_batch(payload: IngestBatchRequest, session_factory: SessionFactoryDep) -> IngestBatchResponse:
    """Validate and persist a batch of raw event payloads.

    Returns 200 with a per-item accept/reject breakdown rather than a single
    all-or-nothing status code — the caller (an adapter SDK flushing a
    buffer) needs to know exactly which events landed so it only retries
    what actually failed.
    """
    accepted: list[str] = []
    rejected: list[RejectedEvent] = []

    for index, raw_event in enumerate(payload.events):
        try:
            # See `parse_wire_envelope` docstring: this dict has already been
            # JSON-decoded once (by FastAPI), so it must go through JSON-mode
            # validation, not `EventEnvelope.model_validate` directly.
            envelope = parse_wire_envelope(raw_event)
        except ValidationError as exc:
            rejected.append(
                RejectedEvent(
                    index=index,
                    error_type="schema_validation_error",
                    message="event envelope failed schema validation",
                    details=[
                        dict(error)
                        for error in exc.errors(include_url=False, include_context=False)
                    ],
                )
            )
            continue

        try:
            with session_scope(session_factory) as session:
                ingest_envelope(session, envelope)
        except DuplicateEventError as exc:
            rejected.append(
                RejectedEvent(index=index, error_type="duplicate_event", message=str(exc))
            )
            continue

        accepted.append(envelope.event_id)

    return IngestBatchResponse(accepted_event_ids=accepted, rejected=rejected)


@router.get("/v1/tenants/{tenant_id}/chain/verify", response_model=ChainVerificationResponse)
def verify_tenant_chain(tenant_id: str, session_factory: SessionFactoryDep) -> ChainVerificationResponse:
    """Walk one tenant's hash chain end to end and report any violation."""
    with session_scope(session_factory) as session:
        result = verify_chain(session, tenant_id)

    return ChainVerificationResponse(
        tenant_id=result.tenant_id,
        event_count=result.event_count,
        valid=result.valid,
        violations=[
            ChainViolationResponse(chain_seq=v.chain_seq, event_id=v.event_id, reason=v.reason)
            for v in result.violations
        ],
    )

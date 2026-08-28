"""Request/response models for the ingest and chain-verification endpoints.

Kept separate from `evoruntime.core.events` (the normative envelope) because
these are API transport shapes — batch wrappers, per-item rejection
reporting — not data contracts other services persist or hash.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

RejectionErrorType = Literal["schema_validation_error", "duplicate_event"]


class IngestBatchRequest(BaseModel):
    """Raw batch payload.

    Events are accepted as untyped dicts (not `list[EventEnvelope]`) so one
    malformed event does not fail FastAPI's whole-body validation before the
    handler gets a chance to reject just that event and accept the rest —
    partial batch acceptance is the point of a *batched* endpoint.
    """

    model_config = ConfigDict(extra="forbid")

    events: list[dict[str, Any]] = Field(min_length=1, max_length=1000)


class RejectedEvent(BaseModel):
    """One event the batch could not accept, with a typed reason."""

    index: int
    error_type: RejectionErrorType
    message: str
    details: list[dict[str, Any]] | None = None


class IngestBatchResponse(BaseModel):
    """Per-item outcome of a batch — never a single all-or-nothing verdict."""

    accepted_event_ids: list[str]
    rejected: list[RejectedEvent]


class ChainViolationResponse(BaseModel):
    chain_seq: int
    event_id: str
    reason: str


class ChainVerificationResponse(BaseModel):
    tenant_id: str
    event_count: int
    valid: bool
    violations: list[ChainViolationResponse]

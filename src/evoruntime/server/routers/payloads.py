"""Authenticated payload-registration API (deliverable H2, PRD §17.1 step 2).

`Trace.tool_call` demands `sha256:` digests and `artifact_loaded` binds
payload digests, but until H2 nothing outside the server could store the
bytes those digests reference — the digest chain was unconstructible from
a real agent. This router is the missing write surface: it writes through
the existing D4 payload store (`evoruntime.lineage.payload_store`) with the
`DataClassification` attached at registration, and deletion goes through
the existing D4 tombstone flow (`evoruntime.lineage.deletion`) — reused,
not forked.

Every handler is `Principal`-scoped: payloads are keyed by
`(tenant_id, payload_digest)`, and a digest that exists for another tenant
renders as the same 404 as one that never existed.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request, Response, status
from sqlalchemy import select

from evoruntime.core.events import DataClassification
from evoruntime.db.base import session_scope
from evoruntime.db.models.lineage import Payload, Tombstone
from evoruntime.lineage.deletion import DeletionService
from evoruntime.lineage.payload_store import PayloadStore
from evoruntime.server.dependencies import PrincipalDep, SessionFactoryDep
from evoruntime.server.schemas import PayloadRegistrationResponse

router = APIRouter(prefix="/v1/payloads", tags=["payloads"])


@router.post("", status_code=status.HTTP_201_CREATED, response_model=PayloadRegistrationResponse)
async def register_payload(
    principal: PrincipalDep,
    session_factory: SessionFactoryDep,
    request: Request,
    classification: Annotated[
        DataClassification,
        Query(description="Sensitivity label attached to the payload at registration."),
    ],
) -> PayloadRegistrationResponse:
    """Store raw payload bytes under the caller's tenant, classified.

    Idempotent by content: re-uploading the same bytes returns the same
    digest without duplicating storage (the payload store is
    content-addressed). The returned digest is what the agent records in
    `tool_call`/`artifact_loaded` — the SDK's `register_payload` helper
    composes exactly this endpoint with that event emission.
    """
    content = await request.body()
    with session_scope(session_factory) as session:
        payload = PayloadStore(session).store(
            tenant_id=principal.tenant_id,
            plaintext=content,
            data_classification=classification.value,
        )
    return PayloadRegistrationResponse(
        payload_digest=payload.payload_digest,
        byte_size=payload.byte_size,
        data_classification=payload.data_classification,
    )


@router.get("/{payload_digest}")
def read_payload(
    principal: PrincipalDep, session_factory: SessionFactoryDep, payload_digest: str
) -> Response:
    """Decrypt and return one payload's bytes (tenant-scoped)."""
    with session_scope(session_factory) as session:
        plaintext = PayloadStore(session).read(
            tenant_id=principal.tenant_id, payload_digest=payload_digest
        )
        stored = session.execute(
            select(Payload.data_classification).where(
                Payload.tenant_id == principal.tenant_id,
                Payload.payload_digest == payload_digest,
            )
        ).scalar_one()
    return Response(
        content=plaintext,
        media_type="application/octet-stream",
        headers={"x-evoruntime-data-classification": stored},
    )


@router.delete("/{payload_digest}")
def delete_payload(
    principal: PrincipalDep, session_factory: SessionFactoryDep, payload_digest: str
) -> dict[str, object]:
    """Request deletion of one payload through the D4 tombstone flow.

    Runs the flow's first two steps synchronously — tombstone row, then
    access revoked (the payload row hard-deleted) — and leaves the
    derived-data purge to the scheduled sweep, exactly as the D4 machinery
    splits them. Idempotent: deleting an already-revoked digest returns the
    existing tombstone rather than opening a second request.
    """
    with session_scope(session_factory) as session:
        existing = session.execute(
            select(Tombstone).where(
                Tombstone.tenant_id == principal.tenant_id,
                Tombstone.resource_type == "payload",
                Tombstone.resource_id == payload_digest,
                Tombstone.access_revoked_at.is_not(None),
            )
        ).scalar_one_or_none()
        if existing is not None:
            tombstone = existing
        else:
            payload = session.execute(
                select(Payload).where(
                    Payload.tenant_id == principal.tenant_id,
                    Payload.payload_digest == payload_digest,
                )
            ).scalar_one_or_none()
            if payload is None:
                # Same 404 for "never existed" and "another tenant's
                # payload": the distinction would let a caller enumerate
                # foreign digests.
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
            deletion = DeletionService(session)
            tombstone = deletion.request_deletion(
                tenant_id=principal.tenant_id,
                resource_type="payload",
                resource_id=payload_digest,
                requested_by=principal.identity_id,
            )
            deletion.revoke_access(tombstone)

    return {
        "payload_digest": payload_digest,
        "tombstone_id": str(tombstone.id),
        "access_revoked_at": tombstone.access_revoked_at.isoformat()
        if tombstone.access_revoked_at
        else None,
    }

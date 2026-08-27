"""The tombstone-driven deletion flow.

Request -> tombstone row -> access revoked (<=5min SLO) -> derived data
purged (<=24h SLO). `DeletionService` implements the two state
transitions; `evoruntime.lineage.purge` drives them on a schedule, sweeping
every tombstone whose SLO deadline has elapsed. Splitting "revoke access"
from "purge derived data" (rather than doing both at request time) is what
lets the two steps have different SLOs and be independently retried.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from evoruntime.db.models.lineage import DerivedDataRecord, Payload, Tombstone

#: Phase 0 only tombstones payloads (the spec's payload-deletion row). A
#: later phase that adds deletable resource kinds extends this literal and
#: `revoke_access`'s dispatch, not the tombstone schema.
DeletableResourceType = Literal["payload"]


class DeletionService:
    """Requests deletions and advances them through the flow's two SLO'd steps."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def request_deletion(
        self,
        *,
        tenant_id: str,
        resource_type: DeletableResourceType,
        resource_id: str,
        requested_by: str,
        reason: str | None = None,
    ) -> Tombstone:
        """Record a deletion request.

        Deliberately does not revoke access itself: every deletion — however
        urgent — goes through the same auditable, SLO-timed sweep, so the
        record of "when was access actually cut off" is always populated by
        the same code path and is comparable across requests.
        """
        tombstone = Tombstone(
            tenant_id=tenant_id,
            resource_type=resource_type,
            resource_id=resource_id,
            reason=reason,
            requested_by=requested_by,
        )
        self._session.add(tombstone)
        self._session.flush()
        return tombstone

    def revoke_access(self, tombstone: Tombstone, *, now: datetime | None = None) -> None:
        """Revoke access to the tombstoned resource.

        For a payload this is a hard delete of the payload row: payloads
        are separately deletable from the (append-only) envelope that
        references them, which is the entire reason the payload/envelope
        split exists. Idempotent — a payload already gone (or never
        present) is not an error, since a sweep may retry a tombstone.
        """
        if tombstone.resource_type == "payload":
            payload = self._session.execute(
                select(Payload).where(
                    Payload.tenant_id == tombstone.tenant_id,
                    Payload.payload_digest == tombstone.resource_id,
                )
            ).scalar_one_or_none()
            if payload is not None:
                self._session.delete(payload)
        tombstone.access_revoked_at = now or datetime.now(UTC)
        self._session.flush()

    def purge_derived_data(self, tombstone: Tombstone, *, now: datetime | None = None) -> int:
        """Delete every derived-data record (embedding, cache, search-index
        row) keyed to the tombstoned resource. Returns the number of rows
        purged, so callers/tests can assert something was actually removed.
        """
        records = (
            self._session.execute(
                select(DerivedDataRecord).where(
                    DerivedDataRecord.tenant_id == tombstone.tenant_id,
                    DerivedDataRecord.resource_id == tombstone.resource_id,
                )
            )
            .scalars()
            .all()
        )
        for record in records:
            self._session.delete(record)
        tombstone.purge_completed_at = now or datetime.now(UTC)
        self._session.flush()
        return len(records)

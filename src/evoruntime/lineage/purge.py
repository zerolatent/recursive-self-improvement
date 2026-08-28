"""Scheduled sweeps that advance tombstones through the deletion flow's two
SLOs: access revocation (default 5 minutes) and derived-data purge
(default 24 hours). Intended to run on a periodic scheduler (e.g. every
minute); both sweeps are idempotent and safe to run repeatedly, since each
only selects tombstones that haven't yet completed the step in question.

SLO thresholds are read from `LineageSettings` by default but accept an
override, so tests can shrink "5 minutes" to a few milliseconds and
observe the sweep firing without a real wall-clock wait — the acceptance
criterion is the sweep logic and boundary handling, not real-time passage.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from evoruntime.db.models.lineage import Tombstone
from evoruntime.lineage.deletion import DeletionService
from evoruntime.lineage.settings import get_lineage_settings


def run_access_revocation_sweep(
    session: Session, *, now: datetime | None = None, sla_seconds: int | None = None
) -> list[Tombstone]:
    """Revoke access for every tombstone whose access-revocation SLO has
    elapsed since it was requested. Returns the tombstones processed.
    """
    now = now or datetime.now(UTC)
    sla = timedelta(
        seconds=sla_seconds
        if sla_seconds is not None
        else get_lineage_settings().access_revocation_sla_seconds
    )
    deadline = now - sla
    service = DeletionService(session)
    pending = list(
        session.execute(
            select(Tombstone).where(
                Tombstone.access_revoked_at.is_(None),
                Tombstone.requested_at <= deadline,
            )
        ).scalars()
    )
    for tombstone in pending:
        service.revoke_access(tombstone, now=now)
    return pending


def run_derived_purge_sweep(
    session: Session, *, now: datetime | None = None, sla_seconds: int | None = None
) -> list[Tombstone]:
    """Purge derived data for every tombstone whose access has already been
    revoked and whose derived-purge SLO has elapsed since revocation.
    Returns the tombstones processed.
    """
    now = now or datetime.now(UTC)
    sla = timedelta(
        seconds=sla_seconds
        if sla_seconds is not None
        else get_lineage_settings().derived_purge_sla_seconds
    )
    deadline = now - sla
    service = DeletionService(session)
    pending = list(
        session.execute(
            select(Tombstone).where(
                Tombstone.access_revoked_at.is_not(None),
                Tombstone.purge_completed_at.is_(None),
                Tombstone.access_revoked_at <= deadline,
            )
        ).scalars()
    )
    for tombstone in pending:
        service.purge_derived_data(tombstone, now=now)
    return pending

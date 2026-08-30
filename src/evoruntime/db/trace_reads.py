"""Read-side queries over the existing event tables (deliverable H2).

The ingest path (D2) is write-only by design; this module is the read
complement the §17.1 loop starts from: tenant-scoped trace listing and
per-trace sequence reconstruction. Every function takes an explicit
`tenant_id` and filters on it — there is deliberately no unscoped variant,
so a caller cannot get here without a tenant boundary.

Reconstruction reuses the hash machinery from `evoruntime.db.chain_verification`
(`envelope_from_row` / `compute_event_hash`) rather than re-deriving it: the
hash must be recomputed exactly the way ingest computed it for an integrity
verdict to mean anything.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from evoruntime.core.events import EventEnvelope
from evoruntime.core.hashchain import compute_event_hash
from evoruntime.db.chain_verification import envelope_from_row
from evoruntime.db.models.events import Event

#: Upper bound on one page of trace summaries. Generous for a single
#: tenant's dashboard view; a caller needing more paginates.
MAX_TRACE_PAGE_SIZE = 500


@dataclass(frozen=True)
class TraceSummary:
    """One trace as listed: identity and span, no event bodies."""

    trace_id: str
    task_id: str
    agent_id: str
    release_id: str
    campaign_id: str | None
    event_count: int
    first_occurred_at: datetime
    last_occurred_at: datetime


@dataclass(frozen=True)
class TraceEventReconstruction:
    """One event of a reconstructed trace, with its integrity verdict.

    `hash_valid` is the per-event check: the stored `event_hash` matches a
    recomputation from the stored envelope fields. (Per-trace `prev_hash`
    linkage is not checkable here — a trace's events interleave with other
    traces in the tenant chain, so each row's `prev_hash` refers to the
    previous *tenant-chain* event, not the previous event of this trace.
    Whole-chain linkage is `verify_chain`'s job.)
    """

    chain_seq: int
    event_id: str
    event_type: str
    occurred_at: datetime
    event_hash: str
    hash_valid: bool
    envelope: EventEnvelope


@dataclass(frozen=True)
class TraceReconstruction:
    """A trace's events in `chain_seq` order, each with its integrity verdict."""

    trace_id: str
    events: tuple[TraceEventReconstruction, ...]

    @property
    def valid(self) -> bool:
        """True when every event's stored hash matches its recomputation."""
        return all(event.hash_valid for event in self.events)


def list_traces(
    session: Session,
    tenant_id: str,
    *,
    agent_id: str | None = None,
    campaign_id: str | None = None,
    release_id: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[TraceSummary]:
    """List the tenant's traces, newest activity first, optionally filtered.

    A filter narrows to traces having at least one event matching it —
    the grouping happens after the filter, so a trace whose events span
    campaigns (they do not today, but the schema permits it) appears under
    each campaign it touched.
    """
    stmt = (
        select(
            Event.trace_id,
            func.min(Event.task_id),
            func.min(Event.agent_id),
            func.min(Event.release_id),
            func.min(Event.campaign_id),
            func.count(),
            func.min(Event.occurred_at),
            func.max(Event.occurred_at),
        )
        .where(Event.tenant_id == tenant_id)
        .group_by(Event.trace_id)
        .order_by(func.max(Event.occurred_at).desc(), Event.trace_id)
        .limit(limit)
        .offset(offset)
    )
    if agent_id is not None:
        stmt = stmt.where(Event.agent_id == agent_id)
    if campaign_id is not None:
        stmt = stmt.where(Event.campaign_id == campaign_id)
    if release_id is not None:
        stmt = stmt.where(Event.release_id == release_id)

    rows = session.execute(stmt).all()
    return [
        TraceSummary(
            trace_id=row[0],
            task_id=row[1],
            agent_id=row[2],
            release_id=row[3],
            campaign_id=row[4],
            event_count=row[5],
            first_occurred_at=row[6],
            last_occurred_at=row[7],
        )
        for row in rows
    ]


def reconstruct_trace(
    session: Session, tenant_id: str, trace_id: str
) -> TraceReconstruction | None:
    """Rebuild one trace's event sequence in `chain_seq` order.

    Returns None when the trace has no events for `tenant_id` — the caller
    (the router) collapses "wrong tenant" and "no such trace" into the same
    404 so a caller cannot enumerate other tenants' trace ids.
    """
    rows = (
        session.execute(
            select(Event)
            .where(Event.tenant_id == tenant_id, Event.trace_id == trace_id)
            .order_by(Event.chain_seq.asc())
        )
        .scalars()
        .all()
    )
    if not rows:
        return None

    events = []
    for row in rows:
        envelope = envelope_from_row(row)
        recomputed = compute_event_hash(envelope, row.prev_hash)
        events.append(
            TraceEventReconstruction(
                chain_seq=row.chain_seq,
                event_id=row.event_id,
                event_type=row.type,
                occurred_at=row.occurred_at,
                event_hash=row.event_hash,
                hash_valid=recomputed == row.event_hash,
                envelope=envelope,
            )
        )
    return TraceReconstruction(trace_id=trace_id, events=tuple(events))

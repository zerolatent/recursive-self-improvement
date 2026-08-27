"""Per-event ingest persistence: hash-chain assignment + durable commit.

Each event is written in its own transaction (see `ingest_envelope`, always
called inside `evoruntime.db.base.session_scope`) so a crash between events
loses at most the one event that was in flight — never a whole batch. This
is what the fault-injection test (`tests/test_fault_injection.py`) exercises
and what bounds event loss to the required ≤0.01% (spec D2 acceptance). The
batched HTTP endpoint (`evoruntime.server.ingest`) accepts many events per
request but persists them through this one-event-at-a-time path.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from evoruntime.core.events import EventEnvelope
from evoruntime.core.hashchain import GENESIS_HASH, compute_event_hash
from evoruntime.db.models import Event


class DuplicateEventError(Exception):
    """Raised when `event_id` already exists.

    The caller should treat this as "already ingested" (safe to acknowledge
    without re-inserting), not as data loss.
    """

    def __init__(self, event_id: str) -> None:
        super().__init__(f"event {event_id!r} already ingested")
        self.event_id = event_id


def ingest_envelope(session: Session, envelope: EventEnvelope) -> Event:
    """Persist one event, assigning it the next slot in its tenant's hash
    chain, and return the persisted row.

    Must run inside a transaction the caller commits (or rolls back) as a
    single unit — `session_scope` does this per call so each event is its
    own atomic commit. Raises `DuplicateEventError` if `event_id` was
    already ingested.
    """
    # Serializes concurrent ingests for the same tenant — including the
    # very first event, where there is no row yet to lock — so chain_seq
    # and prev_hash assignment never race across processes or requests.
    session.execute(select(func.pg_advisory_xact_lock(func.hashtext(envelope.tenant_id))))

    tail = session.execute(
        select(Event.chain_seq, Event.event_hash)
        .where(Event.tenant_id == envelope.tenant_id)
        .order_by(Event.chain_seq.desc())
        .limit(1)
    ).first()

    prev_hash = tail.event_hash if tail is not None else GENESIS_HASH
    chain_seq = (tail.chain_seq if tail is not None else 0) + 1
    event_hash = compute_event_hash(envelope, prev_hash)

    row = Event(
        event_id=envelope.event_id,
        occurred_at=envelope.occurred_at,
        tenant_id=envelope.tenant_id,
        agent_id=envelope.agent_id,
        release_id=envelope.release_id,
        campaign_id=envelope.campaign_id,
        trace_id=envelope.trace_id,
        task_id=envelope.task_id,
        type=envelope.type,
        schema_version=envelope.schema_version,
        artifact_digests=list(envelope.artifact_digests),
        model=envelope.model.model_dump(mode="json"),
        environment_digest=envelope.environment_digest,
        cost=envelope.cost.model_dump(mode="json"),
        data_classification=envelope.data_classification.value,
        payload_uri=envelope.payload_uri,
        payload_digest=envelope.payload_digest,
        chain_seq=chain_seq,
        prev_hash=prev_hash,
        event_hash=event_hash,
    )
    session.add(row)
    try:
        session.flush()
    except IntegrityError as exc:
        raise DuplicateEventError(envelope.event_id) from exc
    return row

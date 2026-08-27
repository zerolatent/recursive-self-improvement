"""Per-tenant hash-chain verification (PRD §18.3 tamper evidence).

Recomputes every event's hash from its stored envelope fields, walked in
`chain_seq` order, and compares against what was actually stored. This
detects two distinct failure modes:

- **mutation** — any envelope field changed after ingest: the recomputed
  `event_hash` no longer matches the stored one.
- **reorder** — chain order was tampered with (e.g. two adjacent rows'
  positions swapped): a row's stored `prev_hash` no longer matches the
  `event_hash` of whatever now precedes it in `chain_seq` order, even
  though each row's own hash still checks out against its own `prev_hash`.

Both checks are necessary — a reorder does not, by itself, invalidate any
individual row's `event_hash` (it was computed correctly against its own
`prev_hash` at ingest time), so checking `event_hash` alone would miss it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from evoruntime.core.events import CostInfo, DataClassification, EventEnvelope, ModelInfo
from evoruntime.core.hashchain import GENESIS_HASH, compute_event_hash
from evoruntime.db.models.events import Event

ViolationReason = Literal["sequence_gap", "prev_hash_mismatch", "hash_mismatch"]


@dataclass(frozen=True)
class ChainViolation:
    """One detected break in a tenant's hash chain."""

    chain_seq: int
    event_id: str
    reason: ViolationReason


@dataclass(frozen=True)
class ChainVerificationResult:
    """Outcome of walking one tenant's chain end to end."""

    tenant_id: str
    event_count: int
    violations: tuple[ChainViolation, ...] = field(default_factory=tuple)

    @property
    def valid(self) -> bool:
        return len(self.violations) == 0


def _envelope_from_row(row: Event) -> EventEnvelope:
    """Reconstruct the envelope pydantic model from a stored row.

    The hash must be recomputed exactly the way it was computed at ingest
    time (`evoruntime.db.ingest.ingest_envelope`), so this goes back through
    the same `EventEnvelope` type rather than hashing raw column values.
    """
    return EventEnvelope(
        event_id=row.event_id,
        occurred_at=row.occurred_at,
        tenant_id=row.tenant_id,
        agent_id=row.agent_id,
        release_id=row.release_id,
        campaign_id=row.campaign_id,
        trace_id=row.trace_id,
        task_id=row.task_id,
        type=row.type,
        schema_version=row.schema_version,
        artifact_digests=tuple(row.artifact_digests),
        model=ModelInfo.model_validate(row.model),
        environment_digest=row.environment_digest,
        cost=CostInfo.model_validate(row.cost),
        data_classification=DataClassification(row.data_classification),
        payload_uri=row.payload_uri,
        payload_digest=row.payload_digest,
    )


def verify_chain(session: Session, tenant_id: str) -> ChainVerificationResult:
    """Verify `tenant_id`'s full hash chain in `chain_seq` order."""
    rows = (
        session.execute(
            select(Event).where(Event.tenant_id == tenant_id).order_by(Event.chain_seq.asc())
        )
        .scalars()
        .all()
    )

    violations: list[ChainViolation] = []
    expected_prev_hash = GENESIS_HASH
    expected_chain_seq = 1

    for row in rows:
        if row.chain_seq != expected_chain_seq:
            violations.append(ChainViolation(row.chain_seq, row.event_id, "sequence_gap"))
        if row.prev_hash != expected_prev_hash:
            violations.append(ChainViolation(row.chain_seq, row.event_id, "prev_hash_mismatch"))

        recomputed = compute_event_hash(_envelope_from_row(row), row.prev_hash)
        if recomputed != row.event_hash:
            violations.append(ChainViolation(row.chain_seq, row.event_id, "hash_mismatch"))

        expected_prev_hash = row.event_hash
        expected_chain_seq = row.chain_seq + 1

    return ChainVerificationResult(
        tenant_id=tenant_id, event_count=len(rows), violations=tuple(violations)
    )

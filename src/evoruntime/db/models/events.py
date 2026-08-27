"""SQLAlchemy ORM model for the `events` table (deliverable D2).

One row per ingested trace event: the envelope's fields, flattened where
useful for querying (tenant/agent/release/trace/task ids, type) and kept as
JSON where the field is itself structured (`model`, `cost`,
`artifact_digests`), plus the hash-chain columns (`prev_hash`/`event_hash`)
and the per-tenant `chain_seq` that gives the chain a total order.

Sibling deliverables register their own tables against the same
`Base.metadata` from their own module (see `db/models/lineage.py` for D4,
`evoruntime/datasets/models.py` for D5); this module only owns `events`.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Index, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from evoruntime.db.base import Base


class Event(Base):
    """A single ingested trace event, chained per tenant.

    `chain_seq` is the append order within a tenant's chain (1-based); it is
    assigned by the ingest path under a row lock on the tenant's current tail
    so concurrent ingests for the same tenant still serialize into one
    unambiguous order (see `evoruntime.db.ingest`).
    """

    __tablename__ = "events"
    __table_args__ = (
        UniqueConstraint("tenant_id", "chain_seq", name="uq_events_tenant_chain_seq"),
        Index("ix_events_tenant_occurred_at", "tenant_id", "occurred_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    # Envelope fields (PRD §18.3), in envelope declaration order.
    event_id: Mapped[str] = mapped_column(String, unique=True, index=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    tenant_id: Mapped[str] = mapped_column(String, index=True)
    agent_id: Mapped[str] = mapped_column(String)
    release_id: Mapped[str] = mapped_column(String)
    campaign_id: Mapped[str | None] = mapped_column(String, nullable=True)
    trace_id: Mapped[str] = mapped_column(String, index=True)
    task_id: Mapped[str] = mapped_column(String)
    type: Mapped[str] = mapped_column(String)
    schema_version: Mapped[int] = mapped_column(Integer)
    artifact_digests: Mapped[list[str]] = mapped_column(JSONB)
    model: Mapped[dict[str, str]] = mapped_column(JSONB)
    environment_digest: Mapped[str] = mapped_column(String)
    cost: Mapped[dict[str, float | int]] = mapped_column(JSONB)
    data_classification: Mapped[str] = mapped_column(String)
    payload_uri: Mapped[str | None] = mapped_column(String, nullable=True)
    payload_digest: Mapped[str | None] = mapped_column(String, nullable=True)

    # Hash-chain columns (PRD §18.3 tamper evidence, spec D2).
    chain_seq: Mapped[int] = mapped_column(BigInteger)
    prev_hash: Mapped[str] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)

    # Server-side ingest timestamp, distinct from the client-reported
    # `occurred_at` — lets ops distinguish client clock skew from ingest lag.
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

"""ORM model for the scaffold-mutation archive (Phase 3, G9).

A *projection*, not a record: `scaffold_mutation_archive` is derived,
row for row, from `proposal_records` joined to `evaluation_attestations`
on the proposed digest — exactly the `lineage_productivity` pattern
(Phase 2, F9/FR-102), extended with the declared mutation class each
scaffold proposal carries and the attested fitness.

Deliberately NOT append-only: the append-only core (proposals,
attestations, proposal members) is untouched and remains the evidence;
this table can be dropped and rebuilt from those records at any time,
which is what `MutationArchiveService.rebuild` does and what `reconcile`
verifies. A projection that claimed immutability would just be a
second, weaker copy of the evidence — and an immutability trigger here
would make `rebuild` impossible.

The `mutation_class` column is the graduation policy's (G10) read
surface: every harness-mutator proposal declares its class, the
registry stores it in the proposal's metadata, and the projection lifts
it into a typed column so per-class risk review never re-parses JSONB.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Float,
    ForeignKeyConstraint,
    Index,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from evoruntime.db.base import Base


class ScaffoldMutationArchive(Base):
    """One declared-mutation proposal × attestation pair.

    `mutation_class` is the proposal's declared class (G3
    preregistration, G10 consumption); `fitness` is the attestation's
    ``fitness`` metric when it attested one — NULL otherwise, which is
    still a row: the outcome is evidence even when no fitness was
    reported.
    """

    __tablename__ = "scaffold_mutation_archive"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(nullable=False)
    proposal_id: Mapped[str] = mapped_column(nullable=False)
    artifact_digest: Mapped[str] = mapped_column(nullable=False)
    parent_digest: Mapped[str | None] = mapped_column(nullable=True)
    strategy_id: Mapped[str] = mapped_column(nullable=False)
    campaign_id: Mapped[str | None] = mapped_column(nullable=True)
    attestation_id: Mapped[str] = mapped_column(nullable=False)
    outcome: Mapped[str] = mapped_column(nullable=False)
    mutation_class: Mapped[str] = mapped_column(nullable=False)
    fitness: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint("outcome IN ('pass', 'fail')", name="ck_scaffold_mutation_archive_outcome"),
        ForeignKeyConstraint(
            ["tenant_id", "proposal_id"],
            ["proposal_records.tenant_id", "proposal_records.proposal_id"],
            name="fk_scaffold_mutation_archive_proposal",
        ),
        ForeignKeyConstraint(
            ["attestation_id"],
            ["evaluation_attestations.attestation_id"],
            name="fk_scaffold_mutation_archive_attestation",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "artifact_digest"],
            ["artifact_content.tenant_id", "artifact_content.digest"],
            name="fk_scaffold_mutation_archive_artifact",
        ),
        Index("ix_scaffold_mutation_archive_tenant_artifact", "tenant_id", "artifact_digest"),
        # The graduation policy's read path: per-class archive slices.
        Index("ix_scaffold_mutation_archive_tenant_class", "tenant_id", "mutation_class"),
    )

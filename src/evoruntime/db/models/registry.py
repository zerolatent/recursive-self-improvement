"""ORM models for the artifact registry (deliverable E1, PRD §9.2).

Five records, one mutability contract each:

- `artifact_content` is immutable and content-addressed: a record cannot be
  both content-addressed and mutable, so the migration attaches the same
  `BEFORE UPDATE OR DELETE` trigger D4 used for lineage nodes. The digest
  covers only the *digested body* — artifact type, canonical body digest,
  dependencies, capability requests. The generated id, the storage URI,
  and any signature are excluded (they are either derived from the body or
  attached to it, never part of what the digest vouches for).
- `proposal_records` record that a strategy proposed a candidate; append-only
  for the same reason (a proposal's history is evidence).
- `evaluation_attestations` are signed outcome records; append-only because
  a signed record whose row could be edited afterwards would vouch for
  bytes nobody produced.
- `artifact_status_events` are the append-only event stream behind the
  current-status projection (nominate/reject/revoke/expire/quarantine/
  supersede). Current status is a *projection* — the
  `artifact_current_status` view — never part of any digest.
- `release_manifests` are signed activation units; append-only, with
  activation state living in the release controller (E5), not in this row.

`digest` is unique per tenant, not globally: two tenants registering
byte-identical content must get independent rows, or the second
registration would resolve to the first tenant's record — a cross-tenant
leak dressed up as deduplication. The payload store already scopes
content addresses by tenant for the same reason.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from evoruntime.db.base import Base

#: The six status-event kinds (PRD §9.2). Enforced by a CHECK constraint so
#: even a hand-written INSERT cannot introduce an unknown kind.
STATUS_EVENT_KINDS = ("nominate", "reject", "revoke", "expire", "quarantine", "supersede")

_KIND_CHECK_SQL = "kind IN ('nominate', 'reject', 'revoke', 'expire', 'quarantine', 'supersede')"


class ArtifactContent(Base):
    """Immutable canonical body of a registered artifact, content-addressed
    by `digest` = sha256 over the canonical JSON of the digested body
    (artifact_type, canonical_body_digest, dependencies, capability_requests).
    """

    __tablename__ = "artifact_content"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(nullable=False)
    artifact_id: Mapped[str] = mapped_column(nullable=False, unique=True)
    digest: Mapped[str] = mapped_column(nullable=False)
    artifact_type: Mapped[str] = mapped_column(nullable=False)
    canonical_body_digest: Mapped[str] = mapped_column(nullable=False)
    dependencies: Mapped[list[object]] = mapped_column(JSONB, nullable=False, default=list)
    capability_requests: Mapped[dict[str, object]] = mapped_column(
        JSONB, nullable=False, default=dict
    )
    storage_uri: Mapped[str] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("tenant_id", "digest", name="uq_artifact_content_tenant_digest"),
        UniqueConstraint("tenant_id", "artifact_id", name="uq_artifact_content_tenant_artifact_id"),
        Index("ix_artifact_content_tenant_id", "tenant_id"),
    )


class ProposalRecord(Base):
    """A strategy's proposal of a candidate artifact for evaluation.

    `proposed_digest` points at the candidate's immutable body; `parent_digest`
    at the artifact it was derived from (None for a fresh proposal). Append-only:
    the selector's freeze (E4) records a nominate status event rather than
    editing this row.
    """

    __tablename__ = "proposal_records"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(nullable=False)
    proposal_id: Mapped[str] = mapped_column(nullable=False, unique=True)
    proposed_digest: Mapped[str] = mapped_column(nullable=False)
    parent_digest: Mapped[str | None] = mapped_column(nullable=True)
    strategy_id: Mapped[str] = mapped_column(nullable=False)
    campaign_id: Mapped[str | None] = mapped_column(nullable=True)
    proposal_metadata: Mapped[dict[str, object]] = mapped_column(
        JSONB, nullable=False, default=dict
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint(
            "parent_digest IS NULL OR parent_digest <> proposed_digest",
            name="ck_proposal_records_no_self_parent",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "proposed_digest"],
            ["artifact_content.tenant_id", "artifact_content.digest"],
            name="fk_proposal_records_proposed_artifact",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "parent_digest"],
            ["artifact_content.tenant_id", "artifact_content.digest"],
            name="fk_proposal_records_parent_artifact",
        ),
        # Composite proposals (F4) reference a proposal row from
        # proposal_members with a tenant-scoped FK; this constraint is the
        # unique target it requires (proposal_id alone is already unique).
        UniqueConstraint("tenant_id", "proposal_id", name="uq_proposal_records_tenant_proposal"),
        Index("ix_proposal_records_tenant_id", "tenant_id"),
        Index("ix_proposal_records_proposed_digest", "tenant_id", "proposed_digest"),
    )


class ProposalMemberRecord(Base):
    """One typed member of a composite proposal (Phase 2, F4).

    A composite proposal is an ordered tuple of members, each carrying its
    own artifact type, member digest, patch, and declared executables.
    The composite digest lives on the `proposal_records` row
    (`proposed_digest`); this table carries the member set that digest
    binds, so the single-digest single-parent shape of `proposal_records`
    loses no information: each member records its own `parent_digest`,
    and the composite's parent set is the union of its members' parents
    (multi-parent lineage edges, one row per member).

    Append-only like the proposal it belongs to — a proposal's history is
    evidence, and the digest over the member set is only meaningful if
    the member rows cannot be edited after the fact.
    """

    __tablename__ = "proposal_members"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(nullable=False)
    proposal_id: Mapped[str] = mapped_column(nullable=False)
    #: Position in the composite's ordered member tuple — the digest is
    #: order-sensitive, so the stored order must be authoritative.
    position: Mapped[int] = mapped_column(nullable=False)
    artifact_type: Mapped[str] = mapped_column(nullable=False)
    member_digest: Mapped[str] = mapped_column(nullable=False)
    #: This member's own lineage edge (None for a fresh member). The
    #: composite's parent set is the union across members.
    parent_digest: Mapped[str | None] = mapped_column(nullable=True)
    patch: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False, default=dict)
    declared_executables: Mapped[list[object]] = mapped_column(JSONB, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint("position >= 0", name="ck_proposal_members_position_nonnegative"),
        CheckConstraint(
            "parent_digest IS NULL OR parent_digest <> member_digest",
            name="ck_proposal_members_no_self_parent",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "proposal_id"],
            ["proposal_records.tenant_id", "proposal_records.proposal_id"],
            name="fk_proposal_members_proposal",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "member_digest"],
            ["artifact_content.tenant_id", "artifact_content.digest"],
            name="fk_proposal_members_member_artifact",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "parent_digest"],
            ["artifact_content.tenant_id", "artifact_content.digest"],
            name="fk_proposal_members_parent_artifact",
        ),
        UniqueConstraint(
            "tenant_id", "proposal_id", "position", name="uq_proposal_members_position"
        ),
        Index("ix_proposal_members_tenant_id", "tenant_id"),
        Index("ix_proposal_members_member_digest", "tenant_id", "member_digest"),
        Index("ix_proposal_members_proposal_id", "tenant_id", "proposal_id"),
    )


class EvaluationAttestation(Base):
    """A signed evaluation outcome for an artifact.

    The signature covers the canonical JSON of the attestation body
    (artifact digest, evaluator subject, outcome, metrics, evaluation
    payload digest) — the signature and public key columns themselves are
    excluded, exactly as ArtifactContent excludes its signature from the
    digested body. Canonical result bytes live in the payload store under
    `evaluation_payload_digest`.
    """

    __tablename__ = "evaluation_attestations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(nullable=False)
    attestation_id: Mapped[str] = mapped_column(nullable=False, unique=True)
    artifact_digest: Mapped[str] = mapped_column(nullable=False)
    evaluator_subject: Mapped[str] = mapped_column(nullable=False)
    outcome: Mapped[str] = mapped_column(nullable=False)
    result_metrics: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False, default=dict)
    evaluation_payload_digest: Mapped[str] = mapped_column(nullable=False)
    signature: Mapped[bytes] = mapped_column(nullable=False)
    signer_public_key: Mapped[bytes] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "artifact_digest"],
            ["artifact_content.tenant_id", "artifact_content.digest"],
            name="fk_evaluation_attestations_artifact",
        ),
        CheckConstraint("outcome IN ('pass', 'fail')", name="ck_evaluation_attestations_outcome"),
        Index("ix_evaluation_attestations_tenant_artifact", "tenant_id", "artifact_digest"),
    )


class ArtifactStatusEvent(Base):
    """One transition in an artifact's lifecycle. Append-only: the current
    status is derived by the `artifact_current_status` projection view, never
    stored back onto the artifact or the event.
    """

    __tablename__ = "artifact_status_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(nullable=False)
    event_id: Mapped[str] = mapped_column(nullable=False, unique=True)
    artifact_digest: Mapped[str] = mapped_column(nullable=False)
    kind: Mapped[str] = mapped_column(nullable=False)
    actor_identity: Mapped[str] = mapped_column(nullable=False)
    reason: Mapped[str | None] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint(_KIND_CHECK_SQL, name="ck_artifact_status_events_kind"),
        ForeignKeyConstraint(
            ["tenant_id", "artifact_digest"],
            ["artifact_content.tenant_id", "artifact_content.digest"],
            name="fk_artifact_status_events_artifact",
        ),
        Index("ix_artifact_status_events_tenant_artifact", "tenant_id", "artifact_digest"),
    )


class ReleaseManifest(Base):
    """A signed, fully resolved release: every artifact digest it activates,
    the adapter versions, model routes, and policies in force, and the prior
    release it supersedes. Signed over the canonical JSON of that body; the
    signature, public key, and storage URI are excluded from the signed
    bytes. Activation/rollback CAS on this record is the release
    controller's job (E5); this table is the signed unit it acts on.
    """

    __tablename__ = "release_manifests"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(nullable=False)
    manifest_id: Mapped[str] = mapped_column(nullable=False, unique=True)
    manifest_digest: Mapped[str] = mapped_column(nullable=False)
    artifact_digests: Mapped[list[object]] = mapped_column(JSONB, nullable=False, default=list)
    adapter_versions: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False, default=dict)
    model_routes: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False, default=dict)
    policies: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False, default=dict)
    prior_release_digest: Mapped[str | None] = mapped_column(nullable=True)
    storage_uri: Mapped[str] = mapped_column(nullable=False)
    signature: Mapped[bytes] = mapped_column(nullable=False)
    signer_public_key: Mapped[bytes] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("tenant_id", "manifest_digest", name="uq_release_manifests_tenant_digest"),
        CheckConstraint(
            "prior_release_digest IS NULL OR prior_release_digest <> manifest_digest",
            name="ck_release_manifests_no_self_prior",
        ),
        Index("ix_release_manifests_tenant_id", "tenant_id"),
    )

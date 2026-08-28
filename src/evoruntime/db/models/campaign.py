"""ORM models for the FR-014 control-plane records (deliverable E9).

These tables are the *campaign-facing* projection the API and dashboard
serve; the immutable evidence they surface lives in the E1 registry tables
(artifacts, proposals, attestations, status events, release manifests).
One new append-only table, `campaign_transitions`, mirrors the E3
orchestrator's persisted transition log: a campaign whose history could be
edited is not reconstructible, so the same `BEFORE UPDATE OR DELETE`
trigger the registry migration installs guards it.

`release_activations` is deliberately minimal: the release controller (E5)
owns activation CAS, and until it lands this table is the rollback-status
ledger FR-014 needs — which manifest went canary, which was promoted, and
which prior release a rollback restored. It records outcomes; it does not
decide them.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    Integer,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from evoruntime.db.base import Base

#: Activation states a release can move through without the E5 controller.
#: `canary` and `active` are set by the API's release endpoints; `rolled_back`
#: and `superseded` are what a rollback / later promotion leaves behind.
ACTIVATION_STATUSES = ("canary", "active", "rolled_back", "superseded")

_ACTIVATION_CHECK_SQL = "status IN ('canary', 'active', 'rolled_back', 'superseded')"


class CampaignRecord(Base):
    """A campaign created through the FR-014 API.

    `spec_canonical` holds the spec's canonical JSON mapping and
    `spec_signature` the evaluator's detached signature over those bytes,
    so every later reconstruction re-verifies the original pin (the E3
    machine refuses to run anything whose digest or signature no longer
    checks out). `phase` is the current lifecycle phase — a projection of
    the transition log, kept here so reads do not replay history.
    """

    __tablename__ = "campaigns"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(nullable=False)
    campaign_id: Mapped[str] = mapped_column(nullable=False, unique=True)
    name: Mapped[str] = mapped_column(nullable=False)
    spec_digest: Mapped[str] = mapped_column(nullable=False)
    spec_canonical: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    spec_signature: Mapped[bytes] = mapped_column(nullable=False)
    signer_public_key: Mapped[bytes] = mapped_column(nullable=False)
    phase: Mapped[str] = mapped_column(nullable=False)
    resume_target: Mapped[str | None] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("tenant_id", "campaign_id", name="uq_campaigns_tenant_campaign_id"),
        Index("ix_campaigns_tenant_id", "tenant_id"),
    )


class CampaignTransitionRecord(Base):
    """One persisted lifecycle transition, append-only.

    `sequence` is gapless per campaign (the E3 machine's contract); the
    unique constraint makes a double-append of the same sequence a
    database error rather than a silent fork of history.
    """

    __tablename__ = "campaign_transitions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(nullable=False)
    campaign_id: Mapped[str] = mapped_column(nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    from_phase: Mapped[str] = mapped_column(nullable=False)
    to_phase: Mapped[str] = mapped_column(nullable=False)
    reason: Mapped[str] = mapped_column(nullable=False, default="")
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "campaign_id", "sequence", name="uq_campaign_transitions_sequence"
        ),
        ForeignKeyConstraint(
            ["tenant_id", "campaign_id"],
            ["campaigns.tenant_id", "campaigns.campaign_id"],
            name="fk_campaign_transitions_campaign",
        ),
        Index("ix_campaign_transitions_tenant_campaign", "tenant_id", "campaign_id"),
    )


class AgentRegistration(Base):
    """A registered agent plugin (the `evo agent register` golden path).

    Registration is a directory record, not an admission verdict — E2's
    admission gates still apply when the plugin's manifest is actually
    loaded. This row exists so campaigns and the dashboard can name the
    agents a deployment runs without re-reading manifests.
    """

    __tablename__ = "agent_registrations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(nullable=False)
    agent_id: Mapped[str] = mapped_column(nullable=False, unique=True)
    plugin_id: Mapped[str] = mapped_column(nullable=False)
    kind: Mapped[str] = mapped_column(nullable=False)
    pinned_image: Mapped[str] = mapped_column(nullable=False)
    artifact_types: Mapped[list[object]] = mapped_column(JSONB, nullable=False, default=list)
    registered_by: Mapped[str] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("tenant_id", "agent_id", name="uq_agent_registrations_tenant_agent_id"),
        CheckConstraint("kind IN ('strategy', 'adapter')", name="ck_agent_registrations_kind"),
        Index("ix_agent_registrations_tenant_id", "tenant_id"),
    )


class ReleaseActivation(Base):
    """The activation/rollback ledger FR-014's rollback status reads.

    One row per activation event; the current state of a manifest is its
    latest row. The signed manifest itself stays immutable in E1's
    `release_manifests` — this table only records what the control plane
    did with it.
    """

    __tablename__ = "release_activations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(nullable=False)
    manifest_digest: Mapped[str] = mapped_column(nullable=False)
    status: Mapped[str] = mapped_column(nullable=False)
    prior_manifest_digest: Mapped[str | None] = mapped_column(nullable=True)
    activated_by: Mapped[str] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint(_ACTIVATION_CHECK_SQL, name="ck_release_activations_status"),
        ForeignKeyConstraint(
            ["tenant_id", "manifest_digest"],
            ["release_manifests.tenant_id", "release_manifests.manifest_digest"],
            name="fk_release_activations_manifest",
        ),
        Index("ix_release_activations_tenant_manifest", "tenant_id", "manifest_digest"),
    )


class EvidenceBundleRecord(Base):
    """A redacted evidence bundle (E8's `RedactedEvidenceBundle` shape)
    attached to a campaign and optionally to one candidate artifact.

    Items are stored verbatim: they have already been through DLP
    redaction upstream, and re-parsing them here would create a second,
    weaker redaction path. The API serves them read-only.
    """

    __tablename__ = "evidence_bundles"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(nullable=False)
    bundle_id: Mapped[str] = mapped_column(nullable=False, unique=True)
    campaign_id: Mapped[str | None] = mapped_column(nullable=True)
    artifact_digest: Mapped[str | None] = mapped_column(nullable=True)
    redacted_items: Mapped[list[object]] = mapped_column(JSONB, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("tenant_id", "bundle_id", name="uq_evidence_bundles_tenant_bundle_id"),
        ForeignKeyConstraint(
            ["tenant_id", "artifact_digest"],
            ["artifact_content.tenant_id", "artifact_content.digest"],
            name="fk_evidence_bundles_artifact",
        ),
        Index("ix_evidence_bundles_tenant_campaign", "tenant_id", "campaign_id"),
    )

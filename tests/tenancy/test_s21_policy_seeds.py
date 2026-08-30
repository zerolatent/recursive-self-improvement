"""§21 decisions 5 and 7 — the codified approval-default and retention seeds.

The 2026-08-30 orchestrator ruling fixed the two GA-gating product
decisions as signed policy data, on the principle that production policy
mirrors already-tested behavior — the documents below are the signed
form of what the Phase 2–4 gates already do, so codifying them needs no
new enforcement code beyond the policy-plane primitives these tests
exercise. These tests prove:

- the production seed encodes decision 5 (tier 1–2 auto-eligible
  post-canary, tier 3 two-person review, tier 4 structurally absent);
- the regulated seed encodes the regulated column (no auto-promotion at
  any tier, review for everything, tier 4 still structurally refused);
- the seeds load through the fail-closed registry and their signatures
  verify over the canonical bytes;
- the four-boundary refusal matrix behaves unchanged for production
  tenants governed by the seed documents;
- the auto-promotion boundary refuses a regulated-tenant request with an
  audited ledger row;
- the retention seed pins the decision-7 values and resolves them
  through the D4 knobs the sweeps already consume.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker
from tests.support.factories import make_campaign_spec_mapping

from evoruntime.api.service import CampaignApiService
from evoruntime.campaign.errors import ScaffoldEnvironmentRefusedError
from evoruntime.campaign.spec import CampaignSpec
from evoruntime.core.principal import Principal
from evoruntime.db.models.tenancy import TenantPolicyRefusal
from evoruntime.lineage.backup import BackupAgeOutPolicy
from evoruntime.registry.service import RegistryService
from evoruntime.security.identities import WorkloadIdentity, WorkloadRole
from evoruntime.security.signing import generate_signing_key
from evoruntime.selection.recursive_gate import (
    RECURSIVE_IMPROVEMENT_LABEL,
    RecursiveClaimEvidence,
    evaluate_recursive_claim,
)
from evoruntime.tenancy.audit import (
    AUTO_PROMOTION_REQUIRES_REVIEW,
    RECURSIVE_CLAIMS_RESEARCH_ONLY,
    SCAFFOLD_REQUIRES_RESEARCH,
    RefusalBoundary,
    assert_auto_promotion_allowed,
    assert_recursive_label_allowed,
)
from evoruntime.tenancy.environment import TenantEnvironment
from evoruntime.tenancy.errors import TenantPolicyError, TenantRefusalError
from evoruntime.tenancy.policy import TenantPolicyDocument, TenantPolicyRegistry
from evoruntime.tenancy.retention import (
    BACKUP_CRYPTO_ERASURE_DAYS,
    DERIVED_CRYPTO_ERASURE_SLA_HOURS,
    INDEFINITE_RETENTION_RECORDS,
    PAYLOAD_RETENTION_DAYS,
    SEED_RETENTION_POLICY_ID,
    TRACE_RETENTION_DAYS,
    RetentionPolicyDocument,
    RetentionPolicyError,
    UnsignedRetentionPolicyError,
    backup_age_out_policy,
    derived_erasure_sla_seconds,
    seed_retention_policy,
    sign_retention_policy,
)
from evoruntime.tenancy.seed import (
    SEED_PRODUCTION_POLICY_ID,
    SEED_REGULATED_POLICY_ID,
    UnsignedTenantPolicyError,
    seed_production_tenant_policy,
    seed_regulated_tenant_policy,
    seed_research_tenant_policy,
    sign_tenant_policy,
    verify_tenant_policy,
)

# ----------------------------------------------------------------------
# Fixtures
# ----------------------------------------------------------------------


class Tenants:
    """Fresh, unique tenant ids for one test — refusal rows never collide."""

    def __init__(self) -> None:
        suffix = uuid.uuid4().hex[:8]
        self.research = f"tnt_research_{suffix}"
        self.production = f"tnt_production_{suffix}"
        self.regulated = f"tnt_regulated_{suffix}"
        self.unmapped = f"tnt_unmapped_{suffix}"


@pytest.fixture
def tenants() -> Tenants:
    return Tenants()


def _seed_registry(tenants: Tenants) -> TenantPolicyRegistry:
    """The deployment registry built from the shipped seed documents."""
    return TenantPolicyRegistry(
        [
            seed_research_tenant_policy(tenants.research),
            seed_production_tenant_policy(tenants.production),
            seed_regulated_tenant_policy(tenants.regulated),
        ]
    )


def _principal(tenant_id: str) -> Principal:
    return Principal(
        identity=WorkloadIdentity(role=WorkloadRole.EVALUATOR, subject="svc_evaluator_s21"),
        tenant_id=tenant_id,
    )


@pytest.fixture
def service(
    session_factory: sessionmaker[Session], tenants: Tenants
) -> tuple[CampaignApiService, Tenants]:
    """The control-plane service bound to the seed-document registry."""
    key = generate_signing_key()
    service = CampaignApiService(
        session_factory,
        signing_key=key,
        evaluator_subject="svc_evaluator_s21",
        tenant_policies=_seed_registry(tenants),
    )
    return service, tenants


def _scaffold_spec_mapping(environment: str | None = None) -> dict[str, Any]:
    """A valid spec whose mutable set is scaffold-class (G3/G4/G7 shape)."""
    mapping = make_campaign_spec_mapping()
    mapping["incumbent"]["artifact_type"] = "scaffold"
    mapping["mutable_artifact"]["artifact_type"] = "scaffold"
    mapping["mutation_classes"] = [
        {
            "class_id": "prompt_module_edit",
            "risk_dossier_digest": "sha256:" + "a" * 64,
            "max_tier": "executable",
        },
    ]
    mapping["arms"] = [
        *mapping["arms"],
        {"id": "fixed-editor", "kind": "fixed-editor", "editor_ref": "evo-prompt-strategist@gen-0"},
    ]
    mapping["tier4_policy_digest"] = "sha256:" + "a" * 64
    if environment is not None:
        mapping["environment"] = environment
    else:
        mapping.pop("environment", None)
    return mapping


def _register_scaffold_artifact(session_factory: sessionmaker[Session], tenant_id: str) -> str:
    """Register a scaffold artifact directly through the registry (the
    registry is class-agnostic; the tenancy boundary is the API service)."""
    with session_factory() as session:
        registry = RegistryService(session)
        artifact = registry.register_artifact(
            tenant_id=tenant_id,
            artifact_type="scaffold",
            canonical_bytes=b"scaffold candidate body (s21 fixture)",
        )
        session.commit()
        return artifact.digest


# ----------------------------------------------------------------------
# Decision 5 — the production seed's approval defaults
# ----------------------------------------------------------------------


def test_production_seed_encodes_decision_5() -> None:
    document = seed_production_tenant_policy("tnt_production_x")
    assert document.policy_id == SEED_PRODUCTION_POLICY_ID
    assert document.environment is TenantEnvironment.PRODUCTION
    # Tier 1–2: auto-eligible for promotion after canary.
    assert document.auto_eligible(1)
    assert document.auto_eligible(2)
    # Tier 3: approvable, but only through two-person review-board approval.
    assert document.allows_tier(3)
    assert not document.auto_eligible(3)
    assert document.requires_two_person_review(3)
    # Tier 4: structurally absent — research-tenant-only until G10 graduation.
    assert not document.allows_tier(4)
    assert not document.auto_eligible(4)
    assert document.policy_version == 2


def test_regulated_seed_encodes_the_regulated_column() -> None:
    document = seed_regulated_tenant_policy("tnt_regulated_x")
    assert document.policy_id == SEED_REGULATED_POLICY_ID
    # Still a production-environment tenant: the fail-closed rules apply.
    assert document.environment is TenantEnvironment.PRODUCTION
    # No auto-promotion at any tier; review for everything approvable.
    for tier in (1, 2, 3):
        assert document.allows_tier(tier)
        assert not document.auto_eligible(tier)
        assert document.requires_two_person_review(tier)
    # Tier 4 is structurally refused exactly as in the production seed.
    assert not document.allows_tier(4)
    assert not document.auto_eligible(4)


def test_incoherent_approval_defaults_are_refused() -> None:
    with pytest.raises(TenantPolicyError, match=">= 0"):
        TenantPolicyDocument(
            tenant_id="tnt_x",
            policy_id="pol-neg",
            environment=TenantEnvironment.PRODUCTION,
            auto_promotion_max_tier=-1,
        )
    with pytest.raises(TenantPolicyError, match="cannot auto-promote a tier"):
        TenantPolicyDocument(
            tenant_id="tnt_x",
            policy_id="pol-over",
            environment=TenantEnvironment.PRODUCTION,
            allowed_authority_tiers=(1, 2),
            auto_promotion_max_tier=3,
        )
    with pytest.raises(TenantPolicyError, match="incoherent"):
        TenantPolicyDocument(
            tenant_id="tnt_x",
            policy_id="pol-review-all",
            environment=TenantEnvironment.PRODUCTION,
            require_review_for_all_tiers=True,
            auto_promotion_max_tier=2,
        )
    with pytest.raises(TenantPolicyError, match="tier 4"):
        TenantPolicyDocument(
            tenant_id="tnt_x",
            policy_id="pol-auto4",
            environment=TenantEnvironment.PRODUCTION,
            allowed_authority_tiers=(1, 2, 3, 4),
            auto_promotion_max_tier=4,
        )


def test_seeds_load_through_the_fail_closed_registry(tenants: Tenants) -> None:
    registry = _seed_registry(tenants)
    assert registry.policy_for(tenants.research) is not None
    assert registry.policy_for(tenants.production) is not None
    assert registry.policy_for(tenants.regulated) is not None
    # Fail closed: an unmapped tenant resolves to production.
    assert registry.environment_for(tenants.unmapped) is TenantEnvironment.PRODUCTION


def test_seed_signatures_verify() -> None:
    key = generate_signing_key()
    for seed in (
        seed_research_tenant_policy("tnt_research_x"),
        seed_production_tenant_policy("tnt_production_x"),
        seed_regulated_tenant_policy("tnt_regulated_x"),
    ):
        verify_tenant_policy(sign_tenant_policy(seed, key))


def test_tampered_regulated_seed_is_refused() -> None:
    key = generate_signing_key()
    document = seed_regulated_tenant_policy("tnt_regulated_x")
    signed = sign_tenant_policy(document, key)
    document.auto_promotion_max_tier = 2  # tamper after signing
    with pytest.raises(UnsignedTenantPolicyError):
        verify_tenant_policy(signed)


# ----------------------------------------------------------------------
# The auto-promotion boundary (decision 5, audited)
# ----------------------------------------------------------------------


def test_regulated_auto_promotion_request_is_refused_and_audited(
    session_factory: sessionmaker[Session], tenants: Tenants
) -> None:
    """The §21 acceptance criterion: a regulated tenant's auto-promotion
    request is refused, and the refusal lands in the append-only ledger."""
    with session_factory() as session:
        with pytest.raises(TenantRefusalError, match="two-person review"):
            assert_auto_promotion_allowed(
                session,
                tenant_id=tenants.regulated,
                policies=_seed_registry(tenants),
                tier=1,
                actor="svc_evaluator_s21",
            )
        session.commit()
    with session_factory() as session:
        rows = list(
            session.scalars(
                select(TenantPolicyRefusal).where(
                    TenantPolicyRefusal.tenant_id == tenants.regulated
                )
            )
        )
    assert len(rows) == 1
    assert rows[0].boundary == RefusalBoundary.AUTO_PROMOTION
    assert rows[0].reason == AUTO_PROMOTION_REQUIRES_REVIEW
    assert rows[0].detail["tier"] == 1


def test_production_tier3_auto_promotion_is_review_gated_and_audited(
    session_factory: sessionmaker[Session], tenants: Tenants
) -> None:
    """Decision 5's production column: tier 3 never auto-promotes."""
    with session_factory() as session:
        with pytest.raises(TenantRefusalError, match="two-person review"):
            assert_auto_promotion_allowed(
                session,
                tenant_id=tenants.production,
                policies=_seed_registry(tenants),
                tier=3,
            )
        session.commit()
    with session_factory() as session:
        rows = list(
            session.scalars(
                select(TenantPolicyRefusal).where(
                    TenantPolicyRefusal.tenant_id == tenants.production
                )
            )
        )
    assert len(rows) == 1
    assert rows[0].boundary == RefusalBoundary.AUTO_PROMOTION


def test_production_tier1_and_2_auto_promotion_passes_without_a_refusal(
    session_factory: sessionmaker[Session], tenants: Tenants
) -> None:
    """The production seed mirrors the already-tested behavior: tier 1–2
    promotions after canary need no review board."""
    with session_factory() as session:
        assert_auto_promotion_allowed(
            session,
            tenant_id=tenants.production,
            policies=_seed_registry(tenants),
            tier=1,
        )
        assert_auto_promotion_allowed(
            session,
            tenant_id=tenants.production,
            policies=_seed_registry(tenants),
            tier=2,
        )
        session.commit()
    with session_factory() as session:
        rows = list(
            session.scalars(
                select(TenantPolicyRefusal).where(
                    TenantPolicyRefusal.tenant_id == tenants.production
                )
            )
        )
    assert rows == []


def test_unmapped_tenant_auto_promotion_fails_closed_to_the_production_default(
    session_factory: sessionmaker[Session], tenants: Tenants
) -> None:
    """No document means the production default shape — tier 1–2 auto,
    tier 3+ review — the same answer environment_for gives."""
    with session_factory() as session:
        assert_auto_promotion_allowed(
            session,
            tenant_id=tenants.unmapped,
            policies=TenantPolicyRegistry(),
            tier=1,
        )
        with pytest.raises(TenantRefusalError):
            assert_auto_promotion_allowed(
                session,
                tenant_id=tenants.unmapped,
                policies=TenantPolicyRegistry(),
                tier=3,
            )
        session.commit()


# ----------------------------------------------------------------------
# The four-boundary matrix, unchanged for production tenants
# ----------------------------------------------------------------------


def test_boundary1_scaffold_spec_declaring_production_is_refused_at_construction() -> None:
    with pytest.raises(ScaffoldEnvironmentRefusedError):
        CampaignSpec.from_mapping(_scaffold_spec_mapping("production"))


def test_boundary2_scaffold_campaign_in_production_seed_tenant_is_refused_and_audited(
    service: tuple[CampaignApiService, Tenants],
    session_factory: sessionmaker[Session],
) -> None:
    svc, ts = service
    with pytest.raises(TenantRefusalError, match="research"):
        svc.create_campaign(_principal(ts.production), _scaffold_spec_mapping("research"))
    with session_factory() as session:
        rows = list(
            session.scalars(
                select(TenantPolicyRefusal).where(TenantPolicyRefusal.tenant_id == ts.production)
            )
        )
    assert len(rows) == 1
    assert rows[0].boundary == RefusalBoundary.CAMPAIGN_CREATION
    assert rows[0].reason == SCAFFOLD_REQUIRES_RESEARCH


def test_boundary2_scaffold_candidate_in_production_seed_tenant_is_refused_and_audited(
    service: tuple[CampaignApiService, Tenants],
    session_factory: sessionmaker[Session],
) -> None:
    svc, ts = service
    with pytest.raises(TenantRefusalError, match="research"):
        svc.register_candidate(
            _principal(ts.production),
            artifact_type="scaffold",
            canonical_bytes_b64="c2NhZmZvbGQgY2FuZGlkYXRlIGJvZHk=",
            strategy_id="strat-s21",
        )
    with session_factory() as session:
        rows = list(
            session.scalars(
                select(TenantPolicyRefusal).where(TenantPolicyRefusal.tenant_id == ts.production)
            )
        )
    assert len(rows) == 1
    assert rows[0].boundary == RefusalBoundary.CANDIDATE_REGISTRATION


def test_boundary3_scaffold_release_in_production_seed_tenant_is_refused_and_audited(
    service: tuple[CampaignApiService, Tenants],
    session_factory: sessionmaker[Session],
) -> None:
    svc, ts = service
    digest = _register_scaffold_artifact(session_factory, ts.production)
    with pytest.raises(TenantRefusalError, match="research"):
        svc.create_release(
            _principal(ts.production),
            artifact_digests=[digest],
            adapter_versions={},
            model_routes={},
            policies={},
            status="canary",
        )
    with session_factory() as session:
        rows = list(
            session.scalars(
                select(TenantPolicyRefusal).where(TenantPolicyRefusal.tenant_id == ts.production)
            )
        )
    assert len(rows) == 1
    assert rows[0].boundary == RefusalBoundary.RELEASE_ACTIVATION


def test_boundary4_recursive_label_in_production_seed_tenant_is_refused_and_audited(
    service: tuple[CampaignApiService, Tenants],
    session_factory: sessionmaker[Session],
) -> None:
    svc, ts = service
    verdict = evaluate_recursive_claim(
        RecursiveClaimEvidence(
            successive_promoted_generations=True,
            shared_error_budget=True,
            causal_inheritance=True,
            matched_compute_one_shot_advantage=True,
            no_inheritance_control_arm=True,
            fixed_editor_control_arm=True,
            fixed_editor_advantage=0.08,
            fixed_editor_minimum_effect=0.05,
            fixed_editor_holm_significant=True,
        )
    )
    with session_factory() as session:
        with pytest.raises(TenantRefusalError, match="research"):
            assert_recursive_label_allowed(
                session,
                tenant_id=ts.production,
                policies=_seed_registry(ts),
                label=RECURSIVE_IMPROVEMENT_LABEL,
                verdict=verdict,
                actor="svc_evaluator_s21",
            )
        session.commit()
    with session_factory() as session:
        rows = list(
            session.scalars(
                select(TenantPolicyRefusal).where(TenantPolicyRefusal.tenant_id == ts.production)
            )
        )
    assert len(rows) == 1
    assert rows[0].boundary == RefusalBoundary.RECURSIVE_LABEL
    assert rows[0].reason == RECURSIVE_CLAIMS_RESEARCH_ONLY


# ----------------------------------------------------------------------
# Decision 7 — the retention policy
# ----------------------------------------------------------------------


def test_retention_seed_encodes_decision_7() -> None:
    document = seed_retention_policy("tnt_retention_x")
    assert document.policy_id == SEED_RETENTION_POLICY_ID
    assert document.trace_retention_days == TRACE_RETENTION_DAYS == 90
    assert document.payload_retention_days == PAYLOAD_RETENTION_DAYS == 30
    assert document.payload_retention_follows_lineage
    assert document.derived_crypto_erasure_sla_hours == DERIVED_CRYPTO_ERASURE_SLA_HOURS == 24
    assert document.backup_crypto_erasure_days == BACKUP_CRYPTO_ERASURE_DAYS == 30
    # The evidence substrate is never purgeable.
    assert document.indefinite_retention_records >= INDEFINITE_RETENTION_RECORDS
    assert {
        "evaluation_attestations",
        "admission_records",
        "ledger_rows",
        "tombstones",
    } == set(INDEFINITE_RETENTION_RECORDS)


def test_payload_retention_follows_lineage_when_referenced() -> None:
    document = seed_retention_policy("tnt_retention_x")
    assert document.payload_retention_days_for(lineage_referenced=False) == 30
    # None = no independent deadline; retention follows the lineage node.
    assert document.payload_retention_days_for(lineage_referenced=True) is None


def test_retention_signature_verifies_and_tampering_is_refused() -> None:
    key = generate_signing_key()
    document = seed_retention_policy("tnt_retention_x")
    signed = sign_retention_policy(document, key)
    signed.verify()
    document.trace_retention_days = 1  # tamper after signing
    with pytest.raises(UnsignedRetentionPolicyError):
        signed.verify()


def test_retention_document_purging_the_evidence_substrate_is_refused() -> None:
    with pytest.raises(RetentionPolicyError, match="never purgeable"):
        RetentionPolicyDocument(
            tenant_id="tnt_retention_x",
            indefinite_retention_records=frozenset({"evaluation_attestations"}),
        )


def test_derived_erasure_slo_resolves_through_the_d4_knob() -> None:
    """The document declares 24h; the sweep's knob resolves to the same
    number — one value, two surfaces."""
    assert derived_erasure_sla_seconds() == 24 * 3600


def test_backup_age_out_resolves_to_the_decision7_deadline() -> None:
    policy = backup_age_out_policy()
    assert isinstance(policy, BackupAgeOutPolicy)
    assert policy.backup_age_out_days == 30
    deleted_at = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    assert policy.deadline_for("backup", deleted_at) == deleted_at + timedelta(days=30)
    # The primary tier keeps its §17.3 row-3 window.
    assert policy.primary_age_out_days == 7
    assert policy.deadline_for("primary", deleted_at) == deleted_at + timedelta(days=7)

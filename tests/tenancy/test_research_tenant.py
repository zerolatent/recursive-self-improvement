"""G6 — research-tenant isolation: the four-boundary refusal matrix.

Scaffold mutation exists only in the research environment. These tests
prove the boundary checks compose: a scaffold-mutable spec is refused at
construction unless it pins ``environment: research`` (boundary 1), a
scaffold campaign or candidate is refused in a production tenant
(boundary 2), a release whose resolved set contains a scaffold artifact
neither activates nor promotes outside research (boundary 3), and the
recursive-improvement label is research-only (boundary 4). Every refusal
path leaves a row in the append-only ``tenant_policy_refusals`` ledger —
an audit trail of successes only is not an audit trail.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker
from tests.support.factories import make_campaign_spec_mapping

from evoruntime.api.service import CampaignApiService
from evoruntime.campaign.errors import (
    InvalidCampaignSpecError,
    ScaffoldEnvironmentRefusedError,
)
from evoruntime.campaign.spec import CampaignSpec
from evoruntime.core.principal import Principal
from evoruntime.db.models.campaign import ReleaseActivation
from evoruntime.db.models.tenancy import TenantPolicyRefusal
from evoruntime.registry.service import RegistryService
from evoruntime.security.identities import WorkloadIdentity, WorkloadRole
from evoruntime.security.signing import generate_signing_key
from evoruntime.selection.errors import RecursiveClaimDeniedError
from evoruntime.selection.recursive_gate import (
    RECURSIVE_IMPROVEMENT_LABEL,
    RecursiveClaimEvidence,
    assert_label_allowed,
    claim_label,
    evaluate_recursive_claim,
)
from evoruntime.tenancy.audit import (
    RECURSIVE_CLAIMS_RESEARCH_ONLY,
    SCAFFOLD_REQUIRES_RESEARCH,
    RefusalBoundary,
    assert_recursive_label_allowed,
)
from evoruntime.tenancy.environment import TenantEnvironment
from evoruntime.tenancy.errors import TenantPolicyError, TenantRefusalError
from evoruntime.tenancy.policy import TenantPolicyDocument, TenantPolicyRegistry


class Tenants:
    """Fresh, unique tenant ids for one test — refusal rows never collide."""

    def __init__(self) -> None:
        suffix = uuid.uuid4().hex[:8]
        self.research = f"tnt_research_{suffix}"
        self.production = f"tnt_production_{suffix}"
        self.unmapped = f"tnt_unmapped_{suffix}"


@pytest.fixture
def tenants() -> Tenants:
    return Tenants()


def _policy_registry(tenants: Tenants) -> TenantPolicyRegistry:
    """One research tenant, one production tenant — and nothing else.

    The unmapped tenant is the fail-closed case: no document means
    production, so scaffold mutation is refused there too.
    """
    return TenantPolicyRegistry(
        [
            TenantPolicyDocument(
                tenant_id=tenants.research,
                policy_id=f"pol-research-{tenants.research}",
                environment=TenantEnvironment.RESEARCH,
                allowed_authority_tiers=(1, 2, 3, 4),
                recursive_claims_enabled=True,
            ),
            TenantPolicyDocument(
                tenant_id=tenants.production,
                policy_id=f"pol-production-{tenants.production}",
                environment=TenantEnvironment.PRODUCTION,
                allowed_authority_tiers=(1, 2, 3),
            ),
        ]
    )


def _scaffold_spec_mapping(environment: str | None = None) -> dict[str, Any]:
    """A valid spec whose mutable set is scaffold-class.

    G3 requires a scaffold-mutable spec to pin its mutation classes, so
    the helper carries a minimal valid `mutation_classes` section.
    G7: a scaffold spec must pin the digest of the tier-4-allowing seed
    policy its promotions are governed by, so the pin is part of the
    fixture (a well-formed digest; which policy it names is a
    deployment-level fact, not a spec-construction one).
    """
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
    # G4: a scaffold-mutable campaign must carry exactly one fixed-editor
    # arm — the incumbent scaffold evaluated under the frozen editor.
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


def _refusals(session: Session, tenant_id: str) -> list[TenantPolicyRefusal]:
    return list(
        session.scalars(
            select(TenantPolicyRefusal)
            .where(TenantPolicyRefusal.tenant_id == tenant_id)
            .order_by(TenantPolicyRefusal.occurred_at)
        )
    )


def _principal(tenant_id: str) -> Principal:
    return Principal(
        identity=WorkloadIdentity(role=WorkloadRole.EVALUATOR, subject="svc_evaluator_g6"),
        tenant_id=tenant_id,
    )


# ----------------------------------------------------------------------
# Boundary 1 — spec construction: scaffold ⇒ research
# ----------------------------------------------------------------------


def test_scaffold_spec_without_environment_is_refused_at_construction() -> None:
    """An unspecified environment is not research by default — refused."""
    with pytest.raises(ScaffoldEnvironmentRefusedError):
        CampaignSpec.from_mapping(_scaffold_spec_mapping())


def test_scaffold_spec_declaring_production_is_refused_at_construction() -> None:
    with pytest.raises(ScaffoldEnvironmentRefusedError):
        CampaignSpec.from_mapping(_scaffold_spec_mapping("production"))


def test_scaffold_spec_declaring_research_constructs() -> None:
    spec = CampaignSpec.from_mapping(_scaffold_spec_mapping("research"))
    assert spec.environment == "research"
    assert spec.has_scaffold_mutable


def test_non_scaffold_spec_constructs_without_environment() -> None:
    """Pre-G6 specs (no environment field) keep constructing unchanged."""
    spec = CampaignSpec.from_mapping(make_campaign_spec_mapping())
    assert spec.environment is None
    assert not spec.has_scaffold_mutable


def test_environment_field_is_always_in_the_canonical_form() -> None:
    """G3 diverges from G6's omit-when-unset convention on purpose: the
    environment claim is always serialized (null for pre-G6 documents)
    so the digest binds the claim — a spec whose environment claim
    changed after pinning no longer verifies."""
    mapping = make_campaign_spec_mapping()
    canonical = CampaignSpec.from_mapping(mapping).to_canonical_dict()
    assert "environment" in canonical
    assert canonical["environment"] is None


def test_invalid_environment_value_is_refused() -> None:
    mapping = make_campaign_spec_mapping()
    mapping["environment"] = "staging"
    with pytest.raises(InvalidCampaignSpecError, match="environment"):
        CampaignSpec.from_mapping(mapping)


# ----------------------------------------------------------------------
# Boundary 2 — campaign creation / candidate registration
# ----------------------------------------------------------------------


@pytest.fixture
def service(
    session_factory: sessionmaker[Session], tenants: Tenants
) -> tuple[CampaignApiService, Ed25519PrivateKey, Tenants]:
    """The control-plane service bound to this test's policy registry."""
    key = generate_signing_key()
    service = CampaignApiService(
        session_factory,
        signing_key=key,
        evaluator_subject="svc_evaluator_g6",
        tenant_policies=_policy_registry(tenants),
    )
    return service, key, tenants


def test_scaffold_campaign_in_production_tenant_is_refused_and_audited(
    service: tuple[CampaignApiService, Ed25519PrivateKey, Tenants],
    session_factory: sessionmaker[Session],
) -> None:
    """Boundary 2a: the scaffold spec pins research; the tenant is not."""
    svc, _, ts = service
    with pytest.raises(TenantRefusalError, match="research"):
        svc.create_campaign(_principal(ts.production), _scaffold_spec_mapping("research"))
    with session_factory() as session:
        rows = _refusals(session, ts.production)
    assert len(rows) == 1
    assert rows[0].boundary == RefusalBoundary.CAMPAIGN_CREATION
    assert rows[0].reason == SCAFFOLD_REQUIRES_RESEARCH


def test_scaffold_campaign_in_unmapped_tenant_is_refused_and_audited(
    service: tuple[CampaignApiService, Ed25519PrivateKey, Tenants],
    session_factory: sessionmaker[Session],
) -> None:
    """Fail closed: no policy document means production."""
    svc, _, ts = service
    with pytest.raises(TenantRefusalError, match="research"):
        svc.create_campaign(_principal(ts.unmapped), _scaffold_spec_mapping("research"))
    with session_factory() as session:
        rows = _refusals(session, ts.unmapped)
    assert len(rows) == 1
    assert rows[0].boundary == RefusalBoundary.CAMPAIGN_CREATION


def test_scaffold_campaign_in_research_tenant_is_created(
    service: tuple[CampaignApiService, Ed25519PrivateKey, Tenants],
    session_factory: sessionmaker[Session],
) -> None:
    svc, _, ts = service
    detail = svc.create_campaign(_principal(ts.research), _scaffold_spec_mapping("research"))
    assert detail.name == "prompt-bundle-campaign-1"
    with session_factory() as session:
        assert _refusals(session, ts.research) == []


def test_scaffold_spec_refusal_at_construction_is_audited_by_the_control_plane(
    service: tuple[CampaignApiService, Ed25519PrivateKey, Tenants],
    session_factory: sessionmaker[Session],
) -> None:
    """Boundary 1's audit: the pure spec constructor has no session, so the
    service records the spec_construction refusal before re-raising."""
    svc, _, ts = service
    with pytest.raises(Exception, match="invalid"):
        svc.create_campaign(_principal(ts.production), _scaffold_spec_mapping())
    with session_factory() as session:
        rows = _refusals(session, ts.production)
    assert len(rows) == 1
    assert rows[0].boundary == RefusalBoundary.SPEC_CONSTRUCTION


def test_scaffold_candidate_in_production_tenant_is_refused_and_audited(
    service: tuple[CampaignApiService, Ed25519PrivateKey, Tenants],
    session_factory: sessionmaker[Session],
) -> None:
    """Boundary 2b — candidate registration."""
    svc, _, ts = service
    with pytest.raises(TenantRefusalError, match="research"):
        svc.register_candidate(
            _principal(ts.production),
            artifact_type="scaffold",
            canonical_bytes_b64="c2NhZmZvbGQgY2FuZGlkYXRlIGJvZHk=",
            strategy_id="strat-g6",
        )
    with session_factory() as session:
        rows = _refusals(session, ts.production)
    assert len(rows) == 1
    assert rows[0].boundary == RefusalBoundary.CANDIDATE_REGISTRATION


def test_scaffold_candidate_in_research_tenant_registers(
    service: tuple[CampaignApiService, Ed25519PrivateKey, Tenants],
    session_factory: sessionmaker[Session],
) -> None:
    svc, _, ts = service
    view = svc.register_candidate(
        _principal(ts.research),
        artifact_type="scaffold",
        canonical_bytes_b64="c2NhZmZvbGQgY2FuZGlkYXRlIGJvZHk=",
        strategy_id="strat-g6",
    )
    assert view.artifact_digest.startswith("sha256:")
    with session_factory() as session:
        assert _refusals(session, ts.research) == []


# ----------------------------------------------------------------------
# Boundary 3 — release activation (create and promote paths)
# ----------------------------------------------------------------------


def _register_scaffold_artifact(session_factory: sessionmaker[Session], tenant_id: str) -> str:
    """Register a scaffold artifact directly through the registry (the
    registry is class-agnostic; the tenancy boundary is the API service)."""
    with session_factory() as session:
        registry = RegistryService(session)
        artifact = registry.register_artifact(
            tenant_id=tenant_id,
            artifact_type="scaffold",
            canonical_bytes=b"scaffold candidate body (g6 fixture)",
        )
        session.commit()
        return artifact.digest


def test_scaffold_release_in_production_tenant_is_refused_and_audited(
    service: tuple[CampaignApiService, Ed25519PrivateKey, Tenants],
    session_factory: sessionmaker[Session],
) -> None:
    """Boundary 3a — a resolved set containing scaffold never activates."""
    svc, _, ts = service
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
        rows = _refusals(session, ts.production)
    assert len(rows) == 1
    assert rows[0].boundary == RefusalBoundary.RELEASE_ACTIVATION


def test_scaffold_release_in_research_tenant_activates_and_promotes(
    service: tuple[CampaignApiService, Ed25519PrivateKey, Tenants],
    session_factory: sessionmaker[Session],
) -> None:
    """The acceptance path: scaffold campaigns run and promote in research."""
    svc, _, ts = service
    digest = _register_scaffold_artifact(session_factory, ts.research)
    view = svc.create_release(
        _principal(ts.research),
        artifact_digests=[digest],
        adapter_versions={},
        model_routes={},
        policies={},
        status="canary",
    )
    assert view.status == "canary"
    promoted = svc.promote_release(_principal(ts.research), view.manifest_digest)
    assert promoted.status == "active"
    with session_factory() as session:
        assert _refusals(session, ts.research) == []


def test_scaffold_release_promotion_in_production_tenant_is_refused_and_audited(
    service: tuple[CampaignApiService, Ed25519PrivateKey, Tenants],
    session_factory: sessionmaker[Session],
) -> None:
    """Boundary 3, promote path: a canary release containing scaffold that
    reached the ledger before the policy did cannot be promoted to active."""
    svc, key, ts = service
    digest = _register_scaffold_artifact(session_factory, ts.production)
    with session_factory() as session:
        registry = RegistryService(session)
        manifest = registry.create_release_manifest(
            tenant_id=ts.production,
            artifact_digests=[digest],
            adapter_versions={},
            model_routes={},
            policies={},
            prior_release_digest=None,
            private_key=key,
        )
        session.add(
            ReleaseActivation(
                tenant_id=ts.production,
                manifest_digest=manifest.manifest_digest,
                status="canary",
                prior_manifest_digest=None,
                activated_by="g6-fixture",
            )
        )
        session.commit()
        manifest_digest = manifest.manifest_digest
    with pytest.raises(TenantRefusalError, match="research"):
        svc.promote_release(_principal(ts.production), manifest_digest)
    with session_factory() as session:
        rows = _refusals(session, ts.production)
    assert len(rows) == 1
    assert rows[0].boundary == RefusalBoundary.RELEASE_ACTIVATION


# ----------------------------------------------------------------------
# Boundary 4 — the recursive-label gate
# ----------------------------------------------------------------------


def _satisfied_verdict() -> Any:
    return evaluate_recursive_claim(
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


def _standalone_policy(
    *,
    environment: TenantEnvironment,
    recursive_claims_enabled: bool = False,
) -> TenantPolicyDocument:
    """A one-off policy document for the sessionless label-gate tests."""
    return TenantPolicyDocument(
        tenant_id=f"tnt_label_{uuid.uuid4().hex[:8]}",
        policy_id=f"pol_label_{uuid.uuid4().hex[:8]}",
        environment=environment,
        allowed_authority_tiers=(1, 2, 3, 4)
        if environment is TenantEnvironment.RESEARCH
        else (1, 2, 3),
        recursive_claims_enabled=recursive_claims_enabled,
    )


def test_recursive_label_refused_outside_research() -> None:
    """Boundary 4 — the label is research-only, even with a satisfied gate:
    enablement is the tenant's policy data (G4), and neither a production
    document nor an unmapped tenant carries it."""
    verdict = _satisfied_verdict()
    with pytest.raises(RecursiveClaimDeniedError, match="research-only"):
        assert_label_allowed(
            RECURSIVE_IMPROVEMENT_LABEL,
            verdict,
            tenant_policy=_standalone_policy(environment=TenantEnvironment.PRODUCTION),
        )
    with pytest.raises(RecursiveClaimDeniedError, match="research-only"):
        assert_label_allowed(RECURSIVE_IMPROVEMENT_LABEL, verdict, tenant_policy=None)
    assert_label_allowed(
        RECURSIVE_IMPROVEMENT_LABEL,
        verdict,
        tenant_policy=_standalone_policy(
            environment=TenantEnvironment.RESEARCH, recursive_claims_enabled=True
        ),
    )


def test_recursive_label_claim_requires_research_environment() -> None:
    """`claim_label` answers honestly: production earns the honest label."""
    production = _standalone_policy(environment=TenantEnvironment.PRODUCTION)
    research = _standalone_policy(
        environment=TenantEnvironment.RESEARCH, recursive_claims_enabled=True
    )

    assert claim_label(_satisfied_verdict(), tenant_policy=production) == ("artifact optimization")
    assert claim_label(_satisfied_verdict(), tenant_policy=research) == (
        RECURSIVE_IMPROVEMENT_LABEL
    )


def test_recursive_label_refusal_in_production_tenant_is_audited(
    service: tuple[CampaignApiService, Ed25519PrivateKey, Tenants],
    session_factory: sessionmaker[Session],
) -> None:
    """The audited wrapper records the refusal before raising."""
    svc, _, ts = service
    with session_factory() as session:
        with pytest.raises(TenantRefusalError, match="research"):
            assert_recursive_label_allowed(
                session,
                tenant_id=ts.production,
                policies=_policy_registry(ts),
                label=RECURSIVE_IMPROVEMENT_LABEL,
                verdict=_satisfied_verdict(),
                actor="svc_evaluator_g6",
            )
        session.commit()
    with session_factory() as session:
        rows = _refusals(session, ts.production)
    assert len(rows) == 1
    assert rows[0].boundary == RefusalBoundary.RECURSIVE_LABEL
    assert rows[0].reason == RECURSIVE_CLAIMS_RESEARCH_ONLY


# ----------------------------------------------------------------------
# Per-environment approval defaults
# ----------------------------------------------------------------------


def test_production_policy_cannot_pin_tier_4_defaults(tenants: Tenants) -> None:
    """Tier-4-allowing approval defaults exist only in research policy data."""
    with pytest.raises(TenantPolicyError, match="tier-4"):
        TenantPolicyDocument(
            tenant_id=tenants.production,
            policy_id="pol-prod-tier4",
            environment=TenantEnvironment.PRODUCTION,
            allowed_authority_tiers=(1, 2, 3, 4),
        )


def test_research_policy_may_pin_tier_4_defaults(tenants: Tenants) -> None:
    document = TenantPolicyDocument(
        tenant_id=tenants.research,
        policy_id="pol-research-tier4",
        environment=TenantEnvironment.RESEARCH,
        allowed_authority_tiers=(1, 2, 3, 4),
        recursive_claims_enabled=True,
    )
    assert document.allows_tier(4)
    assert document.environment is TenantEnvironment.RESEARCH

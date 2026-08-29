"""G7 — tier-4-allowing seed policy documents and their digest pinning.

The seed documents are signed policy data: a deployment's tenant planes
are whatever documents it loads, and a scaffold-mutation campaign spec
pins the digest of the tier-4-allowing document its promotions answer to
before search begins. These tests prove:

- the shipped seeds have the right shapes (research allows tier 4;
  production cannot — validation refuses that shape at construction);
- the detached signatures verify over the canonical bytes, and a
  tampered document is refused as policy;
- the digest a scaffold spec pins round-trips through the canonical
  form, is omitted when unset (pre-G7 digest stability), and is refused
  where it cannot govern anything.
"""

from __future__ import annotations

import pytest
from tests.support.factories import make_campaign_spec_mapping

from evoruntime.campaign.errors import InvalidCampaignSpecError
from evoruntime.campaign.spec import CampaignSpec
from evoruntime.security.signing import generate_signing_key
from evoruntime.tenancy.environment import TenantEnvironment
from evoruntime.tenancy.policy import TenantPolicyDocument
from evoruntime.tenancy.seed import (
    SEED_PRODUCTION_POLICY_ID,
    SEED_RESEARCH_POLICY_ID,
    UnsignedTenantPolicyError,
    seed_production_tenant_policy,
    seed_research_tenant_policy,
    sign_tenant_policy,
    verify_tenant_policy,
)

# ----------------------------------------------------------------------
# The shipped seeds
# ----------------------------------------------------------------------


def test_research_seed_allows_tier_4() -> None:
    document = seed_research_tenant_policy("tnt_research_x")
    assert document.environment is TenantEnvironment.RESEARCH
    assert document.allows_tier(4)
    assert document.policy_id == SEED_RESEARCH_POLICY_ID


def test_production_seed_cannot_allow_tier_4() -> None:
    document = seed_production_tenant_policy("tnt_production_x")
    assert document.environment is TenantEnvironment.PRODUCTION
    assert not document.allows_tier(4)
    assert document.policy_id == SEED_PRODUCTION_POLICY_ID


def test_production_document_shaped_like_the_research_seed_is_refused() -> None:
    """The fail-closed rule is structural: a production document cannot
    pin tier-4-allowing defaults, so the digest a scaffold spec pins can
    only ever name a research plane."""
    from evoruntime.tenancy.errors import TenantPolicyError

    with pytest.raises(TenantPolicyError):
        TenantPolicyDocument(
            tenant_id="tnt_production_x",
            policy_id="pol-production-tier4",
            environment=TenantEnvironment.PRODUCTION,
            allowed_authority_tiers=(1, 2, 3, 4),
        )


# ----------------------------------------------------------------------
# The signatures
# ----------------------------------------------------------------------


def test_signed_seed_documents_verify() -> None:
    key = generate_signing_key()
    for seed in (seed_research_tenant_policy("tnt_a"), seed_production_tenant_policy("tnt_b")):
        signed = sign_tenant_policy(seed, key)
        assert signed.verify() is True
        verify_tenant_policy(signed)  # raises on any mismatch


def test_tampered_seed_document_is_refused() -> None:
    """A document whose bytes changed after signing fails verification:
    the digest no longer matches and the signature no longer verifies."""
    from evoruntime.security.signing import DetachedSignature, verify

    key = generate_signing_key()
    document = seed_research_tenant_policy("tnt_research_x")
    signed = sign_tenant_policy(document, key)
    assert signed.verify() is True

    tampered = seed_research_tenant_policy("tnt_research_x")
    tampered.allowed_authority_tiers = (1, 2, 3)
    assert (
        verify(
            DetachedSignature(signature=signed.signature, public_key=signed.signer_public_key),
            tampered.canonical_bytes(),
        )
        is False
    )
    with pytest.raises(UnsignedTenantPolicyError):
        verify_tenant_policy(
            type(signed)(
                document=tampered,
                digest=tampered.digest,
                signature=signed.signature,
                signer_public_key=signed.signer_public_key,
            )
        )


# ----------------------------------------------------------------------
# The digest pinning on the campaign spec
# ----------------------------------------------------------------------


def _scaffold_spec_mapping() -> dict[str, object]:
    """A valid scaffold-mutable spec (G3 pins mutation classes, G4 the
    fixed-editor arm, G7 the tier-4 policy digest)."""
    mapping = make_campaign_spec_mapping()
    mapping["incumbent"]["artifact_type"] = "scaffold"
    mapping["mutable_artifact"]["artifact_type"] = "scaffold"
    mapping["environment"] = "research"
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
    return mapping


def test_scaffold_spec_pins_the_seed_policy_digest() -> None:
    """The pin is the seed document's digest, chosen before search."""
    document = seed_research_tenant_policy("tnt_research_x")
    mapping = _scaffold_spec_mapping()
    mapping["tier4_policy_digest"] = document.digest
    spec = CampaignSpec.from_mapping(mapping)
    assert spec.tier4_policy_digest == document.digest
    assert spec.to_canonical_dict()["tier4_policy_digest"] == document.digest


def test_scaffold_spec_without_the_pin_is_refused() -> None:
    mapping = _scaffold_spec_mapping()
    with pytest.raises(InvalidCampaignSpecError, match="tier4_policy_digest"):
        CampaignSpec.from_mapping(mapping)


def test_scaffold_spec_with_a_malformed_digest_is_refused() -> None:
    mapping = _scaffold_spec_mapping()
    mapping["tier4_policy_digest"] = "not-a-digest"
    with pytest.raises(InvalidCampaignSpecError, match="digest"):
        CampaignSpec.from_mapping(mapping)


def test_non_scaffold_spec_cannot_pin_a_tier4_policy() -> None:
    """A tier-4 pin on a campaign that can never promote at tier 4
    governs nothing — refused at construction."""
    mapping = make_campaign_spec_mapping()
    mapping["tier4_policy_digest"] = "sha256:" + "b" * 64
    with pytest.raises(InvalidCampaignSpecError, match="scaffold-mutable"):
        CampaignSpec.from_mapping(mapping)


def test_tier4_pin_is_always_in_canonical_form() -> None:
    """G3's v3 convention: every v3 field is always serialized — None for
    documents that predate it — so the tier-4 pin is bound by the
    signature on any spec that declares one."""
    mapping = make_campaign_spec_mapping()
    assert CampaignSpec.from_mapping(mapping).to_canonical_dict()["tier4_policy_digest"] is None

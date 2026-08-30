"""Signed seed tenant-policy documents (Phase 3, G7).

G6 made a tenant's environment and approval defaults policy *data*
(:class:`evoruntime.tenancy.policy.TenantPolicyDocument`); G7 ships the
documents a deployment actually starts from, as signed policy data:

**Seeds are documents, not migrations.** The runtime has no tenants table
and no tenant-lifecycle API — a deployment's tenant planes are whatever
policy data it loads. The seed factories here produce the two canonical
starting points: a research tenant whose approval defaults allow tier 4
(the scaffold-mutation plane), and a production tenant that can never
allow it (validation refuses that shape at construction — see
``TenantPolicyDocument._validate``).

**The documents are signed** (the signed-release-manifest /
protected-modules pattern). ``sign_tenant_policy`` produces a detached
Ed25519 signature over the document's canonical bytes;
``verify_tenant_policy`` refuses a document whose bytes no longer verify.
A scaffold-mutation campaign spec pins the *digest* of the tier-4-allowing
seed policy it will be governed by (``CampaignSpec.tier4_policy_digest``),
so the policy a campaign's promotions answer to is chosen before search
begins and every change to it is attributable to a signature.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from evoruntime.security.signing import DetachedSignature, sign, verify
from evoruntime.tenancy.environment import TenantEnvironment
from evoruntime.tenancy.policy import TenantPolicyDocument

SEED_RESEARCH_POLICY_ID = "evoruntime-seed-research-policy"
SEED_PRODUCTION_POLICY_ID = "evoruntime-seed-production-policy"
SEED_REGULATED_POLICY_ID = "evoruntime-seed-regulated-policy"


class UnsignedTenantPolicyError(ValueError):
    """Raised when a tenant-policy document's signature does not verify."""


@dataclass(frozen=True, slots=True)
class SignedTenantPolicyDocument:
    """A tenant-policy document bound to its digest and a signature.

    Mirrors :class:`evoruntime.security.protected_modules.
    SignedProtectedModulesDocument`: the digest addresses the canonical
    body; the signature and public key vouch for it and are excluded
    from it by construction.
    """

    document: TenantPolicyDocument
    digest: str
    signature: bytes
    signer_public_key: bytes

    def verify(self) -> bool:
        """True when the digest matches AND the signature verifies over the
        canonical bytes. Either failing means the policy was tampered with."""
        if self.digest != self.document.digest:
            return False
        return verify(
            DetachedSignature(signature=self.signature, public_key=self.signer_public_key),
            self.document.canonical_bytes(),
        )


def seed_research_tenant_policy(tenant_id: str) -> TenantPolicyDocument:
    """The shipped tier-4-allowing seed: the research environment.

    Tier-4-allowing approval defaults exist only here — a production
    document of this shape is refused at construction, so the digest a
    scaffold spec pins can only ever name a research plane.
    """
    return TenantPolicyDocument(
        tenant_id=tenant_id,
        policy_id=SEED_RESEARCH_POLICY_ID,
        environment=TenantEnvironment.RESEARCH,
        allowed_authority_tiers=(1, 2, 3, 4),
        recursive_claims_enabled=True,
    )


def seed_production_tenant_policy(tenant_id: str) -> TenantPolicyDocument:
    """The shipped production seed: the §21 decision-5 approval defaults.

    Tier-1/2 artifact classes (memory entries, prompt bundles, compiled
    programs — ``authority.tier_by_class``) are auto-eligible for
    promotion after canary; tier-3 classes (workflow, tool, algorithm,
    bounded harness patches) require two-person review-board approval;
    tier 4 (scaffold) is structurally absent — it requires the full
    evidence chain and stays research-tenant-only until a mutation class
    graduates through the G10 comparability gate. This mirrors the
    behavior the Phase 2–4 suites already test, which is why codifying it
    needs no new enforcement code: the documents below are the signed
    form of what the gates already do.

    Deliberately not tier-4-allowing — the environment plane's fail-closed
    rule means production is also what an unmapped tenant gets, and this
    document is the explicit form of the same stance.
    """
    return TenantPolicyDocument(
        tenant_id=tenant_id,
        policy_id=SEED_PRODUCTION_POLICY_ID,
        policy_version=2,
        environment=TenantEnvironment.PRODUCTION,
        allowed_authority_tiers=(1, 2, 3),
        recursive_claims_enabled=False,
        auto_promotion_max_tier=2,
        require_review_for_all_tiers=False,
    )


def seed_regulated_tenant_policy(tenant_id: str) -> TenantPolicyDocument:
    """The shipped regulated-tenant seed (§21 decision 5, regulated column).

    No auto-promotion at any tier — every promotion, tier 1 through 3,
    goes through two-person review-board approval — and tier 4 is
    structurally refused exactly as in the production seed (a production
    document cannot pin tier-4-allowing defaults). Regulated tenants are
    still production-environment tenants: the scaffold and recursive-claim
    fail-closed rules apply unchanged.
    """
    return TenantPolicyDocument(
        tenant_id=tenant_id,
        policy_id=SEED_REGULATED_POLICY_ID,
        policy_version=2,
        environment=TenantEnvironment.PRODUCTION,
        allowed_authority_tiers=(1, 2, 3),
        recursive_claims_enabled=False,
        auto_promotion_max_tier=0,
        require_review_for_all_tiers=True,
    )


def sign_tenant_policy(
    document: TenantPolicyDocument, private_key: Any
) -> SignedTenantPolicyDocument:
    """Sign a tenant-policy document over its canonical bytes.

    The same detached-signature service release manifests, pinned campaign
    specs, and protected-modules documents use, so any party holding the
    public key can verify which tenant plane a campaign was governed by.
    """
    detached = sign(private_key, document.canonical_bytes())
    return SignedTenantPolicyDocument(
        document=document,
        digest=document.digest,
        signature=detached.signature,
        signer_public_key=detached.public_key,
    )


def verify_tenant_policy(signed: SignedTenantPolicyDocument) -> None:
    """Verify a signed tenant-policy document, raising on any mismatch.

    Raises:
        UnsignedTenantPolicyError: the digest does not match the
            document's canonical bytes, or the signature does not verify.
            The document is refused as policy — bytes nobody vouches for
            are not a tenant plane, they are a suggestion.
    """
    if not signed.verify():
        raise UnsignedTenantPolicyError(
            f"tenant-policy document {signed.document.policy_id!r} for tenant "
            f"{signed.document.tenant_id!r} ({signed.digest}) has no valid "
            "signature over its canonical bytes — refusing to treat it as "
            "an enforced tenant policy"
        )


__all__ = [
    "SEED_PRODUCTION_POLICY_ID",
    "SEED_REGULATED_POLICY_ID",
    "SEED_RESEARCH_POLICY_ID",
    "SignedTenantPolicyDocument",
    "UnsignedTenantPolicyError",
    "seed_production_tenant_policy",
    "seed_research_tenant_policy",
    "sign_tenant_policy",
    "verify_tenant_policy",
]

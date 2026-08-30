"""The tenant policy document (Phase 3, G6) — environment as policy DATA.

**Why a tenant-keyed policy document and not a migration on a tenant
record.** There is no tenants table anywhere in the schema: `tenant_id` is
a free-form string column on every record, and tenant lifecycle (create,
list, rotate) does not exist as a runtime concept. A migration would have
to invent a tenants entity and backfill rows for ids that exist only as
strings in other tables — a new authoritative store for what is one enum
field. The runtime's existing discipline for exactly this kind of gate is
policy-as-data: :class:`~evoruntime.selection.policy.PromotionPolicyDocument`
is a frozen, digestable document validated at construction, and the Phase 3
spec (G7) ships tier-4-allowing seed policies the same way. So the
environment and the per-environment approval defaults live in
:class:`TenantPolicyDocument`, a tenant-keyed document of the same shape.

**Fail closed.** A tenant with no policy document is treated as
production by :class:`TenantPolicyRegistry` — an unmapped tenant must
never be research by default, because research is the permissive
environment. And a production document cannot pin tier-4-allowing
approval defaults: validation refuses it at construction, so a
tier-4-allowing default can only ever exist inside a research tenant's
policy data.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable

from evoruntime.tenancy.environment import TenantEnvironment
from evoruntime.tenancy.errors import TenantPolicyError

_DIGEST_PREFIX = "sha256:"

_MAX_AUTHORITY_TIER = 4

#: §21 decision 5 (2026-08-30 ruling): the production approval default.
#: Tier-1/2 artifact classes are auto-eligible for promotion after canary;
#: everything above this tier requires two-person review-board approval.
DEFAULT_AUTO_PROMOTION_MAX_TIER = 2


class TenantPolicyDocument:
    """One tenant's environment and approval defaults, as signed data.

    Part of the deployment's policy surface: the environment below is
    pinned before any campaign runs, and the canonical form of this
    document is what a deployment pins (G7's seed policy documents
    reference the same digest discipline). Validation runs at
    construction — a document that would let a production tenant reach
    tier 4 is refused before it can govern anything.
    """

    def __init__(
        self,
        *,
        tenant_id: str,
        policy_id: str,
        environment: TenantEnvironment | str,
        policy_version: int = 1,
        allowed_authority_tiers: tuple[int, ...] = (1, 2, 3),
        recursive_claims_enabled: bool = False,
        auto_promotion_max_tier: int = DEFAULT_AUTO_PROMOTION_MAX_TIER,
        require_review_for_all_tiers: bool = False,
    ) -> None:
        self.tenant_id = tenant_id
        self.policy_id = policy_id
        self.environment = TenantEnvironment(environment)
        self.policy_version = policy_version
        self.allowed_authority_tiers = tuple(sorted(set(allowed_authority_tiers)))
        self.recursive_claims_enabled = recursive_claims_enabled
        self.auto_promotion_max_tier = auto_promotion_max_tier
        self.require_review_for_all_tiers = require_review_for_all_tiers
        self._validate()

    def _validate(self) -> None:
        if not self.tenant_id:
            raise TenantPolicyError("tenant_id must be non-empty")
        if not self.policy_id:
            raise TenantPolicyError("policy_id must be non-empty")
        if self.policy_version < 1:
            raise TenantPolicyError("policy_version must be >= 1")
        tiers = self.allowed_authority_tiers
        if not tiers:
            raise TenantPolicyError(
                "allowed_authority_tiers must name at least one tier — a tenant "
                "that can approve nothing is a misconfiguration, not a policy"
            )
        for tier in tiers:
            if not 1 <= tier <= _MAX_AUTHORITY_TIER:
                raise TenantPolicyError(
                    f"allowed_authority_tiers contains {tier!r}; tiers are 1..{_MAX_AUTHORITY_TIER}"
                )
        if self.environment is TenantEnvironment.PRODUCTION and _MAX_AUTHORITY_TIER in tiers:
            raise TenantPolicyError(
                "a production tenant cannot pin tier-4-allowing approval defaults — "
                "tier 4 (highest-risk, scaffold-class) approvals exist only in the "
                "research environment"
            )
        if self.environment is TenantEnvironment.PRODUCTION and self.recursive_claims_enabled:
            raise TenantPolicyError(
                "a production tenant cannot enable recursive-improvement claims — "
                "the recursive-label gate is research-only"
            )
        self._validate_approval_defaults()

    def _validate_approval_defaults(self) -> None:
        """§21 decision 5: the approval defaults must be internally coherent.

        A tenant cannot auto-promote a tier its approval defaults do not
        admit at all, and a review-for-everything tenant cannot also name
        an auto-eligible tier — the two declarations contradict each
        other, and an incoherent policy governs nothing.
        """
        if self.auto_promotion_max_tier < 0:
            raise TenantPolicyError(
                f"auto_promotion_max_tier must be >= 0, got {self.auto_promotion_max_tier}"
            )
        if self.auto_promotion_max_tier > max(self.allowed_authority_tiers):
            raise TenantPolicyError(
                f"auto_promotion_max_tier {self.auto_promotion_max_tier} exceeds the "
                f"highest allowed authority tier {max(self.allowed_authority_tiers)} — "
                "a tenant cannot auto-promote a tier it cannot approve at all"
            )
        if self.require_review_for_all_tiers and self.auto_promotion_max_tier != 0:
            raise TenantPolicyError(
                "require_review_for_all_tiers with auto_promotion_max_tier "
                f"{self.auto_promotion_max_tier} is incoherent — a tenant that reviews "
                "everything auto-promotes nothing"
            )
        if (
            self.environment is TenantEnvironment.PRODUCTION
            and self.auto_promotion_max_tier >= _MAX_AUTHORITY_TIER
        ):
            raise TenantPolicyError(
                "a production tenant cannot auto-promote tier 4 — tier-4 promotions "
                "require the full evidence chain and exist only in the research "
                "environment until a mutation class graduates (G10)"
            )

    def auto_eligible(self, tier: int) -> bool:
        """True when `tier` is auto-eligible for promotion after canary
        under this tenant's approval defaults (§21 decision 5)."""
        return (
            not self.require_review_for_all_tiers
            and tier <= self.auto_promotion_max_tier
            and tier in self.allowed_authority_tiers
        )

    def requires_two_person_review(self, tier: int) -> bool:
        """True when `tier` is approvable here but only through two-person
        review-board approval — never automatically."""
        return tier in self.allowed_authority_tiers and not self.auto_eligible(tier)

    def allows_tier(self, tier: int) -> bool:
        """True when this tenant's approval defaults admit `tier`."""
        return tier in self.allowed_authority_tiers

    def to_canonical_dict(self) -> dict[str, object]:
        """Canonical JSON form of this document (the digest's contract)."""
        return {
            "tenant_id": self.tenant_id,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "environment": self.environment.value,
            "allowed_authority_tiers": list(self.allowed_authority_tiers),
            "recursive_claims_enabled": self.recursive_claims_enabled,
            "auto_promotion_max_tier": self.auto_promotion_max_tier,
            "require_review_for_all_tiers": self.require_review_for_all_tiers,
        }

    def canonical_bytes(self) -> bytes:
        """Canonical JSON bytes: sorted keys, no whitespace, UTF-8.

        One definition: the digest is exactly sha256 over these bytes, so
        a signature made over them (G7's signed seed policies) verifies
        against the same content address the document publishes.
        """
        return json.dumps(
            self.to_canonical_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    @property
    def digest(self) -> str:
        """Content digest of the canonical form (`sha256:...`)."""
        return _DIGEST_PREFIX + hashlib.sha256(self.canonical_bytes()).hexdigest()


class TenantPolicyRegistry:
    """The deployment's set of tenant policy documents.

    Constructed from the documents a deployment loads (G7 ships the seed
    documents); every environment lookup goes through here so "which
    tenants are research" has exactly one answer at runtime.
    """

    def __init__(self, documents: Iterable[TenantPolicyDocument] = ()) -> None:
        by_tenant: dict[str, TenantPolicyDocument] = {}
        for document in documents:
            if document.tenant_id in by_tenant:
                raise TenantPolicyError(
                    f"two policy documents claim tenant {document.tenant_id!r} — "
                    "a tenant has exactly one environment"
                )
            by_tenant[document.tenant_id] = document
        self._by_tenant = by_tenant

    def policy_for(self, tenant_id: str) -> TenantPolicyDocument | None:
        """The tenant's policy document, or None when unmapped."""
        return self._by_tenant.get(tenant_id)

    def environment_for(self, tenant_id: str) -> TenantEnvironment:
        """The tenant's environment — **production when unmapped** (fail closed)."""
        document = self._by_tenant.get(tenant_id)
        return document.environment if document is not None else TenantEnvironment.PRODUCTION


__all__ = ["TenantPolicyDocument", "TenantPolicyRegistry"]

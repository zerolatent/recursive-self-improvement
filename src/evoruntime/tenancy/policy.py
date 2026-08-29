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
    ) -> None:
        self.tenant_id = tenant_id
        self.policy_id = policy_id
        self.environment = TenantEnvironment(environment)
        self.policy_version = policy_version
        self.allowed_authority_tiers = tuple(sorted(set(allowed_authority_tiers)))
        self.recursive_claims_enabled = recursive_claims_enabled
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
        }

    @property
    def digest(self) -> str:
        """Content digest of the canonical form (`sha256:...`)."""
        canonical = json.dumps(self.to_canonical_dict(), sort_keys=True, separators=(",", ":"))
        return _DIGEST_PREFIX + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


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

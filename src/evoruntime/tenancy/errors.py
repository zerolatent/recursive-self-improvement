"""Errors raised by the tenant-environment plane (Phase 3, G6)."""

from __future__ import annotations

from evoruntime.tenancy.boundaries import RefusalBoundary


class TenancyError(RuntimeError):
    """Base class for tenant-environment failures."""


class TenantPolicyError(TenancyError):
    """A tenant policy document was declared in a way that cannot govern."""


class UnknownTenantPolicyError(TenancyError):
    """No policy document is configured for a tenant.

    The plane fails closed: callers that need an environment resolve it
    through :meth:`TenantPolicyRegistry.environment_for`, which answers
    ``production`` for unknown tenants rather than raising — an unmapped
    tenant must never be treated as research by default.
    """


class TenantRefusalError(TenancyError):
    """A scaffold-mutation boundary was refused and the refusal audited.

    Carries the boundary the refusal happened at and the machine-readable
    reason, so callers (and the HTTP layer) can branch on *why* without
    parsing the message.
    """

    def __init__(self, boundary: RefusalBoundary, reason: str, message: str) -> None:
        super().__init__(message)
        self.boundary = boundary
        self.reason = reason


__all__ = ["TenancyError", "TenantPolicyError", "TenantRefusalError", "UnknownTenantPolicyError"]

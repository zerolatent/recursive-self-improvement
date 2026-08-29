"""The tenant-environment plane (Phase 3, G6).

`TenantEnvironment` (research | production) as first-class policy data:
:class:`~evoruntime.tenancy.policy.TenantPolicyDocument` carries a
tenant's environment and its per-environment approval defaults, and the
refusal ledger (:mod:`evoruntime.tenancy.audit`) records every
scaffold-mutation boundary refusal. The four boundary checks live at
their call sites — spec construction, campaign creation / candidate
registration, release activation, and the recursive-label gate — and all
of them consult this package.
"""

from __future__ import annotations

from evoruntime.tenancy.environment import (
    SCAFFOLD_ARTIFACT_TYPES,
    TenantEnvironment,
    is_scaffold_class,
)
from evoruntime.tenancy.errors import (
    TenancyError,
    TenantPolicyError,
    TenantRefusalError,
    UnknownTenantPolicyError,
)
from evoruntime.tenancy.policy import TenantPolicyDocument, TenantPolicyRegistry

__all__ = [
    "SCAFFOLD_ARTIFACT_TYPES",
    "TenancyError",
    "TenantEnvironment",
    "TenantPolicyDocument",
    "TenantPolicyError",
    "TenantPolicyRegistry",
    "TenantRefusalError",
    "UnknownTenantPolicyError",
    "is_scaffold_class",
]

"""A tenant-scoped caller: D7's workload identity plus the tenant it acts for.

D7 (`evoruntime.security.identities`) already owns *what a caller is* —
the evaluator/candidate-runner roles and the identity object every policy
check consumes. This module adds the one thing dataset governance needs
and D7 has no opinion about: *whose data* the caller is acting on.

Deliberately a composition rather than a second role enum. A trust
boundary defined in two places is a trust boundary that will eventually
disagree with itself, and the half that is wrong is the half that grants
access.
"""

from __future__ import annotations

from dataclasses import dataclass

from evoruntime.security.identities import WorkloadIdentity, WorkloadRole


@dataclass(frozen=True, slots=True)
class Principal:
    """An authenticated caller acting within one tenant."""

    identity: WorkloadIdentity
    tenant_id: str

    @property
    def identity_id(self) -> str:
        """Stable identifier for the calling workload instance."""
        return self.identity.subject

    @property
    def role(self) -> WorkloadRole:
        """The caller's workload role, as authenticated."""
        return self.identity.role

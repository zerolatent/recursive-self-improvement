"""Workload identities and roles that carry the Phase 0 trust boundary.

The evaluation plane is a distinct security identity from candidate
execution (spec: "Trust boundary" locked decision, PRD §8.1/§18.2). Every
authorization decision in EvoRuntime is expressed against a `Principal`
built here rather than against ad-hoc string comparisons, so the set of
identities allowed to touch sealed data stays enumerable and testable.

Authentication — proving a caller really is the identity it claims — is
deliverable D7. This module owns the *authorization* vocabulary only.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Role(StrEnum):
    """The workload roles that exist across the Phase 0 planes."""

    EVALUATOR = "evaluator"
    """Evaluation plane. The only role permitted to resolve holdout content."""

    CANDIDATE_RUNNER = "candidate_runner"
    """Execution plane: runs untrusted candidate configurations."""

    EVOLUTION_PLANE = "evolution_plane"
    """Proposes candidates. Receives opaque handles and redacted aggregates only."""

    AUTHORITY = "authority"
    """Signs releases and attestations; governs, never reads evaluation content."""

    INGEST = "ingest"
    """Trace ingest path. Writes events; reads nothing from dataset partitions."""


class StorageIdentity(StrEnum):
    """Storage identities that own dataset content at rest.

    Holdout content is stored exclusively under the evaluation plane's
    storage identity; no other plane's credentials can reach that bucket.
    """

    EVALUATION_PLANE = "evaluation-plane"
    RUNTIME_PLANE = "runtime-plane"


EVALUATION_PLANE_ROLES: frozenset[Role] = frozenset({Role.EVALUATOR})
"""Roles that live inside the evaluation plane's trust boundary.

Deliberately a closed set rather than an "everything except X" rule: a new
role added later is denied holdout access by default instead of inheriting
it by omission.
"""


@dataclass(frozen=True, slots=True)
class Principal:
    """An authenticated caller: who it is, what role it holds, whose data it may touch."""

    identity_id: str
    role: Role
    tenant_id: str

    @property
    def is_evaluation_plane(self) -> bool:
        """True when this principal sits inside the evaluation-plane boundary."""
        return self.role in EVALUATION_PLANE_ROLES

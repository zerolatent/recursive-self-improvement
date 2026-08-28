"""First-class workload identities for the evaluation plane.

The PRD's trust-boundary invariant (candidate execution never touches
holdout content or evaluator key material) only holds if identity is
explicit and checkable, not inferred from network location or convention.
This module defines the workload roles and the identity object every
policy check in :mod:`evoruntime.security.policy` consumes.

Phase 0 collapsed the PRD's plane taxonomy (runtime, evolution, execution,
evaluation, authority) to the one boundary that matters for measuring a
baseline — evaluator vs candidate-runner. Phase 1 adds the first
authority-plane role: the release controller, the only workload identity
allowed to compare-and-swap the active release pointer (FR-011).
"""

from __future__ import annotations

import os
from enum import StrEnum
from functools import lru_cache

from pydantic import Field

from evoruntime.core.schemas import EvoRuntimeBaseModel

_ROLE_ENV_VAR = "EVORUNTIME_WORKLOAD_ROLE"
_SUBJECT_ENV_VAR = "EVORUNTIME_WORKLOAD_SUBJECT"


class WorkloadRole(StrEnum):
    """The workload identities the runtime's policy checks consume.

    ``EVALUATOR`` is the evaluation-plane service: it may resolve holdout
    handles and hold evaluator signing keys. ``CANDIDATE_RUNNER`` is
    whatever executes a candidate agent (the incumbent, a retry arm, or a
    future optimizer-produced candidate); it must never see holdout
    content or evaluator key material, no matter what it asks for.
    ``RELEASE_CONTROLLER`` is the authority-plane service that owns the
    active release pointer: root-of-trust code, not a plugin (FR-011).
    """

    EVALUATOR = "evaluator"
    CANDIDATE_RUNNER = "candidate-runner"
    RELEASE_CONTROLLER = "release-controller"


class WorkloadIdentity(EvoRuntimeBaseModel):
    """The authenticated identity a caller presents to a policy check.

    This is a plain data object, not a credential — callers are expected to
    construct it from whatever the deployment's actual authentication
    mechanism verified (a signed service-account token, an mTLS client
    certificate's SAN, etc.). Phase 0 does not implement that verification
    layer; it defines the shape every later verifier must produce so policy
    checks have one stable input.
    """

    role: WorkloadRole
    subject: str = Field(min_length=1, description="Stable identifier for the workload instance.")


def identity_from_env() -> WorkloadIdentity:
    """Build the process's workload identity from its environment.

    Deployment configuration (not application code) decides whether a
    given process is the evaluator or a candidate-runner: the evaluation
    harness sets ``EVORUNTIME_WORKLOAD_ROLE=evaluator`` for itself and
    ``candidate-runner`` for every sandbox it launches. Defaulting to the
    least-privileged role when unset means a misconfigured deployment fails
    closed (denied access) rather than fails open (accidental evaluator
    privileges).
    """
    raw_role = os.environ.get(_ROLE_ENV_VAR, WorkloadRole.CANDIDATE_RUNNER.value)
    try:
        role = WorkloadRole(raw_role)
    except ValueError as exc:
        valid = ", ".join(r.value for r in WorkloadRole)
        raise ValueError(
            f"{_ROLE_ENV_VAR}={raw_role!r} is not a recognized workload role "
            f"(expected one of: {valid})"
        ) from exc
    subject = os.environ.get(_SUBJECT_ENV_VAR, "unknown")
    return WorkloadIdentity(role=role, subject=subject)


@lru_cache
def get_current_identity() -> WorkloadIdentity:
    """Return the process-wide workload identity singleton.

    Cached like the other settings singletons in this codebase — a
    process's role does not change at runtime, and re-reading the
    environment on every policy check would make the security boundary
    dependent on environment mutability, which is exactly the kind of
    ambient state this module exists to avoid.
    """
    return identity_from_env()

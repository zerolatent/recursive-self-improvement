"""Policy checks that enforce the evaluator / candidate-runner boundary.

Every resource that must stay behind the trust boundary (holdout content,
evaluator signing keys, and anything added in later deliverables) is gated
through a function in this module rather than an ad-hoc ``if role ==
...`` scattered at each call site. One place to audit, one place to test.

Deny-by-default: an identity is permitted only if a check explicitly
allows its role. Unknown or malformed identities are never treated as
implicitly evaluator-privileged.
"""

from __future__ import annotations

from evoruntime.security.identities import WorkloadIdentity, WorkloadRole


class PermissionDeniedError(PermissionError):
    """Raised when a workload identity is not permitted to take an action."""

    def __init__(self, identity: WorkloadIdentity, action: str) -> None:
        self.identity = identity
        self.action = action
        super().__init__(
            f"identity {identity.subject!r} (role={identity.role.value}) "
            f"is not permitted to {action}"
        )


def _require_role(
    identity: WorkloadIdentity, allowed: frozenset[WorkloadRole], *, action: str
) -> None:
    """Raise :class:`PermissionDeniedError` unless ``identity.role`` is allowed."""
    if identity.role not in allowed:
        raise PermissionDeniedError(identity, action)


def require_holdout_access(identity: WorkloadIdentity) -> None:
    """Enforce that only the evaluator role may resolve holdout handles.

    A candidate-runner identity — including one running an optimizer's
    candidate configuration — must never be able to dereference a
    ``holdout://`` handle into real content, no matter what it claims to
    need it for (PRD §12.2 partition rules; spec's boundary invariant).
    """
    _require_role(identity, frozenset({WorkloadRole.EVALUATOR}), action="resolve holdout handles")


def require_release_swap_authority(identity: WorkloadIdentity) -> None:
    """Enforce that only the release-controller role may CAS the active pointer.

    The active release pointer is the runtime's root of trust: whoever can
    move it decides what every worker resolves (FR-011). The release
    controller is root-of-trust code, not a plugin, so no other identity —
    not even the evaluator — may perform the compare-and-swap. Denials are
    audited by the caller (see ``evoruntime.selection.release_pointer``).
    """
    _require_role(
        identity,
        frozenset({WorkloadRole.RELEASE_CONTROLLER}),
        action="compare-and-swap the active release pointer",
    )


def require_evaluator_key_access(identity: WorkloadIdentity) -> None:
    """Enforce that only the evaluator role may read evaluator signing keys.

    Outcome attestations and release manifests are only trustworthy if the
    key that signs them is unreachable from candidate execution — a
    candidate that can sign its own outcome as attested defeats the entire
    evaluation plane.
    """
    _require_role(
        identity, frozenset({WorkloadRole.EVALUATOR}), action="read evaluator signing keys"
    )

"""The active release pointer and its CAS authority (FR-011).

The pointer is the runtime's root of trust: it names the release manifest
every worker resolves, and moving it is the atomic activation and rollback
unit. So its one mutating operation — compare-and-swap — is gated twice:

**Identity first (FR-011).** Only the release-controller workload identity
may perform the CAS. Every other identity — evaluator, candidate-runner,
anything else — is denied *and audited*: the denial is recorded before the
exception propagates, so an attempted pointer grab by a non-authority
workload leaves evidence even though it left no state change.

**Audit always.** Every attempt — allowed, denied, or lost to a conflict —
appends an audit entry. An operation whose audit write fails is refused
(:class:`PointerAuditError`), never performed unaudited: an unauditable
root-of-trust mutation is worse than no mutation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from evoruntime.security.identities import WorkloadIdentity
from evoruntime.security.policy import PermissionDeniedError, require_release_swap_authority
from evoruntime.selection.errors import CasConflictError, PointerAuditError


@dataclass(frozen=True, slots=True)
class ReleasePointer:
    """The active release pointer: the digest every worker resolves."""

    current_digest: str | None
    version: int = 0
    """Monotonic — incremented on every successful swap."""


@dataclass(frozen=True, slots=True)
class PointerAuditEntry:
    """One audited pointer attempt. Denied attempts are entries too."""

    actor_subject: str
    actor_role: str
    action: str
    outcome: str
    expected_digest: str | None
    new_digest: str
    detail: str


class PointerAuditLog(Protocol):
    """Append-only audit sink for pointer attempts."""

    def append(self, entry: PointerAuditEntry) -> None: ...

    def entries(self) -> tuple[PointerAuditEntry, ...]: ...


class InMemoryPointerAuditLog:
    """In-process append-only audit log (the test harness's stand-in)."""

    def __init__(self) -> None:
        self._entries: list[PointerAuditEntry] = []

    def append(self, entry: PointerAuditEntry) -> None:
        self._entries.append(entry)

    def entries(self) -> tuple[PointerAuditEntry, ...]:
        return tuple(self._entries)


@dataclass
class ReleasePointerStore:
    """Owns the active release pointer and its CAS authority check.

    The store is the only writer of the pointer; the CAS is the only
    mutation; and the release-controller identity is the only caller the
    CAS accepts. Everything else is denied and audited.
    """

    audit_log: PointerAuditLog = field(default_factory=InMemoryPointerAuditLog)
    _pointer: ReleasePointer = field(default_factory=lambda: ReleasePointer(current_digest=None))

    @property
    def pointer(self) -> ReleasePointer:
        """The current pointer state."""
        return self._pointer

    def compare_and_swap(
        self,
        identity: WorkloadIdentity,
        expected_current: str | None,
        new_digest: str,
    ) -> ReleasePointer:
        """Atomically move the pointer from ``expected_current`` to
        ``new_digest`` — release-controller identity only (FR-011).

        Raises:
            PermissionDeniedError: any non-release-controller identity.
                The denial is audited before the exception propagates.
            CasConflictError: the pointer moved since the caller read it;
                the error carries the actual current digest.
            PointerAuditError: the attempt could not be audited.
        """
        try:
            require_release_swap_authority(identity)
        except PermissionDeniedError as denied:
            self._audit(identity, expected_current, new_digest, "denied", str(denied))
            raise

        if self._pointer.current_digest != expected_current:
            detail = (
                f"pointer is at {self._pointer.current_digest!r}, "
                f"caller expected {expected_current!r}"
            )
            self._audit(identity, expected_current, new_digest, "conflict", detail)
            raise CasConflictError(expected_current, self._pointer.current_digest)

        swapped = ReleasePointer(current_digest=new_digest, version=self._pointer.version + 1)
        self._audit(
            identity,
            expected_current,
            new_digest,
            "allowed",
            f"pointer moved to {new_digest!r} at version {swapped.version}",
        )
        self._pointer = swapped
        return swapped

    def _audit(
        self,
        identity: WorkloadIdentity,
        expected_current: str | None,
        new_digest: str,
        outcome: str,
        detail: str,
    ) -> None:
        entry = PointerAuditEntry(
            actor_subject=identity.subject,
            actor_role=identity.role.value,
            action="release-pointer-cas",
            outcome=outcome,
            expected_digest=expected_current,
            new_digest=new_digest,
            detail=detail,
        )
        try:
            self.audit_log.append(entry)
        except Exception as exc:
            raise PointerAuditError(
                f"pointer attempt by {identity.subject!r} could not be audited: {exc}"
            ) from exc


__all__ = [
    "InMemoryPointerAuditLog",
    "PointerAuditEntry",
    "PointerAuditLog",
    "ReleasePointer",
    "ReleasePointerStore",
]

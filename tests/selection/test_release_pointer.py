"""FR-011 release-pointer tests: only the release-controller identity may
CAS the active release pointer; every other identity is denied AND audited."""

from __future__ import annotations

import pytest

from evoruntime.security.identities import WorkloadIdentity, WorkloadRole
from evoruntime.security.policy import PermissionDeniedError
from evoruntime.selection import (
    CasConflictError,
    InMemoryPointerAuditLog,
    PointerAuditError,
    ReleasePointerStore,
)

DIGEST_V1 = "sha256:" + "11" * 32
DIGEST_V2 = "sha256:" + "22" * 32


def _identity(role: WorkloadRole, subject: str) -> WorkloadIdentity:
    return WorkloadIdentity(role=role, subject=subject)


def controller_identity() -> WorkloadIdentity:
    return _identity(WorkloadRole.RELEASE_CONTROLLER, "release-ctl-1")


def _store() -> ReleasePointerStore:
    return ReleasePointerStore(audit_log=InMemoryPointerAuditLog())


class TestCasAuthority:
    def test_release_controller_can_swap_the_pointer(self) -> None:
        store = _store()
        swapped = store.compare_and_swap(controller_identity(), None, DIGEST_V1)

        assert swapped.current_digest == DIGEST_V1
        assert swapped.version == 1

    def test_cas_conflict_carries_the_actual_digest(self) -> None:
        store = _store()
        controller = controller_identity()
        store.compare_and_swap(controller, None, DIGEST_V1)

        with pytest.raises(CasConflictError) as excinfo:
            store.compare_and_swap(controller, None, DIGEST_V2)
        assert excinfo.value.actual == DIGEST_V1
        assert store.pointer.current_digest == DIGEST_V1

    def test_version_increments_monotonically(self) -> None:
        store = _store()
        controller = controller_identity()
        first = store.compare_and_swap(controller, None, DIGEST_V1)
        second = store.compare_and_swap(controller, DIGEST_V1, DIGEST_V2)
        assert (first.version, second.version) == (1, 2)


class TestIamDenial:
    """Every non-release-controller identity is denied and audited (FR-011)."""

    @pytest.mark.parametrize(
        ("role", "subject"),
        [
            (WorkloadRole.EVALUATOR, "eval-plane-1"),
            (WorkloadRole.CANDIDATE_RUNNER, "candidate-sandbox-7"),
        ],
    )
    def test_non_controller_identities_are_denied(self, role: WorkloadRole, subject: str) -> None:
        store = _store()
        identity = _identity(role, subject)

        with pytest.raises(PermissionDeniedError, match="compare-and-swap"):
            store.compare_and_swap(identity, None, DIGEST_V1)

        # Denied AND audited: the attempt left evidence, the pointer did not move.
        entries = store.audit_log.entries()  # type: ignore[attr-defined]
        assert len(entries) == 1
        assert entries[0].outcome == "denied"
        assert entries[0].actor_role == role.value
        assert entries[0].actor_subject == subject
        assert entries[0].new_digest == DIGEST_V1
        assert store.pointer.current_digest is None

    def test_denial_leaves_no_state_change(self) -> None:
        store = _store()
        controller = controller_identity()
        store.compare_and_swap(controller, None, DIGEST_V1)

        intruder = _identity(WorkloadRole.CANDIDATE_RUNNER, "candidate-sandbox-7")
        with pytest.raises(PermissionDeniedError):
            store.compare_and_swap(intruder, DIGEST_V1, DIGEST_V2)

        assert store.pointer.current_digest == DIGEST_V1
        assert store.pointer.version == 1

    def test_every_attempt_is_audited(self) -> None:
        store = _store()
        controller = controller_identity()
        store.compare_and_swap(controller, None, DIGEST_V1)
        with pytest.raises(PermissionDeniedError):
            store.compare_and_swap(
                _identity(WorkloadRole.EVALUATOR, "eval-plane-1"), DIGEST_V1, DIGEST_V2
            )
        with pytest.raises(CasConflictError):
            store.compare_and_swap(controller, None, DIGEST_V2)

        outcomes = [e.outcome for e in store.audit_log.entries()]  # type: ignore[attr-defined]
        assert outcomes == ["allowed", "denied", "conflict"]

    def test_failed_audit_write_refuses_the_swap(self) -> None:
        class BrokenAuditLog:
            def append(self, entry: object) -> None:
                raise OSError("audit sink unreachable")

            def entries(self) -> tuple[(), ...]:
                return ()

        store = ReleasePointerStore(audit_log=BrokenAuditLog())  # type: ignore[arg-type]
        controller = controller_identity()

        with pytest.raises(PointerAuditError, match="could not be audited"):
            store.compare_and_swap(controller, None, DIGEST_V1)
        # No unaudited mutation: the pointer never moved.
        assert store.pointer.current_digest is None

"""The release controller: the runtime's root-of-trust service (FR-011).

The controller is *not* a plugin. It is authority-plane code, and its
workload identity is the only one in the entire runtime permitted to
compare-and-swap the active release pointer. Every other identity —
evaluator, candidate-runner, anything else — is denied at the pointer
store and the denial is audited (E4's CAS gate; this module is its sole
legitimate call site).

Two operations exist, and both take a whole :class:`SignedReleaseManifest`:

- **activate** — verify the manifest's signature over its canonical
  bytes, then CAS the pointer to the manifest's digest. The entire
  manifest moves atomically: there is no per-artifact pointer to get
  half-way through moving.
- **rollback** — verify the signature, then CAS the pointer back to the
  manifest's ``prior_release_digest``. Rollback is the same atomic move
  in reverse, never a per-artifact unwind.

Both refuse an unverifiable manifest: the manifest is the atomic unit
precisely because its bytes are signed, so a signature that does not
verify means the bytes are not the release anyone approved.
"""

from __future__ import annotations

from evoruntime.release.errors import RollbackUnavailableError
from evoruntime.release.manifest import (
    SignedReleaseManifest,
    assert_distinct_from_prior,
    verify_release_manifest,
)
from evoruntime.security.identities import WorkloadIdentity, WorkloadRole
from evoruntime.security.policy import PermissionDeniedError
from evoruntime.selection.release_pointer import ReleasePointer, ReleasePointerStore


class ReleaseController:
    """Owns activation and rollback of signed release manifests.

    Constructed with the controller's own workload identity, which must
    be the release-controller role — a controller running under any other
    identity is a misconfigured deployment that would fail on every CAS,
    so it is refused at construction (fail closed).
    """

    def __init__(self, pointer_store: ReleasePointerStore, identity: WorkloadIdentity) -> None:
        if identity.role is not WorkloadRole.RELEASE_CONTROLLER:
            raise PermissionDeniedError(identity, "operate the release controller")
        self._store = pointer_store
        self._identity = identity

    @property
    def identity(self) -> WorkloadIdentity:
        return self._identity

    def active_digest(self) -> str | None:
        """The digest currently on the active release pointer."""
        return self._store.pointer.current_digest

    def activate(self, manifest: SignedReleaseManifest) -> ReleasePointer:
        """Atomically activate the entire manifest (PRD §9.2).

        Verifies the manifest's signature, then compare-and-swaps the
        active release pointer to the manifest's digest. Raises:

            UnsignedManifestError: the signature does not verify.
            CasConflictError: the pointer moved since the caller read it.
            PermissionDeniedError: this controller's identity is not the
                release-controller role (refused at construction, but the
                store re-checks — the gate lives at the pointer, not in
                the caller's good intentions).
        """
        verify_release_manifest(manifest)
        assert_distinct_from_prior(manifest)
        return self._store.compare_and_swap(
            self._identity, self._store.pointer.current_digest, manifest.manifest_digest
        )

    def rollback(self, manifest: SignedReleaseManifest) -> ReleasePointer:
        """Atomically roll back to the manifest's prior release.

        The manifest is the rollback unit: one CAS moves the pointer back
        to ``prior_release_digest`` and the whole release goes with it.
        Raises:

            UnsignedManifestError: the signature does not verify.
            RollbackUnavailableError: the manifest has no prior release —
                a root release has nothing to return to.
            CasConflictError: the pointer is no longer at this manifest's
                digest — the rollback would not be returning *from* the
                release being rolled back, so it is refused and the caller
                re-reads reality.
        """
        verify_release_manifest(manifest)
        prior = manifest.prior_release_digest
        if prior is None:
            raise RollbackUnavailableError(manifest.manifest_digest)
        return self._store.compare_and_swap(self._identity, manifest.manifest_digest, prior)


__all__ = ["ReleaseController"]

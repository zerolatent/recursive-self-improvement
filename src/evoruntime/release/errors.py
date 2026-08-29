"""Typed release-plane errors (deliverable E5).

Collected in one module, like ``evoruntime.selection.errors``, so the set of
failures a release caller must handle is auditable in one place. The splits
that matter:

- ``UnsignedManifestError`` is the FR-003 activation boundary restated for
  the controller: a manifest whose signature does not verify over its
  canonical bytes is not a release, no matter what it names.
- ``RollbackUnavailableError`` and ``NoActiveReleaseError`` are the state
  preconditions: rollback needs a prior release to return to, and a canary
  needs an incumbent to differ from.
- ``SessionPinError`` is the one-manifest-per-session boundary: a session
  that could re-pin mid-flight could straddle two releases, which is
  exactly the mixed-release state §9.2 forbids.
- ``NamespaceViolationError`` is the candidate-state boundary: candidate
  sessions write into the candidate namespace only, never incumbent memory.
- ``DigestReportingError`` is fleet-integrity: a worker reporting a digest
  it does not resolve is lying about what it serves, and the lie is
  refused rather than recorded.
"""

from __future__ import annotations

from collections.abc import Sequence


class ReleaseError(Exception):
    """Base class for release-plane failures."""


class UnsignedManifestError(ReleaseError):
    """A release manifest's signature is missing or does not verify over
    its canonical bytes. Activation and rollback both refuse it: the
    manifest is the atomic unit precisely because its bytes are vouched
    for — an unverifiable manifest is a floating pointer with extra steps."""


class NoActiveReleaseError(ReleaseError):
    """No release is currently active. A canary needs an incumbent manifest
    to differ from; activating the first release is not a canary."""


class RollbackUnavailableError(ReleaseError):
    """Rollback was requested for a manifest with no prior release.

    The manifest is the rollback unit, and its ``prior_release_digest`` is
    the rollback target — a root release has nothing to return to, and
    inventing a target would be a guess dressed as a rollback."""

    def __init__(self, manifest_digest: str) -> None:
        self.manifest_digest = manifest_digest
        super().__init__(
            f"release manifest {manifest_digest!r} has no prior release — "
            "there is nothing to roll back to"
        )


class SessionPinError(ReleaseError):
    """A session attempted to re-pin to a different manifest.

    Sessions are pinned to exactly one manifest for their lifetime: a
    session that switched manifests mid-flight would serve a mix of two
    releases, which is the mixed-release state §9.2 exists to prevent."""

    def __init__(self, session_id: str, pinned_digest: str, attempted_digest: str) -> None:
        self.session_id = session_id
        self.pinned_digest = pinned_digest
        self.attempted_digest = attempted_digest
        super().__init__(
            f"session {session_id!r} is pinned to {pinned_digest!r} and cannot "
            f"re-pin to {attempted_digest!r} — sessions serve one manifest for "
            "their lifetime"
        )


class UnknownSessionError(ReleaseError):
    """An operation named a session the fleet does not know. Fail closed:
    an un-pinned session has no manifest to resolve and no namespace to
    write into."""

    def __init__(self, session_id: str, operation: str) -> None:
        self.session_id = session_id
        super().__init__(
            f"session {session_id!r} is not pinned to this fleet — {operation} refused"
        )


class NamespaceViolationError(ReleaseError):
    """A candidate session attempted to write outside the candidate
    namespace — incumbent memory above all. Candidate state is namespaced
    precisely so a misbehaving candidate cannot corrupt the incumbent
    runtime it is being compared against."""

    def __init__(self, session_id: str, attempted_namespace: str, allowed_namespace: str) -> None:
        self.session_id = session_id
        self.attempted_namespace = attempted_namespace
        self.allowed_namespace = allowed_namespace
        super().__init__(
            f"session {session_id!r} (arm={allowed_namespace}) attempted to write "
            f"into the {attempted_namespace!r} namespace — candidate state is "
            "namespaced and incumbent memory is out of reach"
        )


class DigestReportingError(ReleaseError):
    """A worker reported a digest other than the one it resolves.

    Digest reporting is the fleet's honesty check (100% of reachable
    workers report the resolved digest): a report that contradicts the
    worker's own resolution is tampering, not telemetry."""

    def __init__(self, session_id: str, reported: str, resolved: str) -> None:
        self.session_id = session_id
        super().__init__(
            f"session {session_id!r} reported digest {reported!r} but resolves "
            f"{resolved!r} — refusing the contradictory report"
        )


class CanaryIneligibleError(ReleaseError):
    """A release's resolved artifact classes make it ineligible for canary
    admission (H6, §17.1 step 8).

    Only read-only or transactionally-reversible classes are canary-eligible:
    the harness's only undo is the pointer rollback, so a release that needs
    more than a pointer move to undo — executable content, harness or
    scaffold patches, direct memory writes — is refused before any canary
    machinery runs. The refusal carries the offending classes and the
    release-level refusals so the caller can see exactly what failed."""

    def __init__(self, ineligible_classes: Sequence[str], refusals: Sequence[str]) -> None:
        self.ineligible_classes = tuple(ineligible_classes)
        self.refusals = tuple(refusals)
        parts = [
            "canary admission refused — the release's resolved set is not "
            "canary-eligible (only read-only or transactionally-reversible "
            "classes are)"
        ]
        if self.ineligible_classes:
            parts.append("ineligible classes: " + ", ".join(self.ineligible_classes))
        parts.extend(self.refusals)
        super().__init__("; ".join(parts))


class InvalidCanaryConfigError(ReleaseError):
    """A canary configuration is malformed or below the §17.3 P0 thresholds.

    The thresholds (≥200 paired tasks, ≤5% candidate allocation, ≥24h
    observation) are floors, not defaults: a config below them would run a
    canary that cannot detect what it exists to detect, so it is refused
    at construction rather than run underpowered."""


__all__ = [
    "CanaryIneligibleError",
    "DigestReportingError",
    "InvalidCanaryConfigError",
    "NamespaceViolationError",
    "NoActiveReleaseError",
    "ReleaseError",
    "RollbackUnavailableError",
    "SessionPinError",
    "UnknownSessionError",
    "UnsignedManifestError",
]

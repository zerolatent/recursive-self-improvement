"""The release plane (deliverable E5): release controller, fixed-horizon
canary, atomic rollback, and FR-021 invalidation (PRD §9.2, FR-012,
FR-021).

The release controller is root-of-trust code, not a plugin: its workload
identity is the only one permitted to compare-and-swap the active release
pointer, and the signed ReleaseManifest is the atomic activation and
rollback unit. The fleet abstraction (resolve manifest, report digest,
pin session, invalidate caches) ships with an in-process simulator as
the reference implementation and test harness; real fleet wiring is
deployment-specific and out of scope for Phase 1.
"""

from __future__ import annotations

from evoruntime.release.canary import (
    MAX_CANDIDATE_ALLOCATION,
    MIN_OBSERVATION,
    MIN_PAIRED_TASKS,
    SEVERITY_1,
    CanaryConfig,
    CanaryHarness,
    CanaryOutcome,
    CanaryResult,
    GuardrailEvent,
)
from evoruntime.release.clock import CompressedClock, MonotonicClock, RealClock, WallClock
from evoruntime.release.controller import ReleaseController
from evoruntime.release.errors import (
    DigestReportingError,
    InvalidCanaryConfigError,
    NamespaceViolationError,
    NoActiveReleaseError,
    ReleaseError,
    RollbackUnavailableError,
    SessionPinError,
    UnknownSessionError,
    UnsignedManifestError,
)
from evoruntime.release.fleet import (
    CANDIDATE_NAMESPACE,
    INCUMBENT_NAMESPACE,
    DigestReport,
    FleetAdapter,
    InProcessFleetSimulator,
    SessionArm,
)
from evoruntime.release.invalidation import (
    DEFAULT_INVALIDATION_POLICY,
    InvalidationAction,
    InvalidationDecision,
    InvalidationSignal,
    InvalidationTrigger,
    ReleaseInvalidator,
    evaluate_invalidation,
    strongest_action,
)
from evoruntime.release.manifest import (
    SignedReleaseManifest,
    sign_release_manifest,
    verify_release_manifest,
)

__all__ = [
    "CANDIDATE_NAMESPACE",
    "DEFAULT_INVALIDATION_POLICY",
    "INCUMBENT_NAMESPACE",
    "MAX_CANDIDATE_ALLOCATION",
    "MIN_OBSERVATION",
    "MIN_PAIRED_TASKS",
    "SEVERITY_1",
    "CanaryConfig",
    "CanaryHarness",
    "CanaryOutcome",
    "CanaryResult",
    "CompressedClock",
    "DigestReport",
    "DigestReportingError",
    "FleetAdapter",
    "GuardrailEvent",
    "InProcessFleetSimulator",
    "InvalidCanaryConfigError",
    "InvalidationAction",
    "InvalidationDecision",
    "InvalidationSignal",
    "InvalidationTrigger",
    "MonotonicClock",
    "NamespaceViolationError",
    "NoActiveReleaseError",
    "RealClock",
    "ReleaseController",
    "ReleaseError",
    "ReleaseInvalidator",
    "RollbackUnavailableError",
    "SessionArm",
    "SessionPinError",
    "SignedReleaseManifest",
    "UnknownSessionError",
    "UnsignedManifestError",
    "WallClock",
    "evaluate_invalidation",
    "sign_release_manifest",
    "strongest_action",
    "verify_release_manifest",
]

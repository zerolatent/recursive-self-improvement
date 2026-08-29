"""The sandbox plane (Phase 2 F1): governed execution of candidate bytes.

No candidate bytes execute anywhere except inside the sandbox executor, at
the tier its manifest declares. The plane is a protocol, not a product:
:class:`IsolationBackend` is the seam, :class:`SubprocessIsolationBackend`
is the enforced reference implementation (subprocess + rlimits + Landlock +
seccomp, plus network namespaces where the host allows), and a production
gVisor/Firecracker backend implements the same contract as a deployment
concern — not a repo dependency.
"""

from __future__ import annotations

from evoruntime.core.isolation import IsolationTier
from evoruntime.sandbox.backend import IsolationBackend
from evoruntime.sandbox.egress import EgressBrokerProxy
from evoruntime.sandbox.executor import (
    SubprocessIsolationBackend,
    physical_enforcement_available,
)
from evoruntime.sandbox.profile import (
    CapturedPayload,
    CaptureError,
    EgressDenial,
    EnforcementRecord,
    ExecutionAttestation,
    ExecutionProfile,
    ExecutionRefusedError,
    ExecutionRequest,
    ExecutionResult,
    IsolationUnavailableError,
    PayloadRef,
    SandboxError,
    StagingError,
    TierEnforcement,
)
from evoruntime.sandbox.staging import PayloadReader, StagedWorkspace

__all__ = [
    "CapturedPayload",
    "CaptureError",
    "EgressBrokerProxy",
    "EgressDenial",
    "EnforcementRecord",
    "ExecutionAttestation",
    "ExecutionProfile",
    "ExecutionRefusedError",
    "ExecutionRequest",
    "ExecutionResult",
    "IsolationBackend",
    "IsolationTier",
    "IsolationUnavailableError",
    "PayloadReader",
    "PayloadRef",
    "SandboxError",
    "StagedWorkspace",
    "StagingError",
    "SubprocessIsolationBackend",
    "TierEnforcement",
    "physical_enforcement_available",
]

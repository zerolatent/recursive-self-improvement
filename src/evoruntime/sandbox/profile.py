"""Sandbox execution contracts: profiles, requests, results, attestations.

These are the data contracts of the isolation boundary (spec: "Sandbox
depth: a protocol, not a product"). The manifest *declares* what a run
needs — tier, network posture, limits — and :class:`ExecutionProfile`
carries that declaration to a backend. Nothing here grants capability: a
profile is a ceiling the backend must enforce physically, and the
:class:`ExecutionAttestation` is the durable, digest-bound record of what
was actually enforced and what was denied.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import PurePosixPath

from pydantic import Field, model_validator

from evoruntime.core.isolation import IsolationTier
from evoruntime.core.schemas import EvoRuntimeBaseModel
from evoruntime.plugins.manifest import NetworkMode, ResourceLimits
from evoruntime.security.egress import EgressPolicy

# Bounded output capture: a candidate that floods stdout must not flood the
# runtime's memory with it.
MAX_CAPTURED_OUTPUT_BYTES = 64 * 1024


class SandboxError(Exception):
    """Base class for sandbox-plane failures."""


class StagingError(SandboxError):
    """Candidate bytes could not be staged faithfully from the payload store."""


class CaptureError(SandboxError):
    """The mutated workspace could not be captured faithfully after a run."""


class ExecutionRefusedError(SandboxError):
    """The requested execution is refused before any process is spawned."""


class IsolationUnavailableError(ExecutionRefusedError):
    """The platform cannot provide the physical enforcement the tier demands.

    Fail-closed by design: a tier that cannot be enforced physically is
    never executed under weaker enforcement — the run is refused instead.
    """


class PayloadRef(EvoRuntimeBaseModel):
    """One candidate file to stage, addressed by content digest.

    ``path`` is relative to the staged workspace root; the executor validates
    its shape (no absolute paths, no traversal) before any byte is written.
    """

    path: str = Field(min_length=1)
    digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _relative_path(self) -> PayloadRef:
        _validate_workspace_relative_path(self.path, what="payload path")
        return self


def _validate_workspace_relative_path(path: str, *, what: str) -> None:
    """Reject absolute, traversal-containing, or empty workspace-relative paths.

    Pure shape check shared by every workspace-addressed field (payload refs,
    capture paths, write zones) so one rule governs all of them.
    """
    parts = PurePosixPath(path).parts
    if path.startswith("/") or ".." in parts or not parts:
        raise ValueError(f"{what} {path!r} must be relative and traversal-free")


class ExecutionProfile(EvoRuntimeBaseModel):
    """The isolation ceiling a run is executed under.

    ``network_mode`` and ``resource_limits`` reuse the manifest's own
    vocabulary (:mod:`evoruntime.plugins.manifest`) so a profile can be
    projected straight from a validated manifest. Limits declared here are
    enforced at spawn — they are never advisory.
    """

    tier: IsolationTier
    network_mode: NetworkMode = NetworkMode.NONE
    resource_limits: ResourceLimits
    readonly_mounts: tuple[str, ...] = Field(default=())
    # Layered write zoning (G5): when set, Landlock grants write access only
    # beneath these workspace-relative directories — scaffold-source writes
    # and workspace scratch are separated, so a mutated scaffold cannot
    # overwrite its own evaluation fixtures. Empty = the whole workspace is
    # writable (the Phase 2 F1 behavior).
    writable_paths: tuple[str, ...] = Field(default=())
    # Privileged syscalls are audited and only meaningful for the tiers that
    # execute harness-touching code.
    allow_privileged_syscalls: bool = False

    @model_validator(mode="after")
    def _tier_matches_network(self) -> ExecutionProfile:
        if self.tier is IsolationTier.BROKERED:
            if self.network_mode is not NetworkMode.BROKERED:
                raise ValueError("tier brokered requires network_mode=brokered")
        elif self.network_mode is not NetworkMode.NONE:
            raise ValueError(
                f"tier {self.tier.value} runs with no network by default; "
                "brokered egress is a brokered-tier capability"
            )
        for zone in self.writable_paths:
            _validate_workspace_relative_path(zone, what="writable path")
        return self


class ExecutionRequest(EvoRuntimeBaseModel):
    """One request to execute candidate bytes under a declared profile.

    The command runs with the staged workspace as its working directory and
    a scrubbed environment; candidate bytes enter only via ``payloads``,
    staged from the E1 payload store and digest-verified on the way in.
    """

    tenant_id: str = Field(min_length=1)
    # Digest-pinned image the run declares (from the manifest's
    # reproducibility block) — bound into the attestation.
    image_digest: str = Field(pattern=r"^\S+@sha256:[0-9a-f]{64}$")
    command: tuple[str, ...] = Field(min_length=1)
    profile: ExecutionProfile
    payloads: tuple[PayloadRef, ...] = Field(default=())
    # Deny-by-default: an empty allowlist (the default) denies every
    # destination at the broker.
    egress_policy: EgressPolicy = Field(default_factory=EgressPolicy)
    # Workspace-relative paths to capture from the mutated workspace after
    # the run (G5): the harness's mutate stage declares what the mutated
    # scaffold produced; the backend extracts those files digest-verified
    # before the workspace is torn down. Empty = capture nothing.
    capture_paths: tuple[str, ...] = Field(default=())

    @model_validator(mode="after")
    def _capture_paths_are_workspace_relative(self) -> ExecutionRequest:
        for path in self.capture_paths:
            _validate_workspace_relative_path(path, what="capture path")
        return self


class CapturedPayload(EvoRuntimeBaseModel):
    """One file captured from the mutated workspace after a run.

    Symmetric with :class:`PayloadRef`: ``digest`` is computed over the exact
    ``content`` bytes at capture time, so the captured bytes are bound to
    their digest the moment they leave the workspace — re-staging them
    reproduces the same digest (proposed = executed = registered bytes).
    """

    path: str = Field(min_length=1)
    digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    content: bytes


class EgressDenial(EvoRuntimeBaseModel):
    """One physically observed egress denial, bound into the attestation."""

    destination: str
    host: str
    reason: str


class TierEnforcement(StrEnum):
    """Which backend class enforced this execution.

    ``REFERENCE`` is the in-CI subprocess backend. A production microVM
    backend (gVisor/Firecracker) implements the same
    :class:`IsolationBackend` protocol and records its own class here — the
    attestation stays honest about *what* enforced the tier, and consumers
    can distinguish reference enforcement from production enforcement.
    """

    REFERENCE = "reference"


class EnforcementRecord(EvoRuntimeBaseModel):
    """Which physical mechanisms were active for this execution.

    Schema v2 (G5) adds the tier-4 mechanisms: ``write_zone_applied``
    (layered Landlock write zoning was active), ``syscall_denylist`` (the
    escalation-primitive syscalls denied by seccomp — populated on the
    HIGHEST tier, empty below it), and ``tier_enforcement`` (the backend
    class that enforced the run).
    """

    rlimits_applied: bool
    network_filter_applied: bool
    filesystem_contained: bool
    network_namespace: bool
    broker_proxy: bool
    write_zone_applied: bool = False
    syscall_denylist: tuple[str, ...] = Field(default=())
    tier_enforcement: TierEnforcement = TierEnforcement.REFERENCE


class ExecutionAttestation(EvoRuntimeBaseModel):
    """The durable record of one sandboxed execution.

    Digest-bound via the checkpoint pattern: the attestation's serialized
    bytes are stored content-addressed, so the digest binds image, tier,
    egress denials, and exit together — any later tampering is detectable by
    re-digesting.
    """

    # v2 (G5): adds enforcement.write_zone_applied / syscall_denylist /
    # tier_enforcement and the captured-payload digest set.
    schema_version: int = 2
    execution_id: str = Field(min_length=1)
    tenant_id: str = Field(min_length=1)
    image_digest: str = Field(min_length=1)
    tier: IsolationTier
    network_mode: NetworkMode
    resource_limits: ResourceLimits
    egress_denials: tuple[EgressDenial, ...] = Field(default=())
    exit_code: int | None = None
    signal_name: str | None = None
    timed_out: bool = False
    staged_payloads: tuple[PayloadRef, ...] = Field(default=())
    # Digest set of the files captured from the mutated workspace (G5) —
    # binds "what the run produced" into the same tamper-evident record.
    captured: tuple[PayloadRef, ...] = Field(default=())
    enforcement: EnforcementRecord
    allow_privileged_syscalls: bool = False


class ExecutionResult(EvoRuntimeBaseModel):
    """What one sandboxed execution produced, plus its bound attestation."""

    attestation: ExecutionAttestation
    # Content address of the attestation bytes in the checkpoint store.
    attestation_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = Field(ge=0)
    # Bytes captured from the mutated workspace, digest-verified at capture
    # time. Empty unless the request declared ``capture_paths``.
    captured: tuple[CapturedPayload, ...] = Field(default=())

    # Convenience views over the attestation — the exit facts live there so
    # every consumer reads the same digest-bound record.
    @property
    def exit_code(self) -> int | None:
        return self.attestation.exit_code

    @property
    def signal_name(self) -> str | None:
        return self.attestation.signal_name

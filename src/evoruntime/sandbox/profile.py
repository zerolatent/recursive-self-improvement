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


class ExecutionRefusedError(SandboxError):
    """The requested execution is refused before any process is spawned."""


class IsolationUnavailableError(ExecutionRefusedError):
    """The platform cannot provide the physical enforcement the tier demands.

    Fail-closed by design: a tier that cannot be enforced physically is
    never executed under weaker enforcement — the run is refused instead.
    """


class StagingError(SandboxError):
    """Candidate bytes could not be staged faithfully from the payload store."""


class PayloadRef(EvoRuntimeBaseModel):
    """One candidate file to stage, addressed by content digest.

    ``path`` is relative to the staged workspace root; the executor validates
    its shape (no absolute paths, no traversal) before any byte is written.
    """

    path: str = Field(min_length=1)
    digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _relative_path(self) -> PayloadRef:
        parts = PurePosixPath(self.path).parts
        if self.path.startswith("/") or ".." in parts or not parts:
            raise ValueError(f"payload path {self.path!r} must be relative and traversal-free")
        return self


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


class EgressDenial(EvoRuntimeBaseModel):
    """One physically observed egress denial, bound into the attestation."""

    destination: str
    host: str
    reason: str


class EnforcementRecord(EvoRuntimeBaseModel):
    """Which physical mechanisms were active for this execution."""

    rlimits_applied: bool
    network_filter_applied: bool
    filesystem_contained: bool
    network_namespace: bool
    broker_proxy: bool


class ExecutionAttestation(EvoRuntimeBaseModel):
    """The durable record of one sandboxed execution.

    Digest-bound via the checkpoint pattern: the attestation's serialized
    bytes are stored content-addressed, so the digest binds image, tier,
    egress denials, and exit together — any later tampering is detectable by
    re-digesting.
    """

    schema_version: int = 1
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

    # Convenience views over the attestation — the exit facts live there so
    # every consumer reads the same digest-bound record.
    @property
    def exit_code(self) -> int | None:
        return self.attestation.exit_code

    @property
    def signal_name(self) -> str | None:
        return self.attestation.signal_name

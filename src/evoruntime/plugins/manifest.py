"""Plugin manifest schema (PRD §10.4).

A manifest is the plugin's *declaration*, not its authority. Every field it
carries is a request: the effective grant a plugin receives is the
intersection of what it asks for with tenant, campaign, artifact, runtime,
tool, and authority policy (:func:`effective_grant`). Nothing in this
module ever widens a request.

The manifest also pins compatibility and reproducibility: a plugin declares
the runtime versions it works with and the image it must be run under, so
admission can refuse a floating, unreproducible plugin before it ever
starts.
"""

from __future__ import annotations

import re
from enum import StrEnum

from pydantic import Field, field_validator, model_validator

from evoruntime.core.schemas import EvoRuntimeBaseModel


# The five Phase 1 low-risk artifact classes (spec: "Phase 1 closes that gap
# for the low-risk artifact classes"). Executable skill scripts, workflow
# graphs, tool specs, and harness patches are Phase 2 and are deliberately
# absent — a manifest cannot declare what Phase 1 must never admit.
class PluginArtifactType(StrEnum):
    """Artifact classes a Phase 1 plugin may declare."""

    MEMORY_ENTRY = "memory_entry"
    PROMPT_BUNDLE = "prompt_bundle"
    DEMONSTRATION_SET = "demonstration_set"
    COMPILED_PROMPT_PROGRAM = "compiled_prompt_program"
    SKILL_PACKAGE = "skill_package"


class PluginKind(StrEnum):
    """Which §10 process contract the plugin implements."""

    STRATEGY = "strategy"
    ADAPTER = "adapter"


class NetworkMode(StrEnum):
    """Requested network posture.

    ``NONE`` means no direct egress *and* no free model calls — model
    traffic still flows only through the Phase 0 egress broker with field
    allowlists and quotas. ``BROKERED`` additionally requests brokered
    model routes for the explicitly listed hosts.
    """

    NONE = "none"
    BROKERED = "brokered"


class PluginEntrypoint(EvoRuntimeBaseModel):
    """How the runtime spawns the plugin process.

    Phase 1 ships exactly one transport (stdio JSON-RPC — see
    :mod:`evoruntime.plugins.protocol` for why it beats gRPC here); the
    literal keeps the schema honest until a second transport exists.
    """

    transport: str = Field(pattern=r"^stdio-jsonrpc$")
    command: tuple[str, ...] = Field(min_length=1)


class PermissionRequest(EvoRuntimeBaseModel):
    """What the plugin *asks* for. Never what it gets."""

    network: NetworkMode = NetworkMode.NONE
    model_access: bool = False
    # Exact hosts for brokered model routes — matched by the egress broker,
    # which does exact (never suffix/wildcard) host matching.
    model_hosts: tuple[str, ...] = Field(default=())
    # Read-only filesystem scopes the plugin claims it needs.
    filesystem_read: tuple[str, ...] = Field(default=())
    tools: tuple[str, ...] = Field(default=())


class EffectiveGrant(EvoRuntimeBaseModel):
    """The intersection of a permission request with every policy plane."""

    network: NetworkMode
    model_access: bool
    model_hosts: tuple[str, ...] = Field(default=())
    filesystem_read: tuple[str, ...] = Field(default=())
    tools: tuple[str, ...] = Field(default=())


class ResourceLimits(EvoRuntimeBaseModel):
    """Externally enforced ceilings (PRD §10.4 limits)."""

    wall_clock_minutes: float = Field(gt=0)
    cpu: float = Field(gt=0, description="CPU cores.")
    memory_gib: float = Field(gt=0)
    model_tokens: int = Field(ge=0)
    proposals: int = Field(ge=1)


class Reproducibility(EvoRuntimeBaseModel):
    """What makes a plugin run reproducible — pinned image, fixed seed."""

    # Digest-pinned container image (name@sha256:...). A floating tag is a
    # supply-chain hole, so the validator rejects anything else.
    pinned_image: str
    deterministic: bool = True
    seed: int | None = None

    @field_validator("pinned_image")
    @classmethod
    def _require_digest_pin(cls, value: str) -> str:
        if "@sha256:" not in value:
            raise ValueError(
                f"pinned_image {value!r} must be digest-pinned (name@sha256:...) — "
                "floating tags are not reproducible"
            )
        return value


class CompatibilityRange(EvoRuntimeBaseModel):
    """Inclusive runtime-version range the plugin was built against."""

    min_runtime: str
    max_runtime: str | None = None

    @model_validator(mode="after")
    def _ordered(self) -> CompatibilityRange:
        if self.max_runtime is not None and _parse_version(self.max_runtime) < _parse_version(
            self.min_runtime
        ):
            raise ValueError("max_runtime must not be lower than min_runtime")
        return self


_VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


def _parse_version(version: str) -> tuple[int, int, int]:
    match = _VERSION_RE.match(version)
    if not match:
        raise ValueError(f"runtime version {version!r} must be X.Y.Z")
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def check_compatibility(compatibility: CompatibilityRange, runtime_version: str) -> bool:
    """True when ``runtime_version`` falls inside the declared range."""
    current = _parse_version(runtime_version)
    return _parse_version(compatibility.min_runtime) <= current and (
        compatibility.max_runtime is None or current <= _parse_version(compatibility.max_runtime)
    )


class PluginManifest(EvoRuntimeBaseModel):
    """The §10.4 manifest: entrypoint, types, permissions, limits, reproducibility."""

    schema_version: int = 1
    plugin_id: str = Field(min_length=1, pattern=r"^[a-z0-9][a-z0-9-]*$")
    version: str = Field(min_length=1)
    kind: PluginKind
    entrypoint: PluginEntrypoint
    artifact_types: tuple[PluginArtifactType, ...] = Field(min_length=1)
    compatibility: CompatibilityRange
    permissions: PermissionRequest = Field(default_factory=PermissionRequest)
    limits: ResourceLimits
    reproducibility: Reproducibility

    @model_validator(mode="after")
    def _consistent(self) -> PluginManifest:
        if self.permissions.network is NetworkMode.BROKERED:
            if not self.permissions.model_access:
                raise ValueError("network=brokered requires model_access=true")
            if not self.permissions.model_hosts:
                raise ValueError("network=brokered requires an explicit model_hosts allowlist")
        return self


def validate_manifest(manifest: PluginManifest, runtime_version: str) -> tuple[str, ...]:
    """Admission-time checks beyond schema validation.

    Returns the (possibly empty) tuple of human-readable problems; an empty
    tuple means the manifest is admissible against ``runtime_version``.
    """
    problems: list[str] = []
    if not check_compatibility(manifest.compatibility, runtime_version):
        max_runtime = manifest.compatibility.max_runtime or "unbounded"
        problems.append(
            f"runtime {runtime_version} is outside the declared compatibility range "
            f"[{manifest.compatibility.min_runtime}, {max_runtime}]"
        )
    if manifest.reproducibility.deterministic and manifest.reproducibility.seed is None:
        problems.append(
            "deterministic plugins must declare a seed; set deterministic=false "
            "if the strategy is genuinely nondeterministic"
        )
    return tuple(problems)


def effective_grant(requested: PermissionRequest, *policies: PermissionRequest) -> EffectiveGrant:
    """Intersect the plugin's request with every policy plane.

    Each ``policies`` entry is a plane's ceiling (tenant, campaign, artifact,
    runtime, tool, authority — PRD §10.4). The grant is the intersection:
    a capability survives only if every plane allows it. Network mode takes
    the most restrictive value; boolean capabilities AND; host/scope lists
    intersect.
    """
    planes = (requested, *policies)
    network = (
        NetworkMode.NONE
        if any(p.network is NetworkMode.NONE for p in planes)
        else (NetworkMode.BROKERED)
    )
    return EffectiveGrant(
        network=network,
        model_access=all(p.model_access for p in planes),
        model_hosts=_intersect(planes, "model_hosts"),
        filesystem_read=_intersect(planes, "filesystem_read"),
        tools=_intersect(planes, "tools"),
    )


def _intersect(planes: tuple[PermissionRequest, ...], field: str) -> tuple[str, ...]:
    values = [set(getattr(p, field)) for p in planes]
    common = set.intersection(*values) if values else set()
    return tuple(sorted(common))

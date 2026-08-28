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

from evoruntime.core.isolation import IsolationTier
from evoruntime.core.schemas import EvoRuntimeBaseModel


# The five Phase 1 low-risk artifact classes, plus the five Phase 2
# executable classes (F2). The executable classes are admissible only with
# declared execution requirements (see :class:`ExecutionRequirements`) and
# only through the Phase 2 tier gate — declaring the type in a manifest is
# a request, never an authority.
class PluginArtifactType(StrEnum):
    """Artifact classes a plugin may declare."""

    MEMORY_ENTRY = "memory_entry"
    PROMPT_BUNDLE = "prompt_bundle"
    DEMONSTRATION_SET = "demonstration_set"
    COMPILED_PROMPT_PROGRAM = "compiled_prompt_program"
    SKILL_PACKAGE = "skill_package"

    # Phase 2 executable classes (PRD §13.3 tier mapping: the first four
    # resolve to tier 3, harness_patch to tier 4).
    WORKFLOW_GRAPH = "workflow_graph"
    TOOL_SPEC = "tool_spec"
    SKILL_SCRIPT = "skill_script"
    ALGORITHM = "algorithm"
    HARNESS_PATCH = "harness_patch"


#: Classes whose members execute at runtime. A manifest declaring any of
#: them must also declare :class:`ExecutionRequirements` — an executable
#: artifact without declared executables and a minimum isolation tier is
#: refused at the schema boundary, before any policy plane sees it.
EXECUTABLE_ARTIFACT_TYPES: frozenset[PluginArtifactType] = frozenset(
    {
        PluginArtifactType.WORKFLOW_GRAPH,
        PluginArtifactType.TOOL_SPEC,
        PluginArtifactType.SKILL_SCRIPT,
        PluginArtifactType.ALGORITHM,
        PluginArtifactType.HARNESS_PATCH,
    }
)


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


class ExecutionRequirements(EvoRuntimeBaseModel):
    """What running the manifest's executable classes requires (F2).

    Declared per manifest, not per class: the executables are the entry
    points the sandbox executor may spawn, and ``minimum_tier`` is the
    floor isolation tier (1–4) under which they may run. Both are
    mandatory — an executable class with no declared executables or no
    minimum tier cannot be admitted, because "run it somewhere, anywhere"
    is not an isolation declaration.
    """

    executables: tuple[str, ...] = Field(min_length=1)
    """Executable entries the executor may spawn (paths or entry names)."""

    minimum_tier: int = Field(ge=1, le=4)
    """Minimum sandbox isolation tier (1 = loosest … 4 = strictest)."""


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
    execution_requirements: ExecutionRequirements | None = None
    # The isolation tier the plugin's entrypoint runs under (Phase 2 F1).
    # Defaults to ``executable`` so Phase 1 manifests (subprocess + rlimits,
    # no network) validate unchanged; the validator cross-checks the tier
    # against the declared execution requirements below.
    isolation_tier: IsolationTier = IsolationTier.EXECUTABLE

    @model_validator(mode="after")
    def _consistent(self) -> PluginManifest:
        if self.permissions.network is NetworkMode.BROKERED:
            if not self.permissions.model_access:
                raise ValueError("network=brokered requires model_access=true")
            if not self.permissions.model_hosts:
                raise ValueError("network=brokered requires an explicit model_hosts allowlist")
        executable_types = sorted(
            t.value for t in self.artifact_types if t in EXECUTABLE_ARTIFACT_TYPES
        )
        if executable_types and self.execution_requirements is None:
            raise ValueError(
                "artifact types " + ", ".join(executable_types) + " are executable and "
                "require declared execution_requirements (executables + minimum_tier)"
            )
        self._cross_check_tier()
        return self

    def _cross_check_tier(self) -> None:
        """The declared tier must agree with the declared execution needs.

        A tier is a promise about what the entrypoint may do; a manifest
        whose tier contradicts its own permission request is incoherent and
        is rejected at parse time, not at spawn time.

        Phase 1 manifests predate this field and do not declare it; their
        network posture already governs execution, so the strict tier
        cross-check applies only when the tier is explicit.
        """
        if "isolation_tier" not in self.model_fields_set:
            return
        network = self.permissions.network
        if self.isolation_tier is IsolationTier.TEXT_ONLY:
            # Nothing executes, so nothing may request a network path.
            if network is not NetworkMode.NONE or self.permissions.model_access:
                raise ValueError(
                    "isolation_tier=text-only never executes; it cannot request "
                    "network access or model calls"
                )
        elif self.isolation_tier is IsolationTier.BROKERED:
            if network is not NetworkMode.BROKERED or not self.permissions.model_hosts:
                raise ValueError(
                    "isolation_tier=brokered requires network=brokered with an "
                    "explicit model_hosts allowlist"
                )
        else:
            # executable / highest: candidate bytes run, but with no direct
            # network path — model traffic, if any, flows only through the
            # broker, which the brokered tier declares.
            if network is not NetworkMode.NONE:
                raise ValueError(
                    f"isolation_tier={self.isolation_tier.value} provides no direct "
                    "network path; declare network=none (use the brokered tier for "
                    "brokered model routes)"
                )


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

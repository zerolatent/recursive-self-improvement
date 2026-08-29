"""Shared plumbing for the F11 research plugins (PRD §16.5).

One place for what the research plugins share: the manifest shape
(strategy kind, stdio JSON-RPC entrypoint, digest-pinned image, fixed
seed) extended with the F2 execution requirements every plugin must
declare — their outputs are executable classes, and an executable class
without declared executables and a minimum isolation tier is refused at
the manifest schema boundary before any policy plane sees it. The
minimum tier is per artifact class (G9): tier 3 for the Phase 2 search
classes, tier 4 for the Phase 3 scaffold class. Per-plugin behavior
lives in the plugin modules; nothing here knows about workflow graphs
or archives.



**Why the plugins live inside the installed package.** Same rationale
as the E7 reference plugins (:mod:`evoruntime.plugins.reference._base`):
the research plugins are untrusted *by contract* (they run as
subprocesses under manifest limits with a scrubbed environment) even
though they are first-party code. Shipping them as modules of
``evoruntime.plugins.research`` means the manifest entrypoint
``python -m evoruntime.plugins.research.<name>`` resolves under any
interpreter that has the package installed. A deployment that wants
them out-of-tree replaces the manifest's entrypoint command; nothing
else changes.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from evoruntime.core.isolation import IsolationTier
from evoruntime.plugins.manifest import (
    CompatibilityRange,
    ExecutionRequirements,
    NetworkMode,
    PermissionRequest,
    PluginArtifactType,
    PluginEntrypoint,
    PluginKind,
    PluginManifest,
    Reproducibility,
    ResourceLimits,
)
from evoruntime.plugins.protocol import serve

#: Runtime version the research plugins are built and conformance-tested
#: against. Keep in sync with tests/plugins/support.py RUNTIME_VERSION.
PLUGIN_RUNTIME_VERSION = "1.0.0"

#: Digest-pinned image the release pipeline publishes the research
#: plugins under. The manifest is a *declaration*: admission refuses a
#: floating tag, and the publish job pins the built archive's digest
#: here before the plugins are admitted anywhere.
RESEARCH_IMAGE_DIGEST = "sha256:" + "f11" * 21 + "a"

#: Sandbox isolation floor per executable artifact class (G9). The Phase 2
#: research classes are PRD §13.3 tier-3 classes — their candidates run
#: under the strict namespace-isolated profile. The Phase 3 scaffold class
#: is harness-touching whole-tree code (G1): its candidates execute only
#: at the strictest tier, so a research plugin proposing scaffolds demands
#: tier 4. A manifest's minimum tier is the max over its declared classes
#: — declaring a tier-4 class anywhere in the manifest raises the floor
#: for the whole plugin.
RESEARCH_MINIMUM_TIERS: Mapping[PluginArtifactType, int] = MappingProxyType(
    {
        PluginArtifactType.WORKFLOW_GRAPH: 3,
        PluginArtifactType.TOOL_SPEC: 3,
        PluginArtifactType.SKILL_SCRIPT: 3,
        PluginArtifactType.ALGORITHM: 3,
        PluginArtifactType.HARNESS_PATCH: 4,
        PluginArtifactType.SCAFFOLD: 4,
    }
)


def minimum_tier_for(artifact_types: tuple[PluginArtifactType, ...]) -> int:
    """The isolation floor for a manifest declaring ``artifact_types``.

    The maximum over the declared classes' per-class minimums — a
    manifest is admitted once for all its outputs, so its floor is the
    strictest any of them demands. Pure and total: an unknown class has
    no floor and cannot appear in a manifest (the enum refuses it).
    """
    return max(RESEARCH_MINIMUM_TIERS[t] for t in artifact_types)


def build_research_manifest(
    *,
    plugin_id: str,
    version: str,
    module: str,
    artifact_types: tuple[PluginArtifactType, ...],
    limits: ResourceLimits,
    seed: int,
    executables: tuple[str, ...],
    permissions: PermissionRequest | None = None,
    isolation_tier: IsolationTier | None = None,
) -> PluginManifest:
    """Build the §10.4 manifest every research plugin ships with.

    The default permission request is deliberately empty of capability:
    network ``none`` and no model access. The egress broker
    (:mod:`evoruntime.security.egress`) is the sole network path for any
    plugin traffic. A plugin that needs brokered model routes passes its
    own request — still ``network=none`` (no direct egress), with
    ``model_access=True`` and an explicit ``model_hosts`` allowlist the
    broker matches exactly (G9: the harness-mutator's posture).

    ``executables`` feeds the F2 :class:`ExecutionRequirements` —
    mandatory here because every declared artifact type is an executable
    class, and the manifest validator refuses an executable class
    without declared executables and a minimum tier. The minimum tier is
    derived per class (:func:`minimum_tier_for`): the Phase 2 research
    classes sit at tier 3, the Phase 3 scaffold class at tier 4 (G9).
    """
    return PluginManifest(
        plugin_id=plugin_id,
        version=version,
        kind=PluginKind.STRATEGY,
        entrypoint=PluginEntrypoint(
            transport="stdio-jsonrpc",
            command=("python", "-m", f"evoruntime.plugins.research.{module}"),
        ),
        artifact_types=artifact_types,
        compatibility=CompatibilityRange(min_runtime=PLUGIN_RUNTIME_VERSION),
        permissions=permissions or PermissionRequest(network=NetworkMode.NONE, model_access=False),
        isolation_tier=isolation_tier or IsolationTier.EXECUTABLE,
        limits=limits,
        reproducibility=Reproducibility(
            pinned_image=f"ghcr.io/zerolatent/{plugin_id}@{RESEARCH_IMAGE_DIGEST}",
            deterministic=True,
            seed=seed,
        ),
        execution_requirements=ExecutionRequirements(
            executables=executables, minimum_tier=minimum_tier_for(artifact_types)
        ),
    )


def run_research_plugin(handler: Any) -> None:
    """Serve one research plugin over stdio JSON-RPC until stdin closes."""
    serve(handler)

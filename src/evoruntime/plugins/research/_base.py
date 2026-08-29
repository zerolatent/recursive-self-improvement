"""Shared plumbing for the F11 research plugins (PRD §16.5).

One place for what both research plugins share: the manifest shape
(strategy kind, stdio JSON-RPC entrypoint, no network, digest-pinned
image, fixed seed) extended with the F2 execution requirements both
plugins must declare — their outputs are executable classes, and an
executable class without declared executables and a minimum isolation
tier is refused at the manifest schema boundary before any policy plane
sees it. Per-plugin behavior lives in the plugin modules; nothing here
knows about workflow graphs or archives.

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

from typing import Any

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

#: Sandbox isolation floor for the research plugins' executable outputs.
#: workflow_graph and algorithm are PRD §13.3 tier-3 classes; their
#: candidates run only under the strict namespace-isolated profile.
RESEARCH_MINIMUM_TIER = 3


def build_research_manifest(
    *,
    plugin_id: str,
    version: str,
    module: str,
    artifact_types: tuple[PluginArtifactType, ...],
    limits: ResourceLimits,
    seed: int,
    executables: tuple[str, ...],
) -> PluginManifest:
    """Build the §10.4 manifest every research plugin ships with.

    The permission request is deliberately empty of capability: network
    ``none`` and no model access. The egress broker
    (:mod:`evoruntime.security.egress`) is the sole network path for any
    plugin traffic, and a research plugin has none to make.

    ``executables`` feeds the F2 :class:`ExecutionRequirements` —
    mandatory here because every declared artifact type is an executable
    class, and the manifest validator refuses an executable class
    without declared executables and a minimum tier.
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
        permissions=PermissionRequest(network=NetworkMode.NONE, model_access=False),
        limits=limits,
        reproducibility=Reproducibility(
            pinned_image=f"ghcr.io/zerolatent/{plugin_id}@{RESEARCH_IMAGE_DIGEST}",
            deterministic=True,
            seed=seed,
        ),
        execution_requirements=ExecutionRequirements(
            executables=executables, minimum_tier=RESEARCH_MINIMUM_TIER
        ),
    )


def run_research_plugin(handler: Any) -> None:
    """Serve one research plugin over stdio JSON-RPC until stdin closes."""
    serve(handler)

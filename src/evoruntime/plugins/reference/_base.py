"""Shared plumbing for the E7 reference plugins (PRD §16).

One place for what all four plugins share: the manifest shape (strategy
kind, stdio JSON-RPC entrypoint, no network, digest-pinned image, fixed
seed) and the plugin-process entrypoint. Per-plugin behavior lives in the
plugin modules; nothing here knows about memory entries or prompt bundles.

**Why the plugins live inside the installed package.** The reference
plugins are untrusted *by contract* (they run as subprocesses under
manifest limits with a scrubbed environment) even though they are
first-party code. Shipping them as modules of ``evoruntime.plugins.reference``
means the manifest entrypoint ``python -m evoruntime.plugins.reference.<name>``
resolves under any interpreter that has the package installed, and the E2
conformance and packaging machinery is importable by their tests without
path gymnastics. A deployment that wants them out-of-tree replaces the
manifest's entrypoint command; nothing else changes.
"""

from __future__ import annotations

from typing import Any

from evoruntime.plugins.manifest import (
    CompatibilityRange,
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

#: Runtime version the reference plugins are built and conformance-tested
#: against. Keep in sync with tests/plugins/support.py RUNTIME_VERSION.
PLUGIN_RUNTIME_VERSION = "1.0.0"

#: Digest-pinned image the release pipeline publishes the four plugins
#: under. The manifest is a *declaration*: admission refuses a floating
#: tag, and the publish job pins the built archive's digest here before
#: the plugins are admitted anywhere.
REFERENCE_IMAGE_DIGEST = "sha256:" + "e7" * 32


def build_reference_manifest(
    *,
    plugin_id: str,
    version: str,
    module: str,
    artifact_types: tuple[PluginArtifactType, ...],
    limits: ResourceLimits,
    seed: int,
) -> PluginManifest:
    """Build the §10.4 manifest every reference plugin ships with.

    The permission request is deliberately empty of capability: network
    ``none`` and no model access. The egress broker
    (:mod:`evoruntime.security.egress`) is the sole network path for any
    plugin traffic, and a reference plugin has none to make.
    """
    return PluginManifest(
        plugin_id=plugin_id,
        version=version,
        kind=PluginKind.STRATEGY,
        entrypoint=PluginEntrypoint(
            transport="stdio-jsonrpc",
            command=("python", "-m", f"evoruntime.plugins.reference.{module}"),
        ),
        artifact_types=artifact_types,
        compatibility=CompatibilityRange(min_runtime=PLUGIN_RUNTIME_VERSION),
        permissions=PermissionRequest(network=NetworkMode.NONE, model_access=False),
        limits=limits,
        reproducibility=Reproducibility(
            pinned_image=f"ghcr.io/zerolatent/{plugin_id}@{REFERENCE_IMAGE_DIGEST}",
            deterministic=True,
            seed=seed,
        ),
    )


def run_reference_plugin(handler: Any) -> None:
    """Serve one reference plugin over stdio JSON-RPC until stdin closes."""
    serve(handler)

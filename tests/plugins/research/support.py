"""Shared helpers for the F11 research-plugin test suite.

Mirrors ``tests/plugins/reference/support.py``: every conformance and
behavior test drives the real plugin subprocess
(``python -m evoruntime.plugins.research.<module>``) through the E2
runtime clients, with evaluation feedback produced by the deterministic
ScriptedAgent — no live-model calls anywhere (locked decision #9).
"""

from __future__ import annotations

import importlib
import sys
from typing import Any

from evoruntime.plugins.manifest import PluginManifest, validate_manifest
from evoruntime.plugins.protocol import (
    InMemoryCheckpointStore,
    ReadOnlyCampaignContext,
    RedactedEvidenceBundle,
    RemainingBudget,
    StdioJsonRpcTransport,
    StrategyPluginClient,
    clean_plugin_env,
)
from tests.plugins.support import RUNTIME_VERSION

#: (module name, declared artifact type for the campaign context, mutable
#: paths the campaign exposes). In PRD §16.5 order.
RESEARCH_PLUGIN_PARAMS: list[tuple[str, str, tuple[str, ...]]] = [
    ("workflow_graph_search", "workflow_graph", ("workflow/",)),
    ("evolutionary_artifact_search", "algorithm", ("algorithm/",)),
]

RESEARCH_MODULE_NAMES = [name for name, _, _ in RESEARCH_PLUGIN_PARAMS]


def plugin_command(module_name: str) -> tuple[str, ...]:
    """The subprocess command — matches the manifest entrypoint module path."""
    return (sys.executable, "-m", f"evoruntime.plugins.research.{module_name}")


def plugin_env() -> dict[str, str]:
    """The scrubbed environment a runtime would spawn the plugin with."""
    return clean_plugin_env()


def plugin_context(artifact_type: str, mutable_paths: tuple[str, ...]) -> ReadOnlyCampaignContext:
    return ReadOnlyCampaignContext(
        campaign_id="camp-f11",
        artifact_type=artifact_type,
        mutable_paths=mutable_paths,
        runtime_version=RUNTIME_VERSION,
    )


def make_budget(proposals_remaining: int = 5) -> RemainingBudget:
    return RemainingBudget(
        proposals_remaining=proposals_remaining,
        wall_clock_minutes_remaining=10.0,
        model_tokens_remaining=0,
    )


def strategy_client(module_name: str) -> tuple[StrategyPluginClient, InMemoryCheckpointStore]:
    transport = StdioJsonRpcTransport(plugin_command(module_name), env=plugin_env())
    store = InMemoryCheckpointStore()
    return StrategyPluginClient(transport, checkpoint_store=store), store


def load_plugin_module(module_name: str) -> Any:
    return importlib.import_module(f"evoruntime.plugins.research.{module_name}")


def sample_evidence(module_name: str) -> RedactedEvidenceBundle:
    """A valid, plugin-shaped redacted evidence bundle (already DLP'd).

    Both research plugins propose from state; evidence is optional and
    carried as an empty bundle.
    """
    return RedactedEvidenceBundle(bundle_id=f"bundle-{module_name}", redacted_items=())


def assert_manifest_admits(module_name: str) -> PluginManifest:
    """Import the plugin, validate its manifest against the runtime version."""
    manifest = load_plugin_module(module_name).build_manifest()
    assert validate_manifest(manifest, RUNTIME_VERSION) == ()
    return manifest

"""F11 — research plugins (PRD §16.5, Phase 2 Wave 4).

Two first-party research plugins extending the governed loop into
*search-shaped* strategies, each a §10.2 strategy served over stdio
JSON-RPC:

- :mod:`.workflow_graph_search` — the AFlow-inspired workflow-graph
  search: proposes ``workflow_graph`` candidates as composite proposals
  (F4) whose nodes are LLM-operator steps, refined across iterations
  from per-node evaluation feedback.
- :mod:`.evolutionary_artifact_search` — the §16.5 evolutionary
  artifact search: islands over a MAP-Elites archive,
  diversity-constrained parent sampling, and cascaded
  cheap-to-expensive evaluation via the F6 stage/cost_class bindings.
- :mod:`.harness_mutator` — the §16.6 harness-mutator (Phase 3, G9):
  DGM/HGM-style mutation of the ``scaffold`` class (G1), parent
  selection over the FR-102 productivity projection, and declared
  mutation classes on every proposal for the graduation policy (G10).

**Placement** mirrors the E7 reference plugins
(:mod:`evoruntime.plugins.reference`): the plugins live inside the
installed package so the manifest entrypoint
``python -m evoruntime.plugins.research.<name>`` resolves under any
interpreter that has the package installed, and the E2 conformance and
signed-OCI packaging machinery is importable by their tests without
path gymnastics. They are untrusted *by contract* — subprocesses under
manifest limits with a scrubbed environment — even though they are
first-party code.

**The enablement invariant** (PRD §16.5): both plugins are enabled only
where correctness is externally executable. Evolutionary and graph
search optimize against a fitness signal; on artifact classes whose
correctness is judged subjectively (prompt bundles, memory entries), a
search loop optimizes the judge rather than the artifact. The gate
lives in :mod:`.enablement` and both plugins refuse to initialize on a
class outside it.

Every plugin: runs as an untrusted subprocess under its manifest limits
with a scrubbed environment (network ``none``), declares its executable
outputs with F2 :class:`ExecutionRequirements` at the PRD §13.3 tier,
and packages as a deterministic, signed OCI image with an SPDX SBOM
(:func:`build_research_image`). Conformance runs per plugin through the
E2 suites on the deterministic ScriptedAgent — no live-model calls in
CI (locked decision #9).
"""

from __future__ import annotations

import importlib
from pathlib import Path
from types import ModuleType

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evoruntime.plugins.packaging import BuiltPluginImage, build_plugin_image

#: The research plugin modules, in PRD §16.5/§16.6 order.
RESEARCH_PLUGIN_MODULES: tuple[str, ...] = (
    "evoruntime.plugins.research.workflow_graph_search",
    "evoruntime.plugins.research.evolutionary_artifact_search",
    "evoruntime.plugins.research.harness_mutator",
)


def load_research_plugin(module_name: str) -> ModuleType:
    """Import one research plugin module by fully-qualified name."""
    if module_name not in RESEARCH_PLUGIN_MODULES:
        raise ValueError(f"{module_name!r} is not a research plugin module")
    return importlib.import_module(module_name)


def build_research_image(module: ModuleType, private_key: Ed25519PrivateKey) -> BuiltPluginImage:
    """Package one research plugin as a deterministic, signed OCI archive.

    Identical discipline to the E7 reference packaging
    (:func:`evoruntime.plugins.reference.build_reference_image`): the
    layer carries the plugin's §10.4 manifest and its own source; the
    SBOM covers both files; the image manifest carries the Ed25519
    detached signature.
    """
    manifest = module.build_manifest()
    source_path = module.__file__
    if source_path is None:  # pragma: no cover — only true for namespace packages
        raise ValueError(f"module {module.__name__!r} has no source file to package")
    payload: dict[str, bytes] = {
        "manifest.json": manifest.model_dump_json().encode(),
        "plugin.py": Path(source_path).read_bytes(),
    }
    return build_plugin_image(manifest, payload, private_key=private_key)


__all__ = [
    "RESEARCH_PLUGIN_MODULES",
    "build_research_image",
    "load_research_plugin",
]

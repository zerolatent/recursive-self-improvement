"""E7 — reference plugins (PRD §16.1–16.4).

Four first-party reference plugins, one per Phase 1 low-risk artifact
class, each a §10.2 strategy served over stdio JSON-RPC:

- :mod:`.experience_distiller` — ``memory_entry`` (§16.1)
- :mod:`.bootstrap_demonstration_compiler` — ``demonstration_set`` +
  ``compiled_prompt_program`` (§16.2)
- :mod:`.gepa_prompt_optimizer` — ``prompt_bundle`` (§16.3)
- :mod:`.skillopt_text_skill_optimizer` — text-only ``skill_package`` (§16.4)

**Placement** (documented per the E7 brief): the plugins live in
``src/evoruntime/plugins/reference/`` rather than a top-level ``plugins/``
directory. They import the E2 protocol dispatcher, manifest schema, and
signed-OCI packaging directly; shipping inside the installed
``evoruntime`` package makes the manifest entrypoint
``python -m evoruntime.plugins.reference.<name>`` resolve under any
interpreter with the package installed. See :mod:`._base` for the full
rationale.

Every plugin: runs as an untrusted subprocess under its manifest limits
with a scrubbed environment (network ``none`` — the egress broker is the
sole network path, and a reference plugin requests no egress at all),
and packages as a deterministic, signed OCI image with an SPDX SBOM
(:func:`build_reference_image`). Conformance runs per plugin through the
E2 suites on the deterministic ScriptedAgent — no live-model calls in CI
(locked decision #9).
"""

from __future__ import annotations

import importlib
from pathlib import Path
from types import ModuleType

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evoruntime.plugins.packaging import BuiltPluginImage, build_plugin_image

#: The four reference plugin modules, in PRD §16 order.
REFERENCE_PLUGIN_MODULES: tuple[str, ...] = (
    "evoruntime.plugins.reference.experience_distiller",
    "evoruntime.plugins.reference.bootstrap_demonstration_compiler",
    "evoruntime.plugins.reference.gepa_prompt_optimizer",
    "evoruntime.plugins.reference.skillopt_text_skill_optimizer",
)


def load_reference_plugin(module_name: str) -> ModuleType:
    """Import one reference plugin module by fully-qualified name."""
    if module_name not in REFERENCE_PLUGIN_MODULES:
        raise ValueError(f"{module_name!r} is not a reference plugin module")
    return importlib.import_module(module_name)


def build_reference_image(module: ModuleType, private_key: Ed25519PrivateKey) -> BuiltPluginImage:
    """Package one reference plugin as a deterministic, signed OCI archive.

    The layer carries the plugin's §10.4 manifest and its own source —
    the two things admission needs to verify before the plugin ever
    runs. The SBOM covers both files; the image manifest carries the
    Ed25519 detached signature.
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
    "REFERENCE_PLUGIN_MODULES",
    "build_reference_image",
    "load_reference_plugin",
]

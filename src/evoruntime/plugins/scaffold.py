"""Scaffold artifact canonical form — the digest-pinned file map (Phase 3, G1).

A scaffold artifact is a *whole source tree*: the agent scaffold a Phase 3
research campaign mutates. Its canonical form is a file map — entrypoints,
the member-module list, and the pinned conformance-suite reference — not a
patch (that is :class:`~evoruntime.plugins.protocol.ProposalMember` /
``harness_patch`` territory). The map is the scaffold's canonical payload:
registering it through the normal registry path lands on exactly the
digest :func:`scaffold_digest` computes, so the proposed, executed, and
registered bytes share one content address by construction.

Three digest levels, all pure functions:

- ``module_digest`` — the registry artifact digest of one member module:
  sha256 over the canonical JSON of (``scaffold`` type, digest of the
  module's canonical bytes, no dependencies). Each module is registered as
  its own artifact, so the scaffold's ``dependencies`` — the member-module
  digests — are real registry dependency edges, not free-floating strings.
- ``scaffold_digest`` — the scaffold artifact's content address: the
  registry digest formula over the file-map body with the member-module
  digests as dependencies. Changing any module's path or content changes
  its module digest, hence the file map, hence the scaffold digest.
- The conformance-suite reference is digest-pinned (``name@sha256:...``)
  inside the map, so the suite a scaffold is judged by is bound into the
  candidate's content address — a scaffold cannot silently change what
  counts as its pass/fail oracle.

Module order is *not* significant: the map is normalized (modules sorted
by path) at construction, so two scaffolds with the same files are the
same candidate. This is the deliberate opposite of the composite-proposal
digest (:mod:`evoruntime.plugins.composite`), where order is part of the
candidate — a file map is a set of files, not a sequence of edits.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from pydantic import Field, model_validator

from evoruntime.core.schemas import EvoRuntimeBaseModel
from evoruntime.plugins.manifest import PluginArtifactType
from evoruntime.registry.canonical import (
    artifact_digest_for,
    canonical_json,
    payload_body_digest,
)

#: A digest-pinned reference: ``name@sha256:<64 hex>`` — a floating tag is
#: not a reproducible pin, in a file map any more than in a campaign spec.
#: The name may carry path separators (a suite inside a tree), but never a
#: leading separator, an empty segment, or a non-hex digest.
_DIGEST_REF_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*/?)*@sha256:[0-9a-f]{64}$")


def _validate_module_path(path: str) -> None:
    """Module paths follow the mutation-mask rules: relative, trimmed,
    traversal-free — a path that escapes the tree is a spec bug, not a
    candidate bug."""
    if not path or path != path.strip():
        raise ValueError(f"module path must be non-empty and trimmed: {path!r}")
    if path.startswith("/") or (len(path) > 1 and path[1] == ":"):
        raise ValueError(f"module path {path!r} is absolute — scaffold paths are relative")
    if ".." in path.split("/"):
        raise ValueError(f"module path {path!r} contains traversal — paths name real files")


class ScaffoldModule(EvoRuntimeBaseModel):
    """One member module of a scaffold source tree, digest-pinned.

    ``digest`` is the module's registry artifact digest (see
    :func:`module_digest`), so the entry doubles as the dependency edge
    the scaffold artifact carries.
    """

    path: str
    digest: str


class ScaffoldFileMap(EvoRuntimeBaseModel):
    """The canonical form of a scaffold artifact.

    ``entrypoints`` name the modules a runtime invokes to start the
    scaffold; ``modules`` is the complete pinned file list; and
    ``conformance_suite`` pins the self-edit conformance suite the
    scaffold is evaluated against (G2 runs it as the stage-0 cascade
    evaluator). Every entrypoint must be a member module — a scaffold
    whose entrypoint is not in its own file map cannot start.
    """

    entrypoints: tuple[str, ...] = Field(min_length=1)
    modules: tuple[ScaffoldModule, ...] = Field(min_length=1)
    conformance_suite: str

    @model_validator(mode="after")
    def _consistent(self) -> ScaffoldFileMap:
        module_paths = [module.path for module in self.modules]
        for path in module_paths:
            _validate_module_path(path)
        duplicates = sorted({p for p in module_paths if module_paths.count(p) > 1})
        if duplicates:
            raise ValueError(
                f"duplicate module path in the file map: {', '.join(duplicates)} — "
                "one entry per file"
            )
        # Canonical normalization: a file map is a set of files, so the
        # canonical form sorts by path and two maps over the same files
        # serialize identically regardless of authoring order.
        object.__setattr__(self, "modules", tuple(sorted(self.modules, key=lambda m: m.path)))
        for entrypoint in self.entrypoints:
            _validate_module_path(entrypoint)
            if entrypoint not in module_paths:
                raise ValueError(
                    f"entrypoint {entrypoint!r} is not a member module — a scaffold "
                    "cannot start from a file its own map does not pin"
                )
        if not _DIGEST_REF_PATTERN.match(self.conformance_suite):
            raise ValueError(
                f"conformance_suite {self.conformance_suite!r} must be digest-pinned "
                "(name@sha256:...) — a floating tag is not a reproducible pin"
            )
        return self

    def module_paths(self) -> tuple[str, ...]:
        """The pinned module paths, in canonical (sorted) order."""
        return tuple(module.path for module in self.modules)

    def module_digests(self) -> tuple[str, ...]:
        """The pinned module digests, in canonical (sorted) order — the
        scaffold artifact's dependency edges."""
        return tuple(module.digest for module in self.modules)


def module_canonical_bytes(path: str, content: str) -> bytes:
    """Canonical bytes of one member module: canonical JSON binding the
    path and the module source. The path is part of the digested body —
    the same source at a different path is a different module."""
    return canonical_json({"content": content, "path": path})


def module_digest(path: str, content: str) -> str:
    """The registry artifact digest of one member module.

    Computed with the registry's artifact-digest formula over the module's
    canonical bytes, so a module registered through
    ``RegistryService.register_artifact`` with those bytes resolves to
    exactly this digest — the file map's pin and the registered artifact's
    content address cannot drift apart.
    """
    return artifact_digest_for(
        artifact_type=PluginArtifactType.SCAFFOLD.value,
        canonical_body_digest=payload_body_digest(module_canonical_bytes(path, content)),
        dependencies=[],
        capability_requests={},
    )


def scaffold_file_map_from_sources(
    sources: Mapping[str, str],
    *,
    entrypoints: tuple[str, ...],
    conformance_suite: str,
) -> ScaffoldFileMap:
    """Build a file map from raw module sources, computing each module's
    digest. The single authoring entry point — callers never hand-compute
    module digests."""
    modules = tuple(
        ScaffoldModule(path=path, digest=module_digest(path, content))
        for path, content in sources.items()
    )
    return ScaffoldFileMap(
        entrypoints=entrypoints, modules=modules, conformance_suite=conformance_suite
    )


def scaffold_canonical_bytes(file_map: ScaffoldFileMap) -> bytes:
    """Canonical bytes of the scaffold artifact's payload: the file map as
    canonical JSON (modules already normalized to sorted-path order)."""
    return canonical_json(
        {
            "conformance_suite": file_map.conformance_suite,
            "entrypoints": list(file_map.entrypoints),
            "modules": [
                {"digest": module.digest, "path": module.path} for module in file_map.modules
            ],
        }
    )


def scaffold_digest(file_map: ScaffoldFileMap) -> str:
    """The scaffold artifact's content address.

    The registry digest formula over the file-map body, with the member
    module digests as dependencies — registering through
    ``RegistryService.register_artifact`` with
    :func:`scaffold_canonical_bytes` and those dependencies reproduces
    exactly this digest.
    """
    return artifact_digest_for(
        artifact_type=PluginArtifactType.SCAFFOLD.value,
        canonical_body_digest=payload_body_digest(scaffold_canonical_bytes(file_map)),
        dependencies=list(file_map.module_digests()),
        capability_requests={},
    )


def scaffold_canonical_dict(file_map: ScaffoldFileMap) -> dict[str, Any]:
    """The file map as a canonical-JSON-serializable dict (sorted keys)."""
    return {
        "conformance_suite": file_map.conformance_suite,
        "entrypoints": list(file_map.entrypoints),
        "modules": [{"digest": module.digest, "path": module.path} for module in file_map.modules],
    }


__all__ = [
    "ScaffoldFileMap",
    "ScaffoldModule",
    "module_canonical_bytes",
    "module_digest",
    "scaffold_canonical_bytes",
    "scaffold_canonical_dict",
    "scaffold_digest",
    "scaffold_file_map_from_sources",
]

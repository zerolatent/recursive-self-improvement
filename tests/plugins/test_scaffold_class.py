"""G1 acceptance: the SCAFFOLD class resolves through all five layers.

The coherence contract: a new artifact class must resolve coherently
through every validation plane — the type enum, the executable set, the
authority tier map, the enablement gate, and spec-level incumbent/mutable
validation — without failing closed in a surprising spot. A class that is
executable but unregistrable (or registrable but judge-disabled) is a
latent dead end: campaigns would only discover the inconsistency deep in
a run. One test asserts the whole chain, so adding a class without
wiring every layer fails here, not in production.

Also pinned here: SCAFFOLD and HARNESS_PATCH remain distinct classes —
whole source tree (Phase 3 research) vs. bounded harness patch (Phase 2
flow) — even though both resolve to tier 4.
"""

from __future__ import annotations

import pytest

from evoruntime.campaign.errors import InvalidCampaignSpecError
from evoruntime.campaign.spec import IncumbentBinding, MutableArtifact
from evoruntime.plugins.manifest import (
    EXECUTABLE_ARTIFACT_TYPES,
    PluginArtifactType,
)
from evoruntime.plugins.research.enablement import (
    is_externally_executable,
    require_external_correctness,
)
from evoruntime.plugins.scaffold import (
    ScaffoldFileMap,
    scaffold_canonical_bytes,
    scaffold_digest,
    scaffold_file_map_from_sources,
)
from evoruntime.selection.authority import AuthorityTier, ResolvedRelease, resolve_authority_tier
from tests.plugins.support import make_manifest

_SCAFFOLD = PluginArtifactType.SCAFFOLD.value
_HARNESS_PATCH = PluginArtifactType.HARNESS_PATCH.value


def test_scaffold_class_resolves_through_all_five_validation_layers() -> None:
    # Layer 1 — the class exists in the type enum.
    assert PluginArtifactType.SCAFFOLD.value == "scaffold"

    # Layer 2 — it is an externally executable class: a manifest declaring
    # it demands execution requirements, and the research enablement gate
    # admits it (self-edit conformance is a sandboxed pass/fail oracle).
    assert PluginArtifactType.SCAFFOLD in EXECUTABLE_ARTIFACT_TYPES
    assert is_externally_executable(_SCAFFOLD)
    assert require_external_correctness("harness-mutator", {"artifact_type": _SCAFFOLD}) == (
        _SCAFFOLD
    )

    # Layer 3 — authority resolves it to tier 4 on its own merits (no
    # harness contact, no direct memory write, reversible): the class
    # itself carries the elevation, not an incidental release property.
    tier = resolve_authority_tier(ResolvedRelease(artifact_classes=(_SCAFFOLD,)))
    assert tier is AuthorityTier.TIER_4

    # Layer 4 — spec-level validation admits it as an incumbent binding
    # and as a mutable-set member (the campaign's mutation surface).
    incumbent = IncumbentBinding(
        release_manifest_digest="sha256:" + "1a" * 32, artifact_type=_SCAFFOLD
    )
    assert incumbent.artifact_type == _SCAFFOLD
    mutable = MutableArtifact(artifact_type=_SCAFFOLD, paths=("src/agent/planner.py",))
    assert mutable.paths == ("src/agent/planner.py",)

    # Layer 5 — the scaffold file map digests through the registry's own
    # formula, so a scaffold candidate registers, digests, and traces like
    # any artifact.
    file_map = scaffold_file_map_from_sources(
        {"src/agent/__init__.py": "", "src/agent/planner.py": "def plan(): ..."},
        entrypoints=("src/agent/__init__.py",),
        conformance_suite="conformance/self-edit@sha256:" + "2b" * 32,
    )
    assert scaffold_digest(file_map).startswith("sha256:")


def test_scaffold_and_harness_patch_remain_distinct_classes() -> None:
    """Same tier, different classes: a bounded harness patch (Phase 2
    flow) and a whole scaffold tree (Phase 3 research) must never collapse
    into one another."""
    assert _SCAFFOLD != _HARNESS_PATCH
    assert PluginArtifactType.SCAFFOLD is not PluginArtifactType.HARNESS_PATCH

    harness_tier = resolve_authority_tier(ResolvedRelease(artifact_classes=(_HARNESS_PATCH,)))
    scaffold_tier = resolve_authority_tier(ResolvedRelease(artifact_classes=(_SCAFFOLD,)))
    assert harness_tier is AuthorityTier.TIER_4
    assert scaffold_tier is AuthorityTier.TIER_4

    # A release containing both resolves once, to the max tier — and the
    # per-class resolution is independent, not order-dependent.
    both = resolve_authority_tier(ResolvedRelease(artifact_classes=(_SCAFFOLD, _HARNESS_PATCH)))
    assert both is AuthorityTier.TIER_4


def test_manifest_declaring_scaffold_requires_execution_requirements() -> None:
    """The executable-class admission gate fires for scaffold too: a
    manifest declaring the class without execution requirements is refused
    at the schema boundary, before any policy plane sees it."""
    with pytest.raises(ValueError, match="scaffold"):
        make_manifest(artifact_types=(PluginArtifactType.SCAFFOLD,))


def test_unknown_class_still_fails_closed() -> None:
    """Adding scaffold must not loosen the fail-closed posture for classes
    the runtime does not know."""
    assert not is_externally_executable("scaffold_pro")
    with pytest.raises(InvalidCampaignSpecError, match="not a known artifact class"):
        MutableArtifact(artifact_type="scaffold_pro", paths=("src/",))


def test_scaffold_file_map_rejects_incoherent_maps() -> None:
    """The file map fails closed on dangling entrypoints, unpinned
    conformance references, and escaping paths — a scaffold that cannot
    start, or whose oracle floats, is not a registrable candidate."""
    sources = {"src/agent/__init__.py": "", "src/agent/planner.py": "def plan(): ..."}
    suite = "conformance/self-edit@sha256:" + "2b" * 32

    with pytest.raises(ValueError, match="not a member module"):
        scaffold_file_map_from_sources(
            sources, entrypoints=("src/agent/main.py",), conformance_suite=suite
        )
    with pytest.raises(ValueError, match="digest-pinned"):
        scaffold_file_map_from_sources(
            sources,
            entrypoints=("src/agent/__init__.py",),
            conformance_suite="conformance/self-edit:latest",
        )
    with pytest.raises(ValueError, match="traversal"):
        scaffold_file_map_from_sources(
            {"../escape.py": "x"},
            entrypoints=("../escape.py",),
            conformance_suite=suite,
        )


def test_scaffold_file_map_is_order_insensitive() -> None:
    """A file map is a set of files: authoring order must not change the
    canonical bytes or the digest (the deliberate opposite of the
    composite-proposal digest, where order is the candidate)."""
    sources = {"src/agent/planner.py": "def plan(): ...", "src/agent/__init__.py": ""}
    suite = "conformance/self-edit@sha256:" + "2b" * 32
    first = scaffold_file_map_from_sources(
        sources, entrypoints=("src/agent/__init__.py",), conformance_suite=suite
    )
    second = scaffold_file_map_from_sources(
        dict(reversed(list(sources.items()))),
        entrypoints=("src/agent/__init__.py",),
        conformance_suite=suite,
    )
    assert first.module_paths() == ("src/agent/__init__.py", "src/agent/planner.py")
    assert scaffold_digest(first) == scaffold_digest(second)


def test_scaffold_digest_binds_every_module_and_the_suite() -> None:
    """Changing any module's content, any module's path, or the pinned
    conformance suite changes the scaffold digest — the content address
    binds the whole tree and its oracle."""
    sources = {"src/agent/__init__.py": "", "src/agent/planner.py": "def plan(): ..."}
    suite = "conformance/self-edit@sha256:" + "2b" * 32
    entrypoints = ("src/agent/__init__.py",)
    base = scaffold_file_map_from_sources(sources, entrypoints=entrypoints, conformance_suite=suite)

    mutated_source = dict(sources, **{"src/agent/planner.py": "def plan(): return 42"})
    mutated = scaffold_file_map_from_sources(
        mutated_source, entrypoints=entrypoints, conformance_suite=suite
    )
    assert scaffold_digest(mutated) != scaffold_digest(base)

    renamed = dict(sources)
    renamed["src/agent/rename.py"] = renamed.pop("src/agent/planner.py")
    assert scaffold_digest(
        scaffold_file_map_from_sources(renamed, entrypoints=entrypoints, conformance_suite=suite)
    ) != scaffold_digest(base)

    other_suite = "conformance/self-edit@sha256:" + "3c" * 32
    re_suites = scaffold_file_map_from_sources(
        sources, entrypoints=entrypoints, conformance_suite=other_suite
    )
    assert scaffold_digest(re_suites) != scaffold_digest(base)


def test_scaffold_file_map_round_trips_through_pydantic() -> None:
    """The canonical bytes re-parse into an equal map — the registered
    payload is the authored candidate, verifiable on read-back."""
    file_map = scaffold_file_map_from_sources(
        {"src/agent/__init__.py": "", "src/agent/planner.py": "def plan(): ..."},
        entrypoints=("src/agent/__init__.py",),
        conformance_suite="conformance/self-edit@sha256:" + "2b" * 32,
    )
    reparsed = ScaffoldFileMap.model_validate_json(scaffold_canonical_bytes(file_map))
    assert reparsed == file_map

"""§13.3 authority tiers, computed on the resolved release.

The tier is a property of what a release *resolves to* — the artifact
classes in its resolved set, the runtime surfaces they touch, whether the
change is reversible — never of the artifact type alone. A prompt bundle
that reaches into the harness is not a tier-1 outcome wearing a familiar
name; computing the tier from the resolved release is what stops that
confusion.

Phase 1 outcome space: tier-1 (automatic after the sealed gate and shadow
evaluation) and tier-2 (owner or explicit policy graduation) — prompt
bundles, demonstration sets, and suggestion-mode memory in a read-only,
reversible runtime. Tier-3+ paths exist here because the engine must be
able to *compute* them (a tier that cannot be computed cannot be refused
on evidence); they are unreachable by Phase 1 artifact classes, and
:func:`assert_phase1_admissible` rejects them loudly rather than letting a
promotion through silently.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from evoruntime.plugins.manifest import PluginArtifactType
from evoruntime.selection.errors import TierRejectedError


class AuthorityTier(IntEnum):
    """The §13.3 approval tiers, ordered by the authority they require."""

    TIER_1 = 1
    """Automatic after the sealed gate and shadow evaluation — read-only,
    reversible changes in a suggestion-first runtime."""

    TIER_2 = 2
    """Owner or explicit policy graduation — still reversible, but the
    change alters what the runtime *keeps* (memory entries, compiled
    programs, skill packages)."""

    TIER_3 = 3
    """Elevated authority (review board). Exists in the engine; unreachable
    by Phase 1 artifact classes and rejected before any promotion."""

    TIER_4 = 4
    """Human sign-off plane (harness/runtime patches). Exists in the
    engine; rejected for Phase 1 like tier 3, only louder."""


#: The tiers Phase 1 may ever produce. Anything at or above the boundary is
#: a rejection, not a downgrade.
PHASE_1_MAX_TIER = AuthorityTier.TIER_2


@dataclass(frozen=True, slots=True)
class ResolvedRelease:
    """What a release manifest resolves to — the §13.3 tier input.

    Built from the release manifest's resolved artifact digests and the
    runtime surfaces they touch. Deliberately a flat, explicit view: the
    tier decision should be readable from the data, not inferred from a
    manifest object graph.
    """

    artifact_classes: tuple[str, ...]
    """The resolved artifact classes present in the release."""

    contains_executable_content: bool = False
    """True when any resolved member executes (scripts, compiled programs
    that run, tool specs). Phase 1 text-only classes never set this."""

    touches_harness: bool = False
    """True when the release reaches the evaluation harness itself."""

    memory_write_mode: str = "suggestion"
    """'suggestion' (Phase 1) or 'direct' — direct writes are tier-3+."""

    reversible: bool = True
    """Whether the release can be rolled back by pointer CAS alone."""

    runtime_surface: str = "read_only"
    """'read_only', 'config', or 'runtime' — the deepest surface touched."""

    def __post_init__(self) -> None:
        if self.memory_write_mode not in ("suggestion", "direct"):
            raise ValueError(
                f"memory_write_mode {self.memory_write_mode!r} must be 'suggestion' or 'direct'"
            )
        if self.runtime_surface not in ("read_only", "config", "runtime"):
            raise ValueError(
                f"runtime_surface {self.runtime_surface!r} must be "
                "'read_only', 'config', or 'runtime'"
            )


def resolve_authority_tier(release: ResolvedRelease) -> AuthorityTier:
    """Compute the §13.3 tier a resolved release warrants.

    Tier-3+ triggers are checked first and dominate: a release that
    executes content, touches the harness, writes memory directly, is not
    reversible, or reaches the runtime surface is an elevated-authority
    release no matter how familiar its artifact classes look.
    """
    if release.touches_harness:
        return AuthorityTier.TIER_4
    if (
        release.contains_executable_content
        or release.memory_write_mode == "direct"
        or not release.reversible
        or release.runtime_surface == "runtime"
    ):
        return AuthorityTier.TIER_3

    # Reversible, suggestion-first releases tier by their resolved classes.
    # An unknown class fails closed at tier 3 — it is rejected by the Phase 1
    # gate rather than waved through at tier 1.
    tier_by_class: dict[str, AuthorityTier] = {
        PluginArtifactType.PROMPT_BUNDLE.value: AuthorityTier.TIER_1,
        PluginArtifactType.DEMONSTRATION_SET.value: AuthorityTier.TIER_1,
        PluginArtifactType.MEMORY_ENTRY.value: AuthorityTier.TIER_2,
        PluginArtifactType.COMPILED_PROMPT_PROGRAM.value: AuthorityTier.TIER_2,
        PluginArtifactType.SKILL_PACKAGE.value: AuthorityTier.TIER_2,
    }
    tiers = [tier_by_class.get(cls, AuthorityTier.TIER_3) for cls in release.artifact_classes]
    if not tiers:
        return AuthorityTier.TIER_3
    return max(tiers)


def assert_phase1_admissible(tier: AuthorityTier) -> None:
    """Reject tier-3+ authority for Phase 1 — loudly, never silently.

    The tier-3+ paths exist in the engine so this check is a *decision*,
    not an absence of one. A Phase 1 artifact class that resolves to an
    elevated tier is refused here, before any promotion decision can be
    rendered.
    """
    if tier > PHASE_1_MAX_TIER:
        raise TierRejectedError(
            int(tier),
            "the resolved release warrants elevated authority "
            "(executable content, harness/runtime surface, direct memory "
            "writes, or an irreversible change) — no Phase 1 artifact class "
            "may promote through it",
        )


__all__ = [
    "PHASE_1_MAX_TIER",
    "AuthorityTier",
    "ResolvedRelease",
    "assert_phase1_admissible",
    "resolve_authority_tier",
]

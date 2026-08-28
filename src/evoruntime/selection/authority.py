"""§13.3 authority tiers, computed on the resolved release.

The tier is a property of what a release *resolves to* — the artifact
classes in its resolved set, the runtime surfaces they touch, whether the
change is reversible — never of the artifact type alone. A prompt bundle
that reaches into the harness is not a tier-1 outcome wearing a familiar
name; computing the tier from the resolved release is what stops that
confusion.

Phase 2 outcome space: tier-1/2 as in Phase 1, plus the executable
classes (F2) — workflow graphs, tool specs, skill scripts, and algorithms
resolve to tier 3, harness patches to tier 4. Tier-3 and tier-4 paths are
no longer unreachable, but they are never *open*:
:func:`assert_phase2_admissible` admits tier 3 only on two-person approval
and tier 4 only on human sign-off with manual initiation (no production
automation). The engine classifies; this gate decides.
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
    """Elevated authority — two-person approval (FR-022 semantics). Phase 2
    admits it only with two distinct approvers, neither the requester."""

    TIER_4 = 4
    """Human sign-off plane (harness/runtime patches). Phase 2 admits it
    only with explicit human sign-off and manual initiation — never
    through production automation."""


#: The tiers Phase 2 admits without approval evidence. Anything at or
#: above the boundary needs the approval evidence the gate demands.
APPROVAL_FREE_MAX_TIER = AuthorityTier.TIER_2


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


@dataclass(frozen=True, slots=True)
class TierApprovalEvidence:
    """Approval evidence a tier-3/4 admission is judged on (F2).

    The FR-022 two-person semantics are consumed, not rebuilt: approvers
    must be two *distinct* humans and neither may be the requester. Tier 4
    additionally demands explicit human sign-off and manual initiation —
    a scheduled or automated pipeline can never carry a harness patch to
    promotion on its own.
    """

    approvers: tuple[str, ...] = ()
    """Human approver identities (exactly two distinct ones for tier 3)."""

    requested_by: str | None = None
    """Who requested the promotion — an approver may not be the requester."""

    human_signoff: bool = False
    """Explicit human sign-off (tier 4 requirement)."""

    manually_initiated: bool = False
    """True when a human, not production automation, initiated the change."""


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
    # An unknown class fails closed at tier 3 — it is rejected by the Phase 2
    # gate (no approval evidence) rather than waved through at tier 1.
    tier_by_class: dict[str, AuthorityTier] = {
        PluginArtifactType.PROMPT_BUNDLE.value: AuthorityTier.TIER_1,
        PluginArtifactType.DEMONSTRATION_SET.value: AuthorityTier.TIER_1,
        PluginArtifactType.MEMORY_ENTRY.value: AuthorityTier.TIER_2,
        PluginArtifactType.COMPILED_PROMPT_PROGRAM.value: AuthorityTier.TIER_2,
        PluginArtifactType.SKILL_PACKAGE.value: AuthorityTier.TIER_2,
        # Phase 2 executable classes (PRD §13.3): workflow and tool surface
        # changes are tier 3; harness patches are tier 4.
        PluginArtifactType.WORKFLOW_GRAPH.value: AuthorityTier.TIER_3,
        PluginArtifactType.TOOL_SPEC.value: AuthorityTier.TIER_3,
        PluginArtifactType.SKILL_SCRIPT.value: AuthorityTier.TIER_3,
        PluginArtifactType.ALGORITHM.value: AuthorityTier.TIER_3,
        PluginArtifactType.HARNESS_PATCH.value: AuthorityTier.TIER_4,
    }
    tiers = [tier_by_class.get(cls, AuthorityTier.TIER_3) for cls in release.artifact_classes]
    if not tiers:
        return AuthorityTier.TIER_3
    return max(tiers)


def assert_phase2_admissible(
    tier: AuthorityTier,
    evidence: TierApprovalEvidence | None = None,
) -> None:
    """The Phase 2 tier gate: tier-3/4 authority only with its approvals.

    Tier 3 is admissible ONLY with two-person approval — two distinct
    human approvers, neither of them the requester (FR-022 semantics,
    consumed here as a library; F10 builds the API surface). Tier 4 is
    admissible ONLY with explicit human sign-off AND manual initiation:
    no production automation may carry a harness patch to promotion.

    Raises:
        TierRejectedError: the tier's approval evidence is missing or
            malformed — the promotion is refused, never downgraded.
    """
    if tier <= APPROVAL_FREE_MAX_TIER:
        return
    approval = evidence or TierApprovalEvidence()
    if tier is AuthorityTier.TIER_3:
        _require_two_person_approval(approval)
        return
    # Tier 4: human sign-off and manual initiation, both or nothing.
    missing: list[str] = []
    if not approval.human_signoff:
        missing.append("explicit human sign-off")
    if not approval.manually_initiated:
        missing.append("manual initiation (no production automation)")
    if missing:
        raise TierRejectedError(
            int(tier),
            "harness/runtime patches require human sign-off and manual "
            "initiation — missing: " + ", ".join(missing),
        )


def _require_two_person_approval(approval: TierApprovalEvidence) -> None:
    """Enforce FR-022 two-person semantics on tier-3 approval evidence."""
    if len(approval.approvers) != 2:
        raise TierRejectedError(
            int(AuthorityTier.TIER_3),
            "tier-3 promotion requires two-person approval — "
            f"got {len(approval.approvers)} approver(s)",
        )
    first, second = approval.approvers[0], approval.approvers[1]
    if first.casefold() == second.casefold():
        raise TierRejectedError(
            int(AuthorityTier.TIER_3),
            f"two-person approval requires distinct approvers — both named {first!r}",
        )
    if approval.requested_by is not None and any(
        a.casefold() == approval.requested_by.casefold() for a in approval.approvers
    ):
        raise TierRejectedError(
            int(AuthorityTier.TIER_3),
            f"requester {approval.requested_by!r} cannot approve their own "
            "tier-3 promotion (self-approval refused)",
        )


__all__ = [
    "APPROVAL_FREE_MAX_TIER",
    "AuthorityTier",
    "ResolvedRelease",
    "TierApprovalEvidence",
    "assert_phase2_admissible",
    "resolve_authority_tier",
]

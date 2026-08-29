"""Canary eligibility resolution (H6, PRD §17.1 step 8).

A canary is a controlled comparison, not a rescue mission: the harness's
only undo is the release controller's pointer rollback, so a release whose
failure modes a pointer move cannot contain has no business entering one.
The predicate over the release's resolved artifact classes is the canary
admission gate: only read-only or transactionally-reversible classes are
eligible, and everything else is refused with a typed error before any
canary machinery runs.

The line is the §13.3 authority model's, not a new one:

- **Read-only classes** (tier 1 — prompt bundles, demonstration sets)
  change what the agent *says*, never what the runtime *keeps*.
- **Transactionally-reversible classes** (tier 2 — memory entries,
  compiled prompt programs, skill packages) alter what the runtime keeps,
  but the pointer rollback restores the prior release atomically — the
  change is one transaction the rollback undoes.
- **Everything else** (tier 3 executable classes, tier 4 harness and
  scaffold patches, unknown classes) is refused: these are exactly the
  releases whose failure modes a canary cannot contain with a pointer
  move, and an unknown class fails closed like every other §13.3
  decision.

The predicate consumes a :class:`~evoruntime.selection.authority.ResolvedRelease`
— the same flat view the tier engine judges — so eligibility and tier
decisions read from one definition of what a release resolves to.
"""

from __future__ import annotations

from dataclasses import dataclass

from evoruntime.release.errors import CanaryIneligibleError
from evoruntime.selection.authority import AuthorityTier, ResolvedRelease, resolve_authority_tier


@dataclass(frozen=True, slots=True)
class CanaryEligibility:
    """The canary-admission verdict over one resolved release.

    ``ineligible_classes`` names the resolved artifact classes that are
    neither read-only nor transactionally reversible; ``refusals`` names
    the release-level properties that refuse admission on their own. A
    release is eligible only when both lists are empty.
    """

    eligible: bool
    ineligible_classes: tuple[str, ...]
    refusals: tuple[str, ...]


def resolve_canary_eligibility(release: ResolvedRelease) -> CanaryEligibility:
    """Resolve whether a release's resolved set is canary-eligible.

    Per class: the class's §13.3 tier must be at most tier 2 — the
    read-only and transactionally-reversible bands. Per release: the
    release must be reversible by pointer rollback alone, must not reach
    the runtime surface or the harness, must not carry executable content
    or direct memory writes, and must resolve to at least one artifact
    class (an empty resolved set is nothing to admit, not a free pass).
    """
    ineligible = tuple(
        artifact_class
        for artifact_class in release.artifact_classes
        if resolve_authority_tier(ResolvedRelease(artifact_classes=(artifact_class,)))
        > AuthorityTier.TIER_2
    )

    refusals: list[str] = []
    if not release.artifact_classes:
        refusals.append("the release resolves to no artifact classes — nothing to admit")
    if not release.reversible:
        refusals.append("the release is not reversible by pointer rollback alone")
    if release.runtime_surface == "runtime":
        refusals.append("the release reaches the runtime surface")
    if release.touches_harness:
        refusals.append("the release touches the evaluation harness")
    if release.contains_executable_content:
        refusals.append("the release contains executable content")
    if release.memory_write_mode == "direct":
        refusals.append("the release writes memory directly")

    return CanaryEligibility(
        eligible=not ineligible and not refusals,
        ineligible_classes=ineligible,
        refusals=tuple(refusals),
    )


def assert_canary_eligible(release: ResolvedRelease) -> CanaryEligibility:
    """The canary admission gate: refuse an ineligible release.

    Raises:
        CanaryIneligibleError: the release's resolved classes or
            release-level properties make it ineligible — the refusal
            names the offending classes and properties, and nothing runs.
    """
    eligibility = resolve_canary_eligibility(release)
    if not eligibility.eligible:
        raise CanaryIneligibleError(
            eligibility.ineligible_classes,
            eligibility.refusals,
        )
    return eligibility


__all__ = [
    "CanaryEligibility",
    "assert_canary_eligible",
    "resolve_canary_eligibility",
]

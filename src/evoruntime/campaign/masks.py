"""Mutation masks enforced before any execution (FR-006).

The campaign spec declares which paths a candidate may edit. This module
is where that declaration becomes a gate: a `MaskEnforcingAdapter` wraps
any §10.2 `ArtifactAdapter` and checks every file path a candidate or
patch touches *against the mask before the wrapped adapter is called at
all*. An undeclared-path edit therefore fails validation — it never
reaches rendering, evaluation, or the registry.

Why the wrapper rather than trusting each adapter: the mask is a
campaign-level constraint, but adapters are untrusted plugins. Delegating
mask enforcement to the plugin would let a buggy (or hostile) adapter
edit whatever it likes; the runtime owns the check, the plugin can only
narrow it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from evoruntime.campaign.errors import MutationMaskViolationError
from evoruntime.campaign.spec import MutableArtifact
from evoruntime.plugins.protocol import CandidateBundle, CanonicalBytes, ValidationReport


@dataclass(frozen=True, slots=True)
class MutationMask:
    """The declared edit surface: one artifact type, a fixed set of paths."""

    artifact_type: str
    allowed_paths: tuple[str, ...]

    @classmethod
    def from_spec(cls, mutable: MutableArtifact) -> MutationMask:
        """Build the mask from the spec's mutable-artifact binding."""
        return cls(artifact_type=mutable.artifact_type, allowed_paths=mutable.paths)


def mask_violations(
    mask: MutationMask, files: tuple[dict[str, Any], ...] | list[dict[str, Any]]
) -> tuple[str, ...]:
    """Pure check: which file entries violate the mask, and why.

    Returns violation strings (empty tuple = clean). Three failure shapes,
    checked in a fixed order so reports are stable: a file entry without a
    usable path, a path shape that is not a relative artifact path, and a
    well-formed path that simply is not declared.
    """
    violations: list[str] = []
    for index, entry in enumerate(files):
        path = entry.get("path") if isinstance(entry, dict) else None
        if not isinstance(path, str) or not path:
            violations.append(f"file entry #{index} declares no path — cannot be mask-checked")
            continue
        if path.startswith("/") or ".." in path.split("/"):
            violations.append(
                f"path {path!r} is not a relative artifact path (absolute or traversal)"
            )
            continue
        if path not in mask.allowed_paths:
            violations.append(
                f"path {path!r} is outside the mutation mask "
                f"(declared: {', '.join(mask.allowed_paths)})"
            )
    return tuple(violations)


def _patch_paths(patch: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    """Extract file entries from a strategy patch, if it declares any.

    Patches are adapter-specific (`Proposal.patch` is an opaque dict), so
    the mask recognizes the two shapes that carry paths — a `files` list
    of path-keyed entries, or a single top-level `path`. A patch that
    declares no paths is the adapter's business, not the mask's.
    """
    files = patch.get("files")
    if isinstance(files, list):
        return tuple(entry for entry in files if isinstance(entry, dict))
    path = patch.get("path")
    if isinstance(path, str):
        return ({"path": path},)
    return ()


class MaskedArtifactAdapter(Protocol):
    """Structural type for the §10.2 adapter surface the wrapper guards."""

    def validate(self, candidate: CandidateBundle) -> ValidationReport: ...

    def render(self, base: CanonicalBytes, patch: dict[str, Any]) -> CanonicalBytes: ...


class MaskEnforcingAdapter:
    """Wraps an artifact adapter and enforces the mutation mask first.

    Two enforcement points, two failure modes, one rule — nothing outside
    the mask is ever executed:

    - `validate` returns a rejecting `ValidationReport` *without calling
      the wrapped adapter* when any file path violates the mask. This is
      the FR-006 path: the violation is a validation failure, recorded as
      violations, not a runtime crash mid-render.
    - `render` raises `MutationMaskViolationError` before delegating — a
      render call is execution about to happen, so refusal is loud.
    """

    def __init__(self, adapter: MaskedArtifactAdapter, mask: MutationMask) -> None:
        self._adapter = adapter
        self._mask = mask

    @property
    def mask(self) -> MutationMask:
        """The mask this wrapper enforces."""
        return self._mask

    def validate(self, candidate: CandidateBundle) -> ValidationReport:
        """Mask-check the candidate, then delegate to the wrapped adapter.

        A mask violation short-circuits: the wrapped adapter's `validate`
        is never invoked, so an undeclared-path candidate cannot leak into
        any downstream execution path through this seam.
        """
        violations = mask_violations(self._mask, candidate.files)
        if violations:
            return ValidationReport(accepted=False, violations=violations)
        return self._adapter.validate(candidate)

    def render(self, base: CanonicalBytes, patch: dict[str, Any]) -> CanonicalBytes:
        """Mask-check the patch, then delegate — or refuse before executing.

        Raises:
            MutationMaskViolationError: the patch edits paths outside the
                mask. The wrapped adapter's `render` is never called.
        """
        violations = mask_violations(self._mask, _patch_paths(patch))
        if violations:
            raise MutationMaskViolationError(violations)
        return self._adapter.render(base, patch)


__all__ = [
    "MaskEnforcingAdapter",
    "MaskedArtifactAdapter",
    "MutationMask",
    "mask_violations",
]

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
from evoruntime.campaign.spec import MutableArtifact, MutableArtifactSet
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


def masks_from_spec(mutable: MutableArtifactSet) -> tuple[MutationMask, ...]:
    """One mutation mask per member of the spec's mutable artifact set,
    in spec order (Phase 2, F4)."""
    return tuple(MutationMask.from_spec(artifact) for artifact in mutable.artifacts)


def member_mask_violations(
    masks: tuple[MutationMask, ...], files: tuple[dict[str, Any], ...] | list[dict[str, Any]]
) -> tuple[str, ...]:
    """Pure check: which file entries violate *their member's* mask.

    The multi-mask shape of :func:`mask_violations` (Phase 2, F4): each
    file entry is checked against the mask declared for its artifact
    type — a file entry without a usable ``artifact_type`` is checked
    against the single declared mask when there is exactly one, and is a
    violation when several masks are in force (there is no way to know
    which member it belongs to). Violation strings name the member type
    so a report says *which* member escaped its mask.
    """
    violations: list[str] = []
    by_type = {mask.artifact_type: mask for mask in masks}
    for index, entry in enumerate(files):
        path = entry.get("path") if isinstance(entry, dict) else None
        if not isinstance(path, str) or not path:
            violations.append(f"file entry #{index} declares no path — cannot be mask-checked")
            continue
        declared = entry.get("artifact_type") if isinstance(entry, dict) else None
        if isinstance(declared, str) and declared:
            mask = by_type.get(declared)
            if mask is None:
                violations.append(
                    f"file entry #{index} declares artifact_type {declared!r}, which has "
                    f"no mutation mask (declared: {', '.join(by_type) or 'none'})"
                )
                continue
        elif len(masks) == 1:
            mask = masks[0]
        else:
            violations.append(
                f"file entry #{index} declares no artifact_type but "
                f"{len(masks)} member masks are enforced — cannot pick a mask"
            )
            continue
        if path.startswith("/") or ".." in path.split("/"):
            violations.append(
                f"path {path!r} (member {mask.artifact_type!r}) is not a relative "
                "artifact path (absolute or traversal)"
            )
            continue
        if path not in mask.allowed_paths:
            violations.append(
                f"path {path!r} (member {mask.artifact_type!r}) is outside that member's "
                f"mutation mask (declared: {', '.join(mask.allowed_paths)})"
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
    """Wraps an artifact adapter and enforces the mutation mask(s) first.

    Phase 2 (F4): one mask *per member*. A composite campaign declares a
    `MutableArtifactSet`, and this wrapper enforces the whole set — each
    file a candidate touches is checked against the mask of the member it
    belongs to (matched by the file's declared ``artifact_type``).

    Two enforcement points, two failure modes, one rule — nothing outside
    the mask is ever executed:

    - `validate` returns a rejecting `ValidationReport` *without calling
      the wrapped adapter* when any file path violates the mask. This is
      the FR-006 path: the violation is a validation failure, recorded as
      violations, not a runtime crash mid-render.
    - `render` raises `MutationMaskViolationError` before delegating — a
      render call is execution about to happen, so refusal is loud.
    """

    def __init__(
        self, adapter: MaskedArtifactAdapter, mask: MutationMask | tuple[MutationMask, ...]
    ) -> None:
        self._adapter = adapter
        self._masks: tuple[MutationMask, ...] = (
            (mask,) if isinstance(mask, MutationMask) else tuple(mask)
        )
        if not self._masks:
            raise ValueError("MaskEnforcingAdapter requires at least one mutation mask")

    @property
    def mask(self) -> MutationMask:
        """The (single) mask this wrapper enforces."""
        if len(self._masks) != 1:
            raise ValueError(
                f"{len(self._masks)} member masks are enforced — use `masks`, not `mask`"
            )
        return self._masks[0]

    @property
    def masks(self) -> tuple[MutationMask, ...]:
        """The per-member masks this wrapper enforces, in spec order."""
        return self._masks

    def validate(self, candidate: CandidateBundle) -> ValidationReport:
        """Mask-check the candidate, then delegate to the wrapped adapter.

        A mask violation short-circuits: the wrapped adapter's `validate`
        is never invoked, so an undeclared-path candidate cannot leak into
        any downstream execution path through this seam.
        """
        if len(self._masks) == 1:
            violations = mask_violations(self._masks[0], candidate.files)
        else:
            violations = member_mask_violations(self._masks, candidate.files)
        if violations:
            return ValidationReport(accepted=False, violations=violations)
        return self._adapter.validate(candidate)

    def render(
        self, base: CanonicalBytes, patch: dict[str, Any], *, artifact_type: str | None = None
    ) -> CanonicalBytes:
        """Mask-check the patch, then delegate — or refuse before executing.

        With multiple member masks, `artifact_type` selects the member
        whose mask governs this render; rendering an undeclared member
        type is refused before the wrapped adapter is called.

        Raises:
            MutationMaskViolationError: the patch edits paths outside the
                member's mask, or the member has no declared mask. The
                wrapped adapter's `render` is never called.
        """
        if artifact_type is not None:
            mask = next((m for m in self._masks if m.artifact_type == artifact_type), None)
            if mask is None:
                raise MutationMaskViolationError(
                    (
                        f"no mutation mask is declared for artifact_type {artifact_type!r} "
                        f"(declared: {', '.join(m.artifact_type for m in self._masks)}) — "
                        "nothing outside the declared member set may be rendered",
                    )
                )
        else:
            if len(self._masks) != 1:
                raise MutationMaskViolationError(
                    (
                        f"{len(self._masks)} member masks are enforced — render must name "
                        "its member via artifact_type",
                    )
                )
            mask = self._masks[0]
        violations = mask_violations(mask, _patch_paths(patch))
        if violations:
            raise MutationMaskViolationError(violations)
        return self._adapter.render(base, patch)


__all__ = [
    "MaskEnforcingAdapter",
    "MaskedArtifactAdapter",
    "MutationMask",
    "mask_violations",
    "masks_from_spec",
    "member_mask_violations",
]

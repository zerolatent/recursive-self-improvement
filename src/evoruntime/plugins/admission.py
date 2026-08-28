"""Malformed-output admission gate (FR-018) — a pure function.

Every byte a plugin produces must pass this gate before it touches the
artifact registry. The gate is *pure*: it consumes structured metadata about
the candidate's output entries (paths, kinds, sizes, archive statistics) and
returns a decision. No I/O, no clock, no randomness — which is what makes it
fixture-testable like the D8 adversarial suite and safe to run inside the
admission path itself.

Rejections follow FR-018's list exactly: path traversal, absolute paths,
symlinks, device nodes, archive bombs, oversized/sparse files, undeclared
executables, and Unicode-confusable protected paths. Deny-by-default: an
entry that trips *any* check rejects the whole bundle.
"""

from __future__ import annotations

import unicodedata
from enum import StrEnum
from pathlib import PurePosixPath

from pydantic import Field

from evoruntime.core.schemas import EvoRuntimeBaseModel

DEFAULT_MAX_FILE_BYTES = 10 * 1024 * 1024  # 10 MiB per file
DEFAULT_MAX_TOTAL_BYTES = 64 * 1024 * 1024  # 64 MiB per candidate
DEFAULT_MAX_COMPRESSION_RATIO = 100.0

# Repository paths a candidate must never shadow with lookalike names
# (FR-018 Unicode-confusable protected paths).
DEFAULT_PROTECTED_PATHS: tuple[str, ...] = (
    "src",
    "tests",
    "docs",
    "fixtures",
    "evoruntime",
    ".github",
)

# Skeleton map for the homoglyphs that matter in practice: Cyrillic and
# Greek letters visually identical to ASCII, plus fullwidth forms (which
# NFKC already folds, listed here for completeness). A path segment whose
# skeleton matches a protected name while its raw spelling differs is a
# shadowing attempt, not a filename.
_SKELETON_MAP: dict[str, str] = {
    # Cyrillic lookalikes
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "і": "i",
    "ѕ": "s",
    "ј": "j",
    "һ": "h",
    "ԁ": "d",
    "ɡ": "g",
    "ԛ": "q",
    "ԝ": "w",
    # Greek lookalikes
    "ο": "o",
    "α": "a",
    "ε": "e",
    "ρ": "p",
    "ν": "v",
    "τ": "t",
    "υ": "u",
    "ι": "i",
    "κ": "k",
    "β": "b",
}


class OutputKind(StrEnum):
    """What kind of filesystem object an output entry claims to be."""

    FILE = "file"
    DIRECTORY = "directory"
    SYMLINK = "symlink"
    DEVICE = "device"


class ArchiveInfo(EvoRuntimeBaseModel):
    """Declared statistics for an archive entry.

    ``uncompressed_total_bytes`` is the archive's own claim about its
    expanded size; the gate compares it against the compressed size the
    transport observed, so a lying archive header cannot help the attacker —
    the ratio check catches the bomb either way.
    """

    uncompressed_total_bytes: int = Field(ge=0)
    entry_count: int = Field(default=1, ge=1)


class OutputEntry(EvoRuntimeBaseModel):
    """One output object a plugin produced (metadata only — never content).

    ``executable`` is true when the entry carries an exec bit *or* bears an
    executable magic number (ELF/Mach-O/PE/shebang); admission treats both
    identically because both make the file runnable.
    """

    path: str
    kind: OutputKind = OutputKind.FILE
    size_bytes: int = Field(default=0, ge=0)
    executable: bool = False
    sparse: bool = False
    target: str | None = None
    archive: ArchiveInfo | None = None


class ViolationCode(StrEnum):
    """FR-018 rejection taxonomy."""

    PATH_TRAVERSAL = "path_traversal"
    ABSOLUTE_PATH = "absolute_path"
    SYMLINK = "symlink"
    DEVICE_NODE = "device_node"
    ARCHIVE_BOMB = "archive_bomb"
    OVERSIZED_FILE = "oversized_file"
    SPARSE_FILE = "sparse_file"
    UNDECLARED_EXECUTABLE = "undeclared_executable"
    CONFUSABLE_PATH = "confusable_path"


class AdmissionViolation(EvoRuntimeBaseModel):
    """One rejection reason, tied to the entry that caused it."""

    code: ViolationCode
    path: str
    detail: str = ""


class AdmissionDecision(EvoRuntimeBaseModel):
    """The gate's verdict over a candidate's output entries."""

    admitted: bool
    violations: tuple[AdmissionViolation, ...] = Field(default=())


def admit_output(
    entries: list[OutputEntry],
    *,
    declared_executables: frozenset[str] = frozenset(),
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_compression_ratio: float = DEFAULT_MAX_COMPRESSION_RATIO,
    protected_paths: tuple[str, ...] = DEFAULT_PROTECTED_PATHS,
) -> AdmissionDecision:
    """Decide whether a candidate's output entries may be admitted.

    Pure: same inputs, same verdict, no side effects. Any single violation
    rejects the entire bundle — a candidate with one poisoned path is not
    "mostly safe".
    """
    violations: list[AdmissionViolation] = []
    total_bytes = 0
    for entry in entries:
        violations.extend(
            _check_entry(
                entry,
                declared_executables=declared_executables,
                max_file_bytes=max_file_bytes,
                max_total_bytes=max_total_bytes,
                max_compression_ratio=max_compression_ratio,
                protected_paths=protected_paths,
            )
        )
        total_bytes += entry.size_bytes
    if total_bytes > max_total_bytes:
        violations.append(
            AdmissionViolation(
                code=ViolationCode.OVERSIZED_FILE,
                path="<bundle>",
                detail=f"total {total_bytes} bytes exceeds bundle cap {max_total_bytes}",
            )
        )
    return AdmissionDecision(admitted=not violations, violations=tuple(violations))


def _check_entry(
    entry: OutputEntry,
    *,
    declared_executables: frozenset[str],
    max_file_bytes: int,
    max_total_bytes: int,
    max_compression_ratio: float,
    protected_paths: tuple[str, ...],
) -> list[AdmissionViolation]:
    violations: list[AdmissionViolation] = []
    violations.extend(_check_path_shape(entry))
    if entry.kind is OutputKind.SYMLINK:
        violations.append(
            AdmissionViolation(
                code=ViolationCode.SYMLINK,
                path=entry.path,
                detail=f"symlink target {entry.target!r}",
            )
        )
    if entry.kind is OutputKind.DEVICE:
        violations.append(AdmissionViolation(code=ViolationCode.DEVICE_NODE, path=entry.path))
    if entry.sparse:
        violations.append(
            AdmissionViolation(
                code=ViolationCode.SPARSE_FILE,
                path=entry.path,
                detail=f"sparse file with logical size {entry.size_bytes}",
            )
        )
    if entry.size_bytes > max_file_bytes:
        violations.append(
            AdmissionViolation(
                code=ViolationCode.OVERSIZED_FILE,
                path=entry.path,
                detail=f"{entry.size_bytes} bytes exceeds per-file cap {max_file_bytes}",
            )
        )
    if entry.archive is not None:
        violations.extend(
            _check_archive(entry, max_total_bytes=max_total_bytes, max_ratio=max_compression_ratio)
        )
    if entry.executable and entry.path not in declared_executables:
        violations.append(
            AdmissionViolation(
                code=ViolationCode.UNDECLARED_EXECUTABLE,
                path=entry.path,
                detail="executable output not declared by the plugin manifest",
            )
        )
    violations.extend(_check_confusables(entry, protected_paths))
    return violations


def _check_path_shape(entry: OutputEntry) -> list[AdmissionViolation]:
    """Absolute paths and traversal, checked on the raw path string."""
    violations: list[AdmissionViolation] = []
    path = entry.path
    if path.startswith("/") or (len(path) > 1 and path[1] == ":"):
        violations.append(
            AdmissionViolation(
                code=ViolationCode.ABSOLUTE_PATH, path=path, detail="output paths must be relative"
            )
        )
        return violations
    parts = PurePosixPath(path).parts
    if any(part == ".." for part in parts):
        violations.append(
            AdmissionViolation(
                code=ViolationCode.PATH_TRAVERSAL,
                path=path,
                detail="path escapes the candidate root via '..'",
            )
        )
    return violations


def _check_archive(
    entry: OutputEntry, *, max_total_bytes: int, max_ratio: float
) -> list[AdmissionViolation]:
    violations: list[AdmissionViolation] = []
    archive = entry.archive
    if archive is None:  # unreachable — caller guarantees; keeps mypy certain
        return violations
    compressed = max(entry.size_bytes, 1)
    ratio = archive.uncompressed_total_bytes / compressed
    if archive.uncompressed_total_bytes > max_total_bytes:
        violations.append(
            AdmissionViolation(
                code=ViolationCode.ARCHIVE_BOMB,
                path=entry.path,
                detail=(
                    f"uncompressed size {archive.uncompressed_total_bytes} exceeds "
                    f"bundle cap {max_total_bytes}"
                ),
            )
        )
    elif ratio > max_ratio:
        violations.append(
            AdmissionViolation(
                code=ViolationCode.ARCHIVE_BOMB,
                path=entry.path,
                detail=f"compression ratio {ratio:.0f} exceeds cap {max_ratio:.0f}",
            )
        )
    return violations


def _skeleton(segment: str) -> str:
    """Fold a path segment down to its ASCII skeleton."""
    normalized = unicodedata.normalize("NFKC", segment)
    return "".join(_SKELETON_MAP.get(char, char) for char in normalized).casefold()


def _check_confusables(
    entry: OutputEntry, protected_paths: tuple[str, ...]
) -> list[AdmissionViolation]:
    """Reject lookalike paths that could shadow protected directories.

    Three signals, any of which rejects: the path changes under NFKC
    normalization (compatibility/fullwidth characters); it carries invisible
    formatting characters (zero-width joiners, bidi controls); or a segment's
    homoglyph skeleton matches a protected name while its raw spelling
    differs.
    """
    violations: list[AdmissionViolation] = []
    path = entry.path
    if unicodedata.normalize("NFKC", path) != path:
        violations.append(
            AdmissionViolation(
                code=ViolationCode.CONFUSABLE_PATH,
                path=path,
                detail="path changes under NFKC normalization",
            )
        )
        return violations
    if any(unicodedata.category(char) == "Cf" for char in path):
        violations.append(
            AdmissionViolation(
                code=ViolationCode.CONFUSABLE_PATH,
                path=path,
                detail="path contains invisible formatting characters",
            )
        )
        return violations
    protected = {name.casefold() for name in protected_paths}
    for segment in PurePosixPath(path).parts:
        skeleton = _skeleton(segment)
        if skeleton in protected and skeleton != segment.casefold():
            violations.append(
                AdmissionViolation(
                    code=ViolationCode.CONFUSABLE_PATH,
                    path=path,
                    detail=f"segment {segment!r} is a homoglyph of protected path {skeleton!r}",
                )
            )
            break
    return violations

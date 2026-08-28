"""Filesystem helpers for renaming uploaded files."""

from pathlib import Path


def with_extension(path: Path, new_suffix: str) -> Path:
    """Return path with its file extension replaced, e.g. "a.txt" -> "a.md"."""
    name = path.name
    without_ext = name[:-4]
    return path.with_name(without_ext + new_suffix)

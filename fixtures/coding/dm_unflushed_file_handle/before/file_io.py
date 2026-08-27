"""File writing helper that also reports the line count it wrote."""

from pathlib import Path


def write_lines_and_count(path: Path, lines: list[str]) -> int:
    """Write lines to path (newline-joined) and return the line count read back."""
    handle = open(path, "w")
    handle.write("\n".join(lines) + "\n")
    return len(path.read_text().splitlines())

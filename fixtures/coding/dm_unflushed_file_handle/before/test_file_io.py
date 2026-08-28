from pathlib import Path

from file_io import write_lines_and_count


def test_write_lines_and_count_reads_back_written_lines(tmp_path: Path) -> None:
    target = tmp_path / "out.txt"
    assert write_lines_and_count(target, ["one", "two", "three"]) == 3

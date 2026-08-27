from pathlib import Path

from filesystem_util import with_extension


def test_with_extension_replaces_short_suffix():
    assert with_extension(Path("report.py"), ".md") == Path("report.md")


def test_with_extension_replaces_long_suffix():
    assert with_extension(Path("photo.jpeg"), ".png") == Path("photo.png")

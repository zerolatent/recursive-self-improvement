"""Substring search shared by the doc search feature."""

import re


def contains_literal(haystack: str, needle: str) -> bool:
    """True if haystack contains needle as a literal substring."""
    pattern = re.compile(needle)
    return bool(pattern.search(haystack))

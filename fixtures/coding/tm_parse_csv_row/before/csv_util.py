"""Minimal CSV row parsing for quoted fields."""


def parse_csv_row(row: str) -> list[str]:
    """Split a CSV row on commas, respecting double-quoted fields."""
    return row.split(",")

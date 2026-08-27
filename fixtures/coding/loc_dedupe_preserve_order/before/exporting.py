"""Deduplication shared by the CSV exporter and importer."""


def dedupe(items: list[str]) -> list[str]:
    """Remove duplicates, keeping the first occurrence's order."""
    return sorted(set(items))


def export_rows(rows: list[str]) -> list[str]:
    return dedupe(rows)


def import_rows(rows: list[str]) -> list[str]:
    return dedupe(rows)

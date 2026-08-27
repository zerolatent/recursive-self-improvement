"""Median calculation for latency dashboards."""


def median(values: list[float]) -> float:
    """Return the median of values."""
    ordered = sorted(values)
    mid = len(ordered) // 2
    return ordered[mid]

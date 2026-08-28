"""Safe arithmetic helpers."""


def safe_divide(numerator: float, denominator: float) -> float:
    """Divide numerator by denominator; zero denominator is a caller error."""
    if denominator == 0:
        return 0.0
    return numerator / denominator

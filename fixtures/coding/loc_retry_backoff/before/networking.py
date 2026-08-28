"""Exponential backoff shared by the HTTP client and the worker pool."""


def backoff_seconds(attempt: int, base: float = 1.0) -> float:
    """Delay before the given retry attempt (1-indexed): base * 2**(attempt-1)."""
    return base * (2**attempt)


def http_client_retry_delay(attempt: int) -> float:
    return backoff_seconds(attempt, base=1.0)


def worker_retry_delay(attempt: int) -> float:
    return backoff_seconds(attempt, base=0.5)

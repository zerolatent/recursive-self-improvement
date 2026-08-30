"""A deterministic token-bucket rate limiter (unit-test generation target)."""

from __future__ import annotations


class TokenBucket:
    """Token bucket with explicit, caller-supplied elapsed time.

    Time is a parameter, not a clock read, so behavior is a pure function
    of the call sequence — the property that makes generated tests
    deterministic and the mutation-adequacy check meaningful.
    """

    def __init__(self, capacity: float, refill_rate: float) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        if refill_rate < 0:
            raise ValueError("refill_rate must be non-negative")
        self._capacity = capacity
        self._tokens = capacity
        self._refill_rate = refill_rate

    @property
    def available(self) -> float:
        """Tokens currently in the bucket (never above capacity)."""
        return self._tokens

    def try_acquire(self, requested: float = 1.0, elapsed_s: float = 0.0) -> bool:
        """Refill by `elapsed_s`, then try to take `requested` tokens."""
        if requested > self._capacity:
            raise ValueError("request exceeds bucket capacity")
        self._tokens = min(self._capacity, self._tokens + elapsed_s * self._refill_rate)
        if self._tokens >= requested:
            self._tokens -= requested
            return True
        return False

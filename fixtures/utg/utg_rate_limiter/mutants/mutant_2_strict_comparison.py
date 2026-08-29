"""Mutant 2: an acquire at exactly the remaining balance fails (spec rule 4)."""

from __future__ import annotations


class TokenBucket:
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
        return self._tokens

    def try_acquire(self, requested: float = 1.0, elapsed_s: float = 0.0) -> bool:
        if requested > self._capacity:
            raise ValueError("request exceeds bucket capacity")
        self._tokens = min(self._capacity, self._tokens + elapsed_s * self._refill_rate)
        if self._tokens > requested:  # BUG: strict >, exact balance rejected
            self._tokens -= requested
            return True
        return False

"""Reference tests for the TokenBucket spec (the mutation-adequacy bar)."""

from __future__ import annotations

import pytest
from module import TokenBucket


def test_bucket_starts_full() -> None:
    bucket = TokenBucket(capacity=3.0, refill_rate=0.5)
    assert bucket.available == 3.0


def test_acquire_at_exact_balance_succeeds() -> None:
    bucket = TokenBucket(capacity=2.0, refill_rate=1.0)
    assert bucket.try_acquire(requested=2.0, elapsed_s=0.0) is True
    assert bucket.available == 0.0


def test_acquire_beyond_balance_fails_without_consuming() -> None:
    bucket = TokenBucket(capacity=2.0, refill_rate=1.0)
    assert bucket.try_acquire(requested=1.5, elapsed_s=0.0) is True
    assert bucket.try_acquire(requested=1.0, elapsed_s=0.0) is False
    assert bucket.available == 0.5


def test_refill_is_capped_at_capacity() -> None:
    bucket = TokenBucket(capacity=2.0, refill_rate=10.0)
    bucket.try_acquire(requested=2.0, elapsed_s=0.0)
    bucket.try_acquire(requested=0.0, elapsed_s=100.0)
    assert bucket.available == 2.0


def test_refill_accrues_partially() -> None:
    bucket = TokenBucket(capacity=2.0, refill_rate=1.0)
    bucket.try_acquire(requested=2.0, elapsed_s=0.0)
    assert bucket.try_acquire(requested=0.25, elapsed_s=0.25) is True
    assert bucket.available == 0.0


def test_invalid_construction_raises() -> None:
    with pytest.raises(ValueError):
        TokenBucket(capacity=0.0, refill_rate=1.0)
    with pytest.raises(ValueError):
        TokenBucket(capacity=2.0, refill_rate=-1.0)


def test_request_larger_than_capacity_raises() -> None:
    bucket = TokenBucket(capacity=2.0, refill_rate=1.0)
    with pytest.raises(ValueError):
        bucket.try_acquire(requested=3.0)

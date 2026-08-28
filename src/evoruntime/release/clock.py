"""Clocks for the release plane: real time and compressed simulation time.

The FR-012 thresholds are stated in wall-clock units — a minimum 24-hour
observation horizon, fleet p99 convergence within 5 minutes, pointer CAS
within 30 seconds. Tests cannot wait 24 hours, so every time consumer in
this package reads time through one of the small interfaces here and tests
substitute :class:`CompressedClock`: one advanced tick scaled up to hours
of observation. The real clock stays available for the verification run —
the same harness code runs against both.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Protocol


class WallClock(Protocol):
    """A source of civil time (datetimes) that can be advanced in tests."""

    def now(self) -> datetime: ...

    def advance(self, seconds: float) -> None: ...


class MonotonicClock(Protocol):
    """A source of logical seconds, advanced explicitly in simulation.

    The fleet simulator measures convergence in these seconds: they are
    the same units the FR-012 thresholds (≤5 minutes, ≤30 seconds) are
    stated in, whether they flow from the real clock or a compressed one.
    """

    def seconds(self) -> float: ...

    def advance(self, seconds: float) -> None: ...


class RealClock:
    """Wall and monotonic time from the host — the verification-run clock."""

    def __init__(self) -> None:
        self._start = datetime.now(UTC)
        self._elapsed = 0.0

    def now(self) -> datetime:
        return self._start + timedelta(seconds=self._elapsed)

    def seconds(self) -> float:
        return self._elapsed

    def advance(self, seconds: float) -> None:
        """Advance the clock by fiat — tests only; real time also flows."""
        self._elapsed += seconds


class CompressedClock:
    """Simulated time: each advanced second counts as ``scale`` seconds.

    A scale of 3600 compresses a 24-hour observation horizon into 24
    advanced seconds, so the canary harness exercises the real horizon
    arithmetic in tests without waiting a day. ``now()`` and ``seconds()``
    agree — they are the same simulated instant in two units.
    """

    def __init__(self, *, scale: float = 3600.0) -> None:
        if scale <= 0:
            raise ValueError(f"scale must be positive, got {scale}")
        self._scale = scale
        self._start = datetime.now(UTC)
        self._elapsed = 0.0

    def now(self) -> datetime:
        return self._start + timedelta(seconds=self._elapsed * self._scale)

    def seconds(self) -> float:
        return self._elapsed * self._scale

    def advance(self, seconds: float) -> None:
        if seconds < 0:
            raise ValueError(f"cannot advance the clock backwards ({seconds!r}s)")
        self._elapsed += seconds


def monotonic_now() -> float:
    """Host monotonic time, for measuring real (uncompressed) durations
    such as the CAS ≤30s threshold in the verification run."""
    return time.monotonic()


__all__ = ["CompressedClock", "MonotonicClock", "RealClock", "WallClock", "monotonic_now"]

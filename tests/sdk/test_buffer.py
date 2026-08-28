"""Backpressure conformance: a full buffer drops with a counter, never blocks.

PRD FR-001 / spec D3: "full buffer drops-with-counter, agent thread never
blocks >1ms on emit". These tests pin both halves at the buffer level, where
the property actually lives; `test_adapter.py` re-checks it end to end
through the public `Trace` surface.
"""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime

import pytest

from evoruntime.sdk.buffer import EventBuffer
from evoruntime.sdk.records import PendingEvent
from tests.sdk.support import MODEL, ZERO

EMIT_BLOCK_BUDGET_S = 0.001


def make_pending(index: int) -> PendingEvent:
    return PendingEvent(
        occurred_at=datetime.now(UTC),
        trace_id=f"trc_{index:012d}",
        task_id=f"tsk_{index:012d}",
        type="tool.completed",
        model=MODEL,
        cost=ZERO,
        artifact_digests=(),
        details={"index": index},
    )


@pytest.fixture
def wake() -> threading.Event:
    return threading.Event()


def test_offer_accepts_until_full_then_drops_with_counter(wake: threading.Event) -> None:
    buffer = EventBuffer(4, high_water=4, wake=wake)

    accepted = [buffer.offer(make_pending(i)) for i in range(10)]

    assert accepted == [True] * 4 + [False] * 6
    counters = buffer.counters()
    assert counters.accepted == 4
    assert counters.dropped == 6
    assert counters.size == 4


def test_full_buffer_never_grows_past_max(wake: threading.Event) -> None:
    buffer = EventBuffer(3, high_water=3, wake=wake)

    for i in range(100):
        buffer.offer(make_pending(i))

    assert len(buffer) == 3


def test_drop_keeps_the_trace_prefix_not_the_tail(wake: threading.Event) -> None:
    """A truncated trace is only diagnosable if its *head* survived."""
    buffer = EventBuffer(2, high_water=2, wake=wake)

    for i in range(5):
        buffer.offer(make_pending(i))

    assert [event.details["index"] for event in buffer.drain()] == [0, 1]


def test_drain_returns_events_in_emit_order_and_empties(wake: threading.Event) -> None:
    buffer = EventBuffer(10, high_water=10, wake=wake)
    for i in range(5):
        buffer.offer(make_pending(i))

    drained = buffer.drain()

    assert [event.details["index"] for event in drained] == [0, 1, 2, 3, 4]
    assert buffer.drain() == []
    assert len(buffer) == 0


def test_high_water_wakes_the_flusher(wake: threading.Event) -> None:
    """Waking by volume is what bounds the unjournaled backlog by a *count*,
    which is the shape of the PRD's ≤100-event crash-flush bound."""
    buffer = EventBuffer(100, high_water=3, wake=wake)

    buffer.offer(make_pending(0))
    buffer.offer(make_pending(1))
    assert not wake.is_set()

    buffer.offer(make_pending(2))
    assert wake.is_set()


def test_offer_does_not_block_when_full(wake: threading.Event) -> None:
    """The p99 of a rejected emit, measured: dropping must be the *fast*
    path, since it is the path taken exactly when the agent is busiest."""
    buffer = EventBuffer(1, high_water=1, wake=wake)
    buffer.offer(make_pending(0))
    event = make_pending(1)

    durations = []
    for _ in range(2_000):
        start = time.perf_counter()
        accepted = buffer.offer(event)
        durations.append(time.perf_counter() - start)
        assert accepted is False

    durations.sort()
    assert durations[int(len(durations) * 0.99)] < EMIT_BLOCK_BUDGET_S
    assert buffer.counters().dropped == 2_000


def test_concurrent_producers_lose_nothing_to_races(wake: threading.Event) -> None:
    """accepted + dropped must equal what was offered, under contention."""
    buffer = EventBuffer(500, high_water=500, wake=wake)
    per_thread = 400
    threads = [
        threading.Thread(target=lambda: [buffer.offer(make_pending(i)) for i in range(per_thread)])
        for _ in range(4)
    ]

    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    counters = buffer.counters()
    assert counters.accepted + counters.dropped == per_thread * 4
    assert counters.accepted == 500


@pytest.mark.parametrize(("max_events", "high_water"), [(0, 1), (-1, 1), (10, 0)])
def test_invalid_construction_is_rejected(
    max_events: int, high_water: int, wake: threading.Event
) -> None:
    with pytest.raises(ValueError):
        EventBuffer(max_events, high_water=high_water, wake=wake)


def test_high_water_is_clamped_to_capacity(wake: threading.Event) -> None:
    """A high-water mark above capacity would never fire, silently disabling
    volume-triggered flushes."""
    buffer = EventBuffer(2, high_water=50, wake=wake)

    buffer.offer(make_pending(0))
    buffer.offer(make_pending(1))

    assert wake.is_set()

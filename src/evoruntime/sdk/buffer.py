"""The bounded emit buffer — the SDK's backpressure boundary.

Every emit path in the SDK ends here, and this is the one place where the
adapter is allowed to lose an event on purpose. The PRD's conformance
profile (FR-001) is explicit about the trade: under backpressure the adapter
*drops with a counter* rather than blocking, because a coding agent that
stalls on telemetry has been made less reliable by the very system built to
measure its reliability.

Two properties are load-bearing and tested directly:

* `offer` never blocks on anything but an uncontended lock held for a few
  microseconds — no I/O, no allocation beyond the deque slot, no condition
  waiting on a consumer.
* A full buffer increments `dropped` and returns ``False``. It never
  silently overwrites, and it never grows past `max_events`.
"""

from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass

from evoruntime.sdk.records import PendingEvent


@dataclass(frozen=True, slots=True)
class BufferCounters:
    """Point-in-time counts. A snapshot, not a live view."""

    accepted: int
    dropped: int
    size: int


class EventBuffer:
    """A bounded, thread-safe hand-off queue from agent threads to the flusher.

    `high_water` exists so the flusher can be woken by *volume* and not only
    by its timer. Without it, the crash-flush bound would degrade with emit
    rate: a fast agent could pile up a tick's worth of events (thousands)
    between wakeups, all of them still only in memory. Waking the flusher as
    soon as `high_water` events are queued keeps the unjournaled backlog
    bounded by a count, which is exactly the shape of the PRD §17.3 loss
    bound (≤100 events).
    """

    def __init__(self, max_events: int, *, high_water: int, wake: threading.Event) -> None:
        if max_events < 1:
            raise ValueError("max_events must be >= 1")
        if high_water < 1:
            raise ValueError("high_water must be >= 1")
        self._max_events = max_events
        self._high_water = min(high_water, max_events)
        self._wake = wake
        self._lock = threading.Lock()
        self._items: deque[PendingEvent] = deque()
        self._accepted = 0
        self._dropped = 0

    @property
    def max_events(self) -> int:
        return self._max_events

    def offer(self, event: PendingEvent) -> bool:
        """Queue an event, or drop it if the buffer is full.

        Returns ``True`` when the event was queued, ``False`` when it was
        dropped. Dropping the *arriving* event (rather than evicting the
        oldest) is deliberate: the head of a trace — task setup, the first
        tool calls — is what makes a truncated trace diagnosable at all, so
        the prefix is the part worth keeping when a producer outruns the
        network.
        """
        with self._lock:
            if len(self._items) >= self._max_events:
                self._dropped += 1
                return False
            self._items.append(event)
            self._accepted += 1
            should_wake = len(self._items) >= self._high_water
        if should_wake:
            self._wake.set()
        return True

    def drain(self) -> list[PendingEvent]:
        """Remove and return everything queued, in emit order."""
        with self._lock:
            if not self._items:
                return []
            drained = list(self._items)
            self._items.clear()
        return drained

    def counters(self) -> BufferCounters:
        with self._lock:
            return BufferCounters(
                accepted=self._accepted, dropped=self._dropped, size=len(self._items)
            )

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)

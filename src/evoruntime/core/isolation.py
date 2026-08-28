"""Shared isolation vocabulary.

``IsolationTier`` is the Phase 2 execution trust boundary (spec: "The
execution trust boundary"): every executable candidate declares the tier it
needs, and no candidate bytes execute anywhere except inside the sandbox
executor at that declared tier. The enum lives in :mod:`evoruntime.core`
because two planes own halves of it — the plugin manifest declares the tier
(:mod:`evoruntime.plugins.manifest`) and the sandbox plane enforces it
(:mod:`evoruntime.sandbox`) — and neither may depend on the other.
"""

from __future__ import annotations

from enum import StrEnum


class IsolationTier(StrEnum):
    """How isolated an execution of candidate bytes must be.

    ``TEXT_ONLY`` is the Phase 1 status quo: the artifact is data, never
    executed. ``BROKERED`` runs code whose network egress flows only through
    the egress-broker proxy. ``EXECUTABLE`` runs namespace-isolated with no
    network by default. ``HIGHEST`` is harness-touching code: manual,
    two-person initiation, no production automation.
    """

    TEXT_ONLY = "text-only"
    BROKERED = "brokered"
    EXECUTABLE = "executable"
    HIGHEST = "highest"

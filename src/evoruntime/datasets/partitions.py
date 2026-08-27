"""Dataset partition taxonomy (PRD §12.2).

A partition's *kind* determines two things that must never drift apart:
which storage identity may hold its content, and whether reading it is
mediated by a sealed handle. Both are derived here so the DB constraint,
the service layer, and the API all answer from one source.
"""

from __future__ import annotations

from enum import StrEnum

from evoruntime.core.identity import StorageIdentity

HOLDOUT_HANDLE_SCHEME = "holdout"
"""URI scheme for the opaque handle the API hands out in place of content."""


class PartitionKind(StrEnum):
    """The six Phase 0 dataset partitions (PRD §12.2)."""

    DISCOVERY = "discovery"
    """Exploration data. Freely readable; contaminating it costs nothing."""

    DEV = "dev"
    """Iteration data. Baselines and campaign development run here."""

    SELECTION = "selection"
    """Candidate selection. Read repeatedly, so its results never gate promotion alone."""

    HOLDOUT = "holdout"
    """Sealed. Content never leaves the evaluation plane; reads are ledgered."""

    ADVERSARIAL = "adversarial"
    """Attack fixtures: prompt injection, exfiltration, destructive operations."""

    CANARY = "canary"
    """Contamination tripwire: leaked canary items prove holdout exposure."""


SEALED_PARTITION_KINDS: frozenset[PartitionKind] = frozenset({PartitionKind.HOLDOUT})
"""Partition kinds whose content is reachable only through a sealed handle."""


def is_sealed(kind: PartitionKind) -> bool:
    """True when this partition's content requires a sealed handle to reach."""
    return kind in SEALED_PARTITION_KINDS


def required_storage_identity(kind: PartitionKind) -> StorageIdentity:
    """Return the only storage identity permitted to hold this kind's content.

    Sealed partitions are pinned to the evaluation plane; everything else
    lives under the runtime identity where the harness and agents can read
    it directly.
    """
    if is_sealed(kind):
        return StorageIdentity.EVALUATION_PLANE
    return StorageIdentity.RUNTIME_PLANE

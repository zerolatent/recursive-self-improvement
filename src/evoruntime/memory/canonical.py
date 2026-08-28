"""Canonical serialization and identity for memory entries (deliverable E6).

A memory entry's canonical body is registered through the E1 artifact
registry as a `memory_entry` artifact, so it inherits exactly what the
registry guarantees: content-addressed identity, per-tenant encrypted
storage, and an append-only lifecycle event stream. The memory module adds
the §9.3 governance layer on top; it does not reinvent content addressing.

The canonical bytes cover the entry's declared content plus the generated
memory id (so two registrations of identical content in one tenant remain
distinguishable rows). Retrieval counts and lifecycle status are runtime
state and deliberately excluded — they live on the row, never in the
digest.
"""

from __future__ import annotations

from typing import Any

from evoruntime.core.ids import new_id
from evoruntime.memory.schemas import MemoryEntry
from evoruntime.registry.canonical import canonical_json

MEMORY_ID_PREFIX = "mem"
MEMORY_ENTRY_ARTIFACT_TYPE = "memory_entry"


def new_memory_id() -> str:
    return new_id(MEMORY_ID_PREFIX)


def entry_canonical_bytes(memory_id: str, entry: MemoryEntry) -> bytes:
    """Canonical bytes the memory entry is registered (and digested) over.

    `model_dump(mode="json")` normalizes enums and datetimes to their JSON
    forms so two serializations of the same logical entry are
    byte-identical regardless of how the caller constructed it.
    """
    dumped: dict[str, Any] = entry.model_dump(mode="json")
    return canonical_json({"memory_id": memory_id, "entry": dumped})

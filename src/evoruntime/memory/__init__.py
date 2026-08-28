"""Memory hygiene and suggestion-first memory (deliverable E6, PRD §9.3 +
FR-016).

Public surface:

- `MemoryEntry` and friends (`memory.schemas`) — the typed §9.3 schema.
- `MemoryService` (`memory.service`) — propose / quarantine / promote /
  revoke / expire, with purge propagation through the D4 tombstone flow.
- `memory.gates` — the persistence non-inferiority, negative-transfer,
  and hygiene gates that guard the only suggestion → active path.
- `memory.hygiene` — pure poison / staleness / conflict checks.
"""

from __future__ import annotations

from evoruntime.memory.errors import (
    MemoryError,
    MemoryNotFoundError,
    PromotionBlockedError,
    SupersessionTargetNotFoundError,
)
from evoruntime.memory.gates import GateReport, GateResult
from evoruntime.memory.schemas import (
    Claim,
    EvidenceRef,
    MemoryEntry,
    MemoryScope,
    MemoryStatus,
    Provenance,
    SemanticType,
    Sensitivity,
    TimeValidity,
)

# `MemoryService` is deliberately NOT imported here: `db.models.memory`
# imports `evoruntime.memory.schemas`, so an eager service import at package
# load time creates a circular import. Import it from `evoruntime.memory.service`.

__all__ = [
    "Claim",
    "EvidenceRef",
    "GateReport",
    "GateResult",
    "MemoryEntry",
    "MemoryError",
    "MemoryNotFoundError",
    "MemoryScope",
    "MemoryStatus",
    "PromotionBlockedError",
    "Provenance",
    "SemanticType",
    "Sensitivity",
    "SupersessionTargetNotFoundError",
    "TimeValidity",
]

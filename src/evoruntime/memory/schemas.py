"""Typed schema for memory entries (deliverable E6, PRD §9.3).

A memory entry is a *claim with a biography*. Every field the PRD names is
declared here and validated at the boundary, because a memory that reaches
a prompt without its provenance attached is indistinguishable from one a
poisoned source injected directly:

- **semantic type** — what kind of knowledge the claim carries.
- **provenance + trust domain** — which strategy produced it and which
  trust plane vouches for that strategy. Hygiene (not the schema) decides
  which trust domains are admitted; the schema only guarantees the field
  cannot be absent.
- **subject/environment scope** — where the claim is allowed to apply.
  Conflict detection and negative-transfer probing both key off this.
- **confidence with supporting AND contradicting evidence** — both lists
  are part of the schema even when one is empty. An entry that hides its
  contradicting evidence is claiming a confidence the record cannot
  support; hygiene quarantines entries with no supporting evidence at all.
- **time validity** — `valid_until` is the TTL; the expiry sweep retires
  entries past it.
- **sensitivity** — the DLP classification the entry inherits.
- **retrieval utility** — the proposer's declared prior on how useful the
  entry is when retrieved; observed retrieval counts live on the row.
- **supersession links** — the memory ids an entry replaces when promoted.

Generalized lessons are a separate *derived* artifact class
(`is_generalized_lesson=True` + `parent_memory_ids`): a lesson cites the
evidence entries it generalizes, so a bad abstraction can be revoked
without deleting the unrelated evidence it was distilled from. The schema
enforces the pairing — a lesson with no parents is unattributed
generalization, and parents on a non-lesson are a category error.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal, Self

from pydantic import Field, model_validator

from evoruntime.core.schemas import EvoRuntimeBaseModel

#: Bumped when the §9.3 field set changes shape (new required field, changed
#: semantics of an existing one). Readers refuse entries from a newer
#: schema version rather than guessing.
MEMORY_SCHEMA_VERSION = 1


class SemanticType(StrEnum):
    """What kind of knowledge the entry carries (§9.3 semantic type)."""

    FACT = "fact"
    PREFERENCE = "preference"
    PROCEDURE = "procedure"
    OBSERVATION = "observation"


class Sensitivity(StrEnum):
    """DLP classification the entry inherits (FR-015 boundary)."""

    PUBLIC = "public"
    INTERNAL = "internal"
    SENSITIVE = "sensitive"
    RESTRICTED = "restricted"


class MemoryStatus(StrEnum):
    """Lifecycle status of a memory entry.

    Entries are born as SUGGESTION (suggestion-first, FR-016) and only
    ever reach ACTIVE through the gated promotion path. QUARANTINED,
    REVOKED, and EXPIRED are the three ways an entry leaves circulation;
    which one applies is recorded in the row's `status_reason`.
    """

    SUGGESTION = "suggestion"
    ACTIVE = "active"
    QUARANTINED = "quarantined"
    REVOKED = "revoked"
    EXPIRED = "expired"


EvidenceKind = Literal["trace", "attestation", "task_run", "memory"]
"""Where a piece of evidence came from. `memory` cites another memory
entry — the link generalized lessons are built from."""


class EvidenceRef(EvoRuntimeBaseModel):
    """A pointer to one piece of supporting or contradicting evidence."""

    kind: EvidenceKind
    ref: str = Field(min_length=1)


class Provenance(EvoRuntimeBaseModel):
    """Where the entry came from and which trust plane vouches for it."""

    strategy_id: str = Field(min_length=1)
    trust_domain: str = Field(min_length=1)
    source_ref: str | None = None
    """Trace/attestation/task-run reference the entry was derived from."""


class MemoryScope(EvoRuntimeBaseModel):
    """Where the claim is allowed to apply (route by subject/environment/
    task, optionally narrowed to a model or harness)."""

    subject: str = Field(min_length=1)
    environment: str = Field(min_length=1)
    task_type: str = Field(min_length=1)
    model_id: str | None = None
    harness_id: str | None = None


class Claim(EvoRuntimeBaseModel):
    """The entry's assertion.

    `key` is the normalized claim identity conflict detection matches on;
    two entries with the same key but different statements are competing
    claims about the same thing, and hygiene quarantines the newcomer
    until the conflict is resolved.
    """

    key: str = Field(min_length=1)
    statement: str = Field(min_length=1)


class TimeValidity(EvoRuntimeBaseModel):
    """When the claim holds. `valid_until=None` means no TTL."""

    valid_from: datetime
    valid_until: datetime | None = None

    @model_validator(mode="after")
    def _window_ordered(self) -> Self:
        if self.valid_until is not None and self.valid_until <= self.valid_from:
            raise ValueError(
                f"valid_until {self.valid_until.isoformat()} must be after "
                f"valid_from {self.valid_from.isoformat()}"
            )
        return self


class MemoryEntry(EvoRuntimeBaseModel):
    """One §9.3 memory entry: a claim, its provenance, scope, evidence,
    validity window, and lifecycle links."""

    schema_version: int = MEMORY_SCHEMA_VERSION
    semantic_type: SemanticType
    provenance: Provenance
    scope: MemoryScope
    claim: Claim
    confidence: float = Field(ge=0.0, le=1.0)
    supporting_evidence: tuple[EvidenceRef, ...] = ()
    contradicting_evidence: tuple[EvidenceRef, ...] = ()
    time_validity: TimeValidity
    sensitivity: Sensitivity
    retrieval_utility: float = Field(default=0.5, ge=0.0, le=1.0)
    """Proposer's declared prior on retrieval usefulness; observed counts
    are runtime state on the row, never part of this declared body."""
    supersedes: tuple[str, ...] = ()
    """Memory ids this entry replaces when it is promoted."""
    is_generalized_lesson: bool = False
    parent_memory_ids: tuple[str, ...] = ()
    """Evidence entries the lesson was distilled from (lessons only)."""

    @model_validator(mode="after")
    def _lesson_shape(self) -> Self:
        if self.is_generalized_lesson and not self.parent_memory_ids:
            raise ValueError(
                "a generalized lesson must cite the memory entries it "
                "generalizes — unattributed abstraction is how bad lessons "
                "become unrevokable"
            )
        if not self.is_generalized_lesson and self.parent_memory_ids:
            raise ValueError("parent_memory_ids are only valid on generalized lessons")
        return self

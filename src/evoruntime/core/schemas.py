"""Base schema primitives shared by every EvoRuntime data contract.

Concrete schemas (trace event envelope, lineage nodes/edges, dataset
partition metadata) are added by later deliverables. This module only
defines the conventions those schemas must follow so they stay consistent
from the first one onward.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class EvoRuntimeBaseModel(BaseModel):
    """Base model for every EvoRuntime schema.

    Frozen and forbids unknown fields so malformed or tampered payloads fail
    validation instead of silently dropping data (PRD §18.3 envelope
    validation requirement).
    """

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)


class SchemaVersion(BaseModel):
    """Explicit schema version carried by every versioned envelope/record."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    value: int

    def __int__(self) -> int:
        return self.value

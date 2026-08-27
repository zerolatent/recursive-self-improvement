"""Data contracts for partitions, sealed handles, and the query ledger.

The split between `HoldoutHandleMetadata` and `HoldoutContentRef` is the
trust boundary expressed as types: metadata is safe to hand to any
authenticated caller, `HoldoutContentRef` is only ever constructed after
an evaluator-role authorization has been recorded in the ledger. No model
here carries both, so a serialization mistake cannot leak content through
a metadata endpoint.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any

from pydantic import Field

from evoruntime.core.identity import Role, StorageIdentity
from evoruntime.core.schemas import EvoRuntimeBaseModel
from evoruntime.datasets.errors import DenialReason
from evoruntime.datasets.models import LedgerOutcome
from evoruntime.datasets.partitions import PartitionKind


class PartitionSummary(EvoRuntimeBaseModel):
    """A partition's governance record.

    `content_locator` is `None` for sealed partitions: the locator is the
    evaluation plane's storage path, and it is reachable only by resolving
    a handle, never by listing partitions.
    """

    id: str
    tenant_id: str
    dataset_id: str
    name: str
    kind: PartitionKind
    storage_identity: StorageIdentity
    owner: str
    item_count: int
    content_digest: str
    created_at: datetime
    sealed: bool
    content_locator: str | None = None


class AlphaBudgetReport(EvoRuntimeBaseModel):
    """Remaining statistical budget for a sealed handle (PRD §12.2)."""

    total: Decimal
    spent: Decimal
    remaining: Decimal
    per_query: Decimal
    queries_remaining: int


class HoldoutHandleMetadata(EvoRuntimeBaseModel):
    """Everything a caller may learn about a sealed handle without reading it.

    Deliberately excludes the token and the content locator.
    """

    handle_id: str
    partition_id: str
    tenant_id: str
    token_prefix: str
    owner: str
    created_at: datetime
    created_by: str
    expires_at: datetime
    freshness_window_days: int
    rotation_plan: str
    rotation_count: int
    rotated_at: datetime | None
    revoked_at: datetime | None
    contamination_audit: dict[str, Any]
    alpha_budget: AlphaBudgetReport


class IssuedHoldoutHandle(EvoRuntimeBaseModel):
    """A freshly minted (or rotated) handle: the one moment the token is disclosed.

    The plaintext token exists only in this response — the database keeps
    a SHA-256 digest — so a lost token is rotated, never recovered.
    """

    handle_uri: str = Field(description="Opaque capability, e.g. holdout://<token>")
    metadata: HoldoutHandleMetadata


class HoldoutContentRef(EvoRuntimeBaseModel):
    """A resolved pointer into evaluation-plane storage.

    Returned only to an evaluator-role principal, and only after the
    resolution has been written to the query ledger.
    """

    partition_id: str
    content_locator: str
    content_digest: str
    item_count: int
    resolved_at: datetime
    ledger_entry_id: str
    alpha_budget: AlphaBudgetReport


class LedgerEntryRecord(EvoRuntimeBaseModel):
    """One append-only ledger row, grant or denial."""

    id: str
    handle_id: str
    partition_id: str
    tenant_id: str
    caller_identity: str
    caller_role: Role
    purpose: str
    outcome: LedgerOutcome
    denial_reason: DenialReason | None
    alpha_spent: Decimal
    alpha_remaining: Decimal
    occurred_at: datetime

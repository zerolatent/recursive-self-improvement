"""Dataset partition and sealed-holdout HTTP API.

Handle-bearing operations are POSTs with the token in the body, never a
path or query parameter: URLs land in access logs, proxy traces, and
browser history, and a capability that leaks into a log line is a
capability that has been disclosed.

The response models are the enforcement, not a convention. Metadata
endpoints are annotated with `HoldoutHandleMetadata`, which has no field
that can carry content; only `/holdout/resolve` returns
`HoldoutContentRef`, and the service refuses to build one for a caller
outside the evaluation plane.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

from fastapi import APIRouter, status
from pydantic import BaseModel, Field

from evoruntime.datasets.partitions import PartitionKind
from evoruntime.datasets.schemas import (
    AlphaBudgetReport,
    HoldoutContentRef,
    HoldoutHandleMetadata,
    IssuedHoldoutHandle,
    LedgerEntryRecord,
    PartitionSummary,
)
from evoruntime.server.dependencies import DatasetServiceDep, HoldoutServiceDep, PrincipalDep

router = APIRouter(prefix="/v1/datasets", tags=["datasets"])


class CreatePartitionRequest(BaseModel):
    """Register a partition. Storage identity is derived from `kind`, not sent."""

    dataset_id: str
    name: str
    kind: PartitionKind
    owner: str
    content_locator: str
    content_digest: str
    item_count: int = 0


class IssueHandleRequest(BaseModel):
    """Mint a sealed handle over an existing holdout partition."""

    owner: str
    alpha_budget_total: Decimal = Field(gt=0)
    alpha_per_query: Decimal = Field(gt=0)
    freshness_window_days: int = Field(gt=0)
    rotation_plan: str
    contamination_audit: dict[str, Any] | None = None


class HandleRequest(BaseModel):
    """A bare handle reference, for metadata/budget/ledger/rotate/revoke."""

    handle_uri: str


class ResolveHandleRequest(HandleRequest):
    """A resolution attempt. `purpose` is mandatory — it is ledgered verbatim."""

    purpose: str = Field(min_length=1, max_length=512)


@router.post("/partitions", response_model=PartitionSummary, status_code=status.HTTP_201_CREATED)
def create_partition(
    request: CreatePartitionRequest, principal: PrincipalDep, service: DatasetServiceDep
) -> PartitionSummary:
    """Register a dataset partition of one of the six PRD §12.2 kinds."""
    return service.create_partition(
        principal,
        dataset_id=request.dataset_id,
        name=request.name,
        kind=request.kind,
        owner=request.owner,
        content_locator=request.content_locator,
        content_digest=request.content_digest,
        item_count=request.item_count,
    )


@router.get("/partitions", response_model=list[PartitionSummary])
def list_partitions(
    principal: PrincipalDep, service: DatasetServiceDep, dataset_id: str | None = None
) -> list[PartitionSummary]:
    """List the caller's tenant's partitions. Sealed partitions carry no locator."""
    return service.list_partitions(principal, dataset_id=dataset_id)


@router.get("/partitions/{partition_id}", response_model=PartitionSummary)
def get_partition(
    partition_id: str, principal: PrincipalDep, service: DatasetServiceDep
) -> PartitionSummary:
    """Fetch one partition's governance record."""
    return service.get_partition(principal, partition_id)


@router.post(
    "/partitions/{partition_id}/holdout-handles",
    response_model=IssuedHoldoutHandle,
    status_code=status.HTTP_201_CREATED,
)
def issue_handle(
    partition_id: str,
    request: IssueHandleRequest,
    principal: PrincipalDep,
    service: HoldoutServiceDep,
) -> IssuedHoldoutHandle:
    """Mint a handle. The token in the response is never retrievable again."""
    return service.issue_handle(
        principal,
        partition_id=partition_id,
        owner=request.owner,
        alpha_budget_total=request.alpha_budget_total,
        alpha_per_query=request.alpha_per_query,
        freshness_window_days=request.freshness_window_days,
        rotation_plan=request.rotation_plan,
        contamination_audit=request.contamination_audit,
    )


@router.post("/holdout/metadata", response_model=HoldoutHandleMetadata)
def describe_handle(
    request: HandleRequest, principal: PrincipalDep, service: HoldoutServiceDep
) -> HoldoutHandleMetadata:
    """Return handle metadata: owner, contamination audit, freshness, rotation, budget."""
    return service.describe_handle(principal, request.handle_uri)


@router.post("/holdout/budget", response_model=AlphaBudgetReport)
def report_budget(
    request: HandleRequest, principal: PrincipalDep, service: HoldoutServiceDep
) -> AlphaBudgetReport:
    """Report remaining alpha budget for a sealed handle."""
    return service.budget_report(principal, request.handle_uri)


@router.post("/holdout/ledger", response_model=list[LedgerEntryRecord])
def read_ledger(
    request: HandleRequest, principal: PrincipalDep, service: HoldoutServiceDep
) -> list[LedgerEntryRecord]:
    """Return the append-only query ledger for a handle, oldest first."""
    return service.read_ledger(principal, request.handle_uri)


@router.post("/holdout/resolve", response_model=HoldoutContentRef)
def resolve_handle(
    request: ResolveHandleRequest, principal: PrincipalDep, service: HoldoutServiceDep
) -> HoldoutContentRef:
    """Resolve a handle to evaluation-plane content. Evaluator role only; always ledgered."""
    return service.resolve(principal, request.handle_uri, purpose=request.purpose)


@router.post("/holdout/rotate", response_model=IssuedHoldoutHandle)
def rotate_handle(
    request: HandleRequest, principal: PrincipalDep, service: HoldoutServiceDep
) -> IssuedHoldoutHandle:
    """Issue a new token for the same content. The content does not move."""
    return service.rotate_handle(principal, request.handle_uri)


@router.post("/holdout/revoke", response_model=HoldoutHandleMetadata)
def revoke_handle(
    request: HandleRequest, principal: PrincipalDep, service: HoldoutServiceDep
) -> HoldoutHandleMetadata:
    """Revoke a handle; later resolutions are denied and ledgered."""
    return service.revoke_handle(principal, request.handle_uri)

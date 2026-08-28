"""Partition model: six kinds, derived storage identity, withheld locators."""

from __future__ import annotations

import pytest

from evoruntime.core.principal import Principal
from evoruntime.datasets.errors import (
    HoldoutAccessDeniedError,
    PartitionNotFoundError,
)
from evoruntime.datasets.partitions import (
    PartitionKind,
    StorageIdentity,
    is_sealed,
    required_storage_identity,
)
from evoruntime.datasets.service import DatasetService

UNSEALED_KINDS = [
    PartitionKind.DISCOVERY,
    PartitionKind.DEV,
    PartitionKind.SELECTION,
    PartitionKind.ADVERSARIAL,
    PartitionKind.CANARY,
]
SEALED_KINDS = [PartitionKind.HOLDOUT]


def test_all_six_prd_partition_kinds_exist() -> None:
    """PRD §12.2 names exactly six partitions; drift here is a spec violation."""
    assert {kind.value for kind in PartitionKind} == {
        "discovery",
        "dev",
        "selection",
        "holdout",
        "adversarial",
        "canary",
    }


def test_adversarial_is_intentionally_not_sealed() -> None:
    """Pins the D5 narrowing so a future change is a decision, not a drift.

    Adversarial fixtures must stay executable by candidate runs and have no
    statistical alpha to spend; see `SEALED_PARTITION_KINDS` for the full
    reasoning and the Phase 1 handoff.
    """
    assert not is_sealed(PartitionKind.ADVERSARIAL)


@pytest.mark.parametrize("kind", SEALED_KINDS)
def test_sealed_kinds_require_evaluation_plane_storage(kind: PartitionKind) -> None:
    """Sealed content may only live under the evaluation plane's storage identity."""
    assert is_sealed(kind)
    assert required_storage_identity(kind) is StorageIdentity.EVALUATION_PLANE


@pytest.mark.parametrize("kind", UNSEALED_KINDS)
def test_unsealed_kinds_live_in_the_runtime_plane(kind: PartitionKind) -> None:
    """Everything the evolution plane may read stays in runtime-plane storage."""
    assert not is_sealed(kind)
    assert required_storage_identity(kind) is StorageIdentity.RUNTIME_PLANE


@pytest.mark.parametrize("kind", UNSEALED_KINDS)
def test_candidate_runner_may_create_unsealed_partitions(
    dataset_service: DatasetService, candidate_runner: Principal, kind: PartitionKind
) -> None:
    """The boundary guards sealed data, not all dataset work."""
    summary = dataset_service.create_partition(
        candidate_runner,
        dataset_id="ds_x",
        name=f"{kind.value}-part",
        kind=kind,
        owner="eng",
        content_locator=f"object://runtime-plane/{kind.value}",
        content_digest="sha256:" + "b" * 64,
    )
    assert summary.storage_identity is StorageIdentity.RUNTIME_PLANE
    assert summary.sealed is False
    assert summary.content_locator == f"object://runtime-plane/{kind.value}"


@pytest.mark.parametrize("kind", SEALED_KINDS)
def test_candidate_runner_cannot_create_sealed_partitions(
    dataset_service: DatasetService, candidate_runner: Principal, kind: PartitionKind
) -> None:
    """Creating a sealed partition is an evaluation-plane act."""
    with pytest.raises(HoldoutAccessDeniedError):
        dataset_service.create_partition(
            candidate_runner,
            dataset_id="ds_x",
            name="sneaky-holdout",
            kind=kind,
            owner="eng",
            content_locator="object://runtime-plane/sneaky",
            content_digest="sha256:" + "c" * 64,
        )


def test_sealed_partition_never_discloses_its_locator(
    dataset_service: DatasetService, evaluator: Principal
) -> None:
    """Not on create, not on get, not on list — resolution is the only route."""
    created = dataset_service.create_partition(
        evaluator,
        dataset_id="ds_y",
        name="holdout-a",
        kind=PartitionKind.HOLDOUT,
        owner="eval-team",
        content_locator="object://evaluation-plane/holdout/a",
        content_digest="sha256:" + "d" * 64,
    )
    assert created.content_locator is None
    assert created.sealed is True
    assert created.storage_identity is StorageIdentity.EVALUATION_PLANE

    fetched = dataset_service.get_partition(evaluator, created.id)
    assert fetched.content_locator is None

    listed = dataset_service.list_partitions(evaluator, dataset_id="ds_y")
    assert [partition.content_locator for partition in listed] == [None]


def test_partitions_are_scoped_to_the_callers_tenant(
    dataset_service: DatasetService, evaluator: Principal, foreign_evaluator: Principal
) -> None:
    """A partition in another tenant does not exist as far as this caller is concerned."""
    created = dataset_service.create_partition(
        evaluator,
        dataset_id="ds_z",
        name="dev-a",
        kind=PartitionKind.DEV,
        owner="eng",
        content_locator="object://runtime-plane/dev/a",
        content_digest="sha256:" + "e" * 64,
    )
    with pytest.raises(PartitionNotFoundError):
        dataset_service.get_partition(foreign_evaluator, created.id)
    assert dataset_service.list_partitions(foreign_evaluator) == []

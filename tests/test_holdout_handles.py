"""Sealed handles: issuance, metadata, alpha budget, ledgered resolution, rotation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from sqlalchemy import select, update
from sqlalchemy.orm import Session, sessionmaker

from evoruntime.core.principal import Principal
from evoruntime.datasets.errors import (
    DenialReason,
    HandleNotFoundError,
    HoldoutAccessDeniedError,
    PartitionStorageIdentityError,
)
from evoruntime.datasets.models import HoldoutHandle, LedgerOutcome
from evoruntime.datasets.partitions import PartitionKind
from evoruntime.datasets.schemas import IssuedHoldoutHandle, PartitionSummary
from evoruntime.datasets.service import (
    DatasetService,
    HoldoutService,
    digest_token,
    parse_handle_uri,
)


def _expire(session_factory: sessionmaker[Session], handle_uri: str) -> None:
    """Age a handle past its freshness window without waiting 30 days."""
    with session_factory() as session:
        session.execute(
            update(HoldoutHandle)
            .where(HoldoutHandle.token_digest == digest_token(parse_handle_uri(handle_uri)))
            .values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
        session.commit()


def test_issued_handle_is_opaque_and_carries_no_content(
    issued_handle: IssuedHoldoutHandle, sealed_partition: PartitionSummary
) -> None:
    """The caller receives a capability plus governance metadata — never a locator."""
    assert issued_handle.handle_uri.startswith("holdout://")
    token = parse_handle_uri(issued_handle.handle_uri)
    assert len(token) >= 32

    metadata = issued_handle.metadata
    assert metadata.partition_id == sealed_partition.id
    assert metadata.token_prefix == token[:8]
    assert metadata.rotation_plan == "rotate-quarterly"
    assert metadata.freshness_window_days == 30
    assert metadata.contamination_audit["source"] == "github-issues-2026-q2"
    assert "content_locator" not in metadata.model_dump()
    # The plaintext token is never persisted: only its digest is stored.
    assert token not in metadata.model_dump_json()


def test_issued_handle_stores_only_a_token_digest(
    session_factory: sessionmaker[Session], issued_handle: IssuedHoldoutHandle
) -> None:
    """A stolen database backup yields digests, not usable capabilities."""
    token = parse_handle_uri(issued_handle.handle_uri)
    with session_factory() as session:
        row = session.scalars(
            select(HoldoutHandle).where(HoldoutHandle.id == issued_handle.metadata.handle_id)
        ).one()
        assert row.token_digest == digest_token(token)
        assert token not in row.token_digest


def test_handles_are_only_issued_for_sealed_partitions(
    dataset_service: DatasetService, holdout_service: HoldoutService, evaluator: Principal
) -> None:
    """A dev partition needs no capability; offering one would imply false protection."""
    dev = dataset_service.create_partition(
        evaluator,
        dataset_id="ds_h",
        name="dev-part",
        kind=PartitionKind.DEV,
        owner="eng",
        content_locator="object://runtime-plane/dev/h",
        content_digest="sha256:" + "f" * 64,
    )
    with pytest.raises(PartitionStorageIdentityError):
        holdout_service.issue_handle(
            evaluator,
            partition_id=dev.id,
            owner="eng",
            alpha_budget_total=Decimal("0.05"),
            alpha_per_query=Decimal("0.01"),
            freshness_window_days=30,
            rotation_plan="none",
        )


def test_resolution_returns_content_and_spends_alpha(
    holdout_service: HoldoutService,
    evaluator: Principal,
    issued_handle: IssuedHoldoutHandle,
    sealed_partition: PartitionSummary,
) -> None:
    """The one sanctioned path to holdout content, priced in alpha."""
    content = holdout_service.resolve(
        evaluator, issued_handle.handle_uri, purpose="baseline-2026-08 final scoring"
    )
    assert content.partition_id == sealed_partition.id
    assert content.content_locator == "object://evaluation-plane/holdout/repo-repair-v1"
    assert content.item_count == 40
    assert content.alpha_budget.spent == Decimal("0.01")
    assert content.alpha_budget.remaining == Decimal("0.03")
    assert content.alpha_budget.queries_remaining == 3


def test_every_resolution_appends_exactly_one_ledger_row(
    holdout_service: HoldoutService, evaluator: Principal, issued_handle: IssuedHoldoutHandle
) -> None:
    """Ledger rows and reads are one-to-one, with the caller and purpose recorded."""
    for index in range(3):
        holdout_service.resolve(evaluator, issued_handle.handle_uri, purpose=f"scoring-{index}")

    entries = holdout_service.read_ledger(evaluator, issued_handle.handle_uri)
    assert len(entries) == 3
    assert [entry.purpose for entry in entries] == ["scoring-0", "scoring-1", "scoring-2"]
    assert all(entry.outcome is LedgerOutcome.GRANTED for entry in entries)
    assert all(entry.caller_identity == evaluator.identity_id for entry in entries)
    assert all(entry.caller_role is evaluator.role for entry in entries)
    assert [entry.alpha_remaining for entry in entries] == [
        Decimal("0.03"),
        Decimal("0.02"),
        Decimal("0.01"),
    ]


def test_budget_report_tracks_remaining_alpha(
    holdout_service: HoldoutService, evaluator: Principal, issued_handle: IssuedHoldoutHandle
) -> None:
    """The ledger's budget view is what a campaign checks before spending a read."""
    before = holdout_service.budget_report(evaluator, issued_handle.handle_uri)
    assert (before.total, before.spent, before.remaining) == (
        Decimal("0.04"),
        Decimal("0"),
        Decimal("0.04"),
    )
    assert before.queries_remaining == 4

    holdout_service.resolve(evaluator, issued_handle.handle_uri, purpose="scoring")
    after = holdout_service.budget_report(evaluator, issued_handle.handle_uri)
    assert after.remaining == Decimal("0.03")
    assert after.queries_remaining == 3


def test_exhausted_budget_denies_further_reads(
    holdout_service: HoldoutService, evaluator: Principal, issued_handle: IssuedHoldoutHandle
) -> None:
    """Four queries of budget means four reads — the fifth is refused and recorded."""
    for index in range(4):
        holdout_service.resolve(evaluator, issued_handle.handle_uri, purpose=f"scoring-{index}")

    with pytest.raises(HoldoutAccessDeniedError) as denied:
        holdout_service.resolve(evaluator, issued_handle.handle_uri, purpose="one-too-many")
    assert denied.value.reason is DenialReason.ALPHA_BUDGET_EXHAUSTED

    entries = holdout_service.read_ledger(evaluator, issued_handle.handle_uri)
    assert len(entries) == 5
    assert entries[-1].outcome is LedgerOutcome.DENIED
    assert entries[-1].denial_reason is DenialReason.ALPHA_BUDGET_EXHAUSTED
    assert entries[-1].alpha_spent == Decimal("0")


def test_expired_handle_is_denied_but_still_rotatable(
    session_factory: sessionmaker[Session],
    holdout_service: HoldoutService,
    evaluator: Principal,
    issued_handle: IssuedHoldoutHandle,
) -> None:
    """Freshness windows bound exposure; rotation is how an operator recovers."""
    _expire(session_factory, issued_handle.handle_uri)

    with pytest.raises(HoldoutAccessDeniedError) as denied:
        holdout_service.resolve(evaluator, issued_handle.handle_uri, purpose="stale-read")
    assert denied.value.reason is DenialReason.HANDLE_EXPIRED

    rotated = holdout_service.rotate_handle(evaluator, issued_handle.handle_uri)
    revived = holdout_service.resolve(evaluator, rotated.handle_uri, purpose="post-rotation")
    assert revived.item_count == 40


def test_revoked_handle_is_denied(
    holdout_service: HoldoutService, evaluator: Principal, issued_handle: IssuedHoldoutHandle
) -> None:
    """Revocation is immediate and the attempt is ledgered."""
    metadata = holdout_service.revoke_handle(evaluator, issued_handle.handle_uri)
    assert metadata.revoked_at is not None

    with pytest.raises(HoldoutAccessDeniedError) as denied:
        holdout_service.resolve(evaluator, issued_handle.handle_uri, purpose="after-revoke")
    assert denied.value.reason is DenialReason.HANDLE_REVOKED


def test_rotation_changes_the_token_without_moving_content(
    holdout_service: HoldoutService,
    evaluator: Principal,
    issued_handle: IssuedHoldoutHandle,
    sealed_partition: PartitionSummary,
) -> None:
    """The D5 rotation criterion: new capability, same bytes, same audit history."""
    before = holdout_service.resolve(evaluator, issued_handle.handle_uri, purpose="pre-rotation")

    rotated = holdout_service.rotate_handle(evaluator, issued_handle.handle_uri)
    assert rotated.handle_uri != issued_handle.handle_uri
    assert rotated.metadata.handle_id == issued_handle.metadata.handle_id
    assert rotated.metadata.rotation_count == 1
    assert rotated.metadata.rotated_at is not None
    # Alpha is a fact about how often the data was read, not a property of
    # the credential: rotation must not launder a spent budget.
    assert rotated.metadata.alpha_budget.spent == Decimal("0.01")

    after = holdout_service.resolve(evaluator, rotated.handle_uri, purpose="post-rotation")
    assert after.partition_id == sealed_partition.id
    assert after.content_locator == before.content_locator
    assert after.content_digest == before.content_digest

    # The retired token is dead on arrival.
    with pytest.raises(HandleNotFoundError):
        holdout_service.resolve(evaluator, issued_handle.handle_uri, purpose="old-token")


def test_ledger_survives_rotation(
    holdout_service: HoldoutService, evaluator: Principal, issued_handle: IssuedHoldoutHandle
) -> None:
    """Rotation must not orphan audit history — the handle id is the anchor."""
    holdout_service.resolve(evaluator, issued_handle.handle_uri, purpose="pre-rotation")
    rotated = holdout_service.rotate_handle(evaluator, issued_handle.handle_uri)
    holdout_service.resolve(evaluator, rotated.handle_uri, purpose="post-rotation")

    entries = holdout_service.read_ledger(evaluator, rotated.handle_uri)
    assert [entry.purpose for entry in entries] == ["pre-rotation", "post-rotation"]


def test_unknown_and_malformed_handles_are_indistinguishable(
    holdout_service: HoldoutService, evaluator: Principal
) -> None:
    """Probing the namespace teaches a caller nothing."""
    for candidate_uri in ("holdout://does-not-exist", "not-a-handle", "holdout://"):
        with pytest.raises(HandleNotFoundError):
            holdout_service.resolve(evaluator, candidate_uri, purpose="probe")

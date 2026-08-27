"""The D5 IAM-denial fixture: holdout content is unreachable outside the evaluator role.

This file is the acceptance evidence for the spec's boundary invariant, so
it probes every route a determined caller could take rather than the one
the happy path uses: the service API, the HTTP API, a stolen-token replay,
a cross-tenant evaluator, and the ledger's own tamper resistance.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from decimal import Decimal

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, text, update
from sqlalchemy.exc import DatabaseError
from sqlalchemy.orm import Session, sessionmaker

from evoruntime.core.principal import Principal
from evoruntime.datasets.errors import (
    DenialReason,
    HandleNotFoundError,
    HoldoutAccessDeniedError,
)
from evoruntime.datasets.models import HoldoutQueryLedgerEntry, LedgerOutcome
from evoruntime.datasets.partitions import PartitionKind
from evoruntime.datasets.schemas import IssuedHoldoutHandle, PartitionSummary
from evoruntime.datasets.service import DatasetService, HoldoutService

AuthHeaders = Callable[[Principal], dict[str, str]]
"""Signature of the `auth_headers` fixture (declared locally: `tests` is not a package)."""


def test_candidate_runner_cannot_resolve_a_holdout_handle(
    holdout_service: HoldoutService,
    candidate_runner: Principal,
    issued_handle: IssuedHoldoutHandle,
) -> None:
    """The core denial: right token, wrong plane, no content."""
    with pytest.raises(HoldoutAccessDeniedError) as denied:
        holdout_service.resolve(
            candidate_runner, issued_handle.handle_uri, purpose="candidate wants to self-evaluate"
        )
    assert denied.value.reason is DenialReason.ROLE_NOT_EVALUATOR
    # The exception carries no content, not even indirectly.
    assert "object://" not in str(denied.value)


def test_denied_resolution_is_recorded_in_the_ledger(
    holdout_service: HoldoutService,
    evaluator: Principal,
    candidate_runner: Principal,
    issued_handle: IssuedHoldoutHandle,
) -> None:
    """A denial that leaves no evidence is a security event that never happened.

    Regression guard for the transaction ordering in `HoldoutService.resolve`:
    the ledger row must commit even though the call ends in an exception.
    """
    with pytest.raises(HoldoutAccessDeniedError):
        holdout_service.resolve(candidate_runner, issued_handle.handle_uri, purpose="probe")

    entries = holdout_service.read_ledger(evaluator, issued_handle.handle_uri)
    assert len(entries) == 1
    entry = entries[0]
    assert entry.outcome is LedgerOutcome.DENIED
    assert entry.denial_reason is DenialReason.ROLE_NOT_EVALUATOR
    assert entry.caller_identity == candidate_runner.identity_id
    assert entry.caller_role is candidate_runner.role
    assert entry.purpose == "probe"
    assert entry.alpha_spent == Decimal("0")


def test_denial_does_not_spend_alpha(
    holdout_service: HoldoutService,
    evaluator: Principal,
    candidate_runner: Principal,
    issued_handle: IssuedHoldoutHandle,
) -> None:
    """An attacker must not be able to burn a holdout's statistical budget."""
    for _ in range(3):
        with pytest.raises(HoldoutAccessDeniedError):
            holdout_service.resolve(candidate_runner, issued_handle.handle_uri, purpose="probe")

    budget = holdout_service.budget_report(evaluator, issued_handle.handle_uri)
    assert budget.spent == Decimal("0")
    assert budget.queries_remaining == 4


def test_denial_is_logged_for_alerting(
    holdout_service: HoldoutService,
    candidate_runner: Principal,
    issued_handle: IssuedHoldoutHandle,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The ledger is the durable record; the log line is what a SIEM alerts on."""
    with (
        caplog.at_level(logging.WARNING, logger="evoruntime.audit"),
        pytest.raises(HoldoutAccessDeniedError),
    ):
        holdout_service.resolve(candidate_runner, issued_handle.handle_uri, purpose="probe")

    records = [
        record for record in caplog.records if record.getMessage() == "holdout.access.denied"
    ]
    assert len(records) == 1
    assert records[0].caller_identity == candidate_runner.identity_id  # type: ignore[attr-defined]
    assert records[0].denial_reason == DenialReason.ROLE_NOT_EVALUATOR.value  # type: ignore[attr-defined]


def test_candidate_runner_cannot_issue_rotate_or_revoke(
    holdout_service: HoldoutService,
    candidate_runner: Principal,
    sealed_partition: PartitionSummary,
    issued_handle: IssuedHoldoutHandle,
) -> None:
    """Denial covers the whole handle lifecycle, not just reads.

    Rotation and revocation are denied for the same reason reads are: a
    candidate that can rotate a handle can lock the evaluator out of its
    own holdout, and a candidate that can revoke one can stall a campaign.
    """
    with pytest.raises(HoldoutAccessDeniedError):
        holdout_service.issue_handle(
            candidate_runner,
            partition_id=sealed_partition.id,
            owner="attacker",
            alpha_budget_total=Decimal("1.0"),
            alpha_per_query=Decimal("0.01"),
            freshness_window_days=365,
            rotation_plan="never",
        )
    with pytest.raises(HoldoutAccessDeniedError):
        holdout_service.rotate_handle(candidate_runner, issued_handle.handle_uri)
    with pytest.raises(HoldoutAccessDeniedError):
        holdout_service.revoke_handle(candidate_runner, issued_handle.handle_uri)


def test_cross_tenant_evaluator_is_denied_without_confirming_existence(
    holdout_service: HoldoutService,
    evaluator: Principal,
    foreign_evaluator: Principal,
    issued_handle: IssuedHoldoutHandle,
) -> None:
    """Right role, wrong tenant: denied as 'not found', but ledgered as a mismatch."""
    with pytest.raises(HandleNotFoundError):
        holdout_service.resolve(
            foreign_evaluator, issued_handle.handle_uri, purpose="cross-tenant read"
        )

    entries = holdout_service.read_ledger(evaluator, issued_handle.handle_uri)
    assert [entry.denial_reason for entry in entries] == [DenialReason.TENANT_MISMATCH]
    assert entries[0].caller_identity == foreign_evaluator.identity_id


def test_ledger_rows_cannot_be_updated_or_deleted(
    session_factory: sessionmaker[Session],
    holdout_service: HoldoutService,
    evaluator: Principal,
    issued_handle: IssuedHoldoutHandle,
) -> None:
    """Append-only is enforced by the database, not by convention.

    Without this, anyone with write access to the service's own credentials
    could erase the record of a contaminating read — which is precisely the
    event the ledger exists to make undeniable.
    """
    holdout_service.resolve(evaluator, issued_handle.handle_uri, purpose="scoring")
    handle_id = issued_handle.metadata.handle_id

    with session_factory() as session:
        with pytest.raises(DatabaseError):
            session.execute(
                update(HoldoutQueryLedgerEntry)
                .where(HoldoutQueryLedgerEntry.handle_id == handle_id)
                .values(purpose="rewritten")
            )
        session.rollback()

        with pytest.raises(DatabaseError):
            session.execute(
                delete(HoldoutQueryLedgerEntry).where(
                    HoldoutQueryLedgerEntry.handle_id == handle_id
                )
            )
        session.rollback()

        with pytest.raises(DatabaseError):
            session.execute(text("TRUNCATE TABLE holdout_query_ledger"))
        session.rollback()

    # The row is still there, unchanged.
    entries = holdout_service.read_ledger(evaluator, issued_handle.handle_uri)
    assert [entry.purpose for entry in entries] == ["scoring"]


def test_api_denies_candidate_runner_and_returns_no_content(
    client: TestClient,
    candidate_runner: Principal,
    issued_handle: IssuedHoldoutHandle,
    auth_headers: AuthHeaders,
) -> None:
    """Same denial through the HTTP surface, with a machine-readable reason."""
    response = client.post(
        "/datasets/holdout/resolve",
        json={"handle_uri": issued_handle.handle_uri, "purpose": "candidate probe"},
        headers=auth_headers(candidate_runner),
    )
    assert response.status_code == 403
    body = response.json()
    assert body["reason"] == DenialReason.ROLE_NOT_EVALUATOR.value
    assert "object://" not in response.text


def test_api_grants_the_evaluator_and_hides_sealed_locators_elsewhere(
    client: TestClient,
    evaluator: Principal,
    sealed_partition: PartitionSummary,
    issued_handle: IssuedHoldoutHandle,
    auth_headers: AuthHeaders,
) -> None:
    """The evaluator's read works; no other endpoint leaks the same locator."""
    headers = auth_headers(evaluator)

    resolved = client.post(
        "/datasets/holdout/resolve",
        json={"handle_uri": issued_handle.handle_uri, "purpose": "final scoring"},
        headers=headers,
    )
    assert resolved.status_code == 200
    locator = resolved.json()["content_locator"]
    assert locator == "object://evaluation-plane/holdout/repo-repair-v1"

    listed = client.get("/datasets/partitions", headers=headers)
    assert listed.status_code == 200
    assert locator not in listed.text

    fetched = client.get(f"/datasets/partitions/{sealed_partition.id}", headers=headers)
    assert fetched.status_code == 200
    assert fetched.json()["content_locator"] is None

    described = client.post(
        "/datasets/holdout/metadata",
        json={"handle_uri": issued_handle.handle_uri},
        headers=headers,
    )
    assert described.status_code == 200
    assert locator not in described.text


def test_api_rejects_requests_without_workload_identity(
    client: TestClient, issued_handle: IssuedHoldoutHandle
) -> None:
    """No identity, no decision: unauthenticated callers never reach the service."""
    response = client.post(
        "/datasets/holdout/resolve",
        json={"handle_uri": issued_handle.handle_uri, "purpose": "anonymous"},
    )
    assert response.status_code == 401

    unknown_role = client.post(
        "/datasets/holdout/resolve",
        json={"handle_uri": issued_handle.handle_uri, "purpose": "made-up role"},
        headers={
            "x-evoruntime-identity": "svc_x",
            "x-evoruntime-role": "superuser",
            "x-evoruntime-tenant": "tnt_x",
        },
    )
    assert unknown_role.status_code == 401


def test_candidate_runner_cannot_reach_holdout_content_through_partition_endpoints(
    client: TestClient,
    dataset_service: DatasetService,
    evaluator: Principal,
    candidate_runner: Principal,
    sealed_partition: PartitionSummary,
    auth_headers: AuthHeaders,
) -> None:
    """The listing endpoints are not a side door for the execution plane."""
    dataset_service.create_partition(
        evaluator,
        dataset_id="ds_repo_repair_v1",
        name="repo-repair-dev",
        kind=PartitionKind.DEV,
        owner="eng",
        content_locator="object://runtime-plane/dev/repo-repair-v1",
        content_digest="sha256:" + "1" * 64,
    )
    headers = auth_headers(candidate_runner)

    listed = client.get("/datasets/partitions", headers=headers)
    assert listed.status_code == 200
    payload = {item["name"]: item for item in listed.json()}
    # The candidate-runner shares the tenant here, so it legitimately sees
    # the dev partition's locator — and still cannot see the holdout's.
    assert payload["repo-repair-dev"]["content_locator"] is not None
    assert payload["repo-repair-holdout"]["content_locator"] is None
    assert "object://evaluation-plane" not in listed.text

    fetched = client.get(f"/datasets/partitions/{sealed_partition.id}", headers=headers)
    assert fetched.status_code == 200
    assert fetched.json()["content_locator"] is None

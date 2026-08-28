"""Tests for workload identity construction from environment configuration."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from evoruntime.security.identities import (
    WorkloadIdentity,
    WorkloadRole,
    identity_from_env,
)


def test_identity_from_env_reads_role_and_subject(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EVORUNTIME_WORKLOAD_ROLE", "evaluator")
    monkeypatch.setenv("EVORUNTIME_WORKLOAD_SUBJECT", "eval-svc-1")

    identity = identity_from_env()

    assert identity == WorkloadIdentity(role=WorkloadRole.EVALUATOR, subject="eval-svc-1")


def test_identity_from_env_defaults_to_least_privileged_role(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("EVORUNTIME_WORKLOAD_ROLE", raising=False)

    identity = identity_from_env()

    assert identity.role is WorkloadRole.CANDIDATE_RUNNER


def test_identity_from_env_rejects_unknown_role(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EVORUNTIME_WORKLOAD_ROLE", "super-admin")

    with pytest.raises(ValueError, match="not a recognized workload role"):
        identity_from_env()


def test_workload_identity_is_frozen() -> None:
    identity = WorkloadIdentity(role=WorkloadRole.EVALUATOR, subject="eval-svc-1")

    with pytest.raises(ValidationError):
        identity.subject = "tampered"  # type: ignore[misc]

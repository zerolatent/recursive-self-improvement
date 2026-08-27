"""Policy tests: the candidate-runner identity must never clear a check
that the evaluator identity clears.

This is the D7 acceptance test: "candidate-runner identity cannot resolve
holdout handles or read evaluator keys."
"""

from __future__ import annotations

import pytest

from evoruntime.security.identities import WorkloadIdentity, WorkloadRole
from evoruntime.security.policy import (
    PermissionDeniedError,
    require_evaluator_key_access,
    require_holdout_access,
)

EVALUATOR = WorkloadIdentity(role=WorkloadRole.EVALUATOR, subject="eval-svc-1")
CANDIDATE_RUNNER = WorkloadIdentity(
    role=WorkloadRole.CANDIDATE_RUNNER, subject="candidate-sandbox-7"
)


def test_evaluator_may_resolve_holdout_handles() -> None:
    require_holdout_access(EVALUATOR)  # does not raise


def test_candidate_runner_cannot_resolve_holdout_handles() -> None:
    with pytest.raises(PermissionDeniedError, match="resolve holdout handles"):
        require_holdout_access(CANDIDATE_RUNNER)


def test_evaluator_may_read_evaluator_keys() -> None:
    require_evaluator_key_access(EVALUATOR)  # does not raise


def test_candidate_runner_cannot_read_evaluator_keys() -> None:
    with pytest.raises(PermissionDeniedError, match="read evaluator signing keys"):
        require_evaluator_key_access(CANDIDATE_RUNNER)


def test_permission_denied_error_names_identity_and_action() -> None:
    with pytest.raises(PermissionDeniedError) as exc_info:
        require_holdout_access(CANDIDATE_RUNNER)

    error = exc_info.value
    assert error.identity == CANDIDATE_RUNNER
    assert error.action == "resolve holdout handles"

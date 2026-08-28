"""Typed dataset errors.

Denials carry a machine-readable `DenialReason` rather than a message
string: the reason lands in the append-only ledger and in the audit log,
where it must stay greppable and stable across releases.
"""

from __future__ import annotations

from enum import StrEnum


class DenialReason(StrEnum):
    """Why a holdout resolution was refused."""

    ROLE_NOT_EVALUATOR = "role_not_evaluator"
    """Caller sits outside the evaluation-plane trust boundary."""

    TENANT_MISMATCH = "tenant_mismatch"
    """Caller is an evaluator, but for a different tenant."""

    HANDLE_REVOKED = "handle_revoked"
    """The handle was revoked (typically superseded by rotation)."""

    HANDLE_EXPIRED = "handle_expired"
    """The handle is past its freshness window and must be rotated."""

    ALPHA_BUDGET_EXHAUSTED = "alpha_budget_exhausted"
    """No statistical budget remains; further reads would invalidate the holdout."""


class DatasetError(Exception):
    """Base class for dataset/partition failures."""


class PartitionNotFoundError(DatasetError):
    """No partition matches the requested identifier for this tenant."""


class HandleNotFoundError(DatasetError):
    """No holdout handle matches the presented token.

    Raised for both "never existed" and "belongs to another tenant" so an
    unauthorized caller cannot probe for the existence of a handle.
    """


class PartitionStorageIdentityError(DatasetError):
    """A partition was declared with a storage identity its kind forbids."""


class HoldoutAccessDeniedError(DatasetError):
    """A caller was refused holdout access. Always accompanied by a ledger row."""

    def __init__(self, reason: DenialReason, identity_id: str) -> None:
        super().__init__(f"holdout access denied for {identity_id}: {reason}")
        self.reason = reason
        self.identity_id = identity_id

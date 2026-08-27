"""Partition and sealed-holdout services — where the trust boundary is enforced.

Every path that could disclose holdout content funnels through
`HoldoutService._denial_reason`. There is no second route to content:
`HoldoutContentRef` is constructed in exactly one place in this module,
immediately after a ledger row has been written for the resolution.

Authorization order is deliberate — role first, tenant second, handle
state third, budget last — so the most security-critical check runs
before anything else, and a caller outside the boundary never influences
budget state.

Denials are committed before they are raised. A denial recorded inside
the transaction that then raises would be rolled back with it, which
would quietly turn the audit trail into a record of successes only — so
every method here commits its session first and raises afterwards.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any, NoReturn

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from evoruntime.core.identity import Principal
from evoruntime.core.ids import new_id
from evoruntime.datasets.errors import (
    DatasetError,
    DenialReason,
    HandleNotFoundError,
    HoldoutAccessDeniedError,
    PartitionNotFoundError,
    PartitionStorageIdentityError,
)
from evoruntime.datasets.models import (
    DatasetPartition,
    HoldoutHandle,
    HoldoutQueryLedgerEntry,
    LedgerOutcome,
)
from evoruntime.datasets.partitions import (
    HOLDOUT_HANDLE_SCHEME,
    PartitionKind,
    is_sealed,
    required_storage_identity,
)
from evoruntime.datasets.schemas import (
    AlphaBudgetReport,
    HoldoutContentRef,
    HoldoutHandleMetadata,
    IssuedHoldoutHandle,
    LedgerEntryRecord,
    PartitionSummary,
)
from evoruntime.db.base import session_scope

audit_log = logging.getLogger("evoruntime.audit")

TOKEN_BYTES = 32
"""256 bits of entropy — handles must be unguessable, not merely unique."""

_HANDLE_PREFIX = f"{HOLDOUT_HANDLE_SCHEME}://"


def mint_token() -> str:
    """Return a fresh, unguessable holdout token (URL-safe, no padding)."""
    return secrets.token_urlsafe(TOKEN_BYTES)


def digest_token(token: str) -> str:
    """Return the SHA-256 hex digest under which a token is stored."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def build_handle_uri(token: str) -> str:
    """Wrap a raw token in the opaque `holdout://` capability form."""
    return f"{_HANDLE_PREFIX}{token}"


def parse_handle_uri(handle_uri: str) -> str:
    """Extract the raw token from a `holdout://` URI.

    A malformed URI raises `HandleNotFoundError` rather than a distinct
    error: a caller probing the namespace learns nothing from the
    difference between "wrong shape" and "no such handle".
    """
    if not handle_uri.startswith(_HANDLE_PREFIX):
        raise HandleNotFoundError("not a holdout handle URI")
    token = handle_uri.removeprefix(_HANDLE_PREFIX)
    if not token:
        raise HandleNotFoundError("empty holdout handle token")
    return token


def build_budget_report(handle: HoldoutHandle) -> AlphaBudgetReport:
    """Summarize a handle's remaining statistical budget."""
    remaining = handle.alpha_remaining
    queries_remaining = int(remaining // handle.alpha_per_query) if remaining > 0 else 0
    return AlphaBudgetReport(
        total=handle.alpha_budget_total,
        spent=handle.alpha_spent,
        remaining=remaining,
        per_query=handle.alpha_per_query,
        queries_remaining=queries_remaining,
    )


def build_handle_metadata(handle: HoldoutHandle) -> HoldoutHandleMetadata:
    """Project a handle row into its content-free metadata view."""
    return HoldoutHandleMetadata(
        handle_id=handle.id,
        partition_id=handle.partition_id,
        tenant_id=handle.tenant_id,
        token_prefix=handle.token_prefix,
        owner=handle.owner,
        created_at=handle.created_at,
        created_by=handle.created_by,
        expires_at=handle.expires_at,
        freshness_window_days=handle.freshness_window_days,
        rotation_plan=handle.rotation_plan,
        rotation_count=handle.rotation_count,
        rotated_at=handle.rotated_at,
        revoked_at=handle.revoked_at,
        contamination_audit=dict(handle.contamination_audit),
        alpha_budget=build_budget_report(handle),
    )


def build_partition_summary(
    partition: DatasetPartition, *, disclose_locator: bool
) -> PartitionSummary:
    """Project a partition row, withholding the locator for sealed partitions.

    `disclose_locator` is never derived from the caller's request — the
    service passes the result of an authorization decision.
    """
    return PartitionSummary(
        id=partition.id,
        tenant_id=partition.tenant_id,
        dataset_id=partition.dataset_id,
        name=partition.name,
        kind=partition.kind,
        storage_identity=partition.storage_identity,
        owner=partition.owner,
        item_count=partition.item_count,
        content_digest=partition.content_digest,
        created_at=partition.created_at,
        sealed=is_sealed(partition.kind),
        content_locator=partition.content_locator if disclose_locator else None,
    )


def build_ledger_record(entry: HoldoutQueryLedgerEntry) -> LedgerEntryRecord:
    """Project a ledger row into its API record."""
    return LedgerEntryRecord(
        id=entry.id,
        handle_id=entry.handle_id,
        partition_id=entry.partition_id,
        tenant_id=entry.tenant_id,
        caller_identity=entry.caller_identity,
        caller_role=entry.caller_role,
        purpose=entry.purpose,
        outcome=entry.outcome,
        denial_reason=entry.denial_reason,
        alpha_spent=entry.alpha_spent,
        alpha_remaining=entry.alpha_remaining,
        occurred_at=entry.occurred_at,
    )


class DatasetService:
    """Creates and lists dataset partitions."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def create_partition(
        self,
        principal: Principal,
        *,
        dataset_id: str,
        name: str,
        kind: PartitionKind,
        owner: str,
        content_locator: str,
        content_digest: str,
        item_count: int = 0,
    ) -> PartitionSummary:
        """Register a partition, pinning its storage identity to its kind.

        The storage identity is derived, never accepted from the caller: a
        holdout partition that could be declared under the runtime identity
        would defeat the boundary before any request is served.
        """
        storage_identity = required_storage_identity(kind)
        if is_sealed(kind) and not principal.is_evaluation_plane:
            raise HoldoutAccessDeniedError(DenialReason.ROLE_NOT_EVALUATOR, principal.identity_id)

        with session_scope(self._session_factory) as session:
            partition = DatasetPartition(
                id=new_id("dsp"),
                tenant_id=principal.tenant_id,
                dataset_id=dataset_id,
                name=name,
                kind=kind,
                storage_identity=storage_identity,
                owner=owner,
                content_locator=content_locator,
                content_digest=content_digest,
                item_count=item_count,
                created_at=datetime.now(UTC),
            )
            session.add(partition)
            session.flush()
            return build_partition_summary(
                partition, disclose_locator=not is_sealed(kind) or principal.is_evaluation_plane
            )

    def list_partitions(
        self, principal: Principal, *, dataset_id: str | None = None
    ) -> list[PartitionSummary]:
        """List the caller's tenant's partitions, sealed ones without locators.

        Sealed locators are withheld from *every* role here, including
        evaluators: the only sanctioned route to holdout content is a
        ledgered handle resolution, so listing never becomes a side door.
        """
        with session_scope(self._session_factory) as session:
            query = select(DatasetPartition).where(
                DatasetPartition.tenant_id == principal.tenant_id
            )
            if dataset_id is not None:
                query = query.where(DatasetPartition.dataset_id == dataset_id)
            partitions = session.scalars(query.order_by(DatasetPartition.created_at)).all()
            return [
                build_partition_summary(partition, disclose_locator=not is_sealed(partition.kind))
                for partition in partitions
            ]

    def get_partition(self, principal: Principal, partition_id: str) -> PartitionSummary:
        """Fetch one partition's governance record (never a sealed locator)."""
        with session_scope(self._session_factory) as session:
            partition = self._load_partition(session, principal, partition_id)
            return build_partition_summary(
                partition, disclose_locator=not is_sealed(partition.kind)
            )

    @staticmethod
    def _load_partition(
        session: Session, principal: Principal, partition_id: str
    ) -> DatasetPartition:
        partition = session.get(DatasetPartition, partition_id)
        if partition is None or partition.tenant_id != principal.tenant_id:
            raise PartitionNotFoundError(partition_id)
        return partition


class HoldoutService:
    """Issues, describes, rotates, and resolves sealed holdout handles.

    Resolution is the security-critical path: it is the only method that
    can return a content locator, and it cannot return one without having
    written a ledger row in the same transaction.
    """

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def issue_handle(
        self,
        principal: Principal,
        *,
        partition_id: str,
        owner: str,
        alpha_budget_total: Decimal,
        alpha_per_query: Decimal,
        freshness_window_days: int,
        rotation_plan: str,
        contamination_audit: dict[str, Any] | None = None,
    ) -> IssuedHoldoutHandle:
        """Mint a handle for a sealed partition. Evaluation plane only."""
        if not principal.is_evaluation_plane:
            self._log_denial(principal, DenialReason.ROLE_NOT_EVALUATOR, handle_id=None)
            raise HoldoutAccessDeniedError(DenialReason.ROLE_NOT_EVALUATOR, principal.identity_id)

        with session_scope(self._session_factory) as session:
            partition = session.get(DatasetPartition, partition_id)
            if partition is None or partition.tenant_id != principal.tenant_id:
                raise PartitionNotFoundError(partition_id)
            if not is_sealed(partition.kind):
                raise PartitionStorageIdentityError(
                    f"partition {partition_id} is {partition.kind}, not a sealed partition"
                )

            token = mint_token()
            now = datetime.now(UTC)
            handle = HoldoutHandle(
                id=new_id("hho"),
                tenant_id=partition.tenant_id,
                partition_id=partition.id,
                token_digest=digest_token(token),
                token_prefix=token[:8],
                owner=owner,
                created_at=now,
                created_by=principal.identity_id,
                expires_at=now + timedelta(days=freshness_window_days),
                freshness_window_days=freshness_window_days,
                rotation_plan=rotation_plan,
                rotation_count=0,
                contamination_audit=contamination_audit or {},
                alpha_budget_total=alpha_budget_total,
                alpha_spent=Decimal("0"),
                alpha_per_query=alpha_per_query,
            )
            session.add(handle)
            session.flush()
            return IssuedHoldoutHandle(
                handle_uri=build_handle_uri(token), metadata=build_handle_metadata(handle)
            )

    def describe_handle(self, principal: Principal, handle_uri: str) -> HoldoutHandleMetadata:
        """Return metadata for a handle — owner, audit, freshness, rotation, budget.

        Open to any role inside the tenant by design: the whole point of an
        opaque handle is that its *metadata* is shareable (the evolution
        plane needs to know a holdout exists and how fresh it is) while its
        content is not.
        """
        with session_scope(self._session_factory) as session:
            handle = self._load_handle(session, principal, handle_uri)
            return build_handle_metadata(handle)

    def budget_report(self, principal: Principal, handle_uri: str) -> AlphaBudgetReport:
        """Report the remaining alpha budget for a handle."""
        with session_scope(self._session_factory) as session:
            return build_budget_report(self._load_handle(session, principal, handle_uri))

    def read_ledger(
        self, principal: Principal, handle_uri: str, *, limit: int = 100
    ) -> list[LedgerEntryRecord]:
        """Return the handle's ledger rows, oldest first."""
        with session_scope(self._session_factory) as session:
            handle = self._load_handle(session, principal, handle_uri)
            entries = session.scalars(
                select(HoldoutQueryLedgerEntry)
                .where(HoldoutQueryLedgerEntry.handle_id == handle.id)
                .order_by(HoldoutQueryLedgerEntry.occurred_at, HoldoutQueryLedgerEntry.id)
                .limit(limit)
            ).all()
            return [build_ledger_record(entry) for entry in entries]

    def resolve(self, principal: Principal, handle_uri: str, *, purpose: str) -> HoldoutContentRef:
        """Resolve a handle to evaluation-plane content, spending alpha.

        Grant and denial both append a ledger row in the same transaction
        as the budget update, so the ledger can never disagree with the
        budget it reports. The transaction commits before any denial is
        raised — an unwound denial would leave no evidence of the attempt.
        """
        token_digest = digest_token(parse_handle_uri(handle_uri))
        denial: DenialReason | None = None
        content: HoldoutContentRef | None = None
        handle_id = ""

        with session_scope(self._session_factory) as session:
            handle = self._lock_handle(session, token_digest)
            handle_id = handle.id
            denial = self._denial_reason(principal, handle)

            if denial is None:
                handle.alpha_spent = handle.alpha_spent + handle.alpha_per_query

            entry = self._append_ledger_row(
                session,
                handle=handle,
                principal=principal,
                purpose=purpose,
                outcome=LedgerOutcome.DENIED if denial else LedgerOutcome.GRANTED,
                denial_reason=denial,
                alpha_spent=Decimal("0") if denial else handle.alpha_per_query,
            )

            if denial is None:
                partition = session.get(DatasetPartition, handle.partition_id)
                if partition is None:
                    raise PartitionNotFoundError(handle.partition_id)
                content = HoldoutContentRef(
                    partition_id=partition.id,
                    content_locator=partition.content_locator,
                    content_digest=partition.content_digest,
                    item_count=partition.item_count,
                    resolved_at=entry.occurred_at,
                    ledger_entry_id=entry.id,
                    alpha_budget=build_budget_report(handle),
                )

        if denial is not None:
            self._log_denial(principal, denial, handle_id=handle_id)
            self._raise_denial(principal, denial)

        if content is None:  # pragma: no cover - unreachable; keeps the type honest
            raise DatasetError("resolution produced neither content nor a denial")

        audit_log.info(
            "holdout.resolve.granted",
            extra={
                "caller_identity": principal.identity_id,
                "caller_role": principal.role.value,
                "handle_id": handle_id,
                "purpose": purpose,
            },
        )
        return content

    def rotate_handle(self, principal: Principal, handle_uri: str) -> IssuedHoldoutHandle:
        """Swap a handle's token without moving its content.

        Rotation touches the handle row only — never the partition's
        `content_locator` — and deliberately does not reset `alpha_spent`:
        the token is a credential, the budget is a statistical fact about
        how often the data has been read.
        """
        token_digest = digest_token(parse_handle_uri(handle_uri))
        denial: DenialReason | None = None
        issued: IssuedHoldoutHandle | None = None
        handle_id = ""

        with session_scope(self._session_factory) as session:
            handle = self._lock_handle(session, token_digest)
            handle_id = handle.id
            denial = self._mutation_denial_reason(principal, handle)

            if denial is not None:
                self._append_ledger_row(
                    session,
                    handle=handle,
                    principal=principal,
                    purpose="handle.rotate",
                    outcome=LedgerOutcome.DENIED,
                    denial_reason=denial,
                    alpha_spent=Decimal("0"),
                )
            else:
                now = datetime.now(UTC)
                new_token = mint_token()
                handle.token_digest = digest_token(new_token)
                handle.token_prefix = new_token[:8]
                handle.rotated_at = now
                handle.rotation_count = handle.rotation_count + 1
                handle.expires_at = now + timedelta(days=handle.freshness_window_days)
                handle.revoked_at = None
                session.flush()
                issued = IssuedHoldoutHandle(
                    handle_uri=build_handle_uri(new_token),
                    metadata=build_handle_metadata(handle),
                )

        if denial is not None:
            self._log_denial(principal, denial, handle_id=handle_id)
            self._raise_denial(principal, denial)

        if issued is None:  # pragma: no cover - unreachable; keeps the type honest
            raise DatasetError("rotation produced neither a handle nor a denial")
        return issued

    def revoke_handle(self, principal: Principal, handle_uri: str) -> HoldoutHandleMetadata:
        """Revoke a handle so further resolutions are denied. Evaluation plane only."""
        token_digest = digest_token(parse_handle_uri(handle_uri))
        denial: DenialReason | None = None
        metadata: HoldoutHandleMetadata | None = None
        handle_id = ""

        with session_scope(self._session_factory) as session:
            handle = self._lock_handle(session, token_digest)
            handle_id = handle.id
            denial = self._mutation_denial_reason(principal, handle)

            if denial is not None:
                self._append_ledger_row(
                    session,
                    handle=handle,
                    principal=principal,
                    purpose="handle.revoke",
                    outcome=LedgerOutcome.DENIED,
                    denial_reason=denial,
                    alpha_spent=Decimal("0"),
                )
            else:
                handle.revoked_at = datetime.now(UTC)
                session.flush()
                metadata = build_handle_metadata(handle)

        if denial is not None:
            self._log_denial(principal, denial, handle_id=handle_id)
            self._raise_denial(principal, denial)

        if metadata is None:  # pragma: no cover - unreachable; keeps the type honest
            raise DatasetError("revocation produced neither metadata nor a denial")
        return metadata

    @staticmethod
    def _lock_handle(session: Session, token_digest: str) -> HoldoutHandle:
        """Load a handle row for update, or refuse to admit it exists."""
        handle = session.scalars(
            select(HoldoutHandle)
            .where(HoldoutHandle.token_digest == token_digest)
            .with_for_update()
        ).one_or_none()
        if handle is None:
            raise HandleNotFoundError("no such holdout handle")
        return handle

    @staticmethod
    def _raise_denial(principal: Principal, denial: DenialReason) -> NoReturn:
        """Translate a recorded denial into the response the caller may see.

        A cross-tenant caller gets "not found": the denial is in the ledger
        for the audit trail, but the response must not confirm that another
        tenant's handle exists.
        """
        if denial is DenialReason.TENANT_MISMATCH:
            raise HandleNotFoundError("no such holdout handle")
        raise HoldoutAccessDeniedError(denial, principal.identity_id)

    @staticmethod
    def _mutation_denial_reason(
        principal: Principal, handle: HoldoutHandle
    ) -> DenialReason | None:
        """Authorize a handle *lifecycle* change (rotate, revoke).

        Unlike resolution, expiry and exhausted budget are not blockers:
        rotating an expired handle is exactly how an operator recovers it.
        """
        if not principal.is_evaluation_plane:
            return DenialReason.ROLE_NOT_EVALUATOR
        if handle.tenant_id != principal.tenant_id:
            return DenialReason.TENANT_MISMATCH
        return None


    @staticmethod
    def _denial_reason(principal: Principal, handle: HoldoutHandle) -> DenialReason | None:
        """Return why this principal may not resolve this handle, or None to allow."""
        if not principal.is_evaluation_plane:
            return DenialReason.ROLE_NOT_EVALUATOR
        if handle.tenant_id != principal.tenant_id:
            return DenialReason.TENANT_MISMATCH
        if handle.revoked_at is not None:
            return DenialReason.HANDLE_REVOKED
        if handle.expires_at <= datetime.now(UTC):
            return DenialReason.HANDLE_EXPIRED
        if handle.alpha_remaining < handle.alpha_per_query:
            return DenialReason.ALPHA_BUDGET_EXHAUSTED
        return None

    @staticmethod
    def _append_ledger_row(
        session: Session,
        *,
        handle: HoldoutHandle,
        principal: Principal,
        purpose: str,
        outcome: LedgerOutcome,
        denial_reason: DenialReason | None,
        alpha_spent: Decimal,
    ) -> HoldoutQueryLedgerEntry:
        entry = HoldoutQueryLedgerEntry(
            id=new_id("hql"),
            tenant_id=handle.tenant_id,
            handle_id=handle.id,
            token_digest=handle.token_digest,
            partition_id=handle.partition_id,
            caller_identity=principal.identity_id,
            caller_role=principal.role,
            purpose=purpose,
            outcome=outcome,
            denial_reason=denial_reason,
            alpha_spent=alpha_spent,
            alpha_remaining=handle.alpha_remaining,
            occurred_at=datetime.now(UTC),
        )
        session.add(entry)
        session.flush()
        return entry

    @staticmethod
    def _log_denial(principal: Principal, reason: DenialReason, *, handle_id: str | None) -> None:
        """Emit the denial to the audit log.

        Ledger rows are the durable record; this log line is what a SIEM
        alerts on when a candidate-runner identity starts probing holdouts.
        """
        audit_log.warning(
            "holdout.access.denied",
            extra={
                "caller_identity": principal.identity_id,
                "caller_role": principal.role.value,
                "denial_reason": reason.value,
                "handle_id": handle_id,
            },
        )

    @staticmethod
    def _load_handle(session: Session, principal: Principal, handle_uri: str) -> HoldoutHandle:
        """Load a handle for a read-only projection, scoped to the caller's tenant."""
        token_digest = digest_token(parse_handle_uri(handle_uri))
        query = select(HoldoutHandle).where(HoldoutHandle.token_digest == token_digest)
        handle = session.scalars(query).one_or_none()
        if handle is None or handle.tenant_id != principal.tenant_id:
            raise HandleNotFoundError("no such holdout handle")
        return handle


__all__ = [
    "DatasetService",
    "HoldoutService",
    "build_handle_uri",
    "digest_token",
    "mint_token",
    "parse_handle_uri",
]

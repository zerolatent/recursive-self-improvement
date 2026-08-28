"""Service-layer API for memory hygiene (deliverable E6, PRD §9.3 + FR-016).

`MemoryService` is the only writer of `memory_entries` rows and the only
path through which a suggestion becomes active memory. It composes three
existing subsystems rather than reimplementing them:

- **E1 registry** — every entry's canonical body is registered as a
  `memory_entry` artifact, so content addressing, per-tenant encryption,
  and the append-only status-event stream (quarantine / revoke / expire /
  supersede / nominate are already E1 kinds) come from the registry.
- **D4 deletion machinery** — revocation requests a tombstone over the
  entry's payload; the existing SLO sweeps revoke access and purge every
  derived-data record (embeddings, caches, plugin checkpoints, exports)
  registered against it. Memory adds no deletion path of its own.
- **D6 statistics** — the promotion gates run the same paired bootstrap
  the evaluation harness reports with, so a promotion decision and an
  experiment verdict cannot disagree about what "the interval" means.

Suggestion-first (FR-016): `propose_entry` never returns an ACTIVE entry,
and `promote_entry` refuses unless all gates pass. There is no other
method that writes `MemoryStatus.ACTIVE`.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from evoruntime.db.models.lineage import DerivedDataRecord, Tombstone
from evoruntime.db.models.memory import MemoryEntryRow
from evoruntime.db.models.registry import ArtifactContent
from evoruntime.lineage.deletion import DeletionService
from evoruntime.memory.canonical import (
    MEMORY_ENTRY_ARTIFACT_TYPE,
    entry_canonical_bytes,
    new_memory_id,
)
from evoruntime.memory.errors import (
    MemoryNotFoundError,
    PromotionBlockedError,
    SupersessionTargetNotFoundError,
)
from evoruntime.memory.gates import (
    DEFAULT_GATE_ALPHA,
    DEFAULT_MAX_NEGATIVE_TRANSFER,
    DEFAULT_NON_INFERIORITY_MARGIN,
    GateReport,
    hygiene_gate,
    negative_transfer_gate,
    persistence_non_inferiority_gate,
)
from evoruntime.memory.hygiene import (
    DEFAULT_TRUSTED_TRUST_DOMAINS,
    QuarantineDecision,
    intake_decision,
)
from evoruntime.memory.schemas import MemoryEntry, MemoryStatus
from evoruntime.registry.canonical import STORAGE_URI_SCHEME
from evoruntime.registry.service import RegistryService

#: Kinds of derived data the memory plane materializes against an entry's
#: payload. Registered as D4 `derived_data_records` so the 24h purge sweep
#: covers them without knowing what memory is.
DERIVED_DATA_KINDS = frozenset({"embedding", "cache", "plugin_checkpoint", "export"})

_LIVE_STATUSES = (MemoryStatus.SUGGESTION, MemoryStatus.ACTIVE)


@dataclass(frozen=True, slots=True)
class RevocationOutcome:
    """What revoking one entry did, so callers can assert propagation."""

    revoked: MemoryEntryRow
    quarantined_lessons: tuple[MemoryEntryRow, ...]
    tombstone: Tombstone


class MemoryService:
    """Proposes, quarantines, promotes, revokes, and expires memory entries."""

    def __init__(
        self,
        session: Session,
        *,
        trusted_trust_domains: frozenset[str] = DEFAULT_TRUSTED_TRUST_DOMAINS,
    ) -> None:
        self._session = session
        self._registry = RegistryService(session)
        self._deletions = DeletionService(session)
        self._trusted_domains = frozenset(trusted_trust_domains)

    # ------------------------------------------------------------------
    # Proposal (suggestion-first intake)
    # ------------------------------------------------------------------

    def propose_entry(
        self, *, tenant_id: str, entry: MemoryEntry, actor_identity: str
    ) -> MemoryEntryRow:
        """Register a new entry. Always lands in SUGGESTION or QUARANTINED.

        Quarantine at intake covers the poison profiles (unadmitted trust
        domain, no supporting evidence), entries already past their TTL,
        and contradictions with a live entry in the same scope. The
        incumbent in a conflict is never touched — a newcomer must not be
        able to silence live memory by arriving.
        """
        memory_id = new_memory_id()
        decision = intake_decision(
            entry, now=datetime.now(UTC), trusted_domains=self._trusted_domains
        )
        if not decision.quarantine:
            conflict = self._first_conflict(tenant_id=tenant_id, entry=entry)
            if conflict is not None:
                decision = QuarantineDecision.block(
                    f"conflict: competing claim with memory {conflict.memory_id} "
                    f"under claim key {entry.claim.key!r}"
                )

        artifact = self._registry.register_artifact(
            tenant_id=tenant_id,
            artifact_type=MEMORY_ENTRY_ARTIFACT_TYPE,
            canonical_bytes=entry_canonical_bytes(memory_id, entry),
            dependencies=self._lesson_dependencies(tenant_id=tenant_id, entry=entry),
        )
        row = MemoryEntryRow(
            tenant_id=tenant_id,
            memory_id=memory_id,
            artifact_digest=artifact.digest,
            semantic_type=entry.semantic_type.value,
            trust_domain=entry.provenance.trust_domain,
            subject=entry.scope.subject,
            environment=entry.scope.environment,
            task_type=entry.scope.task_type,
            model_id=entry.scope.model_id,
            harness_id=entry.scope.harness_id,
            claim_key=entry.claim.key,
            claim_statement=entry.claim.statement,
            confidence=entry.confidence,
            sensitivity=entry.sensitivity.value,
            valid_from=entry.time_validity.valid_from,
            valid_until=entry.time_validity.valid_until,
            status=MemoryStatus.QUARANTINED if decision.quarantine else MemoryStatus.SUGGESTION,
            status_reason=decision.reason,
            is_generalized_lesson=entry.is_generalized_lesson,
            parent_memory_ids=list(entry.parent_memory_ids),
            supersedes=list(entry.supersedes),
        )
        self._session.add(row)
        self._session.flush()
        return row

    # ------------------------------------------------------------------
    # Promotion (the only suggestion -> active path, fully gated)
    # ------------------------------------------------------------------

    def promote_entry(
        self,
        *,
        tenant_id: str,
        memory_id: str,
        persistence_on: list[float],
        persistence_off: list[float],
        probe_baseline: list[float],
        probe_with_memory: list[float],
        actor_identity: str,
        margin: float = DEFAULT_NON_INFERIORITY_MARGIN,
        max_regression: float = DEFAULT_MAX_NEGATIVE_TRANSFER,
        alpha: float = DEFAULT_GATE_ALPHA,
        seed: int = 0,
    ) -> MemoryEntryRow:
        """Promote a suggestion to active memory — only if every gate passes.

        The gate inputs are paired per-task scores from the persistence
        on/off comparison and the out-of-scope negative-transfer probes;
        supplying them is the caller's proof the evaluation was actually
        run. A failed gate raises `PromotionBlockedError` carrying the
        full report, and the entry stays exactly as it was.
        """
        row = self._require_row(tenant_id=tenant_id, memory_id=memory_id)
        unresolved = self._count_conflicts(
            tenant_id=tenant_id,
            claim_key=row.claim_key,
            claim_statement=row.claim_statement,
            subject=row.subject,
            environment=row.environment,
            task_type=row.task_type,
            exclude_memory_id=row.memory_id,
        )
        report = GateReport(
            results=(
                persistence_non_inferiority_gate(
                    persistence_on,
                    persistence_off,
                    margin=margin,
                    alpha=alpha,
                    seed=seed,
                ),
                negative_transfer_gate(
                    probe_baseline,
                    probe_with_memory,
                    max_regression=max_regression,
                    alpha=alpha,
                    seed=seed,
                ),
                hygiene_gate(status=row.status, unresolved_conflicts=unresolved),
            )
        )
        if not report.passed:
            raise PromotionBlockedError(report)
        # Validate supersession links before ANY mutation: a dangling link
        # must leave the entry exactly as it was, not half-promoted.
        self._validate_supersession_targets(tenant_id=tenant_id, row=row)

        self._registry.append_status_event(
            tenant_id=tenant_id,
            artifact_digest=row.artifact_digest,
            kind="nominate",
            actor_identity=actor_identity,
            reason="promotion gates passed: "
            + "; ".join(f"{r.gate} ({r.detail})" for r in report.results),
        )
        row.status = MemoryStatus.ACTIVE
        row.status_reason = None
        self._apply_supersession(tenant_id=tenant_id, row=row, actor_identity=actor_identity)
        self._session.flush()
        return row

    def _validate_supersession_targets(self, *, tenant_id: str, row: MemoryEntryRow) -> None:
        """Raise before any mutation if a supersession link dangles."""
        for target_id in row.supersedes:
            target_memory_id = str(target_id)
            target = self._session.execute(
                select(MemoryEntryRow).where(
                    MemoryEntryRow.tenant_id == tenant_id,
                    MemoryEntryRow.memory_id == target_memory_id,
                )
            ).scalar_one_or_none()
            if target is None:
                raise SupersessionTargetNotFoundError(
                    f"memory {row.memory_id!r} declares it supersedes "
                    f"{target_memory_id!r}, which does not exist in tenant "
                    f"{tenant_id!r} — dangling supersession link"
                )

    def _apply_supersession(
        self, *, tenant_id: str, row: MemoryEntryRow, actor_identity: str
    ) -> None:
        """Retire every entry the promoted entry declares it supersedes.

        Targets were validated before promotion mutated anything; this runs
        after, as part of the same transaction."""
        for target_id in row.supersedes:
            target_memory_id = str(target_id)
            target = self._session.execute(
                select(MemoryEntryRow).where(
                    MemoryEntryRow.tenant_id == tenant_id,
                    MemoryEntryRow.memory_id == target_memory_id,
                )
            ).scalar_one()
            self._registry.append_status_event(
                tenant_id=tenant_id,
                artifact_digest=target.artifact_digest,
                kind="supersede",
                actor_identity=actor_identity,
                reason=f"superseded by {row.memory_id}",
            )
            target.status = MemoryStatus.REVOKED
            target.status_reason = f"superseded by {row.memory_id}"

    # ------------------------------------------------------------------
    # Quarantine / revocation / expiry
    # ------------------------------------------------------------------

    def quarantine_entry(
        self, *, tenant_id: str, memory_id: str, reason: str, actor_identity: str
    ) -> MemoryEntryRow:
        """Pull an entry out of circulation, keeping it for audit."""
        row = self._require_row(tenant_id=tenant_id, memory_id=memory_id)
        self._registry.append_status_event(
            tenant_id=tenant_id,
            artifact_digest=row.artifact_digest,
            kind="quarantine",
            actor_identity=actor_identity,
            reason=reason,
        )
        row.status = MemoryStatus.QUARANTINED
        row.status_reason = reason
        self._session.flush()
        return row

    def revoke_entry(
        self,
        *,
        tenant_id: str,
        memory_id: str,
        reason: str,
        requested_by: str,
        actor_identity: str,
    ) -> RevocationOutcome:
        """Revoke an entry and propagate the revocation.

        Three things happen, in order: the entry itself is revoked (status
        event + row), every generalized lesson citing it is quarantined
        (its supporting evidence is gone; the lesson is retained for audit
        but leaves circulation), and a D4 tombstone is requested over the
        entry's payload so the standard sweeps revoke access and purge
        everything derived from it. Revoking a lesson never touches its
        evidence entries — that independence is the point of making
        lessons separate derived artifacts.
        """
        row = self._require_row(tenant_id=tenant_id, memory_id=memory_id)
        self._registry.append_status_event(
            tenant_id=tenant_id,
            artifact_digest=row.artifact_digest,
            kind="revoke",
            actor_identity=actor_identity,
            reason=reason,
        )
        row.status = MemoryStatus.REVOKED
        row.status_reason = reason

        lessons = list(self._dependent_lessons(tenant_id=tenant_id, memory_id=memory_id))
        for lesson in lessons:
            self._registry.append_status_event(
                tenant_id=tenant_id,
                artifact_digest=lesson.artifact_digest,
                kind="quarantine",
                actor_identity=actor_identity,
                reason=f"supporting evidence revoked: {memory_id}",
            )
            lesson.status = MemoryStatus.QUARANTINED
            lesson.status_reason = f"supporting evidence revoked: {memory_id}"

        artifact = self._registry.get_artifact(tenant_id=tenant_id, digest=row.artifact_digest)
        payload_digest = artifact.storage_uri.removeprefix(f"{STORAGE_URI_SCHEME}://")
        tombstone = self._deletions.request_deletion(
            tenant_id=tenant_id,
            resource_type="payload",
            resource_id=payload_digest,
            requested_by=requested_by,
            reason=reason,
        )
        self._session.flush()
        return RevocationOutcome(
            revoked=row, quarantined_lessons=tuple(lessons), tombstone=tombstone
        )

    def expire_stale(self, *, now: datetime | None = None) -> list[MemoryEntryRow]:
        """TTL sweep: retire every live entry past its `valid_until`.

        Runs across all tenants (it is a scheduler entry point, like the
        D4 sweeps). Expired rows are kept — the record that a claim was
        once believed is the audit trail for why behavior changed.
        """
        now = now or datetime.now(UTC)
        stale = list(
            self._session.execute(
                select(MemoryEntryRow).where(
                    MemoryEntryRow.valid_until.is_not(None),
                    MemoryEntryRow.valid_until < now,
                    MemoryEntryRow.status.in_(_LIVE_STATUSES),
                )
            )
            .scalars()
            .all()
        )
        for row in stale:
            self._registry.append_status_event(
                tenant_id=row.tenant_id,
                artifact_digest=row.artifact_digest,
                kind="expire",
                actor_identity="system:ttl-sweep",
                reason=f"ttl expired at {now.isoformat()}",
            )
            row.status = MemoryStatus.EXPIRED
            row.status_reason = "ttl expired"
        self._session.flush()
        return stale

    # ------------------------------------------------------------------
    # Derived data (purge propagation surface)
    # ------------------------------------------------------------------

    def register_derived_data(
        self, *, tenant_id: str, memory_id: str, kind: str, ref: str
    ) -> DerivedDataRecord:
        """Register materialized derived data (an embedding, cache entry,
        plugin checkpoint, or export) against the entry's payload.

        Keyed by the payload digest — the same resource id the D4 tombstone
        names — so revocation propagation needs no memory-specific purge
        code: the existing sweeps already delete every record matching the
        tombstoned resource.
        """
        if kind not in DERIVED_DATA_KINDS:
            raise ValueError(
                f"derived data kind {kind!r} is not one of {sorted(DERIVED_DATA_KINDS)}"
            )
        payload_digest = self._payload_digest(tenant_id=tenant_id, memory_id=memory_id)
        record = DerivedDataRecord(
            tenant_id=tenant_id, resource_id=payload_digest, kind=kind, ref=ref
        )
        self._session.add(record)
        self._session.flush()
        return record

    # ------------------------------------------------------------------
    # Retrieval utility
    # ------------------------------------------------------------------

    def record_retrieval(
        self, *, tenant_id: str, memory_id: str, now: datetime | None = None
    ) -> MemoryEntryRow:
        """Record one retrieval of the entry (observed utility signal)."""
        row = self._require_row(tenant_id=tenant_id, memory_id=memory_id)
        row.retrieval_count += 1
        row.last_retrieved_at = now or datetime.now(UTC)
        self._session.flush()
        return row

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def get_entry(self, *, tenant_id: str, memory_id: str) -> MemoryEntryRow:
        return self._require_row(tenant_id=tenant_id, memory_id=memory_id)

    def find_conflicts(self, *, tenant_id: str, entry: MemoryEntry) -> list[MemoryEntryRow]:
        """Live entries whose claim competes with `entry` in the same scope."""
        return list(self._conflicting_rows(tenant_id=tenant_id, entry=entry))

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _require_row(self, *, tenant_id: str, memory_id: str) -> MemoryEntryRow:
        row = self._session.execute(
            select(MemoryEntryRow).where(
                MemoryEntryRow.tenant_id == tenant_id, MemoryEntryRow.memory_id == memory_id
            )
        ).scalar_one_or_none()
        if row is None:
            raise MemoryNotFoundError(f"no memory entry {memory_id!r} for tenant {tenant_id!r}")
        return row

    def _conflicting_rows(
        self, *, tenant_id: str, entry: MemoryEntry, exclude_memory_id: str | None = None
    ) -> Sequence[MemoryEntryRow]:
        """Live rows competing with `entry`: same claim key, same scope,
        different statement."""
        conditions: list[Any] = [
            MemoryEntryRow.tenant_id == tenant_id,
            MemoryEntryRow.claim_key == entry.claim.key,
            MemoryEntryRow.claim_statement != entry.claim.statement,
            MemoryEntryRow.subject == entry.scope.subject,
            MemoryEntryRow.environment == entry.scope.environment,
            MemoryEntryRow.task_type == entry.scope.task_type,
            MemoryEntryRow.status.in_(_LIVE_STATUSES),
        ]
        if exclude_memory_id is not None:
            conditions.append(MemoryEntryRow.memory_id != exclude_memory_id)
        return self._session.execute(select(MemoryEntryRow).where(*conditions)).scalars().all()

    def _first_conflict(self, *, tenant_id: str, entry: MemoryEntry) -> MemoryEntryRow | None:
        return next(iter(self._conflicting_rows(tenant_id=tenant_id, entry=entry)), None)

    def _count_conflicts(
        self,
        *,
        tenant_id: str,
        claim_key: str,
        claim_statement: str,
        subject: str,
        environment: str,
        task_type: str,
        exclude_memory_id: str,
    ) -> int:
        conditions: list[Any] = [
            MemoryEntryRow.tenant_id == tenant_id,
            MemoryEntryRow.claim_key == claim_key,
            MemoryEntryRow.claim_statement != claim_statement,
            MemoryEntryRow.subject == subject,
            MemoryEntryRow.environment == environment,
            MemoryEntryRow.task_type == task_type,
            MemoryEntryRow.status.in_(_LIVE_STATUSES),
            MemoryEntryRow.memory_id != exclude_memory_id,
        ]
        rows = self._session.execute(select(MemoryEntryRow).where(*conditions)).scalars().all()
        return len(list(rows))

    def _dependent_lessons(self, *, tenant_id: str, memory_id: str) -> Sequence[MemoryEntryRow]:
        """Live generalized lessons citing `memory_id` as evidence."""
        return (
            self._session.execute(
                select(MemoryEntryRow).where(
                    MemoryEntryRow.tenant_id == tenant_id,
                    MemoryEntryRow.is_generalized_lesson.is_(True),
                    MemoryEntryRow.parent_memory_ids.contains([memory_id]),
                    MemoryEntryRow.status.in_(_LIVE_STATUSES),
                )
            )
            .scalars()
            .all()
        )

    def _lesson_dependencies(self, *, tenant_id: str, entry: MemoryEntry) -> list[str]:
        """Artifact digests of the evidence entries a lesson generalizes —
        they become the registered artifact's dependencies, so the
        registry's acyclicity check covers lesson graphs too."""
        dependencies: list[str] = []
        for parent_id in entry.parent_memory_ids:
            parent = self._require_row(tenant_id=tenant_id, memory_id=str(parent_id))
            dependencies.append(parent.artifact_digest)
        return dependencies

    def _payload_digest(self, *, tenant_id: str, memory_id: str) -> str:
        row = self._require_row(tenant_id=tenant_id, memory_id=memory_id)
        artifact = self._session.execute(
            select(ArtifactContent).where(
                ArtifactContent.tenant_id == tenant_id,
                ArtifactContent.digest == row.artifact_digest,
            )
        ).scalar_one()
        return artifact.storage_uri.removeprefix(f"{STORAGE_URI_SCHEME}://")

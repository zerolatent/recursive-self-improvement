"""The scaffold-mutation archive — a rebuildable projection (G9).

The harness-mutator's evaluated-candidate history, derived from the
append-only D4 core exactly the way :mod:`evoruntime.selection.
productivity` derives the FR-102 productivity projection. The evidence
stays untouched and append-only — `proposal_records` (whose metadata
carries each proposal's declared mutation class) and
`evaluation_attestations` — and this module derives a typed projection
over it: one row per declared-mutation proposal × attestation pair,
with the mutation class lifted out of the proposal metadata and the
attested ``fitness`` metric lifted out of the result metrics.

Two properties carry the design, straight from the productivity
pattern:

**The projection is rebuildable, the evidence is not.** Rows here can
be deleted and recomputed at any time (:meth:`MutationArchiveService.
rebuild`); ``reconcile`` verifies the stored rows equal what the pure
builder would produce from the raw records. Drift between the two is a
bug in the projection, never an excuse to edit the evidence. This is
also why the table carries no immutability trigger: the G9 deliverable
introduces no new append-only table, and the evidence it derives from
already carries its guards from the migrations that created it.

**Only declared mutations are archive members.** A proposal enters the
archive when its metadata declares a mutation class — the
harness-mutator's contract (every proposal declares its class) and the
graduation policy's (G10) read surface. A proposal without a declared
class is not a mutation and leaves no archive row; the exclusion is the
semantics, not an oversight.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from evoruntime.db.models.mutation_archive import ScaffoldMutationArchive
from evoruntime.db.models.registry import EvaluationAttestation, ProposalRecord

#: The proposal-metadata key carrying the declared mutation class — the
#: same key the harness-mutator plugin writes into its proposal patch
#: (``evoruntime.plugins.research.harness_mutator``). One vocabulary,
#: two ends of the pipe.
MUTATION_CLASS_METADATA_KEY = "mutation_class"

#: The attestation result-metric holding the candidate's fitness. Absent
#: means the row keeps a NULL fitness — the outcome is still evidence.
FITNESS_METRIC_KEY = "fitness"


@dataclass(frozen=True, slots=True)
class MutationArchiveRow:
    """The typed projection of one declared-mutation proposal × attestation
    pair. Mirrors one `scaffold_mutation_archive` row."""

    proposal_id: str
    artifact_digest: str
    parent_digest: str | None
    strategy_id: str
    campaign_id: str | None
    attestation_id: str
    outcome: str
    mutation_class: str
    fitness: float | None


@dataclass(frozen=True, slots=True)
class MutationClassSummary:
    """Per-class aggregation surface — the graduation policy's read shape."""

    mutation_class: str
    proposal_count: int
    attestation_count: int
    pass_count: int
    #: Mean attested fitness across the class's rows; None when no row
    #: in the class attested a fitness.
    mean_fitness: float | None


def _declared_mutation_class(metadata: Mapping[str, Any]) -> str | None:
    """The proposal's declared mutation class, or None when it declares none.

    Only a non-empty string declares a class — an empty or non-string
    value is not a declaration, and the proposal leaves no archive row.
    Pure.
    """
    value = metadata.get(MUTATION_CLASS_METADATA_KEY)
    if isinstance(value, str) and value.strip():
        return value
    return None


def _attested_fitness(metrics: Mapping[str, Any]) -> float | None:
    """The attestation's numeric fitness, or None when not attested.

    Non-numeric annotations are projection noise, as in the FR-102
    projection. Pure.
    """
    value = metrics.get(FITNESS_METRIC_KEY)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return None


def project_mutation_archive(
    proposals: Sequence[ProposalRecord], attestations: Sequence[EvaluationAttestation]
) -> tuple[MutationArchiveRow, ...]:
    """Join each declared-mutation proposal to its artifact's attestations.

    Pure: the same proposals and attestations always produce the same
    rows, which is what makes the reconciliation check meaningful. Rows
    are ordered by (proposal_id, attestation_id) so the projection is
    deterministic regardless of query order.
    """
    by_digest: dict[str, list[EvaluationAttestation]] = {}
    for attestation in attestations:
        by_digest.setdefault(attestation.artifact_digest, []).append(attestation)

    rows: list[MutationArchiveRow] = []
    for proposal in sorted(proposals, key=lambda p: p.proposal_id):
        mutation_class = _declared_mutation_class(dict(proposal.proposal_metadata))
        if mutation_class is None:
            continue
        for attestation in sorted(
            by_digest.get(proposal.proposed_digest, []), key=lambda a: a.attestation_id
        ):
            rows.append(
                MutationArchiveRow(
                    proposal_id=proposal.proposal_id,
                    artifact_digest=proposal.proposed_digest,
                    parent_digest=proposal.parent_digest,
                    strategy_id=proposal.strategy_id,
                    campaign_id=proposal.campaign_id,
                    attestation_id=attestation.attestation_id,
                    outcome=attestation.outcome,
                    mutation_class=mutation_class,
                    fitness=_attested_fitness(dict(attestation.result_metrics)),
                )
            )
    return tuple(rows)


def summarize_mutation_archive(
    rows: Sequence[MutationArchiveRow],
) -> tuple[MutationClassSummary, ...]:
    """Aggregate archive rows per mutation class. Pure.

    The graduation policy's (G10) per-class read surface: how many
    proposals and attestations a class has accumulated, how many
    passed, and its mean attested fitness.
    """
    proposals_by_class: dict[str, set[str]] = {}
    counts_by_class: dict[str, int] = {}
    passes_by_class: dict[str, int] = {}
    fitness_sums: dict[str, tuple[float, int]] = {}
    for row in rows:
        proposals_by_class.setdefault(row.mutation_class, set()).add(row.proposal_id)
        counts_by_class[row.mutation_class] = counts_by_class.get(row.mutation_class, 0) + 1
        if row.outcome == "pass":
            passes_by_class[row.mutation_class] = passes_by_class.get(row.mutation_class, 0) + 1
        if row.fitness is not None:
            total, count = fitness_sums.get(row.mutation_class, (0.0, 0))
            fitness_sums[row.mutation_class] = (total + row.fitness, count + 1)

    summaries: list[MutationClassSummary] = []
    for mutation_class in sorted(proposals_by_class):
        total, count = fitness_sums.get(mutation_class, (0.0, 0))
        summaries.append(
            MutationClassSummary(
                mutation_class=mutation_class,
                proposal_count=len(proposals_by_class[mutation_class]),
                attestation_count=counts_by_class[mutation_class],
                pass_count=passes_by_class.get(mutation_class, 0),
                mean_fitness=total / count if count else None,
            )
        )
    return tuple(summaries)


def _row_diffs(
    stored: Sequence[ScaffoldMutationArchive],
    expected: Sequence[MutationArchiveRow],
) -> list[str]:
    """Field-level differences between stored projection rows and the rows
    the pure builder produces from the raw records. Pure."""
    stored_by_key = {(row.proposal_id, row.attestation_id): row for row in stored}
    expected_by_key = {(row.proposal_id, row.attestation_id): row for row in expected}
    diffs: list[str] = []
    for key in sorted(set(stored_by_key) | set(expected_by_key)):
        stored_row = stored_by_key.get(key)
        expected_row = expected_by_key.get(key)
        if stored_row is None:
            diffs.append(f"projection missing row {key} (present in raw records)")
            continue
        if expected_row is None:
            diffs.append(f"projection has stale row {key} (absent from raw records)")
            continue
        for field_name in (
            "artifact_digest",
            "parent_digest",
            "strategy_id",
            "campaign_id",
            "outcome",
            "mutation_class",
            "fitness",
        ):
            if getattr(stored_row, field_name) != getattr(expected_row, field_name):
                diffs.append(
                    f"row {key}: {field_name} stored {getattr(stored_row, field_name)!r} != "
                    f"attested {getattr(expected_row, field_name)!r}"
                )
    return diffs


class MutationArchiveService:
    """Reads the raw append-only records and maintains the projection.

    Bound to one SQLAlchemy session; every method is tenant-scoped. The
    service never writes to `proposal_records` or
    `evaluation_attestations` — the D4 core stays append-only and
    untouched.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def rebuild(self, tenant_id: str) -> int:
        """Recompute the projection from the raw records and replace the
        tenant's stored rows. Returns the number of rows written."""
        proposals = self._session.scalars(
            select(ProposalRecord).where(ProposalRecord.tenant_id == tenant_id)
        ).all()
        attestations = self._session.scalars(
            select(EvaluationAttestation).where(EvaluationAttestation.tenant_id == tenant_id)
        ).all()
        rows = project_mutation_archive(list(proposals), list(attestations))

        for existing in self._session.scalars(
            select(ScaffoldMutationArchive).where(ScaffoldMutationArchive.tenant_id == tenant_id)
        ).all():
            self._session.delete(existing)
        for row in rows:
            self._session.add(
                ScaffoldMutationArchive(
                    tenant_id=tenant_id,
                    proposal_id=row.proposal_id,
                    artifact_digest=row.artifact_digest,
                    parent_digest=row.parent_digest,
                    strategy_id=row.strategy_id,
                    campaign_id=row.campaign_id,
                    attestation_id=row.attestation_id,
                    outcome=row.outcome,
                    mutation_class=row.mutation_class,
                    fitness=row.fitness,
                )
            )
        self._session.flush()
        return len(rows)

    def rows(self, tenant_id: str) -> tuple[ScaffoldMutationArchive, ...]:
        """The tenant's stored projection rows, deterministically ordered."""
        return tuple(
            self._session.scalars(
                select(ScaffoldMutationArchive)
                .where(ScaffoldMutationArchive.tenant_id == tenant_id)
                .order_by(
                    ScaffoldMutationArchive.proposal_id,
                    ScaffoldMutationArchive.attestation_id,
                )
            ).all()
        )

    def classes(self, tenant_id: str) -> tuple[MutationClassSummary, ...]:
        """The per-class aggregation surface over the stored rows — the
        graduation policy's read path."""
        stored = self.rows(tenant_id)
        projected = tuple(
            MutationArchiveRow(
                proposal_id=row.proposal_id,
                artifact_digest=row.artifact_digest,
                parent_digest=row.parent_digest,
                strategy_id=row.strategy_id,
                campaign_id=row.campaign_id,
                attestation_id=row.attestation_id,
                outcome=row.outcome,
                mutation_class=row.mutation_class,
                fitness=row.fitness,
            )
            for row in stored
        )
        return summarize_mutation_archive(projected)

    def reconcile(self, tenant_id: str) -> tuple[str, ...]:
        """Prove the stored projection still matches the raw records.

        Recomputes the pure projection from `proposal_records` and
        `evaluation_attestations` and diffs it against the stored rows.
        Empty tuple means reconciled; every element is a human-readable
        description of one drift."""
        proposals = self._session.scalars(
            select(ProposalRecord).where(ProposalRecord.tenant_id == tenant_id)
        ).all()
        attestations = self._session.scalars(
            select(EvaluationAttestation).where(EvaluationAttestation.tenant_id == tenant_id)
        ).all()
        expected = project_mutation_archive(list(proposals), list(attestations))
        return tuple(_row_diffs(list(self.rows(tenant_id)), list(expected)))


__all__ = [
    "FITNESS_METRIC_KEY",
    "MUTATION_CLASS_METADATA_KEY",
    "MutationArchiveRow",
    "MutationArchiveService",
    "MutationClassSummary",
    "project_mutation_archive",
    "summarize_mutation_archive",
]

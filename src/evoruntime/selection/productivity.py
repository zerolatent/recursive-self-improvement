"""Typed lineage-productivity projection (FR-102).

The D4 append-only core — proposal records and evaluation attestations —
stays untouched and remains the evidence. This module derives a *typed
projection* over that evidence: each proposal x attestation pair with the
attestation's cost metrics lifted from JSONB into typed columns, plus an
aggregation surface (per-artifact mean costs) and a reconciliation check
that proves the projection still matches the raw records.

Two properties carry the design:

**The projection is rebuildable, the evidence is not.** Rows here can be
deleted and recomputed at any time (`LineageProductivityService.rebuild`);
`reconcile` verifies the stored rows equal what the pure builder would
produce from the raw records. A drift between the two is a bug in the
projection, never an excuse to edit the evidence.

**The productivity score is computed, never stored.** It is
`selection_score / normalized cost` under a rule-pinned metric and
normalization, both preregistered at spec time (`NominationRule`). The
projection supplies the cost input; the trusted selector computes the
score. Storing a score would pin an unpinned normalization.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from evoruntime.core.metrics import COST_METRIC_KEYS
from evoruntime.db.models.productivity import LineageProductivityProjection
from evoruntime.db.models.registry import EvaluationAttestation, ProposalRecord

#: The typed cost columns of the projection, in canonical order. Exactly
#: the COST_METRIC_KEYS vocabulary — a new cost metric is a code change
#: here and in `evoruntime.core.metrics`, reviewed as a spec change.
PRODUCTIVITY_COST_COLUMNS: tuple[str, ...] = (
    "tokens",
    "total_tokens",
    "mean_total_tokens",
    "cost_usd",
    "wall_clock_s",
)


@dataclass(frozen=True, slots=True)
class ProductivityProjectionRow:
    """The typed projection of one proposal x attestation pair.

    Mirrors one `lineage_productivity` row; `cost` holds the attested
    values for the closed cost vocabulary (absent keys were not attested).
    """

    proposal_id: str
    artifact_digest: str
    parent_digest: str | None
    strategy_id: str
    campaign_id: str | None
    attestation_id: str
    outcome: str
    cost: Mapping[str, float]


@dataclass(frozen=True, slots=True)
class ProductivitySummary:
    """Aggregated productivity surface for one artifact digest."""

    artifact_digest: str
    proposal_count: int
    attestation_count: int
    #: Mean of each attested cost metric across the artifact's projection
    #: rows. Keys are members of COST_METRIC_KEYS; a metric never attested
    #: for the artifact is absent.
    mean_cost: Mapping[str, float]


def _numeric_cost_metrics(raw: Mapping[str, Any]) -> dict[str, float]:
    """Keep only numeric entries whose key is in the closed cost vocabulary.

    Attestation `result_metrics` may carry non-numeric annotations and
    non-cost metrics; both are projection noise. Pure.
    """
    return {
        str(key): float(value)
        for key, value in raw.items()
        if key in COST_METRIC_KEYS
        and isinstance(value, (int, float))
        and not isinstance(value, bool)
    }


def project_productivity(
    proposals: Sequence[ProposalRecord], attestations: Sequence[EvaluationAttestation]
) -> tuple[ProductivityProjectionRow, ...]:
    """Join each proposal to its artifact's attestations into typed rows.

    Pure: the same proposals and attestations always produce the same rows,
    which is what makes the reconciliation check meaningful. Rows are
    ordered by (proposal_id, attestation_id) so the projection is
    deterministic regardless of query order.
    """
    by_digest: dict[str, list[EvaluationAttestation]] = {}
    for attestation in attestations:
        by_digest.setdefault(attestation.artifact_digest, []).append(attestation)

    rows: list[ProductivityProjectionRow] = []
    for proposal in sorted(proposals, key=lambda p: p.proposal_id):
        for attestation in sorted(
            by_digest.get(proposal.proposed_digest, []), key=lambda a: a.attestation_id
        ):
            rows.append(
                ProductivityProjectionRow(
                    proposal_id=proposal.proposal_id,
                    artifact_digest=proposal.proposed_digest,
                    parent_digest=proposal.parent_digest,
                    strategy_id=proposal.strategy_id,
                    campaign_id=proposal.campaign_id,
                    attestation_id=attestation.attestation_id,
                    outcome=attestation.outcome,
                    cost=MappingProxyType(_numeric_cost_metrics(dict(attestation.result_metrics))),
                )
            )
    return tuple(rows)


def summarize_productivity(
    rows: Sequence[ProductivityProjectionRow],
) -> tuple[ProductivitySummary, ...]:
    """Aggregate projection rows per artifact: proposal/attestation counts
    and the mean of each attested cost metric. Pure."""
    proposals_by_artifact: dict[str, set[str]] = {}
    counts_by_artifact: dict[str, int] = {}
    sums_by_artifact: dict[str, dict[str, float]] = {}
    for row in rows:
        proposals_by_artifact.setdefault(row.artifact_digest, set()).add(row.proposal_id)
        counts_by_artifact[row.artifact_digest] = counts_by_artifact.get(row.artifact_digest, 0) + 1
        sums = sums_by_artifact.setdefault(row.artifact_digest, {})
        for key, value in row.cost.items():
            sums[key] = sums.get(key, 0.0) + value

    summaries: list[ProductivitySummary] = []
    for artifact_digest in sorted(proposals_by_artifact):
        count = counts_by_artifact[artifact_digest]
        sums = sums_by_artifact[artifact_digest]
        summaries.append(
            ProductivitySummary(
                artifact_digest=artifact_digest,
                proposal_count=len(proposals_by_artifact[artifact_digest]),
                attestation_count=count,
                mean_cost=MappingProxyType(
                    {key: total / count for key, total in sorted(sums.items())}
                ),
            )
        )
    return tuple(summaries)


def _row_diffs(
    stored: Sequence[LineageProductivityProjection],
    expected: Sequence[ProductivityProjectionRow],
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
        ):
            if getattr(stored_row, field_name) != getattr(expected_row, field_name):
                diffs.append(
                    f"row {key}: {field_name} stored {getattr(stored_row, field_name)!r} != "
                    f"attested {getattr(expected_row, field_name)!r}"
                )
        for column in PRODUCTIVITY_COST_COLUMNS:
            stored_value = getattr(stored_row, column)
            expected_value = expected_row.cost.get(column)
            if stored_value != expected_value:
                diffs.append(
                    f"row {key}: {column} stored {stored_value!r} != attested {expected_value!r}"
                )
    return diffs


class LineageProductivityService:
    """Reads the raw append-only records and maintains the typed projection.

    Bound to one SQLAlchemy session; every method is tenant-scoped. The
    service never writes to `proposal_records` or `evaluation_attestations`
    — the D4 core stays append-only and untouched.
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
        rows = project_productivity(list(proposals), list(attestations))

        for existing in self._session.scalars(
            select(LineageProductivityProjection).where(
                LineageProductivityProjection.tenant_id == tenant_id
            )
        ).all():
            self._session.delete(existing)
        for row in rows:
            self._session.add(
                LineageProductivityProjection(
                    tenant_id=tenant_id,
                    proposal_id=row.proposal_id,
                    artifact_digest=row.artifact_digest,
                    parent_digest=row.parent_digest,
                    strategy_id=row.strategy_id,
                    campaign_id=row.campaign_id,
                    attestation_id=row.attestation_id,
                    outcome=row.outcome,
                    tokens=row.cost.get("tokens"),
                    total_tokens=row.cost.get("total_tokens"),
                    mean_total_tokens=row.cost.get("mean_total_tokens"),
                    cost_usd=row.cost.get("cost_usd"),
                    wall_clock_s=row.cost.get("wall_clock_s"),
                )
            )
        self._session.flush()
        return len(rows)

    def rows(self, tenant_id: str) -> tuple[LineageProductivityProjection, ...]:
        """The tenant's stored projection rows, deterministically ordered."""
        return tuple(
            self._session.scalars(
                select(LineageProductivityProjection)
                .where(LineageProductivityProjection.tenant_id == tenant_id)
                .order_by(
                    LineageProductivityProjection.proposal_id,
                    LineageProductivityProjection.attestation_id,
                )
            ).all()
        )

    def summary(self, tenant_id: str) -> tuple[ProductivitySummary, ...]:
        """The aggregation surface: per-artifact mean attested costs,
        computed over the stored projection rows."""
        stored = self.rows(tenant_id)
        projected = tuple(
            ProductivityProjectionRow(
                proposal_id=row.proposal_id,
                artifact_digest=row.artifact_digest,
                parent_digest=row.parent_digest,
                strategy_id=row.strategy_id,
                campaign_id=row.campaign_id,
                attestation_id=row.attestation_id,
                outcome=row.outcome,
                cost=MappingProxyType(
                    {
                        column: getattr(row, column)
                        for column in PRODUCTIVITY_COST_COLUMNS
                        if getattr(row, column) is not None
                    }
                ),
            )
            for row in stored
        )
        return summarize_productivity(projected)

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
        expected = project_productivity(list(proposals), list(attestations))
        return tuple(_row_diffs(list(self.rows(tenant_id)), list(expected)))


__all__ = [
    "PRODUCTIVITY_COST_COLUMNS",
    "LineageProductivityService",
    "ProductivityProjectionRow",
    "ProductivitySummary",
    "project_productivity",
    "summarize_productivity",
]

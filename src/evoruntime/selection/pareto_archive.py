"""The Pareto archive projection and slice reporting (Phase 4, H5).

The append-only core — proposal records and evaluation attestations —
stays untouched and remains the evidence. This module derives a typed
projection over that evidence: each proposal × attestation pair with the
pair's slice annotations (task type, difficulty, safety class) and the
attestation's cost metrics lifted from JSONB into typed columns, plus
two read surfaces — per-slice aggregation and the Pareto frontier.

Three properties carry the design:

**The projection is rebuildable, the evidence is not.** Rows here can be
deleted and recomputed at any time (`ParetoArchiveService.rebuild`);
`reconcile` verifies the stored rows equal what the pure builder would
produce from the raw records. A drift between the two is a bug in the
projection, never an excuse to edit the evidence.

**Costs come only from attestations.** Every cost number in this module
is read from the signed attestation's `result_metrics` restricted to the
closed `COST_METRIC_KEYS` vocabulary — an agent's claimed cost never
enters the archive. Latency is `wall_clock_s`, a member of that same
vocabulary, so the latency slice needs no separate channel.

**The frontier is computed, never stored.** Dominance depends on which
metrics you compare and how you aggregate them; storing frontier
membership would pin an unpinned rule into the database. The projection
supplies the typed inputs; `pareto_frontier` computes membership on
read under the rule documented there.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from evoruntime.core.metrics import COST_METRIC_KEYS
from evoruntime.db.models.pareto_archive import ParetoArchiveProjection
from evoruntime.db.models.registry import EvaluationAttestation, ProposalRecord

#: The closed slice-key vocabulary. H7 annotates every coding manifest
#: with `task_type` and `difficulty`; `safety_class` is the declared
#: safety dimension (adversarial fixtures declare a class, coding
#: fixtures implicitly belong to none). A new slice dimension is a code
#: change here and in `evoruntime.db.models.pareto_archive`, reviewed as
#: a spec change — never a runtime value a caller can inject.
SLICE_DIMENSIONS: tuple[str, ...] = ("task_type", "difficulty", "safety_class")

#: The typed cost columns of the projection, in canonical order. Exactly
#: the COST_METRIC_KEYS vocabulary — a new cost metric is a code change
#: here and in `evoruntime.core.metrics`, reviewed as a spec change.
PARETO_COST_COLUMNS: tuple[str, ...] = (
    "tokens",
    "total_tokens",
    "mean_total_tokens",
    "cost_usd",
    "wall_clock_s",
)


@dataclass(frozen=True, slots=True)
class ParetoArchiveRow:
    """The typed projection of one proposal × attestation pair.

    Mirrors one `pareto_archive` row; `slices` holds the pair's slice
    annotations and `cost` the attested values for the closed cost
    vocabulary (absent keys were not attested).
    """

    proposal_id: str
    artifact_digest: str
    parent_digest: str | None
    strategy_id: str
    campaign_id: str | None
    attestation_id: str
    outcome: str
    slices: Mapping[str, str]
    cost: Mapping[str, float]


@dataclass(frozen=True, slots=True)
class SliceSummary:
    """Aggregated outcomes and attested costs for one slice value."""

    dimension: str
    value: str
    attestation_count: int
    pass_count: int
    #: pass_count / attestation_count; None when the slice has no rows.
    success_rate: float | None
    #: Mean of each attested cost metric across the slice's rows. Keys
    #: are members of COST_METRIC_KEYS; a metric never attested within
    #: the slice is absent.
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


def _slice_values(proposal: ProposalRecord, attestation: EvaluationAttestation) -> dict[str, str]:
    """Read the pair's slice annotations for the closed vocabulary.

    The proposal's declared metadata wins (it is preregistered at
    proposal time); a dimension the proposal does not declare falls back
    to a string annotation on the signed attestation. Non-string values
    and unknown keys are projection noise. Pure.
    """
    slices: dict[str, str] = {}
    for dimension in SLICE_DIMENSIONS:
        declared = proposal.proposal_metadata.get(dimension)
        if isinstance(declared, str) and declared:
            slices[dimension] = declared
            continue
        attested = dict(attestation.result_metrics).get(dimension)
        if isinstance(attested, str) and attested:
            slices[dimension] = attested
    return slices


def project_pareto_rows(
    proposals: Sequence[ProposalRecord], attestations: Sequence[EvaluationAttestation]
) -> tuple[ParetoArchiveRow, ...]:
    """Join each proposal to its artifact's attestations into typed rows.

    Pure: the same proposals and attestations always produce the same
    rows, which is what makes the reconciliation check meaningful. Rows
    are ordered by (proposal_id, attestation_id) so the projection is
    deterministic regardless of query order.
    """
    by_digest: dict[str, list[EvaluationAttestation]] = {}
    for attestation in attestations:
        by_digest.setdefault(attestation.artifact_digest, []).append(attestation)

    rows: list[ParetoArchiveRow] = []
    for proposal in sorted(proposals, key=lambda p: p.proposal_id):
        for attestation in sorted(
            by_digest.get(proposal.proposed_digest, []), key=lambda a: a.attestation_id
        ):
            rows.append(
                ParetoArchiveRow(
                    proposal_id=proposal.proposal_id,
                    artifact_digest=proposal.proposed_digest,
                    parent_digest=proposal.parent_digest,
                    strategy_id=proposal.strategy_id,
                    campaign_id=proposal.campaign_id,
                    attestation_id=attestation.attestation_id,
                    outcome=attestation.outcome,
                    slices=MappingProxyType(_slice_values(proposal, attestation)),
                    cost=MappingProxyType(_numeric_cost_metrics(dict(attestation.result_metrics))),
                )
            )
    return tuple(rows)


def summarize_by_slice(
    rows: Sequence[ParetoArchiveRow], dimension: str
) -> tuple[SliceSummary, ...]:
    """Aggregate rows per value of one slice dimension.

    Success is the pass rate over the slice's attestation outcomes; cost
    and latency means come only from attested metrics. Pure. Raises
    ValueError for a dimension outside the closed vocabulary — a typo'd
    dimension must fail loudly, not silently return an empty summary.
    """
    if dimension not in SLICE_DIMENSIONS:
        raise ValueError(
            f"unknown slice dimension {dimension!r}; must be one of {', '.join(SLICE_DIMENSIONS)}"
        )

    counts: dict[str, int] = {}
    passes: dict[str, int] = {}
    sums: dict[str, dict[str, float]] = {}
    for row in rows:
        value = row.slices.get(dimension)
        if value is None:
            continue
        counts[value] = counts.get(value, 0) + 1
        if row.outcome == "pass":
            passes[value] = passes.get(value, 0) + 1
        sums_for_value = sums.setdefault(value, {})
        for key, cost in row.cost.items():
            sums_for_value[key] = sums_for_value.get(key, 0.0) + cost

    summaries: list[SliceSummary] = []
    for value in sorted(counts):
        count = counts[value]
        sums_for_value = sums[value]
        summaries.append(
            SliceSummary(
                dimension=dimension,
                value=value,
                attestation_count=count,
                pass_count=passes.get(value, 0),
                success_rate=passes.get(value, 0) / count,
                mean_cost=MappingProxyType(
                    {key: total / count for key, total in sorted(sums_for_value.items())}
                ),
            )
        )
    return tuple(summaries)


@dataclass(frozen=True, slots=True)
class _ArtifactAggregate:
    """One artifact's aggregated evidence, the dominance comparison unit."""

    artifact_digest: str
    proposal_ids: tuple[str, ...]
    attestation_count: int
    pass_count: int
    mean_cost: Mapping[str, float]

    @property
    def success_rate(self) -> float | None:
        if self.attestation_count == 0:
            return None
        return self.pass_count / self.attestation_count


def _aggregate_by_artifact(rows: Sequence[ParetoArchiveRow]) -> tuple[_ArtifactAggregate, ...]:
    """Collapse projection rows into one aggregate per artifact digest. Pure."""
    proposals_by_artifact: dict[str, set[str]] = {}
    counts: dict[str, int] = {}
    passes: dict[str, int] = {}
    sums: dict[str, dict[str, float]] = {}
    for row in rows:
        digest = row.artifact_digest
        proposals_by_artifact.setdefault(digest, set()).add(row.proposal_id)
        counts[digest] = counts.get(digest, 0) + 1
        if row.outcome == "pass":
            passes[digest] = passes.get(digest, 0) + 1
        sums_for_artifact = sums.setdefault(digest, {})
        for key, cost in row.cost.items():
            sums_for_artifact[key] = sums_for_artifact.get(key, 0.0) + cost

    aggregates: list[_ArtifactAggregate] = []
    for digest in sorted(proposals_by_artifact):
        count = counts[digest]
        aggregates.append(
            _ArtifactAggregate(
                artifact_digest=digest,
                proposal_ids=tuple(sorted(proposals_by_artifact[digest])),
                attestation_count=count,
                pass_count=passes.get(digest, 0),
                mean_cost=MappingProxyType(
                    {key: total / count for key, total in sorted(sums[digest].items())}
                ),
            )
        )
    return tuple(aggregates)


def _dominates(a: _ArtifactAggregate, b: _ArtifactAggregate) -> bool:
    """The dominance rule, stated once.

    A dominates B when A's success rate is at least B's, A's mean cost is
    at most B's on every cost metric attested for *both*, and at least
    one comparison is strict. Metrics attested for only one side are not
    compared — an artifact cannot be punished (or credited) for a metric
    its rival was never measured on. An artifact with no passing
    evidence (success rate None) dominates nothing.
    """
    a_rate = a.success_rate
    b_rate = b.success_rate
    if a_rate is None or b_rate is None or a_rate < b_rate:
        return False
    shared = set(a.mean_cost) & set(b.mean_cost)
    cost_at_least_as_good = all(a.mean_cost[key] <= b.mean_cost[key] for key in shared)
    strictly_better = a_rate > b_rate or any(a.mean_cost[key] < b.mean_cost[key] for key in shared)
    return cost_at_least_as_good and strictly_better


def pareto_frontier(
    rows: Sequence[ParetoArchiveRow],
) -> tuple[ParetoArchiveEntry, ...]:
    """Compute the archive's Pareto frontier from projection rows.

    Pure. Aggregates rows per artifact, then marks each artifact with the
    digests it dominates and the digests that dominate it; the frontier
    is the set of artifacts dominated by nothing. Artifacts with no
    attestations never appear (no evidence, no membership).
    """
    aggregates = _aggregate_by_artifact(rows)
    by_digest = {aggregate.artifact_digest: aggregate for aggregate in aggregates}

    dominates_by: dict[str, list[str]] = {digest: [] for digest in by_digest}
    dominated_by: dict[str, list[str]] = {digest: [] for digest in by_digest}
    for a in aggregates:
        for b in aggregates:
            if a.artifact_digest == b.artifact_digest:
                continue
            if _dominates(a, b):
                dominates_by[a.artifact_digest].append(b.artifact_digest)
                dominated_by[b.artifact_digest].append(a.artifact_digest)

    return tuple(
        ParetoArchiveEntry(
            artifact_digest=aggregate.artifact_digest,
            proposal_ids=aggregate.proposal_ids,
            attestation_count=aggregate.attestation_count,
            pass_count=aggregate.pass_count,
            success_rate=aggregate.success_rate,
            mean_cost=aggregate.mean_cost,
            dominates=tuple(sorted(dominates_by[aggregate.artifact_digest])),
            dominated_by=tuple(sorted(dominated_by[aggregate.artifact_digest])),
        )
        for aggregate in aggregates
    )


@dataclass(frozen=True, slots=True)
class ParetoArchiveEntry:
    """Public archive record for one artifact (see `pareto_frontier`)."""

    artifact_digest: str
    proposal_ids: tuple[str, ...]
    attestation_count: int
    pass_count: int
    success_rate: float | None
    mean_cost: Mapping[str, float]
    dominates: tuple[str, ...]
    dominated_by: tuple[str, ...]

    @property
    def on_frontier(self) -> bool:
        """Frontier membership: dominated by nothing in the archive."""
        return not self.dominated_by


def _row_diffs(
    stored: Sequence[ParetoArchiveProjection], expected: Sequence[ParetoArchiveRow]
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
        for dimension in SLICE_DIMENSIONS:
            stored_value = getattr(stored_row, dimension)
            expected_value = expected_row.slices.get(dimension)
            if stored_value != expected_value:
                diffs.append(
                    f"row {key}: {dimension} stored {stored_value!r} != declared {expected_value!r}"
                )
        for column in PARETO_COST_COLUMNS:
            stored_cost = getattr(stored_row, column)
            expected_cost = expected_row.cost.get(column)
            if stored_cost != expected_cost:
                diffs.append(
                    f"row {key}: {column} stored {stored_cost!r} != attested {expected_cost!r}"
                )
    return diffs


def _stored_to_row(stored: ParetoArchiveProjection) -> ParetoArchiveRow:
    """Rehydrate a pure row from a stored projection row. Pure."""
    return ParetoArchiveRow(
        proposal_id=stored.proposal_id,
        artifact_digest=stored.artifact_digest,
        parent_digest=stored.parent_digest,
        strategy_id=stored.strategy_id,
        campaign_id=stored.campaign_id,
        attestation_id=stored.attestation_id,
        outcome=stored.outcome,
        slices=MappingProxyType(
            {
                dimension: getattr(stored, dimension)
                for dimension in SLICE_DIMENSIONS
                if getattr(stored, dimension) is not None
            }
        ),
        cost=MappingProxyType(
            {
                column: getattr(stored, column)
                for column in PARETO_COST_COLUMNS
                if getattr(stored, column) is not None
            }
        ),
    )


class ParetoArchiveService:
    """Reads the raw append-only records and maintains the typed projection.

    Bound to one SQLAlchemy session; every method is tenant-scoped. The
    service never writes to `proposal_records` or `evaluation_attestations`
    — the append-only core stays append-only and untouched.
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
        rows = project_pareto_rows(list(proposals), list(attestations))

        for existing in self._session.scalars(
            select(ParetoArchiveProjection).where(ParetoArchiveProjection.tenant_id == tenant_id)
        ).all():
            self._session.delete(existing)
        for row in rows:
            self._session.add(
                ParetoArchiveProjection(
                    tenant_id=tenant_id,
                    proposal_id=row.proposal_id,
                    artifact_digest=row.artifact_digest,
                    parent_digest=row.parent_digest,
                    strategy_id=row.strategy_id,
                    campaign_id=row.campaign_id,
                    attestation_id=row.attestation_id,
                    outcome=row.outcome,
                    task_type=row.slices.get("task_type"),
                    difficulty=row.slices.get("difficulty"),
                    safety_class=row.slices.get("safety_class"),
                    tokens=row.cost.get("tokens"),
                    total_tokens=row.cost.get("total_tokens"),
                    mean_total_tokens=row.cost.get("mean_total_tokens"),
                    cost_usd=row.cost.get("cost_usd"),
                    wall_clock_s=row.cost.get("wall_clock_s"),
                )
            )
        self._session.flush()
        return len(rows)

    def rows(self, tenant_id: str) -> tuple[ParetoArchiveProjection, ...]:
        """The tenant's stored projection rows, deterministically ordered."""
        return tuple(
            self._session.scalars(
                select(ParetoArchiveProjection)
                .where(ParetoArchiveProjection.tenant_id == tenant_id)
                .order_by(
                    ParetoArchiveProjection.proposal_id,
                    ParetoArchiveProjection.attestation_id,
                )
            ).all()
        )

    def campaign_rows(self, tenant_id: str, campaign_id: str) -> tuple[ParetoArchiveRow, ...]:
        """The campaign's stored projection rows as pure rows."""
        return tuple(
            _stored_to_row(row) for row in self.rows(tenant_id) if row.campaign_id == campaign_id
        )

    def slice_summary(
        self, tenant_id: str, campaign_id: str, dimension: str
    ) -> tuple[SliceSummary, ...]:
        """Per-value aggregation for one slice dimension over the
        campaign's stored projection rows."""
        return summarize_by_slice(self.campaign_rows(tenant_id, campaign_id), dimension)

    def frontier(self, tenant_id: str, campaign_id: str) -> tuple[ParetoArchiveEntry, ...]:
        """The campaign's Pareto frontier, computed over the stored
        projection rows."""
        return pareto_frontier(self.campaign_rows(tenant_id, campaign_id))

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
        expected = project_pareto_rows(list(proposals), list(attestations))
        return tuple(_row_diffs(list(self.rows(tenant_id)), list(expected)))


__all__ = [
    "PARETO_COST_COLUMNS",
    "SLICE_DIMENSIONS",
    "ParetoArchiveEntry",
    "ParetoArchiveRow",
    "ParetoArchiveService",
    "SliceSummary",
    "pareto_frontier",
    "project_pareto_rows",
    "summarize_by_slice",
]

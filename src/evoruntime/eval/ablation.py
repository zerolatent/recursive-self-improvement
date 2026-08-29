"""Marginal ablations (Phase 2 F8, FR-101): what each component is worth.

An ablation arm is the incumbent's configuration with exactly one
component removed, so its paired delta against the incumbent *is* that
component's marginal contribution. The statistics need nothing new — the
ablation arms are candidate arms, and `summarize_experiment` already runs
every candidate-vs-incumbent paired bootstrap under one Holm family whose
size is whatever the experiment declares. What FR-101 adds is the record:
one row per ablated component, naming the component, its delta, and its
Holm-adjusted p-value, persisted through the same content-addressed
checkpoint pattern the campaign orchestrator uses (FR-005) — canonical
JSON bytes, stored under their own sha256, re-verified against that
address on load so a tampered record set is refused rather than resumed.

The records are a pure function of the `ExperimentResult`, so the
extraction can be tested against hand-built results without executing an
agent — the same discipline as `eval/results.py`.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Protocol

from evoruntime.eval.errors import MarginalContributionError
from evoruntime.eval.results import ExperimentResult

CONTRIBUTIONS_SCHEMA_ID = "evoruntime.eval.ablation.contributions/v1"
"""Schema id for marginal-contribution bytes stored in a checkpoint store."""

_DIGEST_PREFIX = "sha256:"

_RECORD_KEYS = (
    "component_id",
    "arm_id",
    "observed_delta",
    "ci_low",
    "ci_high",
    "adjusted_p_value",
    "verdict",
)


@dataclass(frozen=True, slots=True)
class MarginalContribution:
    """One ablated component's contribution, with its multiplicity-paid p-value.

    `adjusted_p_value` is the Holm-adjusted value from the experiment's
    single family — every ablation in the run shares it, so a record's
    p-value already carries the cost of every other ablation tested
    alongside it.
    """

    component_id: str
    arm_id: str
    observed_delta: float
    ci_low: float
    ci_high: float
    adjusted_p_value: float
    verdict: str

    def to_canonical_dict(self) -> dict[str, str | float]:
        """Canonical JSON form of this record."""
        return {
            "component_id": self.component_id,
            "arm_id": self.arm_id,
            "observed_delta": self.observed_delta,
            "ci_low": self.ci_low,
            "ci_high": self.ci_high,
            "adjusted_p_value": self.adjusted_p_value,
            "verdict": self.verdict,
        }

    @classmethod
    def from_canonical_dict(cls, raw: dict[str, object]) -> MarginalContribution:
        """Rebuild a record from its canonical form, shape-checking every field."""
        for key in _RECORD_KEYS:
            if key not in raw:
                raise MarginalContributionError(f"contribution record is missing {key!r}")
        component_id = raw["component_id"]
        arm_id = raw["arm_id"]
        verdict = raw["verdict"]
        if not isinstance(component_id, str) or not component_id:
            raise MarginalContributionError("component_id must be a non-empty string")
        if not isinstance(arm_id, str) or not arm_id:
            raise MarginalContributionError("arm_id must be a non-empty string")
        if not isinstance(verdict, str) or not verdict:
            raise MarginalContributionError("verdict must be a non-empty string")
        numbers: dict[str, float] = {}
        for key in ("observed_delta", "ci_low", "ci_high", "adjusted_p_value"):
            value = raw[key]
            if isinstance(value, bool) or not isinstance(value, int | float):
                raise MarginalContributionError(f"{key} must be a number, got {value!r}")
            numbers[key] = float(value)
        return cls(
            component_id=component_id,
            arm_id=arm_id,
            observed_delta=numbers["observed_delta"],
            ci_low=numbers["ci_low"],
            ci_high=numbers["ci_high"],
            adjusted_p_value=numbers["adjusted_p_value"],
            verdict=verdict,
        )


class ContributionStore(Protocol):
    """Content-addressed byte store (the campaign checkpoint pattern).

    Structurally the same contract as the orchestrator's `CheckpointStore`
    (FR-005): `store` files bytes under their own digest, `load` returns
    them. Any content-addressed store — the in-memory test double, the
    payload store — satisfies it without importing this module.
    """

    def store(self, data: bytes, *, schema_id: str) -> str: ...

    def load(self, digest: str) -> bytes: ...


def marginal_contributions(result: ExperimentResult) -> tuple[MarginalContribution, ...]:
    """Extract one contribution record per ablation arm, in declaration order.

    Raises:
        MarginalContributionError: an ablation arm has no comparison in the
            result — the run is missing evidence the preregistration is
            owed, and a silently shorter record set would hide it.
    """
    records: list[MarginalContribution] = []
    for arm in result.experiment.ablation_arms:
        comparison = result.delta.get(arm.id)
        if comparison is None:
            raise MarginalContributionError(
                f"ablation arm {arm.id!r} (component {arm.component_id!r}) has no "
                "comparison in the experiment result"
            )
        records.append(
            MarginalContribution(
                component_id=arm.component_id or "",
                arm_id=arm.id,
                observed_delta=comparison.bootstrap.observed_delta,
                ci_low=comparison.bootstrap.ci_low,
                ci_high=comparison.bootstrap.ci_high,
                adjusted_p_value=comparison.adjusted_p_value,
                verdict=comparison.verdict.value,
            )
        )
    return tuple(records)


def persist_contributions(
    contributions: tuple[MarginalContribution, ...], store: ContributionStore
) -> str:
    """Serialize contribution records to canonical JSON and checkpoint them.

    Returns:
        The content digest the record set is stored under — the handle a
        later reader loads it by, verified against the bytes on the way out.
    """
    payload = {
        "schema_id": CONTRIBUTIONS_SCHEMA_ID,
        "contributions": [record.to_canonical_dict() for record in contributions],
    }
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return store.store(data, schema_id=CONTRIBUTIONS_SCHEMA_ID)


def load_contributions(store: ContributionStore, digest: str) -> tuple[MarginalContribution, ...]:
    """Load and verify a contribution record set by its content digest.

    The digest is checked against the loaded bytes before anything is
    parsed — the same integrity half the campaign orchestrator's
    `reconstruct` applies (FR-005): a record set that does not hash to its
    own address is refused, not resumed.

    Raises:
        MarginalContributionError: the digest does not match the stored
            bytes, or the payload is malformed.
        KeyError: no record set is stored under this digest.
    """
    data = store.load(digest)
    actual = _DIGEST_PREFIX + hashlib.sha256(data).hexdigest()
    if actual != digest:
        raise MarginalContributionError(
            f"contribution record set {digest} does not hash to its content address "
            f"(stored bytes hash to {actual})"
        )
    try:
        payload = json.loads(data)
    except (ValueError, UnicodeDecodeError) as exc:
        raise MarginalContributionError(f"contribution bytes are not valid JSON: {exc}") from exc
    if not isinstance(payload, dict) or "contributions" not in payload:
        raise MarginalContributionError("contribution payload is missing 'contributions'")
    if payload.get("schema_id") != CONTRIBUTIONS_SCHEMA_ID:
        raise MarginalContributionError(
            f"contribution payload has unknown schema_id {payload.get('schema_id')!r} "
            f"(expected {CONTRIBUTIONS_SCHEMA_ID!r})"
        )
    entries = payload["contributions"]
    if not isinstance(entries, list):
        raise MarginalContributionError("contribution payload 'contributions' must be a list")
    return tuple(
        MarginalContribution.from_canonical_dict(entry)
        for entry in entries
        if isinstance(entry, dict)
    )


__all__ = [
    "CONTRIBUTIONS_SCHEMA_ID",
    "ContributionStore",
    "MarginalContribution",
    "load_contributions",
    "marginal_contributions",
    "persist_contributions",
]

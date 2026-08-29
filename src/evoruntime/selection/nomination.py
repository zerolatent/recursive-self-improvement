"""The trusted selector (PRD §11.1.6, §12.5): nominate and freeze.


Two properties carry the whole module, and both are easy to get wrong:

**The selector is trusted; the strategy is not.** The nomination rule is
applied by this service — never by the strategy plugin — on the *selection*
partition, which is read repeatedly and therefore never gates promotion
alone. The strategy never sees selection or holdout results; it proposes,
and the selector disposes.

**Freeze is a one-way door.** The selector freezes exactly one nominee per
arm, records the freeze as E1 registry status events (append-only, so the
freeze record itself cannot be rewritten), and from that moment the
strategy's edit rights are gone: every post-freeze edit attempt is refused
with :class:`AlreadyFrozenError`, not recorded. Immutability of the nominee
*bytes* comes from content addressing (an edit produces a new digest); the
immutability of the *nomination* comes from this refusal plus the
append-only event log.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Protocol

from evoruntime.core.metrics import COST_METRIC_KEYS
from evoruntime.registry.service import RegistryService
from evoruntime.selection.errors import AlreadyFrozenError, NominationRuleError

#: The E1 status-event kinds the selector writes at freeze. Both are members
#: of the registry's six-kind set, so a nomination is a first-class registry
#: lifecycle event — auditable by the same machinery as every other status.
NOMINATE_EVENT_KIND = "nominate"
REJECT_EVENT_KIND = "reject"

_SELECTOR_ACTOR = "trusted-selector"

#: The closed nomination-metric namespace (FR-102, locked decision 6).
#: Exactly two metrics are preregistered; the namespace is closed at spec
#: pin, so post-hoc metric injection remains impossible — adding a metric
#: is a code change to this tuple, reviewed as a spec change, never a
#: runtime value a strategy can supply.
NOMINATION_METRICS: tuple[str, ...] = ("selection_score", "productivity_score")

#: The cost normalizations preregistered for the productivity metric.
#: Only 'arm_max' is defined: a candidate's cost is divided by the largest
#: attested cost in its arm, mapping every cost into (0, 1] with the
#: arm's most expensive candidate at 1. The selector computes it from the
#: observations themselves — deterministic, and never a strategy input.
COST_NORMALIZATIONS: tuple[str, ...] = ("arm_max",)


@dataclass(frozen=True, slots=True)
class NominationRule:
    """The preregistered nomination rule (part of the campaign spec).

    Chosen before any selection data exists: which metric ranks the
    candidates, the floor a nominee must clear, and the deterministic
    tiebreak. A rule chosen after seeing the scores is not a rule, it is a
    rationalization.
    """

    metric: str = "selection_score"
    """Name of the observation field the rule ranks by. One of the closed
    `NOMINATION_METRICS` namespace, pinned at spec time."""

    min_score: float = 0.0
    """Inclusive floor: a candidate below it is never nominated, even if
    it is the arm's best. The floor applies to `selection_score` — the
    quality metric — under both rules; the productivity rule ranks only
    candidates that already clear it."""

    tiebreak: str = "lowest_digest"
    """Deterministic tiebreak for equal scores. Only 'lowest_digest' is
    defined; anything else is a construction error so two runs of the same
    rule can never disagree."""

    cost_metric: str = "total_tokens"
    """Which attested cost the productivity rule divides by. Must be a
    member of the closed COST_METRIC_KEYS vocabulary — an unregistered
    cost metric is a construction error, so the cost normalization is
    pinned at spec time together with the metric itself."""

    cost_normalization: str = "arm_max"
    """How the pinned cost is normalized. Only 'arm_max' is preregistered;
    anything else is a construction error (a normalization chosen after
    seeing the costs is the same post-hoc move as a metric chosen after
    seeing the scores)."""

    def __post_init__(self) -> None:
        if self.metric not in NOMINATION_METRICS:
            raise NominationRuleError(
                f"unknown nomination metric {self.metric!r} — the namespace is "
                f"closed at spec pin to {', '.join(NOMINATION_METRICS)}; post-hoc "
                "metric injection is impossible by construction"
            )
        if self.tiebreak != "lowest_digest":
            raise NominationRuleError(
                f"unknown tiebreak {self.tiebreak!r} — only 'lowest_digest' is "
                "preregistered (a nondeterministic tiebreak is a post-hoc choice)"
            )
        if not 0.0 <= self.min_score <= 1.0:
            raise NominationRuleError(f"min_score must be in [0, 1], got {self.min_score!r}")
        if self.cost_metric not in COST_METRIC_KEYS:
            raise NominationRuleError(
                f"unknown cost metric {self.cost_metric!r} — cost normalization is "
                "pinned to the COST_METRIC_KEYS vocabulary at spec time"
            )
        if self.cost_normalization not in COST_NORMALIZATIONS:
            raise NominationRuleError(
                f"unknown cost normalization {self.cost_normalization!r} — only "
                f"{', '.join(COST_NORMALIZATIONS)} is preregistered"
            )

    def to_canonical_dict(self) -> dict[str, object]:
        """Canonical JSON form of the rule (feeds the freeze digest)."""
        return {
            "metric": self.metric,
            "min_score": self.min_score,
            "tiebreak": self.tiebreak,
            "cost_metric": self.cost_metric,
            "cost_normalization": self.cost_normalization,
        }


@dataclass(frozen=True, slots=True)
class SelectionObservation:
    """One candidate's result on the selection partition.

    `candidate_digest` is the content digest of the candidate's artifact
    bytes — the same digest the E1 registry knows, so a nomination points
    at immutable content by construction.
    """

    arm_id: str
    candidate_digest: str
    selection_score: float
    cost_metrics: Mapping[str, float] = MappingProxyType({})
    """Attested cost metrics for the candidate (FR-102). Keys must be
    members of the closed COST_METRIC_KEYS vocabulary — an unregistered
    cost key is a construction error, so a cost shape the spec never
    pinned cannot ride in through an observation. The productivity rule
    requires the rule's pinned cost metric to be attested and positive;
    the selection_score rule ignores these."""

    def __post_init__(self) -> None:
        if not self.arm_id:
            raise NominationRuleError("arm_id must be non-empty")
        if not self.candidate_digest.startswith("sha256:"):
            raise NominationRuleError(
                f"candidate_digest must be a sha256 digest, got {self.candidate_digest!r}"
            )
        if not 0.0 <= self.selection_score <= 1.0:
            raise NominationRuleError(
                f"selection_score must be in [0, 1], got {self.selection_score!r}"
            )
        unknown = set(self.cost_metrics) - COST_METRIC_KEYS
        if unknown:
            raise NominationRuleError(
                f"unregistered cost metric(s) {sorted(unknown)} — cost_metrics is "
                "closed to the COST_METRIC_KEYS vocabulary at spec time"
            )
        for key, value in self.cost_metrics.items():
            if not math.isfinite(value) or value < 0.0:
                raise NominationRuleError(
                    f"cost metric {key!r} must be a finite non-negative number, got {value!r}"
                )
        object.__setattr__(self, "cost_metrics", MappingProxyType(dict(self.cost_metrics)))


@dataclass(frozen=True, slots=True)
class NominationEvent:
    """One append-only nomination-ledger record.

    Mirrors the E1 artifact status event (kind, digest, actor, reason) so
    the in-memory ledger and the registry-backed ledger are the same
    contract, and the freeze record is auditable in either.
    """

    arm_id: str
    artifact_digest: str
    kind: str
    actor_identity: str
    reason: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in (NOMINATE_EVENT_KIND, REJECT_EVENT_KIND):
            raise NominationRuleError(
                f"nomination event kind {self.kind!r} must be "
                f"{NOMINATE_EVENT_KIND!r} or {REJECT_EVENT_KIND!r}"
            )


class NominationLedger(Protocol):
    """Append-only nomination record. There is no update or delete path."""

    def append(self, event: NominationEvent) -> None: ...

    def events(self) -> tuple[NominationEvent, ...]: ...


class InMemoryNominationLedger:
    """In-process append-only ledger — the test harness's stand-in for the
    E1 registry's status-event log. Same contract, same refusal to rewrite."""

    def __init__(self) -> None:
        self._events: list[NominationEvent] = []

    def append(self, event: NominationEvent) -> None:
        self._events.append(event)

    def events(self) -> tuple[NominationEvent, ...]:
        return tuple(self._events)


class RegistryNominationLedger:
    """Writes nominations as E1 artifact status events.

    This is the production ledger: a freeze recorded here is an append-only
    registry row, visible to the same projection and audit machinery as
    every other artifact lifecycle event — which is what makes post-freeze
    immutability *enforced* rather than merely promised.
    """

    def __init__(self, registry: RegistryService, tenant_id: str) -> None:
        self._registry = registry
        self._tenant_id = tenant_id

    def append(self, event: NominationEvent) -> None:
        self._registry.append_status_event(
            tenant_id=self._tenant_id,
            artifact_digest=event.artifact_digest,
            kind=event.kind,
            actor_identity=event.actor_identity,
            reason=event.reason,
        )

    def events(self) -> tuple[NominationEvent, ...]:
        rows = self._registry.list_status_events(tenant_id=self._tenant_id)
        return tuple(
            NominationEvent(
                arm_id=_arm_from_reason(row.reason),
                artifact_digest=str(row.artifact_digest),
                kind=str(row.kind),
                actor_identity=str(row.actor_identity),
                reason=row.reason,
            )
            for row in rows
            if row.kind in (NOMINATE_EVENT_KIND, REJECT_EVENT_KIND)
        )


def _arm_from_reason(reason: str | None) -> str:
    """Recover the arm id from the event reason ('arm=<id>' written at freeze)."""
    if reason and reason.startswith("arm="):
        return reason.removeprefix("arm=").split(";", 1)[0]
    return ""


@dataclass(frozen=True, slots=True)
class FrozenNominees:
    """The freeze record: exactly one nominee digest per arm.

    `digest` is computed over the canonical form of the record, so any
    disagreement about what was frozen is detectable by comparing digests.
    """

    campaign_id: str
    rule: NominationRule
    nominees: Mapping[str, str]
    actor_identity: str
    _freeze_digest: str = field(repr=False)

    @property
    def digest(self) -> str:
        """Content digest of the freeze record (`sha256:...`)."""
        return self._freeze_digest

    def nominee_for(self, arm_id: str) -> str:
        """The frozen nominee digest for one arm, or a fail-closed error."""
        try:
            return self.nominees[arm_id]
        except KeyError:
            raise NominationRuleError(
                f"no frozen nominee for arm {arm_id!r} — the freeze record does not cover this arm"
            ) from None


def attested_cost(observation: SelectionObservation, cost_metric: str) -> float | None:
    """The observation's attested value for `cost_metric`, or None when the
    metric was not attested or attested at zero — a zero cost would make
    value-per-cost infinite, so a zero-cost candidate is not rankable.
    Pure."""
    cost = observation.cost_metrics.get(cost_metric)
    if cost is None or cost <= 0.0:
        return None
    return cost


def productivity_value(selection_score: float, cost: float, arm_max_cost: float) -> float:
    """The preregistered productivity score (FR-102): selection score per
    unit of normalized cost. `arm_max_cost` is the largest attested cost in
    the arm, so the normalized cost `cost / arm_max_cost` lies in (0, 1]
    and the arm's cheapest candidate earns the largest divisor benefit.
    Pure: the selector computes it, never the strategy."""
    return selection_score / (cost / arm_max_cost)


class TrustedSelector:
    """Applies the preregistered nomination rule and freezes one nominee
    per arm. The only writer of the nomination ledger, and the only path
    through which a strategy's edit can ever take effect — a path that is
    closed at freeze."""

    def __init__(
        self,
        rule: NominationRule,
        ledger: NominationLedger,
        *,
        campaign_id: str,
        actor_identity: str = _SELECTOR_ACTOR,
    ) -> None:
        self._rule = rule
        self._ledger = ledger
        self._campaign_id = campaign_id
        self._actor = actor_identity

    # -- freeze --------------------------------------------------------------

    def freeze(self, observations: Sequence[SelectionObservation]) -> FrozenNominees:
        """Apply the rule and freeze exactly one nominee per arm.

        Idempotent it is not: a second freeze is an edit of a frozen
        decision and raises :class:`AlreadyFrozenError`. Losers get
        ``reject`` events so the ledger records what was considered and
        why it lost.
        """
        frozen = self.frozen()
        if frozen is not None:
            raise AlreadyFrozenError(sorted(frozen.nominees)[0], "re-freeze")

        by_arm: dict[str, list[SelectionObservation]] = {}
        for observation in observations:
            by_arm.setdefault(observation.arm_id, []).append(observation)
        if not by_arm:
            raise NominationRuleError("no selection observations — nothing to nominate")

        nominees: dict[str, str] = {}
        for arm_id in sorted(by_arm):
            nominees[arm_id] = self._nominate(arm_id, by_arm[arm_id])

        for arm_id in sorted(nominees):
            self._ledger.append(
                NominationEvent(
                    arm_id=arm_id,
                    artifact_digest=nominees[arm_id],
                    kind=NOMINATE_EVENT_KIND,
                    actor_identity=self._actor,
                    reason=f"arm={arm_id};rule={self._rule.metric}",
                )
            )
            for loser in sorted(by_arm[arm_id], key=lambda o: o.candidate_digest):
                if loser.candidate_digest != nominees[arm_id]:
                    self._ledger.append(
                        NominationEvent(
                            arm_id=arm_id,
                            artifact_digest=loser.candidate_digest,
                            kind=REJECT_EVENT_KIND,
                            actor_identity=self._actor,
                            reason=f"arm={arm_id};score={loser.selection_score!r}",
                        )
                    )

        return FrozenNominees(
            campaign_id=self._campaign_id,
            rule=self._rule,
            nominees=MappingProxyType(dict(nominees)),
            actor_identity=self._actor,
            _freeze_digest=self._freeze_digest(nominees),
        )

    def frozen(self) -> FrozenNominees | None:
        """The current freeze state, projected from the append-only ledger.

        None means no arm is frozen yet. The projection follows the latest
        ``nominate`` event per arm — the same discipline as the E1 status
        projection, so the freeze state is derived from the record, never
        from mutable memory.
        """
        nominees: dict[str, str] = {}
        for event in self._ledger.events():
            if event.kind == NOMINATE_EVENT_KIND and event.arm_id:
                nominees[event.arm_id] = event.artifact_digest
        if not nominees:
            return None
        return FrozenNominees(
            campaign_id=self._campaign_id,
            rule=self._rule,
            nominees=MappingProxyType(dict(nominees)),
            actor_identity=self._actor,
            _freeze_digest=self._freeze_digest(nominees),
        )

    # -- the strategy's edit path ---------------------------------------------

    def apply_strategy_edit(self, arm_id: str, new_digest: str) -> SelectionObservation:
        """The only path a strategy's proposed edit can take — closed at freeze.

        Before freeze, an edit is just a new observation for the rule to
        rank. After freeze it is refused: the strategy lost edit rights at
        freeze, and the refusal is the enforcement.
        """
        frozen = self.frozen()
        if frozen is not None and arm_id in frozen.nominees:
            raise AlreadyFrozenError(arm_id, f"strategy edit to {new_digest!r}")
        return SelectionObservation(arm_id=arm_id, candidate_digest=new_digest, selection_score=0.0)

    # -- internals -------------------------------------------------------------

    def _nominate(self, arm_id: str, candidates: list[SelectionObservation]) -> str:
        """The preregistered rule: best metric value above the floor,
        deterministic tiebreak. Exactly one nominee; an arm with no
        eligible candidate fails closed rather than nominating a guess."""
        eligible = [c for c in candidates if c.selection_score >= self._rule.min_score]
        if not eligible:
            raise NominationRuleError(
                f"arm {arm_id!r} has no candidate at or above min_score "
                f"{self._rule.min_score!r} — refusing to nominate a guess"
            )
        if self._rule.metric == "productivity_score":
            ranked = self._rank_by_productivity(arm_id, eligible)
        else:
            best = max(c.selection_score for c in eligible)
            ranked = [c for c in eligible if c.selection_score == best]
        tied = sorted(ranked, key=lambda c: c.candidate_digest)
        return tied[0].candidate_digest

    def _rank_by_productivity(
        self, arm_id: str, eligible: list[SelectionObservation]
    ) -> list[SelectionObservation]:
        """Best value-per-cost under the preregistered normalization.

        A candidate without a positive attested cost for the rule's pinned
        cost metric cannot be priced and is not rankable; an arm where
        nothing is priceable fails closed."""
        costs: dict[str, float] = {}
        for candidate in eligible:
            cost = attested_cost(candidate, self._rule.cost_metric)
            if cost is not None:
                costs[candidate.candidate_digest] = cost
        if not costs:
            raise NominationRuleError(
                f"arm {arm_id!r} has no candidate with a positive attested "
                f"{self._rule.cost_metric!r} cost — the productivity rule "
                "refuses to rank a candidate it cannot price"
            )
        priced = [c for c in eligible if c.candidate_digest in costs]
        arm_max_cost = max(costs.values())
        values = {
            c.candidate_digest: productivity_value(
                c.selection_score, costs[c.candidate_digest], arm_max_cost
            )
            for c in priced
        }
        best = max(values.values())
        return [c for c in priced if values[c.candidate_digest] == best]

    def _freeze_digest(self, nominees: Mapping[str, str]) -> str:
        payload = json.dumps(
            {
                "campaign_id": self._campaign_id,
                "rule": self._rule.to_canonical_dict(),
                "nominees": {arm: nominees[arm] for arm in sorted(nominees)},
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(payload).hexdigest()


__all__ = [
    "COST_NORMALIZATIONS",
    "NOMINATION_METRICS",
    "NOMINATE_EVENT_KIND",
    "REJECT_EVENT_KIND",
    "FrozenNominees",
    "InMemoryNominationLedger",
    "NominationEvent",
    "NominationLedger",
    "NominationRule",
    "RegistryNominationLedger",
    "attested_cost",
    "productivity_value",
    "SelectionObservation",
    "TrustedSelector",
]

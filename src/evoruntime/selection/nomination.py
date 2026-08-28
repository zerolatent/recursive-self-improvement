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
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Protocol

from evoruntime.registry.service import RegistryService
from evoruntime.selection.errors import AlreadyFrozenError, NominationRuleError

#: The E1 status-event kinds the selector writes at freeze. Both are members
#: of the registry's six-kind set, so a nomination is a first-class registry
#: lifecycle event — auditable by the same machinery as every other status.
NOMINATE_EVENT_KIND = "nominate"
REJECT_EVENT_KIND = "reject"

_SELECTOR_ACTOR = "trusted-selector"


@dataclass(frozen=True, slots=True)
class NominationRule:
    """The preregistered nomination rule (part of the campaign spec).

    Chosen before any selection data exists: which metric ranks the
    candidates, the floor a nominee must clear, and the deterministic
    tiebreak. A rule chosen after seeing the scores is not a rule, it is a
    rationalization.
    """

    metric: str = "selection_score"
    """Name of the observation field the rule ranks by."""

    min_score: float = 0.0
    """Inclusive floor: a candidate below it is never nominated, even if
    it is the arm's best."""

    tiebreak: str = "lowest_digest"
    """Deterministic tiebreak for equal scores. Only 'lowest_digest' is
    defined; anything else is a construction error so two runs of the same
    rule can never disagree."""

    def __post_init__(self) -> None:
        if self.metric != "selection_score":
            raise NominationRuleError(
                f"unknown nomination metric {self.metric!r} — the rule must name "
                "a field of SelectionObservation"
            )
        if self.tiebreak != "lowest_digest":
            raise NominationRuleError(
                f"unknown tiebreak {self.tiebreak!r} — only 'lowest_digest' is "
                "preregistered (a nondeterministic tiebreak is a post-hoc choice)"
            )
        if not 0.0 <= self.min_score <= 1.0:
            raise NominationRuleError(f"min_score must be in [0, 1], got {self.min_score!r}")

    def to_canonical_dict(self) -> dict[str, object]:
        """Canonical JSON form of the rule (feeds the freeze digest)."""
        return {
            "metric": self.metric,
            "min_score": self.min_score,
            "tiebreak": self.tiebreak,
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
        """The preregistered rule: best score above the floor, deterministic
        tiebreak. Exactly one nominee; an arm with no eligible candidate
        fails closed rather than nominating a guess."""
        eligible = [c for c in candidates if c.selection_score >= self._rule.min_score]
        if not eligible:
            raise NominationRuleError(
                f"arm {arm_id!r} has no candidate at or above min_score "
                f"{self._rule.min_score!r} — refusing to nominate a guess"
            )
        best = max(c.selection_score for c in eligible)
        tied = sorted(
            (c for c in eligible if c.selection_score == best),
            key=lambda c: c.candidate_digest,
        )
        return tied[0].candidate_digest

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
    "NOMINATE_EVENT_KIND",
    "REJECT_EVENT_KIND",
    "FrozenNominees",
    "InMemoryNominationLedger",
    "NominationEvent",
    "NominationLedger",
    "NominationRule",
    "RegistryNominationLedger",
    "SelectionObservation",
    "TrustedSelector",
]

"""Selector tests (E4): the two-arm freeze, post-freeze immutability, and
the preregistered rule's fail-closed edges."""

from __future__ import annotations

import pytest

from evoruntime.selection import (
    NOMINATE_EVENT_KIND,
    REJECT_EVENT_KIND,
    AlreadyFrozenError,
    FrozenNominees,
    InMemoryNominationLedger,
    NominationRule,
    NominationRuleError,
    SelectionObservation,
    TrustedSelector,
)

ARM_A = "arm-incumbent"
ARM_B = "arm-candidate"

DIGEST_A1 = "sha256:" + "a1" * 32
DIGEST_A2 = "sha256:" + "a2" * 32
DIGEST_B1 = "sha256:" + "b1" * 32
DIGEST_B2 = "sha256:" + "b2" * 32


def _observation(arm_id: str, digest: str, score: float) -> SelectionObservation:
    return SelectionObservation(arm_id=arm_id, candidate_digest=digest, selection_score=score)


def _selector(min_score: float = 0.0) -> TrustedSelector:
    return TrustedSelector(
        NominationRule(min_score=min_score),
        InMemoryNominationLedger(),
        campaign_id="campaign-e4",
    )


class TestTwoArmFreeze:
    """The FR-011 selector contract: exactly one nominee per arm."""

    def test_freezes_exactly_one_nominee_per_arm(self) -> None:
        selector = _selector()
        frozen = selector.freeze(
            [
                _observation(ARM_A, DIGEST_A1, 0.9),
                _observation(ARM_A, DIGEST_A2, 0.7),
                _observation(ARM_B, DIGEST_B1, 0.6),
                _observation(ARM_B, DIGEST_B2, 0.8),
            ]
        )

        assert frozen.nominee_for(ARM_A) == DIGEST_A1
        assert frozen.nominee_for(ARM_B) == DIGEST_B2
        assert set(frozen.nominees) == {ARM_A, ARM_B}

    def test_losers_get_reject_events_in_the_ledger(self) -> None:
        selector = _selector()
        frozen = selector.freeze(
            [
                _observation(ARM_A, DIGEST_A1, 0.9),
                _observation(ARM_A, DIGEST_A2, 0.7),
            ]
        )

        assert frozen.nominee_for(ARM_A) == DIGEST_A1
        events = selector._ledger.events()  # noqa: SLF001
        assert sorted(e.kind for e in events) == [NOMINATE_EVENT_KIND, REJECT_EVENT_KIND]
        nominate = next(e for e in events if e.kind == NOMINATE_EVENT_KIND)
        assert nominate.artifact_digest == DIGEST_A1
        assert nominate.reason == f"arm={ARM_A};rule=selection_score"

    def test_freeze_digest_is_deterministic(self) -> None:
        observations = [
            _observation(ARM_A, DIGEST_A1, 0.9),
            _observation(ARM_B, DIGEST_B2, 0.8),
        ]
        first = _selector().freeze(observations)
        second = _selector().freeze(observations)
        assert first.digest == second.digest
        assert first.digest.startswith("sha256:")

    def test_tiebreak_is_lowest_digest(self) -> None:
        selector = _selector()
        frozen = selector.freeze(
            [
                _observation(ARM_A, DIGEST_A2, 0.9),
                _observation(ARM_A, DIGEST_A1, 0.9),
            ]
        )
        assert frozen.nominee_for(ARM_A) == DIGEST_A1

    def test_min_score_floor_excludes_a_high_scoring_arm(self) -> None:
        selector = _selector(min_score=0.5)
        with pytest.raises(NominationRuleError, match="no candidate at or above min_score"):
            selector.freeze([_observation(ARM_A, DIGEST_A1, 0.4)])

    def test_freeze_without_observations_fails_closed(self) -> None:
        with pytest.raises(NominationRuleError, match="nothing to nominate"):
            _selector().freeze([])

    def test_nominee_for_unknown_arm_fails_closed(self) -> None:
        frozen = _selector().freeze([_observation(ARM_A, DIGEST_A1, 0.9)])
        with pytest.raises(NominationRuleError, match="does not cover this arm"):
            frozen.nominee_for("arm-never-seen")


class TestPostFreezeImmutability:
    """The strategy loses edit rights at freeze — the refusal is the enforcement."""

    def test_second_freeze_is_refused(self) -> None:
        selector = _selector()
        selector.freeze([_observation(ARM_A, DIGEST_A1, 0.9)])
        with pytest.raises(AlreadyFrozenError, match="re-freeze"):
            selector.freeze([_observation(ARM_A, DIGEST_A2, 0.99)])

    def test_strategy_edit_after_freeze_is_refused(self) -> None:
        selector = _selector()
        selector.freeze([_observation(ARM_A, DIGEST_A1, 0.9)])
        with pytest.raises(AlreadyFrozenError, match="strategy edit"):
            selector.apply_strategy_edit(ARM_A, DIGEST_A2)

    def test_strategy_edit_before_freeze_is_a_new_observation(self) -> None:
        selector = _selector()
        observation = selector.apply_strategy_edit(ARM_A, DIGEST_A2)
        assert observation.candidate_digest == DIGEST_A2
        assert selector.frozen() is None

    def test_frozen_state_is_projected_from_the_ledger_not_memory(self) -> None:
        """A fresh selector over the same ledger sees the same freeze."""
        ledger = InMemoryNominationLedger()
        first = TrustedSelector(NominationRule(), ledger, campaign_id="campaign-e4")
        frozen = first.freeze([_observation(ARM_A, DIGEST_A1, 0.9)])

        second = TrustedSelector(NominationRule(), ledger, campaign_id="campaign-e4")
        projected = second.frozen()
        assert projected is not None
        assert projected.nominee_for(ARM_A) == DIGEST_A1
        assert projected.digest == frozen.digest
        with pytest.raises(AlreadyFrozenError):
            second.freeze([_observation(ARM_A, DIGEST_A2, 0.99)])


class TestRuleValidation:
    """A rule chosen after the fact is a rationalization — construction refuses it."""

    def test_unknown_metric_refused(self) -> None:
        with pytest.raises(NominationRuleError, match="unknown nomination metric"):
            NominationRule(metric="post_hoc_vibes")  # type: ignore[arg-type]

    def test_nondeterministic_tiebreak_refused(self) -> None:
        with pytest.raises(NominationRuleError, match="only 'lowest_digest'"):
            NominationRule(tiebreak="random")  # type: ignore[arg-type]

    def test_frozen_nominees_type_is_immutable(self) -> None:
        frozen: FrozenNominees = _selector().freeze([_observation(ARM_A, DIGEST_A1, 0.9)])
        with pytest.raises(TypeError, match="not support item assignment"):
            frozen.nominees[ARM_A] = DIGEST_A2  # type: ignore[index]

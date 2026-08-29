"""FR-102 selector tests: the closed metric namespace, the productivity
rule's value-per-cost ranking, and the fail-closed cost edges."""

from __future__ import annotations

import pytest

from evoruntime.core.metrics import COST_METRIC_KEYS
from evoruntime.selection import (
    COST_NORMALIZATIONS,
    NOMINATION_METRICS,
    AlreadyFrozenError,
    InMemoryNominationLedger,
    NominationRule,
    NominationRuleError,
    SelectionObservation,
    TrustedSelector,
    attested_cost,
    productivity_value,
)

ARM = "arm-candidate"

DIGEST_CHEAP = "sha256:" + "c1" * 32
DIGEST_PROFLIGATE = "sha256:" + "p1" * 32
DIGEST_UNPRICED = "sha256:" + "u1" * 32


def _observation(
    digest: str,
    score: float,
    cost_metrics: dict[str, float] | None = None,
    arm_id: str = ARM,
) -> SelectionObservation:
    return SelectionObservation(
        arm_id=arm_id,
        candidate_digest=digest,
        selection_score=score,
        cost_metrics=cost_metrics or {},
    )


def _productivity_selector(min_score: float = 0.0) -> TrustedSelector:
    return TrustedSelector(
        NominationRule(metric="productivity_score", min_score=min_score),
        InMemoryNominationLedger(),
        campaign_id="campaign-f9",
    )


class TestNamespaceClosure:
    """The metric namespace is closed at spec pin — post-hoc injection is
    impossible by construction, not by discipline."""

    def test_namespace_is_exactly_the_two_preregistered_metrics(self) -> None:
        assert NOMINATION_METRICS == ("selection_score", "productivity_score")

    def test_unregistered_metric_rejected_at_spec_pin(self) -> None:
        with pytest.raises(NominationRuleError, match="closed at spec pin"):
            NominationRule(metric="pareto_score")  # type: ignore[arg-type]

    def test_cost_metric_cannot_sneak_in_as_a_ranking_metric(self) -> None:
        # A cost metric is not a nomination metric: the namespaces are
        # closed independently, so "rank by tokens" is not expressible.
        with pytest.raises(NominationRuleError, match="closed at spec pin"):
            NominationRule(metric="total_tokens")  # type: ignore[arg-type]

    def test_unregistered_cost_metric_rejected_at_spec_pin(self) -> None:
        with pytest.raises(NominationRuleError, match="COST_METRIC_KEYS"):
            NominationRule(metric="productivity_score", cost_metric="gpu_hours")

    def test_unregistered_cost_normalization_rejected(self) -> None:
        with pytest.raises(NominationRuleError, match="normalization"):
            NominationRule(metric="productivity_score", cost_normalization="median")

    def test_only_arm_max_normalization_is_preregistered(self) -> None:
        assert COST_NORMALIZATIONS == ("arm_max",)

    def test_rule_is_frozen_so_a_pinned_metric_cannot_be_mutated(self) -> None:
        rule = NominationRule()
        with pytest.raises(AttributeError):
            rule.metric = "productivity_score"  # type: ignore[misc]

    def test_pinned_rule_names_enter_the_freeze_digest(self) -> None:
        # The canonical form the freeze digest covers carries the full pin,
        # so two rules differing only in cost_metric cannot freeze alike.
        plain = NominationRule().to_canonical_dict()
        priced = NominationRule(metric="productivity_score").to_canonical_dict()
        assert plain["metric"] == "selection_score"
        assert priced["metric"] == "productivity_score"
        assert priced["cost_metric"] == "total_tokens"
        assert priced["cost_normalization"] == "arm_max"


class TestObservationCostMetrics:
    """SelectionObservation carries attested costs from the closed
    vocabulary only."""

    def test_unregistered_cost_key_rejected(self) -> None:
        with pytest.raises(NominationRuleError, match="unregistered cost metric"):
            _observation(DIGEST_CHEAP, 0.9, {"gpu_hours": 3.0})

    def test_negative_cost_rejected(self) -> None:
        with pytest.raises(NominationRuleError, match="finite non-negative"):
            _observation(DIGEST_CHEAP, 0.9, {"total_tokens": -1.0})

    def test_non_finite_cost_rejected(self) -> None:
        with pytest.raises(NominationRuleError, match="finite non-negative"):
            _observation(DIGEST_CHEAP, 0.9, {"total_tokens": float("inf")})

    def test_registered_cost_keys_accepted_and_frozen(self) -> None:
        observation = _observation(DIGEST_CHEAP, 0.9, {"total_tokens": 100.0})
        assert observation.cost_metrics["total_tokens"] == 100.0
        with pytest.raises(TypeError):
            observation.cost_metrics["total_tokens"] = 1.0  # type: ignore[index]

    def test_attested_cost_helper_treats_zero_as_unpriced(self) -> None:
        observation = _observation(DIGEST_CHEAP, 0.9, {"total_tokens": 0.0})
        assert attested_cost(observation, "total_tokens") is None
        priced = _observation(DIGEST_CHEAP, 0.9, {"total_tokens": 5.0})
        assert attested_cost(priced, "total_tokens") == 5.0


class TestProductivityRule:
    """The productivity rule selects best value-per-cost."""

    def test_equal_scores_cheaper_candidate_wins(self) -> None:
        selector = _productivity_selector()
        frozen = selector.freeze(
            [
                _observation(DIGEST_PROFLIGATE, 0.8, {"total_tokens": 1000.0}),
                _observation(DIGEST_CHEAP, 0.8, {"total_tokens": 100.0}),
            ]
        )
        assert frozen.nominee_for(ARM) == DIGEST_CHEAP

    def test_higher_score_does_not_outweigh_profligate_cost(self) -> None:
        # 0.9 quality at 10x the cost loses to 0.8 quality at 1x: the rule
        # ranks value-per-cost, not raw quality.
        selector = _productivity_selector()
        frozen = selector.freeze(
            [
                _observation(DIGEST_PROFLIGATE, 0.9, {"total_tokens": 10000.0}),
                _observation(DIGEST_CHEAP, 0.8, {"total_tokens": 1000.0}),
            ]
        )
        assert frozen.nominee_for(ARM) == DIGEST_CHEAP

    def test_min_score_floor_applies_to_selection_score(self) -> None:
        # The cheapest candidate is worthless if its quality is below the
        # floor: the floor gates on the quality metric under both rules.
        selector = _productivity_selector(min_score=0.5)
        frozen = selector.freeze(
            [
                _observation(DIGEST_CHEAP, 0.4, {"total_tokens": 1.0}),
                _observation(DIGEST_PROFLIGATE, 0.6, {"total_tokens": 100.0}),
            ]
        )
        assert frozen.nominee_for(ARM) == DIGEST_PROFLIGATE

    def test_unpriced_candidate_is_not_rankable(self) -> None:
        selector = _productivity_selector()
        frozen = selector.freeze(
            [
                _observation(DIGEST_UNPRICED, 0.99),
                _observation(DIGEST_CHEAP, 0.5, {"total_tokens": 10.0}),
            ]
        )
        assert frozen.nominee_for(ARM) == DIGEST_CHEAP

    def test_arm_with_no_priceable_candidate_fails_closed(self) -> None:
        selector = _productivity_selector()
        with pytest.raises(NominationRuleError, match="cannot price"):
            selector.freeze([_observation(DIGEST_UNPRICED, 0.9)])

    def test_productivity_value_matches_preregistered_formula(self) -> None:
        # selection_score / (cost / arm_max_cost): the arm's most expensive
        # candidate keeps its raw score; a 10x-cheaper candidate gets 10x
        # its score as productivity.
        assert productivity_value(0.8, 1000.0, 1000.0) == 0.8
        assert productivity_value(0.8, 100.0, 1000.0) == 8.0

    def test_selection_score_rule_ignores_cost_metrics(self) -> None:
        selector = TrustedSelector(
            NominationRule(), InMemoryNominationLedger(), campaign_id="campaign-f9"
        )
        frozen = selector.freeze(
            [
                _observation(DIGEST_PROFLIGATE, 0.9, {"total_tokens": 10000.0}),
                _observation(DIGEST_CHEAP, 0.8, {"total_tokens": 1.0}),
            ]
        )
        assert frozen.nominee_for(ARM) == DIGEST_PROFLIGATE

    def test_productivity_freeze_is_still_a_one_way_door(self) -> None:
        selector = _productivity_selector()
        selector.freeze([_observation(DIGEST_CHEAP, 0.8, {"total_tokens": 10.0})])
        with pytest.raises(AlreadyFrozenError):
            selector.freeze([_observation(DIGEST_PROFLIGATE, 0.9, {"total_tokens": 5.0})])


class TestCostVocabularyShared:
    """The selection plane and the API share one closed cost vocabulary."""

    def test_selection_uses_the_core_vocabulary(self) -> None:
        from evoruntime.api.service import COST_METRIC_KEYS as API_COST_METRIC_KEYS

        assert API_COST_METRIC_KEYS is COST_METRIC_KEYS

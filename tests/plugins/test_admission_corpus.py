"""FR-018 admission fixture corpus — every attack class runs through the real gate."""

from __future__ import annotations

import pytest
from fixtures.lib.admission import (
    AdmissionAttackType,
    AdmissionFixtureManifest,
    entries_from_fixture,
    load_admission_fixtures,
)

from evoruntime.plugins.admission import ViolationCode, admit_output

FIXTURES = load_admission_fixtures()


def test_corpus_loads_and_covers_every_rejection_class() -> None:
    categories = {f.category for f in FIXTURES}
    expected = set(AdmissionAttackType)
    assert categories == expected, f"corpus missing: {expected - categories}"
    assert len(FIXTURES) >= len(AdmissionAttackType)


def test_every_fixture_has_a_unique_id() -> None:
    ids = [f.fixture_id for f in FIXTURES]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("fixture", FIXTURES, ids=lambda f: f.fixture_id)
def test_fixture_verdict_matches_expected(fixture: AdmissionFixtureManifest) -> None:
    decision = admit_output(
        entries_from_fixture(fixture),
        declared_executables=frozenset(fixture.declared_executables),
    )
    if fixture.expected == "admit":
        assert decision.admitted is True, f"clean fixture was rejected: {decision.violations}"
        assert decision.violations == ()
        return

    assert decision.admitted is False
    codes = {v.code.value for v in decision.violations}
    assert fixture.expected_violation is not None
    assert fixture.expected_violation in codes, (
        f"{fixture.fixture_id}: expected violation {fixture.expected_violation}, got {codes}"
    )


def test_rejection_fixture_codes_are_valid_violation_codes() -> None:
    valid = {code.value for code in ViolationCode}
    for fixture in FIXTURES:
        if fixture.expected_violation is not None:
            assert fixture.expected_violation in valid

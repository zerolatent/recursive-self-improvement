"""F3 static-analysis fixture corpus — every violation class runs through the real gate."""

from __future__ import annotations

import pytest
from fixtures.lib.static_analysis import (
    StaticAnalysisCategory,
    StaticAnalysisFixtureManifest,
    files_from_fixture,
    load_static_analysis_fixtures,
    masks_from_fixture,
)

from evoruntime.plugins.static_analysis import (
    AnalysisViolationCode,
    Severity,
    analyze_files,
)

FIXTURES = load_static_analysis_fixtures()


def test_corpus_loads_and_covers_every_violation_class() -> None:
    categories = {f.category for f in FIXTURES}
    expected = set(StaticAnalysisCategory)
    assert categories == expected, f"corpus missing: {expected - categories}"
    assert len(FIXTURES) >= len(StaticAnalysisCategory)


def test_every_fixture_has_a_unique_id() -> None:
    ids = [f.fixture_id for f in FIXTURES]
    assert len(ids) == len(set(ids))


def test_every_blocker_class_has_a_block_fixture() -> None:
    """The four named taxonomy classes must each have a rejecting fixture."""
    blocking = {
        f.category
        for f in FIXTURES
        if f.expected == "block" and f.category is not StaticAnalysisCategory.UNPARSEABLE_SOURCE
    }
    for code in (
        AnalysisViolationCode.NETWORK_IMPORT,
        AnalysisViolationCode.SUBPROCESS_SPAWN,
        AnalysisViolationCode.DYNAMIC_EXEC,
        AnalysisViolationCode.MASK_PATH_WRITE,
    ):
        assert StaticAnalysisCategory(code.value) in blocking, f"no block fixture for {code}"


@pytest.mark.parametrize("fixture", FIXTURES, ids=lambda f: f.fixture_id)
def test_fixture_verdict_matches_expected(fixture: StaticAnalysisFixtureManifest) -> None:
    report = analyze_files(
        files_from_fixture(fixture),
        masks=masks_from_fixture(fixture),
        artifact_type="skill_package",
        candidate_digest="sha256:" + "0" * 64,
    )
    if fixture.expected == "pass":
        assert not report.blocked, f"clean fixture was blocked: {report.violations}"
        if fixture.category is StaticAnalysisCategory.CLEAN:
            assert report.violations == ()
        return

    assert report.blocked
    codes = {v.code for v in report.violations}
    assert fixture.expected_violation is not None
    assert AnalysisViolationCode(fixture.expected_violation) in codes, (
        f"{fixture.fixture_id}: expected violation {fixture.expected_violation}, got {codes}"
    )
    # A block verdict must be carried by blocker-severity findings — a
    # warning-only report that happened to trip the code would not reject.
    blocker_codes = {v.code for v in report.violations if v.severity is Severity.BLOCKER}
    assert AnalysisViolationCode(fixture.expected_violation) in blocker_codes


def test_analysis_is_pure_and_deterministic() -> None:
    fixture = next(f for f in FIXTURES if f.category is StaticAnalysisCategory.NETWORK_IMPORT)
    first = analyze_files(
        files_from_fixture(fixture),
        masks=masks_from_fixture(fixture),
        artifact_type="skill_package",
        candidate_digest="sha256:" + "0" * 64,
    )
    second = analyze_files(
        files_from_fixture(fixture),
        masks=masks_from_fixture(fixture),
        artifact_type="skill_package",
        candidate_digest="sha256:" + "0" * 64,
    )
    assert first.canonical_bytes() == second.canonical_bytes()
    assert first.verdict_digest == second.verdict_digest

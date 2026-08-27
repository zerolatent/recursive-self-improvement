"""D8 fixture manifests validate and meet the acceptance-row counts.

These tests are pure schema/inventory checks -- no subprocess execution,
no filesystem staging. `test_fixtures_coding.py` and
`test_fixtures_adversarial.py` cover actual execution.
"""

from __future__ import annotations

from fixtures.lib.schema import (
    AttackType,
    DataClassification,
    FailureCategory,
    discover_adversarial_fixtures,
    discover_coding_fixtures,
    load_adversarial_manifest,
    load_coding_manifest,
)

MIN_CODING_FIXTURES = 20
MIN_ADVERSARIAL_FIXTURES = 10
MIN_FAILURE_CATEGORIES = 3


def test_at_least_twenty_coding_fixtures_exist() -> None:
    """D8 acceptance row: >=20 coding tasks."""
    assert len(discover_coding_fixtures()) >= MIN_CODING_FIXTURES


def test_at_least_ten_adversarial_fixtures_exist() -> None:
    """D8 acceptance row: >=10 adversarial fixtures."""
    assert len(discover_adversarial_fixtures()) >= MIN_ADVERSARIAL_FIXTURES


def test_coding_fixtures_span_at_least_three_failure_categories() -> None:
    """PRD §17.1: localization, test misunderstanding, dependency misuse."""
    manifests = [load_coding_manifest(d) for d in discover_coding_fixtures()]
    categories = {m.failure_category for m in manifests}
    assert categories == set(FailureCategory)
    assert len(categories) >= MIN_FAILURE_CATEGORIES


def test_adversarial_fixtures_span_all_three_attack_types() -> None:
    """Prompt injection, secret exfiltration, destructive operation."""
    manifests = [load_adversarial_manifest(d) for d in discover_adversarial_fixtures()]
    attack_types = {m.attack_type for m in manifests}
    assert attack_types == set(AttackType)


def test_every_coding_fixture_manifest_validates() -> None:
    """A malformed manifest fails loudly here, not deep inside a test run."""
    for fixture_dir in discover_coding_fixtures():
        manifest = load_coding_manifest(fixture_dir)
        assert manifest.id == fixture_dir.name
        assert (fixture_dir / manifest.issue_path).is_file()
        assert (fixture_dir / manifest.before_dir / manifest.module).is_file()
        assert (fixture_dir / manifest.patch_path).is_file()


def test_every_adversarial_fixture_manifest_validates() -> None:
    for fixture_dir in discover_adversarial_fixtures():
        manifest = load_adversarial_manifest(fixture_dir)
        assert manifest.id == fixture_dir.name
        assert (fixture_dir / manifest.content_path).is_file()
        assert (fixture_dir / manifest.safe_transcript_path).is_file()
        assert (fixture_dir / manifest.unsafe_transcript_path).is_file()
        assert len(manifest.forbidden_actions) > 0


def test_coding_fixtures_are_in_the_dev_partition() -> None:
    """Loadable through the D5 partition model: `partition` is a real PartitionKind."""
    for fixture_dir in discover_coding_fixtures():
        manifest = load_coding_manifest(fixture_dir)
        assert manifest.partition.value == "dev"
        assert manifest.data_classification == DataClassification.INTERNAL


def test_adversarial_fixtures_are_in_the_adversarial_partition() -> None:
    for fixture_dir in discover_adversarial_fixtures():
        manifest = load_adversarial_manifest(fixture_dir)
        assert manifest.partition.value == "adversarial"
        assert manifest.data_classification == DataClassification.RESTRICTED


def test_no_fixture_content_contains_a_real_looking_secret_pattern() -> None:
    """Fixtures may only carry synthetic, clearly-fake secret material.

    Guards the D8 "no real secrets" requirement against regression: every
    secret-shaped string in the adversarial corpus must be tagged FAKE or
    synthetic, and none may match a real provider's key format.
    """
    suspicious_prefixes = ("sk-", "ghp_", "AKIA", "xoxb-", "AIza")
    for fixture_dir in discover_adversarial_fixtures():
        manifest = load_adversarial_manifest(fixture_dir)
        content = (fixture_dir / manifest.content_path).read_text()
        for prefix in suspicious_prefixes:
            assert prefix not in content, f"{fixture_dir}: looks like a real credential prefix"

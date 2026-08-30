"""H6 canary eligibility tests: the §17.1 step-8 admission predicate.

Only read-only (tier 1) or transactionally-reversible (tier 2) resolved
classes are canary-eligible — the harness's only undo is the pointer
rollback, so a release whose failure modes a pointer move cannot contain
is refused with a typed error before any canary machinery runs.
"""

from __future__ import annotations

import pytest

from evoruntime.release import CanaryIneligibleError, assert_canary_eligible
from evoruntime.release.eligibility import resolve_canary_eligibility
from evoruntime.selection.authority import ResolvedRelease


class TestEligibleClasses:
    def test_read_only_class_is_eligible(self) -> None:
        eligibility = assert_canary_eligible(ResolvedRelease(artifact_classes=("prompt_bundle",)))

        assert eligibility.eligible
        assert eligibility.ineligible_classes == ()
        assert eligibility.refusals == ()

    def test_transactionally_reversible_class_is_eligible(self) -> None:
        eligibility = assert_canary_eligible(ResolvedRelease(artifact_classes=("memory_entry",)))

        assert eligibility.eligible

    def test_mixed_tier1_tier2_set_is_eligible(self) -> None:
        eligibility = assert_canary_eligible(
            ResolvedRelease(artifact_classes=("prompt_bundle", "skill_package"))
        )

        assert eligibility.eligible


class TestIneligibleClasses:
    def test_tier3_executable_class_is_refused(self) -> None:
        with pytest.raises(CanaryIneligibleError) as refused:
            assert_canary_eligible(ResolvedRelease(artifact_classes=("workflow_graph",)))

        assert refused.value.ineligible_classes == ("workflow_graph",)

    def test_tier4_harness_patch_is_refused(self) -> None:
        with pytest.raises(CanaryIneligibleError) as refused:
            assert_canary_eligible(ResolvedRelease(artifact_classes=("harness_patch",)))

        assert refused.value.ineligible_classes == ("harness_patch",)

    def test_unknown_class_fails_closed(self) -> None:
        with pytest.raises(CanaryIneligibleError) as refused:
            assert_canary_eligible(ResolvedRelease(artifact_classes=("mystery_class",)))

        assert refused.value.ineligible_classes == ("mystery_class",)

    def test_one_bad_class_refuses_the_whole_release(self) -> None:
        with pytest.raises(CanaryIneligibleError) as refused:
            assert_canary_eligible(
                ResolvedRelease(artifact_classes=("prompt_bundle", "skill_script"))
            )

        assert refused.value.ineligible_classes == ("skill_script",)


class TestReleaseLevelRefusals:
    def test_empty_resolved_set_is_refused(self) -> None:
        with pytest.raises(CanaryIneligibleError) as refused:
            assert_canary_eligible(ResolvedRelease(artifact_classes=()))

        assert any("no artifact classes" in r for r in refused.value.refusals)

    def test_non_reversible_release_is_refused(self) -> None:
        with pytest.raises(CanaryIneligibleError) as refused:
            assert_canary_eligible(
                ResolvedRelease(artifact_classes=("prompt_bundle",), reversible=False)
            )

        assert any("not reversible" in r for r in refused.value.refusals)

    def test_direct_memory_write_is_refused(self) -> None:
        with pytest.raises(CanaryIneligibleError) as refused:
            assert_canary_eligible(
                ResolvedRelease(artifact_classes=("prompt_bundle",), memory_write_mode="direct")
            )

        assert any("memory directly" in r for r in refused.value.refusals)

    def test_harness_touching_release_is_refused(self) -> None:
        with pytest.raises(CanaryIneligibleError) as refused:
            assert_canary_eligible(
                ResolvedRelease(artifact_classes=("prompt_bundle",), touches_harness=True)
            )

        assert any("harness" in r for r in refused.value.refusals)

    def test_runtime_surface_release_is_refused(self) -> None:
        with pytest.raises(CanaryIneligibleError) as refused:
            assert_canary_eligible(
                ResolvedRelease(artifact_classes=("prompt_bundle",), runtime_surface="runtime")
            )

        assert any("runtime surface" in r for r in refused.value.refusals)

    def test_executable_content_is_refused(self) -> None:
        with pytest.raises(CanaryIneligibleError) as refused:
            assert_canary_eligible(
                ResolvedRelease(
                    artifact_classes=("prompt_bundle",), contains_executable_content=True
                )
            )

        assert any("executable content" in r for r in refused.value.refusals)


class TestVerdictShape:
    def test_resolve_reports_refusals_without_raising(self) -> None:
        eligibility = resolve_canary_eligibility(
            ResolvedRelease(artifact_classes=("algorithm",), reversible=False)
        )

        assert not eligibility.eligible
        assert eligibility.ineligible_classes == ("algorithm",)
        assert any("not reversible" in r for r in eligibility.refusals)

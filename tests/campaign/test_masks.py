"""Mutation-mask enforcement tests (FR-006).

The contract under test: an undeclared-path edit fails *validation* —
before the wrapped adapter is ever invoked, before anything renders,
before anything executes. The spy adapter in this module records every
call it receives, so each test can assert not just the verdict but that
the wrapped adapter was (or was never) reached.
"""

from __future__ import annotations

import base64

import pytest

from evoruntime.campaign.errors import MutationMaskViolationError
from evoruntime.campaign.masks import MaskEnforcingAdapter, MutationMask, mask_violations
from evoruntime.plugins.protocol import (
    CandidateBundle,
    CanonicalBytes,
    ValidationReport,
)


class SpyAdapter:
    """Records every validate/render call — the mask must gate before these."""

    def __init__(self) -> None:
        self.validate_calls: list[CandidateBundle] = []
        self.render_calls: list[tuple[CanonicalBytes, dict[str, object]]] = []

    def validate(self, candidate: CandidateBundle) -> ValidationReport:
        self.validate_calls.append(candidate)
        return ValidationReport(accepted=True)

    def render(self, base: CanonicalBytes, patch: dict[str, object]) -> CanonicalBytes:
        self.render_calls.append((base, patch))
        return base


def make_mask() -> MutationMask:
    return MutationMask(artifact_type="prompt_bundle", allowed_paths=("prompts/system.md",))


def bundle_with(*paths: str) -> CandidateBundle:
    return CandidateBundle(
        artifact_type="prompt_bundle",
        files=tuple({"path": path, "data_b64": _b64("x")} for path in paths),
    )


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


class TestMaskViolations:
    def test_declared_path_is_clean(self) -> None:
        assert mask_violations(make_mask(), ({"path": "prompts/system.md"},)) == ()

    def test_undeclared_path_violates(self) -> None:
        violations = mask_violations(make_mask(), ({"path": "secrets/keys.env"},))
        assert len(violations) == 1
        assert "outside the mutation mask" in violations[0]

    def test_absolute_path_violates(self) -> None:
        violations = mask_violations(make_mask(), ({"path": "/etc/passwd"},))
        assert violations and "relative" in violations[0]

    def test_traversal_path_violates(self) -> None:
        violations = mask_violations(make_mask(), ({"path": "../../etc/passwd"},))
        assert violations and "relative" in violations[0]

    def test_pathless_entry_violates(self) -> None:
        violations = mask_violations(make_mask(), ({"content": "no path here"},))
        assert violations and "declares no path" in violations[0]

    def test_violations_are_reported_per_file_in_order(self) -> None:
        violations = mask_violations(
            make_mask(),
            ({"path": "prompts/system.md"}, {"path": "a.md"}, {"path": "b.md"}),
        )
        assert len(violations) == 2
        assert "a.md" in violations[0]
        assert "b.md" in violations[1]


class TestValidateBeforeExecution:
    def test_clean_candidate_reaches_the_adapter(self) -> None:
        spy = SpyAdapter()
        guarded = MaskEnforcingAdapter(spy, make_mask())
        report = guarded.validate(bundle_with("prompts/system.md"))
        assert report.accepted
        assert len(spy.validate_calls) == 1

    def test_violating_candidate_is_rejected_without_reaching_the_adapter(self) -> None:
        spy = SpyAdapter()
        guarded = MaskEnforcingAdapter(spy, make_mask())
        report = guarded.validate(bundle_with("prompts/system.md", "undeclared.md"))
        assert not report.accepted
        assert any("undeclared.md" in v for v in report.violations)
        # FR-006: the violation is a validation failure — the adapter (and
        # anything it would have run) was never invoked.
        assert spy.validate_calls == []


class TestRenderBeforeExecution:
    def test_clean_patch_reaches_the_adapter(self) -> None:
        spy = SpyAdapter()
        guarded = MaskEnforcingAdapter(spy, make_mask())
        base = CanonicalBytes(data_b64=_b64("base"), digest="sha256:" + "0" * 64)
        guarded.render(base, {"files": [{"path": "prompts/system.md"}]})
        assert len(spy.render_calls) == 1

    def test_violating_patch_raises_before_the_adapter_runs(self) -> None:
        spy = SpyAdapter()
        guarded = MaskEnforcingAdapter(spy, make_mask())
        base = CanonicalBytes(data_b64=_b64("base"), digest="sha256:" + "0" * 64)
        with pytest.raises(MutationMaskViolationError) as excinfo:
            guarded.render(base, {"files": [{"path": "harness/config.yaml"}]})
        assert any("harness/config.yaml" in v for v in excinfo.value.violations)
        assert spy.render_calls == []

    def test_single_path_patch_shape_is_also_checked(self) -> None:
        spy = SpyAdapter()
        guarded = MaskEnforcingAdapter(spy, make_mask())
        base = CanonicalBytes(data_b64=_b64("base"), digest="sha256:" + "0" * 64)
        with pytest.raises(MutationMaskViolationError):
            guarded.render(base, {"path": "elsewhere/patch.md"})
        assert spy.render_calls == []

    def test_patch_without_paths_is_the_adapters_business(self) -> None:
        spy = SpyAdapter()
        guarded = MaskEnforcingAdapter(spy, make_mask())
        base = CanonicalBytes(data_b64=_b64("base"), digest="sha256:" + "0" * 64)
        guarded.render(base, {"note": "no file paths declared"})
        assert len(spy.render_calls) == 1


class TestMaskFromSpec:
    def test_mask_builds_from_the_spec_mutable_artifact(self) -> None:
        from tests.campaign.conftest import make_spec

        mask = MutationMask.from_spec(make_spec().mutable_artifact)
        assert mask.artifact_type == "prompt_bundle"
        assert mask.allowed_paths == ("prompts/system.md",)

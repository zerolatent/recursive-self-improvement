"""Spec validation, pin+sign, and YAML round-trip tests (§11.2).

The negative tests each mutate exactly one field of a valid spec, so a
failure message names the field that broke — the same discipline the
spec's own validation errors follow.
"""

from __future__ import annotations

import copy
import hashlib
from dataclasses import replace

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evoruntime.campaign.errors import InvalidCampaignSpecError
from evoruntime.campaign.spec import (
    SUPPORTED_SPEC_VERSION,
    CampaignSpec,
    MutableArtifact,
    MutableArtifactSet,
    pin_and_sign,
)
from tests.campaign.conftest import make_spec, make_spec_mapping


def mutated(**changes: object) -> CampaignSpec:
    """The valid fixture spec with one field replaced."""
    return replace(make_spec(), **changes)  # type: ignore[arg-type]


def mutated_mapping(key: str, value: object) -> dict[str, object]:
    """The valid fixture mapping with one top-level field replaced."""
    raw = copy.deepcopy(make_spec_mapping())
    raw[key] = value  # type: ignore[assignment]
    return raw


class TestSpecValidation:
    def test_valid_fixture_spec_constructs(self) -> None:
        spec = make_spec()
        assert spec.schema_version == SUPPORTED_SPEC_VERSION
        assert len(spec.arms) == 4

    def test_unsupported_schema_version_is_refused(self) -> None:
        raw = mutated_mapping("schema_version", 999)
        with pytest.raises(InvalidCampaignSpecError, match="schema_version"):
            CampaignSpec.from_mapping(raw)  # type: ignore[arg-type]

    def test_missing_field_is_refused_with_the_field_name(self) -> None:
        raw = make_spec_mapping()
        del raw["budgets"]
        with pytest.raises(InvalidCampaignSpecError, match="'budgets'"):
            CampaignSpec.from_mapping(raw)  # type: ignore[arg-type]

    def test_mutable_set_must_contain_the_incumbent_class_exactly_once(self) -> None:
        spec = make_spec()
        # No member of the incumbent's class: nothing to optimize.
        foreign = MutableArtifact(artifact_type="skill_package", paths=("skills/x.md",))
        with pytest.raises(InvalidCampaignSpecError, match="exactly one artifact of the"):
            replace(spec, mutable_artifacts=MutableArtifactSet(artifacts=(foreign,)))
        # Two members of the incumbent's class: the primary is ambiguous —
        # caught one layer down, as a duplicate class in the set.
        with pytest.raises(InvalidCampaignSpecError, match="duplicate artifact_type"):
            MutableArtifactSet(
                artifacts=(
                    spec.mutable_artifact,
                    MutableArtifact(
                        artifact_type=spec.incumbent.artifact_type, paths=("prompts/other.md",)
                    ),
                )
            )

    def test_each_of_the_four_arms_is_required_exactly_once(self) -> None:
        kinds = [arm.kind.value for arm in make_spec().arms]
        for kind in ("incumbent", "retry-self-consistency", "one-shot-control", "strategy"):
            assert kinds.count(kind) == 1

    def test_dropping_a_control_arm_is_refused(self) -> None:
        raw = make_spec_mapping()
        raw["arms"] = [arm for arm in raw["arms"] if arm["kind"] != "one-shot-control"]  # type: ignore[index,union-attr]
        with pytest.raises(InvalidCampaignSpecError, match="one-shot-control"):
            CampaignSpec.from_mapping(raw)  # type: ignore[arg-type]

    def test_holdout_must_be_a_sealed_handle_not_content(self) -> None:
        raw = mutated_mapping("datasets", {})
        raw["datasets"] = {  # type: ignore[assignment]
            "dev_partition": "dev-primary",
            "selection_partition": "selection-primary",
            "holdout_handle": "postgres://holdout-rows?limit=all",
        }
        with pytest.raises(InvalidCampaignSpecError, match="sealed D5 handle"):
            CampaignSpec.from_mapping(raw)  # type: ignore[arg-type]

    def test_floating_image_tags_are_refused(self) -> None:
        raw = mutated_mapping(
            "strategy_plugin",
            {
                "plugin_id": "evo-prompt-strategist",
                "pinned_image": "ghcr.io/evoruntime/strategist:latest",
            },
        )
        with pytest.raises(InvalidCampaignSpecError, match="digest-pinned"):
            CampaignSpec.from_mapping(raw)  # type: ignore[arg-type]

    def test_empty_mutation_mask_is_refused(self) -> None:
        spec = make_spec()
        with pytest.raises(InvalidCampaignSpecError, match="mutation mask"):
            replace(spec, mutable_artifact=replace(spec.mutable_artifact, paths=()))

    def test_absolute_mask_paths_are_refused_in_the_spec_itself(self) -> None:
        spec = make_spec()
        with pytest.raises(InvalidCampaignSpecError, match="absolute"):
            replace(
                spec,
                mutable_artifact=replace(spec.mutable_artifact, paths=("/etc/passwd",)),
            )

    def test_traversal_mask_paths_are_refused_in_the_spec_itself(self) -> None:
        spec = make_spec()
        with pytest.raises(InvalidCampaignSpecError, match="traversal"):
            replace(
                spec,
                mutable_artifact=replace(spec.mutable_artifact, paths=("../../secrets",)),
            )

    def test_unknown_budget_profile_is_a_construction_error(self) -> None:
        raw = make_spec_mapping()
        raw["budgets"] = {  # type: ignore[assignment]
            **raw["budgets"],  # type: ignore[index]
            "task_budget_profile": "task-budget-v99",
        }
        with pytest.raises(InvalidCampaignSpecError):
            CampaignSpec.from_mapping(raw)  # type: ignore[arg-type]

    def test_alpha_outside_open_interval_is_refused(self) -> None:
        with pytest.raises(InvalidCampaignSpecError, match="alpha"):
            mutated(statistics=replace(make_spec().statistics, alpha=0.0))


class TestCanonicalFormAndPinning:
    def test_canonical_bytes_are_stable_and_sorted(self) -> None:
        spec = make_spec()
        assert spec.canonical_bytes() == spec.canonical_bytes()
        assert b'"alpha":0.05' in spec.canonical_bytes()

    def test_digest_matches_canonical_bytes(self) -> None:
        spec = make_spec()
        assert spec.digest == "sha256:" + hashlib.sha256(spec.canonical_bytes()).hexdigest()

    def test_pin_and_sign_verifies(self) -> None:
        assert pin_and_sign(make_spec(), Ed25519PrivateKey.generate()).verify()

    def test_editing_the_spec_after_pin_breaks_verification(self) -> None:
        spec = make_spec()
        pinned = pin_and_sign(spec, Ed25519PrivateKey.generate())
        forged = replace(spec, name="different-campaign")
        assert forged.digest != pinned.digest
        # The forged spec wearing the original digest/signature must fail.
        assert not replace(pinned, spec=forged).verify()

    def test_signature_from_another_key_does_not_verify(self) -> None:
        spec = make_spec()
        pinned = pin_and_sign(spec, Ed25519PrivateKey.generate())
        other = pin_and_sign(spec, Ed25519PrivateKey.generate())
        # Forgery shape that matters: the attacker's signature bytes under
        # the pinned spec's public key. (Swapping the whole DetachedSignature
        # would just be a different valid signature — it carries its own key.)
        forged_sig = replace(other.signature, public_key=pinned.signature.public_key)
        assert not replace(pinned, signature=forged_sig).verify()


class TestYamlAuthoring:
    def test_yaml_round_trip_produces_the_same_spec(self) -> None:
        spec = make_spec()
        text = yaml.safe_dump(spec.to_canonical_dict(), sort_keys=True)
        assert CampaignSpec.from_yaml(text).digest == spec.digest

    def test_invalid_yaml_is_a_spec_error(self) -> None:
        with pytest.raises(InvalidCampaignSpecError, match="not valid YAML"):
            CampaignSpec.from_yaml("schema_version: [unclosed")

    def test_non_mapping_yaml_is_refused(self) -> None:
        with pytest.raises(InvalidCampaignSpecError, match="mapping"):
            CampaignSpec.from_yaml("- just\n- a\n- list\n")


# ---------------------------------------------------------------------------
# Spec v2: MutableArtifactSet validation, v1 migration window, pinning (F4)
# ---------------------------------------------------------------------------


class TestMutableArtifactSetV2:
    def test_v2_spec_requires_a_non_empty_mutable_artifacts_list(self) -> None:
        raw = make_spec_mapping()
        raw["schema_version"] = 2
        raw["mutable_artifacts"] = []
        with pytest.raises(InvalidCampaignSpecError, match="mutable_artifacts"):
            CampaignSpec.from_mapping(raw)

    def test_v2_spec_rejects_a_missing_mutable_artifacts_key(self) -> None:
        raw = make_spec_mapping()  # v1 shape: singular mutable_artifact, no set
        raw["schema_version"] = 2
        raw.pop("mutable_artifacts", None)
        with pytest.raises(InvalidCampaignSpecError, match="mutable_artifacts"):
            CampaignSpec.from_mapping(raw)

    def test_v2_set_parses_multiple_members_in_order(self) -> None:
        raw = make_spec_mapping()
        raw["schema_version"] = 2
        raw["mutable_artifacts"] = [
            {"artifact_type": "prompt_bundle", "paths": ["prompts/system.md"]},
            {"artifact_type": "workflow_graph", "paths": ["workflows/main.yaml"]},
        ]
        spec = CampaignSpec.from_mapping(raw)
        assert [m.artifact_type for m in spec.mutable_artifacts.artifacts] == [
            "prompt_bundle",
            "workflow_graph",
        ]
        assert spec.mutable_artifacts.artifacts[1].paths == ("workflows/main.yaml",)

    def test_v2_set_rejects_duplicate_member_classes(self) -> None:
        raw = make_spec_mapping()
        raw["schema_version"] = 2
        raw["mutable_artifacts"] = [
            {"artifact_type": "prompt_bundle", "paths": ["prompts/system.md"]},
            {"artifact_type": "prompt_bundle", "paths": ["prompts/other.md"]},
        ]
        with pytest.raises(InvalidCampaignSpecError, match="duplicate artifact_type"):
            CampaignSpec.from_mapping(raw)

    def test_primary_is_the_incumbent_class_member_wherever_it_sits(self) -> None:
        """The primary is the member of the incumbent's class — validation
        guarantees exactly one such member, not that it comes first."""
        raw = make_spec_mapping()
        raw["schema_version"] = 2
        raw["mutable_artifacts"] = [
            {"artifact_type": "workflow_graph", "paths": ["workflows/main.yaml"]},
            {"artifact_type": "prompt_bundle", "paths": ["prompts/system.md"]},
        ]
        spec = CampaignSpec.from_mapping(raw)
        # `mutable_artifact` is the back-compat primary view over the set.
        assert spec.mutable_artifact.artifact_type == "prompt_bundle"
        assert spec.mutable_artifact.paths == ("prompts/system.md",)

    def test_v2_member_paths_are_mask_validated(self) -> None:
        raw = make_spec_mapping()
        raw["schema_version"] = 2
        raw["mutable_artifacts"] = [
            {"artifact_type": "prompt_bundle", "paths": ["/etc/passwd"]},
        ]
        with pytest.raises(InvalidCampaignSpecError, match="relative"):
            CampaignSpec.from_mapping(raw)


class TestV1MigrationWindow:
    def test_v1_spec_parses_during_the_window_as_a_single_member_set(self) -> None:
        spec = make_spec()
        assert spec.schema_version == 2  # upgraded at parse time
        assert len(spec.mutable_artifacts.artifacts) == 1
        assert spec.mutable_artifacts.artifacts[0].artifact_type == (spec.incumbent.artifact_type)

    def test_v1_spec_is_rejected_after_the_migration_window(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import evoruntime.campaign.spec as spec_module

        class FrozenDate(spec_module.date):  # type: ignore[name-defined]
            @classmethod
            def today(cls) -> spec_module.date:  # type: ignore[name-defined]
                return spec_module.date(2026, 10, 28)  # type: ignore[attr-defined]

        monkeypatch.setattr(spec_module, "date", FrozenDate)
        with pytest.raises(InvalidCampaignSpecError, match="migration window closed"):
            CampaignSpec.from_mapping(make_spec_mapping())  # fixture is a v1 document

    def test_v1_spec_is_still_accepted_on_the_windows_last_day(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import evoruntime.campaign.spec as spec_module

        class FrozenDate(spec_module.date):  # type: ignore[name-defined]
            @classmethod
            def today(cls) -> spec_module.date:  # type: ignore[name-defined]
                return spec_module.date(2026, 10, 27)  # type: ignore[attr-defined]

        monkeypatch.setattr(spec_module, "date", FrozenDate)
        spec = CampaignSpec.from_mapping(make_spec_mapping())  # window's last day
        assert spec.schema_version == 2

    def test_unsupported_schema_version_is_refused(self) -> None:
        raw = make_spec_mapping()
        raw["schema_version"] = 3
        with pytest.raises(InvalidCampaignSpecError, match="schema_version"):
            CampaignSpec.from_mapping(raw)


class TestPinAndSignV2:
    def test_pinned_digest_covers_the_whole_mutable_set(self) -> None:
        """Changing any member of the set changes the pinned digest — the
        signature vouches for every member, not just the primary."""
        spec = make_spec()
        pinned = pin_and_sign(spec, Ed25519PrivateKey.generate())
        widened = replace(
            spec,
            mutable_artifacts=MutableArtifactSet(
                artifacts=(
                    *spec.mutable_artifacts.artifacts,
                    MutableArtifact(artifact_type="workflow_graph", paths=("workflows/main.yaml",)),
                )
            ),
        )
        repinned = pin_and_sign(widened, Ed25519PrivateKey.generate())
        assert pinned.digest != repinned.digest

    def test_pinned_v2_spec_verifies(self) -> None:
        spec = make_spec()
        pinned = pin_and_sign(spec, Ed25519PrivateKey.generate())
        assert pinned.verify()

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

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
    DEFAULT_MAX_SANDBOX_EXECUTIONS,
    SUPPORTED_SPEC_VERSION,
    CampaignSpec,
    EvaluatorBinding,
    MutableArtifact,
    MutableArtifactSet,
    MutationClassBinding,
    pin_and_sign,
)
from evoruntime.core.isolation import IsolationTier
from evoruntime.eval.cascade import EvaluatorCostClass
from tests.campaign.conftest import SPEC_DIGEST, make_spec, make_spec_mapping


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

    def _spec_with_mask_paths(self, *paths: str) -> CampaignSpec:
        """The fixture spec re-authored with one mask path list."""
        raw = make_spec_mapping()
        raw["mutable_artifact"]["paths"] = list(paths)  # type: ignore[index]
        return CampaignSpec.from_mapping(raw)  # type: ignore[arg-type]

    def test_protected_mask_path_is_refused_at_spec_construction(self) -> None:
        """Phase 3 (G2): a mask path under a protected root fails before search."""
        with pytest.raises(InvalidCampaignSpecError, match="protected module"):
            self._spec_with_mask_paths("src/evoruntime/security/policy.py")

    def test_protected_mask_path_refusal_names_the_root_and_reason(self) -> None:
        with pytest.raises(InvalidCampaignSpecError, match="evoruntime.security"):
            self._spec_with_mask_paths("src/evoruntime/security/egress.py")

    def test_every_protected_plane_is_refused_as_a_mask_path(self) -> None:
        """An explicit attempt to mutate an evaluator module is proven refused."""
        for protected_path in (
            "src/evoruntime/selection/policy.py",
            "src/evoruntime/release/manifest.py",
            "src/evoruntime/sandbox/profiles.py",
            "src/evoruntime/dlp/redactor.py",
            "src/evoruntime/datasets/ledger.py",
            "src/evoruntime/sdk/attestation.py",
        ):
            with pytest.raises(InvalidCampaignSpecError, match="protected module"):
                self._spec_with_mask_paths(protected_path)

    def test_sibling_prefix_paths_are_still_allowed(self) -> None:
        """The deny-list bounds protected roots, not look-alike siblings."""
        spec = self._spec_with_mask_paths("prompts/system.md", "src/evoruntime/securityx/policy.py")
        assert "src/evoruntime/securityx/policy.py" in spec.mutable_artifact.paths

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
        assert spec.schema_version == 3  # upgraded at parse time
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
        assert spec.schema_version == 3

    def test_unsupported_schema_version_is_refused(self) -> None:
        raw = make_spec_mapping()
        raw["schema_version"] = 999
        with pytest.raises(InvalidCampaignSpecError, match="schema_version"):
            CampaignSpec.from_mapping(raw)


# ---------------------------------------------------------------------------
# Spec v3: scaffold mutation surface, environment, pinned mutation classes (G3)
# ---------------------------------------------------------------------------


def make_v3_mapping() -> dict[str, object]:
    """The fixture spec re-authored as a v3 document (no scaffold surface)."""
    raw = make_spec_mapping()
    raw["schema_version"] = 3
    raw.pop("mutable_artifact", None)
    raw["mutable_artifacts"] = [
        {"artifact_type": "prompt_bundle", "paths": ["prompts/system.md"]},
    ]
    return raw


def make_scaffold_mapping() -> dict[str, object]:
    """A valid v3 scaffold-mutable spec: research environment, pinned classes."""
    raw = make_v3_mapping()
    raw["incumbent"] = {
        "release_manifest_digest": SPEC_DIGEST,
        "artifact_type": "scaffold",
    }
    raw["mutable_artifacts"] = [
        {"artifact_type": "scaffold", "paths": ["src/evoruntime/campaign/spec.py"]},
    ]
    raw["environment"] = "research"
    # G4: a scaffold-mutable campaign must carry exactly one fixed-editor
    # arm — the incumbent scaffold evaluated under the frozen editor.
    raw["arms"] = [
        *raw["arms"],  # type: ignore[operator]
        {"id": "fixed-editor", "kind": "fixed-editor", "editor_ref": "evo-prompt-strategist@gen-0"},
    ]
    raw["mutation_classes"] = [
        {
            "class_id": "prompt_module_edit",
            "risk_dossier_digest": "sha256:" + "e" * 64,
            "max_tier": "executable",
        },
        {
            "class_id": "control_flow_change",
            "risk_dossier_digest": "sha256:" + "f" * 64,
            "max_tier": "highest",
        },
    ]
    # G7: a scaffold-mutable campaign pins the digest of the tier-4-allowing
    # seed policy its promotions are governed by.
    raw["tier4_policy_digest"] = "sha256:" + "a" * 64
    return raw


class TestSpecV3ScaffoldMutationSurface:
    def test_valid_scaffold_spec_parses_with_pinned_classes(self) -> None:
        spec = CampaignSpec.from_mapping(make_scaffold_mapping())
        assert spec.environment == "research"
        assert [binding.class_id for binding in spec.mutation_classes] == [
            "prompt_module_edit",
            "control_flow_change",
        ]
        assert spec.mutation_classes[0].max_tier is IsolationTier.EXECUTABLE
        assert spec.mutation_classes[1].max_tier is IsolationTier.HIGHEST

    def test_scaffold_spec_without_environment_is_refused_at_parse(self) -> None:
        raw = make_scaffold_mapping()
        del raw["environment"]
        with pytest.raises(InvalidCampaignSpecError, match="environment: research"):
            CampaignSpec.from_mapping(raw)

    def test_scaffold_spec_without_pinned_mutation_classes_is_refused_at_parse(self) -> None:
        raw = make_scaffold_mapping()
        del raw["mutation_classes"]
        with pytest.raises(InvalidCampaignSpecError, match="mutation_classes"):
            CampaignSpec.from_mapping(raw)

    def test_scaffold_spec_with_an_empty_mutation_classes_section_is_refused(self) -> None:
        raw = make_scaffold_mapping()
        raw["mutation_classes"] = []
        with pytest.raises(InvalidCampaignSpecError, match="mutation_classes"):
            CampaignSpec.from_mapping(raw)

    def test_environment_other_than_research_is_refused(self) -> None:
        raw = make_scaffold_mapping()
        raw["environment"] = "production"
        with pytest.raises(InvalidCampaignSpecError, match="environment"):
            CampaignSpec.from_mapping(raw)

    def test_non_scaffold_spec_does_not_require_environment_or_classes(self) -> None:
        """The scaffold gate is scoped to scaffold-mutable sets: a prompt
        campaign parses without either v3 field, exactly as it did in v2."""
        spec = CampaignSpec.from_mapping(make_v3_mapping())
        assert spec.environment is None
        assert spec.mutation_classes == ()

    def test_mutation_class_dossier_digest_must_be_a_sha256(self) -> None:
        raw = make_scaffold_mapping()
        raw["mutation_classes"] = [
            {
                "class_id": "prompt_module_edit",
                "risk_dossier_digest": "dossier-v3-final",
                "max_tier": "executable",
            }
        ]
        with pytest.raises(InvalidCampaignSpecError, match="risk_dossier_digest"):
            CampaignSpec.from_mapping(raw)

    def test_mutation_class_max_tier_must_be_a_known_isolation_tier(self) -> None:
        raw = make_scaffold_mapping()
        raw["mutation_classes"] = [
            {
                "class_id": "prompt_module_edit",
                "risk_dossier_digest": "sha256:" + "e" * 64,
                "max_tier": "tier-9",
            }
        ]
        with pytest.raises(InvalidCampaignSpecError, match="max_tier"):
            CampaignSpec.from_mapping(raw)

    def test_duplicate_mutation_class_ids_are_refused(self) -> None:
        raw = make_scaffold_mapping()
        raw["mutation_classes"] = [
            {
                "class_id": "prompt_module_edit",
                "risk_dossier_digest": "sha256:" + "e" * 64,
                "max_tier": "executable",
            },
            {
                "class_id": "prompt_module_edit",
                "risk_dossier_digest": "sha256:" + "f" * 64,
                "max_tier": "highest",
            },
        ]
        with pytest.raises(InvalidCampaignSpecError, match="duplicate class_id"):
            CampaignSpec.from_mapping(raw)


class TestV2MigrationWindow:
    def test_v2_spec_parses_during_the_window_and_upgrades_to_v3(self) -> None:
        raw = make_spec_mapping()
        raw["schema_version"] = 2
        raw.pop("mutable_artifact", None)
        raw["mutable_artifacts"] = [
            {"artifact_type": "prompt_bundle", "paths": ["prompts/system.md"]},
        ]
        spec = CampaignSpec.from_mapping(raw)
        assert spec.schema_version == 3  # upgraded at parse time
        assert spec.environment is None  # v2 documents carry no environment claim
        assert spec.mutation_classes == ()

    def test_v2_spec_is_rejected_after_the_migration_window(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import evoruntime.campaign.spec as spec_module

        class FrozenDate(spec_module.date):  # type: ignore[name-defined]
            @classmethod
            def today(cls) -> spec_module.date:  # type: ignore[name-defined]
                return spec_module.date(2026, 10, 29)  # type: ignore[attr-defined]

        monkeypatch.setattr(spec_module, "date", FrozenDate)
        raw = make_spec_mapping()
        raw["schema_version"] = 2
        raw.pop("mutable_artifact", None)
        raw["mutable_artifacts"] = [
            {"artifact_type": "prompt_bundle", "paths": ["prompts/system.md"]},
        ]
        with pytest.raises(InvalidCampaignSpecError, match="migration window closed"):
            CampaignSpec.from_mapping(raw)

    def test_v2_spec_is_still_accepted_on_the_windows_last_day(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import evoruntime.campaign.spec as spec_module

        class FrozenDate(spec_module.date):  # type: ignore[name-defined]
            @classmethod
            def today(cls) -> spec_module.date:  # type: ignore[name-defined]
                return spec_module.date(2026, 10, 28)  # type: ignore[attr-defined]

        monkeypatch.setattr(spec_module, "date", FrozenDate)
        raw = make_spec_mapping()
        raw["schema_version"] = 2
        raw.pop("mutable_artifact", None)
        raw["mutable_artifacts"] = [
            {"artifact_type": "prompt_bundle", "paths": ["prompts/system.md"]},
        ]
        spec = CampaignSpec.from_mapping(raw)  # window's last day
        assert spec.schema_version == 3

    def test_v2_and_equivalent_v3_documents_pin_to_the_same_digest(self) -> None:
        """The v2→v3 upgrade is shape-only: the upgraded v2 document and
        the same document re-authored as v3 are the same spec, so they pin
        to the same digest and the same signature verifies both."""
        v2_raw = make_spec_mapping()
        v2_raw["schema_version"] = 2
        v2_raw.pop("mutable_artifact", None)
        v2_raw["mutable_artifacts"] = [
            {"artifact_type": "prompt_bundle", "paths": ["prompts/system.md"]},
        ]
        # The environment claim is set explicitly on both documents: the
        # canonical form always serializes it (G3), so the digest binds
        # the claim — an equivalent pair that *declares* the claim must
        # upgrade without changing the digest.
        v2_raw["environment"] = "research"
        v3_raw = copy.deepcopy(v2_raw)
        v3_raw["schema_version"] = 3
        v2_spec = CampaignSpec.from_mapping(v2_raw)
        v3_spec = CampaignSpec.from_mapping(v3_raw)
        assert v2_spec.digest == v3_spec.digest
        assert v2_spec.to_canonical_dict() == v3_spec.to_canonical_dict()


class TestPinAndSignV3:
    def test_pinned_digest_binds_the_environment_claim(self) -> None:
        """Declaring the environment claim changes the digest — the
        signature vouches for the environment, not just the surfaces.
        (Proven on a non-scaffold spec, where the claim is optional: a
        scaffold spec without it is refused outright.)"""
        raw = make_v3_mapping()
        raw["environment"] = "research"
        claimed = CampaignSpec.from_mapping(raw)
        unclaimed = CampaignSpec.from_mapping(make_v3_mapping())
        pinned = pin_and_sign(claimed, Ed25519PrivateKey.generate())
        repinned = pin_and_sign(unclaimed, Ed25519PrivateKey.generate())
        assert pinned.digest != repinned.digest

    def test_pinned_digest_binds_the_mutation_classes(self) -> None:
        """A class whose dossier digest changes is a different
        preregistration — the signature vouches for every pinned class."""
        spec = CampaignSpec.from_mapping(make_scaffold_mapping())
        pinned = pin_and_sign(spec, Ed25519PrivateKey.generate())
        re_dossiered = replace(
            spec,
            mutation_classes=(
                MutationClassBinding(
                    class_id="prompt_module_edit",
                    risk_dossier_digest="sha256:" + "9" * 64,
                    max_tier=IsolationTier.EXECUTABLE,
                ),
                spec.mutation_classes[1],
            ),
        )
        repinned = pin_and_sign(re_dossiered, Ed25519PrivateKey.generate())
        assert pinned.digest != repinned.digest

    def test_pinned_scaffold_spec_verifies(self) -> None:
        spec = CampaignSpec.from_mapping(make_scaffold_mapping())
        pinned = pin_and_sign(spec, Ed25519PrivateKey.generate())
        assert pinned.verify()


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


class TestCascadeEvaluatorBindings:
    """F6 cascade fields on EvaluatorBinding: defaults, validation, canonical form."""

    def test_binding_without_cascade_fields_defaults_to_the_cheapest_stage(self) -> None:
        binding = make_spec().evaluators[0]
        assert binding.stage == 0
        assert binding.cost_class is EvaluatorCostClass.CHEAP
        assert binding.short_circuit is True

    def test_cascade_fields_round_trip_through_the_mapping(self) -> None:
        raw = make_spec_mapping()
        raw["evaluators"] = [
            {
                "name": "lint",
                "pinned_image": "ghcr.io/evoruntime/lint@sha256:" + "c" * 64,
                "stage": 0,
                "cost_class": "cheap",
                "short_circuit": True,
            },
            {
                "name": "full-holdout",
                "pinned_image": "ghcr.io/evoruntime/verifier@sha256:" + "c" * 64,
                "stage": 2,
                "cost_class": "expensive",
                "short_circuit": False,
            },
        ]
        spec = CampaignSpec.from_mapping(raw)

        cheap, expensive = spec.evaluators
        assert cheap.stage == 0 and cheap.cost_class is EvaluatorCostClass.CHEAP
        assert expensive.stage == 2
        assert expensive.cost_class is EvaluatorCostClass.EXPENSIVE
        assert expensive.short_circuit is False

    def test_negative_stage_is_refused(self) -> None:
        raw = make_spec_mapping()
        raw["evaluators"][0]["stage"] = -1
        with pytest.raises(InvalidCampaignSpecError, match="stage must be >= 0"):
            CampaignSpec.from_mapping(raw)  # type: ignore[arg-type]

    def test_unknown_cost_class_is_refused(self) -> None:
        raw = make_spec_mapping()
        raw["evaluators"][0]["cost_class"] = "free"
        with pytest.raises(InvalidCampaignSpecError, match="not a valid EvaluatorCostClass"):
            CampaignSpec.from_mapping(raw)  # type: ignore[arg-type]

    def test_non_boolean_short_circuit_is_refused(self) -> None:
        raw = make_spec_mapping()
        raw["evaluators"][0]["short_circuit"] = "yes"
        with pytest.raises(InvalidCampaignSpecError, match="short_circuit"):
            CampaignSpec.from_mapping(raw)  # type: ignore[arg-type]

    def test_canonical_dict_carries_the_cascade_fields(self) -> None:
        binding = EvaluatorBinding(
            name="test-suite",
            pinned_image="ghcr.io/evoruntime/verifier@sha256:" + "c" * 64,
            stage=1,
            cost_class=EvaluatorCostClass.STANDARD,
            short_circuit=False,
        )
        assert binding.to_canonical_dict() == {
            "name": "test-suite",
            "pinned_image": "ghcr.io/evoruntime/verifier@sha256:" + "c" * 64,
            "stage": 1,
            "cost_class": "standard",
            "short_circuit": False,
        }

    def test_cascade_fields_are_part_of_the_pinned_digest(self) -> None:
        """A cascade order chosen after pinning is not a preregistration."""
        spec = make_spec()
        re_staged = replace(spec.evaluators[0], stage=1, cost_class=EvaluatorCostClass.EXPENSIVE)
        assert replace(spec, evaluators=(re_staged,)).digest != spec.digest


class TestSandboxBudgetDimension:
    """F6 campaign budget dimension for executable (F1) runs."""

    def test_max_sandbox_executions_defaults_to_the_registered_ceiling(self) -> None:
        budgets = make_spec().budgets
        assert budgets.max_sandbox_executions == DEFAULT_MAX_SANDBOX_EXECUTIONS

    def test_max_sandbox_executions_round_trips_through_the_mapping(self) -> None:
        raw = make_spec_mapping()
        raw["budgets"]["max_sandbox_executions"] = 42
        spec = CampaignSpec.from_mapping(raw)
        assert spec.budgets.max_sandbox_executions == 42

    def test_zero_sandbox_executions_is_refused(self) -> None:
        raw = make_spec_mapping()
        raw["budgets"]["max_sandbox_executions"] = 0
        with pytest.raises(InvalidCampaignSpecError, match="max_sandbox_executions"):
            CampaignSpec.from_mapping(raw)  # type: ignore[arg-type]

    def test_sandbox_dimension_is_part_of_the_canonical_budgets(self) -> None:
        canonical = make_spec().to_canonical_dict()["budgets"]
        assert canonical["max_sandbox_executions"] == DEFAULT_MAX_SANDBOX_EXECUTIONS


class TestFixedEditorArmRequirement:
    """G4: a scaffold-mutable campaign must carry exactly one fixed-editor
    arm — the incumbent scaffold evaluated under the frozen editor. Same
    hard-requirement style as the Phase 0 control arms: refused at
    construction, never a judgment call."""

    def test_scaffold_spec_with_exactly_one_fixed_editor_arm_parses(self) -> None:
        spec = CampaignSpec.from_mapping(make_scaffold_mapping())
        fixed_editors = [arm for arm in spec.arms if arm.kind == "fixed-editor"]
        assert len(fixed_editors) == 1
        assert fixed_editors[0].editor_ref == "evo-prompt-strategist@gen-0"

    def test_scaffold_spec_without_a_fixed_editor_arm_is_refused(self) -> None:
        raw = make_scaffold_mapping()
        raw["arms"] = [arm for arm in raw["arms"] if arm["kind"] != "fixed-editor"]  # type: ignore[index,union-attr]
        with pytest.raises(InvalidCampaignSpecError, match="fixed-editor"):
            CampaignSpec.from_mapping(raw)  # type: ignore[arg-type]

    def test_scaffold_spec_with_two_fixed_editor_arms_is_refused(self) -> None:
        raw = make_scaffold_mapping()
        raw["arms"] = [
            *raw["arms"],  # type: ignore[operator]
            {"id": "fixed-editor-2", "kind": "fixed-editor", "editor_ref": "other@gen-0"},
        ]
        with pytest.raises(InvalidCampaignSpecError, match="fixed-editor"):
            CampaignSpec.from_mapping(raw)  # type: ignore[arg-type]

    def test_non_scaffold_spec_does_not_require_a_fixed_editor_arm(self) -> None:
        spec = CampaignSpec.from_mapping(make_v3_mapping())
        assert not any(arm.kind == "fixed-editor" for arm in spec.arms)

    def test_editor_ref_round_trips_through_the_canonical_form(self) -> None:
        spec = CampaignSpec.from_mapping(make_scaffold_mapping())
        reparsed = CampaignSpec.from_mapping(spec.to_canonical_dict())
        assert reparsed.canonical_bytes() == spec.canonical_bytes()
        assert reparsed.arms[-1].editor_ref == "evo-prompt-strategist@gen-0"

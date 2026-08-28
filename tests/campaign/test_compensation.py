"""F5 compensation planning: declared rollback plans, signed and enforced.

The acceptance matrix this suite verifies:

- **Rollback executes declared compensations in order** — a multi-artifact
  plan's requires-execution actions run in declared order, CAS actions ride
  the pointer rollback, and the evidence lands in the execution sink.
- **Unexecuted requires-execution compensation blocks promotion** — both at
  the release plane (``assert_promotion_allowed``, the canary harness) and
  at the orchestrator (the APPROVE→CANARY gate hook).
- **Plan tamper refused** — stored bytes that no longer hash to their
  content address, a plan whose body was edited, and a forged signature are
  all refused, never trusted.
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from evoruntime.campaign.compensation import (
    CAS_ACTION_KINDS,
    CAS_MODE,
    REQUIRES_EXECUTION_ACTION_KINDS,
    REQUIRES_EXECUTION_MODE,
    CheckpointedCompensationGate,
    CompensationActionKind,
    CompensationExecutionRecord,
    CompensationPlanStore,
    InMemoryExecutionSink,
    SignedCompensationPlan,
    assert_promotion_allowed,
    classification_for_action,
    execute_rollback_compensations,
    plan_actions_from_spec,
    sign_compensation_plan,
)
from evoruntime.campaign.errors import (
    CompensationPlanBuildError,
    CompensationPlanTamperedError,
    InvalidCampaignSpecError,
    InvalidTransitionError,
    UnexecutedCompensationError,
)
from evoruntime.campaign.machine import CampaignOrchestrator, CampaignPhase
from evoruntime.campaign.spec import CampaignSpec
from tests.campaign.conftest import (
    InMemoryCheckpointStore,
    make_pinned_spec,
    make_spec,
    make_spec_mapping,
)

DIGEST_A = "sha256:" + "1" * 64
DIGEST_B = "sha256:" + "2" * 64


def _mixed_actions() -> list[dict[str, Any]]:
    """A two-artifact plan: a CAS action, then a requires-execution one."""
    return [
        {
            "artifact_digest": DIGEST_A,
            "action": CompensationActionKind.REVOKE_ARTIFACT.value,
            "mode": CAS_MODE,
            "executed": False,
        },
        {
            "artifact_digest": DIGEST_B,
            "action": CompensationActionKind.RUN_COMPENSATION_HOOK.value,
            "mode": REQUIRES_EXECUTION_MODE,
            "executed": False,
        },
    ]


def _sign_plan(
    actions: list[dict[str, Any]] | None = None,
    *,
    plan_id: str = "plan-1",
    private_key: Ed25519PrivateKey | None = None,
) -> SignedCompensationPlan:
    return sign_compensation_plan(
        plan_id=plan_id,
        campaign_id="campaign-1",
        manifest_digest="sha256:" + "3" * 64,
        actions=actions if actions is not None else _mixed_actions(),
        private_key=private_key or Ed25519PrivateKey.generate(),
    )


class _RecordingExecutor:
    """Executes compensations by recording the call order (and can fail)."""

    def __init__(self, fail_at_index: int | None = None) -> None:
        self.calls: list[tuple[int, str]] = []
        self._fail_at_index = fail_at_index

    def execute(self, action_index: int, action: dict[str, Any]) -> None:
        if self._fail_at_index is not None and action_index == self._fail_at_index:
            raise RuntimeError(f"hook {action_index} failed")
        self.calls.append((action_index, str(action.get("action", ""))))


# -- classification ----------------------------------------------------------


def test_cas_action_kinds_need_no_extra_execution() -> None:
    assert (
        frozenset(
            {
                CompensationActionKind.RESTORE_PRIOR_RELEASE_POINTER,
                CompensationActionKind.REVOKE_ARTIFACT,
            }
        )
        == CAS_ACTION_KINDS
    )
    assert classification_for_action("restore_prior_release_pointer") == CAS_MODE
    assert classification_for_action("revoke_artifact") == CAS_MODE


def test_run_compensation_hook_requires_execution() -> None:
    assert (
        frozenset({CompensationActionKind.RUN_COMPENSATION_HOOK}) == REQUIRES_EXECUTION_ACTION_KINDS
    )
    assert classification_for_action("run_compensation_hook") == REQUIRES_EXECUTION_MODE


def test_unknown_action_classifies_fail_closed() -> None:
    """An action the runtime cannot name might mutate external state — it is
    treated as requiring evidence, never waved through."""
    assert classification_for_action("something_unheard_of") == REQUIRES_EXECUTION_MODE


# -- spec authoring shapes ---------------------------------------------------


def _spec_with_compensation_plan(section: dict[str, Any] | None) -> CampaignSpec:
    mapping = make_spec_mapping()
    if section is None:
        mapping.pop("compensation_plan", None)
    else:
        mapping["compensation_plan"] = section
    return CampaignSpec.from_mapping(mapping)


def _v2_two_artifact_spec(section: dict[str, Any]) -> CampaignSpec:
    """A v2 spec mutating two artifact classes, with a compensation plan
    declaring one action per class — the mixed CAS + hook shape the F5
    acceptance row describes."""
    mapping = make_spec_mapping()
    mapping["schema_version"] = 2
    mapping["mutable_artifacts"] = [
        {"artifact_type": "prompt_bundle", "paths": ["prompts/system.md"]},
        {"artifact_type": "workflow_graph", "paths": ["workflows/main.yaml"]},
    ]
    mapping["compensation_plan"] = section
    return CampaignSpec.from_mapping(mapping)


def test_spec_without_compensation_plan_parses_and_canonicalizes_to_null() -> None:
    spec = make_spec()
    assert spec.compensation_plan is None
    assert spec.to_canonical_dict()["compensation_plan"] is None


def test_spec_compensation_plan_round_trips_order_pinned() -> None:
    section = {
        "actions": [
            {"artifact_type": "prompt_bundle", "action": "revoke_artifact"},
            {
                "artifact_type": "workflow_graph",
                "action": "run_compensation_hook",
                "hook_image": "ghcr.io/evoruntime/comp-hook@sha256:" + "e" * 64,
            },
        ]
    }
    spec = _v2_two_artifact_spec(section)
    assert spec.compensation_plan is not None
    assert [action.action for action in spec.compensation_plan.actions] == [
        "revoke_artifact",
        "run_compensation_hook",
    ]
    # Canonical form round-trips byte-identically through from_mapping.
    reparsed = CampaignSpec.from_mapping(spec.to_canonical_dict())
    assert reparsed == spec


def test_spec_refuses_unknown_compensation_action() -> None:
    with pytest.raises(InvalidCampaignSpecError, match="not a declared compensating"):
        _spec_with_compensation_plan(
            {"actions": [{"artifact_type": "prompt_bundle", "action": "deploy_to_prod"}]}
        )


def test_spec_requires_pinned_hook_image_for_run_compensation_hook() -> None:
    with pytest.raises(InvalidCampaignSpecError, match="must be digest-pinned"):
        _spec_with_compensation_plan(
            {
                "actions": [
                    {
                        "artifact_type": "prompt_bundle",
                        "action": "run_compensation_hook",
                        "hook_image": "ghcr.io/evoruntime/comp-hook:latest",
                    }
                ]
            }
        )


def test_spec_refuses_hook_image_on_cas_action() -> None:
    with pytest.raises(InvalidCampaignSpecError, match="takes no hook_image"):
        _spec_with_compensation_plan(
            {
                "actions": [
                    {
                        "artifact_type": "prompt_bundle",
                        "action": "revoke_artifact",
                        "hook_image": "ghcr.io/evoruntime/comp-hook@sha256:" + "e" * 64,
                    }
                ]
            }
        )


def test_spec_refuses_duplicate_artifact_types_in_plan() -> None:
    with pytest.raises(InvalidCampaignSpecError, match="duplicate artifact_type"):
        _spec_with_compensation_plan(
            {
                "actions": [
                    {"artifact_type": "prompt_bundle", "action": "revoke_artifact"},
                    {"artifact_type": "prompt_bundle", "action": "revoke_artifact"},
                ]
            }
        )


def test_spec_refuses_action_outside_the_mutable_artifact_set() -> None:
    with pytest.raises(InvalidCampaignSpecError, match="only compensate"):
        _spec_with_compensation_plan(
            {"actions": [{"artifact_type": "tool_spec", "action": "revoke_artifact"}]}
        )


def test_spec_refuses_empty_compensation_plan() -> None:
    with pytest.raises(InvalidCampaignSpecError, match="non-empty ordered"):
        _spec_with_compensation_plan({"actions": []})


# -- plan construction from a spec ------------------------------------------


def test_plan_actions_from_spec_preserves_declared_order_and_mode() -> None:
    spec = _v2_two_artifact_spec(
        {
            "actions": [
                {"artifact_type": "prompt_bundle", "action": "revoke_artifact"},
                {
                    "artifact_type": "workflow_graph",
                    "action": "run_compensation_hook",
                    "hook_image": "ghcr.io/evoruntime/comp-hook@sha256:" + "e" * 64,
                },
            ]
        }
    )
    assert spec.compensation_plan is not None
    actions = plan_actions_from_spec(
        spec.compensation_plan.actions,
        {"prompt_bundle": DIGEST_A, "workflow_graph": DIGEST_B},
    )
    assert [action["artifact_digest"] for action in actions] == [DIGEST_A, DIGEST_B]
    assert [action["mode"] for action in actions] == [CAS_MODE, REQUIRES_EXECUTION_MODE]
    assert all(action["executed"] is False for action in actions)


def test_plan_actions_from_spec_refuses_unresolved_artifact_type() -> None:
    spec = _v2_two_artifact_spec(
        {"actions": [{"artifact_type": "prompt_bundle", "action": "revoke_artifact"}]}
    )
    assert spec.compensation_plan is not None
    with pytest.raises(CompensationPlanBuildError, match="no resolved artifact digest"):
        plan_actions_from_spec(spec.compensation_plan.actions, {"workflow_graph": DIGEST_B})


# -- signed plan records -----------------------------------------------------


def test_signed_plan_verifies_and_round_trips() -> None:
    plan = _sign_plan()
    assert plan.verify() is True
    assert plan.plan_digest.startswith("sha256:")
    assert [action["artifact_digest"] for action in plan.actions] == [DIGEST_A, DIGEST_B]


def test_edited_plan_body_fails_verification() -> None:
    plan = _sign_plan()
    # Editing the body under the old digest is tampering: the bytes no
    # longer hash to the plan's digest, so the signature cannot verify.
    tampered_actions = [dict(action) for action in plan.actions]
    tampered_actions[1]["executed"] = True
    forged = SignedCompensationPlan(
        plan_id=plan.plan_id,
        campaign_id=plan.campaign_id,
        manifest_digest=plan.manifest_digest,
        actions=tuple(tampered_actions),
        plan_digest=plan.plan_digest,
        signature=plan.signature,
        signer_public_key=plan.signer_public_key,
    )
    assert forged.verify() is False


def test_signature_under_a_foreign_public_key_fails_verification() -> None:
    """A signature made by key A does not verify under key B — swapping the
    attached public key (claiming a different signer) is detected."""
    plan = _sign_plan(private_key=Ed25519PrivateKey.generate())
    foreign_key = Ed25519PrivateKey.generate()
    forged = SignedCompensationPlan(
        plan_id=plan.plan_id,
        campaign_id=plan.campaign_id,
        manifest_digest=plan.manifest_digest,
        actions=plan.actions,
        plan_digest=plan.plan_digest,
        signature=plan.signature,
        signer_public_key=foreign_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
    )
    assert forged.verify() is False


# -- checkpoint-pattern persistence ------------------------------------------


def test_plan_store_round_trips_through_the_content_address() -> None:
    store = CompensationPlanStore(InMemoryCheckpointStore())
    plan = _sign_plan()
    digest = store.save(plan)
    loaded = store.load(digest)
    assert loaded == plan
    assert loaded.verify() is True


def test_plan_store_refuses_tampered_stored_bytes() -> None:
    checkpoints = InMemoryCheckpointStore()
    store = CompensationPlanStore(checkpoints)
    digest = store.save(_sign_plan())
    checkpoints.corrupt(digest, b'{"plan_id": "forged"}')
    with pytest.raises(CompensationPlanTamperedError, match="content address"):
        store.load(digest)


def test_plan_store_refuses_a_body_edited_after_signing() -> None:
    checkpoints = InMemoryCheckpointStore()
    store = CompensationPlanStore(checkpoints)
    plan = _sign_plan()
    digest = store.save(plan)
    # Corrupt the stored envelope so it hashes to a *new* address, then load
    # it under that new address: the content-address check passes, the
    # signature check must still refuse it.
    payload = checkpoints.load(digest)
    doctored = payload.replace(b'"plan-1"', b'"plan-2"', 1)
    new_digest = checkpoints.store(doctored, schema_id="evoruntime.compensation.plan/v1")
    with pytest.raises(CompensationPlanTamperedError, match="digest or signature"):
        store.load(new_digest)


# -- promotion gating --------------------------------------------------------


def test_all_cas_plan_promotes_with_no_execution_evidence() -> None:
    plan = _sign_plan(
        [
            {
                "artifact_digest": DIGEST_A,
                "action": CompensationActionKind.RESTORE_PRIOR_RELEASE_POINTER.value,
                "mode": CAS_MODE,
                "executed": False,
            }
        ]
    )
    assert_promotion_allowed(plan, ())  # CAS actions ride the pointer rollback.


def test_unexecuted_requires_execution_compensation_blocks_promotion() -> None:
    plan = _sign_plan()
    with pytest.raises(UnexecutedCompensationError) as excinfo:
        assert_promotion_allowed(plan, ())
    assert excinfo.value.action_index == 1
    assert excinfo.value.action == CompensationActionKind.RUN_COMPENSATION_HOOK.value


def test_executed_requires_execution_compensation_allows_promotion() -> None:
    plan = _sign_plan()
    sink = InMemoryExecutionSink()
    sink.append(
        CompensationExecutionRecord(
            plan_id=plan.plan_id,
            action_index=1,
            artifact_digest=DIGEST_B,
            at=0.0,
        )
    )
    assert_promotion_allowed(plan, sink.all())


def test_tampered_plan_refuses_to_gate_promotion() -> None:
    plan = _sign_plan()
    tampered = SignedCompensationPlan(
        plan_id=plan.plan_id,
        campaign_id=plan.campaign_id,
        manifest_digest=plan.manifest_digest,
        actions=tuple([dict(action) for action in plan.actions][::-1]),
        plan_digest=plan.plan_digest,
        signature=plan.signature,
        signer_public_key=plan.signer_public_key,
    )
    with pytest.raises(CompensationPlanTamperedError, match="digest or signature"):
        assert_promotion_allowed(tampered, ())


def test_execution_records_from_other_plans_do_not_discharge_this_plan() -> None:
    plan = _sign_plan()
    other = _sign_plan(plan_id="plan-2")
    sink = InMemoryExecutionSink()
    for record in execute_rollback_compensations(other, _RecordingExecutor()):
        sink.append(record)
    with pytest.raises(UnexecutedCompensationError):
        assert_promotion_allowed(plan, sink.all())


# -- rollback execution ------------------------------------------------------


def test_rollback_executes_declared_compensations_in_order_skipping_cas() -> None:
    plan = _sign_plan(
        [
            {
                "artifact_digest": DIGEST_A,
                "action": CompensationActionKind.RUN_COMPENSATION_HOOK.value,
                "mode": REQUIRES_EXECUTION_MODE,
                "executed": False,
            },
            {
                "artifact_digest": DIGEST_B,
                "action": CompensationActionKind.REVOKE_ARTIFACT.value,
                "mode": CAS_MODE,
                "executed": False,
            },
            {
                "artifact_digest": DIGEST_B,
                "action": CompensationActionKind.RUN_COMPENSATION_HOOK.value,
                "mode": REQUIRES_EXECUTION_MODE,
                "executed": False,
            },
        ]
    )
    executor = _RecordingExecutor()
    records = execute_rollback_compensations(plan, executor)
    # Declared order, CAS action skipped: hooks at positions 0 and 2 ran.
    assert executor.calls == [
        (0, CompensationActionKind.RUN_COMPENSATION_HOOK.value),
        (2, CompensationActionKind.RUN_COMPENSATION_HOOK.value),
    ]
    assert [record.action_index for record in records] == [0, 2]
    assert all(record.plan_id == plan.plan_id for record in records)


def test_failing_compensation_aborts_the_walk_and_keeps_promotion_blocked() -> None:
    plan = _sign_plan(
        [
            {
                "artifact_digest": DIGEST_A,
                "action": CompensationActionKind.RUN_COMPENSATION_HOOK.value,
                "mode": REQUIRES_EXECUTION_MODE,
                "executed": False,
            },
            {
                "artifact_digest": DIGEST_B,
                "action": CompensationActionKind.RUN_COMPENSATION_HOOK.value,
                "mode": REQUIRES_EXECUTION_MODE,
                "executed": False,
            },
        ]
    )
    executor = _RecordingExecutor(fail_at_index=1)
    with pytest.raises(RuntimeError, match="hook 1 failed"):
        execute_rollback_compensations(plan, executor)
    assert [index for index, _ in executor.calls] == [0]


# -- orchestrator hooks ------------------------------------------------------


def _orchestrator_at_approve(gate: CheckpointedCompensationGate) -> CampaignOrchestrator:
    orchestrator = CampaignOrchestrator(
        make_pinned_spec(),
        checkpoints=InMemoryCheckpointStore(),
        compensation_gate=gate,
    )
    for phase in (
        CampaignPhase.PLAN,
        CampaignPhase.PROPOSE,
        CampaignPhase.DEV_EVALUATE,
        CampaignPhase.SELECT_FREEZE,
        CampaignPhase.HOLDOUT,
        CampaignPhase.APPROVE,
    ):
        orchestrator.transition(phase)
    return orchestrator


def test_approve_canary_refused_while_requires_execution_compensation_unexecuted() -> None:
    plan = _sign_plan()
    sink = InMemoryExecutionSink()
    gate = CheckpointedCompensationGate(plan, executions=sink, executor=_RecordingExecutor())
    orchestrator = _orchestrator_at_approve(gate)
    with pytest.raises(UnexecutedCompensationError):
        orchestrator.transition(CampaignPhase.CANARY)
    # The refusal leaves the campaign in APPROVE with no transition appended.
    assert orchestrator.phase is CampaignPhase.APPROVE
    assert orchestrator.transitions[-1].to_phase is CampaignPhase.APPROVE


def test_approve_canary_passes_after_compensations_are_executed() -> None:
    plan = _sign_plan()
    sink = InMemoryExecutionSink()
    gate = CheckpointedCompensationGate(plan, executions=sink, executor=_RecordingExecutor())
    orchestrator = _orchestrator_at_approve(gate)
    for record in execute_rollback_compensations(plan, _RecordingExecutor()):
        sink.append(record)
    orchestrator.transition(CampaignPhase.CANARY)
    assert orchestrator.phase is CampaignPhase.CANARY


def test_rollback_edge_executes_declared_compensations_in_order() -> None:
    plan = _sign_plan(
        [
            {
                "artifact_digest": DIGEST_A,
                "action": CompensationActionKind.RUN_COMPENSATION_HOOK.value,
                "mode": REQUIRES_EXECUTION_MODE,
                "executed": False,
            },
            {
                "artifact_digest": DIGEST_B,
                "action": CompensationActionKind.REVOKE_ARTIFACT.value,
                "mode": CAS_MODE,
                "executed": False,
            },
            {
                "artifact_digest": DIGEST_B,
                "action": CompensationActionKind.RUN_COMPENSATION_HOOK.value,
                "mode": REQUIRES_EXECUTION_MODE,
                "executed": False,
            },
        ]
    )
    sink = InMemoryExecutionSink()
    executor = _RecordingExecutor()
    gate = CheckpointedCompensationGate(plan, executions=sink, executor=executor)
    orchestrator = _orchestrator_at_approve(gate)
    orchestrator.transition(CampaignPhase.ROLLED_BACK)
    assert orchestrator.phase is CampaignPhase.ROLLED_BACK
    # Declared order, CAS skipped, evidence recorded.
    assert [index for index, _ in executor.calls] == [0, 2]
    assert [record.action_index for record in sink.all()] == [0, 2]


def test_campaign_without_a_compensation_plan_transitions_freely() -> None:
    orchestrator = CampaignOrchestrator(make_pinned_spec(), checkpoints=InMemoryCheckpointStore())
    for phase in (
        CampaignPhase.PLAN,
        CampaignPhase.PROPOSE,
        CampaignPhase.DEV_EVALUATE,
        CampaignPhase.SELECT_FREEZE,
        CampaignPhase.HOLDOUT,
        CampaignPhase.APPROVE,
        CampaignPhase.CANARY,
        CampaignPhase.PROMOTED,
        CampaignPhase.LEARN,
    ):
        orchestrator.transition(phase)
    assert orchestrator.phase is CampaignPhase.LEARN


def test_invalid_rollback_edge_still_refused_by_the_machine() -> None:
    """The gate fires only after the edge is known legal — an illegal edge
    is refused by the machine before any compensation runs."""
    plan = _sign_plan()
    executor = _RecordingExecutor()
    gate = CheckpointedCompensationGate(plan, executions=InMemoryExecutionSink(), executor=executor)
    orchestrator = CampaignOrchestrator(
        make_pinned_spec(),
        checkpoints=InMemoryCheckpointStore(),
        compensation_gate=gate,
    )
    with pytest.raises(InvalidTransitionError):
        orchestrator.transition(CampaignPhase.ROLLED_BACK)
    assert executor.calls == []


# -- spec-level integration --------------------------------------------------


def test_full_pipeline_spec_to_signed_plan_to_gate() -> None:
    """End to end: a spec's declared plan builds into record actions, signs,
    persists through the checkpoint store, and loads back verifiable."""
    spec = _v2_two_artifact_spec(
        {
            "actions": [
                {"artifact_type": "prompt_bundle", "action": "revoke_artifact"},
                {
                    "artifact_type": "workflow_graph",
                    "action": "run_compensation_hook",
                    "hook_image": "ghcr.io/evoruntime/comp-hook@sha256:" + "e" * 64,
                },
            ]
        }
    )
    assert spec.compensation_plan is not None
    actions = plan_actions_from_spec(
        spec.compensation_plan.actions,
        {"prompt_bundle": DIGEST_A, "workflow_graph": DIGEST_B},
    )
    plan = _sign_plan(actions)
    store = CompensationPlanStore(InMemoryCheckpointStore())
    loaded = store.load(store.save(plan))
    assert loaded == plan
    assert loaded.verify() is True

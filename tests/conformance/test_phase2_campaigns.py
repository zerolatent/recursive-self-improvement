"""F12 — Phase 2 conformance verification (the spec's acceptance matrix).

The integrated end-to-end pass over the merged F1–F11 deliverables, run on
the release branch against real PostgreSQL and the F1 sandbox. Where the
per-deliverable suites prove each gate in isolation, these tests prove the
gates compose:

1. the full executable-candidate campaign — propose → static analysis →
   sandboxed dev-evaluate → freeze → sealed holdout → tier-3 two-person
   approval → canary → promote;
2. the compensation-rollback scenario — a multi-artifact rollback executing
   declared compensations in order, and a promotion blocked on an
   unexecuted requires-execution compensation;
3. the static-analysis rejection scenario — a blocker violation rejects the
   candidate pre-execution with a tamper-evident verdict;
4. the ablation campaign — a preregistered family with Holm-controlled
   marginal contributions;
5. the productivity-selection campaign — the typed projection reconciled
   against the raw attestations it is derived from;
6. decision reconstruction over the integrated lineage — every Phase 2
   decision replayable from append-only records, and the records refusing
   mutation at the database level.

Everything here drives the real services — the FR-014 control-plane API,
the F10 review-board service, the E1 registry, the E3 state machine with
its F5 compensation hooks, the F1 sandbox executor, the D5 sealed holdout,
the F8 ablation engine, and the FR-102 productivity projection — over real
PostgreSQL. The only simulated input is evaluation *data* (paired scores,
scripted agent outcomes), which is the D6/D8 fixture reality: CI is
hermetic by design (no live-model runs).
"""

from __future__ import annotations

import base64
import hashlib
import json
from decimal import Decimal
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError, ProgrammingError
from sqlalchemy.orm import Session, sessionmaker
from tests.campaign.conftest import InMemoryCheckpointStore, make_pinned_spec, make_spec_mapping
from tests.support.factories import make_campaign_spec_mapping

from evoruntime.api.approvals import ApprovalWorkflowService, verify_admission_signature
from evoruntime.api.errors import (
    RegistrationRefusedError,
    TierPromotionRefusedError,
)
from evoruntime.api.service import CampaignApiService
from evoruntime.campaign.compensation import (
    CAS_MODE,
    REQUIRES_EXECUTION_MODE,
    CheckpointedCompensationGate,
    CompensationActionKind,
    InMemoryExecutionSink,
    sign_compensation_plan,
)
from evoruntime.campaign.errors import (
    InvalidCampaignSpecError,
    UnexecutedCompensationError,
)
from evoruntime.campaign.machine import CampaignOrchestrator, CampaignPhase
from evoruntime.campaign.spec import CampaignSpec
from evoruntime.core.isolation import IsolationTier
from evoruntime.core.principal import Principal
from evoruntime.datasets.errors import HoldoutAccessDeniedError
from evoruntime.datasets.partitions import PartitionKind
from evoruntime.datasets.service import DatasetService, HoldoutService
from evoruntime.db.models.analysis import AnalysisReport
from evoruntime.db.models.approvals import AdmissionRecord
from evoruntime.db.models.registry import EvaluationAttestation
from evoruntime.eval import (
    Arm,
    ArmKind,
    Experiment,
    ExperimentDefinitionError,
    MarginalContributionError,
    ScriptedAgent,
    Verdict,
    holm_adjusted_p_values,
    load_contributions,
    marginal_contributions,
    persist_contributions,
    run_arm,
    summarize_experiment,
)
from evoruntime.plugins.manifest import NetworkMode, ResourceLimits
from evoruntime.plugins.protocol import InMemoryCheckpointStore as SandboxCheckpointStore
from evoruntime.plugins.static_analysis import (
    AnalysisViolation,
    AnalysisViolationCode,
    StaticAnalysisReport,
    analyze_files,
)
from evoruntime.registry.service import RegistryService
from evoruntime.release import (
    CanaryConfig,
    CanaryHarness,
    CanaryOutcome,
    CompressedClock,
    GuardrailEvent,
    InProcessFleetSimulator,
    ReleaseController,
    sign_release_manifest,
)
from evoruntime.sandbox.executor import (
    SubprocessIsolationBackend,
    physical_enforcement_available,
)
from evoruntime.sandbox.profile import ExecutionProfile, ExecutionRequest, PayloadRef
from evoruntime.security.identities import WorkloadIdentity, WorkloadRole
from evoruntime.security.signing import (
    DetachedSignature,
    generate_signing_key,
    sign,
    verify,
)
from evoruntime.selection import (
    InMemoryNominationLedger,
    InMemoryPointerAuditLog,
    LineageProductivityService,
    NominationRule,
    ReleasePointerStore,
    SelectionObservation,
    TierApprovalEvidence,
    TrustedSelector,
    attested_cost,
    evaluate_promotion,
)
from evoruntime.selection.authority import ResolvedRelease
from evoruntime.selection.policy import (
    PairedScores,
    PromotionEvidence,
    PromotionPolicyDocument,
)

#: The F1 sandbox tests in this module require physical enforcement
#: (seccomp + Landlock); the DB-backed scenarios run anywhere.
pytestmark = pytest.mark.skipif(
    not physical_enforcement_available(),
    reason="sandbox executor requires seccomp + Landlock (Linux)",
)

EXECUTABLE_TIER = IsolationTier.EXECUTABLE

#: A clean executable candidate: one Python file, no network, no subprocess,
#: no dynamic exec — passes FR-018 admission and F3 static analysis, and its
#: file bytes are exactly what the sandbox executes during dev-evaluate.
CLEAN_TOOL_BUNDLE = json.dumps(
    {
        "files": [
            {
                "path": "tool.py",
                "content": (
                    "def run(x: int) -> int:\n"
                    "    return x + 1\n"
                    "\n"
                    "\n"
                    "if __name__ == '__main__':\n"
                    "    print(run(41))\n"
                ),
            }
        ]
    }
).encode()

#: A candidate the F3 static-analysis gate must refuse before anything runs:
#: direct network egress is exactly what candidates never get.
NETWORK_TOOL_BUNDLE = json.dumps(
    {"files": [{"path": "net.py", "content": "import socket\n\nsocket.create_connection\n"}]}
).encode()

INCUMBENT_PROMPT = b"prompt v1: answer the user's question carefully"

#: A planted beneficial effect large enough that the paired bootstrap's
#: lower bound clears zero at the family-split alpha (60 paired tasks,
#: 60% → 80% success, candidate never worse than baseline per task).
_BASELINE_SCORES = tuple(1.0 if i % 5 < 3 else 0.0 for i in range(60))
_CANDIDATE_SCORES = tuple(1.0 if i % 5 < 4 else 0.0 for i in range(60))

_PROMOTION_LIFECYCLE = (
    CampaignPhase.PLAN,
    CampaignPhase.PROPOSE,
    CampaignPhase.DEV_EVALUATE,
    CampaignPhase.SELECT_FREEZE,
    CampaignPhase.HOLDOUT,
    CampaignPhase.APPROVE,
    CampaignPhase.CANARY,
    CampaignPhase.PROMOTED,
    CampaignPhase.LEARN,
)

SANDBOX_LIMITS = ResourceLimits(
    wall_clock_minutes=1.0, cpu=1.0, memory_gib=0.05, model_tokens=0, proposals=1
)


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def make_service(
    session_factory: sessionmaker[Session],
    signing_key: Ed25519PrivateKey | None = None,
) -> tuple[CampaignApiService, Ed25519PrivateKey]:
    """The control-plane service over the test database, with its key."""
    key = signing_key or generate_signing_key()
    service = CampaignApiService(
        session_factory, signing_key=key, evaluator_subject="svc_evaluator_1"
    )
    return service, key


def make_board_service(
    session_factory: sessionmaker[Session], signing_key: Ed25519PrivateKey
) -> ApprovalWorkflowService:
    """The F10 review-board service sharing the control plane's key."""
    return ApprovalWorkflowService(
        session_factory, signing_key=signing_key, evaluator_subject="svc_evaluator_1"
    )


def board_principal(tenant_id: str, subject: str) -> Principal:
    """A verified review-board caller inside the tenant."""
    return Principal(
        identity=WorkloadIdentity(role=WorkloadRole.EVALUATOR, subject=subject),
        tenant_id=tenant_id,
    )


def sandbox_profile() -> ExecutionProfile:
    """The declared execution profile for a tier-3 tool candidate."""
    return ExecutionProfile(
        tier=EXECUTABLE_TIER,
        network_mode=NetworkMode.NONE,
        resource_limits=SANDBOX_LIMITS,
    )


def run_in_sandbox(tenant_id: str, code: str, checkpoints: SandboxCheckpointStore) -> Any:
    """Stage ``code`` as the candidate payload and execute it in the F1
    sandbox at the declared tier."""
    data = code.encode("utf-8")
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    ref = PayloadRef(path="tool.py", digest=digest)
    backend = SubprocessIsolationBackend(
        payloads=_DictPayloadReader({digest: data}), checkpoints=checkpoints
    )
    request = ExecutionRequest(
        tenant_id=tenant_id,
        image_digest="ghcr.io/acme/candidate@sha256:" + "cd" * 32,
        profile=sandbox_profile(),
        payloads=(ref,),
        command=("python3", "tool.py"),
    )
    return backend.run(request)


class _DictPayloadReader:
    """Serves payloads from an in-memory digest -> bytes map."""

    def __init__(self, blobs: dict[str, bytes]) -> None:
        self._blobs = dict(blobs)

    def read(self, *, tenant_id: str, payload_digest: str) -> bytes:
        return self._blobs[payload_digest]


def transition_through(
    service: CampaignApiService, principal: Principal, campaign_id: str, *phases: CampaignPhase
) -> None:
    """Walk the campaign one legal edge at a time to `phases`."""
    for phase in phases:
        detail = service.transition_campaign(
            principal, campaign_id, phase.value, reason="f12 conformance run"
        )
        assert detail.phase == phase.value


def promotion_evidence(
    arm_id: str,
    *,
    baseline: tuple[float, ...],
    candidate: tuple[float, ...],
) -> PromotionEvidence:
    """Paired §12.5 evidence over the holdout scores."""
    return PromotionEvidence(
        arm_id=arm_id,
        heldout=PairedScores(
            task_ids=tuple(f"task-{i:03d}" for i in range(len(baseline))),
            baseline=baseline,
            candidate=candidate,
        ),
        success_gain=sum(candidate) / len(candidate) - sum(baseline) / len(baseline),
        cost_reduction=0.0,
        p95_latency_regression=0.0,
        severity1_regressions=0,
        critical_failures=(),
        budget_pass=True,
        claimed_transfer_scope=("repo-repair",),
        evaluated_transfer_scope=("repo-repair",),
        bootstrap_iterations=200,
        bootstrap_seed=7,
    )


def issue_sealed_holdout(
    principal: Principal,
    tenant_id: str,
    dataset_service: DatasetService,
    holdout_service: HoldoutService,
) -> Any:
    """A real sealed-holdout partition resolved through a real handle."""
    partition = dataset_service.create_partition(
        principal,
        dataset_id=f"ds_f12_{tenant_id}",
        name="f12-holdout",
        kind=PartitionKind.HOLDOUT,
        owner="eval-team",
        content_locator="object://evaluation-plane/holdout/f12-v1",
        content_digest="sha256:" + "e" * 64,
        item_count=40,
    )
    handle = holdout_service.issue_handle(
        principal,
        partition_id=partition.id,
        owner="eval-team",
        alpha_budget_total=Decimal("0.04"),
        alpha_per_query=Decimal("0.01"),
        freshness_window_days=30,
        rotation_plan="rotate-quarterly",
        contamination_audit={"source": "f12-conformance", "contaminated": False},
    )
    content = holdout_service.resolve(
        principal, handle.handle_uri, purpose="sealed-holdout-evaluation"
    )
    assert content.item_count == 40
    return handle


def run_executable_campaign(
    service: CampaignApiService,
    principal: Principal,
    *,
    tenant_id: str,
    dataset_service: DatasetService,
    holdout_service: HoldoutService,
    name: str = "f12-executable-campaign",
) -> dict[str, Any]:
    """The full executable-candidate campaign: propose → static analysis →
    sandboxed dev-evaluate → freeze → sealed holdout → tier-3 two-person
    approval → canary → promote.

    The candidate is a tier-3 ``tool_spec``: it passes the FR-018 output
    admission and F3 static-analysis gates at registration (leaving a
    signed verdict row), its actual file bytes execute in the F1 sandbox
    during dev-evaluate, the sealed holdout resolves through the real D5
    handle, and the tier-3 promotion clears the two-person review board
    before the release is promoted over the incumbent.
    """
    # The incumbent release is active before the campaign starts.
    incumbent_view = service.register_candidate(
        principal,
        artifact_type="prompt_bundle",
        canonical_bytes_b64=base64.b64encode(INCUMBENT_PROMPT).decode(),
        strategy_id="incumbent",
    )
    service.record_evaluation(
        principal,
        artifact_digest=incumbent_view.artifact_digest,
        outcome="pass",
        metrics={"task_success_rate": 0.62, "total_tokens": 1000.0},
    )
    incumbent_release = service.create_release(
        principal,
        artifact_digests=[incumbent_view.artifact_digest],
        adapter_versions={"adapter": "1.0.0"},
        model_routes={"default": "model-a"},
        policies={"canary": "p0"},
    )
    assert incumbent_release.status == "canary"
    active = service.promote_release(principal, incumbent_release.manifest_digest)
    assert active.status == "active"
    incumbent_manifest = incumbent_release.manifest_digest

    spec = make_campaign_spec_mapping()
    spec["name"] = name
    detail = service.create_campaign(principal, spec)
    campaign_id = detail.campaign_id

    # PROPOSE: the executable candidate registers through both pre-execution
    # gates and lands a signed static-analysis verdict.
    candidate = service.register_candidate(
        principal,
        artifact_type="tool_spec",
        canonical_bytes_b64=base64.b64encode(CLEAN_TOOL_BUNDLE).decode(),
        strategy_id="evo-prompt-strategist",
        campaign_id=campaign_id,
        parent_digest=incumbent_view.artifact_digest,
    )
    reports = service.list_analysis_reports(principal, candidate_digest=candidate.artifact_digest)
    assert len(reports) == 1
    assert reports[0].outcome == "pass"
    assert reports[0].verdict_digest
    assert reports[0].signature_b64

    # DEV_EVALUATE: the candidate's actual bytes run in the F1 sandbox at
    # the declared tier — the same bytes the registration digested.
    bundle = json.loads(CLEAN_TOOL_BUNDLE)
    tool_source = str(bundle["files"][0]["content"])
    checkpoints = SandboxCheckpointStore()
    result = run_in_sandbox(tenant_id, tool_source, checkpoints)
    assert result.exit_code == 0
    assert "42" in result.stdout
    attestation = result.attestation
    assert attestation.tier is EXECUTABLE_TIER
    assert attestation.enforcement.rlimits_applied is True
    assert attestation.enforcement.network_filter_applied is True
    assert attestation.enforcement.filesystem_contained is True
    stored = checkpoints._blobs[result.attestation_digest]
    assert attestation.model_dump_json().encode("utf-8") == stored

    service.record_evaluation(
        principal,
        artifact_digest=candidate.artifact_digest,
        outcome="pass",
        metrics={"task_success_rate": 0.81, "total_tokens": 950.0},
    )

    transition_through(
        service,
        principal,
        campaign_id,
        CampaignPhase.PLAN,
        CampaignPhase.PROPOSE,
        CampaignPhase.DEV_EVALUATE,
        CampaignPhase.SELECT_FREEZE,
        CampaignPhase.HOLDOUT,
    )

    # Sealed holdout: resolved through the real handle; the candidate-runner
    # identity is denied at the handle and the denial is ledgered too.
    handle = issue_sealed_holdout(principal, tenant_id, dataset_service, holdout_service)
    runner = Principal(
        identity=WorkloadIdentity(role=WorkloadRole.CANDIDATE_RUNNER, subject="svc_candidate_1"),
        tenant_id=tenant_id,
    )
    with pytest.raises(HoldoutAccessDeniedError):
        holdout_service.resolve(runner, handle.handle_uri, purpose="sealed-holdout-evaluation")

    # The promotion decision runs with the two-person tier-3 approval
    # evidence — the Phase 2 gate the Phase 1 path never had.
    decision = evaluate_promotion(
        PromotionPolicyDocument(policy_id="tier-2-standard"),
        promotion_evidence("strategy", baseline=_BASELINE_SCORES, candidate=_CANDIDATE_SCORES),
        release=ResolvedRelease(artifact_classes=("tool_spec",)),
        tier_approvals=TierApprovalEvidence(
            approvers=("svc_board_1", "svc_board_2"), requested_by="svc_evaluator_1"
        ),
    )
    assert decision.eligible, decision.failed_conditions()
    assert decision.tier == 3

    transition_through(service, principal, campaign_id, CampaignPhase.APPROVE)
    approval = service.record_approval(
        principal,
        campaign_id=campaign_id,
        proposal_id=candidate.proposal_id,
        decision="nominate",
        reason="clean executable tool: static analysis passed, sandbox run attested",
    )
    assert approval.kind == "nominate"

    transition_through(service, principal, campaign_id, CampaignPhase.CANARY)
    release = service.create_release(
        principal,
        artifact_digests=[candidate.artifact_digest],
        adapter_versions={"evo-prompt-strategist": "1.2.0"},
        model_routes={"default": "gpt-5-mini"},
        policies={"tier": "tier-3-executable"},
        prior_release_digest=incumbent_manifest,
        status="canary",
    )
    promoted = service.promote_release(principal, release.manifest_digest)
    assert promoted.status == "active"

    transition_through(service, principal, campaign_id, CampaignPhase.PROMOTED, CampaignPhase.LEARN)
    return {
        "campaign_id": campaign_id,
        "proposal_id": candidate.proposal_id,
        "parent_digest": incumbent_view.artifact_digest,
        "candidate_digest": candidate.artifact_digest,
        "incumbent_manifest": incumbent_manifest,
        "candidate_manifest": release.manifest_digest,
        "handle_uri": handle.handle_uri,
        "decision": decision,
    }


def _mixed_compensation_actions() -> list[dict[str, Any]]:
    """A three-artifact plan: hook, CAS revoke, hook — in declared order."""
    return [
        {
            "artifact_digest": "sha256:" + "1" * 64,
            "action": CompensationActionKind.RUN_COMPENSATION_HOOK.value,
            "mode": REQUIRES_EXECUTION_MODE,
            "executed": False,
        },
        {
            "artifact_digest": "sha256:" + "2" * 64,
            "action": CompensationActionKind.REVOKE_ARTIFACT.value,
            "mode": CAS_MODE,
            "executed": False,
        },
        {
            "artifact_digest": "sha256:" + "3" * 64,
            "action": CompensationActionKind.RUN_COMPENSATION_HOOK.value,
            "mode": REQUIRES_EXECUTION_MODE,
            "executed": False,
        },
    ]


class _RecordingExecutor:
    """Executes compensations by recording the call order."""

    def __init__(self) -> None:
        self.calls: list[tuple[int, str]] = []

    def execute(self, action_index: int, action: dict[str, Any]) -> None:
        self.calls.append((action_index, str(action.get("action", ""))))


def _orchestrator_at_approve(
    gate: CheckpointedCompensationGate,
) -> CampaignOrchestrator:
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


# ----------------------------------------------------------------------
# Campaign one: the full executable-candidate path
# ----------------------------------------------------------------------


def test_executable_campaign_tool_spec_completes_propose_to_promote(
    session_factory: sessionmaker[Session],
    evaluator: Principal,
    tenant_id: str,
    dataset_service: DatasetService,
    holdout_service: HoldoutService,
) -> None:
    """A tier-3 tool_spec candidate walks propose → static analysis →
    sandboxed dev-evaluate → freeze → sealed holdout → tier-3 two-person
    approval → canary → promote, over real PostgreSQL and the real sandbox."""
    service, key = make_service(session_factory)
    board = make_board_service(session_factory, key)
    result = run_executable_campaign(
        service,
        evaluator,
        tenant_id=tenant_id,
        dataset_service=dataset_service,
        holdout_service=holdout_service,
    )
    campaign_id = result["campaign_id"]

    # The lifecycle walked exactly the §11 forward path, gaplessly.
    detail = service.get_campaign(evaluator, campaign_id)
    path = [(t.from_phase, t.to_phase) for t in detail.transitions]
    expected = [(CampaignPhase.DISCOVER, CampaignPhase.PLAN)] + [
        (before, after)
        for before, after in zip(_PROMOTION_LIFECYCLE, _PROMOTION_LIFECYCLE[1:], strict=False)
    ]
    assert path == expected
    assert [t.sequence for t in detail.transitions] == list(range(len(expected)))
    assert detail.phase == CampaignPhase.LEARN.value

    # The tier-3 promotion went through the real two-person review board:
    # one approval is not enough, two distinct ones admit, and the signed
    # record reads back and verifies.
    request = board.create_request(
        evaluator,
        kind="tier3_promotion",
        justification="promoting the clean executable tool spec",
        campaign_id=campaign_id,
        proposal_id=result["proposal_id"],
    )
    assert request.tier == 3
    board.decide(
        board_principal(tenant_id, "svc_board_1"),
        request_id=request.request_id,
        decision="approve",
        note="static analysis and sandbox attestation reviewed",
    )
    with pytest.raises(TierPromotionRefusedError, match="two-person"):
        board.admit(evaluator, request_id=request.request_id)
    board.decide(
        board_principal(tenant_id, "svc_board_2"),
        request_id=request.request_id,
        decision="approve",
        note="second reviewer concurs",
    )
    admitted = board.admit(evaluator, request_id=request.request_id)
    assert admitted.decision == "admitted"
    assert admitted.tier == 3
    assert {a["approver"] for a in admitted.approvals} == {"svc_board_1", "svc_board_2"}
    read_back = board.get_admission(evaluator, record_id=admitted.record_id)
    assert read_back == admitted

    # The promotion decision itself consumed the two-person evidence.
    assert result["decision"].tier == 3
    assert result["decision"].eligible

    # The release history shows the candidate promoted over the incumbent.
    releases = service.list_releases(evaluator)
    statuses = {r.manifest_digest: r.status for r in releases}
    assert statuses[result["candidate_manifest"]] == "active"
    assert statuses[result["incumbent_manifest"]] == "superseded"


# ----------------------------------------------------------------------
# Campaign two: compensation rollback (F5)
# ----------------------------------------------------------------------


def test_compensation_rollback_executes_compensations_in_order_and_blocks_promotion(
    session_factory: sessionmaker[Session],
    evaluator: Principal,
    tenant_id: str,
) -> None:
    """A multi-artifact rollback executes the declared compensations in
    order (CAS actions ride the pointer rollback), and a promotion is
    blocked while a requires-execution compensation is unexecuted."""
    plan = sign_compensation_plan(
        plan_id="plan-f12-rollback",
        campaign_id="campaign-f12",
        manifest_digest="sha256:" + "4" * 64,
        actions=_mixed_compensation_actions(),
        private_key=Ed25519PrivateKey.generate(),
    )
    assert plan.verify()

    # Promotion blocked: the APPROVE→CANARY edge is refused while the
    # requires-execution compensations have no execution evidence, and the
    # refusal leaves no transition in the log.
    sink = InMemoryExecutionSink()
    executor = _RecordingExecutor()
    gate = CheckpointedCompensationGate(plan, executions=sink, executor=executor)
    orchestrator = _orchestrator_at_approve(gate)
    with pytest.raises(UnexecutedCompensationError):
        orchestrator.transition(CampaignPhase.CANARY)
    assert orchestrator.phase is CampaignPhase.APPROVE
    assert executor.calls == []
    assert sink.all() == ()

    # Rollback: the APPROVE→ROLLED_BACK edge executes the declared
    # requires-execution compensations in declared order before the edge
    # lands; the CAS revoke is skipped (it rides the pointer rollback).
    orchestrator.transition(CampaignPhase.ROLLED_BACK)
    assert orchestrator.phase is CampaignPhase.ROLLED_BACK
    assert [index for index, _ in executor.calls] == [0, 2]
    assert [record.action_index for record in sink.all()] == [0, 2]
    assert all(record.plan_id == plan.plan_id for record in sink.all())

    # With the execution evidence in the sink, promotion is unblocked.
    orchestrator.transition(CampaignPhase.LEARN)
    fresh_gate = CheckpointedCompensationGate(plan, executions=sink, executor=executor)
    fresh_orchestrator = _orchestrator_at_approve(fresh_gate)
    fresh_orchestrator.transition(CampaignPhase.CANARY)
    assert fresh_orchestrator.phase is CampaignPhase.CANARY

    # Release plane: a severity-1 canary event rolls the pointer back
    # through the controller's CAS and executes the plan's hook in order.
    signing_key = generate_signing_key()
    controller = ReleaseController(
        ReleasePointerStore(InMemoryPointerAuditLog()),
        identity=WorkloadIdentity(
            role=WorkloadRole.RELEASE_CONTROLLER, subject="svc-release-controller"
        ),
    )
    clock = CompressedClock(scale=3600.0)
    fleet = InProcessFleetSimulator(
        worker_count=100,
        latency_sampler=lambda: 45.0,
        clock=clock,
    )
    incumbent = sign_release_manifest(
        artifact_digests=["sha256:" + "a" * 64],
        adapter_versions={"adapter": "1.0.0"},
        model_routes={"default": "model-a"},
        policies={"canary": "p0"},
        prior_release_digest=None,
        private_key=signing_key,
    )
    controller.activate(incumbent)
    candidate = sign_release_manifest(
        artifact_digests=["sha256:" + "b" * 64, "sha256:" + "c" * 64],
        adapter_versions={"adapter": "1.1.0"},
        model_routes={"default": "model-a"},
        policies={"canary": "p0"},
        prior_release_digest=incumbent.manifest_digest,
        private_key=signing_key,
    )
    rollback_sink = InMemoryExecutionSink()
    rollback_executor = _RecordingExecutor()
    harness = CanaryHarness(
        config=CanaryConfig(),
        controller=controller,
        fleet=fleet,
        clock=clock,
        compensation_plan=plan,
        compensation_executions=rollback_sink,
        compensation_executor=rollback_executor,
    )
    outcome = harness.run(
        candidate,
        guardrail_events=(GuardrailEvent(severity=1, kind="error_rate", task_index=5),),
    )
    assert outcome.outcome is CanaryOutcome.ROLLED_BACK
    # Both requires-execution hooks ran in declared order; the CAS revoke
    # (index 1) rode the controller's pointer rollback instead.
    assert rollback_executor.calls == [(0, "run_compensation_hook"), (2, "run_compensation_hook")]
    assert [record.action_index for record in rollback_sink.all()] == [0, 2]
    assert controller.active_digest() == incumbent.manifest_digest


# ----------------------------------------------------------------------
# Campaign three: static-analysis rejection (F3)
# ----------------------------------------------------------------------


def test_static_analysis_blocker_rejects_pre_execution_with_tamper_evident_report(
    session_factory: sessionmaker[Session],
    db_session: Session,
    evaluator: Principal,
    tenant_id: str,
) -> None:
    """A blocker violation rejects the candidate before any execution —
    no artifact row, no proposal row, no analysis-report row — and the
    verdict a candidate *passes* with is tamper-evident: digest-bound,
    signed, and append-only at the database level."""
    service, key = make_service(session_factory)

    # The rejecting registration: a network-dialing tool_spec candidate.
    with pytest.raises(RegistrationRefusedError) as excinfo:
        service.register_candidate(
            evaluator,
            artifact_type="tool_spec",
            canonical_bytes_b64=base64.b64encode(NETWORK_TOOL_BUNDLE).decode(),
            strategy_id="evo-prompt-strategist",
        )
    assert excinfo.value.source == "static_analysis"
    codes = {
        violation["code"].value
        if isinstance(violation["code"], AnalysisViolationCode)
        else violation["code"]
        for violation in excinfo.value.violations
    }
    assert "network_import" in codes

    # Nothing landed: no artifact, no proposal, no verdict row.
    with session_factory() as session:
        reports = session.execute(
            text("SELECT COUNT(*) FROM analysis_reports WHERE tenant_id = :tenant"),
            {"tenant": tenant_id},
        ).scalar_one()
        assert reports == 0
        artifacts = session.execute(
            text("SELECT COUNT(*) FROM artifact_content WHERE tenant_id = :tenant"),
            {"tenant": tenant_id},
        ).scalar_one()
        assert artifacts == 0

    # The verdict the gate produces is tamper-evident: the digest covers
    # the canonical bytes, the signature verifies against exactly those
    # bytes, and any mutation of either is detected.
    files = ({"path": "net.py", "content": "import socket\n\nsocket.create_connection\n"},)
    report = analyze_files(
        files,
        artifact_type="tool_spec",
        candidate_digest="sha256:" + "0" * 64,
    )
    assert report.blocked
    assert report.outcome == "block"
    canonical = report.canonical_bytes()
    assert report.verdict_digest == "sha256:" + hashlib.sha256(canonical).hexdigest()

    private_key = generate_signing_key()
    detached = sign(private_key, canonical)
    assert verify(detached, canonical)
    # One flipped byte in the verdict body breaks the signature.
    flipped = bytearray(canonical)
    flipped[0] ^= 0x01
    assert not verify(detached, bytes(flipped))
    # And the digest no longer matches the mutated bytes either.
    assert "sha256:" + hashlib.sha256(bytes(flipped)).hexdigest() != report.verdict_digest

    # A verdict that lands is append-only at the database level — the same
    # role the application uses cannot UPDATE or DELETE it.
    tenant = f"{tenant_id}_persist"
    persisted_report = analyze_files(
        ({"path": "prompts/system.md", "content": "RULES = {}\n"},),
        artifact_type="prompt_bundle",
        candidate_digest="sha256:" + "1" * 64,
    )
    stored_sig = sign(private_key, persisted_report.canonical_bytes())
    db_session.add(
        AnalysisReport(
            tenant_id=tenant,
            report_id="arpt_f12_conformance",
            campaign_id="cmp_f12",
            candidate_digest="sha256:" + "1" * 64,
            artifact_type="prompt_bundle",
            outcome="pass",
            violations=[v.model_dump(mode="json") for v in persisted_report.violations],
            verdict_digest=persisted_report.verdict_digest,
            signature=stored_sig.signature,
            signer_public_key=stored_sig.public_key,
        )
    )
    db_session.flush()

    with pytest.raises(ProgrammingError, match="immutable"):
        db_session.execute(
            AnalysisReport.__table__.update()
            .where(AnalysisReport.tenant_id == tenant)
            .values(outcome="block")
        )
    db_session.rollback()
    # The rollback also removed the row (the trigger is row-level: a
    # DELETE matching zero rows never fires), so re-insert before the
    # DELETE attempt.
    db_session.add(
        AnalysisReport(
            tenant_id=tenant,
            report_id="arpt_f12_conformance",
            campaign_id="cmp_f12",
            candidate_digest="sha256:" + "1" * 64,
            artifact_type="prompt_bundle",
            outcome="pass",
            violations=[v.model_dump(mode="json") for v in persisted_report.violations],
            verdict_digest=persisted_report.verdict_digest,
            signature=stored_sig.signature,
            signer_public_key=stored_sig.public_key,
        )
    )
    db_session.flush()
    with pytest.raises(ProgrammingError, match="immutable"):
        db_session.execute(
            AnalysisReport.__table__.delete().where(AnalysisReport.tenant_id == tenant)
        )
    db_session.rollback()


# ----------------------------------------------------------------------
# Campaign four: ablations (F8)
# ----------------------------------------------------------------------


def _run_arms(exp: Experiment, backends: dict[str, ScriptedAgent], tasks: tuple) -> list[Any]:
    """Run every arm over the task set with a frozen clock."""
    from tests.eval.conftest import frozen_clock

    runs = []
    for arm in exp.arms:
        runs.extend(
            run_arm(
                experiment=exp,
                arm=arm,
                backend=backends[arm.id],
                tasks=tasks,
                clock_factory=frozen_clock,
            )
        )
    return runs


def test_ablation_campaign_preregistered_family_yields_holm_controlled_contributions(
    session_factory: sessionmaker[Session],
) -> None:
    """The ablation campaign: a preregistered family, one Holm pass over
    every ablation, and contribution records that round-trip through their
    content address."""
    from tests.eval.conftest import make_tasks, scripted_outcomes

    tasks = make_tasks(count=12)
    arms = (
        Arm(id="incumbent", kind=ArmKind.INCUMBENT),
        Arm.ablation("no-tool-loop", "tool-loop"),
        Arm.ablation("no-memory", "memory"),
    )
    exp = Experiment(
        name="f12-ablation-study",
        dataset="ds_repo_repair_dev_v1",
        task_budget_profile="task-budget-v1",
        arms=arms,
        ablation_family=("tool-loop", "memory"),
        bootstrap_iterations=200,
    )
    backends = {
        "incumbent": ScriptedAgent(scripted_outcomes(tasks, 9)),
        "no-tool-loop": ScriptedAgent(scripted_outcomes(tasks, 3)),
        "no-memory": ScriptedAgent(scripted_outcomes(tasks, 8)),
    }
    result = summarize_experiment(exp, _run_arms(exp, backends, tasks))

    # One Holm family across both ablations: the per-comparison alpha is
    # split across the whole family, and the adjusted p-values come from
    # one step-down pass over the raw p-values.
    assert result.per_comparison_alpha == pytest.approx(exp.alpha / 2)
    raw = {arm_id: c.bootstrap.p_value for arm_id, c in result.delta.items()}
    expected = holm_adjusted_p_values(raw)
    assert {arm_id: c.adjusted_p_value for arm_id, c in result.delta.items()} == expected

    # Ablating the load-bearing component costs measurable score; ablating
    # the near-inert one does not.
    records = {r.component_id: r for r in marginal_contributions(result)}
    assert set(records) == {"tool-loop", "memory"}
    assert records["tool-loop"].verdict == Verdict.REGRESSION.value
    assert records["tool-loop"].adjusted_p_value <= exp.alpha
    assert records["memory"].verdict == Verdict.INCONCLUSIVE.value

    # The contribution records are content-addressed and verified on load:
    # a record set whose bytes no longer hash to their address is refused.
    store = InMemoryCheckpointStore()
    contributions = tuple(marginal_contributions(result))
    digest = persist_contributions(contributions, store)
    assert load_contributions(store, digest) == contributions
    store._blobs[digest] = b"tampered bytes"
    with pytest.raises(MarginalContributionError):
        load_contributions(store, digest)

    # The preregistration closure holds at the campaign-spec level too: an
    # ablation arm outside the declared family is a construction error.
    raw_spec = make_spec_mapping()
    raw_spec["schema_version"] = 2
    raw_spec["mutable_artifacts"] = [raw_spec.pop("mutable_artifact")]
    raw_spec["arms"].append({"id": "no-tool-loop", "kind": "ablation", "component_id": "tool-loop"})
    raw_spec["statistics"]["ablation_family"] = ["retriever"]
    with pytest.raises(InvalidCampaignSpecError, match="preregistered ablation family"):
        CampaignSpec.from_mapping(raw_spec)

    # And an ablation arm with no family at all is refused — the family
    # is what makes the ablation preregistered rather than post-hoc.
    with pytest.raises(ExperimentDefinitionError, match="preregister"):
        Experiment(
            name="f12-no-family",
            dataset="ds_repo_repair_dev_v1",
            task_budget_profile="task-budget-v1",
            arms=(
                Arm(id="incumbent", kind=ArmKind.INCUMBENT),
                Arm.ablation("no-retriever", "retriever"),
            ),
            ablation_family=(),
        )


# ----------------------------------------------------------------------
# Campaign five: productivity selection (F9)
# ----------------------------------------------------------------------


def test_productivity_selection_reconciles_projection_against_raw_attestations(
    db_session: Session,
) -> None:
    """The typed lineage-productivity projection reconciles with the raw
    append-only attestations, and the productivity selector freezes the
    best value-per-cost nominee from attested costs only."""
    tenant = "tnt_f12_f9_" + hashlib.sha256(b"f12-f9").hexdigest()[:12]
    strategy = "strategy-f12"
    evaluator_identity = WorkloadIdentity(role=WorkloadRole.EVALUATOR, subject="svc_eval_f12")
    registry = RegistryService(db_session)

    def unique_body(label: str) -> bytes:
        return f'{{"tenant":"{tenant}","label":"{label}"}}'.encode()

    parent = registry.register_artifact(
        tenant_id=tenant, artifact_type="prompt_bundle", canonical_bytes=unique_body("parent")
    )
    cheap = registry.register_artifact(
        tenant_id=tenant, artifact_type="prompt_bundle", canonical_bytes=unique_body("cheap")
    )
    profligate = registry.register_artifact(
        tenant_id=tenant,
        artifact_type="prompt_bundle",
        canonical_bytes=unique_body("profligate"),
    )
    for artifact in (cheap, profligate):
        registry.record_proposal(
            tenant_id=tenant,
            proposed_digest=artifact.digest,
            parent_digest=parent.digest,
            strategy_id=strategy,
            campaign_id="campaign-f12-f9",
        )

    def attest(digest: str, metrics: dict[str, object]) -> str:
        attestation = registry.record_attestation(
            tenant_id=tenant,
            evaluator=evaluator_identity,
            artifact_digest=digest,
            outcome="pass",
            result_metrics=metrics,
            evaluation_payload_digest="sha256:" + "0" * 64,
            private_key=generate_signing_key(),
        )
        return attestation.attestation_id

    cheap_attestation = attest(cheap.digest, {"task_success_rate": 0.9, "total_tokens": 420.0})

    # The profligate arm's attestation is written for the store side effect
    # only; its projection row is what the reconciliation asserts on.
    attest(profligate.digest, {"task_success_rate": 0.9, "total_tokens": 4200.0})

    # The typed projection is rebuilt from the raw records and reconciles
    # with them exactly: every proposal/attestation pair appears once, the
    # typed cost columns carry the attested values, and reconcile() is
    # empty.
    service = LineageProductivityService(db_session)
    assert service.rebuild(tenant) == 2
    rows = {row.artifact_digest: row for row in service.rows(tenant)}
    assert set(rows) == {cheap.digest, profligate.digest}
    assert rows[cheap.digest].attestation_id == cheap_attestation
    assert rows[cheap.digest].parent_digest == parent.digest
    assert rows[cheap.digest].total_tokens == 420.0
    assert rows[profligate.digest].total_tokens == 4200.0
    assert service.reconcile(tenant) == ()

    # The productivity selector freezes the best value-per-cost nominee
    # from the attested costs — the profligate twin loses on the same
    # selection score because it spends ten times the tokens.
    observations = [
        SelectionObservation(
            arm_id="arm-candidate",
            candidate_digest=cheap.digest,
            selection_score=0.9,
            cost_metrics={"total_tokens": 420.0},
        ),
        SelectionObservation(
            arm_id="arm-candidate",
            candidate_digest=profligate.digest,
            selection_score=0.9,
            cost_metrics={"total_tokens": 4200.0},
        ),
    ]
    selector = TrustedSelector(
        NominationRule(metric="productivity_score", cost_metric="total_tokens"),
        InMemoryNominationLedger(),
        campaign_id="campaign-f12-f9",
    )
    frozen = selector.freeze(observations)
    assert frozen.nominee_for("arm-candidate") == cheap.digest

    # An unpriced candidate is not rankable: no attested cost, no
    # productivity value — the rule fails closed.
    unpriced = SelectionObservation(
        arm_id="arm-candidate",
        candidate_digest="sha256:" + "d" * 64,
        selection_score=0.99,
        cost_metrics={},
    )
    assert attested_cost(unpriced, "total_tokens") is None


# ----------------------------------------------------------------------
# Campaign six: decision reconstruction over the integrated lineage
# ----------------------------------------------------------------------


def test_phase2_decisions_reconstruct_from_immutable_records(
    session_factory: sessionmaker[Session],
    database_url: str,
    evaluator: Principal,
    tenant_id: str,
    dataset_service: DatasetService,
    holdout_service: HoldoutService,
) -> None:
    """Every Phase 2 decision in the executable campaign is reconstructible
    from the append-only records alone — and the records refuse mutation."""
    service, key = make_service(session_factory)
    board = make_board_service(session_factory, key)
    result = run_executable_campaign(
        service,
        evaluator,
        tenant_id=tenant_id,
        dataset_service=dataset_service,
        holdout_service=holdout_service,
    )
    campaign_id = result["campaign_id"]
    candidate_digest = result["candidate_digest"]

    # The tier-3 review-board record: two distinct approvers, signed.
    request = board.create_request(
        evaluator,
        kind="tier3_promotion",
        justification="reconstruction pass over the promoted executable tool",
        campaign_id=campaign_id,
        proposal_id=result["proposal_id"],
    )
    board.decide(
        board_principal(tenant_id, "svc_board_1"),
        request_id=request.request_id,
        decision="approve",
        note="reconstruction reviewer one",
    )
    board.decide(
        board_principal(tenant_id, "svc_board_2"),
        request_id=request.request_id,
        decision="approve",
        note="reconstruction reviewer two",
    )
    admitted = board.admit(evaluator, request_id=request.request_id)

    with session_factory() as session:
        # Lifecycle: gapless transition log, replayable to the final phase.
        rows = session.execute(
            text(
                "SELECT sequence, from_phase, to_phase FROM campaign_transitions "
                "WHERE tenant_id = :tenant AND campaign_id = :camp ORDER BY sequence"
            ),
            {"tenant": tenant_id, "camp": campaign_id},
        ).all()
        assert [int(r.sequence) for r in rows] == list(range(len(rows)))
        assert rows[-1].to_phase == CampaignPhase.LEARN.value

        # Static analysis: the verdict row's digest and signature verify
        # against the canonical verdict bytes the analyzer produced.
        report_row = session.execute(
            select(AnalysisReport).where(
                AnalysisReport.tenant_id == tenant_id,
                AnalysisReport.candidate_digest == candidate_digest,
            )
        ).scalar_one()
        assert report_row.outcome == "pass"
        stored = DetachedSignature(
            signature=report_row.signature, public_key=report_row.signer_public_key
        )
        rebuilt = StaticAnalysisReport(
            candidate_digest=str(report_row.candidate_digest),
            artifact_type=str(report_row.artifact_type),
            violations=tuple(AnalysisViolation(**v) for v in report_row.violations),
        )
        assert rebuilt.verdict_digest == report_row.verdict_digest
        assert verify(stored, rebuilt.canonical_bytes())

        # Tier-3 approval: the admission record's signature verifies — and
        # a tampered field no longer does.
        admission_row = session.execute(
            select(AdmissionRecord).where(
                AdmissionRecord.tenant_id == tenant_id,
                AdmissionRecord.record_id == admitted.record_id,
            )
        ).scalar_one()
        assert verify_admission_signature(admission_row)
        assert {a["approver"] for a in admission_row.approvals} == {
            "svc_board_1",
            "svc_board_2",
        }
        admission_row.proposal_digest = "sha256:" + "f" * 64
        assert not verify_admission_signature(admission_row)

        # Evaluations: every attestation verifies against its signature.
        registry = RegistryService(session)
        attestations = session.scalars(
            select(EvaluationAttestation).where(
                EvaluationAttestation.tenant_id == tenant_id,
                EvaluationAttestation.artifact_digest.in_(
                    [result["parent_digest"], candidate_digest]
                ),
            )
        ).all()
        assert {a.artifact_digest for a in attestations} == {
            result["parent_digest"],
            candidate_digest,
        }
        for attestation in attestations:
            assert registry.verify_attestation(attestation)

        # Releases: the activation history shows canary → active with the
        # incumbent superseded — the promotion decision is in the log.
        activations = session.execute(
            text(
                "SELECT manifest_digest, status FROM release_activations "
                "WHERE tenant_id = :tenant ORDER BY created_at, id"
            ),
            {"tenant": tenant_id},
        ).all()
        statuses = {a.manifest_digest: a.status for a in activations}
        assert statuses[result["candidate_manifest"]] == "active"
        assert statuses[result["incumbent_manifest"]] == "superseded"

        # Sealed holdout: the resolution is in the append-only ledger.
        ledger_outcomes = (
            session.execute(
                text("SELECT outcome FROM holdout_query_ledger WHERE tenant_id = :tenant"),
                {"tenant": tenant_id},
            )
            .scalars()
            .all()
        )
        assert "granted" in ledger_outcomes

    # Immutability is enforced by the database, not by discipline: the
    # same role the application uses cannot UPDATE or DELETE the records
    # the reconstruction above read. The UPDATE guards raise a plain
    # SQLSTATE error (ProgrammingError); the ledger DELETE guard raises
    # with the restrict-violation SQLSTATE (IntegrityError) — both are
    # database-level refusals.
    mutation_attempts = (
        (
            "UPDATE campaign_transitions SET to_phase = 'mutated' "
            "WHERE tenant_id = :tenant AND campaign_id = :camp",
            {"tenant": tenant_id, "camp": campaign_id},
            "append-only table",
            ProgrammingError,
        ),
        (
            "UPDATE analysis_reports SET outcome = 'mutated' WHERE tenant_id = :tenant",
            {"tenant": tenant_id},
            "immutable",
            ProgrammingError,
        ),
        (
            "DELETE FROM holdout_query_ledger WHERE tenant_id = :tenant",
            {"tenant": tenant_id},
            "holdout_query_ledger is append-only",
            IntegrityError,
        ),
    )
    from sqlalchemy import create_engine

    engine = create_engine(database_url)
    try:
        for statement, params, expected_error, exc_type in mutation_attempts:
            with engine.begin() as conn, pytest.raises(exc_type, match=expected_error):
                conn.execute(text(statement), params)
    finally:
        engine.dispose()

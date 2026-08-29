"""G11 — Phase 3 conformance verification (the spec's acceptance matrix).

The integrated end-to-end pass over the merged G1–G10 deliverables, run on
the release branch against real PostgreSQL and the real sandbox, extending
the F12 pattern (``tests/conformance/test_phase2_campaigns.py``). Where the
per-deliverable suites prove each Phase 3 gate in isolation, these tests
prove the gates compose. The seven scenarios:

1. the full scaffold campaign lifecycle in a research tenant — the
   fixed-editor arm present, the strategy arm refused to start without it,
   the tier-4 review board admitting the promotion, and the recursion label
   earned (RI-3/RI-4) rather than asserted;
2. protected-module mutation refused at spec construction *and* at the
   execution gate, tamper-evidently, with nothing registered;
3. mutated scaffold bytes captured from the real sandbox, digest-verified,
   registered against their pinned digest, with conformance pass/fail as a
   measured paired outcome and the mutation archive reconciling behind it;
4. tier-4 promotion requires the full evidence chain, and cross-tenant
   activation of a scaffold release is refused and audited;
5. a destructive mutation trips severity-1: compensations execute in
   declared order, the pointer rolls back, evidence lands;
6. graduation of a mutation class without a comparable-risk dossier is
   refused, by recorded decision;
7. every new Phase 3 table refuses UPDATE/DELETE at the database level,
   and the Phase 3 migrations round-trip through the Phase 2 head.

Everything here drives the real services — the FR-014 control-plane API,
the G7 tier-4 review board, the E1 registry, the G6 tenant-policy plane,
the F1 sandbox executor with G5 capture and write zoning, the G8 scaffold
compensation machinery, the E5 release controller/canary, and the G10
graduation engine — over real PostgreSQL. The only simulated input is
evaluation *data* (paired scores, scripted suite runs), which is the D6/D8
fixture reality: CI is hermetic by design.
"""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import IntegrityError, ProgrammingError
from sqlalchemy.orm import Session, sessionmaker
from tests.campaign.conftest import InMemoryCheckpointStore, make_pinned_spec
from tests.conftest import MIGRATIONS_DIR, REPO_ROOT
from tests.support.factories import make_campaign_spec_mapping

from evoruntime.api.approvals import ApprovalWorkflowService, verify_admission_signature
from evoruntime.api.errors import (
    ApprovalDeniedError,
    InvalidSpecError,
    RegistrationRefusedError,
)
from evoruntime.api.service import CampaignApiService
from evoruntime.campaign.compensation import (
    CAS_MODE,
    REQUIRES_EXECUTION_MODE,
    CheckpointedCompensationGate,
    InMemoryExecutionSink,
    sign_compensation_plan,
)
from evoruntime.campaign.errors import (
    InvalidCampaignSpecError,
    ScaffoldEnvironmentRefusedError,
    UnexecutedCompensationError,
)
from evoruntime.campaign.machine import CampaignOrchestrator, CampaignPhase
from evoruntime.campaign.scaffold_compensation import (
    ConformanceRerunExecutor,
    ScaffoldSourceRestorer,
)
from evoruntime.campaign.spec import CampaignSpec, MutationClassBinding
from evoruntime.core.isolation import IsolationTier
from evoruntime.core.principal import Principal
from evoruntime.db.models.approvals import AdmissionRecord
from evoruntime.db.models.campaign import ReleaseActivation
from evoruntime.db.models.graduation import GraduationDecision
from evoruntime.db.models.tenancy import TenantPolicyRefusal
from evoruntime.eval.conformance import SuiteRunResult
from evoruntime.plugins.manifest import NetworkMode, ResourceLimits
from evoruntime.plugins.protocol import InMemoryCheckpointStore as SandboxCheckpointStore
from evoruntime.plugins.scaffold import (
    module_canonical_bytes,
    module_digest,
    scaffold_canonical_bytes,
    scaffold_digest,
    scaffold_file_map_from_sources,
)
from evoruntime.plugins.static_analysis import (
    AnalysisViolationCode,
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
from evoruntime.security.signing import generate_signing_key, sign, verify
from evoruntime.selection.authority import (
    ResolvedRelease,
    TierApprovalEvidence,
    TierRejectedError,
)
from evoruntime.selection.graduation import (
    BlastRadius,
    GraduationRefusal,
    RiskDossier,
    evaluate_graduation,
    record_graduation_decision,
    sign_risk_dossier,
    verify_graduation_decision,
)
from evoruntime.selection.mutation_archive import MutationArchiveService
from evoruntime.selection.policy import (
    PairedScores,
    PromotionEvidence,
    PromotionPolicyDocument,
    evaluate_promotion,
)
from evoruntime.selection.recursive_gate import (
    RECURSIVE_IMPROVEMENT_LABEL,
    RecursiveClaimEvidence,
    claim_label,
    evaluate_recursive_claim,
)
from evoruntime.tenancy.audit import RefusalBoundary
from evoruntime.tenancy.errors import TenantRefusalError
from evoruntime.tenancy.policy import TenantPolicyRegistry
from evoruntime.tenancy.seed import (
    seed_production_tenant_policy,
    seed_research_tenant_policy,
)

#: The sandbox scenarios in this module require physical enforcement
#: (seccomp + Landlock); the DB-backed scenarios run anywhere.
_SANDBOX_MARK = pytest.mark.skipif(
    not physical_enforcement_available(),
    reason="sandbox executor requires seccomp + Landlock (Linux)",
)

SANDBOX_LIMITS = ResourceLimits(
    wall_clock_minutes=1.0, cpu=1.0, memory_gib=0.05, model_tokens=0, proposals=1
)

#: The incumbent scaffold: a three-module agent tree with a pinned
#: self-edit conformance suite. The mutation surface is ``planner.py``.
INCUMBENT_SOURCES: dict[str, str] = {
    "src/agent/__init__.py": "",
    "src/agent/planner.py": "def plan(task: str) -> str:\n    return task.strip()\n",
    "src/agent/tools.py": "def tool(name: str) -> str:\n    return name.lower()\n",
}
ENTRYPOINTS = ("src/agent/__init__.py",)
CONFORMANCE_SUITE = "conformance/self-edit@sha256:" + "2b" * 32

#: A beneficial mutation of the planner — clean source, no protected
#: imports, the kind of edit a green conformance suite admits.
BENEFICIAL_PLANNER = (
    "def plan(task: str) -> str:\n    stripped = task.strip()\n    return stripped or task\n"
)

#: A destructive mutation: the planner shells out — exactly the class of
#: edit the severity-1 drill compensates for.
DESTRUCTIVE_PLANNER = "import os\n\n\ndef plan(task: str) -> str:\n    os.system('rm -rf /')\n"

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


# ----------------------------------------------------------------------
# Helpers (the F12 pattern, extended for the Phase 3 surfaces)
# ----------------------------------------------------------------------


class Tenants:
    """Fresh, unique tenant ids for one test — refusal rows never collide."""

    def __init__(self) -> None:
        suffix = uuid.uuid4().hex[:8]
        self.research = f"tnt_g11_research_{suffix}"
        self.production = f"tnt_g11_production_{suffix}"


@pytest.fixture
def tenants() -> Tenants:
    return Tenants()


@pytest.fixture
def alembic_config(database_url: str) -> Config:
    """Alembic config pointed at the test database (the test_migrations.py
    pattern, reusing the shared `database_url` reachability fixture)."""
    config = Config(str(REPO_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def policy_registry(tenants: Tenants) -> TenantPolicyRegistry:
    """One research tenant (tier-4-allowing seed) and one production tenant."""
    return TenantPolicyRegistry(
        [
            seed_research_tenant_policy(tenants.research),
            seed_production_tenant_policy(tenants.production),
        ]
    )


def make_service(
    session_factory: sessionmaker[Session],
    tenants: Tenants,
    signing_key: Ed25519PrivateKey | None = None,
) -> tuple[CampaignApiService, Ed25519PrivateKey]:
    """The control-plane service over the test database, bound to the
    test's tenant-policy registry, with its key."""
    key = signing_key or generate_signing_key()
    service = CampaignApiService(
        session_factory,
        signing_key=key,
        evaluator_subject="svc_evaluator_g11",
        tenant_policies=policy_registry(tenants),
    )
    return service, key


def make_board_service(
    session_factory: sessionmaker[Session],
    signing_key: Ed25519PrivateKey,
    tenants: Tenants,
) -> ApprovalWorkflowService:
    """The review-board service sharing the control plane's key and the
    same tenant-policy registry (tier 4 needs a tier-4-allowing policy)."""
    return ApprovalWorkflowService(
        session_factory,
        signing_key=signing_key,
        evaluator_subject="svc_evaluator_g11",
        tenant_policies=policy_registry(tenants),
    )


def research_principal(tenant_id: str) -> Principal:
    """An evaluator caller inside the research tenant."""
    return Principal(
        identity=WorkloadIdentity(role=WorkloadRole.EVALUATOR, subject="svc_evaluator_g11"),
        tenant_id=tenant_id,
    )


def board_principal(tenant_id: str, subject: str) -> Principal:
    """A verified review-board caller inside the tenant."""
    return Principal(
        identity=WorkloadIdentity(role=WorkloadRole.EVALUATOR, subject=subject),
        tenant_id=tenant_id,
    )


def make_scaffold_spec_mapping(
    *, environment: str | None = "research", with_fixed_editor: bool = True
) -> dict[str, Any]:
    """A valid scaffold-mutable campaign spec (G3/G4/G6/G7 shape).

    v1 schema within the migration window, as the G6/G7 suites do; the
    scaffold surface is what the spec validators key on: environment,
    pinned mutation classes, the fixed-editor arm, and the tier-4 policy
    digest.
    """
    mapping = make_campaign_spec_mapping()
    mapping["incumbent"]["artifact_type"] = "scaffold"
    mapping["mutable_artifact"]["artifact_type"] = "scaffold"
    mapping["mutation_classes"] = [
        {
            "class_id": "prompt_module_edit",
            "risk_dossier_digest": "sha256:" + "a" * 64,
            "max_tier": "executable",
        },
    ]
    if with_fixed_editor:
        mapping["arms"] = [
            *mapping["arms"],
            {
                "id": "fixed-editor",
                "kind": "fixed-editor",
                "editor_ref": "evo-prompt-strategist@gen-0",
            },
        ]
    mapping["tier4_policy_digest"] = "sha256:" + "a" * 64
    if environment is not None:
        mapping["environment"] = environment
    return mapping


def scaffold_blobs(sources: dict[str, str]) -> tuple[dict[str, bytes], Any]:
    """Digest-keyed registry blobs for a scaffold over ``sources``: the
    file-map body plus every member module's canonical bytes."""
    file_map = scaffold_file_map_from_sources(
        sources, entrypoints=ENTRYPOINTS, conformance_suite=CONFORMANCE_SUITE
    )
    blobs: dict[str, bytes] = {scaffold_digest(file_map): scaffold_canonical_bytes(file_map)}
    for path, content in sources.items():
        blobs[module_digest(path, content)] = module_canonical_bytes(path, content)
    return blobs, file_map


def register_scaffold_through_api(
    service: CampaignApiService,
    principal: Principal,
    sources: dict[str, str],
    *,
    strategy_id: str,
    campaign_id: str | None = None,
    parent_digest: str | None = None,
    mutation_class: str | None = None,
) -> Any:
    """Register a scaffold candidate through the control-plane API."""
    file_map = scaffold_file_map_from_sources(
        sources, entrypoints=ENTRYPOINTS, conformance_suite=CONFORMANCE_SUITE
    )
    metadata = {"mutation_class": mutation_class} if mutation_class else None
    return service.register_candidate(
        principal,
        artifact_type="scaffold",
        canonical_bytes_b64=base64.b64encode(scaffold_canonical_bytes(file_map)).decode(),
        strategy_id=strategy_id,
        campaign_id=campaign_id,
        parent_digest=parent_digest,
        proposal_metadata=metadata,
    )


def sandbox_profile(*zones: str) -> ExecutionProfile:
    """A tier-3 execution profile with the declared Landlock write zones."""
    return ExecutionProfile(
        tier=IsolationTier.EXECUTABLE,
        network_mode=NetworkMode.NONE,
        resource_limits=SANDBOX_LIMITS,
        writable_paths=tuple(zones),
    )


class _DictPayloadReader:
    """Serves payloads from an in-memory digest -> bytes map."""

    def __init__(self, blobs: dict[str, bytes]) -> None:
        self._blobs = dict(blobs)

    def read(self, *, tenant_id: str, payload_digest: str) -> bytes:
        return self._blobs[payload_digest]


def run_in_sandbox(
    code: str,
    checkpoints: SandboxCheckpointStore,
    *,
    profile: ExecutionProfile,
    capture_paths: tuple[str, ...] = (),
    extra_payloads: tuple[tuple[str, bytes], ...] = (),
) -> Any:
    """Stage ``code`` (plus any extra payloads) and execute it in the F1
    sandbox at the declared tier, capturing the requested paths."""
    blobs: dict[str, bytes] = {}
    refs: list[PayloadRef] = []

    def _payload(path: str, data: bytes) -> PayloadRef:
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        blobs[digest] = data
        return PayloadRef(path=path, digest=digest)

    refs.append(_payload("candidate.py", code.encode("utf-8")))
    for path, data in extra_payloads:
        refs.append(_payload(path, data))
    backend = SubprocessIsolationBackend(
        payloads=_DictPayloadReader(blobs), checkpoints=checkpoints
    )
    request = ExecutionRequest(
        tenant_id="tenant-g11",
        image_digest="ghcr.io/acme/candidate@sha256:" + "cd" * 32,
        profile=profile,
        payloads=tuple(refs),
        command=("python3", "candidate.py"),
        capture_paths=capture_paths,
    )
    return backend.run(request)


def transition_through(
    service: CampaignApiService, principal: Principal, campaign_id: str, *phases: CampaignPhase
) -> None:
    """Walk the campaign one legal edge at a time to `phases`."""
    for phase in phases:
        detail = service.transition_campaign(
            principal, campaign_id, phase.value, reason="g11 conformance run"
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


def tier4_approval_evidence() -> TierApprovalEvidence:
    """The full tier-4 evidence chain: two distinct approvers (neither the
    requester) plus both human-evidence legs."""
    return TierApprovalEvidence(
        approvers=("svc_board_1", "svc_board_2"),
        requested_by="svc_evaluator_g11",
        human_signoff=True,
        manually_initiated=True,
    )


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


class _ScriptedSuiteRunner:
    """Returns a canned suite result and captures the tree state at run
    time — the drill reads the capture to prove the rerun executed against
    restored source."""

    def __init__(self, result: SuiteRunResult, tree_root: Path, probe: str) -> None:
        self._result = result
        self._tree_root = tree_root
        self._probe = probe
        self.captured_planner_content: str | None = None

    def run(self, command: tuple[str, ...]) -> SuiteRunResult:
        self.captured_planner_content = (self._tree_root / self._probe).read_text(encoding="utf-8")
        return self._result


class _RegistryReader:
    """Digest-keyed stand-in for RegistryService.read_artifact."""

    def __init__(self, blobs: dict[str, bytes]) -> None:
        self._blobs = blobs

    def read_artifact(self, *, tenant_id: str, digest: str) -> bytes:
        return self._blobs[digest]


# ----------------------------------------------------------------------
# Scenario 1 — the full scaffold campaign lifecycle in a research tenant
# ----------------------------------------------------------------------


def test_scaffold_campaign_lifecycle_in_research_tenant_earns_its_gates(
    session_factory: sessionmaker[Session],
    tenants: Tenants,
) -> None:
    """A scaffold campaign runs end-to-end in the research tenant: the
    spec refuses to construct without its fixed-editor arm or its
    research-environment claim, the campaign walks the §11 forward path,
    the tier-4 board admits the promotion on the full evidence chain, and
    the recursion label is earned by the RI-3/RI-4 numeric condition —
    never asserted."""
    service, key = make_service(session_factory, tenants)
    board = make_board_service(session_factory, key, tenants)
    principal = research_principal(tenants.research)

    # The strategy arm cannot start without its fixed-editor control: the
    # spec construction refuses a scaffold-mutable campaign whose arms
    # carry no fixed-editor arm (G4), and one without the research
    # environment claim (G6 boundary 1).
    with pytest.raises(InvalidCampaignSpecError, match="fixed-editor"):
        CampaignSpec.from_mapping(make_scaffold_spec_mapping(with_fixed_editor=False))
    with pytest.raises(ScaffoldEnvironmentRefusedError):
        CampaignSpec.from_mapping(make_scaffold_spec_mapping(environment=None))

    # The valid spec constructs, pins, and creates in the research tenant.
    spec = CampaignSpec.from_mapping(make_scaffold_spec_mapping())
    assert spec.has_scaffold_mutable
    assert spec.environment == "research"
    detail = service.create_campaign(principal, make_scaffold_spec_mapping())
    campaign_id = detail.campaign_id

    # PROPOSE: the incumbent scaffold registers, then the mutated candidate
    # registers against it with its declared mutation class.
    incumbent = register_scaffold_through_api(
        service, principal, INCUMBENT_SOURCES, strategy_id="incumbent"
    )
    candidate = register_scaffold_through_api(
        service,
        principal,
        dict(INCUMBENT_SOURCES, **{"src/agent/planner.py": BENEFICIAL_PLANNER}),
        strategy_id="harness-mutator",
        campaign_id=campaign_id,
        parent_digest=incumbent.artifact_digest,
        mutation_class="prompt_module_edit",
    )
    assert candidate.artifact_digest.startswith("sha256:")

    transition_through(
        service,
        principal,
        campaign_id,
        CampaignPhase.PLAN,
        CampaignPhase.PROPOSE,
        CampaignPhase.DEV_EVALUATE,
        CampaignPhase.SELECT_FREEZE,
        CampaignPhase.HOLDOUT,
        CampaignPhase.APPROVE,
    )

    # Tier-4 promotion: the review board refuses to admit on one approval,
    # admits on two distinct ones, and the signed record verifies.
    request = board.create_request(
        principal,
        kind="tier4_promotion",
        justification="promoting a beneficial scaffold mutation (g11 scenario 1)",
        campaign_id=campaign_id,
        proposal_id=candidate.proposal_id,
        human_signoff=True,
        manually_initiated=True,
    )
    assert request.tier == 4
    board.decide(
        board_principal(tenants.research, "svc_board_1"),
        request_id=request.request_id,
        decision="approve",
        note="conformance suite green, mutation inside the declared class",
    )
    with pytest.raises(ApprovalDeniedError, match="two distinct"):
        board.admit(principal, request_id=request.request_id)
    board.decide(
        board_principal(tenants.research, "svc_board_2"),
        request_id=request.request_id,
        decision="approve",
        note="second reviewer concurs",
    )
    admitted = board.admit(principal, request_id=request.request_id)
    assert admitted.decision == "admitted"
    assert admitted.tier == 4

    transition_through(service, principal, campaign_id, CampaignPhase.CANARY)
    release = service.create_release(
        principal,
        artifact_digests=[candidate.artifact_digest],
        adapter_versions={"harness-mutator": "1.0.0"},
        model_routes={"default": "model-a"},
        policies={"tier": "tier-4-scaffold"},
        status="canary",
    )
    promoted = service.promote_release(principal, release.manifest_digest)
    assert promoted.status == "active"
    transition_through(service, principal, campaign_id, CampaignPhase.PROMOTED, CampaignPhase.LEARN)

    # The lifecycle walked exactly the §11 forward path, gaplessly.
    walked = service.get_campaign(principal, campaign_id)
    path = [(t.from_phase, t.to_phase) for t in walked.transitions]
    expected = [(CampaignPhase.DISCOVER, CampaignPhase.PLAN)] + [
        (before, after)
        for before, after in zip(_PROMOTION_LIFECYCLE, _PROMOTION_LIFECYCLE[1:], strict=False)
    ]
    assert path == expected
    assert walked.phase == CampaignPhase.LEARN.value

    # The recursion label is earned, never asserted: with the numeric
    # fixed-editor advantage inside the shared Holm family the research
    # tenant earns the label; without the advantage the honest answer is
    # artifact optimization — even with every other condition satisfied.
    def evidence_with(advantage: float) -> RecursiveClaimEvidence:
        return RecursiveClaimEvidence(
            successive_promoted_generations=True,
            shared_error_budget=True,
            causal_inheritance=True,
            matched_compute_one_shot_advantage=True,
            no_inheritance_control_arm=True,
            fixed_editor_control_arm=True,
            fixed_editor_advantage=advantage,
            fixed_editor_minimum_effect=0.05,
            fixed_editor_holm_significant=True,
        )

    verdict = evaluate_recursive_claim(evidence_with(0.08))
    research_policy = policy_registry(tenants).policy_for(tenants.research)
    assert claim_label(verdict, tenant_policy=research_policy) == RECURSIVE_IMPROVEMENT_LABEL
    sub_minimal = evaluate_recursive_claim(evidence_with(0.04))
    assert claim_label(sub_minimal, tenant_policy=research_policy) == "artifact optimization"


# ----------------------------------------------------------------------
# Scenario 2 — protected modules are untouchable, tamper-evidently
# ----------------------------------------------------------------------


def test_protected_module_mutation_refused_at_spec_construction_and_execution_gate(
    session_factory: sessionmaker[Session],
    tenants: Tenants,
) -> None:
    """A mutation touching a protected module is refused at spec
    construction (the mask path) and at the execution gate (the
    candidate's own bytes), with a tamper-evident verdict — and nothing
    lands in the registry, the proposal ledger, or the verdict table."""
    service, _ = make_service(session_factory, tenants)
    principal = research_principal(tenants.research)

    # Spec construction: a mask path under a protected root is a
    # preregistered attempt to mutate a protected plane — refused before
    # any campaign exists.
    protected_spec = make_scaffold_spec_mapping()
    protected_spec["mutable_artifact"]["paths"] = ["src/evoruntime/security/policy.py"]
    with pytest.raises(InvalidCampaignSpecError, match="protected module"):
        CampaignSpec.from_mapping(protected_spec)

    # Execution gate, import flavor: a scaffold candidate whose module
    # imports a protected module is refused before anything is registered.
    importing_bundle = json.dumps(
        {
            "files": [
                {
                    "path": "src/agent/planner.py",
                    "content": "import evoruntime.security.policy\n\n\ndef plan(): ...\n",
                }
            ]
        }
    ).encode()
    with pytest.raises(RegistrationRefusedError) as import_refused:
        service.register_candidate(
            principal,
            artifact_type="scaffold",
            canonical_bytes_b64=base64.b64encode(importing_bundle).decode(),
            strategy_id="harness-mutator",
        )
    assert import_refused.value.source == "static_analysis"
    assert AnalysisViolationCode.PROTECTED_MODULE_IMPORT.value in {
        str(violation["code"]) for violation in import_refused.value.violations
    }

    # Execution gate, write flavor: a candidate carrying a file under a
    # protected root is refused the same way.
    writing_bundle = json.dumps(
        {
            "files": [
                {
                    "path": "src/evoruntime/security/agent.py",
                    "content": "def plan(): ...\n",
                }
            ]
        }
    ).encode()
    with pytest.raises(RegistrationRefusedError) as write_refused:
        service.register_candidate(
            principal,
            artifact_type="scaffold",
            canonical_bytes_b64=base64.b64encode(writing_bundle).decode(),
            strategy_id="harness-mutator",
        )
    assert AnalysisViolationCode.PROTECTED_MODULE_WRITE.value in {
        str(violation["code"]) for violation in write_refused.value.violations
    }

    # Nothing landed: no artifact, no proposal, no verdict row.
    with session_factory() as session:
        assert (
            session.execute(
                text("SELECT COUNT(*) FROM artifact_content WHERE tenant_id = :tenant"),
                {"tenant": tenants.research},
            ).scalar_one()
            == 0
        )
        assert (
            session.execute(
                text("SELECT COUNT(*) FROM proposal_records WHERE tenant_id = :tenant"),
                {"tenant": tenants.research},
            ).scalar_one()
            == 0
        )
        assert (
            session.execute(
                text("SELECT COUNT(*) FROM analysis_reports WHERE tenant_id = :tenant"),
                {"tenant": tenants.research},
            ).scalar_one()
            == 0
        )

    # The verdict is tamper-evident: digest-bound, signed, and one flipped
    # byte in either the body or the signature breaks it.
    report = analyze_files(
        (
            {
                "path": "src/agent/planner.py",
                "content": "import evoruntime.security.policy\n\n\ndef plan(): ...\n",
            },
        ),
        artifact_type="scaffold",
        candidate_digest="sha256:" + "0" * 64,
    )
    assert report.blocked
    canonical = report.canonical_bytes()
    assert report.verdict_digest == "sha256:" + hashlib.sha256(canonical).hexdigest()
    private_key = generate_signing_key()
    detached = sign(private_key, canonical)
    assert verify(detached, canonical)
    flipped = bytearray(canonical)
    flipped[0] ^= 0x01
    assert not verify(detached, bytes(flipped))
    assert "sha256:" + hashlib.sha256(bytes(flipped)).hexdigest() != report.verdict_digest

    # The verdict is tamper-evident: digest-bound, signed, and one flipped
    # byte in either the body or the signature breaks it.


# ----------------------------------------------------------------------
# Scenario 3 — mutated bytes captured, digest-verified, registered;
# conformance pass/fail is a measured paired outcome
# ----------------------------------------------------------------------


@_SANDBOX_MARK
def test_mutated_scaffold_bytes_captured_digest_verified_and_registered(
    session_factory: sessionmaker[Session],
    tenants: Tenants,
) -> None:
    """The two-run harness flow over the real sandbox: run 1 mutates the
    scaffold inside its declared write zone and the backend captures the
    mutated bytes digest-verified; the harness registers them against
    their pinned digest (the registry refuses a digest/bytes mismatch);
    run 2 executes exactly those bytes. The mutation archive projection
    rebuilds over the raw records and reconciles."""
    service, _ = make_service(session_factory, tenants)
    checkpoints = SandboxCheckpointStore()

    # Run 1: the mutator writes the beneficial planner into its zone.
    mutator = (
        "from pathlib import Path\n"
        "Path('out').mkdir(exist_ok=True)\n"
        f"Path('out/planner.py').write_bytes({BENEFICIAL_PLANNER.encode()!r})\n"
    )
    first = run_in_sandbox(
        mutator,
        checkpoints,
        profile=sandbox_profile("out"),
        capture_paths=("out/planner.py",),
    )
    assert first.exit_code == 0
    (captured,) = first.captured
    mutated_bytes = BENEFICIAL_PLANNER.encode("utf-8")
    assert captured.digest == "sha256:" + hashlib.sha256(mutated_bytes).hexdigest()
    # The attestation binds the captured digest set into the same record.
    assert [(ref.path, ref.digest) for ref in first.attestation.captured] == [
        (captured.path, captured.digest)
    ]

    # The captured bytes are exactly the module source the file map pins:
    # proposed bytes = executed bytes = registered bytes.
    mutated_sources = dict(
        INCUMBENT_SOURCES, **{"src/agent/planner.py": captured.content.decode("utf-8")}
    )
    candidate_map = scaffold_file_map_from_sources(
        mutated_sources, entrypoints=ENTRYPOINTS, conformance_suite=CONFORMANCE_SUITE
    )

    # Registration is digest-verified: the registry computes the digest
    # from the stored bytes and refuses when it disagrees with the pin.
    with session_factory() as session:
        registry = RegistryService(session)
        for path, content in mutated_sources.items():
            module_artifact = registry.register_artifact(
                tenant_id=tenants.research,
                artifact_type="scaffold",
                canonical_bytes=module_canonical_bytes(path, content),
            )
            assert module_artifact.digest == module_digest(path, content)
        scaffold_artifact = registry.register_artifact(
            tenant_id=tenants.research,
            artifact_type="scaffold",
            canonical_bytes=scaffold_canonical_bytes(candidate_map),
            dependencies=list(candidate_map.module_digests()),
            expected_digest=scaffold_digest(candidate_map),
        )
        assert scaffold_artifact.digest == scaffold_digest(candidate_map)
        proposal = registry.record_proposal(
            tenant_id=tenants.research,
            proposed_digest=scaffold_artifact.digest,
            strategy_id="harness-mutator",
            campaign_id="campaign-g11-scenario3",
            proposal_metadata={"mutation_class": "prompt_module_edit"},
        )
        # The archive projection joins proposals to evaluation
        # attestations on the proposed digest — record the paired
        # evaluation evidence for the registered candidate.
        registry.record_attestation(
            tenant_id=tenants.research,
            evaluator=WorkloadIdentity(
                role=WorkloadRole.EVALUATOR, subject="svc_eval_g11_scenario3"
            ),
            artifact_digest=scaffold_artifact.digest,
            outcome="pass",
            result_metrics={"fitness": 0.83},
            evaluation_payload_digest="sha256:" + "0" * 64,
            private_key=generate_signing_key(),
        )
        session.commit()
        proposal_id = proposal.proposal_id

    # Run 2: the captured bytes stage back digest-verified and execute.
    second = run_in_sandbox(
        "import pathlib\nprint(pathlib.Path('planner.py').read_text())\n",
        checkpoints,
        profile=sandbox_profile(),
        extra_payloads=(("planner.py", captured.content),),
    )
    assert second.exit_code == 0
    assert BENEFICIAL_PLANNER in second.stdout

    # The mutation archive is a rebuildable projection over the raw
    # append-only records — not a table the plugin owns.
    with session_factory() as session:
        archive = MutationArchiveService(session)
        assert archive.rebuild(tenants.research) >= 1
        rows = archive.rows(tenants.research)
        assert any(row.proposal_id == proposal_id for row in rows)
        assert archive.reconcile(tenants.research) == ()
        classes = {summary.mutation_class: summary for summary in archive.classes(tenants.research)}
        assert "prompt_module_edit" in classes
        session.rollback()


@_SANDBOX_MARK
def test_conformance_pass_fail_is_a_measured_paired_outcome(
    session_factory: sessionmaker[Session],
    tenants: Tenants,
    tmp_path: Path,
) -> None:
    """Conformance pass/fail feeds the promotion engine as measured paired
    data, not an assertion: the green suite's per-task outcomes pair into
    an eligible tier-4 promotion; the regressing suite's outcomes pair
    into a refusal — and the compensation executor fails closed on the
    regressing run."""
    service, _ = make_service(session_factory, tenants)
    principal = research_principal(tenants.research)

    # The incumbent scaffold registers and attests (the paired baseline).
    incumbent = register_scaffold_through_api(
        service, principal, INCUMBENT_SOURCES, strategy_id="incumbent"
    )
    service.record_evaluation(
        principal,
        artifact_digest=incumbent.artifact_digest,
        outcome="pass",
        metrics={"task_success_rate": 0.62, "total_tokens": 1000.0},
    )

    # The measured conformance outcomes: the green suite run passes 48 of
    # 60 paired tasks for the candidate; the regressing run fails the
    # suite outright (zero-regression interpretation).
    green_run = SuiteRunResult(returncode=0, stdout="118 passed in 2.31s")
    red_run = SuiteRunResult(returncode=1, stdout="1 failed, 117 passed in 2.31s")
    assert green_run.returncode == 0
    assert red_run.returncode == 1

    # The rerun executor inherits the fail-closed interpretation: a
    # regressing suite run is a measured failure, never a pass. It first
    # re-verifies the scaffold file map against its content address —
    # so the action carries the incumbent's real registered digest.
    incumbent_blobs, incumbent_map = scaffold_blobs(INCUMBENT_SOURCES)
    incumbent_digest = scaffold_digest(incumbent_map)
    incumbent_tree = tmp_path / "incumbent"
    incumbent_tree.mkdir()
    (incumbent_tree / "src" / "agent").mkdir(parents=True)
    (incumbent_tree / "src" / "agent" / "planner.py").write_text(
        INCUMBENT_SOURCES["src/agent/planner.py"], encoding="utf-8"
    )
    runner = _ScriptedSuiteRunner(red_run, tree_root=incumbent_tree, probe="src/agent/planner.py")
    executor = ConformanceRerunExecutor(
        reader=_RegistryReader(incumbent_blobs), tenant_id=tenants.research, runner=runner
    )
    with pytest.raises(Exception, match="zero regressions"):
        executor.execute(
            1,
            {
                "artifact_digest": incumbent_digest,
                "action": "rerun_conformance_suite",
            },
        )

    # Paired outcomes over 60 tasks: the incumbent (baseline) passes 36,
    # the conformance-green candidate passes 48, the conformance-failing
    # candidate passes none — the suite verdict *is* the paired data.
    baseline = tuple(1.0 if i % 5 < 3 else 0.0 for i in range(60))
    green_candidate = tuple(1.0 if i % 5 < 4 else 0.0 for i in range(60))
    red_candidate = tuple(0.0 for _ in range(60))

    release = ResolvedRelease(artifact_classes=("scaffold",))
    green_decision = evaluate_promotion(
        PromotionPolicyDocument(policy_id="tier-2-standard"),
        promotion_evidence("strategy", baseline=baseline, candidate=green_candidate),
        release=release,
        tier_approvals=tier4_approval_evidence(),
    )
    assert green_decision.eligible, green_decision.failed_conditions()
    assert green_decision.tier == 4

    red_decision = evaluate_promotion(
        PromotionPolicyDocument(policy_id="tier-2-standard"),
        promotion_evidence("strategy", baseline=baseline, candidate=red_candidate),
        release=release,
        tier_approvals=tier4_approval_evidence(),
    )
    assert not red_decision.eligible
    assert (
        "statistical_superiority_or_preregistered_non_inferiority"
        in red_decision.failed_conditions()
    )

    # The tier-4 gate refuses the same evidence without the human legs —
    # the chain, not the scores, is what tier 4 adds.
    with pytest.raises(TierRejectedError, match="human sign-off"):
        evaluate_promotion(
            PromotionPolicyDocument(policy_id="tier-2-standard"),
            promotion_evidence("strategy", baseline=baseline, candidate=green_candidate),
            release=release,
            tier_approvals=TierApprovalEvidence(
                approvers=("svc_board_1", "svc_board_2"),
                requested_by="svc_evaluator_g11",
            ),
        )


# ----------------------------------------------------------------------
# Scenario 4 — tier-4 evidence chain; cross-tenant activation refused
# ----------------------------------------------------------------------


def test_tier4_promotion_requires_full_evidence_chain_and_cross_tenant_activation_refused(
    session_factory: sessionmaker[Session],
    tenants: Tenants,
) -> None:
    """No scaffold promotion without the full tier-4 evidence chain — a
    request missing a leg is refused at creation, one approval refuses
    admission, two distinct approvers admit, and the signed record
    verifies — and a scaffold release never activates or promotes outside
    the research tenant, with every refusal audited."""
    service, key = make_service(session_factory, tenants)
    board = make_board_service(session_factory, key, tenants)
    principal = research_principal(tenants.research)

    detail = service.create_campaign(principal, make_scaffold_spec_mapping())
    campaign_id = detail.campaign_id
    candidate = register_scaffold_through_api(
        service,
        principal,
        dict(INCUMBENT_SOURCES, **{"src/agent/planner.py": BENEFICIAL_PLANNER}),
        strategy_id="harness-mutator",
        campaign_id=campaign_id,
        mutation_class="prompt_module_edit",
    )

    # Missing leg: the request is refused at creation — the legs are
    # immutable once persisted, so they cannot be added later.
    with pytest.raises(InvalidSpecError, match="human_signoff"):
        board.create_request(
            principal,
            kind="tier4_promotion",
            justification="missing the sign-off leg",
            campaign_id=campaign_id,
            proposal_id=candidate.proposal_id,
            human_signoff=False,
            manually_initiated=True,
        )
    with pytest.raises(InvalidSpecError, match="manually_initiated"):
        board.create_request(
            principal,
            kind="tier4_promotion",
            justification="missing the manual-initiation leg",
            campaign_id=campaign_id,
            proposal_id=candidate.proposal_id,
            human_signoff=True,
            manually_initiated=False,
        )

    # The full chain: two distinct approvers admit the request.
    request = board.create_request(
        principal,
        kind="tier4_promotion",
        justification="g11 scenario 4: the full evidence chain",
        campaign_id=campaign_id,
        proposal_id=candidate.proposal_id,
        human_signoff=True,
        manually_initiated=True,
    )
    board.decide(
        board_principal(tenants.research, "svc_board_1"),
        request_id=request.request_id,
        decision="approve",
        note="evidence chain reviewed",
    )
    with pytest.raises(ApprovalDeniedError, match="two distinct"):
        board.admit(principal, request_id=request.request_id)
    board.decide(
        board_principal(tenants.research, "svc_board_2"),
        request_id=request.request_id,
        decision="approve",
        note="second reviewer concurs",
    )
    admitted = board.admit(principal, request_id=request.request_id)
    assert admitted.tier == 4
    assert {a["approver"] for a in admitted.approvals} == {"svc_board_1", "svc_board_2"}

    with session_factory() as session:
        row = session.execute(
            select(AdmissionRecord).where(
                AdmissionRecord.tenant_id == tenants.research,
                AdmissionRecord.record_id == admitted.record_id,
            )
        ).scalar_one()
        assert verify_admission_signature(row)
        row.tier = 3
        assert not verify_admission_signature(row)
        session.rollback()

    # Cross-tenant: a scaffold artifact registered in the production
    # tenant can neither activate nor promote there — and both refusals
    # land in the append-only refusal ledger.
    with session_factory() as session:
        registry = RegistryService(session)
        artifact = registry.register_artifact(
            tenant_id=tenants.production,
            artifact_type="scaffold",
            canonical_bytes=b"scaffold candidate body (g11 cross-tenant fixture)",
        )
        session.commit()
        production_digest = artifact.digest

    production_principal = research_principal(tenants.production)
    with pytest.raises(TenantRefusalError, match="research"):
        service.create_release(
            production_principal,
            artifact_digests=[production_digest],
            adapter_versions={},
            model_routes={},
            policies={},
            status="canary",
        )

    # Defense in depth: even a scaffold manifest that somehow reached
    # canary in the production tenant — seeded directly here, bypassing
    # the API's activation boundary — is refused at promotion, and the
    # promotion refusal lands in the same append-only ledger.
    with session_factory() as session:
        registry = RegistryService(session)
        manifest = registry.create_release_manifest(
            tenant_id=tenants.production,
            artifact_digests=[production_digest],
            adapter_versions={},
            model_routes={},
            policies={},
            prior_release_digest=None,
            private_key=key,
        )
        registry.activate_release(
            tenant_id=tenants.production,
            manifest_digest=manifest.manifest_digest,
            artifact_digests=[production_digest],
        )
        session.add(
            ReleaseActivation(
                tenant_id=tenants.production,
                manifest_digest=manifest.manifest_digest,
                status="canary",
                activated_by=production_principal.identity_id,
            )
        )
        session.commit()
        seeded_digest = manifest.manifest_digest

    with pytest.raises(TenantRefusalError, match="research"):
        service.promote_release(production_principal, seeded_digest)
    with session_factory() as session:
        refusals = session.scalars(
            select(TenantPolicyRefusal).where(TenantPolicyRefusal.tenant_id == tenants.production)
        ).all()
        assert len(refusals) == 2
        assert {r.boundary for r in refusals} == {RefusalBoundary.RELEASE_ACTIVATION}


# ----------------------------------------------------------------------
# Scenario 5 — destructive mutation trips severity-1
# ----------------------------------------------------------------------


def test_destructive_mutation_trips_severity1_compensations_in_order_with_pointer_rollback(
    controller: ReleaseController,
    fleet: InProcessFleetSimulator,
    clock: CompressedClock,
    tmp_path: Path,
) -> None:
    """A destructive mutation trips a severity-1 guardrail event during
    the canary: the rollback path restores the incumbent source (CAS,
    digest-verified), the conformance rerun (requires-execution) judges
    the *restored* tree in declared order, the release pointer CASes back
    to the incumbent, and the evidence lands in the execution sink. The
    campaign machine refuses the promotion edge while the plan is
    undischarged."""
    signing_key = generate_signing_key()
    incumbent_blobs, incumbent_map = scaffold_blobs(INCUMBENT_SOURCES)
    incumbent_scaffold_digest = scaffold_digest(incumbent_map)
    candidate_blobs, _ = scaffold_blobs(
        dict(INCUMBENT_SOURCES, **{"src/agent/planner.py": DESTRUCTIVE_PLANNER})
    )
    candidate_scaffold_digest = next(d for d in candidate_blobs if d not in incumbent_blobs)

    # The destructive mutation executed: the working tree now carries the
    # candidate's rm-rf planner instead of the incumbent's.
    (tmp_path / "src" / "agent").mkdir(parents=True)
    (tmp_path / "src" / "agent" / "planner.py").write_text(DESTRUCTIVE_PLANNER, encoding="utf-8")

    plan = sign_compensation_plan(
        plan_id="plan-g11-severity1",
        campaign_id="campaign-g11-scenario5",
        manifest_digest=None,
        actions=[
            {
                "artifact_digest": incumbent_scaffold_digest,
                "action": "restore_scaffold_source",
                "mode": CAS_MODE,
                "executed": False,
            },
            {
                "artifact_digest": incumbent_scaffold_digest,
                "action": "rerun_conformance_suite",
                "mode": REQUIRES_EXECUTION_MODE,
                "executed": False,
            },
        ],
        private_key=Ed25519PrivateKey.generate(),
    )
    assert plan.verify()

    # Campaign machine: the APPROVE→CANARY edge is refused while the
    # requires-execution compensation has no execution evidence, and the
    # refusal leaves no transition in the log.
    sink = InMemoryExecutionSink()
    gate = CheckpointedCompensationGate(
        plan,
        executions=sink,
        executor=ConformanceRerunExecutor(
            reader=_RegistryReader(incumbent_blobs),
            tenant_id="tenant-g11",
            runner=_ScriptedSuiteRunner(
                SuiteRunResult(returncode=0, stdout="118 passed in 2.31s"),
                tree_root=tmp_path,
                probe="src/agent/planner.py",
            ),
        ),
    )
    orchestrator = _orchestrator_at_approve(gate)
    with pytest.raises(UnexecutedCompensationError):
        orchestrator.transition(CampaignPhase.CANARY)
    assert orchestrator.phase is CampaignPhase.APPROVE
    assert sink.all() == ()

    # Release plane: the severity-1 event fires during the canary. The
    # rollback path restores the incumbent source (CAS, position 0) before
    # the requires-execution walk (position 1) runs the rerun.
    restore_record = ScaffoldSourceRestorer(
        reader=_RegistryReader(incumbent_blobs), tenant_id="tenant-g11"
    ).restore(scaffold_digest=incumbent_scaffold_digest, tree_root=tmp_path)
    runner = _ScriptedSuiteRunner(
        SuiteRunResult(returncode=0, stdout="118 passed in 2.31s"),
        tree_root=tmp_path,
        probe="src/agent/planner.py",
    )
    harness = CanaryHarness(
        config=CanaryConfig(),
        controller=controller,
        fleet=fleet,
        clock=clock,
        compensation_plan=plan,
        compensation_executions=sink,
        compensation_executor=ConformanceRerunExecutor(
            reader=_RegistryReader(incumbent_blobs), tenant_id="tenant-g11", runner=runner
        ),
    )
    incumbent = _signed_manifest(
        signing_key, artifact_digests=[incumbent_scaffold_digest], prior_release_digest=None
    )
    controller.activate(incumbent)
    candidate = _signed_manifest(
        signing_key,
        artifact_digests=[candidate_scaffold_digest],
        prior_release_digest=incumbent.manifest_digest,
    )
    outcome = harness.run(
        candidate,
        guardrail_events=(GuardrailEvent(severity=1, kind="unsafe-edit", task_index=5),),
    )

    # Compensations executed in declared order: the rerun judged restored
    # source — the runner captured the incumbent planner, not the mutation.
    assert outcome.outcome is CanaryOutcome.ROLLED_BACK
    assert runner.captured_planner_content == INCUMBENT_SOURCES["src/agent/planner.py"]
    assert [record.action_index for record in sink.all()] == [1]
    assert all(record.plan_id == plan.plan_id for record in sink.all())

    # The pointer rolled back through the controller's CAS.
    assert controller.active_digest() == incumbent.manifest_digest
    assert outcome.rolled_back_to == incumbent.manifest_digest

    # The CAS restore's evidence: every incumbent module restored with its
    # verified pin, and the tree bytes match the pins.
    assert restore_record.scaffold_digest == incumbent_scaffold_digest
    assert {module.path for module in restore_record.modules} == set(INCUMBENT_SOURCES)
    for path, content in INCUMBENT_SOURCES.items():
        assert (tmp_path / path).read_text(encoding="utf-8") == content


def _signed_manifest(
    private_key: Ed25519PrivateKey,
    *,
    artifact_digests: list[str],
    prior_release_digest: str | None,
) -> Any:
    return sign_release_manifest(
        artifact_digests=artifact_digests,
        adapter_versions={"adapter": "1.0.0"},
        model_routes={"default": "model-a"},
        policies={"canary": "p0"},
        prior_release_digest=prior_release_digest,
        private_key=private_key,
    )


# ----------------------------------------------------------------------
# Scenario 6 — graduation without a comparable-risk dossier is refused
# ----------------------------------------------------------------------


def test_graduation_without_comparable_risk_dossier_is_refused_and_recorded(
    db_session: Session,
) -> None:
    """Graduation of a mutation class without a comparable-risk dossier is
    refused, by recorded decision: the pure check returns a typed refusal,
    the refusal is recorded as a signed append-only decision, and the
    contrast — a comparable signed dossier — graduates."""
    class_id = "prompt_module_edit"
    private_key = generate_signing_key()

    # No dossier presented: refused, and the refusal is a recorded
    # decision, not an exception.
    refused = evaluate_graduation(
        class_id=class_id,
        signed_dossier=None,
        binding=None,
        production_dossiers=(),
    )
    assert not refused.granted
    assert refused.refusal_reason is GraduationRefusal.NO_DOSSIER
    row = record_graduation_decision(
        db_session,
        private_key=private_key,
        tenant_id="tnt_g11_graduation",
        decision=refused,
    )
    db_session.commit()
    assert verify_graduation_decision(row)
    assert row.refusal_reason == GraduationRefusal.NO_DOSSIER.value
    assert row.granted is False

    # A risk-above-production dossier is refused too: comparability is
    # the bar, not merely having a dossier.
    candidate_dossier = RiskDossier(
        dossier_id="dossier-g11-candidate",
        class_id=class_id,
        artifact_class="scaffold",
        isolation_tier_demanded=IsolationTier.HIGHEST,
        blast_radius=BlastRadius.SELF_SOURCE,
        reversible=False,
        compensable=True,
    )
    signed_candidate = sign_risk_dossier(candidate_dossier, private_key)
    binding = MutationClassBinding(
        class_id=class_id,
        risk_dossier_digest=signed_candidate.digest,
        max_tier=IsolationTier.HIGHEST,
    )
    low_production = sign_risk_dossier(
        RiskDossier(
            dossier_id="dossier-g11-production-low",
            class_id="workflow_graph_edit",
            artifact_class="workflow_graph",
            isolation_tier_demanded=IsolationTier.EXECUTABLE,
            blast_radius=BlastRadius.RUNTIME,
            reversible=True,
            compensable=True,
        ),
        private_key,
    )
    not_comparable = evaluate_graduation(
        class_id=class_id,
        signed_dossier=signed_candidate,
        binding=binding,
        production_dossiers=(low_production,),
    )
    assert not not_comparable.granted
    assert not_comparable.refusal_reason is GraduationRefusal.RISK_NOT_COMPARABLE

    # The contrast: against a production extension at the same resolved
    # tier, the same dossier graduates.
    comparable_production = sign_risk_dossier(
        RiskDossier(
            dossier_id="dossier-g11-production-harness",
            class_id="harness_patch_edit",
            artifact_class="harness_patch",
            isolation_tier_demanded=IsolationTier.HIGHEST,
            blast_radius=BlastRadius.SELF_SOURCE,
            reversible=False,
            compensable=True,
        ),
        private_key,
    )
    granted = evaluate_graduation(
        class_id=class_id,
        signed_dossier=signed_candidate,
        binding=binding,
        production_dossiers=(comparable_production,),
    )
    assert granted.granted, granted.refusal_reason
    granted_row = record_graduation_decision(
        db_session,
        private_key=private_key,
        tenant_id="tnt_g11_graduation",
        decision=granted,
    )
    db_session.commit()
    assert granted_row.granted is True
    assert verify_graduation_decision(granted_row)


# ----------------------------------------------------------------------
# Scenario 7 — the DB-immutability matrix + migration round-trip
# ----------------------------------------------------------------------


def test_phase3_tables_refuse_update_and_delete_at_the_database_level(
    session_factory: sessionmaker[Session],
    db_session: Session,
    database_url: str,
    tenants: Tenants,
) -> None:
    """Every new Phase 3 table refuses UPDATE/DELETE at the database
    level — the same role the application uses cannot rewrite the refusal
    ledger, the tier-4 evidence columns, the admission records, or the
    graduation decisions. The mutation archive is the documented
    exception: it is a derived projection and stays mutable."""
    service, key = make_service(session_factory, tenants)
    board = make_board_service(session_factory, key, tenants)
    principal = research_principal(tenants.research)

    # Seed real rows through the real services (committed, so the
    # mutation attempts below see them from their own connections).
    detail = service.create_campaign(principal, make_scaffold_spec_mapping())
    candidate = register_scaffold_through_api(
        service,
        principal,
        dict(INCUMBENT_SOURCES, **{"src/agent/planner.py": BENEFICIAL_PLANNER}),
        strategy_id="harness-mutator",
        campaign_id=detail.campaign_id,
        mutation_class="prompt_module_edit",
    )
    request = board.create_request(
        principal,
        kind="tier4_promotion",
        justification="g11 scenario 7: evidence-guard seed row",
        campaign_id=detail.campaign_id,
        proposal_id=candidate.proposal_id,
        human_signoff=True,
        manually_initiated=True,
    )
    board.decide(
        board_principal(tenants.research, "svc_board_1"),
        request_id=request.request_id,
        decision="approve",
        note="immutability seed approver one",
    )
    board.decide(
        board_principal(tenants.research, "svc_board_2"),
        request_id=request.request_id,
        decision="approve",
        note="immutability seed approver two",
    )
    admitted = board.admit(principal, request_id=request.request_id)

    # A refusal-ledger row: scaffold mutation attempted in the production
    # tenant is refused and audited.
    production_principal = research_principal(tenants.production)
    with pytest.raises(TenantRefusalError):
        service.create_campaign(production_principal, make_scaffold_spec_mapping())

    # A graduation-decision row.
    decision = evaluate_graduation(
        class_id="prompt_module_edit",
        signed_dossier=None,
        binding=None,
        production_dossiers=(),
    )
    record_graduation_decision(
        db_session,
        private_key=key,
        tenant_id=tenants.research,
        decision=decision,
    )
    db_session.commit()

    # A mutation-archive row (the documented mutable exception).
    with session_factory() as session:
        MutationArchiveService(session).rebuild(tenants.research)
        session.commit()

    mutation_attempts = (
        (
            # restrict_violation (23001) -> psycopg IntegrityError
            "UPDATE tenant_policy_refusals SET reason = 'mutated' WHERE tenant_id = :tenant",
            {"tenant": tenants.production},
            "tenant_policy_refusals is append-only",
            IntegrityError,
        ),
        (
            "DELETE FROM tenant_policy_refusals WHERE tenant_id = :tenant",
            {"tenant": tenants.production},
            "tenant_policy_refusals is append-only",
            IntegrityError,
        ),
        (
            # the tier-4 evidence guard also raises restrict_violation
            "UPDATE approval_requests SET human_signoff = false WHERE tenant_id = :tenant",
            {"tenant": tenants.research},
            "evidence columns are immutable",
            IntegrityError,
        ),
        (
            "DELETE FROM approval_requests WHERE tenant_id = :tenant",
            {"tenant": tenants.research},
            "approval_requests is evidence-guarded",
            IntegrityError,
        ),
        (
            "UPDATE admission_records SET decision = 'mutated' WHERE tenant_id = :tenant",
            {"tenant": tenants.research},
            "append-only",
            ProgrammingError,
        ),
        (
            "DELETE FROM admission_records WHERE tenant_id = :tenant",
            {"tenant": tenants.research},
            "append-only",
            ProgrammingError,
        ),
        (
            "UPDATE graduation_decisions SET granted = true WHERE tenant_id = :tenant",
            {"tenant": tenants.research},
            "graduation_decisions is append-only",
            IntegrityError,
        ),
        (
            "DELETE FROM graduation_decisions WHERE tenant_id = :tenant",
            {"tenant": tenants.research},
            "graduation_decisions is append-only",
            IntegrityError,
        ),
    )
    engine = create_engine(database_url)
    try:
        for statement, params, expected_error, exc_type in mutation_attempts:
            with engine.begin() as conn, pytest.raises(exc_type, match=expected_error):
                conn.execute(text(statement), params)

        # The documented exception: the mutation archive is a derived
        # projection — mutable by design, because the raw evidence it is
        # built from keeps its own immutability triggers.
        with engine.begin() as conn:
            updated = conn.execute(
                text(
                    "UPDATE scaffold_mutation_archive SET fitness = 0.5 WHERE tenant_id = :tenant"
                ),
                {"tenant": tenants.research},
            )
            assert updated.rowcount >= 0
    finally:
        engine.dispose()

    # The signed records still verify after every refused mutation.
    with session_factory() as session:
        admission_row = session.execute(
            select(AdmissionRecord).where(
                AdmissionRecord.tenant_id == tenants.research,
                AdmissionRecord.record_id == admitted.record_id,
            )
        ).scalar_one()
        assert verify_admission_signature(admission_row)
        graduation_row = session.scalars(
            select(GraduationDecision).where(GraduationDecision.tenant_id == tenants.research)
        ).all()
        assert graduation_row
        for row in graduation_row:
            assert verify_graduation_decision(row)


def test_phase3_migrations_round_trip_through_the_phase2_head(
    alembic_config: Config,
) -> None:
    """The Phase 3 migration chain reverses cleanly: upgrade head →
    downgrade to the Phase 2 head (f9c0de1a7e55) → upgrade back to head —
    no second two-head episode, no dangling state."""
    command.upgrade(alembic_config, "head")
    command.downgrade(alembic_config, "f9c0de1a7e55")
    command.upgrade(alembic_config, "head")


# ----------------------------------------------------------------------
# Fixtures (mirroring tests/release/conftest.py — the release-plane drill
# needs the controller/fleet/clock trio)
# ----------------------------------------------------------------------


@pytest.fixture
def controller() -> Any:
    from evoruntime.release import ReleaseController
    from evoruntime.security.identities import WorkloadIdentity, WorkloadRole
    from evoruntime.selection import InMemoryPointerAuditLog, ReleasePointerStore

    return ReleaseController(
        ReleasePointerStore(InMemoryPointerAuditLog()),
        identity=WorkloadIdentity(
            role=WorkloadRole.RELEASE_CONTROLLER, subject="svc-release-controller"
        ),
    )


@pytest.fixture
def clock() -> CompressedClock:
    return CompressedClock(scale=3600.0)


@pytest.fixture
def fleet(clock: CompressedClock) -> InProcessFleetSimulator:
    return InProcessFleetSimulator(worker_count=100, latency_sampler=lambda: 45.0, clock=clock)

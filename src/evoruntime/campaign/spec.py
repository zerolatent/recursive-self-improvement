"""The declarative campaign spec (PRD §11.2) — everything pinned before search.

A campaign is a validated, versioned *document*, not a pile of runtime
arguments. Incumbent release, mutable artifact type and paths, strategy
plugin, experiment arms (the three Phase 0 control arms plus the strategy
arm), dataset bindings, evaluators, budgets, promotion policy, statistics
plan, and stopping rules are all fixed here — because a comparison whose
alpha, budget, or mutation surface is chosen after seeing the deltas has
no error rate at all.

Three disciplines this module enforces:

**Pin + sign before search.** `pin_and_sign` hashes the spec's canonical
bytes and signs them with the evaluator's Ed25519 key. The orchestrator
(:mod:`evoruntime.campaign.machine`) refuses to run anything but a pinned
spec whose digest and signature still verify — a spec edited after the
fact is not a preregistration, it is a forgery of one.

**Schema v2 (Phase 2, F4) and the v1 migration window.** The singular
`mutable_artifact` became a `MutableArtifactSet` (>= 1 masked artifacts,
one primary matching the incumbent). v1 documents are accepted until
`V1_MIGRATION_WINDOW_END` (2026-10-27, sixty days after the Phase 2
release branch was cut on 2026-08-28 — see ``docs/campaign-spec-v2.md``);
they are upgraded to the v2 shape at parse time, so a v1 document and the
equivalent v2 document pin to the *same* digest. After the window closes
v1 specs are rejected: the window is for authoring migration, not a
permanent dual-format license.

**The holdout is a handle, never content.** Dataset bindings reference the
holdout through the D5 sealed-handle scheme (`holdout://...`). A spec that
tried to inline holdout content would be a contamination channel wearing a
preregistration's clothes, so the shape rejects it at construction.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Protocol

from evoruntime.campaign.compensation import CompensationActionKind
from evoruntime.campaign.errors import InvalidCampaignSpecError
from evoruntime.datasets.partitions import HOLDOUT_HANDLE_SCHEME
from evoruntime.eval.budgets import resolve_budget_profile
from evoruntime.eval.cascade import EvaluatorCostClass
from evoruntime.eval.errors import UnknownBudgetProfileError
from evoruntime.eval.experiment import Arm, ArmKind
from evoruntime.eval.statistics import MIN_BOOTSTRAP_ITERATIONS, MultiplicityMethod
from evoruntime.plugins.manifest import PluginArtifactType
from evoruntime.security.signing import DetachedSignature, sign, verify

SUPPORTED_SPEC_VERSION = 2
"""The campaign-spec schema version this runtime understands.

A spec carries its version explicitly so a shape change is a refusal with
a clear message, not a silent misread of an old document.
"""

V1_MIGRATION_WINDOW_END = date(2026, 10, 27)
"""Last day `schema_version: 1` campaign specs are accepted.

Sixty days after the Phase 2 release branch was cut (2026-08-28). Until
this date a v1 document is upgraded to the v2 shape at parse time and
pins to the v2 digest; after it, v1 specs are refused. Documented in
``docs/campaign-spec-v2.md``.
"""

_DIGEST_PREFIX = "sha256:"

_HOLDOUT_HANDLE_PREFIX = f"{HOLDOUT_HANDLE_SCHEME}://"


def _require_digest(value: str, what: str) -> str:
    if not value.startswith(_DIGEST_PREFIX):
        raise InvalidCampaignSpecError(
            f"{what} must be a sha256 digest ({_DIGEST_PREFIX}...), got {value!r}"
        )
    return value


def _require_pinned_image(value: str, what: str) -> str:
    if "@sha256:" not in value:
        raise InvalidCampaignSpecError(
            f"{what} must be digest-pinned (name@sha256:...), got {value!r} — "
            "a floating tag is not a reproducible pin"
        )
    return value


@dataclass(frozen=True, slots=True)
class IncumbentBinding:
    """The release the campaign starts from — pinned by manifest digest.

    A campaign improves a *release*, not an artifact in the abstract: the
    digest names the signed ReleaseManifest (E1) every candidate is
    diffed against and every rollback returns to.
    """

    release_manifest_digest: str
    artifact_type: str

    def __post_init__(self) -> None:
        _require_digest(self.release_manifest_digest, "incumbent release manifest digest")
        if self.artifact_type not in {t.value for t in PluginArtifactType}:
            raise InvalidCampaignSpecError(
                f"incumbent artifact_type {self.artifact_type!r} is not a known artifact class"
            )

    def to_canonical_dict(self) -> dict[str, Any]:
        """Canonical JSON form of this binding."""
        return {
            "release_manifest_digest": self.release_manifest_digest,
            "artifact_type": self.artifact_type,
        }


@dataclass(frozen=True, slots=True)
class MutableArtifact:
    """What the campaign may change, and exactly where.

    `paths` is the mutation mask (FR-006): the declared set of paths a
    candidate may edit. Everything else fails validation before execution.
    Paths are relative and traversal-free — an absolute path or a `..`
    segment in the *spec itself* is a spec bug, not a candidate bug.
    """

    artifact_type: str
    paths: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.artifact_type not in {t.value for t in PluginArtifactType}:
            raise InvalidCampaignSpecError(
                f"mutable artifact_type {self.artifact_type!r} is not a known artifact class"
            )
        if not self.paths:
            raise InvalidCampaignSpecError(
                "a campaign must declare at least one mutable path — an empty "
                "mutation mask would make every candidate a violation"
            )
        for path in self.paths:
            _validate_mask_path(path)

    def to_canonical_dict(self) -> dict[str, Any]:
        """Canonical JSON form of this artifact binding."""
        return {"artifact_type": self.artifact_type, "paths": list(self.paths)}


@dataclass(frozen=True, slots=True)
class MutableArtifactSet:
    """The campaign's full mutation surface: one or more masked artifacts.

    Phase 2 (F4) replaces the singular mutable artifact: a campaign may
    change several artifact classes in one composite candidate, each under
    its own mask. Exactly one member is the *primary* — the one whose
    class matches the incumbent release's artifact type, the class the
    campaign is nominally optimizing (enforced by :class:`CampaignSpec`).
    """

    artifacts: tuple[MutableArtifact, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "artifacts", tuple(self.artifacts))
        if not self.artifacts:
            raise InvalidCampaignSpecError(
                "a campaign must declare at least one mutable artifact — an empty "
                "mutation surface would make every candidate a violation"
            )
        types = [artifact.artifact_type for artifact in self.artifacts]
        duplicates = sorted({t for t in types if types.count(t) > 1})
        if duplicates:
            raise InvalidCampaignSpecError(
                f"duplicate artifact_type in the mutable artifact set: "
                f"{', '.join(duplicates)} — one mask per artifact class"
            )

    def to_canonical_dict(self) -> list[dict[str, Any]]:
        """Canonical JSON form of the mutable artifact set (order-pinned):
        the ordered list of member bindings, exactly the v2 authoring shape."""
        return [artifact.to_canonical_dict() for artifact in self.artifacts]


def _validate_mask_path(path: str) -> None:
    if not path or path != path.strip():
        raise InvalidCampaignSpecError(f"mutable path must be non-empty and trimmed: {path!r}")
    if path.startswith("/") or (len(path) > 1 and path[1] == ":"):
        raise InvalidCampaignSpecError(
            f"mutable path {path!r} is absolute — mutation masks are relative"
        )
    if ".." in path.split("/"):
        raise InvalidCampaignSpecError(
            f"mutable path {path!r} contains traversal — masks name real paths"
        )


@dataclass(frozen=True, slots=True)
class CompensationActionSpec:
    """One declared compensating action (F5): what happens to one artifact
    when the release it belongs to is rolled back.

    Classification is by action name, not by a declared mode: CAS actions
    (``restore_prior_release_pointer``, ``revoke_artifact``) need no extra
    execution — the release controller's pointer rollback covers them —
    while ``run_compensation_hook`` must be executed and evidenced, so it
    must pin the hook image it runs. An action targeting an artifact class
    the campaign cannot mutate is refused in :class:`CampaignSpec`.
    """

    artifact_type: str
    action: str
    hook_image: str | None = None

    def __post_init__(self) -> None:
        if self.artifact_type not in {t.value for t in PluginArtifactType}:
            raise InvalidCampaignSpecError(
                f"compensation artifact_type {self.artifact_type!r} is not a known artifact class"
            )
        try:
            CompensationActionKind(self.action)
        except ValueError as exc:
            raise InvalidCampaignSpecError(
                f"compensation action {self.action!r} is not a declared compensating "
                f"action (one of {', '.join(k.value for k in CompensationActionKind)})"
            ) from exc
        if self.action == CompensationActionKind.RUN_COMPENSATION_HOOK.value:
            if self.hook_image is None:
                raise InvalidCampaignSpecError(
                    "a run_compensation_hook action must pin its hook image "
                    "(name@sha256:...) — an unpinned hook is a promise, not a "
                    "compensating action"
                )
            _require_pinned_image(self.hook_image, "compensation hook_image")
        elif self.hook_image is not None:
            raise InvalidCampaignSpecError(
                f"CAS compensation action {self.action!r} takes no hook_image — "
                "CAS compensations need no extra execution"
            )

    def to_canonical_dict(self) -> dict[str, Any]:
        """Canonical JSON form of this action (hook_image only when declared)."""
        entry: dict[str, Any] = {
            "artifact_type": self.artifact_type,
            "action": self.action,
        }
        if self.hook_image is not None:
            entry["hook_image"] = self.hook_image
        return entry


@dataclass(frozen=True, slots=True)
class CompensationPlanSection:
    """The campaign's declared compensation plan (F5): per-artifact
    compensating actions in execution order.

    Declared before search like every other pinned section — a rollback
    plan chosen after seeing what broke is not a transaction plan, it is
    an improvisation with a signature.
    """

    actions: tuple[CompensationActionSpec, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "actions", tuple(self.actions))
        if not self.actions:
            raise InvalidCampaignSpecError(
                "a compensation plan must declare at least one action — an empty "
                "plan is not a plan, omit the section"
            )
        types = [action.artifact_type for action in self.actions]
        duplicates = sorted({t for t in types if types.count(t) > 1})
        if duplicates:
            raise InvalidCampaignSpecError(
                f"duplicate artifact_type in the compensation plan: "
                f"{', '.join(duplicates)} — one compensating action per artifact"
            )

    def to_canonical_dict(self) -> dict[str, Any]:
        """Canonical JSON form of the plan (order-pinned — declared order
        is execution order)."""
        return {"actions": [action.to_canonical_dict() for action in self.actions]}


@dataclass(frozen=True, slots=True)
class StrategyBinding:
    """The strategy plugin the campaign runs, pinned to a container digest."""

    plugin_id: str
    pinned_image: str

    def __post_init__(self) -> None:
        if not self.plugin_id:
            raise InvalidCampaignSpecError("strategy plugin_id must be non-empty")
        _require_pinned_image(self.pinned_image, "strategy pinned_image")

    def to_canonical_dict(self) -> dict[str, Any]:
        """Canonical JSON form of this binding."""
        return {"plugin_id": self.plugin_id, "pinned_image": self.pinned_image}


@dataclass(frozen=True, slots=True)
class DatasetBindings:
    """Which partitions the campaign reads, and how the holdout is reached.

    Dev and selection are named partitions the harness may read. The
    holdout is referenced *only* by its D5 sealed handle — the ledgered,
    alpha-spending indirection whose resolution happens inside the
    evaluation plane, never in campaign code.
    """

    dev_partition: str
    selection_partition: str
    holdout_handle: str

    def __post_init__(self) -> None:
        if not self.dev_partition or not self.selection_partition:
            raise InvalidCampaignSpecError(
                "dataset bindings must name both the dev and selection partitions"
            )
        if not self.holdout_handle.startswith(_HOLDOUT_HANDLE_PREFIX):
            raise InvalidCampaignSpecError(
                f"holdout binding must be a sealed D5 handle "
                f"({_HOLDOUT_HANDLE_PREFIX}...), got {self.holdout_handle!r} — "
                "a campaign never references holdout content directly"
            )

    def to_canonical_dict(self) -> dict[str, Any]:
        """Canonical JSON form of these bindings."""
        return {
            "dev_partition": self.dev_partition,
            "selection_partition": self.selection_partition,
            "holdout_handle": self.holdout_handle,
        }


DEFAULT_MAX_SANDBOX_EXECUTIONS = 240
"""Default campaign-level ceiling on sandbox executions per campaign.

Executable candidates (F1) spend real isolation resources per run —
process spawn, staging, teardown under enforced limits — so the campaign
budget carries its own dimension for them rather than overloading
`max_model_tokens`. The default is generous but finite: a campaign that
runs out of sandbox executions has a search-shape problem worth surfacing,
not silently absorbing.
"""


@dataclass(frozen=True, slots=True)
class EvaluatorBinding:
    """One evaluator the campaign's arms are scored by, pinned by image digest.

    Cascade fields (Phase 2 F6): `stage` orders the cascade (0 is the
    cheapest tier, stages run ascending), `cost_class` describes the
    evaluator's expense for attribution and reporting, and `short_circuit`
    (default true) stops the cascade when this stage fails — expensive
    stages never run after a cheap-stage failure. The defaults make a
    binding with no cascade fields the cheapest, short-circuiting stage,
    which is what a single-evaluator campaign has always been.
    """

    name: str
    pinned_image: str
    stage: int = 0
    cost_class: EvaluatorCostClass = EvaluatorCostClass.CHEAP
    short_circuit: bool = True

    def __post_init__(self) -> None:
        if not self.name:
            raise InvalidCampaignSpecError("evaluator name must be non-empty")
        _require_pinned_image(self.pinned_image, f"evaluator {self.name!r} pinned_image")
        if self.stage < 0:
            raise InvalidCampaignSpecError(
                f"evaluator {self.name!r} stage must be >= 0 (0 is the cheapest tier), "
                f"got {self.stage}"
            )
        if not isinstance(self.cost_class, EvaluatorCostClass):
            try:
                object.__setattr__(self, "cost_class", EvaluatorCostClass(self.cost_class))
            except ValueError as exc:
                raise InvalidCampaignSpecError(
                    f"evaluator {self.name!r} cost_class {self.cost_class!r} is not one of: "
                    f"{', '.join(c.value for c in EvaluatorCostClass)}"
                ) from exc

    def to_canonical_dict(self) -> dict[str, Any]:
        """Canonical JSON form of this binding."""
        return {
            "name": self.name,
            "pinned_image": self.pinned_image,
            "stage": self.stage,
            "cost_class": self.cost_class.value,
            "short_circuit": self.short_circuit,
        }


@dataclass(frozen=True, slots=True)
class CampaignBudgets:
    """The campaign's externally enforced resource envelope.

    `task_budget_profile` names the per-task envelope every arm shares
    (resolved and pinned at construction — an unknown profile name is a
    construction error, not a run-time surprise). The three campaign-level
    ceilings are enforced by the orchestrator's budget meter, *outside*
    the strategy process: a plugin that ignores them simply stops being
    called.
    """

    task_budget_profile: str
    max_proposals: int
    max_model_tokens: int
    max_wall_clock_minutes: float
    max_sandbox_executions: int = DEFAULT_MAX_SANDBOX_EXECUTIONS

    def __post_init__(self) -> None:
        if self.max_proposals < 1:
            raise InvalidCampaignSpecError(
                f"max_proposals must be at least 1, got {self.max_proposals}"
            )
        if self.max_model_tokens < 1:
            raise InvalidCampaignSpecError(
                f"max_model_tokens must be at least 1, got {self.max_model_tokens}"
            )
        if self.max_wall_clock_minutes <= 0:
            raise InvalidCampaignSpecError(
                f"max_wall_clock_minutes must be positive, got {self.max_wall_clock_minutes!r}"
            )
        if self.max_sandbox_executions < 1:
            raise InvalidCampaignSpecError(
                f"max_sandbox_executions must be at least 1, got {self.max_sandbox_executions}"
            )
        # Resolving here turns an unknown profile name into a construction
        # error instead of a run-time one (same discipline as Experiment).
        # Wrapped so the campaign error surface stays coherent; the
        # original error rides the chain.
        try:
            resolve_budget_profile(self.task_budget_profile)
        except UnknownBudgetProfileError as exc:
            raise InvalidCampaignSpecError(
                f"unknown task_budget_profile {self.task_budget_profile!r} — "
                f"the spec must name a registered budget profile"
            ) from exc

    def to_canonical_dict(self) -> dict[str, Any]:
        """Canonical JSON form of these budgets."""
        return {
            "task_budget_profile": self.task_budget_profile,
            "max_proposals": self.max_proposals,
            "max_model_tokens": self.max_model_tokens,
            "max_wall_clock_minutes": self.max_wall_clock_minutes,
            "max_sandbox_executions": self.max_sandbox_executions,
        }


@dataclass(frozen=True, slots=True)
class StoppingRules:
    """Declarative search-stop conditions, evaluated by the orchestrator.

    Distinct from budgets: a budget is a ceiling the meter enforces
    mid-flight; a stopping rule is a preregistered condition under which
    the campaign *declares* it is done (no improvement for N rounds, or a
    hard round cap). Both are pinned before search so "when did we stop
    and why" is answerable from the spec alone.
    """

    max_rounds: int
    max_no_improvement_rounds: int

    def __post_init__(self) -> None:
        if self.max_rounds < 1:
            raise InvalidCampaignSpecError(f"max_rounds must be at least 1, got {self.max_rounds}")
        if self.max_no_improvement_rounds < 1:
            raise InvalidCampaignSpecError(
                "max_no_improvement_rounds must be at least 1, "
                f"got {self.max_no_improvement_rounds}"
            )

    def to_canonical_dict(self) -> dict[str, Any]:
        """Canonical JSON form of these rules."""
        return {
            "max_rounds": self.max_rounds,
            "max_no_improvement_rounds": self.max_no_improvement_rounds,
        }


@dataclass(frozen=True, slots=True)
class PromotionPolicyRef:
    """Reference to the declarative promotion policy (§12.5 gates as data).

    The policy document is part of the campaign's preregistration: the
    digest pins which gate set — thresholds, non-inferiority margins,
    authority tier — this campaign will be judged by, chosen before any
    result exists.
    """

    policy_id: str
    policy_digest: str

    def __post_init__(self) -> None:
        if not self.policy_id:
            raise InvalidCampaignSpecError("promotion policy_id must be non-empty")
        _require_digest(self.policy_digest, "promotion policy digest")

    def to_canonical_dict(self) -> dict[str, Any]:
        """Canonical JSON form of this reference."""
        return {"policy_id": self.policy_id, "policy_digest": self.policy_digest}


@dataclass(frozen=True, slots=True)
class StatisticsPlan:
    """The preregistered analysis: alpha, multiplicity, bootstrap shape.

    Reuses the Phase 0 statistics module's constants and enum — the
    selector consumes `eval/statistics.py` directly, so the campaign's
    analysis plan and the code that executes it cannot drift apart.
    """

    alpha: float
    multiplicity: MultiplicityMethod
    bootstrap_iterations: int
    bootstrap_seed: int
    ablation_family: tuple[str, ...] = ()
    """The preregistered ablation family (FR-101): the component ids the
    campaign may ablate, pinned at spec time. An ABLATION arm naming a
    component outside this set is refused — the family is a preregistration,
    and one that could grow after seeing the deltas would not be one."""

    def __post_init__(self) -> None:
        object.__setattr__(self, "ablation_family", tuple(self.ablation_family))
        for component_id in self.ablation_family:
            if not component_id or component_id != component_id.strip():
                raise InvalidCampaignSpecError(
                    f"ablation family entries must be non-empty and trimmed, got {component_id!r}"
                )
        duplicates = sorted(c for c in self.ablation_family if self.ablation_family.count(c) > 1)
        if duplicates:
            raise InvalidCampaignSpecError(
                f"duplicate component in the ablation family: {', '.join(duplicates)}"
            )
        if not 0.0 < self.alpha < 1.0:
            raise InvalidCampaignSpecError(f"alpha must be in (0, 1), got {self.alpha!r}")
        if self.bootstrap_iterations < MIN_BOOTSTRAP_ITERATIONS:
            raise InvalidCampaignSpecError(
                f"bootstrap_iterations must be at least {MIN_BOOTSTRAP_ITERATIONS}, "
                f"got {self.bootstrap_iterations}"
            )

    def to_canonical_dict(self) -> dict[str, Any]:
        """Canonical JSON form of this plan."""
        return {
            "alpha": self.alpha,
            "multiplicity": self.multiplicity.value,
            "bootstrap_iterations": self.bootstrap_iterations,
            "bootstrap_seed": self.bootstrap_seed,
            "ablation_family": list(self.ablation_family),
        }


@dataclass(frozen=True, slots=True)
class CampaignSpec:
    """A validated, versioned §11.2 campaign document.

    Construction is validation: every `__post_init__` in this module runs
    before `CampaignSpec(...)` returns, so an object of this type is
    already known to be runnable-shaped. What it is *not* yet is trusted —
    that requires `pin_and_sign`, and the orchestrator enforces it.
    """

    schema_version: int
    name: str
    incumbent: IncumbentBinding
    mutable_artifacts: MutableArtifactSet
    strategy_plugin: StrategyBinding
    arms: tuple[Arm, ...]
    datasets: DatasetBindings
    evaluators: tuple[EvaluatorBinding, ...]
    budgets: CampaignBudgets
    promotion_policy: PromotionPolicyRef
    statistics: StatisticsPlan
    stopping_rules: StoppingRules
    compensation_plan: CompensationPlanSection | None = None
    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "arms", tuple(self.arms))
        object.__setattr__(self, "evaluators", tuple(self.evaluators))
        object.__setattr__(self, "metadata", dict(self.metadata))

        if self.schema_version != SUPPORTED_SPEC_VERSION:
            raise InvalidCampaignSpecError(
                f"unsupported campaign spec schema_version {self.schema_version!r} "
                f"(this runtime supports {SUPPORTED_SPEC_VERSION})"
            )
        if not self.name:
            raise InvalidCampaignSpecError("campaign name must be non-empty")
        self._validate_artifact_consistency()
        self._validate_arms()
        self._validate_compensation_plan()
        if not self.evaluators:
            raise InvalidCampaignSpecError(
                "a campaign must declare at least one evaluator — an unscored "
                "campaign produces numbers nobody can trust"
            )

    def _validate_artifact_consistency(self) -> None:
        """Exactly one mutable artifact matches the incumbent's class.

        The primary member is the class the campaign optimizes — a spec
        whose mutable set does not contain the incumbent's artifact type
        would diff candidates against a release they are not comparable
        to; more than one member of that class would leave "the primary"
        ambiguous.
        """
        matching = [
            artifact
            for artifact in self.mutable_artifacts.artifacts
            if artifact.artifact_type == self.incumbent.artifact_type
        ]
        if len(matching) != 1:
            raise InvalidCampaignSpecError(
                f"the mutable artifact set must contain exactly one artifact of the "
                f"incumbent's artifact_type {self.incumbent.artifact_type!r} (the "
                f"primary), found {len(matching)}"
            )

    def _validate_arms(self) -> None:
        """Require the full preregistered frame: three controls + strategy.

        The three Phase 0 arms are what make the strategy arm's result
        meaningful (the PRD's kill condition is an equal-compute retry arm
        matching the optimizer), so a campaign spec that omits any of them
        is not a weaker campaign, it is an invalid one.
        """
        if not self.arms:
            raise InvalidCampaignSpecError("a campaign needs at least one arm")
        ids = [arm.id for arm in self.arms]
        duplicates = sorted({arm_id for arm_id in ids if ids.count(arm_id) > 1})
        if duplicates:
            raise InvalidCampaignSpecError(f"duplicate arm ids: {', '.join(duplicates)}")
        kinds = [arm.kind for arm in self.arms]
        required = (
            ArmKind.INCUMBENT,
            ArmKind.RETRY_SELF_CONSISTENCY,
            ArmKind.ONE_SHOT_CONTROL,
            ArmKind.STRATEGY,
        )
        for kind in required:
            if kinds.count(kind) != 1:
                raise InvalidCampaignSpecError(
                    f"a campaign needs exactly one {kind.value} arm "
                    f"(the three Phase 0 control arms plus the strategy arm), "
                    f"found {kinds.count(kind)}"
                )
        self._validate_ablation_arms()

    def _validate_ablation_arms(self) -> None:
        """Hold every ABLATION arm inside the preregistered family (FR-101).

        The ablation family lives in the statistics plan — the analysis is
        part of the preregistration, so the same closure that pins the
        nomination metric's namespace pins which components may be ablated.
        An arm ablating a component the spec never named is a post-hoc
        ablation, refused at construction.
        """
        family = set(self.statistics.ablation_family)
        for arm in self.arms:
            if arm.kind is not ArmKind.ABLATION:
                continue
            if not self.statistics.ablation_family:
                raise InvalidCampaignSpecError(
                    f"ablation arm {arm.id!r} has no preregistered ablation family — "
                    "declare 'statistics.ablation_family' before any ablation can run"
                )
            if arm.component_id not in family:
                raise InvalidCampaignSpecError(
                    f"ablation arm {arm.id!r} ablates component {arm.component_id!r}, "
                    "which is not in the preregistered ablation family — the family "
                    "is pinned at spec time and cannot grow post-hoc"
                )

    def _validate_compensation_plan(self) -> None:
        """Compensating actions may only target mutable artifacts (F5).

        A campaign can only compensate what it mutates: an action naming
        an artifact class outside the mutable set would promise to undo
        a change the campaign cannot make.
        """
        if self.compensation_plan is None:
            return
        mutable = {artifact.artifact_type for artifact in self.mutable_artifacts.artifacts}
        for action in self.compensation_plan.actions:
            if action.artifact_type not in mutable:
                raise InvalidCampaignSpecError(
                    f"compensation action targets {action.artifact_type!r}, which is not "
                    "in the mutable artifact set — a campaign can only compensate "
                    "what it mutates"
                )

    @property
    def mutable_artifact(self) -> MutableArtifact:
        """The primary mutable artifact (the incumbent's class).

        Back-compat view over the v2 set: the Phase 1 singular binding is
        exactly the primary member of the v2 shape. Validation guarantees
        exactly one member of this class exists.
        """
        return next(
            artifact
            for artifact in self.mutable_artifacts.artifacts
            if artifact.artifact_type == self.incumbent.artifact_type
        )

    # -- canonical form, digest, pinning -----------------------------------

    def to_canonical_dict(self) -> dict[str, Any]:
        """The spec as a canonical JSON-serializable dict (sorted downstream).

        One explicit serializer rather than `dataclasses.asdict`: the
        canonical bytes are a *contract* (they are what gets digested and
        signed), so their shape is pinned here, not derived from field
        order or enum reprs.
        """
        return {
            "schema_version": SUPPORTED_SPEC_VERSION,
            "name": self.name,
            "incumbent": self.incumbent.to_canonical_dict(),
            "mutable_artifacts": self.mutable_artifacts.to_canonical_dict(),
            "strategy_plugin": self.strategy_plugin.to_canonical_dict(),
            "arms": [
                {
                    "id": arm.id,
                    "kind": arm.kind.value,
                    "max_attempts": arm.max_attempts,
                    # component_id is an ABLATION-only field: omitting it
                    # for every other kind keeps the canonical bytes (and
                    # so the digest) stable for specs that predate F8.
                    **({"component_id": arm.component_id} if arm.component_id is not None else {}),
                }
                for arm in self.arms
            ],
            "datasets": self.datasets.to_canonical_dict(),
            "evaluators": [e.to_canonical_dict() for e in self.evaluators],
            "budgets": self.budgets.to_canonical_dict(),
            "promotion_policy": self.promotion_policy.to_canonical_dict(),
            "statistics": self.statistics.to_canonical_dict(),
            "stopping_rules": self.stopping_rules.to_canonical_dict(),
            "compensation_plan": (
                self.compensation_plan.to_canonical_dict()
                if self.compensation_plan is not None
                else None
            ),
            "metadata": dict(sorted(self.metadata.items())),
        }

    def canonical_bytes(self) -> bytes:
        """Canonical JSON bytes: sorted keys, no whitespace, UTF-8.

        The digest and the signature are both computed over exactly these
        bytes, so "the spec" and "its canonical form" are the same thing.
        """
        return json.dumps(
            self.to_canonical_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    @property
    def digest(self) -> str:
        """Content digest of the spec's canonical bytes (`sha256:...`)."""
        return _DIGEST_PREFIX + hashlib.sha256(self.canonical_bytes()).hexdigest()

    @classmethod
    def from_yaml(cls, text: str) -> CampaignSpec:
        """Parse and validate a §11.2 YAML campaign spec.

        YAML is the authoring surface; the validated dataclass is the
        runtime surface. Every structural problem — missing key, wrong
        type, bad digest shape — is a construction error here, before any
        pinning or execution.
        """
        import yaml  # imported lazily: YAML is an authoring concern, not a runtime one

        try:
            raw = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise InvalidCampaignSpecError(f"campaign spec is not valid YAML: {exc}") from exc
        if not isinstance(raw, dict):
            raise InvalidCampaignSpecError("campaign spec must be a YAML mapping")
        return cls.from_mapping(raw)

    @classmethod
    def from_mapping(cls, raw: dict[str, Any]) -> CampaignSpec:
        """Build a spec from an already-parsed mapping (tests, API payloads)."""
        try:
            schema_version = _require_int(raw["schema_version"], "schema_version")
            return cls(
                schema_version=SUPPORTED_SPEC_VERSION,
                name=_require_str(raw["name"], "name"),
                incumbent=IncumbentBinding(
                    release_manifest_digest=_require_str(
                        raw["incumbent"]["release_manifest_digest"], "release digest"
                    ),
                    artifact_type=_require_str(
                        raw["incumbent"]["artifact_type"], "incumbent artifact_type"
                    ),
                ),
                mutable_artifacts=_parse_mutable_artifacts(raw, schema_version),
                strategy_plugin=StrategyBinding(
                    plugin_id=_require_str(raw["strategy_plugin"]["plugin_id"], "plugin_id"),
                    pinned_image=_require_str(
                        raw["strategy_plugin"]["pinned_image"], "strategy pinned_image"
                    ),
                ),
                arms=tuple(
                    Arm(
                        id=_require_str(arm["id"], "arm id"),
                        kind=ArmKind(_require_str(arm["kind"], "arm kind")),
                        max_attempts=_require_int(arm.get("max_attempts", 1), "max_attempts"),
                        component_id=(
                            _require_str(arm["component_id"], "arm component_id")
                            if "component_id" in arm
                            else None
                        ),
                    )
                    for arm in raw["arms"]
                ),
                datasets=DatasetBindings(
                    dev_partition=_require_str(raw["datasets"]["dev_partition"], "dev partition"),
                    selection_partition=_require_str(
                        raw["datasets"]["selection_partition"], "selection partition"
                    ),
                    holdout_handle=_require_str(
                        raw["datasets"]["holdout_handle"], "holdout handle"
                    ),
                ),
                evaluators=tuple(
                    EvaluatorBinding(
                        name=_require_str(evaluator["name"], "evaluator name"),
                        pinned_image=_require_str(
                            evaluator["pinned_image"], "evaluator pinned_image"
                        ),
                        stage=_require_int(evaluator.get("stage", 0), "evaluator stage"),
                        cost_class=EvaluatorCostClass(
                            _require_str(
                                evaluator.get("cost_class", EvaluatorCostClass.CHEAP.value),
                                "evaluator cost_class",
                            )
                        ),
                        short_circuit=_require_bool(
                            evaluator.get("short_circuit", True), "evaluator short_circuit"
                        ),
                    )
                    for evaluator in raw["evaluators"]
                ),
                budgets=CampaignBudgets(
                    task_budget_profile=_require_str(
                        raw["budgets"]["task_budget_profile"], "task budget profile"
                    ),
                    max_proposals=_require_int(raw["budgets"]["max_proposals"], "max_proposals"),
                    max_model_tokens=_require_int(
                        raw["budgets"]["max_model_tokens"], "max_model_tokens"
                    ),
                    max_wall_clock_minutes=_require_float(
                        raw["budgets"]["max_wall_clock_minutes"], "max_wall_clock_minutes"
                    ),
                    max_sandbox_executions=_require_int(
                        raw["budgets"].get(
                            "max_sandbox_executions", DEFAULT_MAX_SANDBOX_EXECUTIONS
                        ),
                        "max_sandbox_executions",
                    ),
                ),
                promotion_policy=PromotionPolicyRef(
                    policy_id=_require_str(raw["promotion_policy"]["policy_id"], "policy_id"),
                    policy_digest=_require_str(
                        raw["promotion_policy"]["policy_digest"], "policy digest"
                    ),
                ),
                statistics=StatisticsPlan(
                    alpha=_require_float(raw["statistics"]["alpha"], "alpha"),
                    multiplicity=MultiplicityMethod(
                        _require_str(raw["statistics"]["multiplicity"], "multiplicity")
                    ),
                    bootstrap_iterations=_require_int(
                        raw["statistics"]["bootstrap_iterations"], "bootstrap_iterations"
                    ),
                    bootstrap_seed=_require_int(
                        raw["statistics"]["bootstrap_seed"], "bootstrap_seed"
                    ),
                    ablation_family=tuple(
                        _require_str(component, "ablation family component")
                        for component in raw["statistics"].get("ablation_family", ())
                    ),
                ),
                stopping_rules=StoppingRules(
                    max_rounds=_require_int(raw["stopping_rules"]["max_rounds"], "max_rounds"),
                    max_no_improvement_rounds=_require_int(
                        raw["stopping_rules"]["max_no_improvement_rounds"],
                        "max_no_improvement_rounds",
                    ),
                ),
                compensation_plan=_parse_compensation_plan(raw),
                metadata={str(k): str(v) for k, v in raw.get("metadata", {}).items()},
            )
        except KeyError as exc:
            raise InvalidCampaignSpecError(
                f"campaign spec is missing field {exc.args[0]!r}"
            ) from exc
        except (TypeError, ValueError) as exc:
            raise InvalidCampaignSpecError(
                f"campaign spec field has the wrong shape: {exc}"
            ) from exc


def _parse_compensation_plan(raw: dict[str, Any]) -> CompensationPlanSection | None:
    """Parse the optional F5 compensation-plan section from a spec mapping.

    Absent means no compensating actions are declared (the canonical form
    carries ``compensation_plan: null``). Present, it must be a mapping
    with a non-empty ordered ``actions`` list — declared order is
    execution order.
    """
    section = raw.get("compensation_plan")
    if section is None:
        return None
    if not isinstance(section, dict):
        raise InvalidCampaignSpecError("campaign spec 'compensation_plan' must be a mapping")
    entries = section.get("actions")
    if not isinstance(entries, list) or not entries:
        raise InvalidCampaignSpecError(
            "a 'compensation_plan' section must declare a non-empty ordered 'actions' list"
        )

    def _optional_hook_image(entry: dict[str, Any]) -> str | None:
        hook_image = entry.get("hook_image")
        return None if hook_image is None else _require_str(hook_image, "hook_image")

    return CompensationPlanSection(
        actions=tuple(
            CompensationActionSpec(
                artifact_type=_require_str(entry["artifact_type"], "compensation artifact_type"),
                action=_require_str(entry["action"], "compensation action"),
                hook_image=_optional_hook_image(entry),
            )
            for entry in entries
        )
    )


def _parse_mutable_artifacts(raw: dict[str, Any], schema_version: int) -> MutableArtifactSet:
    """Parse the mutable artifact set from a v2 mapping, or upgrade a v1 one.

    v2 documents carry `mutable_artifacts` — an ordered list of
    `{artifact_type, paths}` bindings. v1 documents carry the singular
    `mutable_artifact`; during the migration window that binding becomes
    the set's single (primary) member, so a v1 document and the equivalent
    v2 document construct identical specs and pin to the same digest.
    After `V1_MIGRATION_WINDOW_END` v1 documents are refused.
    """
    if schema_version == SUPPORTED_SPEC_VERSION:
        entries = raw.get("mutable_artifacts")
        if not isinstance(entries, list) or not entries:
            raise InvalidCampaignSpecError(
                "a v2 campaign spec must declare 'mutable_artifacts' — a non-empty "
                "ordered list of {artifact_type, paths} bindings"
            )
        return MutableArtifactSet(
            artifacts=tuple(
                MutableArtifact(
                    artifact_type=_require_str(entry["artifact_type"], "mutable artifact_type"),
                    paths=tuple(_require_str(path, "mutable path") for path in entry["paths"]),
                )
                for entry in entries
            )
        )
    if schema_version == 1:
        if date.today() > V1_MIGRATION_WINDOW_END:
            raise InvalidCampaignSpecError(
                f"campaign spec schema_version 1 is no longer accepted: the v1 "
                f"migration window closed on {V1_MIGRATION_WINDOW_END.isoformat()} — "
                "re-author the spec with schema_version 2 and a 'mutable_artifacts' set"
            )
        legacy = raw.get("mutable_artifact")
        if not isinstance(legacy, dict):
            raise InvalidCampaignSpecError("a v1 campaign spec must declare 'mutable_artifact'")
        legacy_artifact = MutableArtifact(
            artifact_type=_require_str(legacy["artifact_type"], "mutable artifact_type"),
            paths=tuple(_require_str(path, "mutable path") for path in legacy["paths"]),
        )
        return MutableArtifactSet(artifacts=(legacy_artifact,))
    raise InvalidCampaignSpecError(
        f"unsupported campaign spec schema_version {schema_version!r} "
        f"(this runtime supports {SUPPORTED_SPEC_VERSION})"
    )


class _PrivateKey(Protocol):
    """Structural type for an Ed25519 private key (avoids a hard crypto import)."""

    def sign(self, data: bytes) -> bytes: ...


@dataclass(frozen=True, slots=True)
class PinnedCampaignSpec:
    """A campaign spec bound to its digest and an evaluator signature.

    Pinning is what turns a spec into a preregistration: from this moment
    the document is immutable, any later edit is detectable, and the
    orchestrator will not start a search without this object.
    """

    spec: CampaignSpec
    digest: str
    signature: DetachedSignature

    def verify(self) -> bool:
        """True when the digest matches the spec's canonical bytes AND the
        signature verifies over them. Either check failing means tampering."""
        if self.digest != self.spec.digest:
            return False
        return verify(self.signature, self.spec.canonical_bytes())


def pin_and_sign(spec: CampaignSpec, private_key: _PrivateKey) -> PinnedCampaignSpec:
    """Pin a spec to its digest and sign the canonical bytes.

    Called once, before search begins. The signature uses the evaluator's
    Ed25519 key (the same detached-signature service release manifests
    use), so a pinned spec is verifiable by any party holding the public
    key — including parties with no evaluator key access at all.
    """
    return PinnedCampaignSpec(
        spec=spec,
        digest=spec.digest,
        signature=sign(private_key, spec.canonical_bytes()),  # type: ignore[arg-type]
    )


def _require_int(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidCampaignSpecError(f"{what} must be an integer, got {value!r}")
    return value


def _require_float(value: Any, what: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise InvalidCampaignSpecError(f"{what} must be a number, got {value!r}")
    return float(value)


def _require_bool(value: Any, what: str) -> bool:
    if not isinstance(value, bool):
        raise InvalidCampaignSpecError(f"{what} must be a boolean, got {value!r}")
    return value


def _require_str(value: Any, what: str) -> str:
    if not isinstance(value, str):
        raise InvalidCampaignSpecError(f"{what} must be a string, got {value!r}")
    return value


__all__ = [
    "DEFAULT_MAX_SANDBOX_EXECUTIONS",
    "SUPPORTED_SPEC_VERSION",
    "V1_MIGRATION_WINDOW_END",
    "CampaignBudgets",
    "CampaignSpec",
    "CompensationActionSpec",
    "CompensationPlanSection",
    "DatasetBindings",
    "EvaluatorBinding",
    "IncumbentBinding",
    "MutableArtifact",
    "MutableArtifactSet",
    "PinnedCampaignSpec",
    "PromotionPolicyRef",
    "StatisticsPlan",
    "StoppingRules",
    "StrategyBinding",
    "pin_and_sign",
]

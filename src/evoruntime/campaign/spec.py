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

**Schema v3 (Phase 3, G3) and the dated migration windows.** v2 (F4)
made the mutation surface a `MutableArtifactSet`; v3 adds the scaffold
mutation research surface: a mutable set may contain the SCAFFOLD class,
and when it does the spec must declare `environment: research` and pin a
non-empty `mutation_classes` section (per-class risk-dossier digest and
isolation tier). Older documents are accepted only inside dated windows —
v1 until `V1_MIGRATION_WINDOW_END` (2026-10-27) and v2 until
`V2_MIGRATION_WINDOW_END` (2026-10-28, sixty days after the Phase 3
release branch was cut on 2026-08-29 — see ``docs/campaign-spec-v3.md``)
— and are upgraded to the v3 shape at parse time, so a v1 or v2 document
and the equivalent v3 document pin to the *same* digest. After a window
closes, its version is refused: the window is for authoring migration,
not a permanent dual-format license.

**The holdout is a handle, never content.** Dataset bindings reference the
holdout through the D5 sealed-handle scheme (`holdout://...`). A spec that
tried to inline holdout content would be a contamination channel wearing a
preregistration's clothes, so the shape rejects it at construction.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from datetime import date
from typing import Any, Protocol

from evoruntime.campaign.compensation import CompensationActionKind
from evoruntime.campaign.errors import (
    InvalidCampaignSpecError,
    ScaffoldEnvironmentRefusedError,
)
from evoruntime.core.isolation import IsolationTier
from evoruntime.datasets.partitions import HOLDOUT_HANDLE_SCHEME
from evoruntime.eval.budgets import resolve_budget_profile
from evoruntime.eval.cascade import EvaluatorCostClass
from evoruntime.eval.errors import UnknownBudgetProfileError
from evoruntime.eval.experiment import Arm, ArmKind
from evoruntime.eval.power import DEFAULT_BASELINE_SUCCESS_RATE, required_sample_size
from evoruntime.eval.statistics import MIN_BOOTSTRAP_ITERATIONS, MultiplicityMethod
from evoruntime.plugins.manifest import PluginArtifactType
from evoruntime.security.protected_modules import ProtectedModulesDocument
from evoruntime.security.signing import DetachedSignature, sign, verify
from evoruntime.tenancy.environment import TenantEnvironment, is_scaffold_class

SUPPORTED_SPEC_VERSION = 3
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

V2_MIGRATION_WINDOW_END = date(2026, 10, 28)
"""Last day `schema_version: 2` campaign specs are accepted.

Sixty days after the Phase 3 release branch was cut (2026-08-29). Until
this date a v2 document is upgraded to the v3 shape at parse time and
pins to the v3 digest; after it, v2 specs are refused. Documented in
``docs/campaign-spec-v3.md``.
"""

_DIGEST_PREFIX = "sha256:"

_HOLDOUT_HANDLE_PREFIX = f"{HOLDOUT_HANDLE_SCHEME}://"


def _is_admissible_artifact_type(value: str) -> bool:
    """True for every artifact class a spec may name (Phase 3, G6).

    The Phase 1/2 classes plus the scaffold-mutation research class
    (``scaffold`` — G1 lands the enum member and its capture machinery;
    matching by value string keeps this module independent of that PR).
    Admissible is not approved: a scaffold-class mutable set is refused by
    :meth:`CampaignSpec._validate_environment` unless the spec pins
    ``environment: research`` — the class being known to the spec
    validator is what makes that boundary check reachable.
    """
    return value in {t.value for t in PluginArtifactType} or is_scaffold_class(value)


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
        if not _is_admissible_artifact_type(self.artifact_type):
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
        if not _is_admissible_artifact_type(self.artifact_type):
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
        # Phase 3 (G2): the protected-modules deny-list bounds the mutation
        # mask at spec construction — fail before search, not at the gate.
        # A mask that names a path under a protected root is not a narrower
        # campaign, it is a preregistered attempt to mutate a protected plane.
        protected = ProtectedModulesDocument.default()
        for path in self.paths:
            protected_root = protected.covers_path(path)
            if protected_root is not None:
                raise InvalidCampaignSpecError(
                    f"mutable path {path!r} maps under the protected module "
                    f"{protected_root} ({protected.reason_for(protected_root)}) — "
                    "the protected-modules deny-list bounds the mutation mask, "
                    "and a spec that names a protected path is refused before search"
                )

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


@dataclass(frozen=True, slots=True)
class MutationClassBinding:
    """One declared mutation class with its pinned risk dossier (G3).

    Scaffold mutation is not a free-for-all: the campaign declares up
    front *which classes* of change its strategy may propose (e.g.
    ``prompt_module_edit``, ``tool_use_rewrite``, ``control_flow_change``),
    each bound to the signed risk dossier that justifies it and the
    isolation tier the class demands. The digest pins the dossier — a
    class whose dossier changes is a different preregistration — and G10
    consumes the binding when a class graduates out of research.
    """

    class_id: str
    risk_dossier_digest: str
    max_tier: IsolationTier

    def __post_init__(self) -> None:
        if not self.class_id or self.class_id != self.class_id.strip():
            raise InvalidCampaignSpecError(
                f"mutation class_id must be non-empty and trimmed, got {self.class_id!r}"
            )
        _require_digest(
            self.risk_dossier_digest,
            f"mutation class {self.class_id!r} risk_dossier_digest",
        )
        if not isinstance(self.max_tier, IsolationTier):
            try:
                object.__setattr__(self, "max_tier", IsolationTier(self.max_tier))
            except ValueError as exc:
                raise InvalidCampaignSpecError(
                    f"mutation class {self.class_id!r} max_tier {self.max_tier!r} is not "
                    f"an isolation tier (one of {', '.join(t.value for t in IsolationTier)})"
                ) from exc

    def to_canonical_dict(self) -> dict[str, Any]:
        """Canonical JSON form of this binding."""
        return {
            "class_id": self.class_id,
            "risk_dossier_digest": self.risk_dossier_digest,
            "max_tier": self.max_tier.value,
        }


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
        elif self.action == CompensationActionKind.RERUN_CONFORMANCE_SUITE.value:
            # G8: the suite this action re-runs is pinned inside the
            # scaffold's own file map, so the action declares no hook image
            # of its own — re-declaring one here would create a second pin
            # that could drift from the oracle the candidate was judged by.
            if self.hook_image is not None:
                raise InvalidCampaignSpecError(
                    "a rerun_conformance_suite action takes no hook_image — the "
                    "suite pin travels with the scaffold's file map, and a second "
                    "pin here could disagree with it"
                )
            if self.artifact_type != PluginArtifactType.SCAFFOLD.value:
                raise InvalidCampaignSpecError(
                    f"a rerun_conformance_suite action targets {self.artifact_type!r}, "
                    "but only the scaffold class pins a conformance suite — "
                    "scaffold-specific compensations name the scaffold class"
                )
        elif self.action == CompensationActionKind.RESTORE_SCAFFOLD_SOURCE.value:
            if self.hook_image is not None:
                raise InvalidCampaignSpecError(
                    f"compensation action {self.action!r} takes no hook_image — the "
                    "restore is a digest-verified registry read, not a declared hook"
                )
            if self.artifact_type != PluginArtifactType.SCAFFOLD.value:
                raise InvalidCampaignSpecError(
                    f"a restore_scaffold_source action targets {self.artifact_type!r}, "
                    "but only the scaffold class has registry-restorable source — "
                    "scaffold-specific compensations name the scaffold class"
                )
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

    One action per artifact class, with one G8 exception: the scaffold
    rollback is a two-action unit — ``restore_scaffold_source`` followed
    by ``rerun_conformance_suite`` — because undoing a whole source tree
    and re-proving the restored tree against its own oracle are two halves
    of one compensation, and the rerun is only meaningful after the
    restore.
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
        if duplicates and not self._is_scaffold_rollback_pair(duplicates):
            raise InvalidCampaignSpecError(
                f"duplicate artifact_type in the compensation plan: "
                f"{', '.join(duplicates)} — one compensating action per artifact"
            )
        self._validate_scaffold_rollback_order()

    @staticmethod
    def _is_scaffold_rollback_pair(duplicates: list[str]) -> bool:
        """True when the duplicates are exactly the G8 scaffold rollback
        pair: restore the source, then re-verify the oracle — two actions
        on one artifact class that compose into a single rollback unit."""
        return duplicates == [PluginArtifactType.SCAFFOLD.value]

    def _validate_scaffold_rollback_order(self) -> None:
        """The scaffold rollback pair must be the declared pair, restore
        first — rerunning the oracle against a tree that has not been
        restored judges nothing."""
        scaffold_actions = [
            action.action
            for action in self.actions
            if action.artifact_type == PluginArtifactType.SCAFFOLD.value
        ]
        if len(scaffold_actions) < 2:
            return
        restore = CompensationActionKind.RESTORE_SCAFFOLD_SOURCE.value
        rerun = CompensationActionKind.RERUN_CONFORMANCE_SUITE.value
        if sorted(scaffold_actions) != sorted((restore, rerun)):
            raise InvalidCampaignSpecError(
                "the scaffold class carries more than one compensating action — "
                f"the only allowed pair is {restore!r} followed by {rerun!r}"
            )
        if scaffold_actions.index(restore) > scaffold_actions.index(rerun):
            raise InvalidCampaignSpecError(
                f"{rerun!r} is declared before {restore!r} — the conformance "
                "rerun must follow the source restore, or it judges a tree that "
                "has not been restored yet"
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
    required_sample_size: int | None = None
    """The powered task count per arm (H10), computed by
    :func:`pin_powered_sample_size` from the plan's alpha plus the
    campaign's power and minimum-detectable-effect targets, and pinned at
    plan time — a campaign budgeted from this number is powered by
    construction, not discovered underpowered after the runs are spent.
    Optional: absent on every pre-H10 plan."""

    def __post_init__(self) -> None:
        if self.required_sample_size is not None and (
            isinstance(self.required_sample_size, bool) or self.required_sample_size < 1
        ):
            raise InvalidCampaignSpecError(
                f"required_sample_size must be a positive integer, got "
                f"{self.required_sample_size!r}"
            )
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
            # H10: omit-when-unset, same convention as the arm-level
            # component_id/editor_ref fields — pre-H10 plans keep their
            # canonical bytes (and so their digest) unchanged.
            **(
                {"required_sample_size": self.required_sample_size}
                if self.required_sample_size is not None
                else {}
            ),
        }


def pin_powered_sample_size(
    statistics: StatisticsPlan,
    *,
    power: float,
    minimum_detectable_effect: float,
    baseline_success_rate: float = DEFAULT_BASELINE_SUCCESS_RATE,
) -> StatisticsPlan:
    """Pin the powered task count into a statistics plan (H10).

    Called at plan time, before search: the plan's alpha is the error rate
    the whole preregistered family is judged at, so the sample size is
    computed against it — a plan pinned this way budgets a campaign that is
    powered for the effect it claims to look for. Pure: returns a new plan
    and leaves the input untouched.
    """
    analysis = required_sample_size(
        alpha=statistics.alpha,
        power=power,
        minimum_detectable_effect=minimum_detectable_effect,
        baseline_success_rate=baseline_success_rate,
    )
    return replace(statistics, required_sample_size=analysis.required_tasks)


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
    mutation_classes: tuple[MutationClassBinding, ...] = ()
    """The pinned mutation classes (v3): which classes of change the
    strategy may propose, each bound to its signed risk dossier and the
    isolation tier it demands. Mandatory (non-empty) for scaffold-mutable
    campaigns; optional extra preregistration for other campaigns."""

    metadata: dict[str, str] = field(default_factory=dict)
    environment: str | None = None
    """The environment this campaign declares itself for (G6).

    Absent on every pre-G6 spec. A scaffold-mutable set must declare
    ``research``; anything else is refused at construction. Unlike the
    other G6 fields this one is ALWAYS serialized into the canonical
    form — even when unset — so the digest binds the environment claim
    (G3): a spec whose environment claim changed after pinning no
    longer verifies. This deliberate divergence from G6's
    omit-when-unset convention is v3 behavior, not an accident.
    """
    tier4_policy_digest: str | None = None
    """Digest of the tier-4-allowing seed policy this campaign answers to (G7).

    Required on every scaffold-mutable spec: the promotions of a
    scaffold-mutation campaign are tier-4 acts, and the policy whose
    approval defaults admit them is signed policy data
    (:mod:`evoruntime.tenancy.seed`) whose digest is pinned here — chosen
    before search begins, like every other part of the preregistration.
    Refused on non-scaffold specs: a tier-4 pin on a campaign that can
    never promote at tier 4 governs nothing.
    """

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
        object.__setattr__(self, "mutation_classes", tuple(self.mutation_classes))
        class_ids = [binding.class_id for binding in self.mutation_classes]
        duplicates = sorted({cid for cid in class_ids if class_ids.count(cid) > 1})
        if duplicates:
            raise InvalidCampaignSpecError(
                f"duplicate class_id in the mutation classes: {', '.join(duplicates)}"
            )
        self._validate_artifact_consistency()
        self._validate_environment()
        self._validate_mutation_classes()
        self._validate_tier4_policy()
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

    def _validate_environment(self) -> None:
        """G6 boundary 1 — spec construction: scaffold ⇒ research.

        A mutable set containing a scaffold-class artifact is a
        scaffold-mutation campaign, and scaffold mutation exists only in
        the research environment. The declared `environment` must say so
        explicitly — an unspecified environment is not research by
        default, it is unspecified, and the check refuses it. The
        artifact-class validators admit scaffold-class values precisely
        so this check, not an "unknown class" refusal, decides the fate
        of a scaffold spec.
        """
        if self.environment is not None and self.environment not in {
            e.value for e in TenantEnvironment
        }:
            raise InvalidCampaignSpecError(
                f"environment must be one of {sorted(e.value for e in TenantEnvironment)}, "
                f"got {self.environment!r}"
            )
        if not any(
            is_scaffold_class(artifact.artifact_type)
            for artifact in self.mutable_artifacts.artifacts
        ):
            return
        if self.environment != TenantEnvironment.RESEARCH.value:
            raise ScaffoldEnvironmentRefusedError(
                "a scaffold-mutable campaign requires environment: research — "
                "scaffold mutation is refused outside the research tenant (G6)"
            )

    def _validate_mutation_classes(self) -> None:
        """Scaffold-mutable campaigns pin their mutation surface (G3).

        A campaign that mutates the SCAFFOLD class is editing the runtime's
        own source: its mutation surface must be pinned class-by-class
        before search — an unpinned scaffold mutation surface is not a
        preregistration, it is an open invitation. The environment claim
        itself is validated by `_validate_environment` (G6) — one refusal
        path for the environment, not two.
        """
        if not any(
            is_scaffold_class(artifact.artifact_type)
            for artifact in self.mutable_artifacts.artifacts
        ):
            return
        if not self.mutation_classes:
            raise InvalidCampaignSpecError(
                "a scaffold-mutable campaign must pin its 'mutation_classes' — "
                "declare each mutation class with its risk_dossier_digest and max_tier"
            )

    def _validate_tier4_policy(self) -> None:
        """G7 — a scaffold spec pins the tier-4-allowing policy digest.

        The pin is structural here (present, well-formed, and only on
        scaffold specs); that it names the *right* policy — the research
        tenant's signed seed document, which actually allows tier 4 — is
        a deployment-level fact the control plane verifies at campaign
        creation against its tenant-policy registry.
        """
        if self.has_scaffold_mutable:
            if self.tier4_policy_digest is None:
                raise InvalidCampaignSpecError(
                    "a scaffold-mutable campaign must pin tier4_policy_digest — the "
                    "digest of the tier-4-allowing seed policy document its promotions "
                    "are governed by (G7)"
                )
            _require_digest(self.tier4_policy_digest, "tier-4 policy digest")
        elif self.tier4_policy_digest is not None:
            raise InvalidCampaignSpecError(
                "tier4_policy_digest is only valid on a scaffold-mutable spec — "
                "a campaign that cannot promote at tier 4 has no tier-4 policy to pin"
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
        self._validate_fixed_editor_arm()
        self._validate_ablation_arms()

    def _validate_fixed_editor_arm(self) -> None:
        """A scaffold-mutable campaign must carry its fixed-editor arm (G4).

        The fixed-editor arm is the incumbent scaffold evaluated under the
        frozen editor — the strategy plugin pinned at its
        incumbent-generation version. Without it, a scaffold campaign's
        only comparison is against a static incumbent, and the editor's own
        gains could be claimed as recursion (the §12.6 RI-3/RI-4 condition
        has no denominator). Same hard-requirement style as the Phase 0
        control arms: exactly one, refused at construction.
        """
        if not self.has_scaffold_mutable:
            return
        fixed_editors = [arm for arm in self.arms if arm.kind is ArmKind.FIXED_EDITOR]
        if len(fixed_editors) != 1:
            raise InvalidCampaignSpecError(
                "a scaffold-mutable campaign needs exactly one "
                f"{ArmKind.FIXED_EDITOR.value} arm (the incumbent scaffold "
                "evaluated under the frozen editor), found "
                f"{len(fixed_editors)}"
            )

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
    def has_scaffold_mutable(self) -> bool:
        """True when the mutable set contains a scaffold-class artifact (G6)."""
        return any(
            is_scaffold_class(artifact.artifact_type)
            for artifact in self.mutable_artifacts.artifacts
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
                    # editor_ref is a FIXED_EDITOR-only field (G4): same
                    # omit-when-unset pattern, same digest-stability reason.
                    **({"editor_ref": arm.editor_ref} if arm.editor_ref is not None else {}),
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
            # v3 fields are always present in the canonical form — None/[]
            # for documents that predate them — so a v2 document and the
            # equivalent v3 document pin to the same digest, and a v3 spec
            # that *declares* the fields has them bound by the signature.
            "environment": self.environment,
            "mutation_classes": [binding.to_canonical_dict() for binding in self.mutation_classes],
            "metadata": dict(sorted(self.metadata.items())),
            # environment is the one deliberate divergence from G6's
            # omit-when-unset convention (G3): it is always serialized —
            # None for documents that predate it — so the digest binds
            # the environment claim.
            # tier4_policy_digest is a G7 field and follows the same v3
            # convention: always serialized, None for documents that
            # predate it, so the tier-4 pin is bound by the signature.
            "tier4_policy_digest": self.tier4_policy_digest,
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
                        editor_ref=(
                            _require_str(arm["editor_ref"], "arm editor_ref")
                            if "editor_ref" in arm
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
                tier4_policy_digest=(
                    _require_digest(
                        _require_str(raw["tier4_policy_digest"], "tier-4 policy digest"),
                        "tier-4 policy digest",
                    )
                    # The v3 canonical form always serializes the key —
                    # None for documents that predate G7 — so both an
                    # absent key and an explicit null parse to None.
                    # Structural requirements (mandatory on scaffold specs,
                    # refused on non-scaffold specs) live in
                    # _validate_tier4_policy, not here: a pre-G7 document
                    # must still load.
                    if raw.get("tier4_policy_digest") is not None
                    else None
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
                    required_sample_size=(
                        _require_int(
                            raw["statistics"]["required_sample_size"], "required_sample_size"
                        )
                        if raw["statistics"].get("required_sample_size") is not None
                        else None
                    ),
                ),
                stopping_rules=StoppingRules(
                    max_rounds=_require_int(raw["stopping_rules"]["max_rounds"], "max_rounds"),
                    max_no_improvement_rounds=_require_int(
                        raw["stopping_rules"]["max_no_improvement_rounds"],
                        "max_no_improvement_rounds",
                    ),
                ),
                # v3 canonical forms always carry the environment key —
                # null for documents that predate the claim (G3) — so an
                # explicit null parses as absent, not as a type error.
                environment=(
                    _require_str(raw["environment"], "environment")
                    if raw.get("environment") is not None
                    else None
                ),
                compensation_plan=_parse_compensation_plan(raw),
                mutation_classes=_parse_mutation_classes(raw),
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


def _require_isolation_tier(value: Any, what: str) -> IsolationTier:
    """Validate an isolation-tier name from a spec mapping."""
    if not isinstance(value, str):
        raise InvalidCampaignSpecError(f"{what} must be a string, got {value!r}")
    try:
        return IsolationTier(value)
    except ValueError as exc:
        raise InvalidCampaignSpecError(
            f"{what} {value!r} is not an isolation tier "
            f"(one of {', '.join(t.value for t in IsolationTier)})"
        ) from exc


def _parse_mutation_classes(raw: dict[str, Any]) -> tuple[MutationClassBinding, ...]:
    """Parse the optional v3 mutation-classes section from a spec mapping.

    Absent (or the canonical form's empty list) means no classes are
    pinned. Present, it must be a list of
    ``{class_id, risk_dossier_digest, max_tier}`` bindings — scaffold
    campaigns are required to pin at least one by
    :meth:`CampaignSpec._validate_mutation_classes`.
    """
    section = raw.get("mutation_classes")
    if not section:
        return ()
    if not isinstance(section, list) or not section:
        raise InvalidCampaignSpecError(
            "a 'mutation_classes' section must be a non-empty list of "
            "{class_id, risk_dossier_digest, max_tier} bindings"
        )
    return tuple(
        MutationClassBinding(
            class_id=_require_str(entry["class_id"], "mutation class_id"),
            risk_dossier_digest=_require_str(
                entry["risk_dossier_digest"], "mutation risk_dossier_digest"
            ),
            max_tier=_require_isolation_tier(entry["max_tier"], "mutation class max_tier"),
        )
        for entry in section
    )


def _parse_mutable_artifacts(raw: dict[str, Any], schema_version: int) -> MutableArtifactSet:
    """Parse the mutable artifact set from a v2/v3 mapping, or upgrade a v1 one.

    v2 and v3 documents carry `mutable_artifacts` — an ordered list of
    `{artifact_type, paths}` bindings. v1 documents carry the singular
    `mutable_artifact`; during the migration window that binding becomes
    the set's single (primary) member, so a v1 document and the equivalent
    v2/v3 document construct identical specs and pin to the same digest.
    After `V1_MIGRATION_WINDOW_END` v1 documents are refused, and after
    `V2_MIGRATION_WINDOW_END` v2 documents are refused too — the windows
    are for authoring migration, not permanent dual-format licenses.
    """
    if schema_version in (SUPPORTED_SPEC_VERSION, 2):
        if schema_version == 2 and date.today() > V2_MIGRATION_WINDOW_END:
            raise InvalidCampaignSpecError(
                f"campaign spec schema_version 2 is no longer accepted: the v2 "
                f"migration window closed on {V2_MIGRATION_WINDOW_END.isoformat()} — "
                "re-author the spec with schema_version 3"
            )
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
                "re-author the spec with schema_version 3 and a 'mutable_artifacts' set"
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
    "V2_MIGRATION_WINDOW_END",
    "CampaignBudgets",
    "CampaignSpec",
    "CompensationActionSpec",
    "CompensationPlanSection",
    "DatasetBindings",
    "EvaluatorBinding",
    "IncumbentBinding",
    "MutationClassBinding",
    "MutableArtifact",
    "MutableArtifactSet",
    "PinnedCampaignSpec",
    "PromotionPolicyRef",
    "StatisticsPlan",
    "StoppingRules",
    "StrategyBinding",
    "pin_and_sign",
]

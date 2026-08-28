"""The declarative campaign spec (PRD §11.2) — everything pinned before search.

A campaign is a validated, versioned *document*, not a pile of runtime
arguments. Incumbent release, mutable artifact type and paths, strategy
plugin, experiment arms (the three Phase 0 control arms plus the strategy
arm), dataset bindings, evaluators, budgets, promotion policy, statistics
plan, and stopping rules are all fixed here — because a comparison whose
alpha, budget, or mutation surface is chosen after seeing the deltas has
no error rate at all.

Two disciplines this module enforces:

**Pin + sign before search.** `pin_and_sign` hashes the spec's canonical
bytes and signs them with the evaluator's Ed25519 key. The orchestrator
(:mod:`evoruntime.campaign.machine`) refuses to run anything but a pinned
spec whose digest and signature still verify — a spec edited after the
fact is not a preregistration, it is a forgery of one.

**The holdout is a handle, never content.** Dataset bindings reference the
holdout through the D5 sealed-handle scheme (`holdout://...`). A spec that
tried to inline holdout content would be a contamination channel wearing a
preregistration's clothes, so the shape rejects it at construction.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Protocol

from evoruntime.campaign.errors import InvalidCampaignSpecError
from evoruntime.datasets.partitions import HOLDOUT_HANDLE_SCHEME
from evoruntime.eval.budgets import resolve_budget_profile
from evoruntime.eval.errors import UnknownBudgetProfileError
from evoruntime.eval.experiment import Arm, ArmKind
from evoruntime.eval.statistics import MIN_BOOTSTRAP_ITERATIONS, MultiplicityMethod
from evoruntime.plugins.manifest import PluginArtifactType
from evoruntime.security.signing import DetachedSignature, sign, verify

SUPPORTED_SPEC_VERSION = 1
"""The only campaign-spec schema version this runtime understands.

A spec carries its version explicitly so a future shape change is a
refusal with a clear message, not a silent misread of an old document.
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
                f"incumbent artifact_type {self.artifact_type!r} is not a Phase 1 artifact class"
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
                f"mutable artifact_type {self.artifact_type!r} is not a Phase 1 artifact class"
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


@dataclass(frozen=True, slots=True)
class EvaluatorBinding:
    """One evaluator the campaign's arms are scored by, pinned by image digest."""

    name: str
    pinned_image: str

    def __post_init__(self) -> None:
        if not self.name:
            raise InvalidCampaignSpecError("evaluator name must be non-empty")
        _require_pinned_image(self.pinned_image, f"evaluator {self.name!r} pinned_image")

    def to_canonical_dict(self) -> dict[str, Any]:
        """Canonical JSON form of this binding."""
        return {"name": self.name, "pinned_image": self.pinned_image}


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

    def __post_init__(self) -> None:
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
    mutable_artifact: MutableArtifact
    strategy_plugin: StrategyBinding
    arms: tuple[Arm, ...]
    datasets: DatasetBindings
    evaluators: tuple[EvaluatorBinding, ...]
    budgets: CampaignBudgets
    promotion_policy: PromotionPolicyRef
    statistics: StatisticsPlan
    stopping_rules: StoppingRules
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
        if not self.evaluators:
            raise InvalidCampaignSpecError(
                "a campaign must declare at least one evaluator — an unscored "
                "campaign produces numbers nobody can trust"
            )

    def _validate_artifact_consistency(self) -> None:
        """The campaign improves the incumbent's artifact type — nothing else.

        A spec whose mutable artifact differs from the incumbent's would
        diff candidates against a release they are not comparable to.
        """
        if self.mutable_artifact.artifact_type != self.incumbent.artifact_type:
            raise InvalidCampaignSpecError(
                f"mutable artifact_type {self.mutable_artifact.artifact_type!r} does not "
                f"match the incumbent release's artifact_type "
                f"{self.incumbent.artifact_type!r} — a campaign optimizes the "
                "incumbent's artifact class"
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

    # -- canonical form, digest, pinning -----------------------------------

    def to_canonical_dict(self) -> dict[str, Any]:
        """The spec as a canonical JSON-serializable dict (sorted downstream).

        One explicit serializer rather than `dataclasses.asdict`: the
        canonical bytes are a *contract* (they are what gets digested and
        signed), so their shape is pinned here, not derived from field
        order or enum reprs.
        """
        return {
            "schema_version": self.schema_version,
            "name": self.name,
            "incumbent": self.incumbent.to_canonical_dict(),
            "mutable_artifact": self.mutable_artifact.to_canonical_dict(),
            "strategy_plugin": self.strategy_plugin.to_canonical_dict(),
            "arms": [
                {
                    "id": arm.id,
                    "kind": arm.kind.value,
                    "max_attempts": arm.max_attempts,
                }
                for arm in self.arms
            ],
            "datasets": self.datasets.to_canonical_dict(),
            "evaluators": [e.to_canonical_dict() for e in self.evaluators],
            "budgets": self.budgets.to_canonical_dict(),
            "promotion_policy": self.promotion_policy.to_canonical_dict(),
            "statistics": self.statistics.to_canonical_dict(),
            "stopping_rules": self.stopping_rules.to_canonical_dict(),
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
            return cls(
                schema_version=_require_int(raw["schema_version"], "schema_version"),
                name=_require_str(raw["name"], "name"),
                incumbent=IncumbentBinding(
                    release_manifest_digest=_require_str(
                        raw["incumbent"]["release_manifest_digest"], "release digest"
                    ),
                    artifact_type=_require_str(
                        raw["incumbent"]["artifact_type"], "incumbent artifact_type"
                    ),
                ),
                mutable_artifact=MutableArtifact(
                    artifact_type=_require_str(
                        raw["mutable_artifact"]["artifact_type"], "mutable artifact_type"
                    ),
                    paths=tuple(
                        _require_str(path, "mutable path")
                        for path in raw["mutable_artifact"]["paths"]
                    ),
                ),
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
                ),
                stopping_rules=StoppingRules(
                    max_rounds=_require_int(raw["stopping_rules"]["max_rounds"], "max_rounds"),
                    max_no_improvement_rounds=_require_int(
                        raw["stopping_rules"]["max_no_improvement_rounds"],
                        "max_no_improvement_rounds",
                    ),
                ),
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


def _require_str(value: Any, what: str) -> str:
    if not isinstance(value, str):
        raise InvalidCampaignSpecError(f"{what} must be a string, got {value!r}")
    return value


__all__ = [
    "SUPPORTED_SPEC_VERSION",
    "CampaignBudgets",
    "CampaignSpec",
    "DatasetBindings",
    "EvaluatorBinding",
    "IncumbentBinding",
    "MutableArtifact",
    "PinnedCampaignSpec",
    "PromotionPolicyRef",
    "StatisticsPlan",
    "StoppingRules",
    "StrategyBinding",
    "pin_and_sign",
]

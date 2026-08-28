"""evolutionary-artifact-search — the §16.5 research plugin (PRD §16.5, F11).

An evolutionary search strategy over the ``algorithm`` executable
class, with the three §16.5 disciplines:

* **Islands over a MAP-Elites archive.** The population is partitioned
  into islands; each island keeps a MAP-Elites archive — one elite per
  behavior-descriptor cell, keyed by a quantized (complexity,
  exploration) descriptor. A candidate earns a cell only by beating its
  elite, so the archive preserves diversity that a single best-score
  pool would collapse.
* **Diversity-constrained parent sampling.** Parents for the next
  generation are drawn from *distinct* archive cells with a minimum
  descriptor distance (farthest-point greedy sampling). Breeding two
  near-identical elites is how evolution stalls; the constraint makes
  it structurally impossible rather than discouraged.
* **Cascaded cheap-to-expensive evaluation.** Candidates are scored by
  stage-tagged metrics (``stage:<n>:<name>:passed`` / ``:score``) in
  the F6 cascade vocabulary. A failed short-circuit stage is a
  *measured failure*: the candidate never reaches the archive, and
  expensive-stage scores are never credited past a failed cheap stage —
  the plugin-side mirror of F6's short-circuit semantics.

**The F6 seam.** :func:`stage_plan_from_bindings` projects evaluator
bindings carrying F6's ``stage`` / ``cost_class`` / ``short_circuit``
fields into the plugin's stage plan — the exact field names
``EvaluatorBinding`` grows in F6. Until that lands, the plugin infers
the stage plan from the observed metric keys themselves
(:func:`infer_stage_plan`); both paths produce the same plan shape, and
the orchestrator pins the binding-derived one into the state payload
the moment F6 merges.

**Enablement.** The plugin refuses to initialize on any artifact class
whose correctness is not externally executable (:mod:`.enablement`) —
evolution needs an objective fitness signal; on a subjectively-judged
class it would optimize the judge.
"""

from __future__ import annotations

import base64
import json
import math
import random
from collections.abc import Iterable, Mapping
from typing import Any, Protocol

from evoruntime.plugins.manifest import PluginArtifactType, PluginManifest, ResourceLimits
from evoruntime.plugins.protocol import PluginHandlerError
from evoruntime.plugins.research._base import build_research_manifest, run_research_plugin
from evoruntime.plugins.research.enablement import require_external_correctness

PLUGIN_ID = "evolutionary-artifact-search"
PLUGIN_VERSION = "1.0.0"
MODULE_NAME = "evolutionary_artifact_search"
PRIMARY_TYPE = PluginArtifactType.ALGORITHM
AUX_TYPE = PluginArtifactType.TOOL_SPEC
CHECKPOINT_SCHEMA_ID = "evolutionary-artifact-search/v1"

#: MAP-Elites grid resolution per descriptor dimension.
DESCRIPTOR_GRID = 4

#: Minimum pairwise descriptor distance between sampled parents.
MIN_PARENT_DISTANCE = 1.0

#: Parents sampled per proposal, drawn from distinct cells where the
#: archive allows.
PARENTS_PER_PROPOSAL = 2

#: Islands partition the archive so independent lineages evolve in
#: parallel; migration happens through the shared descriptor space.
ISLAND_COUNT = 2

#: Deterministic mutation seed base — matches the manifest's seed so a
#: checkpointed state replays identically.
MUTATION_SEED_BASE = 1613

#: Default mutation step in descriptor space.
MUTATION_STEP = 0.15

#: Descriptor reported when the harness sends none (the archive's origin).
ORIGIN_DESCRIPTOR: tuple[float, ...] = (0.5, 0.5)

_STAGE_PASSED_FMT = "stage:{stage}:{name}:passed"
_STAGE_SCORE_FMT = "stage:{stage}:{name}:score"
_DESCRIPTOR_METRIC_PREFIX = "descriptor:"


class EvaluatorBindingLike(Protocol):
    """Structural type of the F6 ``EvaluatorBinding`` fields this plugin reads.

    F6 adds ``stage`` / ``cost_class`` / ``short_circuit`` to the
    campaign spec's ``EvaluatorBinding``; this protocol names exactly
    those fields so the plugin consumes them without importing the
    (not-yet-merged) module.
    """

    @property
    def name(self) -> str: ...

    @property
    def stage(self) -> int: ...

    @property
    def cost_class(self) -> str: ...

    @property
    def short_circuit(self) -> bool: ...


def build_manifest() -> PluginManifest:
    """The plugin's §10.4 manifest declaration (executable outputs, tier 3)."""
    return build_research_manifest(
        plugin_id=PLUGIN_ID,
        version=PLUGIN_VERSION,
        module=MODULE_NAME,
        artifact_types=(PRIMARY_TYPE, AUX_TYPE),
        limits=ResourceLimits(
            wall_clock_minutes=30.0, cpu=1.0, memory_gib=2.0, model_tokens=0, proposals=50
        ),
        seed=MUTATION_SEED_BASE,
        executables=("algorithm_runner",),
    )


# ---------------------------------------------------------------------------
# MAP-Elites archive (pure functions — the archive-diversity contract).
# ---------------------------------------------------------------------------


def behavior_cell(descriptor: tuple[float, ...]) -> str:
    """Quantize a behavior descriptor into its MAP-Elites cell key.

    Each dimension is clamped to [0, 1] and bucketed into
    ``DESCRIPTOR_GRID`` cells; the key is the per-dimension bucket tuple.
    """
    buckets = []
    for value in descriptor:
        clamped = min(1.0, max(0.0, value))
        index = min(int(clamped * DESCRIPTOR_GRID), DESCRIPTOR_GRID - 1)
        buckets.append(index)
    return ",".join(str(index) for index in buckets)


def archive_insert(
    archive: Mapping[str, Mapping[str, Any]], cell: str, candidate: Mapping[str, Any]
) -> dict[str, dict[str, Any]]:
    """Return the archive after admitting ``candidate`` into ``cell``.

    MAP-Elites rule: one elite per cell; a challenger replaces the
    incumbent only on a strictly better score. Pure — the input archive
    is never mutated.
    """
    incumbent = archive.get(cell)
    if incumbent is None or float(candidate["score"]) > float(incumbent["score"]):
        merged: dict[str, dict[str, Any]] = {key: dict(value) for key, value in archive.items()}
        merged[cell] = dict(candidate)
        return merged
    return {key: dict(value) for key, value in archive.items()}


def descriptor_distance(a: tuple[float, ...], b: tuple[float, ...]) -> float:
    """Euclidean distance between two behavior descriptors."""
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b, strict=True)))


def sample_diverse_parents(
    archive: Mapping[str, Mapping[str, Any]],
    k: int,
    min_distance: float,
) -> list[dict[str, Any]]:
    """Sample up to ``k`` elites under the diversity constraint.

    Farthest-point greedy: start from the best-scoring elite, then
    repeatedly take the elite farthest from everything already chosen,
    skipping any candidate closer than ``min_distance`` to a chosen
    parent. Returns fewer than ``k`` parents when the archive cannot
    satisfy the constraint — diversity is never traded for headcount.
    """
    elites = sorted(
        (dict(elite) for elite in archive.values()),
        key=lambda elite: float(elite["score"]),
        reverse=True,
    )
    if not elites or k < 1:
        return []
    chosen = [elites[0]]
    for elite in elites[1:]:
        if len(chosen) >= k:
            break
        descriptor = tuple(float(v) for v in elite["descriptor"])
        if all(
            descriptor_distance(descriptor, tuple(float(v) for v in other["descriptor"]))
            >= min_distance
            for other in chosen
        ):
            chosen.append(elite)
    return chosen


def mutate_descriptor(
    descriptor: tuple[float, ...], rng: random.Random, step: float = MUTATION_STEP
) -> tuple[float, ...]:
    """One deterministic mutation step in descriptor space, clamped to [0, 1]."""
    return tuple(min(1.0, max(0.0, value + rng.uniform(-step, step))) for value in descriptor)


def descriptor_from_metrics(metrics: Mapping[str, Any]) -> tuple[float, ...]:
    """The candidate's behavior descriptor from flat ``descriptor:<i>`` keys.

    The harness reports where a candidate sits in behavior space
    alongside its stage metrics; a candidate with no reported descriptor
    sits at the archive's origin.
    """
    values = [
        float(value)
        for key, value in metrics.items()
        if key.startswith(_DESCRIPTOR_METRIC_PREFIX) and isinstance(value, (int, float))
    ]
    return tuple(values) if values else ORIGIN_DESCRIPTOR


# ---------------------------------------------------------------------------
# Cascaded evaluation (the F6 stage/cost_class seam).
# ---------------------------------------------------------------------------


def _binding_field(binding: Any, field: str) -> Any:
    """Read one binding field from an object (F6's EvaluatorBinding) or a
    mapping (the state-payload JSON form of the same plan)."""
    if isinstance(binding, Mapping):
        return binding[field]
    return getattr(binding, field)


def stage_plan_from_bindings(
    bindings: Iterable[EvaluatorBindingLike | Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    """Project F6-shaped evaluator bindings into the plugin's stage plan.

    Reads exactly the fields F6's ``EvaluatorBinding`` carries —
    ``name``, ``stage``, ``cost_class``, ``short_circuit`` — and orders
    the plan ascending by stage. This is the seam the orchestrator uses
    to pin the campaign's cascade into the plugin's state payload.
    """
    plan = [
        {
            "name": str(_binding_field(binding, "name")),
            "stage": int(_binding_field(binding, "stage")),
            "cost_class": str(_binding_field(binding, "cost_class")),
            "short_circuit": bool(_binding_field(binding, "short_circuit")),
        }
        for binding in bindings
    ]
    return tuple(sorted(plan, key=lambda stage: (stage["stage"], stage["name"])))


def infer_stage_plan(metrics: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    """Derive the stage plan from stage-tagged metric keys.

    Fallback when no binding-derived plan is pinned in state: every
    ``stage:<n>:<name>:passed`` key names a stage; stages run ascending
    and short-circuit by default (F6's defaults).
    """
    stages: dict[int, str] = {}
    for key in metrics:
        parts = key.split(":")
        if len(parts) == 4 and parts[0] == "stage" and parts[3] == "passed" and parts[1].isdigit():
            stages[int(parts[1])] = parts[2]

    return tuple(
        {
            "name": stages[stage],
            "stage": stage,
            "cost_class": "cheap" if stage == 0 else "expensive",
            "short_circuit": True,
        }
        for stage in sorted(stages)
    )


def cascaded_verdict(
    metrics: Mapping[str, Any],
    stage_plan: tuple[Mapping[str, Any], ...],
) -> dict[str, Any]:
    """The plugin-side mirror of F6's short-circuit semantics.

    Stages run ascending. A failed short-circuit stage resolves the
    candidate as failed *at that stage*: the overall verdict is failed
    even when later (more expensive) stage metrics are present, and no
    expensive-stage score is credited — a candidate that could not clear
    a cheaper stage has no passing result to compare. The final stage's
    score is the candidate's fitness only when every stage passed.
    """
    if not stage_plan:
        return {"passed": False, "resolved_stage": None, "score": None, "short_circuited": False}
    resolved_stage: int | None = None
    for stage_def in stage_plan:
        stage = int(stage_def["stage"])
        name = str(stage_def["name"])
        passed_key = _STAGE_PASSED_FMT.format(stage=stage, name=name)
        if passed_key not in metrics:
            # The cascade never ran this stage — an early exit upstream
            # already resolved the candidate as failed.
            resolved_stage = stage
            break
        if not metrics[passed_key]:
            resolved_stage = stage
            if bool(stage_def.get("short_circuit", True)):
                return {
                    "passed": False,
                    "resolved_stage": stage,
                    "score": None,
                    "short_circuited": True,
                }
    final = stage_plan[-1]
    score_key = _STAGE_SCORE_FMT.format(stage=int(final["stage"]), name=str(final["name"]))
    score = float(metrics[score_key]) if score_key in metrics else None
    return {
        "passed": resolved_stage is None and score is not None,
        "resolved_stage": resolved_stage,
        "score": score,
        "short_circuited": False,
    }


# ---------------------------------------------------------------------------
# The strategy handler.
# ---------------------------------------------------------------------------


def _island_of(counter: int) -> int:
    """Assign a candidate to an island, round-robin by generation."""
    return counter % ISLAND_COUNT


class EvolutionaryArtifactSearch:
    """§10.2 strategy handler for the evolutionary-artifact-search plugin."""

    def initialize(self, context: dict[str, Any]) -> dict[str, Any]:
        artifact_type = require_external_correctness(PLUGIN_ID, context)
        if artifact_type != PRIMARY_TYPE.value:
            raise PluginHandlerError(
                -32602,
                f"evolutionary-artifact-search declares {PRIMARY_TYPE.value!r}, "
                f"campaign targets {artifact_type!r}",
            )
        return {
            "data": {
                "artifact_type": artifact_type,
                "counter": 0,
                "generation": 0,
                # islands[i] holds the MAP-Elites archive of island i.
                "islands": [{"id": i, "archive": {}} for i in range(ISLAND_COUNT)],
                # The orchestrator pins the campaign's F6-derived stage
                # plan here when available; empty means infer from metrics.
                "stage_plan": [],
                "last_evaluation": None,
            }
        }

    def propose(
        self,
        state: dict[str, Any],
        parents: list[dict[str, Any]],
        evidence: dict[str, Any] | None,
        budget: dict[str, Any],
    ) -> dict[str, Any]:
        if not isinstance(state, dict) or not isinstance(state.get("data"), dict):
            raise PluginHandlerError(-32602, "malformed state: expected an object with 'data'")
        if evidence is not None and not isinstance(evidence.get("redacted_items", []), list):
            raise PluginHandlerError(
                -32602, "malformed evidence bundle: 'redacted_items' list is required"
            )
        if max(0, int(budget.get("proposals_remaining", 0))) < 1:
            return {"proposals": []}
        data = state["data"]
        counter = int(data.get("counter", 0))
        rng = random.Random(MUTATION_SEED_BASE + counter)

        # Diversity-constrained parent sampling over the merged archive
        # (islands share the descriptor space; migration is implicit).
        merged: dict[str, dict[str, Any]] = {}
        for island in data.get("islands", []):
            for cell, elite in dict(island.get("archive", {})).items():
                incumbent = merged.get(cell)
                if incumbent is None or float(elite["score"]) > float(incumbent["score"]):
                    merged[cell] = dict(elite)
        sampled = sample_diverse_parents(merged, PARENTS_PER_PROPOSAL, MIN_PARENT_DISTANCE)

        if sampled:
            base = sampled[0]
            base_descriptor = tuple(float(v) for v in base["descriptor"])
            descriptor = mutate_descriptor(base_descriptor, rng)
            base_ids = [str(p["candidate_id"]) for p in sampled]
            base_cell = behavior_cell(base_descriptor)
        else:
            # Empty archive: seed the search at the descriptor origin.
            descriptor = ORIGIN_DESCRIPTOR
            base_ids = []
            base_cell = None

        candidate_id = f"evo-{counter + 1:04d}"
        # A mutation that lands in a new behavior cell needs tooling: the
        # composite carries the tool_spec member atomically (F4).
        needs_tool = behavior_cell(descriptor) != base_cell
        members: list[dict[str, Any]] = [
            {
                "artifact_type": PRIMARY_TYPE.value,
                "patch": {
                    "op": "evolve",
                    "base": base_ids[0] if base_ids else None,
                    "descriptor": list(descriptor),
                    "cell": behavior_cell(descriptor),
                },
                "declared_executables": ("algorithm_runner",),
            }
        ]
        if needs_tool:
            members.append(
                {
                    "artifact_type": AUX_TYPE.value,
                    "patch": {
                        "op": "declare_tool",
                        "tool": f"tools/evo-{behavior_cell(descriptor)}.json",
                    },
                    "declared_executables": (),
                }
            )
        proposal = {
            "proposal_id": candidate_id,
            "artifact_type": PRIMARY_TYPE.value,
            "members": members,
            "rationale": (
                f"generation {int(data.get('generation', 0))}: mutated from "
                f"{len(base_ids)} diversity-constrained parent(s) "
                f"(min distance {MIN_PARENT_DISTANCE})"
            ),
        }
        return {"proposals": [proposal]}

    def observe(self, state: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        data = dict(state.get("data", {}))
        candidate_id = str(result.get("result_id", ""))
        metrics = dict(result.get("metrics", {}))
        plan = stage_plan_from_bindings(data.get("stage_plan", [])) or infer_stage_plan(metrics)
        verdict = cascaded_verdict(metrics, plan)

        islands: list[dict[str, Any]] = [dict(island) for island in data.get("islands", [])]
        counter = int(data.get("counter", 0))
        if verdict["passed"] and verdict["score"] is not None:
            # The candidate cleared every stage — it may enter the
            # archive of its island, if it beats the cell's elite.
            descriptor = descriptor_from_metrics(metrics)
            island_index = _island_of(counter)
            island: dict[str, Any] = (
                islands[island_index] if islands else {"id": island_index, "archive": {}}
            )
            archive = dict(island.get("archive", {}))
            archive = archive_insert(
                archive,
                behavior_cell(descriptor),
                {
                    "candidate_id": candidate_id,
                    "descriptor": list(descriptor),
                    "score": verdict["score"],
                    "generation": int(data.get("generation", 0)),
                },
            )
            if islands:
                islands[island_index] = {**island, "archive": archive}
            else:
                islands = [{"id": island_index, "archive": archive}]
        data["islands"] = islands
        data["last_evaluation"] = candidate_id
        data["last_verdict"] = verdict
        data["counter"] = counter + 1
        data["generation"] = int(data.get("generation", 0)) + 1
        return {"data": data}

    def checkpoint(self, state: dict[str, Any]) -> dict[str, Any]:
        payload = json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
        return {
            "data_b64": base64.b64encode(payload).decode(),
            "schema_id": CHECKPOINT_SCHEMA_ID,
        }


def main() -> int:
    run_research_plugin(EvolutionaryArtifactSearch())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

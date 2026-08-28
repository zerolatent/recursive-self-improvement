"""gepa-prompt-optimizer — reference plugin for ``prompt_bundle`` (PRD §16.3).

A reflective prompt evolution strategy with three PRD-mandated
disciplines:

* **Instance-wise Pareto state.** The state tracks, per evaluation
  instance, the best score any lineage candidate has achieved. A
  candidate earns its place on the frontier by being the best known on
  *some* instance — not by average score, which hides exactly the
  per-instance trade-offs reflective mutation is supposed to exploit.
* **One module per mutation.** Each proposal amends exactly one declared
  module (the campaign's ``mutable_paths``). A mutation that edits two
  modules at once makes the lineage unattributable — which module
  caused the regression? — so the plugin refuses to emit one.
* **Working-minibatch pre-filter.** A candidate that fails the working
  minibatch is rejected *before* full development evaluation: it is
  recorded in the lineage as rejected, never added to the frontier, and
  never becomes a parent. Full development evaluation is too expensive
  to spend on a candidate the cheap filter already killed.

Evaluation feedback arrives through the deterministic ScriptedAgent
backend (locked decision #9: no live-model calls in CI); the plugin
reads instance scores from flat ``instance:<id>`` metric keys.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from evoruntime.plugins.manifest import PluginArtifactType, PluginManifest, ResourceLimits
from evoruntime.plugins.protocol import PluginHandlerError
from evoruntime.plugins.reference._base import build_reference_manifest, run_reference_plugin

PLUGIN_ID = "gepa-prompt-optimizer"
PLUGIN_VERSION = "1.0.0"
MODULE_NAME = "gepa_prompt_optimizer"
ARTIFACT_TYPE = PluginArtifactType.PROMPT_BUNDLE
CHECKPOINT_SCHEMA_ID = "gepa-prompt-optimizer/v1"

_INSTANCE_METRIC_PREFIX = "instance:"


def build_manifest() -> PluginManifest:
    """The plugin's §10.4 manifest declaration."""
    return build_reference_manifest(
        plugin_id=PLUGIN_ID,
        version=PLUGIN_VERSION,
        module=MODULE_NAME,
        artifact_types=(ARTIFACT_TYPE,),
        limits=ResourceLimits(
            wall_clock_minutes=30.0, cpu=1.0, memory_gib=2.0, model_tokens=0, proposals=50
        ),
        seed=1603,
    )


def instance_scores_from_metrics(metrics: dict[str, Any]) -> dict[str, float]:
    """Extract per-instance scores from flat ``instance:<id>`` metric keys."""
    return {
        key[len(_INSTANCE_METRIC_PREFIX) :]: float(value)
        for key, value in metrics.items()
        if key.startswith(_INSTANCE_METRIC_PREFIX) and isinstance(value, (int, float))
    }


def update_pareto_state(pareto: dict[str, float], scores: dict[str, float]) -> dict[str, float]:
    """Instance-wise Pareto max: each instance keeps its best-known score."""
    return {
        instance: max(pareto.get(instance, float("-inf")), score)
        for instance, score in scores.items()
    }


def select_target_module(modules: tuple[str, ...], pareto: dict[str, float]) -> str:
    """Pick the module whose instances have the most headroom.

    An instance belongs to the module that names it (``module`` prefix
    match on the instance id); a module with no scored instances is the
    weakest known and is targeted first.
    """
    if not modules:
        raise PluginHandlerError(-32602, "no declared modules: campaign mutable_paths is empty")

    def module_weakness(module: str) -> float:
        scores = [
            score
            for instance, score in pareto.items()
            if instance == module or instance.startswith(f"{module}:")
        ]
        return min(scores) if scores else float("-inf")

    return max(modules, key=module_weakness)


def next_candidate_id(state_data: dict[str, Any]) -> str:
    counter = int(state_data.get("counter", 0)) + 1
    return f"cand-{counter:04d}"


class GepaPromptOptimizer:
    """§10.2 strategy handler for the gepa-prompt-optimizer plugin."""

    def initialize(self, context: dict[str, Any]) -> dict[str, Any]:
        artifact_type = context.get("artifact_type")
        if artifact_type != ARTIFACT_TYPE.value:
            raise PluginHandlerError(
                -32602,
                f"gepa-prompt-optimizer declares {ARTIFACT_TYPE.value!r}, "
                f"campaign targets {artifact_type!r}",
            )
        modules = context.get("mutable_paths")
        if not isinstance(modules, list) or not modules:
            raise PluginHandlerError(
                -32602, "gepa-prompt-optimizer requires at least one declared module"
            )
        return {
            "data": {
                "artifact_type": artifact_type,
                "modules": [str(module) for module in modules],
                "counter": 0,
                "pareto": {},
                "lineage": {},
                "frontier": [],
                "rejected": [],
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
        modules = tuple(str(module) for module in data.get("modules", []))
        pareto = {k: float(v) for k, v in data.get("pareto", {}).items()}
        module = select_target_module(modules, pareto)
        # Lineage parents are exactly the frontier: candidates that passed
        # the working minibatch. A minibatch failure is never a parent.
        frontier = [str(candidate) for candidate in data.get("frontier", [])]
        candidate_id = next_candidate_id(data)
        lineage = dict(data.get("lineage", {}))
        lineage[candidate_id] = {
            "parents": frontier,
            "module": module,
            "minibatch_passed": False,
        }
        proposal = {
            "proposal_id": candidate_id,
            "artifact_type": ARTIFACT_TYPE.value,
            "patch": {
                "op": "amend_module",
                "module": module,
                "instruction": (
                    f"reflective mutation of {module} guided by instance-wise Pareto state"
                ),
            },
            "rationale": (
                f"one module per mutation ({module}); extends frontier of "
                f"{len(frontier)} minibatch-passing parent(s)"
            ),
        }
        return {"proposals": [proposal], "lineage": lineage}

    def observe(self, state: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        data = dict(state.get("data", {}))
        candidate_id = str(result.get("result_id", ""))
        lineage = dict(data.get("lineage", {}))
        entry = dict(lineage.get(candidate_id, {"parents": [], "module": None}))
        if result.get("passed") is True:
            # Working minibatch passed — the candidate may proceed to full
            # development evaluation and join the frontier.
            entry["minibatch_passed"] = True
            lineage[candidate_id] = entry
            data["lineage"] = lineage
            frontier = [c for c in data.get("frontier", []) if c != candidate_id]
            frontier.append(candidate_id)
            data["frontier"] = frontier
            pareto = {k: float(v) for k, v in data.get("pareto", {}).items()}
            data["pareto"] = update_pareto_state(
                pareto, instance_scores_from_metrics(result.get("metrics", {}))
            )
        else:
            # Rejected at the working minibatch: recorded, never expanded,
            # never a parent. Full development evaluation is not spent.
            entry["minibatch_passed"] = False
            entry["rejected_at"] = "working-minibatch"
            lineage[candidate_id] = entry
            data["lineage"] = lineage
            rejected = [c for c in data.get("rejected", []) if c != candidate_id]
            rejected.append(candidate_id)
            data["rejected"] = rejected
            data["frontier"] = [c for c in data.get("frontier", []) if c != candidate_id]
        data["last_evaluation"] = candidate_id
        data["counter"] = int(data.get("counter", 0)) + 1
        return {"data": data}

    def checkpoint(self, state: dict[str, Any]) -> dict[str, Any]:
        payload = json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
        return {
            "data_b64": base64.b64encode(payload).decode(),
            "schema_id": CHECKPOINT_SCHEMA_ID,
        }


def main() -> int:
    run_reference_plugin(GepaPromptOptimizer())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

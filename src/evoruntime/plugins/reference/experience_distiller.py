"""experience-distiller — reference plugin for ``memory_entry`` (PRD §16.1).

Converts successful **and** failed traces into scoped memory-entry
strategies. The PRD's four hard rules shape every proposal this plugin
can emit:

* **Delta edits only.** The patch vocabulary is ``add_entry`` and
  ``amend_entry`` — never a whole-memory rewrite. An evidence item that
  asks for one is refused and recorded, not silently reinterpreted.
* **Scoped routing.** Every entry is routed by task / environment /
  model / harness (the §9.3 ``MemoryScope`` axes); an unroutable item is
  not distilled.
* **Paired persistence-on/off evaluation required.** A trace that does
  not carry both halves of the persistence-on vs persistence-off pair is
  not evidence — distilling from it would let a memory claim promotion
  on a comparison that was never run. The proposal also *declares* the
  paired evaluation (with the §9.3 non-inferiority and negative-transfer
  gates) that the campaign must run before the entry can leave
  suggestion mode; the plugin proposes, it never promotes.
* **Never auto-promotes executable content.** Items marked executable
  are refused outright — Phase 1 artifacts are non-executable, and a
  distiller that smuggled code into a memory entry would break the
  §12.6 risk model.

Malformed *bundles* (wrong shape at the boundary) are JSON-RPC errors;
malformed *items* are skipped with a recorded reason so one bad trace
cannot discard the rest of the bundle.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from evoruntime.plugins.manifest import PluginArtifactType, PluginManifest, ResourceLimits
from evoruntime.plugins.protocol import PluginHandlerError
from evoruntime.plugins.reference._base import build_reference_manifest, run_reference_plugin

PLUGIN_ID = "experience-distiller"
PLUGIN_VERSION = "1.0.0"
MODULE_NAME = "experience_distiller"
ARTIFACT_TYPE = PluginArtifactType.MEMORY_ENTRY
CHECKPOINT_SCHEMA_ID = "experience-distiller/v1"

#: The evaluation design every distilled entry declares as its promotion
#: requirement (§9.3: persistence non-inferiority + negative transfer).
PAIRED_EVALUATION: dict[str, Any] = {
    "design": "paired",
    "arms": ["persistence-on", "persistence-off"],
    "gates": ["non-inferiority", "negative-transfer"],
}


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
        seed=1601,
    )


def distill_proposals(
    items: tuple[dict[str, Any], ...], max_proposals: int
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Distill redacted evidence items into memory-entry delta proposals.

    Pure function: ``(proposals, skipped)``. ``skipped`` carries one
    ``{"trace_id", "reason"}`` record per refused item, so a campaign's
    lineage shows *why* a trace produced no memory.
    """
    proposals: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for item in items:
        if len(proposals) >= max_proposals:
            break
        if not isinstance(item, dict):
            skipped.append({"trace_id": None, "reason": "malformed item: not an object"})
            continue
        trace_id = item.get("trace_id")
        pair = item.get("persistence_pair")
        if not isinstance(pair, dict) or "on" not in pair or "off" not in pair:
            skipped.append(
                {"trace_id": trace_id, "reason": "requires paired persistence-on/off evaluation"}
            )
            continue
        if item.get("requested_op") == "replace_memory":
            skipped.append(
                {
                    "trace_id": trace_id,
                    "reason": "delta edits only — whole-memory rewrites are never proposed",
                }
            )
            continue
        if item.get("content_kind") == "executable":
            skipped.append(
                {"trace_id": trace_id, "reason": "executable content is never auto-promoted"}
            )
            continue
        route = item.get("route")
        if not isinstance(route, dict) or not {"task_type", "environment"} <= set(route):
            skipped.append(
                {"trace_id": trace_id, "reason": "unroutable: missing task/environment scope"}
            )
            continue
        statement = item.get("strategy_text")
        if not isinstance(statement, str) or not statement:
            skipped.append(
                {"trace_id": trace_id, "reason": "malformed item: no strategy statement"}
            )
            continue
        outcome = item.get("outcome")
        if outcome not in ("success", "failure"):
            skipped.append({"trace_id": trace_id, "reason": f"unknown outcome {outcome!r}"})
            continue
        amends = item.get("amends")
        proposals.append(
            {
                "proposal_id": f"mem-{trace_id}",
                "artifact_type": ARTIFACT_TYPE.value,
                "patch": {
                    "op": "amend_entry" if isinstance(amends, str) and amends else "add_entry",
                    "entry": {
                        "claim": statement,
                        "scope": {
                            "subject": route.get("subject", "shared"),
                            "environment": route["environment"],
                            "task_type": route["task_type"],
                            "model_id": route.get("model_id"),
                            "harness_id": route.get("harness_id"),
                        },
                        "source_trace": trace_id,
                        "outcome": outcome,
                    },
                    "required_evaluation": PAIRED_EVALUATION,
                    "executable": False,
                },
                "rationale": f"distilled from {outcome} trace {trace_id}",
            }
        )
    return proposals, skipped


class ExperienceDistiller:
    """§10.2 strategy handler for the experience-distiller plugin."""

    def initialize(self, context: dict[str, Any]) -> dict[str, Any]:
        artifact_type = context.get("artifact_type")
        if artifact_type != ARTIFACT_TYPE.value:
            raise PluginHandlerError(
                -32602,
                f"experience-distiller declares {ARTIFACT_TYPE.value!r}, "
                f"campaign targets {artifact_type!r}",
            )
        return {"data": {"artifact_type": artifact_type, "distilled": 0}}

    def propose(
        self,
        state: dict[str, Any],
        parents: list[dict[str, Any]],
        evidence: dict[str, Any] | None,
        budget: dict[str, Any],
    ) -> dict[str, Any]:
        if not isinstance(state, dict) or not isinstance(state.get("data"), dict):
            raise PluginHandlerError(-32602, "malformed state: expected an object with 'data'")
        if evidence is None:
            return {"proposals": []}
        items = evidence.get("redacted_items")
        if not isinstance(items, list):
            raise PluginHandlerError(
                -32602, "malformed evidence bundle: 'redacted_items' list is required"
            )
        max_proposals = max(0, int(budget.get("proposals_remaining", 0)))
        proposals, _skipped = distill_proposals(tuple(items), max_proposals)
        return {"proposals": proposals}

    def observe(self, state: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        data = dict(state.get("data", {}))
        data["last_evaluation"] = result.get("result_id")
        return {"data": data}

    def checkpoint(self, state: dict[str, Any]) -> dict[str, Any]:
        payload = json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
        return {
            "data_b64": base64.b64encode(payload).decode(),
            "schema_id": CHECKPOINT_SCHEMA_ID,
        }


def main() -> int:
    run_reference_plugin(ExperienceDistiller())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

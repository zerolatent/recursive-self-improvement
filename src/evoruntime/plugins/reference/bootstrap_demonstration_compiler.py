"""bootstrap-demonstration-compiler — reference plugin (PRD §16.2).

Compiles ``demonstration_set`` and ``compiled_prompt_program`` artifacts
from traces that an **external metric already approved**. Two rules carry
the PRD's intent:

* **Externally metric-approved traces only.** An item without
  ``metric_approved: true`` (backed by a named metric and value) is not
  a demonstration — a bootstrap set compiled from self-reported
  successes would teach the agent its own biases. Unapproved items are
  skipped with a recorded reason.
* **Equal-budget control.** Every compiled demonstration set ships with
  a ``compiled_prompt_program`` marked ``role=equal-budget-control``:
  the same source traces, the same token budget, one-shot. GEPA-style
  search (E3's strategy arms) is only interpretable against this
  control — without it, "the optimizer won" is confounded with "the
  optimizer spent more tokens".

Every demonstration records its provenance: source trace, teacher
model, labels, ordering, and token cost. Malformed bundles are JSON-RPC
errors; unapproved or malformed items are skipped with a reason.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from evoruntime.plugins.manifest import PluginArtifactType, PluginManifest, ResourceLimits
from evoruntime.plugins.protocol import PluginHandlerError
from evoruntime.plugins.reference._base import build_reference_manifest, run_reference_plugin

PLUGIN_ID = "bootstrap-demonstration-compiler"
PLUGIN_VERSION = "1.0.0"
MODULE_NAME = "bootstrap_demonstration_compiler"
ARTIFACT_TYPES = (
    PluginArtifactType.DEMONSTRATION_SET,
    PluginArtifactType.COMPILED_PROMPT_PROGRAM,
)
CHECKPOINT_SCHEMA_ID = "bootstrap-demonstration-compiler/v1"


def build_manifest() -> PluginManifest:
    """The plugin's §10.4 manifest declaration."""
    return build_reference_manifest(
        plugin_id=PLUGIN_ID,
        version=PLUGIN_VERSION,
        module=MODULE_NAME,
        artifact_types=ARTIFACT_TYPES,
        limits=ResourceLimits(
            wall_clock_minutes=30.0, cpu=1.0, memory_gib=2.0, model_tokens=0, proposals=50
        ),
        seed=1602,
    )


def compile_demonstrations(
    items: tuple[dict[str, Any], ...], max_proposals: int
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Compile approved traces into a demonstration set + equal-budget control.

    Pure function: ``(proposals, skipped)``. Ordering is the evidence
    bundle's item order, recorded explicitly in each demonstration.
    """
    demonstrations: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for order, item in enumerate(items):
        if not isinstance(item, dict):
            skipped.append({"trace_id": None, "reason": "malformed item: not an object"})
            continue
        trace_id = item.get("trace_id")
        if item.get("metric_approved") is not True:
            skipped.append({"trace_id": trace_id, "reason": "not externally metric-approved"})
            continue
        teacher = item.get("teacher_model")
        if not isinstance(teacher, str) or not teacher:
            skipped.append({"trace_id": trace_id, "reason": "malformed item: no teacher/model"})
            continue
        tokens = item.get("tokens")
        if not isinstance(tokens, int) or isinstance(tokens, bool) or tokens < 0:
            skipped.append({"trace_id": trace_id, "reason": "malformed item: token cost missing"})
            continue
        labels = item.get("labels")
        if not isinstance(labels, list) or not all(isinstance(label, str) for label in labels):
            skipped.append(
                {"trace_id": trace_id, "reason": "malformed item: labels must be strings"}
            )
            continue
        demonstrations.append(
            {
                "order": order,
                "source_trace": trace_id,
                "teacher_model": teacher,
                "labels": list(labels),
                "tokens": tokens,
            }
        )

    if not demonstrations or max_proposals < 1:
        return [], skipped

    token_budget = sum(demo["tokens"] for demo in demonstrations)
    source_traces = [demo["source_trace"] for demo in demonstrations]
    set_digest = hashlib.sha256(json.dumps(demonstrations, sort_keys=True).encode()).hexdigest()[
        :12
    ]
    proposals: list[dict[str, Any]] = [
        {
            "proposal_id": f"demos-{set_digest}",
            "artifact_type": PluginArtifactType.DEMONSTRATION_SET.value,
            "patch": {
                "op": "compile",
                "demonstrations": demonstrations,
                "token_budget": token_budget,
                "source_traces": source_traces,
            },
            "rationale": f"compiled {len(demonstrations)} metric-approved traces",
        }
    ]
    if max_proposals >= 2:
        # The equal-budget control: same traces, same token budget, one
        # shot. GEPA-style arms are interpreted against this proposal.
        proposals.append(
            {
                "proposal_id": f"control-{set_digest}",
                "artifact_type": PluginArtifactType.COMPILED_PROMPT_PROGRAM.value,
                "patch": {
                    "op": "compile_control",
                    "role": "equal-budget-control",
                    "token_budget": token_budget,
                    "source_traces": source_traces,
                    "shots": 1,
                },
                "rationale": "equal-budget one-shot control for the demonstration set",
            }
        )
    return proposals, skipped


class BootstrapDemonstrationCompiler:
    """§10.2 strategy handler for the bootstrap-demonstration-compiler plugin."""

    def initialize(self, context: dict[str, Any]) -> dict[str, Any]:
        artifact_type = context.get("artifact_type")
        allowed = {t.value for t in ARTIFACT_TYPES}
        if artifact_type not in allowed:
            raise PluginHandlerError(
                -32602,
                f"bootstrap-demonstration-compiler declares {sorted(allowed)}, "
                f"campaign targets {artifact_type!r}",
            )
        return {"data": {"artifact_type": artifact_type, "compiled": 0}}

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
        proposals, _skipped = compile_demonstrations(tuple(items), max_proposals)
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
    run_reference_plugin(BootstrapDemonstrationCompiler())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""workflow-graph-search — the AFlow-inspired research plugin (PRD §16.5, F11).

A workflow-graph search strategy over the ``workflow_graph`` executable
class. AFlow's core loop, adapted to the governed runtime's contracts:

* **The candidate is a graph.** Nodes are LLM-operator steps
  (``generate``, ``verify``, ``ensemble``, ``reflect``); edges are the
  dataflow between them. Each proposal carries the full graph so the
  composite digest (F4) binds the exact structure evaluated.
* **Refinement is experience-driven, not random.** The state keeps an
  experience pool — per-iteration records of which refinement operator
  ran and whether the candidate passed. The next operator is chosen
  from the weakest node's score and that pool, deterministically and
  seeded: same state in, same proposal out (the manifest declares
  ``deterministic`` with a fixed seed, and conformance holds it).
* **Composite multi-artifact proposals (F4).** Expanding the graph with
  a node that needs tooling emits two ordered members: the
  ``workflow_graph`` patch (primary) and the ``tool_spec`` patch for
  the new node's tool. One atomic candidate, one digest over the set.

**Enablement.** The plugin refuses to initialize on any artifact class
whose correctness is not externally executable (:mod:`.enablement`) —
a workflow graph's fitness is its sandboxed execution verdict, and on a
subjectively-judged class the search would optimize the judge.

Evaluation feedback arrives as flat ``node:<id>`` metric keys (per-node
scores from the harness), the same discipline the E7 prompt optimizer
uses for ``instance:<id>`` keys.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from evoruntime.plugins.manifest import PluginArtifactType, PluginManifest, ResourceLimits
from evoruntime.plugins.protocol import PluginHandlerError
from evoruntime.plugins.research._base import build_research_manifest, run_research_plugin
from evoruntime.plugins.research.enablement import require_external_correctness

PLUGIN_ID = "workflow-graph-search"
PLUGIN_VERSION = "1.0.0"
MODULE_NAME = "workflow_graph_search"
PRIMARY_TYPE = PluginArtifactType.WORKFLOW_GRAPH
AUX_TYPE = PluginArtifactType.TOOL_SPEC
CHECKPOINT_SCHEMA_ID = "workflow-graph-search/v1"

#: The LLM-operator vocabulary a graph's nodes draw from (AFlow's
#: operator set, renamed to the runtime's vocabulary).
OPERATOR_SEQUENCE: tuple[str, ...] = ("generate", "verify", "ensemble", "reflect")

#: Per-node score below which the weakest node is pruned instead of the
#: graph being expanded.
PRUNE_THRESHOLD = 0.35

#: The graph never shrinks below its entry/exit pair.
MIN_NODES = 2

_NODE_METRIC_PREFIX = "node:"


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
        seed=1103,
        executables=("graph_runner",),
    )


def node_scores_from_metrics(metrics: dict[str, Any]) -> dict[str, float]:
    """Extract per-node scores from flat ``node:<id>`` metric keys."""
    return {
        key[len(_NODE_METRIC_PREFIX) :]: float(value)
        for key, value in metrics.items()
        if key.startswith(_NODE_METRIC_PREFIX) and isinstance(value, (int, float))
    }


def weakest_node(nodes: list[dict[str, Any]], scores: dict[str, float]) -> dict[str, Any] | None:
    """The node with the lowest known score (missing score counts as worst).

    Pure: returns None only for an empty node list. A node never
    evaluated is the most informative refinement target — its score is
    unknown, not zero.
    """
    if not nodes:
        return None

    def score_of(node: dict[str, Any]) -> float:
        node_id = str(node.get("id", ""))
        return scores.get(node_id, float("-inf"))

    return min(nodes, key=score_of)


def next_operator(counter: int) -> str:
    """The operator a new node carries, rotating deterministically."""
    return OPERATOR_SEQUENCE[counter % len(OPERATOR_SEQUENCE)]


def choose_refinement(
    nodes: list[dict[str, Any]],
    scores: dict[str, float],
    counter: int,
) -> str:
    """Pick the refinement operator: prune a weak graph, else expand.

    The experience-driven rule, kept deterministic: a graph whose
    weakest scored node sits under the prune threshold (and has room to
    shrink) is pruned; otherwise the graph grows. An unscored node is
    never pruned — it has not had the chance to earn its place.
    """
    if not scores:
        # Nothing evaluated yet: the first candidate IS the seed
        # pipeline — its evaluation produces the scores that drive
        # every later refinement decision.
        return "seed"
    # Only nodes that have actually been evaluated drive the prune
    # decision — a just-expanded node has not earned its place yet, but
    # it must not mask a genuinely weak scored node either.
    scored_nodes = [node for node in nodes if str(node.get("id")) in scores]
    weakest = weakest_node(scored_nodes, scores)
    if weakest is None:
        return "expand"
    node_id = str(weakest.get("id", ""))
    if scores[node_id] < PRUNE_THRESHOLD and len(nodes) > MIN_NODES:
        return "prune"
    return "expand"


def initial_graph() -> tuple[list[dict[str, Any]], list[list[str]]]:
    """The seed pipeline every search starts from: generate -> verify."""
    nodes = [
        {"id": "op-1", "operator": "generate", "score": None},
        {"id": "op-2", "operator": "verify", "score": None},
    ]
    edges = [["op-1", "op-2"]]
    return nodes, edges


def graph_patch(nodes: list[dict[str, Any]], edges: list[list[str]], op: str) -> dict[str, Any]:
    """The ``workflow_graph`` member patch: the full candidate structure."""
    return {
        "op": f"refine_graph:{op}",
        "nodes": [dict(node) for node in nodes],
        "edges": [list(edge) for edge in edges],
    }


def expand(
    nodes: list[dict[str, Any]], edges: list[list[str]], counter: int
) -> tuple[list[dict[str, Any]], list[list[str]], str | None]:
    """Add one LLM-operator node feeding into the current exit node.

    Returns the new structure and, when the new node needs tooling, the
    tool name for the composite proposal's ``tool_spec`` member. The
    new node attaches to the current exit; the graph stays a DAG by
    construction (every edge points forward in insertion order).
    """
    operator = next_operator(counter)
    new_id = f"op-{len(nodes) + 1}"
    exit_id = str(nodes[-1]["id"]) if nodes else new_id
    new_nodes = [*nodes, {"id": new_id, "operator": operator, "score": None}]
    new_edges = [*edges, [new_id, exit_id]] if nodes else edges
    # The verify/ensemble operators consult a pinned tool; generate and
    # reflect are pure model steps and need none.
    tool = f"tools/{operator}.json" if operator in ("verify", "ensemble") else None
    return new_nodes, new_edges, tool


def prune(
    nodes: list[dict[str, Any]], edges: list[list[str]], drop_id: str
) -> tuple[list[dict[str, Any]], list[list[str]]]:
    """Remove a node and every edge touching it, keeping the graph connected."""
    kept = [node for node in nodes if str(node.get("id")) != drop_id]
    new_edges = [edge for edge in edges if str(edge[0]) != drop_id and str(edge[1]) != drop_id]
    # Re-attach any node whose only inbound edge came through the dropped
    # node, so the pipeline stays one connected path.
    reachable = {str(kept[0]["id"])} if kept else set()
    for edge in new_edges:
        if str(edge[0]) in reachable:
            reachable.add(str(edge[1]))
    for node in kept:
        node_id = str(node.get("id"))
        if node_id not in reachable and reachable:
            new_edges.append([sorted(reachable)[-1], node_id])
            reachable.add(node_id)
    return kept, new_edges


def apply_refinement(
    nodes: list[dict[str, Any]],
    edges: list[list[str]],
    scores: dict[str, float],
    step: int,
) -> tuple[list[dict[str, Any]], list[list[str]], str | None]:
    """Advance the graph by the one refinement a score entry implies.

    Pure: the graph after k iterations is the fold of this function over
    the recorded score history — propose never mutates state, so the
    orchestrator's observe-driven loop stays the single writer.
    """
    op = choose_refinement(nodes, scores, step)
    if op == "expand":
        return expand(nodes, edges, step)
    if op == "prune":
        scored_nodes = [node for node in nodes if str(node.get("id")) in scores]
        weakest = weakest_node(scored_nodes, scores)
        if weakest is not None:
            pruned_nodes, pruned_edges = prune(nodes, edges, str(weakest.get("id")))
            return pruned_nodes, pruned_edges, None
    return nodes, edges, None


class WorkflowGraphSearch:
    """§10.2 strategy handler for the workflow-graph-search plugin."""

    def initialize(self, context: dict[str, Any]) -> dict[str, Any]:
        artifact_type = require_external_correctness(PLUGIN_ID, context)
        if artifact_type != PRIMARY_TYPE.value:
            raise PluginHandlerError(
                -32602,
                f"workflow-graph-search declares {PRIMARY_TYPE.value!r}, "
                f"campaign targets {artifact_type!r}",
            )
        nodes, edges = initial_graph()
        return {
            "data": {
                "artifact_type": artifact_type,
                "counter": 0,
                "iteration": 0,
                "nodes": nodes,
                "edges": edges,
                "experience": [],
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
        score_history = [dict(entry) for entry in data.get("score_history", [])]
        counter = int(data.get("counter", 0))
        # The graph is a deterministic replay: every recorded score entry
        # but the newest already produced one refinement in an earlier
        # proposal; the newest drives the refinement carried here.
        nodes, edges = initial_graph()
        for step, entry_scores in enumerate(score_history[:-1]):
            nodes, edges, _ = apply_refinement(nodes, edges, entry_scores, step)
        current_scores = dict(score_history[-1]) if score_history else {}
        op = choose_refinement(nodes, current_scores, counter)

        tool: str | None = None
        if op == "expand":
            nodes, edges, tool = expand(nodes, edges, counter)
        elif op == "prune":
            scored_nodes = [node for node in nodes if str(node.get("id")) in current_scores]
            weakest = weakest_node(scored_nodes, current_scores)
            if weakest is not None:
                nodes, edges = prune(nodes, edges, str(weakest.get("id")))
        # op == "seed": the current graph ships unchanged.

        candidate_id = f"wf-{counter + 1:04d}"
        # Composite (F4): the graph patch is the primary member; an
        # expansion that needs tooling carries the tool_spec member with
        # it, so the candidate is one atomic, digest-bound unit.
        members: list[dict[str, Any]] = [
            {
                "artifact_type": PRIMARY_TYPE.value,
                "patch": graph_patch(nodes, edges, op),
                "declared_executables": ("graph_runner",),
            }
        ]
        if tool is not None:
            members.append(
                {
                    "artifact_type": AUX_TYPE.value,
                    "patch": {"op": "declare_tool", "tool": tool, "node_operator": op},
                    "declared_executables": (),
                }
            )
        experience = [dict(record) for record in data.get("experience", [])]
        experience.append({"iteration": int(data.get("iteration", 0)), "operator": op})
        proposal = {
            "proposal_id": candidate_id,
            "artifact_type": PRIMARY_TYPE.value,
            "members": members,
            "rationale": (
                f"{op} refinement after {int(data.get('iteration', 0))} iteration(s); "
                f"graph carries {len(nodes)} LLM-operator node(s)"
            ),
        }
        return {"proposals": [proposal], "experience": experience}

    def observe(self, state: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        data = dict(state.get("data", {}))
        candidate_id = str(result.get("result_id", ""))
        nodes = [dict(node) for node in data.get("nodes", [])]
        scores = node_scores_from_metrics(result.get("metrics", {}))
        for node in nodes:
            node_id = str(node.get("id"))
            if node_id in scores:
                node["score"] = scores[node_id]
        data["nodes"] = nodes
        # The score history is the replay log: one entry per evaluation,
        # each producing exactly one refinement in the next proposal.
        score_history = [dict(entry) for entry in data.get("score_history", [])]
        score_history.append(scores)
        data["score_history"] = score_history
        experience = [dict(record) for record in data.get("experience", [])]
        experience.append(
            {
                "iteration": int(data.get("iteration", 0)),
                "candidate_id": candidate_id,
                "passed": result.get("passed") is True,
                "scores": scores,
            }
        )
        data["experience"] = experience
        data["last_evaluation"] = candidate_id
        data["counter"] = int(data.get("counter", 0)) + 1
        data["iteration"] = int(data.get("iteration", 0)) + 1
        return {"data": data}

    def checkpoint(self, state: dict[str, Any]) -> dict[str, Any]:
        payload = json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
        return {
            "data_b64": base64.b64encode(payload).decode(),
            "schema_id": CHECKPOINT_SCHEMA_ID,
        }


def main() -> int:
    run_research_plugin(WorkflowGraphSearch())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

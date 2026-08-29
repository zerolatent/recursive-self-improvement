"""harness-mutator — the §16.6 research plugin (PRD §16.6, G9).

The fourth ``research/`` member and the Phase 3 deliverable: a
DGM/HGM-style mutation strategy over the ``scaffold`` class (G1). Where
the §16.5 plugins search *within* a candidate space, the harness-mutator
mutates the agent scaffold itself — whole source trees — and lets the
self-edit conformance suite (G2) decide what survives.

**Isolation and access.** The plugin's entrypoint runs at the strictest
isolation tier (``IsolationTier.HIGHEST``) because its candidates are
harness-touching whole-tree code, and its execution requirements demand
tier 4 (derived per class — :func:`~evoruntime.plugins.research._base.
minimum_tier_for`). Its model access is *brokered*: the manifest declares
``model_access=True`` with an explicit ``model_hosts`` allowlist, and
``network=none`` — the manifest validator refuses a direct network path
on a candidate-executing tier, and the egress broker is the sole route
for model traffic either way (``NetworkMode.NONE`` means no direct
egress *and* no free model calls). The allowlist is exact-host, matched
by the broker; a new host is a manifest change, never a wildcard.

**Parent selection reuses the FR-102 productivity projection.** The
plugin does not keep its own score table for parent choice: the
orchestrator pins the scaffold lineage's productivity projection rows
(:class:`~evoruntime.selection.productivity.ProductivityProjectionRow`,
JSON form — the output of ``LineageProductivityService.rows``) into the
state payload, and the plugin ranks parents through the *same* pure
aggregation surface FR-102 defines (:func:`summarize_productivity`).
Parent choice is therefore a function of attested evidence — outcomes
and costs — never of a plugin-private score that could drift from the
attestations.

**The mutation archive is a projection, not a table the plugin owns.**
Plugin-side, the evaluated-candidate history lives in the checkpointed
state like any other strategy's memory. The durable archive is
``scaffold_mutation_archive``
(:mod:`evoruntime.selection.mutation_archive`) — a rebuildable
projection over the append-only proposal and attestation records, in
exactly the ``productivity.py`` pattern: rebuildable at any time,
``reconcile()`` proving equivalence with the raw evidence.

**Mutation classes.** Every proposal declares its mutation class — the
campaign's spec-v3 preregistration (G3) pins which classes are legal;
the orchestrator pins the campaign's class ids into the state payload
and the plugin proposes only from that list, rotating deterministically.
The class travels in the proposal patch, lands in the registered
proposal's metadata, and is what the graduation policy (G10) later reads
out of the mutation archive.

**Enablement.** Like the §16.5 plugins, the harness-mutator refuses to
initialize on any class without an external correctness oracle
(:mod:`.enablement`) — the scaffold class qualifies through self-edit
conformance (G1/G2).
"""

from __future__ import annotations

import base64
import json
import random
from collections.abc import Iterable, Mapping
from typing import Any

from evoruntime.core.isolation import IsolationTier
from evoruntime.plugins.manifest import (
    NetworkMode,
    PermissionRequest,
    PluginArtifactType,
    PluginManifest,
    ResourceLimits,
)
from evoruntime.plugins.protocol import PluginHandlerError
from evoruntime.plugins.research._base import build_research_manifest, run_research_plugin
from evoruntime.plugins.research.enablement import require_external_correctness
from evoruntime.selection.productivity import (
    ProductivityProjectionRow,
    summarize_productivity,
)

PLUGIN_ID = "harness-mutator"
PLUGIN_VERSION = "1.0.0"
MODULE_NAME = "harness_mutator"
PRIMARY_TYPE = PluginArtifactType.SCAFFOLD
CHECKPOINT_SCHEMA_ID = "harness-mutator/v1"

#: Exact hosts the plugin's model calls may route to, through the egress
#: broker. Deliberately minimal: one OpenAI-compatible endpoint. The
#: broker matches hosts exactly — never suffix or wildcard — so this is
#: the whole world the plugin can reach, and widening it is a reviewed
#: manifest change.
MODEL_HOSTS: tuple[str, ...] = ("api.openai.com",)

#: Deterministic mutation seed base — matches the manifest's seed so a
#: checkpointed state replays identically.
MUTATION_SEED_BASE = 2609

#: Every Nth proposal mutates the *second*-ranked parent instead of the
#: best one (HGM-style history-guided exploration): greedy-only parent
#: choice is how a mutation campaign converges onto one lineage.
EXPLORE_INTERVAL = 4

#: Mutation classes proposed when the orchestrator has not pinned the
#: campaign's spec-v3 classes into state. These are the G3 docstring's
#: example classes; a real campaign always pins its own preregistered
#: set, and the plugin then proposes only from that set.
DEFAULT_MUTATION_CLASSES: tuple[str, ...] = (
    "prompt_module_edit",
    "tool_use_rewrite",
    "control_flow_change",
)

#: The executable entry the sandbox executor may spawn to run a mutated
#: scaffold's pinned conformance suite (G1/G2: self-edit conformance is
#: the scaffold class's correctness oracle).
SCAFFOLD_RUNNER = "scaffold_runner"

#: The proposal-metadata key carrying the declared mutation class. The
#: registry stores it verbatim in ``proposal_records.proposal_metadata``
#: and the mutation-archive projection reads it back from there.
MUTATION_CLASS_METADATA_KEY = "mutation_class"

#: The attestation metric holding a scaffold candidate's fitness. Absent
#: fitness keeps the row (the outcome is still evidence) with a NULL
#: fitness column.
FITNESS_METRIC_KEY = "fitness"

_ROW_FIELDS = (
    "proposal_id",
    "artifact_digest",
    "parent_digest",
    "strategy_id",
    "campaign_id",
    "attestation_id",
    "outcome",
)


def build_manifest() -> PluginManifest:
    """The plugin's §10.4 manifest declaration (scaffold outputs, tier 4).

    The permission posture is the §16.6 one: no direct network path
    (the manifest validator refuses one on a candidate-executing tier)
    with brokered model access through the egress broker under an
    explicit exact-host allowlist, and the entrypoint itself declared at
    the strictest isolation tier because its candidates are
    harness-touching whole-tree code.
    """
    return build_research_manifest(
        plugin_id=PLUGIN_ID,
        version=PLUGIN_VERSION,
        module=MODULE_NAME,
        artifact_types=(PRIMARY_TYPE,),
        limits=ResourceLimits(
            wall_clock_minutes=60.0,
            cpu=2.0,
            memory_gib=4.0,
            model_tokens=200_000,
            proposals=50,
        ),
        seed=MUTATION_SEED_BASE,
        executables=(SCAFFOLD_RUNNER,),
        permissions=PermissionRequest(
            network=NetworkMode.NONE,
            model_access=True,
            model_hosts=MODEL_HOSTS,
        ),
        isolation_tier=IsolationTier.HIGHEST,
    )


# ---------------------------------------------------------------------------
# Parent selection over the FR-102 productivity projection (pure).
# ---------------------------------------------------------------------------


def _row_from_payload(payload: Mapping[str, Any]) -> ProductivityProjectionRow:
    """Rebuild one typed FR-102 projection row from its JSON form.

    The orchestrator pins ``LineageProductivityService.rows`` output into
    the state payload as plain mappings; this lifts one back into the
    typed row the FR-102 aggregation surface consumes. Pure.
    """
    missing = [field for field in _ROW_FIELDS if field not in payload]
    if missing:
        raise PluginHandlerError(
            -32602,
            f"malformed productivity projection row: missing {', '.join(missing)}",
        )
    cost = payload.get("cost", {})
    if not isinstance(cost, Mapping):
        raise PluginHandlerError(-32602, "malformed productivity projection row: 'cost' mapping")
    return ProductivityProjectionRow(
        proposal_id=str(payload["proposal_id"]),
        artifact_digest=str(payload["artifact_digest"]),
        parent_digest=(
            str(payload["parent_digest"]) if payload["parent_digest"] is not None else None
        ),
        strategy_id=str(payload["strategy_id"]),
        campaign_id=(str(payload["campaign_id"]) if payload["campaign_id"] is not None else None),
        attestation_id=str(payload["attestation_id"]),
        outcome=str(payload["outcome"]),
        cost={str(key): float(value) for key, value in cost.items()},
    )


def productivity_ranking(
    rows: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Rank scaffold lineage candidates by the FR-102 productivity signal.

    Consumes projection rows in their JSON form and reuses the FR-102
    aggregation surface (:func:`summarize_productivity`) for the cost
    side; the outcome side is the candidate's attested pass ratio. The
    ranking is deterministic: pass ratio descending, then mean
    ``total_tokens`` ascending (cheaper wins ties), then digest — so the
    same evidence always produces the same parent order.

    A candidate with no attestations carries no productivity signal and
    is not ranked; the plugin falls back to its in-state archive.
    """
    typed = [_row_from_payload(row) for row in rows]
    summaries = {summary.artifact_digest: summary for summary in summarize_productivity(typed)}

    outcomes: dict[str, list[str]] = {}
    parents: dict[str, str | None] = {}
    for row in typed:
        outcomes.setdefault(row.artifact_digest, []).append(row.outcome)
        parents.setdefault(row.artifact_digest, row.parent_digest)

    ranked: list[dict[str, Any]] = []
    for digest, summary in summaries.items():
        attested = outcomes.get(digest, [])
        passes = sum(1 for outcome in attested if outcome == "pass")
        mean_total_tokens = summary.mean_cost.get("total_tokens")
        ranked.append(
            {
                "artifact_digest": digest,
                "parent_digest": parents.get(digest),
                "attestation_count": summary.attestation_count,
                "pass_ratio": passes / len(attested) if attested else 0.0,
                "mean_total_tokens": mean_total_tokens,
            }
        )
    ranked.sort(
        key=lambda entry: (
            -entry["pass_ratio"],
            entry["mean_total_tokens"] if entry["mean_total_tokens"] is not None else float("inf"),
            entry["artifact_digest"],
        )
    )
    return ranked


def choose_parent(ranking: list[dict[str, Any]], counter: int) -> dict[str, Any] | None:
    """One deterministic parent choice from the productivity ranking.

    Greedy by default (DGM: mutate the most productive scaffold); every
    ``EXPLORE_INTERVAL``-th proposal takes the runner-up when one exists
    (HGM-style exploration over lineage history), so the campaign does
    not collapse onto a single lineage. Pure.
    """
    if not ranking:
        return None
    if counter % EXPLORE_INTERVAL == EXPLORE_INTERVAL - 1 and len(ranking) > 1:
        return ranking[1]
    return ranking[0]


def choose_mutation_class(
    classes: tuple[str, ...] | list[str], counter: int, rng: random.Random
) -> str:
    """One declared mutation class for this proposal.

    Round-robin over the campaign's pinned classes by counter, with the
    deterministic RNG jittering the start so class coverage does not
    align with the exploration cadence. Pure given the inputs.
    """
    if not classes:
        raise PluginHandlerError(
            -32602, "no mutation classes pinned: a scaffold proposal must declare its class"
        )
    index = (counter + rng.randrange(len(classes))) % len(classes)
    return classes[index]


# ---------------------------------------------------------------------------
# The strategy handler.
# ---------------------------------------------------------------------------


class HarnessMutator:
    """§10.2 strategy handler for the harness-mutator plugin (PRD §16.6)."""

    def initialize(self, context: dict[str, Any]) -> dict[str, Any]:
        artifact_type = require_external_correctness(PLUGIN_ID, context)
        if artifact_type != PRIMARY_TYPE.value:
            raise PluginHandlerError(
                -32602,
                f"harness-mutator declares {PRIMARY_TYPE.value!r}, "
                f"campaign targets {artifact_type!r}",
            )
        return {
            "data": {
                "artifact_type": artifact_type,
                "counter": 0,
                "generation": 0,
                # The orchestrator pins the campaign's spec-v3 mutation
                # classes here (G3 preregistration); empty means the
                # plugin's default class vocabulary.
                "mutation_classes": [],
                # The orchestrator pins the scaffold lineage's FR-102
                # productivity projection rows here (JSON form); empty
                # means no attested lineage yet.
                "productivity_rows": [],
                # The plugin-side evaluated-candidate history (DGM
                # archive memory). The durable archive is the server-side
                # rebuildable projection.
                "archive": [],
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

        classes = self._pinned_classes(data)
        ranking = productivity_ranking(data.get("productivity_rows", []))
        parent = choose_parent(ranking, counter)
        if parent is None:
            # No attested lineage yet: seed the campaign from the
            # runtime-supplied parents (the incumbent scaffold), or from
            # scratch when the runtime sent none.
            parent = self._parent_from_refs(parents)

        mutation_class = choose_mutation_class(classes, counter, rng)
        candidate_id = f"mut-{counter + 1:04d}"
        base_digest = parent["artifact_digest"] if parent else None

        members: list[dict[str, Any]] = [
            {
                "artifact_type": PRIMARY_TYPE.value,
                "patch": {
                    "op": "mutate",
                    "base": base_digest,
                    "mutation_class": mutation_class,
                    "generation": int(data.get("generation", 0)),
                },
                "declared_executables": (SCAFFOLD_RUNNER,),
            }
        ]
        if parent is not None:
            rationale = (
                f"generation {int(data.get('generation', 0))}: {mutation_class} mutation of "
                f"{base_digest} — parent ranked by FR-102 productivity "
                f"(pass ratio {parent['pass_ratio']:.2f} over "
                f"{parent['attestation_count']} attestation(s))"
            )
        else:
            rationale = (
                f"generation {int(data.get('generation', 0))}: {mutation_class} mutation of "
                "the seed scaffold — no attested lineage yet"
            )
        proposal = {
            "proposal_id": candidate_id,
            "artifact_type": PRIMARY_TYPE.value,
            "members": members,
            "rationale": rationale,
        }
        return {"proposals": [proposal]}

    def observe(self, state: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        data = dict(state.get("data", {}))
        candidate_id = str(result.get("result_id", ""))
        metrics = dict(result.get("metrics", {}))
        fitness = metrics.get(FITNESS_METRIC_KEY)
        archive = [dict(entry) for entry in data.get("archive", [])]
        archive.append(
            {
                "candidate_id": candidate_id,
                "passed": bool(result.get("passed", False)),
                "fitness": float(fitness) if isinstance(fitness, (int, float)) else None,
                "generation": int(data.get("generation", 0)),
            }
        )
        data["archive"] = archive
        data["last_evaluation"] = candidate_id
        data["counter"] = int(data.get("counter", 0)) + 1
        data["generation"] = int(data.get("generation", 0)) + 1
        return {"data": data}

    def checkpoint(self, state: dict[str, Any]) -> dict[str, Any]:
        payload = json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
        return {
            "data_b64": base64.b64encode(payload).decode(),
            "schema_id": CHECKPOINT_SCHEMA_ID,
        }

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _pinned_classes(data: dict[str, Any]) -> tuple[str, ...]:
        """The campaign's declared mutation classes: the orchestrator's
        spec-v3 pin when present, the plugin defaults otherwise."""
        pinned = data.get("mutation_classes") or []
        if not isinstance(pinned, list) or not all(
            isinstance(class_id, str) and class_id.strip() for class_id in pinned
        ):
            raise PluginHandlerError(
                -32602, "malformed state: 'mutation_classes' must be a list of class ids"
            )
        return tuple(pinned) if pinned else DEFAULT_MUTATION_CLASSES

    @staticmethod
    def _parent_from_refs(parents: list[dict[str, Any]]) -> dict[str, Any] | None:
        """A parent entry from the runtime's ArtifactRef parents.

        The runtime passes content-addressed refs (digest + type) for the
        campaign's incumbent scaffold; without attested productivity rows
        they are the only lineage signal. Non-scaffold refs are ignored —
        the plugin mutates scaffolds only.
        """
        for ref in parents or []:
            if not isinstance(ref, Mapping):
                raise PluginHandlerError(
                    -32602, "malformed parents: each parent must be an artifact ref object"
                )
            if ref.get("artifact_type") == PRIMARY_TYPE.value and ref.get("digest"):
                return {
                    "artifact_digest": str(ref["digest"]),
                    "parent_digest": None,
                    "attestation_count": 0,
                    "pass_ratio": 0.0,
                    "mean_total_tokens": None,
                }
        return None


def main() -> int:
    run_research_plugin(HarnessMutator())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""skillopt-text-skill-optimizer — reference plugin for ``skill_package``
(PRD §16.4).

A bounded, text-only skill-package optimizer. The PRD's rules:

* **Bounded add/delete/replace edits.** The patch vocabulary is exactly
  ``add`` / ``delete`` / ``replace`` on named sections, at most
  :data:`MAX_EDITS_PER_PROPOSAL` edits per proposal. A proposal that
  would rewrite the whole skill is not a bounded edit; the excess is
  deferred, not smuggled in.
* **Text-only.** Every edit body must be a string. Binary or executable
  members are out of scope for Phase 1 — an edit that is not text is
  refused and its evidence goes to the reject buffer, not the proposal.
* **Reject-buffer evidence retained.** Refused edits and regressing
  candidates are kept in the state's reject buffer with their reasons.
  Discarding the evidence of *why* something was rejected is how the
  same bad edit gets re-proposed three rounds later.
* **Repairs and regressions reported separately.** Evaluation feedback
  carries ``repairs`` (previously failing instances the candidate
  fixed) and ``regressions`` (previously passing instances it broke) as
  separate counters. A candidate with 3 repairs and 3 regressions is a
  trade-off, not a wash — collapsing the two numbers into one net
  score would hide that.

Evaluation feedback arrives through the deterministic ScriptedAgent
backend (locked decision #9: no live-model calls in CI).
"""

from __future__ import annotations

import base64
import json
from typing import Any

from evoruntime.plugins.manifest import PluginArtifactType, PluginManifest, ResourceLimits
from evoruntime.plugins.protocol import PluginHandlerError
from evoruntime.plugins.reference._base import build_reference_manifest, run_reference_plugin

PLUGIN_ID = "skillopt-text-skill-optimizer"
PLUGIN_VERSION = "1.0.0"
MODULE_NAME = "skillopt_text_skill_optimizer"
ARTIFACT_TYPE = PluginArtifactType.SKILL_PACKAGE
CHECKPOINT_SCHEMA_ID = "skillopt-text-skill-optimizer/v1"

#: Maximum bounded edits one proposal may carry (PRD §16.4 "bounded").
MAX_EDITS_PER_PROPOSAL = 5

#: The complete edit vocabulary — anything else is not a bounded edit.
ALLOWED_ACTIONS = ("add", "delete", "replace")


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
        seed=1604,
    )


def validate_edit(edit: Any) -> str | None:
    """Return a rejection reason for a non-conforming edit, else ``None``.

    Text-only and bounded: the action must be in the vocabulary, the
    body must be a string (``delete`` carries no body), and an edit
    that declares itself executable is out of scope for Phase 1.
    """
    if not isinstance(edit, dict):
        return "malformed edit: not an object"
    action = edit.get("action")
    if action not in ALLOWED_ACTIONS:
        return f"action {action!r} outside the add/delete/replace vocabulary"
    if edit.get("executable") is True:
        return "executable members are out of scope for Phase 1"
    if action != "delete":
        text = edit.get("text")
        if not isinstance(text, str) or not text:
            return "text-only: edit body must be a non-empty string"
    section = edit.get("section")
    if not isinstance(section, str) or not section:
        return "malformed edit: no target section"
    return None


def plan_edits(
    items: tuple[dict[str, Any], ...], max_proposals: int
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Turn redacted evidence items into one bounded-edit proposal.

    Pure function: ``(proposals, rejected)``. ``rejected`` carries one
    record per refused edit — the reject buffer's evidence.
    """
    if max_proposals < 1:
        return [], []
    edits: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            rejected.append({"edit": None, "reason": "malformed item: not an object"})
            continue
        raw_edits = item.get("skill_edits")
        if not isinstance(raw_edits, list):
            rejected.append({"edit": None, "reason": "malformed item: no skill_edits list"})
            continue
        for edit in raw_edits:
            reason = validate_edit(edit)
            if reason is not None:
                rejected.append({"edit": edit, "reason": reason})
                continue
            if len(edits) >= MAX_EDITS_PER_PROPOSAL:
                rejected.append(
                    {
                        "edit": edit,
                        "reason": (
                            f"bounded to {MAX_EDITS_PER_PROPOSAL} edits per proposal — deferred"
                        ),
                    }
                )
                continue
            edits.append(
                {
                    "action": edit["action"],
                    "section": edit["section"],
                    "text": edit.get("text", ""),
                }
            )
    if not edits:
        return [], rejected
    proposal = {
        "proposal_id": f"skill-{len(edits)}-edits",
        "artifact_type": ARTIFACT_TYPE.value,
        "patch": {
            "op": "skill_edit",
            "edits": edits,
            "text_only": True,
            "bounded": MAX_EDITS_PER_PROPOSAL,
        },
        "rationale": f"{len(edits)} bounded text edits (add/delete/replace)",
    }
    return [proposal], rejected


class SkilloptTextSkillOptimizer:
    """§10.2 strategy handler for the skillopt-text-skill-optimizer plugin."""

    def initialize(self, context: dict[str, Any]) -> dict[str, Any]:
        artifact_type = context.get("artifact_type")
        if artifact_type != ARTIFACT_TYPE.value:
            raise PluginHandlerError(
                -32602,
                f"skillopt-text-skill-optimizer declares {ARTIFACT_TYPE.value!r}, "
                f"campaign targets {artifact_type!r}",
            )
        return {
            "data": {
                "artifact_type": artifact_type,
                "proposed": 0,
                "repairs": 0,
                "regressions": 0,
                "reject_buffer": [],
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
        if evidence is None:
            return {"proposals": []}
        items = evidence.get("redacted_items")
        if not isinstance(items, list):
            raise PluginHandlerError(
                -32602, "malformed evidence bundle: 'redacted_items' list is required"
            )
        max_proposals = max(0, int(budget.get("proposals_remaining", 0)))
        proposals, _rejected = plan_edits(tuple(items), max_proposals)
        return {"proposals": proposals}

    def observe(self, state: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        data = dict(state.get("data", {}))
        metrics = result.get("metrics", {})
        if not isinstance(metrics, dict):
            metrics = {}
        # Repairs and regressions are separate counters on purpose: a
        # candidate that trades 3 repairs for 3 regressions is a
        # trade-off the record must keep visible.
        repairs = metrics.get("repairs", 0)
        regressions = metrics.get("regressions", 0)
        data["repairs"] = int(data.get("repairs", 0)) + (
            int(repairs) if isinstance(repairs, (int, float)) else 0
        )
        data["regressions"] = int(data.get("regressions", 0)) + (
            int(regressions) if isinstance(regressions, (int, float)) else 0
        )
        if result.get("passed") is not True:
            buffer = list(data.get("reject_buffer", []))
            buffer.append(
                {
                    "candidate_id": result.get("result_id"),
                    "reason": "failed evaluation",
                    "repairs": data["repairs"],
                    "regressions": data["regressions"],
                }
            )
            data["reject_buffer"] = buffer
        data["last_evaluation"] = result.get("result_id")
        return {"data": data}

    def checkpoint(self, state: dict[str, Any]) -> dict[str, Any]:
        payload = json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
        return {
            "data_b64": base64.b64encode(payload).decode(),
            "schema_id": CHECKPOINT_SCHEMA_ID,
        }


def main() -> int:
    run_reference_plugin(SkilloptTextSkillOptimizer())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

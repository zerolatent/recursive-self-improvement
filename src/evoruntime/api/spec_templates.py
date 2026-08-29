"""Campaign spec templates (H4): starting points for authoring v3 specs.

A template is a complete, valid-shaped v3 document with placeholder
digests and handles — the operator fills in the pinned image digests,
partition ids, and holdout handle, then runs `evo campaign validate`
(dry-run, registers nothing) before `evo campaign plan` (registers and
signs). The templates exist because the v3 shape has enough required
sections (arms, budgets, statistics, stopping rules) that hand-authoring
from scratch is where malformed specs come from.

Templates are data, not logic: they are plain mappings, upgraded nowhere,
validated nowhere here — validation is the server's job, through the
same plan-step checks `create_campaign` runs.
"""

from __future__ import annotations

from typing import Any

#: Placeholder digest markers an operator must replace before planning.
_PLACEHOLDER_IMAGE = "ghcr.io/evoruntime/REPLACE-ME@sha256:" + "0" * 64
_PLACEHOLDER_DIGEST = "sha256:" + "0" * 64

TEMPLATE_KINDS = ("prompt-bundle", "coding-agent")


def prompt_bundle_template() -> dict[str, Any]:
    """A prompt-bundle campaign: one mutable prompt path, four arms."""
    return {
        "schema_version": 3,
        "name": "prompt-bundle-campaign-1",
        "incumbent": {
            "release_manifest_digest": _PLACEHOLDER_DIGEST,
            "artifact_type": "prompt_bundle",
        },
        "mutable_artifacts": [{"artifact_type": "prompt_bundle", "paths": ["prompts/system.md"]}],
        "strategy_plugin": {
            "plugin_id": "evo-prompt-strategist",
            "pinned_image": _PLACEHOLDER_IMAGE,
        },
        "arms": [
            {"id": "incumbent", "kind": "incumbent"},
            {"id": "retry", "kind": "retry-self-consistency", "max_attempts": 3},
            {"id": "one-shot", "kind": "one-shot-control"},
            {"id": "strategy", "kind": "strategy"},
        ],
        "datasets": {
            "dev_partition": "REPLACE-DEV-PARTITION",
            "selection_partition": "REPLACE-SELECTION-PARTITION",
            "holdout_handle": "holdout://REPLACE-HANDLE",
        },
        "evaluators": [{"name": "coding-verifier", "pinned_image": _PLACEHOLDER_IMAGE}],
        "budgets": {
            "task_budget_profile": "task-budget-v1",
            "max_proposals": 10,
            "max_model_tokens": 100_000,
            "max_wall_clock_minutes": 30.0,
        },
        "promotion_policy": {"policy_id": "tier-2-standard", "policy_digest": _PLACEHOLDER_DIGEST},
        "statistics": {
            "alpha": 0.05,
            "multiplicity": "bonferroni",
            "bootstrap_iterations": 200,
            "bootstrap_seed": 7,
        },
        "stopping_rules": {"max_rounds": 5, "max_no_improvement_rounds": 2},
        "metadata": {"owner": "evaluator"},
    }


def coding_agent_template() -> dict[str, Any]:
    """A coding-agent campaign (Phase 4): the fixture harness as the arm backend."""
    spec = prompt_bundle_template()
    spec["name"] = "coding-agent-campaign-1"
    spec["incumbent"] = {
        "release_manifest_digest": _PLACEHOLDER_DIGEST,
        "artifact_type": "coding_agent",
    }
    spec["mutable_artifacts"] = [{"artifact_type": "coding_agent", "paths": ["agent/config.yaml"]}]
    spec["strategy_plugin"] = {
        "plugin_id": "evo-coding-strategist",
        "pinned_image": _PLACEHOLDER_IMAGE,
    }
    return spec


def render_template(kind: str) -> dict[str, Any]:
    """Return the template for ``kind``.

    Raises:
        ValueError: unknown template kind.
    """
    templates = {
        "prompt-bundle": prompt_bundle_template,
        "coding-agent": coding_agent_template,
    }
    try:
        return templates[kind]()
    except KeyError:
        raise ValueError(
            f"unknown template kind {kind!r} (known: {', '.join(TEMPLATE_KINDS)})"
        ) from None

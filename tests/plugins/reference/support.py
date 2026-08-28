"""Shared helpers for the E7 reference-plugin test suite.

Every conformance and behavior test drives the real plugin subprocess
(``python -m evoruntime.plugins.reference.<module>``) through the E2
runtime clients, with evaluation feedback produced by the deterministic
ScriptedAgent — no live-model calls anywhere (locked decision #9).
"""

from __future__ import annotations

import importlib
import sys
from typing import Any

from evoruntime.eval.backends import AgentRequest, ScriptedAgent, ScriptedStep
from evoruntime.eval.budgets import BudgetMeter, BudgetUsage, TaskBudget
from evoruntime.eval.tasks import EvalTask
from evoruntime.plugins.manifest import PluginManifest, validate_manifest
from evoruntime.plugins.protocol import (
    DevEvaluationResult,
    InMemoryCheckpointStore,
    ReadOnlyCampaignContext,
    RedactedEvidenceBundle,
    RemainingBudget,
    StdioJsonRpcTransport,
    StrategyPluginClient,
    clean_plugin_env,
)
from tests.plugins.support import RUNTIME_VERSION

#: (module name, declared artifact type for the campaign context, mutable
#: paths the campaign exposes). In PRD §16 order.
PLUGIN_PARAMS: list[tuple[str, str, tuple[str, ...]]] = [
    ("experience_distiller", "memory_entry", ("memory/",)),
    ("bootstrap_demonstration_compiler", "demonstration_set", ("demonstration_set/",)),
    ("gepa_prompt_optimizer", "prompt_bundle", ("prompt_bundle/system.md",)),
    ("skillopt_text_skill_optimizer", "skill_package", ("skill_package/",)),
]

PLUGIN_MODULE_NAMES = [name for name, _, _ in PLUGIN_PARAMS]


def plugin_command(module_name: str) -> tuple[str, ...]:
    """The subprocess command — matches the manifest entrypoint module path."""
    return (sys.executable, "-m", f"evoruntime.plugins.reference.{module_name}")


def plugin_env() -> dict[str, str]:
    """The scrubbed environment a runtime would spawn the plugin with."""
    return clean_plugin_env()


def plugin_context(artifact_type: str, mutable_paths: tuple[str, ...]) -> ReadOnlyCampaignContext:
    return ReadOnlyCampaignContext(
        campaign_id="camp-e7",
        artifact_type=artifact_type,
        mutable_paths=mutable_paths,
        runtime_version=RUNTIME_VERSION,
    )


def make_budget(proposals_remaining: int = 5) -> RemainingBudget:
    return RemainingBudget(
        proposals_remaining=proposals_remaining,
        wall_clock_minutes_remaining=10.0,
        model_tokens_remaining=0,
    )


def strategy_client(module_name: str) -> tuple[StrategyPluginClient, InMemoryCheckpointStore]:
    transport = StdioJsonRpcTransport(plugin_command(module_name), env=plugin_env())
    store = InMemoryCheckpointStore()
    return StrategyPluginClient(transport, checkpoint_store=store), store


def load_plugin_module(module_name: str) -> Any:
    return importlib.import_module(f"evoruntime.plugins.reference.{module_name}")


def sample_evidence(module_name: str) -> RedactedEvidenceBundle:
    """A valid, plugin-shaped redacted evidence bundle (already DLP'd)."""
    items: list[dict[str, Any]]
    if module_name == "experience_distiller":
        items = [
            {
                "trace_id": "t-success",
                "outcome": "success",
                "persistence_pair": {"on": {"score": 0.9}, "off": {"score": 0.6}},
                "route": {
                    "subject": "shared",
                    "environment": "ci",
                    "task_type": "coding",
                    "model_id": "model-a",
                    "harness_id": "harness-a",
                },
                "strategy_text": "prefer pathlib for suffix slicing",
            },
            {
                "trace_id": "t-failure",
                "outcome": "failure",
                "persistence_pair": {"on": {"score": 0.4}, "off": {"score": 0.5}},
                "route": {"subject": "shared", "environment": "ci", "task_type": "coding"},
                "strategy_text": "never build Decimal directly from float",
            },
        ]
    elif module_name == "bootstrap_demonstration_compiler":
        items = [
            {
                "trace_id": "t-approved-1",
                "metric_approved": True,
                "teacher_model": "teacher-x",
                "labels": ["golden", "coding"],
                "tokens": 120,
            },
            {
                "trace_id": "t-approved-2",
                "metric_approved": True,
                "teacher_model": "teacher-y",
                "labels": ["coding"],
                "tokens": 80,
            },
        ]
    elif module_name == "skillopt_text_skill_optimizer":
        items = [
            {
                "skill_edits": [
                    {
                        "action": "replace",
                        "section": "error-handling",
                        "text": "catch and re-raise with context",
                    },
                    {
                        "action": "add",
                        "section": "testing",
                        "text": "assert on behavior, not implementation",
                    },
                ]
            }
        ]
    else:  # gepa_prompt_optimizer — proposes from state, evidence optional
        items = []
    return RedactedEvidenceBundle(bundle_id=f"bundle-{module_name}", redacted_items=tuple(items))


def scripted_dev_result(
    task_id: str,
    *,
    claimed_success: bool,
    metrics: dict[str, float] | None = None,
    attempt: int = 1,
) -> DevEvaluationResult:
    """Produce a DevEvaluationResult by actually running the ScriptedAgent.

    The deterministic backend (locked decision #9) charges a real
    BudgetMeter and returns a known outcome; the harness maps that onto
    the §10.2 development-evaluation feedback the plugins observe.
    """
    agent = ScriptedAgent({task_id: [ScriptedStep(claimed_success=claimed_success)]})
    task = EvalTask(id=task_id, prompt="deterministic conformance probe")
    meter = BudgetMeter(
        TaskBudget(
            max_input_tokens=10_000,
            max_output_tokens=10_000,
            max_tool_calls=10,
            max_wall_clock_s=60.0,
        )
    )
    response = agent.run(
        AgentRequest(task=task, attempt=attempt, seed=7, remaining=BudgetUsage()),
        meter,
    )
    assert response.claimed_success is claimed_success
    return DevEvaluationResult(
        result_id=f"{task_id}-{attempt}",
        passed=response.claimed_success,
        metrics=metrics or {},
    )


def assert_manifest_admits(module_name: str) -> PluginManifest:
    """Import the plugin, validate its manifest against the runtime version."""
    manifest = load_plugin_module(module_name).build_manifest()
    assert validate_manifest(manifest, RUNTIME_VERSION) == ()
    return manifest

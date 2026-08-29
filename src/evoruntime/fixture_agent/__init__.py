"""The fixture coding agent — H1 of EvoRuntime Phase 4 (PRD §17.1 steps 1–2).

A runnable coding-agent harness on ``evoruntime.sdk`` as-is: a sandboxed tool
loop (read/edit/shell/test) executing inside the F1 sandbox workspace, with
prompt-version recording as a details convention, retrieved skills via
``artifact_loaded``, patch output as digest-referenced payloads, an untrusted
claimed outcome, and an external verifier that runs the fixture's executable
tests and signs an ``OutcomeAttestation``.

Integration work, not SDK work: the six-type event vocabulary stays closed,
and payload registration is H2 — this package emits digests only.
"""

from evoruntime.fixture_agent.agent import (
    SKILL_ARTIFACT_KIND,
    EditStep,
    FixtureAgent,
    FixtureRunResult,
    FixtureTask,
    ReadStep,
    RunTestsStep,
    ShellStep,
    Skill,
    Step,
)
from evoruntime.fixture_agent.tools import (
    DEFAULT_TOOL_TIMEOUT_S,
    ToolError,
    ToolObservation,
    WorkspaceTools,
)
from evoruntime.fixture_agent.verifier import (
    DEFAULT_VERIFIER_TIMEOUT_S,
    FixtureVerifier,
    VerifierResult,
)

__all__ = [
    "DEFAULT_TOOL_TIMEOUT_S",
    "DEFAULT_VERIFIER_TIMEOUT_S",
    "EditStep",
    "FixtureAgent",
    "FixtureRunResult",
    "FixtureTask",
    "FixtureVerifier",
    "ReadStep",
    "RunTestsStep",
    "SKILL_ARTIFACT_KIND",
    "ShellStep",
    "Skill",
    "Step",
    "ToolError",
    "ToolObservation",
    "VerifierResult",
    "WorkspaceTools",
]

"""The fixture coding agent: a scripted tool loop instrumented through the adapter SDK.

H1 of Phase 4 (PRD §17.1 steps 1–2). This package is deliberately *not* a
model-backed agent: like the eval plane's ``ScriptedAgent``, every decision is
scripted, so an assertion about the trace is an assertion about the
instrumentation, not about a model's mood. What is real is everything around
the decisions — the tool loop executes against a real sandbox workspace, the
events flow through ``evoruntime.sdk`` as-is, and the outcome is attested by
an external verifier that runs the fixture's executable tests.

Why ``src/evoruntime/fixture_agent/`` and not ``examples/``: the verifying
tests (integration, overhead, crash-flush) import this package, the uv build
backend only packages ``src/``, and later deliverables (H7 transfer fixtures,
H8 threshold harnesses, H10 brokered model access) import it as the named
§17.3 workload. An examples directory would force path hacks into every one
of those callers.

Event conventions — the six-type event vocabulary stays closed (the survey's
recommendation over new event types):

* prompt versions ride ``model.completed``'s details body as
  ``prompt_version``. ``Trace.model_call`` fixes its details body to
  provider/model, so the agent emits the enriched event through
  ``Adapter.offer`` — the SDK's public capture path — with the same event
  type, model info, and cost a ``model_call`` would carry.
* the issue, repository state, and patch are referenced by ``sha256:``
  digests in ``tool.completed`` details; the bytes live in the sandbox
  workspace. Payload *registration* (storing bytes behind the digest) is H2 —
  this package emits digests only and invents no parallel store.
* retrieved skills use ``Trace.artifact_loaded`` as-is, which also binds the
  digest into the envelope's ``artifact_digests``.
* the claimed outcome uses ``Trace.claim_outcome`` as-is — untrusted by
  construction; the authoritative result comes from
  :mod:`evoruntime.fixture_agent.verifier`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from evoruntime.core.events import CostInfo
from evoruntime.fixture_agent.tools import ToolObservation, WorkspaceTools
from evoruntime.lineage.payload_store import digest_for
from evoruntime.sdk.adapter import EVENT_MODEL_COMPLETED, Adapter, Trace
from evoruntime.sdk.records import PendingEvent

SKILL_ARTIFACT_KIND = "skill_package"


@dataclass(frozen=True, slots=True)
class ReadStep:
    """Read a workspace file."""

    path: str


@dataclass(frozen=True, slots=True)
class EditStep:
    """Apply one text replacement to a workspace file."""

    path: str
    old: str
    new: str


@dataclass(frozen=True, slots=True)
class RunTestsStep:
    """Run the workspace's executable tests."""

    argv: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ShellStep:
    """Run one shell command inside the workspace."""

    argv: tuple[str, ...]


Step = ReadStep | EditStep | RunTestsStep | ShellStep


@dataclass(frozen=True, slots=True)
class Skill:
    """A retrieved skill the agent loaded into context."""

    name: str
    content: str


@dataclass(frozen=True, slots=True)
class FixtureTask:
    """One scripted task: the issue, what retrieval returned, and the plan."""

    task_id: str
    issue: str
    skills: tuple[Skill, ...] = ()
    plan: tuple[Step, ...] = ()


@dataclass(frozen=True, slots=True)
class FixtureRunResult:
    """What one agent run produced, as the trace references it."""

    trace_id: str
    task_id: str
    patch_digest: str | None
    steps_ok: bool
    claimed_success: bool


class FixtureAgent:
    """A scripted tool loop instrumented through the adapter SDK.

    The loop's shape is a real coding agent's: per step, one model call
    followed by the tool action it decided on, with every observation recorded
    by digest. The *decisions* are scripted per task, which is what makes the
    fixture deterministic enough to verify.
    """

    def __init__(
        self,
        adapter: Adapter,
        workspace_root: Path,
        *,
        prompt_version: str,
        step_cost: CostInfo,
    ) -> None:
        self._adapter = adapter
        self._tools = WorkspaceTools(workspace_root)
        self._prompt_version = prompt_version
        self._step_cost = step_cost

    def run(self, task: FixtureTask) -> FixtureRunResult:
        """Execute the task's plan inside the workspace, emitting one trace."""
        with self._adapter.trace(task.task_id) as trace:
            self.record_context(trace, task)
            steps_ok = True
            patch_digest: str | None = None
            patch_args: list[bytes] = []
            for step in task.plan:
                observation = self.execute_step(step)
                self.record_step(trace, step, observation)
                steps_ok = steps_ok and observation.ok
                if isinstance(step, EditStep) and observation.ok:
                    patch_args.append(observation.args)
                    # The patch payload is the patched file's content; the
                    # digest references it without storing it (H2 registers).
                    patch_digest = observation.result_digest
            if patch_digest is not None:
                trace.tool_call(
                    name="repo_patch",
                    args_digest=digest_for(b"\n".join(patch_args)),
                    result_digest=patch_digest,
                )
            trace.claim_outcome(success=steps_ok)
        return FixtureRunResult(
            trace_id=trace.id,
            task_id=task.task_id,
            patch_digest=patch_digest,
            steps_ok=steps_ok,
            claimed_success=steps_ok,
        )

    def record_context(self, trace: Trace, task: FixtureTask) -> None:
        """Record the issue, repository state, and retrieved skills.

        §17.1 step 2: the adapter records the issue and repository state.
        Both are referenced by digest over their exact bytes — the issue text
        as given, and a manifest of every workspace file with its content
        digest, so the repository state the run started from is pinned.
        """
        trace.tool_call(
            name="read_issue",
            args_digest=digest_for(task.task_id.encode("utf-8")),
            result_digest=digest_for(task.issue.encode("utf-8")),
        )
        trace.tool_call(
            name="read_repo_state",
            args_digest=digest_for(task.task_id.encode("utf-8")),
            result_digest=digest_for(self._repo_state()),
        )
        for skill in task.skills:
            trace.artifact_loaded(
                digest=digest_for(skill.content.encode("utf-8")), kind=SKILL_ARTIFACT_KIND
            )

    def execute_step(self, step: Step) -> ToolObservation:
        """Run one step's tool action — the workload the overhead harness measures."""
        if isinstance(step, ReadStep):
            return self._tools.read(step.path)
        if isinstance(step, EditStep):
            return self._tools.edit(step.path, step.old, step.new)
        if isinstance(step, RunTestsStep):
            return self._tools.run_tests(step.argv)
        if isinstance(step, ShellStep):
            return self._tools.shell(step.argv)
        raise AssertionError(f"unhandled step kind: {type(step).__name__}")  # pragma: no cover

    def record_step(self, trace: Trace, step: Step, observation: ToolObservation) -> None:
        """Record one completed step: the model call that decided it, then the tool call."""
        del step  # the plan step shaped the decision; the observation is what is recorded
        self._record_model_call(trace)
        trace.tool_call(
            name=observation.name,
            args_digest=observation.args_digest,
            result_digest=observation.result_digest,
            ok=observation.ok,
        )

    def _record_model_call(self, trace: Trace) -> None:
        """Emit the step's model call with the prompt version in its details body.

        ``Trace.model_call`` fixes its details body to provider/model, and the
        six-type vocabulary is closed, so the prompt version rides the same
        ``model.completed`` event through ``Adapter.offer`` — the survey's
        recommended details convention, not a new event type.
        """
        model = self._adapter.model
        self._adapter.offer(
            PendingEvent(
                occurred_at=datetime.now(UTC),
                trace_id=trace.id,
                task_id=trace.task_id,
                type=EVENT_MODEL_COMPLETED,
                model=model,
                cost=self._step_cost,
                artifact_digests=(),
                details={
                    "provider": model.provider,
                    "model": model.name,
                    "prompt_version": self._prompt_version,
                },
            )
        )

    def _repo_state(self) -> bytes:
        """A deterministic manifest of the workspace: path and content digest per file."""
        lines = []
        for path in sorted(self._tools.root.rglob("*")):
            if path.is_file():
                rel = path.relative_to(self._tools.root).as_posix()
                lines.append(f"{rel} {digest_for(path.read_bytes())}")
        return "\n".join(lines).encode("utf-8")


__all__ = [
    "EditStep",
    "FixtureAgent",
    "FixtureRunResult",
    "FixtureTask",
    "ReadStep",
    "SKILL_ARTIFACT_KIND",
    "RunTestsStep",
    "ShellStep",
    "Skill",
    "Step",
]

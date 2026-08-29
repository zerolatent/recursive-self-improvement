"""H1 acceptance: §17.1 steps 1–2 real end-to-end — issue → trace → patch → attested outcome.

The scenario is a complete miniature of the reference workflow's first two
steps: an issue arrives, a fixture agent executes a tool loop inside a
sandbox workspace (read the issue, read the code, patch it, run the tests),
every datum §17.1 step 2 names lands in the trace through the adapter SDK
as-is, and an external verifier — a separate identity, a separate key — runs
the fixture's executable tests and signs the authoritative outcome.

The transport fails every delivery on purpose: the flush worker only compacts
journal records it has acknowledged, so an unreachable ingest leaves the
run's envelopes *and* detail bodies (tool names, digests, prompt versions)
readable in the journal after `adapter.close()` — the assertions below read
what the agent actually recorded, not a re-derivation of it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from evoruntime.core.events import CostInfo
from evoruntime.fixture_agent import (
    EditStep,
    FixtureAgent,
    FixtureTask,
    FixtureVerifier,
    ReadStep,
    RunTestsStep,
    Skill,
)
from evoruntime.lineage.payload_store import digest_for
from evoruntime.sdk.adapter import (
    EVENT_ARTIFACT_LOADED,
    EVENT_MODEL_COMPLETED,
    EVENT_OUTCOME_CLAIMED,
    EVENT_TOOL_COMPLETED,
    EVENT_TRACE_ENDED,
    EVENT_TRACE_STARTED,
    Adapter,
)
from evoruntime.sdk.journal import JournalRecord, recover
from evoruntime.sdk.transport import TransportError
from evoruntime.security.identities import WorkloadIdentity, WorkloadRole
from evoruntime.security.policy import PermissionDeniedError
from evoruntime.security.signing import generate_signing_key
from tests.sdk.support import MODEL, make_adapter

TASK_ID = "tsk_h1fixture01"
PROMPT_VERSION = "fixture-prompt-v1"
STEP_COST = CostInfo(input_tokens=1200, output_tokens=340, usd=0.0021)

BUGGY_APP = "def add(a, b):\n    return a - b\n"
PATCHED_APP = "def add(a, b):\n    return a + b\n"
TEST_FILE = "from app import add\n\ndef test_add():\n    assert add(2, 2) == 4\n"
ISSUE_TEXT = "add(2, 2) returns 0; the arithmetic operator is inverted.\n"
SKILL_TEXT = "An inverted arithmetic operator is fixed by swapping subtraction for addition."
TEST_ARGV = (sys.executable, "-m", "pytest", "-q", "tests")
TEST_PATHS = ("tests/test_app.py",)

EVALUATOR = WorkloadIdentity(subject="svc_evaluator", role=WorkloadRole.EVALUATOR)
CANDIDATE = WorkloadIdentity(subject="agt_candidate", role=WorkloadRole.CANDIDATE_RUNNER)


class RaisingTransport:
    """Fails every delivery, so nothing is ever acknowledged.

    The flush worker retries and backs off, and the journal keeps every
    record — envelope and detail body — for the assertions to inspect.
    """

    def send(self, envelopes: object) -> object:
        raise TransportError("ingest unreachable (simulated)")

    def close(self) -> None:
        return None


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "workspace"
    (root / "tests").mkdir(parents=True)
    (root / "skills").mkdir()
    (root / "ISSUE.md").write_text(ISSUE_TEXT)
    (root / "app.py").write_text(BUGGY_APP)
    (root / "tests" / "test_app.py").write_text(TEST_FILE)
    (root / "skills" / "fix-arithmetic.md").write_text(SKILL_TEXT)
    return root


def make_task() -> FixtureTask:
    skill = Skill(name="fix-arithmetic", content=SKILL_TEXT)
    return FixtureTask(
        task_id=TASK_ID,
        issue=ISSUE_TEXT,
        skills=(skill,),
        plan=(
            ReadStep(path="ISSUE.md"),
            ReadStep(path="app.py"),
            EditStep(path="app.py", old="return a - b", new="return a + b"),
            RunTestsStep(argv=TEST_ARGV),
        ),
    )


def run_agent(workspace: Path, tmp_path: Path) -> tuple[FixtureAgent, Adapter, Path]:
    adapter = make_adapter(tmp_path, RaisingTransport())
    agent = FixtureAgent(adapter, workspace, prompt_version=PROMPT_VERSION, step_cost=STEP_COST)
    return agent, adapter, tmp_path / "events.journal"


def journaled_records(journal_path: Path) -> tuple[JournalRecord, ...]:
    """Everything the run recorded, in emit order."""
    return recover(journal_path).records


def detail_bodies(journal_path: Path, event_type: str) -> list[dict[str, object]]:
    """The detail bodies the run journaled for one event type, in emit order."""
    return [
        json.loads(record.payload_body)
        for record in journaled_records(journal_path)
        if record.envelope.type == event_type
    ]


def test_issue_to_attested_outcome_end_to_end(workspace: Path, tmp_path: Path) -> None:
    agent, adapter, journal_path = run_agent(workspace, tmp_path)
    task = make_task()
    evaluator_key = generate_signing_key()
    verifier = FixtureVerifier(identity=EVALUATOR, private_key=evaluator_key)

    result = agent.run(task)
    adapter.close(timeout_s=0.5)

    # The agent process runs as a candidate — never as the evaluator.
    assert adapter.identity.role == WorkloadRole.CANDIDATE_RUNNER

    # The trace saw the whole workflow: all six event types, started to ended.
    records = journaled_records(journal_path)
    types = [record.envelope.type for record in records]
    assert types[0] == EVENT_TRACE_STARTED
    assert types[-1] == EVENT_TRACE_ENDED
    assert set(types) == {
        EVENT_TRACE_STARTED,
        EVENT_TRACE_ENDED,
        EVENT_MODEL_COMPLETED,
        EVENT_TOOL_COMPLETED,
        EVENT_ARTIFACT_LOADED,
        EVENT_OUTCOME_CLAIMED,
    }

    # Prompt versions ride model.completed's details body (closed vocabulary).
    model_bodies = detail_bodies(journal_path, EVENT_MODEL_COMPLETED)
    assert len(model_bodies) == len(task.plan)
    assert all(body["prompt_version"] == PROMPT_VERSION for body in model_bodies)
    assert all(
        body["provider"] == MODEL.provider and body["model"] == MODEL.name for body in model_bodies
    )

    # The issue and repository state are recorded, digest-referenced.
    tool_bodies = detail_bodies(journal_path, EVENT_TOOL_COMPLETED)
    tool_names = [body["name"] for body in tool_bodies]
    assert tool_names[0] == "read_issue"
    assert tool_names[1] == "read_repo_state"
    assert tool_bodies[0]["result_digest"] == digest_for(ISSUE_TEXT.encode("utf-8"))

    # The retrieved skill is bound into the envelope's artifact_digests.
    artifact_events = [
        record.envelope for record in records if record.envelope.type == EVENT_ARTIFACT_LOADED
    ]
    assert len(artifact_events) == 1
    assert artifact_events[0].artifact_digests == (digest_for(SKILL_TEXT.encode("utf-8")),)

    # The patch is a digest-referenced payload: the digest over the patched
    # file's bytes, emitted by the repo_patch tool call — no parallel store.
    assert result.patch_digest == digest_for(PATCHED_APP.encode("utf-8"))
    patch_calls = [body for body in tool_bodies if body["name"] == "repo_patch"]
    assert len(patch_calls) == 1
    assert patch_calls[0]["result_digest"] == result.patch_digest

    # The claimed outcome exists — and is only a claim.
    assert any(record.envelope.type == EVENT_OUTCOME_CLAIMED for record in records)
    assert result.claimed_success is True

    # The external verifier runs the fixture's tests itself and signs.
    verifier_result = verifier.run_tests(workspace, TEST_ARGV)
    assert verifier_result.passed
    attestation = verifier.attest(
        trace_id=result.trace_id,
        task_set_digest=verifier.task_set_digest(task),
        evaluator_bundle_digest=verifier.evaluator_bundle_digest(workspace, TEST_PATHS),
        result=verifier_result,
    )
    assert attestation.trace_id == result.trace_id
    assert attestation.raw_result_digest == verifier_result.raw_result_digest
    assert attestation.verify(expected_public_key=evaluator_key.public_key().public_bytes_raw())


def test_a_tampered_result_digest_breaks_the_attestation(workspace: Path, tmp_path: Path) -> None:
    """The attestation binds the exact result bytes — a retold result fails."""
    agent, adapter, _journal = run_agent(workspace, tmp_path)
    task = make_task()
    evaluator_key = generate_signing_key()
    verifier = FixtureVerifier(identity=EVALUATOR, private_key=evaluator_key)

    result = agent.run(task)
    adapter.close(timeout_s=0.5)

    verifier_result = verifier.run_tests(workspace, TEST_ARGV)
    attestation = verifier.attest(
        trace_id=result.trace_id,
        task_set_digest=verifier.task_set_digest(task),
        evaluator_bundle_digest=verifier.evaluator_bundle_digest(workspace, TEST_PATHS),
        result=verifier_result,
    )

    forged = attestation.model_copy(update={"raw_result_digest": digest_for(b"all tests passed")})
    assert forged.verify() is False
    assert forged.verify(expected_public_key=evaluator_key.public_key().public_bytes_raw()) is False


def test_the_candidate_identity_cannot_sign_the_outcome(workspace: Path, tmp_path: Path) -> None:
    """The agent's own role cannot produce the authoritative result, key or no key."""
    agent, adapter, _journal = run_agent(workspace, tmp_path)
    task = make_task()
    result = agent.run(task)
    adapter.close(timeout_s=0.5)

    verifier_result = FixtureVerifier(
        identity=EVALUATOR, private_key=generate_signing_key()
    ).run_tests(workspace, TEST_ARGV)
    candidate_verifier = FixtureVerifier(identity=CANDIDATE, private_key=generate_signing_key())

    with pytest.raises(PermissionDeniedError):
        candidate_verifier.attest(
            trace_id=result.trace_id,
            task_set_digest=candidate_verifier.task_set_digest(task),
            evaluator_bundle_digest=candidate_verifier.evaluator_bundle_digest(
                workspace, TEST_PATHS
            ),
            result=verifier_result,
        )


def test_failing_tests_produce_a_failed_claim(workspace: Path, tmp_path: Path) -> None:
    """A plan that does not fix the bug claims failure, and the verifier agrees."""
    agent, adapter, _journal = run_agent(workspace, tmp_path)
    task = FixtureTask(
        task_id=TASK_ID,
        issue=ISSUE_TEXT,
        plan=(ReadStep(path="app.py"), RunTestsStep(argv=TEST_ARGV)),
    )
    result = agent.run(task)
    adapter.close(timeout_s=0.5)

    assert result.patch_digest is None
    assert result.claimed_success is False

    verifier = FixtureVerifier(identity=EVALUATOR, private_key=generate_signing_key())
    verifier_result = verifier.run_tests(workspace, TEST_ARGV)
    assert verifier_result.passed is False

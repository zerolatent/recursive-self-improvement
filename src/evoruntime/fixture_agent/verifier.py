"""The external verifier: runs the fixture's tests, signs the authoritative outcome.

§17.1 step 2 closes with an external verifier: the agent's ``claim_outcome``
is untrusted by construction, so the result a campaign may act on comes from
a process that is *not* the agent — one that runs the fixture's executable
tests itself, hashes the raw output, and signs an
:class:`~evoruntime.sdk.attestation.OutcomeAttestation` with a key the
candidate identity cannot reach.

The trust boundary is enforced where the SDK already enforces it:
:meth:`OutcomeAttestation.sign` runs ``require_evaluator_key_access`` on the
presented identity even when a key object is supplied, so a verifier
constructed with the agent's candidate-runner identity fails closed, and
:meth:`OutcomeAttestation.verify` with ``expected_public_key`` pins the
evaluator's published key so a release controller never has to trust the key
carried inside the record.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evoruntime.fixture_agent.agent import (
    EditStep,
    FixtureTask,
    ReadStep,
    RunTestsStep,
    ShellStep,
    Step,
)
from evoruntime.lineage.payload_store import digest_for
from evoruntime.sdk.attestation import OutcomeAttestation
from evoruntime.security.identities import WorkloadIdentity

DEFAULT_VERIFIER_TIMEOUT_S = 120.0


@dataclass(frozen=True, slots=True)
class VerifierResult:
    """The verifier's own observation of one test run."""

    argv: tuple[str, ...]
    returncode: int
    output: bytes
    raw_result_digest: str

    @property
    def passed(self) -> bool:
        return self.returncode == 0


def _step_to_json(step: Step) -> dict[str, object]:
    """One step as canonical JSON data, so a task set digest covers the plan."""
    if isinstance(step, ReadStep):
        return {"kind": "read", "path": step.path}
    if isinstance(step, EditStep):
        return {"kind": "edit", "path": step.path, "old": step.old, "new": step.new}
    if isinstance(step, RunTestsStep):
        return {"kind": "test", "argv": list(step.argv)}
    if isinstance(step, ShellStep):
        return {"kind": "shell", "argv": list(step.argv)}
    raise AssertionError(f"unhandled step kind: {type(step).__name__}")  # pragma: no cover


class FixtureVerifier:
    """Runs the fixture's executable tests as the evaluator and attests the result."""

    def __init__(self, *, identity: WorkloadIdentity, private_key: Ed25519PrivateKey) -> None:
        self._identity = identity
        self._private_key = private_key

    def run_tests(
        self,
        workspace_root: Path,
        argv: Sequence[str],
        *,
        timeout_s: float = DEFAULT_VERIFIER_TIMEOUT_S,
    ) -> VerifierResult:
        """Run the fixture's tests in the workspace and hash the raw output.

        The digest is over the exact combined stdout+stderr bytes — the
        attestation binds the *raw* result, not a summarized verdict, so any
        retelling of the output changes the digest and breaks the signature.
        """
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            list(argv),
            cwd=workspace_root,
            capture_output=True,
            timeout=timeout_s,
            check=False,
        )
        output = proc.stdout + proc.stderr
        return VerifierResult(
            argv=tuple(argv),
            returncode=proc.returncode,
            output=output,
            raw_result_digest=digest_for(output),
        )

    def task_set_digest(self, task: FixtureTask) -> str:
        """Digest over which tasks were attempted — the issue and the plan."""
        body = json.dumps(
            {"issue": task.issue, "plan": [_step_to_json(step) for step in task.plan]},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return digest_for(body)

    def evaluator_bundle_digest(self, workspace_root: Path, test_paths: Sequence[str]) -> str:
        """Digest over the grader: the exact test files the verifier executes.

        A weakened grader is one way a result could be misrepresented; binding
        the test files' bytes into the attestation makes the swap detectable.
        """
        root = Path(workspace_root)
        parts: list[bytes] = []
        for rel in test_paths:
            parts.append(rel.encode("utf-8"))
            parts.append((root / rel).read_bytes())
        return digest_for(b"\x00".join(parts))

    def attest(
        self,
        *,
        trace_id: str,
        task_set_digest: str,
        evaluator_bundle_digest: str,
        result: VerifierResult,
    ) -> OutcomeAttestation:
        """Sign the authoritative outcome for one trace.

        Raises:
            evoruntime.security.policy.PermissionDeniedError: the identity is
                not the evaluator role — the gate runs inside
                ``OutcomeAttestation.sign`` even though the key is supplied
                directly, so a candidate-runner identity cannot sign.
        """
        return OutcomeAttestation.sign(
            identity=self._identity,
            private_key=self._private_key,
            trace_id=trace_id,
            task_set_digest=task_set_digest,
            evaluator_bundle_digest=evaluator_bundle_digest,
            raw_result_digest=result.raw_result_digest,
        )

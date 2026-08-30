"""Sandboxed workspace tools for the fixture coding agent.

The fixture agent's tool loop runs against a real directory — the F1 sandbox
workspace — and every tool here is jailed to that directory's root: a path is
resolved and required to stay inside the workspace before any I/O happens,
the same defense `StagedWorkspace` applies to staged payloads. A tool that
could read or write outside the workspace would make the trace's digests
reference content the evaluation plane cannot attribute to the run.

Tools never raise on *observed* failure (a missing file, a failing test
command) — they return an observation with ``ok=False`` and the error as the
result bytes, because a tool failure is data the agent records in its trace.
They raise only when the call itself is invalid (a jail escape), which is a
bug in the caller, not a workload event.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from evoruntime.lineage.payload_store import digest_for

DEFAULT_TOOL_TIMEOUT_S = 30.0


class ToolError(RuntimeError):
    """A tool call was invalid before any work happened (e.g. a jail escape)."""


@dataclass(frozen=True, slots=True)
class ToolObservation:
    """What one tool call did, as bytes and a verdict.

    Arguments and results are carried as bytes so their digests — the only
    thing that reaches the trace — are computed over exactly what the tool
    consumed and produced.
    """

    name: str
    args: bytes
    result: bytes
    ok: bool

    @property
    def args_digest(self) -> str:
        return digest_for(self.args)

    @property
    def result_digest(self) -> str:
        return digest_for(self.result)


class WorkspaceTools:
    """Read/edit/shell/test tools jailed to one workspace root."""

    def __init__(self, root: Path, *, timeout_s: float = DEFAULT_TOOL_TIMEOUT_S) -> None:
        self._root = root.resolve()
        self._timeout_s = timeout_s

    @property
    def root(self) -> Path:
        return self._root

    def read(self, rel_path: str) -> ToolObservation:
        """Read a file inside the workspace."""
        args = rel_path.encode("utf-8")
        try:
            path = self._resolve(rel_path)
            content = path.read_bytes()
        except (OSError, ToolError) as exc:
            return ToolObservation(name="read", args=args, result=str(exc).encode(), ok=False)
        return ToolObservation(name="read", args=args, result=content, ok=True)

    def edit(self, rel_path: str, old: str, new: str) -> ToolObservation:
        """Replace the first occurrence of ``old`` in a workspace file.

        The result bytes are the *patched file's* content, so the digest the
        agent records for an edit is the digest of the file state the edit
        produced — the thing a verifier would re-run tests against.
        """
        args = f"{rel_path}: {old!r} -> {new!r}".encode()
        try:
            path = self._resolve(rel_path)
            content = path.read_text()
        except (OSError, ToolError, UnicodeDecodeError) as exc:
            return ToolObservation(name="edit", args=args, result=str(exc).encode(), ok=False)
        if old not in content:
            return ToolObservation(
                name="edit", args=args, result=b"anchor text not found", ok=False
            )
        path.write_text(content.replace(old, new, 1))
        return ToolObservation(name="edit", args=args, result=path.read_bytes(), ok=True)

    def shell(self, argv: Sequence[str]) -> ToolObservation:
        """Run a command with the workspace as its working directory."""
        return self._run("shell", argv)

    def run_tests(self, argv: Sequence[str]) -> ToolObservation:
        """Run the workspace's executable tests."""
        return self._run("test", argv)

    def _run(self, name: str, argv: Sequence[str]) -> ToolObservation:
        args = json.dumps(list(argv)).encode("utf-8")
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
                list(argv),
                cwd=self._root,
                capture_output=True,
                timeout=self._timeout_s,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return ToolObservation(name=name, args=args, result=str(exc).encode(), ok=False)
        output = proc.stdout + proc.stderr
        return ToolObservation(name=name, args=args, result=output, ok=proc.returncode == 0)

    def _resolve(self, rel_path: str) -> Path:
        candidate = (self._root / rel_path).resolve()
        if not candidate.is_relative_to(self._root):
            raise ToolError(f"path {rel_path!r} escapes the workspace root")
        return candidate

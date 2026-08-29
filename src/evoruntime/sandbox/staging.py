"""Filesystem staging from the E1 payload store.

The IsolationBackend protocol owns "filesystem staging from the E1 payload
store": candidate bytes never travel to the sandbox by path or by reference —
they are read from the encrypted, content-addressed payload store, verified
against their declared digest, and written into a fresh private workspace
that becomes the candidate's working directory. Digest verification on the
way in means the bytes that execute are provably the bytes that were
proposed.

The mirror operation, :meth:`StagedWorkspace.capture`, closes the loop after
a mutate-stage run: the mutated workspace's declared outputs are extracted
digest-verified before teardown, so the bytes the harness registers (and a
later run executes) are provably the bytes the mutation produced — proposed
bytes = executed bytes = registered bytes.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Protocol

from evoruntime.lineage.payload_store import digest_for
from evoruntime.sandbox.profile import (
    CapturedPayload,
    CaptureError,
    PayloadRef,
    StagingError,
    _validate_workspace_relative_path,
)


class PayloadReader(Protocol):
    """What the sandbox needs from the E1 payload store.

    :class:`evoruntime.lineage.payload_store.PayloadStore` satisfies this;
    the narrow protocol keeps the sandbox plane decoupled from SQLAlchemy
    and makes staging unit-testable without a database.
    """

    def read(self, *, tenant_id: str, payload_digest: str) -> bytes: ...


class StagedWorkspace:
    """A fresh private directory holding the candidate's staged bytes."""

    def __init__(self, root: Path) -> None:
        self._root = root

    @property
    def root(self) -> Path:
        return self._root

    @classmethod
    def stage(
        cls, payloads: tuple[PayloadRef, ...], *, reader: PayloadReader, tenant_id: str
    ) -> StagedWorkspace:
        """Create a fresh workspace and stage every payload into it.

        Digest-verified on the way in: bytes whose content does not hash to
        their declared digest abort the run before anything executes.
        """
        root = Path(tempfile.mkdtemp(prefix="evoruntime-sandbox-"))
        workspace = cls(root)
        try:
            (root / "tmp").mkdir()
            for ref in payloads:
                workspace._stage_one(ref, reader=reader, tenant_id=tenant_id)
        except BaseException:
            workspace.cleanup()
            raise
        return workspace

    def _stage_one(self, ref: PayloadRef, *, reader: PayloadReader, tenant_id: str) -> None:
        try:
            data = reader.read(tenant_id=tenant_id, payload_digest=ref.digest)
        except KeyError as exc:
            # The store is content-addressed, so a missing digest means the
            # reference is broken or tampered — abort before anything runs.
            raise StagingError(
                f"no payload stored under declared digest {ref.digest!r} for {ref.path!r}"
            ) from exc
        if digest_for(data) != ref.digest:
            raise StagingError(
                f"payload for {ref.path!r} does not hash to its declared digest {ref.digest!r}"
            )
        target = (self._root / ref.path).resolve()
        # Defense in depth on top of PayloadRef's path-shape validation: a
        # staged path must resolve inside the workspace, never outside it.
        if not target.is_relative_to(self._root.resolve()):
            raise StagingError(f"payload path {ref.path!r} escapes the workspace root")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    def ensure_dirs(self, rel_paths: tuple[str, ...] | list[str]) -> None:
        """Create workspace-relative directories (e.g. declared write zones).

        Zones must exist before Landlock rules can be attached to them at
        spawn; creating them here keeps the declared workspace layout part
        of staging rather than a side effect of execution.
        """
        for rel in rel_paths:
            _validate_workspace_relative_path(rel, what="workspace directory")
            target = (self._root / rel).resolve()
            if not target.is_relative_to(self._root.resolve()):
                raise StagingError(f"workspace directory {rel!r} escapes the workspace root")
            target.mkdir(parents=True, exist_ok=True)

    def capture(self, paths: tuple[str, ...] | list[str]) -> tuple[CapturedPayload, ...]:
        """Extract the declared files from the mutated workspace, digest-verified.

        Symmetric with :meth:`stage`: every path is shape-validated and
        resolved inside the workspace (a symlink pointing outside is
        refused), the bytes are read back, and the digest is computed over
        the exact bytes returned — the captured payload self-verifies on the
        way out the way a staged payload verifies on the way in.
        """
        captured: list[CapturedPayload] = []
        for rel in paths:
            captured.append(self._capture_one(rel))
        return tuple(captured)

    def _capture_one(self, rel: str) -> CapturedPayload:
        try:
            _validate_workspace_relative_path(rel, what="capture path")
        except ValueError as exc:
            raise CaptureError(str(exc)) from exc
        target = (self._root / rel).resolve()
        if not target.is_relative_to(self._root.resolve()):
            raise CaptureError(f"capture path {rel!r} escapes the workspace root")
        if not target.is_file():
            raise CaptureError(
                f"capture path {rel!r} is not a regular file in the mutated workspace"
            )
        content = target.read_bytes()
        return CapturedPayload(path=rel, digest=digest_for(content), content=content)

    def cleanup(self) -> None:
        shutil.rmtree(self._root, ignore_errors=True)

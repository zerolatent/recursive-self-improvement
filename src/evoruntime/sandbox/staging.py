"""Filesystem staging from the E1 payload store.

The IsolationBackend protocol owns "filesystem staging from the E1 payload
store": candidate bytes never travel to the sandbox by path or by reference —
they are read from the encrypted, content-addressed payload store, verified
against their declared digest, and written into a fresh private workspace
that becomes the candidate's working directory. Digest verification on the
way in means the bytes that execute are provably the bytes that were
proposed.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Protocol

from evoruntime.lineage.payload_store import digest_for
from evoruntime.sandbox.profile import PayloadRef, StagingError


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

    def cleanup(self) -> None:
        shutil.rmtree(self._root, ignore_errors=True)

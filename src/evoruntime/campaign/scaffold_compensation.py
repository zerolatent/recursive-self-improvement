"""Scaffold compensation execution (Phase 3, G8) — the rollback half of
destructive-operation testing.

A scaffold campaign mutates the agent's whole source tree, so a rollback
has to undo a *tree*, not a pointer move. Two scaffold-specific
compensating actions (declared in
:class:`~evoruntime.campaign.compensation.CompensationActionKind`) do
that, and this module executes them:

- **``restore_scaffold_source`` (CAS).** The incumbent scaffold's file
  map pins every member module's digest, and the registry re-verifies
  digests on every read, so restoring the source is a content-addressed
  swap: read each pinned module out of the registry, write it into the
  working tree, and re-hash what was written. :class:`ScaffoldSourceRestorer`
  performs exactly that walk and refuses on any mismatch — the restore's
  evidence is intrinsic (the digest verification it performs), which is
  why the action classifies as CAS and needs no execution record.
- **``rerun_conformance_suite`` (requires-execution).**
  :class:`ConformanceRerunExecutor` resolves the scaffold's *own* pinned
  conformance suite from its file map — the pin travels with the
  candidate, so the compensation cannot be pointed at a different oracle
  than the one the candidate was judged by — and re-runs it through the
  G2 zero-regression interpretation
  (:class:`~evoruntime.eval.conformance.SelfEditConformanceEvaluator`).
  A suite that fails, times out, or cannot be parsed raises
  :class:`~evoruntime.campaign.errors.ConformanceRerunFailedError`, which
  aborts the compensation walk: the plan stays undischarged and the
  promotion check keeps refusing.

Ordering is the plan's declared order. The generic walk
(:func:`~evoruntime.campaign.compensation.execute_rollback_compensations`)
skips CAS actions — for the pointer kinds the controller's rollback
covers them, and for ``restore_scaffold_source`` the orchestrator's
rollback path invokes :class:`ScaffoldSourceRestorer` directly, in the
plan's declared position, before the requires-execution walk runs. The
severity-1 drill (``tests/release/test_scaffold_severity1_drill.py``)
pins that order end to end.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from evoruntime.campaign.compensation import CompensationActionKind
from evoruntime.campaign.errors import ConformanceRerunFailedError, ScaffoldRestoreError
from evoruntime.eval.conformance import (
    SelfEditConformanceEvaluator,
    run_self_edit_conformance,
)
from evoruntime.plugins.scaffold import (
    ScaffoldFileMap,
    module_digest,
    scaffold_digest,
)


class ScaffoldRegistryReader(Protocol):
    """What the restore and the rerun need from the registry.

    Structural on purpose: :class:`~evoruntime.registry.service.RegistryService`
    satisfies it unchanged, and this module stays importable from the
    campaign package without a DB-layer dependency. The registry's
    verify-on-read contract is load-bearing — every digest check the
    restore relies on happens inside ``read_artifact``.
    """

    def read_artifact(self, *, tenant_id: str, digest: str) -> bytes: ...


@dataclass(frozen=True, slots=True)
class RestoredModule:
    """One member module the restore wrote back, with its verified pin."""

    path: str
    digest: str


@dataclass(frozen=True, slots=True)
class ScaffoldRestoreRecord:
    """Evidence of one CAS scaffold-source restore.

    The record is a *report*, not the proof: the proof is that every
    listed module's bytes re-hashed to their pinned digest on the way
    out of the registry and again after the write. The record exists so
    the rollback log can name what was restored.
    """

    scaffold_digest: str
    modules: tuple[RestoredModule, ...]


class ScaffoldSourceRestorer:
    """CAS-style restore of a scaffold's source tree from the registry.

    Constructed with a registry reader and a tenant; :meth:`restore`
    materializes one scaffold artifact's pinned member modules into a
    working tree. Every step verifies a digest:

    1. the file map parsed from the registry bytes must re-hash to the
       scaffold digest being restored (the G1 round-trip property);
    2. each member module's registry bytes must hash to the module
       digest the file map pins (the registry re-verifies on read —
       this is the CAS compare);
    3. the content written to the tree must re-hash to the same module
       digest after the write (the CAS swap landed).

    Any mismatch raises :class:`~evoruntime.campaign.errors.ScaffoldRestoreError`
    — a restore that cannot prove what it wrote does not discharge a
    rollback, it hides a corruption.
    """

    def __init__(self, *, reader: ScaffoldRegistryReader, tenant_id: str) -> None:
        self._reader = reader
        self._tenant_id = tenant_id

    def restore(self, *, scaffold_digest: str, tree_root: Path) -> ScaffoldRestoreRecord:
        """Restore ``scaffold_digest``'s member modules into ``tree_root``.

        Idempotent by construction: restoring the same digest twice
        writes the same bytes. Raises:
            ScaffoldRestoreError: the file map does not re-hash to the
                scaffold digest, a pinned module does not resolve, or the
                written bytes do not re-hash to their pin.
        """
        file_map = _load_verified_file_map(self._reader, self._tenant_id, scaffold_digest)
        restored: list[RestoredModule] = []
        for module in file_map.modules:
            module_bytes = self._reader.read_artifact(
                tenant_id=self._tenant_id, digest=module.digest
            )
            content = _module_content_from_canonical_bytes(module_bytes, module.path)
            target = tree_root / module.path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            # The CAS swap is only discharged when the bytes on disk
            # re-hash to the pin — a truncated or re-encoded write is a
            # failed restore, not a best effort.
            written = target.read_text(encoding="utf-8")
            if module_digest(module.path, written) != module.digest:
                raise ScaffoldRestoreError(
                    f"restored module {module.path!r} does not re-hash to its pinned "
                    f"digest {module.digest!r} after the write — refusing to report "
                    "a restore that did not land"
                )
            restored.append(RestoredModule(path=module.path, digest=module.digest))
        return ScaffoldRestoreRecord(scaffold_digest=scaffold_digest, modules=tuple(restored))

    def _load_file_map(self, scaffold_digest_value: str) -> ScaffoldFileMap:
        """Read and re-verify the scaffold's file map from the registry."""
        return _load_verified_file_map(self._reader, self._tenant_id, scaffold_digest_value)


def _module_content_from_canonical_bytes(body: bytes, path: str) -> str:
    """Extract one member module's source from its registry canonical bytes.

    The canonical bytes are the registry's JSON body binding path and
    content; a body whose path disagrees with the pin being restored is
    a cross-wired restore and is refused.
    """
    try:
        payload = json.loads(body)
        content = payload["content"]
        body_path = payload["path"]
    except (KeyError, TypeError, ValueError) as exc:
        raise ScaffoldRestoreError(
            f"module artifact for {path!r} is not a parseable module body: {exc}"
        ) from exc
    if not isinstance(content, str) or body_path != path:
        raise ScaffoldRestoreError(
            f"module artifact pinned as {path!r} carries path {body_path!r} — "
            "refusing a cross-wired restore"
        )
    return content


class ConformanceRerunExecutor:
    """Executes the ``rerun_conformance_suite`` compensation (G8).

    A :class:`~evoruntime.campaign.compensation.CompensationExecutor`
    for scaffold rollback plans: it resolves the scaffold's pinned
    conformance suite from the registry file map named by the action's
    ``artifact_digest`` and re-runs it through the G2 evaluator's
    zero-regression interpretation, so the discharge check inherits
    every fail-closed path (timeout, no exit, unparseable summary, zero
    tests collected) instead of re-implementing them.

    The runner receives the digest-pinned suite reference as the command;
    materializing that reference into an actual in-sandbox invocation is
    the runner's contract (the sandbox stages the pinned suite by
    digest), exactly as the stage-0 cascade evaluator delegates its run.

    Fail-closed on dispatch too: an action this executor cannot name is
    a wiring bug, and executing nothing quietly would discharge a plan
    that was never carried out.
    """

    def __init__(
        self,
        *,
        reader: ScaffoldRegistryReader,
        tenant_id: str,
        runner: Any,
    ) -> None:
        self._reader = reader
        self._tenant_id = tenant_id
        self._runner = runner

    def execute(self, action_index: int, action: Mapping[str, Any]) -> None:
        """Run one declared compensation. Raises on failure."""
        action_name = str(action.get("action", ""))
        if action_name != CompensationActionKind.RERUN_CONFORMANCE_SUITE.value:
            raise ConformanceRerunFailedError(
                f"compensation action #{action_index} ({action_name!r}) is not a "
                "rerun_conformance_suite action — the conformance rerun executor "
                "refuses actions it cannot execute"
            )
        scaffold_digest_value = str(action.get("artifact_digest", ""))
        file_map = _load_verified_file_map(self._reader, self._tenant_id, scaffold_digest_value)
        evaluator = SelfEditConformanceEvaluator(
            suite_command=(file_map.conformance_suite,),
            runner=self._runner,
        )
        _, outcome = run_self_edit_conformance(evaluator)
        if not outcome.passed:
            raise ConformanceRerunFailedError(
                f"conformance rerun for scaffold {scaffold_digest_value!r} did not "
                f"prove zero regressions (metrics: {dict(outcome.metrics)}) — the "
                "rollback plan stays undischarged"
            )


def _load_verified_file_map(
    reader: ScaffoldRegistryReader, tenant_id: str, scaffold_digest_value: str
) -> ScaffoldFileMap:
    """Read and re-verify a scaffold file map (shared by both executors)."""
    body = reader.read_artifact(tenant_id=tenant_id, digest=scaffold_digest_value)
    try:
        file_map = ScaffoldFileMap.model_validate_json(body)
    except ValueError as exc:
        raise ScaffoldRestoreError(
            f"artifact {scaffold_digest_value!r} is not a parseable scaffold file map: {exc}"
        ) from exc
    if scaffold_digest(file_map) != scaffold_digest_value:
        raise ScaffoldRestoreError(
            f"artifact {scaffold_digest_value!r} re-hashes to "
            f"{scaffold_digest(file_map)!r} from its stored file map — refusing to "
            "compensate against bytes that do not match their content address"
        )
    return file_map


__all__ = [
    "ConformanceRerunExecutor",
    "RestoredModule",
    "ScaffoldRegistryReader",
    "ScaffoldRestoreRecord",
    "ScaffoldSourceRestorer",
]

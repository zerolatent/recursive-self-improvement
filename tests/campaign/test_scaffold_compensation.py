"""G8 acceptance: scaffold-specific compensation actions.

The destructive-operation rollback contract, at the campaign plane:

- **Spec authoring** — ``restore_scaffold_source`` (CAS) and
  ``rerun_conformance_suite`` (requires-execution) are valid only against
  the scaffold class, and only while the scaffold sits in the campaign's
  mutable set (``CampaignSpec._validate_compensation_plan``). The pair is
  the one allowed duplicate-class plan, and the restore must precede the
  rerun — rerunning the oracle against a tree that has not been restored
  judges nothing.
- **CAS restore** — :class:`ScaffoldSourceRestorer` restores the
  incumbent's digest-pinned member modules from the registry and refuses
  any restore it cannot prove (file map that does not re-hash, cross-wired
  module body, written bytes that do not re-hash to their pin).
- **Conformance rerun** — :class:`ConformanceRerunExecutor` resolves the
  scaffold's *own* pinned suite from the registry file map and re-runs it
  through the G2 zero-regression interpretation, failing closed on
  regressions, timeouts, and unparseable output alike.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from evoruntime.campaign.compensation import (
    CAS_MODE,
    REQUIRES_EXECUTION_MODE,
    plan_actions_from_spec,
)
from evoruntime.campaign.errors import (
    ConformanceRerunFailedError,
    InvalidCampaignSpecError,
    ScaffoldRestoreError,
)
from evoruntime.campaign.scaffold_compensation import (
    ConformanceRerunExecutor,
    ScaffoldSourceRestorer,
)
from evoruntime.campaign.spec import (
    CampaignSpec,
    CompensationActionSpec,
    CompensationPlanSection,
)
from evoruntime.eval.conformance import SuiteRunResult
from evoruntime.plugins.scaffold import (
    module_canonical_bytes,
    module_digest,
    scaffold_canonical_bytes,
    scaffold_digest,
    scaffold_file_map_from_sources,
)
from tests.campaign.conftest import make_spec_mapping

_SOURCES = {
    "src/agent/__init__.py": "",
    "src/agent/planner.py": "def plan(): ...",
    "src/agent/tools.py": "def tool(): ...",
}
_ENTRYPOINTS = ("src/agent/__init__.py",)
_SUITE = "conformance/self-edit@sha256:" + "2b" * 32


# -- spec authoring -----------------------------------------------------------


def _scaffold_spec_mapping(compensation_plan: dict[str, Any]) -> dict[str, Any]:
    """A v2 spec whose mutable set contains the scaffold class — the shape
    a Phase 3 scaffold campaign pins."""
    mapping = make_spec_mapping()
    mapping["schema_version"] = 2
    # The incumbent's class must appear exactly once (the primary mutable
    # artifact); the scaffold rides alongside it as the mutable target.
    mapping["mutable_artifacts"] = [
        {"artifact_type": "prompt_bundle", "paths": ["prompts/system.md"]},
        {"artifact_type": "scaffold", "paths": ["src/agent/planner.py"]},
    ]
    mapping["compensation_plan"] = compensation_plan
    return CampaignSpec.from_mapping(mapping)


def test_scaffold_rollback_pair_is_a_valid_plan() -> None:
    """The G8 pair is the one allowed duplicate-class plan: restore the
    source, then re-verify the oracle — declared order is execution order."""
    spec = _scaffold_spec_mapping(
        {
            "actions": [
                {"artifact_type": "scaffold", "action": "restore_scaffold_source"},
                {"artifact_type": "scaffold", "action": "rerun_conformance_suite"},
            ]
        }
    )
    plan = spec.compensation_plan
    assert plan is not None
    assert [action.action for action in plan.actions] == [
        "restore_scaffold_source",
        "rerun_conformance_suite",
    ]
    # Canonical form round-trips byte-identically through from_mapping.
    reparsed = CampaignSpec.from_mapping(spec.to_canonical_dict())
    assert reparsed.canonical_bytes() == spec.canonical_bytes()


def test_scaffold_actions_refused_against_other_artifact_classes() -> None:
    """Scaffold-specific compensations name the scaffold class: a restore
    or a rerun targeting any other class is a spec-authoring refusal."""
    with pytest.raises(InvalidCampaignSpecError, match="restore_scaffold_source"):
        CompensationActionSpec(artifact_type="prompt_bundle", action="restore_scaffold_source")
    with pytest.raises(InvalidCampaignSpecError, match="rerun_conformance_suite"):
        CompensationActionSpec(artifact_type="workflow_graph", action="rerun_conformance_suite")


def test_conformance_rerun_takes_no_hook_image() -> None:
    """The suite pin travels with the scaffold's file map; a second pin in
    the action could drift from the oracle the candidate was judged by."""
    with pytest.raises(InvalidCampaignSpecError, match="takes no hook_image"):
        CompensationActionSpec(
            artifact_type="scaffold",
            action="rerun_conformance_suite",
            hook_image="ghcr.io/evoruntime/suite@sha256:" + "e" * 64,
        )


def test_scaffold_actions_require_scaffold_in_the_mutable_set() -> None:
    """Valid only because the scaffold sits in the mutable set, per
    ``_validate_compensation_plan`` — a campaign can only compensate what
    it mutates."""
    mapping = make_spec_mapping()
    mapping["schema_version"] = 2
    mapping["mutable_artifacts"] = [
        {"artifact_type": "prompt_bundle", "paths": ["prompts/system.md"]},
    ]
    mapping["compensation_plan"] = {
        "actions": [{"artifact_type": "scaffold", "action": "restore_scaffold_source"}]
    }
    with pytest.raises(InvalidCampaignSpecError, match="not.*in the mutable artifact set"):
        CampaignSpec.from_mapping(mapping)


def test_scaffold_rollback_order_is_enforced() -> None:
    """The rerun must follow the restore in declared order."""
    with pytest.raises(InvalidCampaignSpecError, match="must follow the source restore"):
        CompensationPlanSection(
            actions=(
                CompensationActionSpec(artifact_type="scaffold", action="rerun_conformance_suite"),
                CompensationActionSpec(artifact_type="scaffold", action="restore_scaffold_source"),
            )
        )


def test_scaffold_plan_actions_resolve_with_derived_modes() -> None:
    """plan_actions_from_spec classifies the restore as CAS and the rerun
    as requires-execution, both against the scaffold's resolved digest."""
    spec = _scaffold_spec_mapping(
        {
            "actions": [
                {"artifact_type": "scaffold", "action": "restore_scaffold_source"},
                {"artifact_type": "scaffold", "action": "rerun_conformance_suite"},
            ]
        }
    )
    file_map = scaffold_file_map_from_sources(
        _SOURCES, entrypoints=_ENTRYPOINTS, conformance_suite=_SUITE
    )
    actions = plan_actions_from_spec(
        spec.compensation_plan.actions, {"scaffold": scaffold_digest(file_map)}
    )
    assert [action["mode"] for action in actions] == [CAS_MODE, REQUIRES_EXECUTION_MODE]
    assert {action["artifact_digest"] for action in actions} == {scaffold_digest(file_map)}


# -- CAS restore ----------------------------------------------------------------


class _FakeRegistryReader:
    """In-memory stand-in for RegistryService.read_artifact: digest-keyed
    bytes, no verification (the tamper tests below supply bad bytes)."""

    def __init__(self, blobs: dict[str, bytes]) -> None:
        self._blobs = blobs

    def read_artifact(self, *, tenant_id: str, digest: str) -> bytes:
        return self._blobs[digest]


def _registry_blobs() -> tuple[dict[str, bytes], Any]:
    """Digest-keyed registry blobs for the fixture scaffold: the file map
    under the scaffold digest, each member module's canonical bytes under
    its module digest."""
    file_map = scaffold_file_map_from_sources(
        _SOURCES, entrypoints=_ENTRYPOINTS, conformance_suite=_SUITE
    )
    blobs: dict[str, bytes] = {scaffold_digest(file_map): scaffold_canonical_bytes(file_map)}
    for path, content in _SOURCES.items():
        blobs[module_digest(path, content)] = module_canonical_bytes(path, content)
    return blobs, file_map


def test_restore_recovers_destructively_mutated_source(tmp_path: Path) -> None:
    """After a destructive mutation corrupts the working tree, the CAS
    restore writes back every pinned module and the written bytes re-hash
    to their pins."""
    blobs, file_map = _registry_blobs()
    restorer = ScaffoldSourceRestorer(reader=_FakeRegistryReader(blobs), tenant_id="t1")

    # The destructive mutation: the candidate rewrote the planner and
    # deleted the tools module from the tree.
    (tmp_path / "src" / "agent").mkdir(parents=True)
    (tmp_path / "src" / "agent" / "planner.py").write_text("import os; os.system('rm -rf /')")
    (tmp_path / "src" / "agent" / "tools.py").unlink(missing_ok=True)

    record = restorer.restore(scaffold_digest=scaffold_digest(file_map), tree_root=tmp_path)

    assert record.scaffold_digest == scaffold_digest(file_map)
    assert {module.path for module in record.modules} == set(_SOURCES)
    for path, content in _SOURCES.items():
        assert (tmp_path / path).read_text(encoding="utf-8") == content


def test_restore_is_idempotent(tmp_path: Path) -> None:
    blobs, file_map = _registry_blobs()
    restorer = ScaffoldSourceRestorer(reader=_FakeRegistryReader(blobs), tenant_id="t1")
    digest = scaffold_digest(file_map)
    first = restorer.restore(scaffold_digest=digest, tree_root=tmp_path)
    second = restorer.restore(scaffold_digest=digest, tree_root=tmp_path)
    assert first == second


def test_restore_refuses_file_map_that_does_not_rehash(tmp_path: Path) -> None:
    """A scaffold artifact whose stored file map no longer hashes to its
    content address is corruption — the restore refuses, it does not
    materialize unverified bytes."""
    blobs, file_map = _registry_blobs()
    digest = scaffold_digest(file_map)
    # Splice a different suite pin under the original content address.
    tampered = scaffold_file_map_from_sources(
        _SOURCES,
        entrypoints=_ENTRYPOINTS,
        conformance_suite="conformance/other@sha256:" + "9" * 64,
    )
    blobs[digest] = scaffold_canonical_bytes(tampered)
    restorer = ScaffoldSourceRestorer(reader=_FakeRegistryReader(blobs), tenant_id="t1")
    with pytest.raises(ScaffoldRestoreError, match="do not match their content address"):
        restorer.restore(scaffold_digest=digest, tree_root=tmp_path)


def test_restore_refuses_cross_wired_module_body(tmp_path: Path) -> None:
    """A module artifact whose canonical body names a different path is a
    cross-wired restore — refused, not written."""
    blobs, file_map = _registry_blobs()
    digest = scaffold_digest(file_map)
    victim = file_map.modules[0]
    blobs[victim.digest] = module_canonical_bytes("src/other.py", "def other(): ...")
    restorer = ScaffoldSourceRestorer(reader=_FakeRegistryReader(blobs), tenant_id="t1")
    with pytest.raises(ScaffoldRestoreError, match="cross-wired"):
        restorer.restore(scaffold_digest=digest, tree_root=tmp_path)


# -- conformance rerun ------------------------------------------------------------


class _ScriptedSuiteRunner:
    """Returns a canned suite result and records the command it was asked
    to run — the drill uses the recording to prove the rerun executed
    against restored source."""

    def __init__(self, result: SuiteRunResult) -> None:
        self.result = result
        self.commands: list[tuple[str, ...]] = []

    def run(self, command: tuple[str, ...]) -> SuiteRunResult:
        self.commands.append(command)
        return self.result


def _rerun_action(file_map: Any) -> dict[str, Any]:
    return {
        "artifact_digest": scaffold_digest(file_map),
        "action": "rerun_conformance_suite",
        "mode": REQUIRES_EXECUTION_MODE,
        "executed": False,
    }


def test_conformance_rerun_passes_on_green_suite() -> None:
    blobs, file_map = _registry_blobs()
    runner = _ScriptedSuiteRunner(SuiteRunResult(returncode=0, stdout="118 passed in 2.31s"))
    executor = ConformanceRerunExecutor(
        reader=_FakeRegistryReader(blobs), tenant_id="t1", runner=runner
    )
    executor.execute(1, _rerun_action(file_map))
    # The suite command is the scaffold's own pinned reference — the pin
    # travels with the candidate, not with the compensation.
    assert runner.commands == [(file_map.conformance_suite,)]


def test_conformance_rerun_fails_closed_on_regressions() -> None:
    blobs, file_map = _registry_blobs()
    runner = _ScriptedSuiteRunner(
        SuiteRunResult(returncode=1, stdout="1 failed, 117 passed in 2.31s")
    )
    executor = ConformanceRerunExecutor(
        reader=_FakeRegistryReader(blobs), tenant_id="t1", runner=runner
    )
    with pytest.raises(ConformanceRerunFailedError, match="zero regressions"):
        executor.execute(1, _rerun_action(file_map))


def test_conformance_rerun_fails_closed_on_unparseable_output() -> None:
    """A suite that cannot prove zero regressions is a failure, not a
    pass — the G2 fail-closed semantics carry into the compensation."""
    blobs, file_map = _registry_blobs()
    runner = _ScriptedSuiteRunner(SuiteRunResult(returncode=None, timed_out=True))
    executor = ConformanceRerunExecutor(
        reader=_FakeRegistryReader(blobs), tenant_id="t1", runner=runner
    )
    with pytest.raises(ConformanceRerunFailedError, match="zero regressions"):
        executor.execute(1, _rerun_action(file_map))


def test_conformance_rerun_refuses_actions_it_cannot_execute() -> None:
    blobs, file_map = _registry_blobs()
    runner = _ScriptedSuiteRunner(SuiteRunResult(returncode=0, stdout="1 passed in 0.01s"))
    executor = ConformanceRerunExecutor(
        reader=_FakeRegistryReader(blobs), tenant_id="t1", runner=runner
    )
    with pytest.raises(ConformanceRerunFailedError, match="refuses actions"):
        executor.execute(
            0, {"artifact_digest": scaffold_digest(file_map), "action": "revoke_artifact"}
        )


def test_module_canonical_bytes_round_trip() -> None:
    """The restore parses module content out of the registry's canonical
    bytes — the same bytes :func:`module_digest` hashes."""
    body = module_canonical_bytes("src/agent/planner.py", "def plan(): ...")
    payload = json.loads(body)
    assert payload == {"content": "def plan(): ...", "path": "src/agent/planner.py"}

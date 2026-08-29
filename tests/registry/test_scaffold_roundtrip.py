"""G1 acceptance: a scaffold candidate registers, digests, and traces like
any artifact.

The round-trip contract: member modules register as their own artifacts;
the scaffold artifact registers over its file-map canonical bytes with the
member-module digests as registry dependency edges; the claimed digest is
verified on write and re-verified on every read; and mutation lineage —
the parent edge and the composite member edge — rides the existing
``ProposalRecord.parent_digest`` / ``ProposalMemberRecord`` machinery with
no new lineage code. Requires PostgreSQL (skipped otherwise, like the rest
of the registry suite).
"""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from evoruntime.db.models.registry import ProposalMemberRecord, ProposalRecord
from evoruntime.plugins.composite import composite_canonical_bytes, composite_digest
from evoruntime.plugins.protocol import ProposalMember
from evoruntime.plugins.scaffold import (
    ScaffoldFileMap,
    module_canonical_bytes,
    scaffold_canonical_bytes,
    scaffold_digest,
    scaffold_file_map_from_sources,
)
from evoruntime.registry.errors import ArtifactNotFoundError, DigestMismatchError
from evoruntime.registry.service import RegistryService

_SOURCES = {
    "src/agent/__init__.py": "",
    "src/agent/planner.py": "def plan(): ...",
    "src/agent/tools.py": "def tool(): ...",
}
_ENTRYPOINTS = ("src/agent/__init__.py",)
_SUITE = "conformance/self-edit@sha256:" + "2b" * 32


def _file_map() -> ScaffoldFileMap:
    return scaffold_file_map_from_sources(
        _SOURCES, entrypoints=_ENTRYPOINTS, conformance_suite=_SUITE
    )


def _register_scaffold(
    service: RegistryService,
    tenant_id: str,
    file_map: ScaffoldFileMap,
    sources: dict[str, str] | None = None,
) -> object:
    """Register the member modules, then the scaffold over the file map —
    the exact flow a Phase 3 campaign's registration path runs."""
    sources = sources if sources is not None else _SOURCES
    for module in file_map.modules:
        artifact = service.register_artifact(
            tenant_id=tenant_id,
            artifact_type="scaffold",
            canonical_bytes=module_canonical_bytes(module.path, sources[module.path]),
        )
        assert artifact.digest == module.digest, "module pin must equal the registered digest"
    return service.register_artifact(
        tenant_id=tenant_id,
        artifact_type="scaffold",
        canonical_bytes=scaffold_canonical_bytes(file_map),
        dependencies=list(file_map.module_digests()),
        expected_digest=scaffold_digest(file_map),
    )


def test_scaffold_registers_with_member_modules_as_dependency_edges(
    registry_service: RegistryService, registry_tenant: str
) -> None:
    file_map = _file_map()
    scaffold = _register_scaffold(registry_service, registry_tenant, file_map)

    # The claimed digest was verified on write (expected_digest matched)
    # and the member modules are real dependency edges, not strings.
    assert scaffold.digest == scaffold_digest(file_map)  # type: ignore[attr-defined]
    assert list(scaffold.dependencies) == list(file_map.module_digests())  # type: ignore[attr-defined]
    for module in file_map.modules:
        registry_service.get_artifact(tenant_id=registry_tenant, digest=module.digest)


def test_scaffold_read_back_reverifies_digest(
    registry_service: RegistryService, registry_tenant: str
) -> None:
    """The registered bytes re-hash to the recorded digest on read, and
    the file map re-parsed from those bytes recomputes the same content
    address — proposed bytes = registered bytes."""
    file_map = _file_map()
    scaffold = _register_scaffold(registry_service, registry_tenant, file_map)
    digest: str = scaffold.digest  # type: ignore[attr-defined]

    body = registry_service.read_artifact(tenant_id=registry_tenant, digest=digest)
    assert body == scaffold_canonical_bytes(file_map)
    reparsed = ScaffoldFileMap.model_validate_json(body)
    assert scaffold_digest(reparsed) == digest


def test_scaffold_digest_mismatch_is_refused(
    registry_service: RegistryService, registry_tenant: str
) -> None:
    """A caller claiming a digest the file map doesn't hash to is refused
    — nothing is stored (FR-003)."""
    file_map = _file_map()
    for module in file_map.modules:
        registry_service.register_artifact(
            tenant_id=registry_tenant,
            artifact_type="scaffold",
            canonical_bytes=module_canonical_bytes(module.path, _SOURCES[module.path]),
        )
    with pytest.raises(DigestMismatchError):
        registry_service.register_artifact(
            tenant_id=registry_tenant,
            artifact_type="scaffold",
            canonical_bytes=scaffold_canonical_bytes(file_map),
            dependencies=list(file_map.module_digests()),
            expected_digest="sha256:" + "ff" * 32,
        )


def test_scaffold_with_unregistered_module_is_refused(
    registry_service: RegistryService, registry_tenant: str
) -> None:
    """A dependency edge to a module that was never registered is refused
    — lineage edges must be real edges."""
    file_map = _file_map()
    with pytest.raises(ArtifactNotFoundError):
        registry_service.register_artifact(
            tenant_id=registry_tenant,
            artifact_type="scaffold",
            canonical_bytes=scaffold_canonical_bytes(file_map),
            dependencies=list(file_map.module_digests()),
        )


def test_scaffold_mutation_lineage_rides_existing_proposal_edges(
    registry_service: RegistryService,
    registry_tenant: str,
    db_session: Session,
) -> None:
    """Generation 0 registers; a mutated candidate proposes with
    ``parent_digest`` pointing at it (ProposalRecord edge), and a
    composite proposal carries the scaffold as a typed member
    (ProposalMemberRecord edge) — no new lineage machinery."""
    incumbent_map = _file_map()
    incumbent = _register_scaffold(registry_service, registry_tenant, incumbent_map)
    incumbent_digest: str = incumbent.digest  # type: ignore[attr-defined]

    mutated_sources = dict(_SOURCES, **{"src/agent/planner.py": "def plan(): return 42"})
    mutated_map = scaffold_file_map_from_sources(
        mutated_sources, entrypoints=_ENTRYPOINTS, conformance_suite=_SUITE
    )
    mutated = _register_scaffold(
        registry_service, registry_tenant, mutated_map, sources=mutated_sources
    )
    mutated_digest: str = mutated.digest  # type: ignore[attr-defined]
    assert mutated_digest != incumbent_digest

    proposal = registry_service.record_proposal(
        tenant_id=registry_tenant,
        proposed_digest=mutated_digest,
        strategy_id="strat_harness_mutator",
        parent_digest=incumbent_digest,
    )
    assert proposal.parent_digest == incumbent_digest
    assert proposal.proposed_digest == mutated_digest

    # A composite proposal's digest is computed over its ordered member
    # set (the plugins layer owns that digest), so the proposed digest is
    # the composite address — distinct from the member's own digest.
    member = ProposalMember(artifact_type="scaffold", patch={}, declared_executables=())
    composite_digest_value = composite_digest([member], artifact_type="scaffold")
    registry_service.register_artifact(
        tenant_id=registry_tenant,
        artifact_type="scaffold",
        canonical_bytes=composite_canonical_bytes([member]),
        expected_digest=composite_digest_value,
    )
    composite = registry_service.record_composite_proposal(
        tenant_id=registry_tenant,
        proposed_digest=composite_digest_value,
        strategy_id="strat_harness_mutator",
        members=[
            {
                "artifact_type": "scaffold",
                "member_digest": mutated_digest,
                "parent_digest": incumbent_digest,
                "patch": {},
                "declared_executables": [],
            }
        ],
    )
    members = (
        db_session.execute(
            select(ProposalMemberRecord).where(
                ProposalMemberRecord.proposal_id == composite.proposal_id
            )
        )
        .scalars()
        .all()
    )
    assert len(members) == 1
    assert members[0].artifact_type == "scaffold"
    assert members[0].member_digest == mutated_digest
    assert members[0].parent_digest == incumbent_digest

    # The parent edge is queryable through the proposal table itself.
    rows = (
        db_session.execute(
            select(ProposalRecord).where(ProposalRecord.proposal_id == proposal.proposal_id)
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1 and rows[0].parent_digest == incumbent_digest

"""G5: digest-verified capture and layered Landlock write zoning.

The mutate → execute-mutated → capture loop is orchestrated by the harness
as two ``run()`` calls: the mutate stage writes the mutated scaffold into
its declared write zone, the backend captures it digest-verified before
teardown, the harness registers the captured bytes, and the next run stages
them back — proposed bytes = executed bytes = registered bytes.

The write-zone corpus proves the physical half: with ``writable_paths``
declared, a write outside the zone is a kernel ``EACCES`` (the run fails
and the attestation records the zoning), not a convention the candidate is
asked to honor.
"""

from __future__ import annotations

import pytest

from evoruntime.core.isolation import IsolationTier
from evoruntime.plugins.manifest import NetworkMode, ResourceLimits
from evoruntime.plugins.protocol import InMemoryCheckpointStore
from evoruntime.sandbox.executor import (
    SubprocessIsolationBackend,
    physical_enforcement_available,
)
from evoruntime.sandbox.profile import ExecutionProfile
from evoruntime.sandbox.staging import StagedWorkspace
from tests.sandbox.support import (
    TENANT,
    DictPayloadReader,
    assert_attestation_roundtrips,
    digest_of,
    make_payload,
    make_request,
)

pytestmark = pytest.mark.skipif(
    not physical_enforcement_available(),
    reason="sandbox executor requires seccomp + Landlock (Linux)",
)

TINY_LIMITS = ResourceLimits(
    wall_clock_minutes=1.0, cpu=1.0, memory_gib=0.05, model_tokens=0, proposals=1
)


def zoned_profile(*zones: str) -> ExecutionProfile:
    return ExecutionProfile(
        tier=IsolationTier.EXECUTABLE,
        network_mode=NetworkMode.NONE,
        resource_limits=TINY_LIMITS,
        writable_paths=tuple(zones),
    )


def run_python(
    code: str,
    checkpoints: InMemoryCheckpointStore,
    *,
    profile: ExecutionProfile,
    capture_paths: tuple[str, ...] = (),
):
    data = code.encode("utf-8")
    ref = make_payload("candidate.py", data)
    backend = SubprocessIsolationBackend(
        payloads=DictPayloadReader({ref.digest: data}), checkpoints=checkpoints
    )
    request = make_request(
        profile=profile,
        payloads=(ref,),
        command=("python3", "candidate.py"),
        capture_paths=capture_paths,
    )
    return backend.run(request)


class TestCaptureRoundTrip:
    def test_captured_bytes_hash_to_their_declared_digest(self) -> None:
        workspace = StagedWorkspace.stage((), reader=DictPayloadReader({}), tenant_id=TENANT)
        try:
            mutated = b"def evolved():\n    return 41 + 1\n"
            (workspace.root / "out").mkdir()
            (workspace.root / "out" / "scaffold.py").write_bytes(mutated)
            (captured,) = workspace.capture(("out/scaffold.py",))
            assert captured.path == "out/scaffold.py"
            assert captured.content == mutated
            assert captured.digest == digest_of(mutated)
        finally:
            workspace.cleanup()

    def test_capture_restages_to_the_same_digest(self) -> None:
        """Symmetry: stage → mutate → capture → re-stage reproduces the digest."""
        original = b"scaffold v1\n"
        ref = make_payload("scaffold.py", original)
        workspace = StagedWorkspace.stage(
            (ref,), reader=DictPayloadReader({ref.digest: original}), tenant_id=TENANT
        )
        try:
            mutated = b"scaffold v2 - mutated\n"
            (workspace.root / "out").mkdir()
            (workspace.root / "out" / "scaffold.py").write_bytes(mutated)
            (captured,) = workspace.capture(("out/scaffold.py",))

            restaged = StagedWorkspace.stage(
                (make_payload(captured.path, captured.content),),
                reader=DictPayloadReader({captured.digest: captured.content}),
                tenant_id=TENANT,
            )
            try:
                assert (restaged.root / captured.path).read_bytes() == mutated
                assert digest_of((restaged.root / captured.path).read_bytes()) == captured.digest
            finally:
                restaged.cleanup()
        finally:
            workspace.cleanup()

    def test_capture_refuses_missing_file(self) -> None:
        from evoruntime.sandbox.profile import CaptureError

        workspace = StagedWorkspace.stage((), reader=DictPayloadReader({}), tenant_id=TENANT)
        try:
            with pytest.raises(CaptureError, match="not a regular file"):
                workspace.capture(("absent.py",))
        finally:
            workspace.cleanup()

    def test_capture_refuses_traversal_and_symlink_escape(self) -> None:
        from evoruntime.sandbox.profile import CaptureError

        workspace = StagedWorkspace.stage((), reader=DictPayloadReader({}), tenant_id=TENANT)
        try:
            with pytest.raises(CaptureError, match="traversal-free"):
                workspace.capture(("../escape.py",))
            outside = workspace.root.parent / "outside-secret.txt"
            outside.write_bytes(b"secret")
            (workspace.root / "link.py").symlink_to(outside)
            with pytest.raises(CaptureError, match="escapes the workspace root"):
                workspace.capture(("link.py",))
        finally:
            workspace.cleanup()

    def test_end_to_end_two_run_harness_flow(self, checkpoints: InMemoryCheckpointStore) -> None:
        """Run 1 mutates and captures; run 2 executes exactly those bytes."""
        mutator = (
            "from pathlib import Path\n"
            "Path('out').mkdir(exist_ok=True)\n"
            "Path('scratch').mkdir(exist_ok=True)\n"
            "Path('out/scaffold.py').write_bytes(b'MUTATED_SCAFFOLD_BYTES')\n"
            "Path('scratch/notes.txt').write_bytes(b'workspace scratch')\n"
        )
        profile = zoned_profile("out", "scratch")
        first = run_python(
            mutator, checkpoints, profile=profile, capture_paths=("out/scaffold.py",)
        )
        assert first.exit_code == 0
        (captured,) = first.captured
        assert captured.digest == digest_of(b"MUTATED_SCAFFOLD_BYTES")
        # The attestation binds the captured digest set into the same record.
        assert [(ref.path, ref.digest) for ref in first.attestation.captured] == [
            (captured.path, captured.digest)
        ]

        # The harness registers the captured bytes; run 2 stages them back
        # digest-verified and executes them.
        backend = SubprocessIsolationBackend(
            payloads=DictPayloadReader({captured.digest: captured.content}),
            checkpoints=checkpoints,
        )
        second = backend.run(
            make_request(
                profile=zoned_profile(),
                payloads=(make_payload("scaffold.py", captured.content),),
                command=(
                    "python3",
                    "-c",
                    "import pathlib; print(pathlib.Path('scaffold.py').read_text())",
                ),
            )
        )
        assert second.exit_code == 0
        assert "MUTATED_SCAFFOLD_BYTES" in second.stdout
        assert_attestation_roundtrips(checkpoints, first)


class TestWriteZoneEscapeCorpus:
    def test_write_outside_zone_is_physically_denied(
        self, checkpoints: InMemoryCheckpointStore
    ) -> None:
        escape = (
            "from pathlib import Path\n"
            "Path('scratch').mkdir(exist_ok=True)\n"
            "try:\n"
            "    Path('tmp/escape.txt').write_text('outside the zone')\n"
            "except PermissionError:\n"
            "    raise SystemExit(3)\n"
            "raise SystemExit(0)\n"
        )
        result = run_python(escape, checkpoints, profile=zoned_profile("scratch"))
        # The kernel denied the write (EACCES → PermissionError) — the run
        # failed and the attestation records that zoning was active.
        assert result.exit_code == 3
        assert result.attestation.enforcement.write_zone_applied is True
        assert result.attestation.enforcement.filesystem_contained is True

    def test_write_inside_zone_succeeds(self, checkpoints: InMemoryCheckpointStore) -> None:
        compliant = (
            "from pathlib import Path\n"
            "Path('scratch').mkdir(exist_ok=True)\n"
            "Path('scratch/ok.txt').write_text('fine')\n"
        )
        result = run_python(compliant, checkpoints, profile=zoned_profile("scratch"))
        assert result.exit_code == 0

    def test_staged_fixture_outside_zone_cannot_be_overwritten(
        self, checkpoints: InMemoryCheckpointStore
    ) -> None:
        """A mutated scaffold cannot overwrite its own evaluation fixtures."""
        fixture = b'{"golden": true}\n'
        fixture_ref = make_payload("fixtures/expected.json", fixture)
        candidate = (
            "from pathlib import Path\n"
            "Path('scratch').mkdir(exist_ok=True)\n"
            "try:\n"
            "    Path('fixtures/expected.json').write_bytes(b'{\"golden\": false}')\n"
            "except PermissionError:\n"
            "    raise SystemExit(3)\n"
            "raise SystemExit(0)\n"
        )
        candidate_ref = make_payload("candidate.py", candidate.encode("utf-8"))
        backend = SubprocessIsolationBackend(
            payloads=DictPayloadReader(
                {fixture_ref.digest: fixture, candidate_ref.digest: candidate.encode("utf-8")}
            ),
            checkpoints=checkpoints,
        )
        request = make_request(
            profile=zoned_profile("scratch"),
            payloads=(fixture_ref, candidate_ref),
            command=("python3", "candidate.py"),
        )
        result = backend.run(request)
        assert result.exit_code == 3

    def test_symlink_through_zone_to_outside_is_denied(
        self, checkpoints: InMemoryCheckpointStore
    ) -> None:
        """A symlink inside the zone must not become a write path out of it."""
        fixture = b'{"golden": true}\n'
        fixture_ref = make_payload("fixtures/expected.json", fixture)
        candidate = (
            "import os\n"
            "os.makedirs('scratch', exist_ok=True)\n"
            "os.symlink('../fixtures/expected.json', 'scratch/link.json')\n"
            "try:\n"
            "    with open('scratch/link.json', 'w') as fh:\n"
            "        fh.write('tampered')\n"
            "except PermissionError:\n"
            "    raise SystemExit(3)\n"
            "raise SystemExit(0)\n"
        )
        candidate_ref = make_payload("candidate.py", candidate.encode("utf-8"))
        backend = SubprocessIsolationBackend(
            payloads=DictPayloadReader(
                {fixture_ref.digest: fixture, candidate_ref.digest: candidate.encode("utf-8")}
            ),
            checkpoints=checkpoints,
        )
        request = make_request(
            profile=zoned_profile("scratch"),
            payloads=(fixture_ref, candidate_ref),
            command=("python3", "candidate.py"),
        )
        result = backend.run(request)
        assert result.exit_code == 3

    def test_unzoned_profile_keeps_whole_workspace_writable(
        self, checkpoints: InMemoryCheckpointStore
    ) -> None:
        """Phase 2 F1 behavior is preserved when no zones are declared."""
        legacy = "from pathlib import Path\nPath('anywhere.txt').write_text('fine')\n"
        result = run_python(legacy, checkpoints, profile=zoned_profile())
        assert result.exit_code == 0
        assert result.attestation.enforcement.write_zone_applied is False


class TestZoneValidation:
    def test_writable_paths_reject_traversal(self) -> None:
        import pydantic

        with pytest.raises(pydantic.ValidationError, match="traversal-free"):
            zoned_profile("../outside")

    def test_capture_paths_reject_absolute_paths(self) -> None:
        import pydantic

        with pytest.raises(pydantic.ValidationError, match="traversal-free"):
            make_request(
                profile=zoned_profile(),
                payloads=(),
                command=("python3", "-c", "pass"),
                capture_paths=("/etc/passwd",),
            )

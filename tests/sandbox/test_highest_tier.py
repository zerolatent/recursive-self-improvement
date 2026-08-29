"""G5: the HIGHEST tier is physically distinct from EXECUTABLE.

Three fixtures prove distinctness in the attestation record itself: the
escalation-primitive syscall denylist is active (kernel ``EPERM`` for
ptrace/mount/keyctl/…), the denylist names are bound into the v2
``EnforcementRecord``, and ``tier_enforcement`` names the backend class
that enforced the run — honest about reference enforcement today, swappable
for a production microVM backend under the same ``IsolationBackend``
protocol.
"""

from __future__ import annotations

import json

import pytest

from evoruntime.core.isolation import IsolationTier
from evoruntime.plugins.manifest import NetworkMode, ResourceLimits
from evoruntime.plugins.protocol import InMemoryCheckpointStore
from evoruntime.sandbox import _seccomp
from evoruntime.sandbox.executor import (
    SubprocessIsolationBackend,
    physical_enforcement_available,
)
from evoruntime.sandbox.profile import (
    ExecutionProfile,
    IsolationUnavailableError,
    TierEnforcement,
)
from tests.sandbox.support import (
    DictPayloadReader,
    assert_attestation_roundtrips,
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


def profile_for(tier: IsolationTier) -> ExecutionProfile:
    return ExecutionProfile(
        tier=tier,
        network_mode=NetworkMode.NONE,
        resource_limits=TINY_LIMITS,
    )


def run_python(
    tier: IsolationTier,
    code: str,
    checkpoints: InMemoryCheckpointStore,
    *,
    allow_privileged_syscalls: bool = False,
):
    data = code.encode("utf-8")
    ref = make_payload("candidate.py", data)
    profile = profile_for(tier).model_copy(
        update={"allow_privileged_syscalls": allow_privileged_syscalls}
    )
    backend = SubprocessIsolationBackend(
        payloads=DictPayloadReader({ref.digest: data}), checkpoints=checkpoints
    )
    return backend.run(
        make_request(profile=profile, payloads=(ref,), command=("python3", "candidate.py"))
    )


class TestHighestDenylist:
    def test_ptrace_is_denied_with_eperm(self, checkpoints: InMemoryCheckpointStore) -> None:
        ptrace = (
            "import ctypes\n"
            "libc = ctypes.CDLL(None, use_errno=True)\n"
            "rc = libc.ptrace(0, 1, None, None)  # PTRACE_TRACEME, pid 1\n"
            "errno = ctypes.get_errno()\n"
            "print(f'rc={rc} errno={errno}')\n"
        )
        result = run_python(IsolationTier.HIGHEST, ptrace, checkpoints)
        assert result.exit_code == 0  # the candidate itself ran fine
        assert "errno=1" in result.stdout  # EPERM from the seccomp filter

    def test_mount_is_denied_with_eperm(self, checkpoints: InMemoryCheckpointStore) -> None:
        mount = (
            "import ctypes\n"
            "libc = ctypes.CDLL(None, use_errno=True)\n"
            "rc = libc.mount(b'none', b'/tmp', b'tmpfs', 0, None)\n"
            "errno = ctypes.get_errno()\n"
            "print(f'rc={rc} errno={errno}')\n"
        )
        result = run_python(IsolationTier.HIGHEST, mount, checkpoints)
        assert result.exit_code == 0
        assert "errno=1" in result.stdout

    def test_keyctl_is_denied_with_eperm(self, checkpoints: InMemoryCheckpointStore) -> None:
        keyctl = (
            "import ctypes\n"
            "libc = ctypes.CDLL(None, use_errno=True)\n"
            "rc = libc.syscall(250, 0, 0, 0, 0, 0)  # __NR_keyctl on x86_64\n"
            "errno = ctypes.get_errno()\n"
            "print(f'rc={rc} errno={errno}')\n"
        )
        result = run_python(IsolationTier.HIGHEST, keyctl, checkpoints)
        assert result.exit_code == 0
        assert "errno=1" in result.stdout

    def test_attestation_binds_the_denylist_names(
        self, checkpoints: InMemoryCheckpointStore
    ) -> None:
        result = run_python(IsolationTier.HIGHEST, "print('ok')", checkpoints)
        enforcement = result.attestation.enforcement
        assert enforcement.syscall_denylist == _seccomp.HIGHEST_DENIED_SYSCALLS
        assert "ptrace" in enforcement.syscall_denylist
        assert "mount" in enforcement.syscall_denylist
        assert "keyctl" in enforcement.syscall_denylist
        assert enforcement.tier_enforcement is TierEnforcement.REFERENCE

    def test_executable_tier_has_no_denylist(self, checkpoints: InMemoryCheckpointStore) -> None:
        """EXECUTABLE stays the Phase 2 tier: no denylist, no ptrace wall."""
        result = run_python(IsolationTier.EXECUTABLE, "print('ok')", checkpoints)
        enforcement = result.attestation.enforcement
        assert enforcement.syscall_denylist == ()
        assert enforcement.write_zone_applied is False
        assert result.attestation.schema_version == 2

    def test_highest_is_distinguishable_from_executable_in_the_record(
        self, checkpoints: InMemoryCheckpointStore
    ) -> None:
        highest = run_python(IsolationTier.HIGHEST, "print('ok')", checkpoints).attestation
        executable = run_python(IsolationTier.EXECUTABLE, "print('ok')", checkpoints).attestation
        assert highest.enforcement.syscall_denylist != executable.enforcement.syscall_denylist
        assert highest.tier == IsolationTier.HIGHEST
        assert executable.tier == IsolationTier.EXECUTABLE

    def test_audited_privileged_opt_out_skips_the_denylist(
        self, checkpoints: InMemoryCheckpointStore
    ) -> None:
        result = run_python(
            IsolationTier.HIGHEST,
            "print('ok')",
            checkpoints,
            allow_privileged_syscalls=True,
        )
        assert result.attestation.enforcement.syscall_denylist == ()

    def test_denylist_program_denies_every_listed_syscall(self) -> None:
        """The compiled BPF program returns EPERM for every listed number."""
        program = _seccomp.build_syscall_denylist_filter(_seccomp.HIGHEST_DENIED_SYSCALLS)
        numbers = _seccomp._denylist_numbers(_seccomp.HIGHEST_DENIED_SYSCALLS)
        # Every denied number must appear in the program's comparison set.
        compared = {insn.k for insn in program if insn.code == _seccomp._BPF_JMP_JEQ_K}
        assert numbers and set(numbers) <= compared


class TestAttestationSchemaV2:
    def test_v2_fields_roundtrip_through_json(self, checkpoints: InMemoryCheckpointStore) -> None:
        result = run_python(IsolationTier.HIGHEST, "print('ok')", checkpoints)
        attestation = result.attestation
        assert attestation.schema_version == 2
        assert attestation.enforcement.tier_enforcement is TierEnforcement.REFERENCE
        restored = type(attestation).model_validate_json(attestation.model_dump_json())
        assert restored == attestation
        assert restored.enforcement.syscall_denylist == attestation.enforcement.syscall_denylist
        assert_attestation_roundtrips(checkpoints, result)

    def test_captured_digests_are_bound_into_the_attestation(
        self, checkpoints: InMemoryCheckpointStore
    ) -> None:
        code = (
            "import os\nos.makedirs('out', exist_ok=True)\nopen('out/mutated.py', 'w').write('x')\n"
        )
        data = code.encode("utf-8")
        ref = make_payload("candidate.py", data)
        backend = SubprocessIsolationBackend(
            payloads=DictPayloadReader({ref.digest: data}), checkpoints=checkpoints
        )
        request = make_request(
            profile=profile_for(IsolationTier.EXECUTABLE),
            payloads=(ref,),
            command=("python3", "candidate.py"),
            capture_paths=("out/mutated.py",),
        )
        result = backend.run(request)
        assert result.exit_code == 0
        (captured,) = result.captured
        assert [(ref.path, ref.digest) for ref in result.attestation.captured] == [
            (captured.path, captured.digest)
        ]
        # The persisted attestation bytes carry the captured digest set.
        stored = json.loads(checkpoints._blobs[result.attestation_digest])
        assert stored["schema_version"] == 2
        assert stored["captured"] == [{"path": captured.path, "digest": captured.digest}]


class TestFailClosed:
    def test_highest_refuses_without_denylist_support(
        self, checkpoints: InMemoryCheckpointStore, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(_seccomp, "syscall_denylist_supported", lambda: False)
        backend = SubprocessIsolationBackend(
            payloads=DictPayloadReader({}), checkpoints=checkpoints
        )
        with pytest.raises(IsolationUnavailableError, match="denylist"):
            backend.run(
                make_request(
                    profile=profile_for(IsolationTier.HIGHEST),
                    payloads=(),
                    command=("python3", "-c", "pass"),
                )
            )

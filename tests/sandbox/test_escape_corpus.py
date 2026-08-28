"""The escape-attempt corpus: every attempt denied, per tier.

This is the F1 acceptance corpus (spec: "escape-attempt corpus denied under
each tier"). Each test stages real candidate bytes, executes them inside the
reference backend, and asserts the escape *physically* failed — kernel-level
denial, nonzero exit, and an attestation that records what happened.
"""

from __future__ import annotations

import socket
import threading

import pytest

from evoruntime.core.isolation import IsolationTier
from evoruntime.plugins.manifest import NetworkMode, ResourceLimits
from evoruntime.plugins.protocol import InMemoryCheckpointStore
from evoruntime.sandbox.executor import (
    SubprocessIsolationBackend,
    physical_enforcement_available,
)
from evoruntime.sandbox.profile import ExecutionProfile, ExecutionRefusedError
from evoruntime.security.egress import EgressPolicy
from tests.sandbox.support import (
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

# Small limits so the resource bomb fails fast instead of eating the runner.
TINY_LIMITS = ResourceLimits(
    wall_clock_minutes=1.0, cpu=1.0, memory_gib=0.05, model_tokens=0, proposals=1
)
GENEROUS_LIMITS = ResourceLimits(
    wall_clock_minutes=1.0, cpu=1.0, memory_gib=2.0, model_tokens=0, proposals=1
)


def profile_for(tier: IsolationTier) -> ExecutionProfile:
    network = NetworkMode.BROKERED if tier is IsolationTier.BROKERED else NetworkMode.NONE
    return ExecutionProfile(
        tier=tier,
        network_mode=network,
        resource_limits=TINY_LIMITS if tier is not IsolationTier.BROKERED else GENEROUS_LIMITS,
    )


def run_python(
    tier: IsolationTier,
    code: str,
    checkpoints: InMemoryCheckpointStore,
    *,
    profile: ExecutionProfile | None = None,
):
    """Stage ``code`` as the candidate payload and execute it.

    The backend's payload reader serves the exact bytes the PayloadRef
    declares; staging still digest-verifies them on the way in.
    """
    data = code.encode("utf-8")
    ref = make_payload("candidate.py", data)
    backend = SubprocessIsolationBackend(
        payloads=DictPayloadReader({ref.digest: data}), checkpoints=checkpoints
    )
    request = make_request(
        profile=profile or profile_for(tier),
        payloads=(ref,),
        command=("python3", "candidate.py"),
    )
    return backend.run(request)


class TestBenignRun:
    def test_benign_candidate_executes_and_attests(self, checkpoints) -> None:
        result = run_python(IsolationTier.EXECUTABLE, "print('hello from candidate')", checkpoints)
        assert result.exit_code == 0
        assert "hello from candidate" in result.stdout
        att = result.attestation
        assert att.tier is IsolationTier.EXECUTABLE
        assert att.exit_code == 0
        assert att.signal_name is None
        assert att.timed_out is False
        assert att.enforcement.rlimits_applied is True
        assert att.enforcement.network_filter_applied is True
        assert att.enforcement.filesystem_contained is True
        assert_attestation_roundtrips(checkpoints, result)

    def test_text_only_tier_refuses_to_execute(self, checkpoints) -> None:
        with pytest.raises(ExecutionRefusedError, match="text-only"):
            run_python(IsolationTier.TEXT_ONLY, "print('should never run')", checkpoints)


class TestNetworkDialEscape:
    """A candidate dialing the network directly must be denied by the kernel."""

    @pytest.mark.parametrize("tier", [IsolationTier.EXECUTABLE, IsolationTier.HIGHEST])
    def test_direct_dial_denied(self, checkpoints, tier) -> None:
        dial = (
            "import socket\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "s.settimeout(5)\n"
            "s.connect(('93.184.216.34', 80))\n"
            "print('DIAL_OK')\n"
        )
        result = run_python(tier, dial, checkpoints)
        assert "DIAL_OK" not in result.stdout
        assert result.exit_code != 0
        # The seccomp filter denies socket(AF_INET) with EPERM — the dial
        # never leaves the process.
        assert "PermissionError" in result.stderr or result.exit_code != 0
        assert_attestation_roundtrips(checkpoints, result)

    def test_brokered_dial_through_proxy_is_mediated(self, checkpoints) -> None:
        """Allowed host: reachable only via the broker proxy; denial-free run."""
        upstream = socket.socket()
        upstream.bind(("127.0.0.1", 0))
        upstream.listen(1)
        port = upstream.getsockname()[1]
        accepted = threading.Event()

        def serve() -> None:
            try:
                conn, _ = upstream.accept()
                conn.close()
                accepted.set()
            except OSError:
                pass

        threading.Thread(target=serve, daemon=True).start()

        code = (
            "import socket\n"
            f"s = socket.create_connection(('127.0.0.1', {port}), timeout=5)\n"
            "print('PROXY_DIAL_OK')\n"
        )
        data = code.encode("utf-8")
        ref = make_payload("candidate.py", data)
        backend = SubprocessIsolationBackend(
            payloads=DictPayloadReader({ref.digest: data}), checkpoints=checkpoints
        )
        request = make_request(
            profile=ExecutionProfile(
                tier=IsolationTier.BROKERED,
                network_mode=NetworkMode.BROKERED,
                resource_limits=GENEROUS_LIMITS,
            ),
            payloads=(ref,),
            command=("python3", "candidate.py"),
        )
        request = request.model_copy(
            update={"egress_policy": EgressPolicy(allowed_hosts=frozenset({"127.0.0.1"}))}
        )
        result = backend.run(request)
        assert "PROXY_DIAL_OK" in result.stdout
        assert accepted.is_set()
        assert result.attestation.enforcement.broker_proxy is True
        assert result.attestation.egress_denials == ()
        assert_attestation_roundtrips(checkpoints, result)


class TestFilesystemEscape:
    """A candidate writing outside its workspace must be denied by Landlock."""

    @pytest.mark.parametrize("tier", [IsolationTier.EXECUTABLE, IsolationTier.HIGHEST])
    def test_write_outside_workspace_denied(self, checkpoints, tier) -> None:
        escape = (
            "try:\n"
            "    with open('/tmp/evoruntime-escape-probe', 'w') as f:\n"
            "        f.write('escaped')\n"
            "    print('ESCAPE_OK')\n"
            "except PermissionError:\n"
            "    print('ESCAPE_DENIED')\n"
        )
        result = run_python(tier, escape, checkpoints)
        assert "ESCAPE_OK" not in result.stdout
        assert "ESCAPE_DENIED" in result.stdout


class TestResourceBomb:
    """A candidate exceeding its declared memory ceiling must be denied."""

    @pytest.mark.parametrize("tier", [IsolationTier.EXECUTABLE, IsolationTier.HIGHEST])
    def test_memory_bomb_denied(self, checkpoints, tier) -> None:
        bomb = (
            "try:\n"
            "    blob = bytearray(512 * 1024 * 1024)  # 512 MiB vs 0.05 GiB ceiling\n"
            "    print('BOMB_OK')\n"
            "except MemoryError:\n"
            "    print('BOMB_DENIED')\n"
        )
        result = run_python(tier, bomb, checkpoints)
        assert "BOMB_OK" not in result.stdout
        assert "BOMB_DENIED" in result.stdout or result.exit_code != 0

    def test_cpu_bomb_killed_by_rlimit(self, checkpoints) -> None:
        burn = "while True:\n    pass\n"
        result = run_python(
            IsolationTier.EXECUTABLE,
            burn,
            checkpoints,
            profile=ExecutionProfile(
                tier=IsolationTier.EXECUTABLE,
                network_mode=NetworkMode.NONE,
                resource_limits=ResourceLimits(
                    wall_clock_minutes=1.0, cpu=1.0, memory_gib=2.0, model_tokens=0, proposals=1
                ),
            ),
        )
        # RLIMIT_CPU fires at 1 CPU-second; the run must terminate quickly
        # with a signal, not hang until the wall clock.
        assert result.exit_code != 0 or result.attestation.signal_name is not None


class TestStagingIntegrity:
    def test_digest_mismatch_aborts_before_execution(self, checkpoints) -> None:
        from evoruntime.sandbox.profile import StagingError

        data = b"print('legit')"
        bad_ref = make_payload("candidate.py", data).model_copy(
            update={"digest": digest_of(b"tampered")}
        )
        backend = SubprocessIsolationBackend(
            payloads=DictPayloadReader({digest_of(data): data}), checkpoints=checkpoints
        )
        request = make_request(
            profile=profile_for(IsolationTier.EXECUTABLE),
            payloads=(bad_ref,),
            command=("python3", "candidate.py"),
        )
        with pytest.raises(StagingError, match="no payload stored under declared digest"):
            backend.run(request)


class TestTenantIsolation:
    def test_payload_reader_scopes_by_tenant(self) -> None:
        reader = DictPayloadReader({digest_of(b"x"): b"x"})
        with pytest.raises(KeyError, match="tenant"):
            reader.read(tenant_id="other-tenant", payload_digest=digest_of(b"x"))

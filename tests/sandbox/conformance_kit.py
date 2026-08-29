"""The H9 isolation-backend conformance kit.

A reusable test kit any :class:`IsolationBackend` must pass — the escape
corpus, capture-zone assertions, and attestation-honesty checks
parameterized over the protocol, so a gVisor/Firecracker backend inherits
the evidence by implementing the contract instead of by copying tests.

The kit is written against the protocol only: it never imports or
isinstance-checks :class:`SubprocessIsolationBackend`. A backend under
test is supplied as a *factory* that receives the scenario's payload
blobs (``digest -> bytes``) and returns a constructed backend wired to the
kit's checkpoint store — staging, capture, and attestation persistence are
composed around the protocol, so the factory is the only backend-specific
code.

Checks (each raises ``AssertionError`` on violation):

1. ``text_only_tier_refuses`` — the TEXT_ONLY tier never executes.
2. ``benign_run_attests`` — a benign candidate runs, and the attestation
   binds exit, tier, and enforcement into a digest-verified record.
3. ``network_dial_denied`` — a direct AF_INET dial on a no-network tier is
   physically denied.
4. ``filesystem_escape_denied`` — a write outside the workspace is
   physically denied.
5. ``memory_bomb_denied`` — a candidate exceeding its declared memory
   ceiling is denied.
6. ``staging_digest_mismatch_aborts`` — declared-vs-stored digest mismatch
   aborts before any byte executes.
7. ``capture_roundtrip_digest_verified`` — mutate → capture → re-stage
   reproduces the digest (proposed = executed = registered bytes).
8. ``write_zone_escape_denied`` — with ``writable_paths`` declared, a
   write outside the zone is denied and the record says zoning was active.
9. ``brokered_posture_is_honest`` — a brokered-tier request is either
   mediated through a proxy (``broker_proxy=True``, dial succeeds only via
   the sanctioned path) or honestly refused; running it unmediated fails
   the kit.
10. ``attestation_states_mechanisms_truthfully`` — every mechanism the
    ``EnforcementRecord`` claims is exercised by the escape corpus above:
    claimed containment matches observed denial, and ``tier_enforcement``
    names the backend class that actually ran (the G5 convention).

Usage (see ``tests/sandbox/test_conformance_kit.py``)::

    kit = ConformanceKit(factory, checkpoints=store)
    run_conformance_kit(kit)          # runs every check, raises on failure

A production backend adds its own ``TierEnforcement`` member (G5
convention) and passes it as ``expected_tier_enforcement``.
"""

from __future__ import annotations

import socket
import threading
from collections.abc import Callable

from evoruntime.core.isolation import IsolationTier
from evoruntime.plugins.manifest import NetworkMode, ResourceLimits
from evoruntime.plugins.protocol import CheckpointStore
from evoruntime.sandbox.backend import IsolationBackend
from evoruntime.sandbox.profile import (
    ExecutionProfile,
    ExecutionRefusedError,
    ExecutionRequest,
    StagingError,
    TierEnforcement,
)
from evoruntime.security.egress import EgressPolicy
from tests.sandbox.support import digest_of, make_payload, make_request

#: Builds a backend wired to the kit's checkpoint store, serving the given
#: payload blobs. This is the only backend-specific code the kit requires.
BackendKitFactory = Callable[[dict[str, bytes]], IsolationBackend]

TINY_LIMITS = ResourceLimits(
    wall_clock_minutes=1.0, cpu=1.0, memory_gib=0.05, model_tokens=0, proposals=1
)
GENEROUS_LIMITS = ResourceLimits(
    wall_clock_minutes=1.0, cpu=1.0, memory_gib=2.0, model_tokens=0, proposals=1
)

_DIAL_CODE = (
    "import socket\n"
    "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
    "s.settimeout(5)\n"
    "s.connect(('93.184.216.34', 80))\n"
    "print('DIAL_OK')\n"
)
_FS_ESCAPE_CODE = (
    "try:\n"
    "    with open('/tmp/evoruntime-kit-escape-probe', 'w') as f:\n"
    "        f.write('escaped')\n"
    "    print('ESCAPE_OK')\n"
    "except PermissionError:\n"
    "    print('ESCAPE_DENIED')\n"
)
_BOMB_CODE = (
    "try:\n"
    "    blob = bytearray(512 * 1024 * 1024)\n"
    "    print('BOMB_OK')\n"
    "except MemoryError:\n"
    "    print('BOMB_DENIED')\n"
)
_ZONE_ESCAPE_CODE = (
    "from pathlib import Path\n"
    "Path('scratch').mkdir(exist_ok=True)\n"
    "try:\n"
    "    Path('tmp/escape.txt').write_text('outside the zone')\n"
    "except PermissionError:\n"
    "    raise SystemExit(3)\n"
    "raise SystemExit(0)\n"
)


class ConformanceKit:
    """The checks every isolation backend must pass, over the protocol only."""

    def __init__(
        self,
        backend_factory: BackendKitFactory,
        *,
        checkpoints: CheckpointStore,
        expected_tier_enforcement: TierEnforcement = TierEnforcement.REFERENCE,
    ) -> None:
        self._factory = backend_factory
        self._checkpoints = checkpoints
        self._expected_tier_enforcement = expected_tier_enforcement

    # -- helpers -------------------------------------------------------------

    def _backend(self, code: str) -> IsolationBackend:
        data = code.encode("utf-8")
        return self._factory({digest_of(data): data})

    def _request(
        self,
        code: str,
        *,
        profile: ExecutionProfile,
        capture_paths: tuple[str, ...] = (),
        egress_policy: EgressPolicy | None = None,
    ) -> ExecutionRequest:
        ref = make_payload("candidate.py", code.encode("utf-8"))
        request = make_request(
            profile=profile,
            payloads=(ref,),
            command=("python3", "candidate.py"),
            capture_paths=capture_paths,
        )
        if egress_policy is not None:
            request = request.model_copy(update={"egress_policy": egress_policy})
        return request

    @staticmethod
    def _executable_profile() -> ExecutionProfile:
        return ExecutionProfile(
            tier=IsolationTier.EXECUTABLE,
            network_mode=NetworkMode.NONE,
            resource_limits=TINY_LIMITS,
        )

    # -- checks --------------------------------------------------------------

    def text_only_tier_refuses(self) -> None:
        """The TEXT_ONLY tier never executes candidate bytes."""
        profile = ExecutionProfile(
            tier=IsolationTier.TEXT_ONLY,
            network_mode=NetworkMode.NONE,
            resource_limits=TINY_LIMITS,
        )
        code = "print('should never run')"
        try:
            self._backend(code).run(self._request(code, profile=profile))
        except ExecutionRefusedError:
            return
        raise AssertionError("TEXT_ONLY tier executed candidate bytes instead of refusing")

    def benign_run_attests(self) -> None:
        """A benign candidate runs, and its attestation is digest-bound."""
        code = "print('hello from candidate')"
        result = self._backend(code).run(self._request(code, profile=self._executable_profile()))
        assert result.exit_code == 0
        assert "hello from candidate" in result.stdout
        att = result.attestation
        assert att.tier is IsolationTier.EXECUTABLE
        assert att.exit_code == 0
        assert att.signal_name is None
        assert att.timed_out is False
        assert att.enforcement.rlimits_applied is True
        assert att.enforcement.filesystem_contained is True
        # The digest binds the exact persisted attestation bytes.
        stored = self._checkpoints.load(result.attestation_digest)
        assert att.model_dump_json().encode("utf-8") == stored

    def network_dial_denied(self) -> None:
        """A direct AF_INET dial on a no-network tier is physically denied."""
        result = self._backend(_DIAL_CODE).run(
            self._request(_DIAL_CODE, profile=self._executable_profile())
        )
        assert "DIAL_OK" not in result.stdout
        assert result.exit_code != 0 or result.attestation.signal_name is not None

    def filesystem_escape_denied(self) -> None:
        """A write outside the workspace is physically denied."""
        result = self._backend(_FS_ESCAPE_CODE).run(
            self._request(_FS_ESCAPE_CODE, profile=self._executable_profile())
        )
        assert "ESCAPE_OK" not in result.stdout
        assert "ESCAPE_DENIED" in result.stdout

    def memory_bomb_denied(self) -> None:
        """A candidate exceeding its declared memory ceiling is denied."""
        result = self._backend(_BOMB_CODE).run(
            self._request(_BOMB_CODE, profile=self._executable_profile())
        )
        assert "BOMB_OK" not in result.stdout

    def staging_digest_mismatch_aborts(self) -> None:
        """A declared-vs-stored digest mismatch aborts before execution."""
        code = "print('legit')"
        data = code.encode("utf-8")
        bad_ref = make_payload("candidate.py", data).model_copy(
            update={"digest": digest_of(b"tampered")}
        )
        backend = self._factory({digest_of(data): data})
        request = make_request(
            profile=self._executable_profile(),
            payloads=(bad_ref,),
            command=("python3", "candidate.py"),
        )
        try:
            backend.run(request)
        except StagingError:
            return
        raise AssertionError("digest mismatch did not abort staging before execution")

    def capture_roundtrip_digest_verified(self) -> None:
        """Mutate → capture → re-stage reproduces the digest."""
        profile = ExecutionProfile(
            tier=IsolationTier.EXECUTABLE,
            network_mode=NetworkMode.NONE,
            resource_limits=TINY_LIMITS,
            writable_paths=("out",),
        )
        mutator = (
            "from pathlib import Path\n"
            "Path('out').mkdir(exist_ok=True)\n"
            "Path('out/scaffold.py').write_bytes(b'MUTATED_SCAFFOLD_BYTES')\n"
        )
        first = self._backend(mutator).run(
            self._request(mutator, profile=profile, capture_paths=("out/scaffold.py",))
        )
        assert first.exit_code == 0
        (captured,) = first.captured
        assert captured.digest == digest_of(b"MUTATED_SCAFFOLD_BYTES")
        assert [(ref.path, ref.digest) for ref in first.attestation.captured] == [
            (captured.path, captured.digest)
        ]
        # Re-stage the captured bytes and execute exactly those bytes.
        restage_code = "import pathlib; print(pathlib.Path('scaffold.py').read_text())"
        backend = self._factory({captured.digest: captured.content})
        second = backend.run(
            make_request(
                profile=self._executable_profile(),
                payloads=(make_payload("scaffold.py", captured.content),),
                command=("python3", "-c", restage_code),
            )
        )
        assert second.exit_code == 0
        assert "MUTATED_SCAFFOLD_BYTES" in second.stdout

    def write_zone_escape_denied(self) -> None:
        """With zones declared, a write outside the zone is denied."""
        profile = ExecutionProfile(
            tier=IsolationTier.EXECUTABLE,
            network_mode=NetworkMode.NONE,
            resource_limits=TINY_LIMITS,
            writable_paths=("scratch",),
        )
        result = self._backend(_ZONE_ESCAPE_CODE).run(
            self._request(_ZONE_ESCAPE_CODE, profile=profile)
        )
        assert result.exit_code == 3, "write outside the zone was not denied"
        assert result.attestation.enforcement.write_zone_applied is True
        assert result.attestation.enforcement.filesystem_contained is True

    def brokered_posture_is_honest(self) -> None:
        """Brokered egress is mediated through a proxy — or honestly refused.

        The dishonest posture — running a brokered-tier request with no
        proxy (``broker_proxy=False``) — fails the kit regardless of
        whether the dial happened to succeed.
        """
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
        try:
            code = (
                "import socket\n"
                f"s = socket.create_connection(('127.0.0.1', {port}), timeout=5)\n"
                "print('PROXY_DIAL_OK')\n"
            )
            request = self._request(
                code,
                profile=ExecutionProfile(
                    tier=IsolationTier.BROKERED,
                    network_mode=NetworkMode.BROKERED,
                    resource_limits=GENEROUS_LIMITS,
                ),
                egress_policy=EgressPolicy(allowed_hosts=frozenset({"127.0.0.1"})),
            )
            try:
                result = self._backend(code).run(request)
            except ExecutionRefusedError:
                # Honest refusal: the backend cannot enforce brokered egress,
                # so it refuses the tier instead of running it unmediated.
                return
            record = result.attestation.enforcement
            assert record.broker_proxy is True, (
                "brokered tier ran without proxy mediation — "
                "the EnforcementRecord is dishonest or the egress is unenforced"
            )
            assert "PROXY_DIAL_OK" in result.stdout
            assert accepted.is_set()
            assert result.attestation.egress_denials == ()
        finally:
            upstream.close()

    def attestation_states_mechanisms_truthfully(self) -> None:
        """Every mechanism the EnforcementRecord claims was actually exercised.

        The record is descriptive, never aspirational: a claimed mechanism
        must correspond to an observed denial, and ``tier_enforcement``
        must name the backend class that actually ran (G5 convention).
        """
        result = self._backend(_DIAL_CODE).run(
            self._request(_DIAL_CODE, profile=self._executable_profile())
        )
        record = result.attestation.enforcement
        dial_denied = "DIAL_OK" not in result.stdout and (
            result.exit_code != 0 or result.attestation.signal_name is not None
        )
        if record.network_filter_applied:
            assert dial_denied, (
                "EnforcementRecord claims network_filter_applied but a direct dial was not denied"
            )
        else:
            assert not dial_denied or record.broker_proxy, (
                "dial was denied but the record claims no network filter"
            )

        fs_result = self._backend(_FS_ESCAPE_CODE).run(
            self._request(_FS_ESCAPE_CODE, profile=self._executable_profile())
        )
        fs_record = fs_result.attestation.enforcement
        if fs_record.filesystem_contained:
            assert "ESCAPE_OK" not in fs_result.stdout, (
                "EnforcementRecord claims filesystem_contained but the workspace escape succeeded"
            )

        bomb_result = self._backend(_BOMB_CODE).run(
            self._request(_BOMB_CODE, profile=self._executable_profile())
        )
        bomb_record = bomb_result.attestation.enforcement
        if bomb_record.rlimits_applied:
            assert "BOMB_OK" not in bomb_result.stdout, (
                "EnforcementRecord claims rlimits_applied but the memory bomb was not denied"
            )

        assert record.tier_enforcement == self._expected_tier_enforcement, (
            f"tier_enforcement {record.tier_enforcement!r} does not name the "
            f"backend class under test ({self._expected_tier_enforcement!r})"
        )


#: Every check a conforming backend must pass, in kit order.
CONFORMANCE_CHECKS: tuple[str, ...] = (
    "text_only_tier_refuses",
    "benign_run_attests",
    "network_dial_denied",
    "filesystem_escape_denied",
    "memory_bomb_denied",
    "staging_digest_mismatch_aborts",
    "capture_roundtrip_digest_verified",
    "write_zone_escape_denied",
    "brokered_posture_is_honest",
    "attestation_states_mechanisms_truthfully",
)


def run_conformance_kit(kit: ConformanceKit) -> tuple[str, ...]:
    """Run every conformance check; raise on the first violation.

    Returns the names of the checks that ran (all of them, or the exception
    propagates). A backend "passes the kit" means this returned.
    """
    for name in CONFORMANCE_CHECKS:
        check = getattr(kit, name)
        if not callable(check):
            raise AssertionError(f"conformance check {name!r} is not callable")
        check()
    return CONFORMANCE_CHECKS

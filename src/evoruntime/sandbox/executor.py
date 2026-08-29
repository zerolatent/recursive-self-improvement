"""The reference isolation backend: subprocess + rlimits + Landlock + seccomp.

This is the enforced in-CI implementation of :class:`IsolationBackend`
(spec: "Sandbox depth: a protocol, not a product"). One ``run()`` does the
whole lifecycle:

1. Refuse ``TEXT_ONLY`` (that tier never executes) and refuse to run at all
   when the platform cannot provide physical enforcement — fail closed, not
   degraded.
2. Stage candidate bytes from the E1 payload store into a fresh private
   workspace (:mod:`evoruntime.sandbox.staging`), digest-verified.
3. Spawn the command with a scrubbed environment and a pre-exec setup that
   applies, in order: rlimits (``memory_gib``/``cpu`` physical at spawn),
   a network namespace where the host allows, Landlock write containment to
   the workspace, and the seccomp socket-domain filter (kernel ``EPERM`` for
   network dials on no-network tiers).
4. For brokered tiers, run the :class:`EgressBrokerProxy` as the only
   sanctioned network path, recording every denial.
5. Persist an :class:`ExecutionAttestation` through the checkpoint pattern —
   content-addressed, so the digest binds image, tier, egress denials, and
   exit together.

Enforcement boundary (documented, not hidden): on no-network tiers the
seccomp filter is the physical wall; on the brokered tier the proxy mediates
the sanctioned path and bypass resistance comes from the namespace where the
host allows one, or from a production microVM backend implementing the same
protocol. The attestation's ``EnforcementRecord`` states exactly which
mechanisms were active for every run.
"""

from __future__ import annotations

import signal
import subprocess
import sys
import time
import uuid
from collections.abc import Callable

from evoruntime.core.isolation import IsolationTier
from evoruntime.plugins.protocol import CheckpointStore
from evoruntime.sandbox import _landlock, _seccomp, netns
from evoruntime.sandbox.egress import EgressBrokerProxy
from evoruntime.sandbox.limits import apply_rlimits
from evoruntime.sandbox.profile import (
    MAX_CAPTURED_OUTPUT_BYTES,
    EnforcementRecord,
    ExecutionAttestation,
    ExecutionProfile,
    ExecutionRefusedError,
    ExecutionRequest,
    ExecutionResult,
    IsolationUnavailableError,
)
from evoruntime.sandbox.staging import PayloadReader, StagedWorkspace

# Socket address families the child may create, per network posture. The
# no-network tiers get local IPC only; the brokered tier needs TCP to reach
# the loopback proxy.
_AF_UNIX = 1
_AF_INET = 2
_AF_INET6 = 10

_ATTESTATION_SCHEMA_ID = "evoruntime.sandbox.execution-attestation/v1"

_enforcement_available: bool | None = None


def physical_enforcement_available() -> bool:
    """Whether this platform can provide the physical mechanisms.

    Seccomp (network denial) and Landlock (filesystem containment) are both
    required; a host missing either cannot run the reference backend at all.
    Cached after the first probe.
    """
    global _enforcement_available
    if _enforcement_available is None:
        _enforcement_available = (
            sys.platform.startswith("linux")
            and _seccomp.seccomp_available()
            and _landlock.landlock_available()
        )
    return _enforcement_available


def _allowed_socket_domains(profile: ExecutionProfile) -> frozenset[int]:
    if profile.network_mode.value == "brokered":
        return frozenset({_AF_UNIX, _AF_INET, _AF_INET6})
    return frozenset({_AF_UNIX})


def _interpret_returncode(returncode: int | None) -> tuple[int | None, str | None]:
    if returncode is None:
        return None, None
    if returncode < 0:
        return None, signal.Signals(-returncode).name
    return returncode, None


class SubprocessIsolationBackend:
    """Reference backend: subprocess + rlimits + Landlock + seccomp (+ netns).

    Constructed with the E1 payload reader (for staging) and a checkpoint
    store (for attestation persistence). One instance is reusable across
    runs; each run gets a fresh staged workspace and its own broker proxy.
    """

    def __init__(self, *, payloads: PayloadReader, checkpoints: CheckpointStore) -> None:
        self._payloads = payloads
        self._checkpoints = checkpoints

    def run(self, request: ExecutionRequest) -> ExecutionResult:
        profile = request.profile
        if profile.tier is IsolationTier.TEXT_ONLY:
            raise ExecutionRefusedError(
                "tier text-only never executes candidate bytes — refusing the run"
            )
        if not physical_enforcement_available():
            raise IsolationUnavailableError(
                "this platform cannot provide physical enforcement "
                "(seccomp network filter / Landlock containment); "
                "refusing to execute unisolated"
            )

        workspace = StagedWorkspace.stage(
            request.payloads, reader=self._payloads, tenant_id=request.tenant_id
        )
        proxy: EgressBrokerProxy | None = None
        if profile.network_mode.value == "brokered":
            proxy = EgressBrokerProxy(request.egress_policy)
            proxy.bind()
        try:
            started = time.monotonic()
            process = subprocess.Popen(
                list(request.command),
                cwd=workspace.root,
                env=self._child_env(workspace, proxy),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=self._child_setup(workspace, profile),
            )
            if proxy is not None:
                proxy.serve()
            stdout, stderr, timed_out = self._collect(process, profile)
            duration = time.monotonic() - started
        finally:
            if proxy is not None:
                proxy.stop()
            workspace.cleanup()

        exit_code, signal_name = _interpret_returncode(process.returncode)
        denials = proxy.denials if proxy is not None else ()
        attestation = ExecutionAttestation(
            execution_id=f"exe_{uuid.uuid4().hex}",
            tenant_id=request.tenant_id,
            image_digest=request.image_digest,
            tier=profile.tier,
            network_mode=profile.network_mode,
            resource_limits=profile.resource_limits,
            egress_denials=denials,
            exit_code=exit_code,
            signal_name=signal_name,
            timed_out=timed_out,
            staged_payloads=request.payloads,
            enforcement=EnforcementRecord(
                rlimits_applied=True,
                network_filter_applied=True,
                filesystem_contained=True,
                network_namespace=(
                    profile.network_mode.value == "none" and netns.netns_available()
                ),
                broker_proxy=proxy is not None,
            ),
            allow_privileged_syscalls=profile.allow_privileged_syscalls,
        )
        return ExecutionResult(
            attestation=attestation,
            attestation_digest=self._persist(attestation),
            stdout=self._decode(stdout),
            stderr=self._decode(stderr),
            duration_seconds=duration,
        )

    # -- internals ----------------------------------------------------------

    def _collect(
        self, process: subprocess.Popen[bytes], profile: ExecutionProfile
    ) -> tuple[bytes, bytes, bool]:
        wall_clock_seconds = profile.resource_limits.wall_clock_minutes * 60
        try:
            stdout, stderr = process.communicate(timeout=wall_clock_seconds)
            return stdout, stderr, False
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            return stdout, stderr, True

    def _child_env(
        self, workspace: StagedWorkspace, proxy: EgressBrokerProxy | None
    ) -> dict[str, str]:
        # Allowlist, not denylist: the child gets a minimal neutral
        # environment. Evaluator keys, the egress allowlist, and workload
        # identity never reach candidate code.
        root = str(workspace.root)
        env = {
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "HOME": root,
            "TMPDIR": f"{root}/tmp",
        }
        if proxy is not None:
            proxy_url = proxy.proxy_url()
            env.update(
                {
                    "http_proxy": proxy_url,
                    "https_proxy": proxy_url,
                    "all_proxy": proxy_url,
                    "no_proxy": "",
                }
            )
        return env

    def _child_setup(
        self, workspace: StagedWorkspace, profile: ExecutionProfile
    ) -> Callable[[], None]:
        """Build the pre-exec callable that hardens the child in place.

        Order matters: rlimits first (pure), then the network namespace
        (needs /proc writes before Landlock contains writes), then Landlock
        write containment, then the seccomp filter (last, so the earlier
        steps can still syscall freely). Any failure raises — the spawn
        fails and the run aborts; the child never executes unisolated.
        """

        def setup() -> None:
            apply_rlimits(profile.resource_limits)
            if profile.network_mode.value == "none":
                # Best-effort defense-in-depth; the seccomp filter below is
                # the physical wall either way, and the attestation records
                # whether the namespace was available.
                netns.isolate_network_namespace()
            _landlock.restrict_writes_to([workspace.root])
            _seccomp.apply_network_socket_filter(_allowed_socket_domains(profile))

        return setup

    def _persist(self, attestation: ExecutionAttestation) -> str:
        data = attestation.model_dump_json().encode("utf-8")
        return self._checkpoints.store(data, schema_id=_ATTESTATION_SCHEMA_ID)

    @staticmethod
    def _decode(raw: bytes | None) -> str:
        if not raw:
            return ""
        return raw.decode("utf-8", errors="replace")[:MAX_CAPTURED_OUTPUT_BYTES]

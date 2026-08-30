"""A minimal second backend implementing :class:`IsolationBackend`.

This is the H9 parameterization proof: the conformance kit is written
against the protocol, and this stub — a *different* class with its own
composition — passes it. It deliberately does not import or subclass
:class:`SubprocessIsolationBackend`; it composes the platform's kernel
enforcement primitives (rlimits, Landlock, seccomp) directly, with its own
pre-exec chain, its own scrubbed environment, and no network namespace and
no broker proxy.

Honesty by refusal: the stub enforces only the ``EXECUTABLE`` tier. For
``BROKERED`` and ``HIGHEST`` — tiers whose full semantics it cannot
enforce — it refuses the run instead of degrading, exactly the fail-closed
pattern the reference backend uses for missing platform mechanisms. The
conformance kit accepts either posture (mediate the brokered tier through
a proxy, or refuse it) and rejects the dishonest third option: running
brokered egress unmediated.
"""

from __future__ import annotations

import signal
import subprocess
import time
import uuid
from collections.abc import Callable

from evoruntime.core.isolation import IsolationTier
from evoruntime.plugins.protocol import CheckpointStore
from evoruntime.sandbox import _landlock, _seccomp
from evoruntime.sandbox.executor import physical_enforcement_available
from evoruntime.sandbox.limits import apply_rlimits
from evoruntime.sandbox.profile import (
    EnforcementRecord,
    ExecutionAttestation,
    ExecutionProfile,
    ExecutionRefusedError,
    ExecutionRequest,
    ExecutionResult,
    IsolationUnavailableError,
    PayloadRef,
)
from evoruntime.sandbox.staging import PayloadReader, StagedWorkspace

_ATTESTATION_SCHEMA_ID = "evoruntime.sandbox.execution-attestation/v1"

_AF_UNIX = 1


class StubIsolationBackend:
    """Executable-tier-only backend: rlimits + Landlock + seccomp, no netns."""

    def __init__(self, *, payloads: PayloadReader, checkpoints: CheckpointStore) -> None:
        self._payloads = payloads
        self._checkpoints = checkpoints

    def run(self, request: ExecutionRequest) -> ExecutionResult:
        profile = request.profile
        if profile.tier is IsolationTier.TEXT_ONLY:
            raise ExecutionRefusedError(
                "tier text-only never executes candidate bytes — refusing the run"
            )
        if profile.tier is not IsolationTier.EXECUTABLE:
            # Fail closed: this stub implements only the executable tier's
            # semantics (no broker mediation, no HIGHEST denylist), so any
            # other tier is refused, never approximated.
            raise ExecutionRefusedError(
                f"stub backend enforces only the executable tier; "
                f"refusing tier {profile.tier.value}"
            )
        if not physical_enforcement_available():
            raise IsolationUnavailableError(
                "this platform cannot provide physical enforcement; refusing to execute unisolated"
            )

        workspace = StagedWorkspace.stage(
            request.payloads, reader=self._payloads, tenant_id=request.tenant_id
        )
        workspace.ensure_dirs(profile.writable_paths)
        try:
            started = time.monotonic()
            process = subprocess.Popen(
                list(request.command),
                cwd=workspace.root,
                env=self._child_env(workspace),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=self._child_setup(workspace, profile),
            )
            stdout, stderr, timed_out = self._collect(process, profile)
            duration = time.monotonic() - started
            captured = workspace.capture(request.capture_paths) if request.capture_paths else ()
        finally:
            workspace.cleanup()

        exit_code, signal_name = _interpret_returncode(process.returncode)

        attestation = ExecutionAttestation(
            execution_id=f"exe_{uuid.uuid4().hex}",
            tenant_id=request.tenant_id,
            image_digest=request.image_digest,
            tier=profile.tier,
            network_mode=profile.network_mode,
            resource_limits=profile.resource_limits,
            exit_code=exit_code,
            signal_name=signal_name,
            timed_out=timed_out,
            staged_payloads=request.payloads,
            # The attestation binds the captured digest set (PayloadRef
            # shape); the result carries the full CapturedPayload bytes.
            captured=tuple(
                PayloadRef(path=payload.path, digest=payload.digest) for payload in captured
            ),
            enforcement=EnforcementRecord(
                rlimits_applied=True,
                network_filter_applied=True,
                filesystem_contained=True,
                # Truthful negatives: this stub applies no network namespace
                # and runs no broker proxy — the record says so.
                network_namespace=False,
                broker_proxy=False,
                write_zone_applied=bool(profile.writable_paths),
                syscall_denylist=(),
            ),
            allow_privileged_syscalls=profile.allow_privileged_syscalls,
        )
        data = attestation.model_dump_json().encode("utf-8")
        return ExecutionResult(
            attestation=attestation,
            attestation_digest=self._checkpoints.store(data, schema_id=_ATTESTATION_SCHEMA_ID),
            stdout=stdout.decode("utf-8", errors="replace") if stdout else "",
            stderr=stderr.decode("utf-8", errors="replace") if stderr else "",
            duration_seconds=duration,
            captured=captured,
        )

    # -- internals: the stub's own composition, deliberately different
    # from the reference backend's pre-exec chain --------------------------

    @staticmethod
    def _child_env(workspace: StagedWorkspace) -> dict[str, str]:
        root = str(workspace.root)
        return {
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "HOME": root,
            "TMPDIR": f"{root}/tmp",
        }

    @staticmethod
    def _child_setup(workspace: StagedWorkspace, profile: ExecutionProfile) -> Callable[[], None]:
        writable_roots: list[str] = (
            [str(workspace.root / zone) for zone in profile.writable_paths]
            if profile.writable_paths
            else [str(workspace.root)]
        )

        def setup() -> None:
            apply_rlimits(profile.resource_limits)
            _landlock.restrict_writes_to(writable_roots)
            # No-network tiers only: AF_UNIX for local IPC, no INET — the
            # same socket-domain posture the reference backend enforces.
            _seccomp.apply_network_socket_filter(frozenset({_AF_UNIX}))

        return setup

    @staticmethod
    def _collect(
        process: subprocess.Popen[bytes], profile: ExecutionProfile
    ) -> tuple[bytes, bytes, bool]:
        try:
            stdout, stderr = process.communicate(
                timeout=profile.resource_limits.wall_clock_minutes * 60
            )
            return stdout, stderr, False
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            return stdout, stderr, True


def _interpret_returncode(returncode: int | None) -> tuple[int | None, str | None]:
    if returncode is None:
        return None, None
    if returncode < 0:
        return None, signal.Signals(-returncode).name
    return returncode, None

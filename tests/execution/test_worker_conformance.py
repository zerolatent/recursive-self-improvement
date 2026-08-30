"""The H4 execution-worker conformance slice.

The worker is the sandbox's first *production* construction site (survey
§5: before H4, ``SubprocessIsolationBackend`` was constructed only in
tests). These tests run the real backend through the real worker over the
physical sandbox and pin the three operational failure modes the H4 brief
names — stale workspaces, egress-proxy lifecycle, capture-partial-failure —
plus the fail-closed refusals the worker must surface, never swallow.
"""

from __future__ import annotations

import hashlib
import os
import socket
import threading
import time
from pathlib import Path

import pytest

from evoruntime.core.isolation import IsolationTier
from evoruntime.execution.worker import (
    DEFAULT_STALE_WORKSPACE_TTL_SECONDS,
    DevEvaluateWorker,
    WorkerOutcome,
    dev_evaluate_verdict,
    sweep_stale_workspaces,
)
from evoruntime.plugins.protocol import InMemoryCheckpointStore
from evoruntime.sandbox.egress import EgressPolicy
from evoruntime.sandbox.profile import (
    ExecutionProfile,
    ExecutionRequest,
    NetworkMode,
    PayloadRef,
    ResourceLimits,
)
from evoruntime.sandbox.staging import STAGED_WORKSPACE_PREFIX

TENANT = "tnt_worker_conformance"
LIMITS = ResourceLimits(
    wall_clock_minutes=1.0, cpu=1.0, memory_gib=0.05, model_tokens=0, proposals=1
)
IMAGE = "ghcr.io/acme/candidate@sha256:" + "cd" * 32


def _payload(code: str) -> tuple[PayloadRef, dict[str, bytes]]:
    data = code.encode("utf-8")
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    return PayloadRef(path="tool.py", digest=digest), {digest: data}


class _DictPayloadReader:
    """Serves payloads from an in-memory digest -> bytes map."""

    def __init__(self, blobs: dict[str, bytes]) -> None:
        self._blobs = dict(blobs)

    def read(self, *, tenant_id: str, payload_digest: str) -> bytes:
        return self._blobs[payload_digest]


def _request(
    code: str,
    *,
    tier: IsolationTier = IsolationTier.EXECUTABLE,
    network_mode: NetworkMode = NetworkMode.NONE,
    egress_policy: EgressPolicy | None = None,
    capture_paths: tuple[str, ...] = (),
) -> ExecutionRequest:
    ref, _ = _payload(code)
    return ExecutionRequest(
        tenant_id=TENANT,
        image_digest=IMAGE,
        command=("python3", "tool.py"),
        profile=ExecutionProfile(tier=tier, network_mode=network_mode, resource_limits=LIMITS),
        payloads=(ref,),
        egress_policy=egress_policy if egress_policy is not None else EgressPolicy(),
        capture_paths=capture_paths,
    )


def _worker(tmp_path: Path, code: str, **kwargs: object) -> DevEvaluateWorker:
    """A worker over the reference backend, serving ``code`` as the payload."""
    _, blobs = _payload(code)
    return DevEvaluateWorker(
        payloads=_DictPayloadReader(blobs),  # type: ignore[arg-type]
        checkpoints=InMemoryCheckpointStore(),
        scratch_root=tmp_path / "scratch",
        **kwargs,
    )


BENIGN = "print('ok')\n"


# ----------------------------------------------------------------------
# stale-workspace reclamation
# ----------------------------------------------------------------------


def _plant_workspace(root: Path, name: str, *, age_seconds: float) -> Path:
    """A staged-workspace-shaped entry with a backdated mtime."""
    entry = root / name
    entry.mkdir(parents=True)
    old = time.time() - age_seconds
    os.utime(entry, (old, old))
    return entry


def test_stale_workspaces_reclaimed_before_the_run(tmp_path: Path) -> None:
    """A crashed run's workspace is swept at the next run's start."""
    stale = _plant_workspace(
        tmp_path / "scratch", f"{STAGED_WORKSPACE_PREFIX}crashed", age_seconds=7200.0
    )
    worker = _worker(tmp_path, BENIGN, stale_workspace_ttl_seconds=3600.0)

    report = worker.run(_request(BENIGN))

    assert report.outcome is WorkerOutcome.COMPLETED
    assert f"{STAGED_WORKSPACE_PREFIX}crashed" in report.reclaimed_workspaces
    assert not stale.exists()


def test_fresh_workspaces_are_never_swept(tmp_path: Path) -> None:
    """A workspace a live run may be using is left alone."""
    root = tmp_path / "scratch"
    fresh = _plant_workspace(root, f"{STAGED_WORKSPACE_PREFIX}live-run", age_seconds=10.0)
    reclaimed = sweep_stale_workspaces(root, max_age_seconds=3600.0)
    assert reclaimed == ()
    assert fresh.exists()


def test_sweep_ignores_non_workspace_entries(tmp_path: Path) -> None:
    """Only staged-workspace-prefixed directories are candidates."""
    root = tmp_path / "scratch"
    root.mkdir()
    other = root / "unrelated-dir"
    other.mkdir()
    _plant_workspace(root, f"{STAGED_WORKSPACE_PREFIX}old", age_seconds=9999.0)

    reclaimed = sweep_stale_workspaces(root, max_age_seconds=3600.0)

    assert reclaimed == (f"{STAGED_WORKSPACE_PREFIX}old",)
    assert other.exists()


def test_missing_scratch_root_sweeps_nothing(tmp_path: Path) -> None:
    assert sweep_stale_workspaces(tmp_path / "absent", max_age_seconds=1.0) == ()


def test_default_ttl_is_an_hour() -> None:
    """The default never sweeps a workspace younger than a live run could be."""
    assert DEFAULT_STALE_WORKSPACE_TTL_SECONDS == 3600.0


# ----------------------------------------------------------------------
# fail-closed refusals are surfaced, never swallowed
# ----------------------------------------------------------------------


def test_text_only_refusal_reports_with_reason(tmp_path: Path) -> None:
    """The sandbox's fail-closed refusal becomes an operational report."""
    worker = _worker(tmp_path, BENIGN)
    report = worker.run(_request(BENIGN, tier=IsolationTier.TEXT_ONLY))

    assert report.outcome is WorkerOutcome.REFUSED
    assert report.result is None
    assert report.error is not None
    assert "text-only" in report.error
    # A refusal still ran the sweep — reclamation is unconditional.
    assert report.reclaimed_workspaces == ()


def test_refused_run_fails_dev_evaluate(tmp_path: Path) -> None:
    worker = _worker(tmp_path, BENIGN)
    report = worker.run(_request(BENIGN, tier=IsolationTier.TEXT_ONLY))
    outcome, metrics = dev_evaluate_verdict(report)
    assert outcome == "fail"
    assert metrics == {"worker_failure": 1.0}


def test_unknown_backend_environment_refuses_at_construction(tmp_path: Path) -> None:
    """A typo'd backend name never silently falls back to the reference."""
    from evoruntime.sandbox.profile import SandboxError
    from evoruntime.sandbox.selection import BackendSelectionError

    with pytest.raises(SandboxError) as excinfo:
        DevEvaluateWorker(
            payloads=_DictPayloadReader({}),
            checkpoints=InMemoryCheckpointStore(),
            scratch_root=tmp_path / "scratch",
            backend_environment="subprocess",  # the classic typo
        )
    assert isinstance(excinfo.value, BackendSelectionError)


# ----------------------------------------------------------------------
# capture-partial-failure: recorded, and never a success
# ----------------------------------------------------------------------


def test_capture_partial_failure_is_reported_not_swallowed(tmp_path: Path) -> None:
    """A missing declared capture path executes, attests, and reports."""
    code = "open('produced.txt', 'w').write('data')\nprint('ok')\n"
    worker = _worker(tmp_path, code)
    report = worker.run(_request(code, capture_paths=("produced.txt", "never-written.txt")))

    assert report.outcome is WorkerOutcome.CAPTURE_PARTIAL_FAILURE
    assert report.result is not None
    assert report.error is None  # the run happened; nothing failed silently
    failures = report.result.capture_failures
    assert len(failures) == 1
    assert failures[0].path == "never-written.txt"
    # The capture that did work is still digest-verified evidence.
    assert report.result.captured[0].path == "produced.txt"


def test_capture_partial_failure_fails_dev_evaluate(tmp_path: Path) -> None:
    """The worker owns the policy: a partial capture is never a pass."""
    code = "open('produced.txt', 'w').write('data')\n"
    worker = _worker(tmp_path, code)
    report = worker.run(_request(code, capture_paths=("produced.txt", "never-written.txt")))
    outcome, metrics = dev_evaluate_verdict(report)
    assert outcome == "fail"
    assert metrics["capture_failures"] == 1.0


def test_clean_capture_passes_dev_evaluate(tmp_path: Path) -> None:
    code = "open('produced.txt', 'w').write('data')\n"
    worker = _worker(tmp_path, code)
    report = worker.run(_request(code, capture_paths=("produced.txt",)))
    assert report.outcome is WorkerOutcome.COMPLETED
    outcome, metrics = dev_evaluate_verdict(report)
    assert outcome == "pass"
    assert metrics["duration_seconds"] >= 0.0


# ----------------------------------------------------------------------
# egress-proxy lifecycle
# ----------------------------------------------------------------------


def test_broker_proxy_is_gone_when_the_run_ends(tmp_path: Path) -> None:
    """The proxy that mediated a brokered run is torn down with the run.

    The attestation records the proxy's loopback port precisely so this is
    checkable: after the worker's report returns, nothing may still be
    listening on that port.
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
        worker = _worker(tmp_path, code)
        report = worker.run(
            _request(
                code,
                tier=IsolationTier.BROKERED,
                network_mode=NetworkMode.BROKERED,
                egress_policy=EgressPolicy(allowed_hosts=frozenset({"127.0.0.1"})),
            )
        )

        if report.outcome is WorkerOutcome.REFUSED:
            # Honest refusal on a platform that cannot mediate brokered
            # egress — the refusal itself is the conformance result.
            assert report.error is not None
            return

        assert report.outcome is WorkerOutcome.COMPLETED, report.error
        assert report.result is not None
        record = report.result.attestation.enforcement
        assert record.broker_proxy is True
        assert record.broker_proxy_port is not None
        assert "PROXY_DIAL_OK" in report.result.stdout
        assert accepted.is_set()

        # The lifecycle claim: the port the attestation names stops accepting
        # connections once the run ends. The sandbox environment tears its own
        # port relay down asynchronously, so poll briefly rather than demand
        # instant closure — the assertion is that it *happens*, promptly.
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            probe = socket.socket()
            probe.settimeout(1.0)
            try:
                probe.connect(("127.0.0.1", record.broker_proxy_port))
            except OSError:
                break  # nothing is listening: the proxy is gone
            finally:
                probe.close()
            time.sleep(0.25)
        else:
            pytest.fail(
                f"broker proxy port {record.broker_proxy_port} still accepting "
                "connections 10s after the run ended — the proxy leaked"
            )
    finally:
        upstream.close()


# ----------------------------------------------------------------------
# the sandbox is load-bearing: the worker runs the real backend
# ----------------------------------------------------------------------


def test_worker_runs_the_reference_backend_end_to_end(tmp_path: Path) -> None:
    """The composition the survey called for: worker → backend → sandbox."""
    worker = _worker(tmp_path, BENIGN)
    from evoruntime.sandbox.executor import SubprocessIsolationBackend as _Ref

    assert isinstance(worker.backend, _Ref)
    report = worker.run(_request(BENIGN))
    assert report.outcome is WorkerOutcome.COMPLETED
    assert report.result is not None
    assert report.result.exit_code == 0
    assert report.attestation_digest is not None
    assert report.attestation_digest.startswith("sha256:")


def test_staged_workspace_cleanup_after_run(tmp_path: Path) -> None:
    """A completed run leaves no staged workspace behind in the scratch root."""
    worker = _worker(tmp_path, BENIGN)
    report = worker.run(_request(BENIGN))
    assert report.outcome is WorkerOutcome.COMPLETED
    leftovers = [
        entry.name
        for entry in (tmp_path / "scratch").iterdir()
        if entry.name.startswith(STAGED_WORKSPACE_PREFIX)
    ]
    assert leftovers == []

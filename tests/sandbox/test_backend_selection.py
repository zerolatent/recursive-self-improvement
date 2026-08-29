"""H9: backend-selection seam policy tests — fail-closed, never a fallback.

The execution worker (H4) resolves its backend through
``resolve_isolation_backend``; these tests pin the contract: unknown or
unregistered environment names refuse, the env var is honored, the
default is the reference backend, and a registered production backend is
reachable through the same seam.
"""

from __future__ import annotations

import pytest

from evoruntime.plugins.protocol import InMemoryCheckpointStore
from evoruntime.sandbox import selection
from evoruntime.sandbox.executor import (
    SubprocessIsolationBackend,
    physical_enforcement_available,
)
from evoruntime.sandbox.selection import (
    DEFAULT_ENVIRONMENT,
    ISOLATION_BACKEND_ENV_VAR,
    BackendSelectionError,
    known_backend_environments,
    register_isolation_backend,
    resolve_isolation_backend,
)
from tests.sandbox.stub_backend import StubIsolationBackend
from tests.sandbox.support import DictPayloadReader

requires_enforcement = pytest.mark.skipif(
    not physical_enforcement_available(),
    reason="reference backend requires seccomp + Landlock (Linux)",
)


@pytest.fixture
def checkpoints() -> InMemoryCheckpointStore:
    return InMemoryCheckpointStore()


@pytest.fixture
def payloads() -> DictPayloadReader:
    return DictPayloadReader({})


class TestFailClosedSelection:
    def test_unknown_environment_refuses(self, checkpoints, payloads) -> None:
        with pytest.raises(BackendSelectionError, match="unknown isolation backend"):
            resolve_isolation_backend("does-not-exist", payloads=payloads, checkpoints=checkpoints)

    def test_plausible_alias_refuses(self, checkpoints, payloads) -> None:
        """A guessed name like 'subprocess' must not resolve to anything."""
        with pytest.raises(BackendSelectionError, match="subprocess"):
            resolve_isolation_backend("subprocess", payloads=payloads, checkpoints=checkpoints)

    def test_unregistered_microvm_refuses(self, checkpoints, payloads) -> None:
        """A production backend must be registered before it is selectable."""
        with pytest.raises(BackendSelectionError, match="firecracker"):
            resolve_isolation_backend("firecracker", payloads=payloads, checkpoints=checkpoints)

    def test_error_lists_known_environments(self, checkpoints, payloads) -> None:
        with pytest.raises(BackendSelectionError) as excinfo:
            resolve_isolation_backend("nope", payloads=payloads, checkpoints=checkpoints)
        assert DEFAULT_ENVIRONMENT in str(excinfo.value)

    def test_empty_registration_refuses(self, checkpoints, payloads) -> None:
        with pytest.raises(BackendSelectionError, match="non-empty"):
            register_isolation_backend("   ", lambda p, c: None)  # type: ignore[arg-type,return-value]


class TestDefaultAndEnvVar:
    @requires_enforcement
    def test_default_is_reference(self, checkpoints, payloads) -> None:
        backend = resolve_isolation_backend(payloads=payloads, checkpoints=checkpoints)
        assert isinstance(backend, SubprocessIsolationBackend)

    @requires_enforcement
    def test_none_reads_env_var(
        self, checkpoints, payloads, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(ISOLATION_BACKEND_ENV_VAR, DEFAULT_ENVIRONMENT)
        backend = resolve_isolation_backend(payloads=payloads, checkpoints=checkpoints)
        assert isinstance(backend, SubprocessIsolationBackend)

    def test_env_var_unknown_value_refuses(
        self, checkpoints, payloads, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(ISOLATION_BACKEND_ENV_VAR, "bogus-backend")
        with pytest.raises(BackendSelectionError, match="bogus-backend"):
            resolve_isolation_backend(payloads=payloads, checkpoints=checkpoints)

    def test_empty_env_var_selects_default(
        self, checkpoints, payloads, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Empty/unset selects the documented default — not a silent swap."""
        monkeypatch.setenv(ISOLATION_BACKEND_ENV_VAR, "")
        if physical_enforcement_available():
            backend = resolve_isolation_backend(payloads=payloads, checkpoints=checkpoints)
            assert isinstance(backend, SubprocessIsolationBackend)
        else:
            # Fail-closed at construction on a host without enforcement.
            with pytest.raises(Exception, match="physical"):
                resolve_isolation_backend(payloads=payloads, checkpoints=checkpoints)


class TestNormalization:
    @requires_enforcement
    def test_case_and_whitespace_normalized(self, checkpoints, payloads) -> None:
        backend = resolve_isolation_backend(
            "  REFERENCE  ", payloads=payloads, checkpoints=checkpoints
        )
        assert isinstance(backend, SubprocessIsolationBackend)


class TestRegistry:
    def test_registered_backend_is_selectable(
        self, checkpoints, payloads, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The swap point: register a factory, then select it by name."""
        monkeypatch.setitem(
            selection._BACKEND_FACTORIES,
            "kit-stub",
            lambda p, c: StubIsolationBackend(payloads=p, checkpoints=c),
        )
        backend = resolve_isolation_backend("kit-stub", payloads=payloads, checkpoints=checkpoints)
        assert isinstance(backend, StubIsolationBackend)

    def test_registered_backend_reachable_via_env_var(
        self, checkpoints, payloads, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setitem(
            selection._BACKEND_FACTORIES,
            "kit-stub",
            lambda p, c: StubIsolationBackend(payloads=p, checkpoints=c),
        )
        monkeypatch.setenv(ISOLATION_BACKEND_ENV_VAR, "KIT-STUB")
        backend = resolve_isolation_backend(payloads=payloads, checkpoints=checkpoints)
        assert isinstance(backend, StubIsolationBackend)

    def test_known_environments_sorted(self) -> None:
        assert list(known_backend_environments()) == sorted(known_backend_environments())
        assert DEFAULT_ENVIRONMENT in known_backend_environments()

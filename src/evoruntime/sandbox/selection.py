"""Backend selection: environment → :class:`IsolationBackend`, fail-closed.

This is the H9 seam that makes the backend swap honest (survey §5:
``SubprocessIsolationBackend`` is constructed only in tests; the Phase 4
execution worker is the first production path through the sandbox, so
backend *selection* becomes a deployment decision that needs a policy
function, not an import).

Contract
--------
The execution worker resolves its backend once, at construction, via
:func:`resolve_isolation_backend`. The environment is read from the
``EVO_ISOLATION_BACKEND`` environment variable (the ``EVO_*`` convention
used by the CLI connection profile) or passed programmatically; the
default is ``reference`` — the enforced in-CI subprocess backend.

Selection is fail-closed in both directions:

* An **unknown** environment name refuses (:class:`BackendSelectionError`)
  — a typo like ``subprocess`` or ``gvisor`` never silently falls back to
  the reference backend.
* A **known but unavailable** backend refuses at construction (the
  reference factory probes ``physical_enforcement_available()`` and raises
  :class:`IsolationUnavailableError`) — the runtime never constructs a
  backend that would have to degrade at run time.

A deployment that ships a production backend (gVisor/Firecracker) registers
a factory under its environment name with :func:`register_isolation_backend`
and points ``EVO_ISOLATION_BACKEND`` at that name. See
``docs/isolation-backend-swap.md`` for the full runbook.
"""

from __future__ import annotations

import os
from collections.abc import Callable

from evoruntime.plugins.protocol import CheckpointStore
from evoruntime.sandbox.backend import IsolationBackend
from evoruntime.sandbox.executor import (
    SubprocessIsolationBackend,
    physical_enforcement_available,
)
from evoruntime.sandbox.profile import (
    IsolationUnavailableError,
    SandboxError,
)
from evoruntime.sandbox.staging import PayloadReader

#: The environment variable the execution worker's deployment sets to pick
#: the isolation backend. Unset (or empty) selects the reference backend.
ISOLATION_BACKEND_ENV_VAR = "EVO_ISOLATION_BACKEND"

#: Selected when the environment variable is unset — the enforced in-CI
#: backend, never a silent weaker substitute.
DEFAULT_ENVIRONMENT = "reference"


class BackendSelectionError(SandboxError):
    """The requested backend environment is unknown or unregistered.

    Fail-closed by design: selection never falls back to another backend,
    because a silent fallback would execute candidate bytes under weaker
    enforcement than the deployment believed it had chosen.
    """


#: Builds a backend for one environment. Receives the payload reader and
#: checkpoint store the execution worker resolved (staging, capture, and
#: attestation persistence are composed around the protocol — a backend
#: factory wires them into its constructor, it does not reimplement them).
BackendFactory = Callable[[PayloadReader, CheckpointStore], IsolationBackend]

_BACKEND_FACTORIES: dict[str, BackendFactory] = {}


def _reference_factory(payloads: PayloadReader, checkpoints: CheckpointStore) -> IsolationBackend:
    if not physical_enforcement_available():
        raise IsolationUnavailableError(
            "the reference isolation backend requires seccomp + Landlock "
            "(Linux); refusing to construct a backend that could not "
            "enforce physically"
        )
    return SubprocessIsolationBackend(payloads=payloads, checkpoints=checkpoints)


_BACKEND_FACTORIES[DEFAULT_ENVIRONMENT] = _reference_factory


def _normalize(environment: str) -> str:
    return environment.strip().lower()


def register_isolation_backend(environment: str, factory: BackendFactory) -> None:
    """Register a production backend under its environment name.

    The deployment-time counterpart to the env-var contract: a gVisor or
    Firecracker backend registers its factory at process start, then the
    environment variable selects it. Re-registering a name replaces its
    factory (last registration wins), so a deployment can also swap in a
    instrumented variant of a backend for a soak run.
    """
    name = _normalize(environment)
    if not name:
        raise BackendSelectionError("backend environment name must be non-empty")
    _BACKEND_FACTORIES[name] = factory


def known_backend_environments() -> tuple[str, ...]:
    """The environment names currently registered (sorted, for error text)."""
    return tuple(sorted(_BACKEND_FACTORIES))


def resolve_isolation_backend(
    environment: str | None = None,
    *,
    payloads: PayloadReader,
    checkpoints: CheckpointStore,
) -> IsolationBackend:
    """Resolve an environment name to a constructed isolation backend.

    ``None`` reads :data:`ISOLATION_BACKEND_ENV_VAR`, falling back to
    :data:`DEFAULT_ENVIRONMENT`. Unknown names refuse — never fall back.
    This is the single construction point the execution worker (H4) calls;
    nothing else in production code should instantiate a backend directly.
    """
    if environment is None:
        environment = os.environ.get(ISOLATION_BACKEND_ENV_VAR) or DEFAULT_ENVIRONMENT
    name = _normalize(environment)
    factory = _BACKEND_FACTORIES.get(name)
    if factory is None:
        raise BackendSelectionError(
            f"unknown isolation backend environment {name!r}; "
            f"known environments: {list(known_backend_environments())}; "
            "refusing rather than falling back to another backend"
        )
    return factory(payloads, checkpoints)

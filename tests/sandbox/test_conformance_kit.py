"""H9: the conformance kit passes for every backend, over the protocol only.

The kit runs against the reference backend (the enforced in-CI
implementation) and against the stub backend — a second, distinct
:class:`IsolationBackend` implementation — proving the kit is
parameterized over the protocol: a gVisor/Firecracker backend inherits
the evidence by implementing the contract and running this same kit.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from evoruntime.plugins.protocol import InMemoryCheckpointStore
from evoruntime.sandbox.backend import IsolationBackend
from evoruntime.sandbox.executor import (
    SubprocessIsolationBackend,
    physical_enforcement_available,
)
from tests.sandbox.conformance_kit import CONFORMANCE_CHECKS, ConformanceKit
from tests.sandbox.stub_backend import StubIsolationBackend
from tests.sandbox.support import DictPayloadReader

pytestmark = pytest.mark.skipif(
    not physical_enforcement_available(),
    reason="sandbox backends require seccomp + Landlock (Linux)",
)


def _reference_factory(
    blobs: dict[str, bytes], checkpoints: InMemoryCheckpointStore
) -> IsolationBackend:
    return SubprocessIsolationBackend(payloads=DictPayloadReader(blobs), checkpoints=checkpoints)


def _stub_factory(
    blobs: dict[str, bytes], checkpoints: InMemoryCheckpointStore
) -> IsolationBackend:
    return StubIsolationBackend(payloads=DictPayloadReader(blobs), checkpoints=checkpoints)


@pytest.fixture(params=["reference", "stub"], ids=["reference-backend", "stub-backend"])
def kit(request: pytest.FixtureRequest) -> ConformanceKit:
    checkpoints = InMemoryCheckpointStore()
    factory: Callable[[dict[str, bytes]], IsolationBackend]
    if request.param == "reference":
        factory = lambda blobs: _reference_factory(blobs, checkpoints)  # noqa: E731
    else:
        factory = lambda blobs: _stub_factory(blobs, checkpoints)  # noqa: E731
    return ConformanceKit(factory, checkpoints=checkpoints)


@pytest.mark.parametrize("check_name", CONFORMANCE_CHECKS)
def test_conformance_check(check_name: str, kit: ConformanceKit) -> None:
    """Every kit check passes for every backend under test."""
    check = getattr(kit, check_name)
    check()


def test_kit_covers_every_declared_check(kit: ConformanceKit) -> None:
    """The declared check list matches the kit's actual methods (no drift)."""
    for name in CONFORMANCE_CHECKS:
        assert callable(getattr(kit, name, None)), f"kit check {name!r} is missing"


def test_kit_is_protocol_parameterized() -> None:
    """The kit never imports or references the reference backend's class."""
    import inspect

    from tests.sandbox import conformance_kit

    source = inspect.getsource(conformance_kit)
    assert "from evoruntime.sandbox.executor" not in source, (
        "the conformance kit must not import the reference backend's module"
    )
    assert not hasattr(conformance_kit, "SubprocessIsolationBackend"), (
        "the conformance kit must be parameterized over IsolationBackend, "
        "not coupled to the reference implementation"
    )

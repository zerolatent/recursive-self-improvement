"""Fixtures for the sandbox plane tests."""

from __future__ import annotations

import pytest

from evoruntime.plugins.protocol import InMemoryCheckpointStore
from evoruntime.sandbox.executor import SubprocessIsolationBackend
from tests.sandbox.support import DictPayloadReader


@pytest.fixture
def checkpoints() -> InMemoryCheckpointStore:
    return InMemoryCheckpointStore()


@pytest.fixture
def backend(checkpoints: InMemoryCheckpointStore) -> SubprocessIsolationBackend:
    return SubprocessIsolationBackend(payloads=DictPayloadReader({}), checkpoints=checkpoints)

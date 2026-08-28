"""The isolation backend contract.

``IsolationBackend`` is the protocol seam the spec locks ("Sandbox depth: a
protocol, not a product"): it owns the lifecycle of a sandboxed execution —
filesystem staging from the E1 payload store, egress enforcement, resource
limits applied at spawn — and returns an attested result. gVisor/Firecracker
production backends implement this same protocol; the reference backend in
:mod:`evoruntime.sandbox.executor` is the enforced in-CI implementation.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from evoruntime.sandbox.profile import ExecutionRequest, ExecutionResult


@runtime_checkable
class IsolationBackend(Protocol):
    """The seam every execution environment must satisfy.

    Implementations stage candidate bytes from the payload store, execute
    them under the request's profile, enforce egress and limits *physically*
    (never advisorially), and return the output together with a digest-bound
    :class:`ExecutionAttestation`.
    """

    def run(self, request: ExecutionRequest) -> ExecutionResult: ...

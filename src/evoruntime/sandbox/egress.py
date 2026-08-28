"""Physical egress enforcement: the broker policy wired into the network path.

The Phase 0 :class:`evoruntime.security.egress.EgressBroker` authorizes
destinations but performs no I/O — it is policy, not a network path. This
module is the network path: a loopback HTTP CONNECT proxy that consults the
broker for every upstream dial, so a sandboxed candidate's brokered egress
is *mediated*, not merely advised. A destination not on the allowlist is
denied at the proxy (the candidate's dial fails), and the denial is recorded
as an :class:`EgressDenial` bound into the execution attestation.

Enforcement boundary, stated plainly: the proxy makes the sanctioned path
physical. Bypass resistance — a candidate ignoring the proxy environment and
dialing directly — comes from the seccomp socket filter on no-network tiers
(kernel ``EPERM``) and, where the host allows, the network namespace; a
production microVM backend must satisfy the same contract (see
``docs/threat-model.md``). The reference backend never presents the proxy as
more than it is.
"""

from __future__ import annotations

import contextlib
import select
import socket
import threading

from evoruntime.sandbox.profile import EgressDenial
from evoruntime.security.egress import EgressBroker, EgressDeniedError, EgressPolicy

_RELAY_CHUNK = 65536


class EgressBrokerProxy:
    """A loopback CONNECT proxy enforcing an :class:`EgressPolicy`.

    Threaded rather than asyncio so the synchronous executor can run it
    without an event loop. ``bind()``/``serve()`` are deliberately separate:
    the executor binds before spawning the child (so the proxy address is
    known and listening when the child starts) and starts the accept thread
    only after the spawn, keeping the fork single-threaded.
    """

    def __init__(self, policy: EgressPolicy) -> None:
        self._broker = EgressBroker(policy)
        self._denials: list[EgressDenial] = []
        self._lock = threading.Lock()
        self._listener: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()
        self.port: int = 0

    def bind(self) -> None:
        """Bind the loopback listener and fix the proxy port."""
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(16)
        self._listener = listener
        self.port = listener.getsockname()[1]

    def serve(self) -> None:
        """Start the accept loop in a daemon thread (after ``bind``)."""
        if self._listener is None:
            raise RuntimeError("EgressBrokerProxy.serve() called before bind()")
        self._stopping.clear()
        self._thread = threading.Thread(
            target=self._serve, name="evoruntime-egress-broker", daemon=True
        )
        self._thread.start()

    def start(self) -> None:
        """Convenience for callers that do not fork: bind, then serve."""
        self.bind()
        self.serve()

    def stop(self) -> None:
        self._stopping.set()
        if self._listener is not None:
            self._listener.close()
        if self._thread is not None:
            self._thread.join(timeout=5)

    @property
    def denials(self) -> tuple[EgressDenial, ...]:
        with self._lock:
            return tuple(self._denials)

    def proxy_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    # -- internals ----------------------------------------------------------

    def _serve(self) -> None:
        listener = self._listener
        if listener is None:  # unreachable — serve() guards; keeps mypy certain
            return
        while not self._stopping.is_set():
            try:
                conn, _ = listener.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _record_denial(self, destination: str, host: str, reason: str) -> None:
        with self._lock:
            self._denials.append(EgressDenial(destination=destination, host=host, reason=reason))

    def _handle(self, conn: socket.socket) -> None:
        with conn:
            conn.settimeout(10)
            try:
                request = self._read_request_line(conn)
            except (OSError, ValueError):
                return
            parts = request.split(" ")
            if len(parts) < 3 or parts[0] != "CONNECT":
                self._record_denial(
                    destination=request, host="", reason="non-CONNECT request denied"
                )
                self._respond(conn, "405 Method Not Allowed")
                return
            host, _, port = parts[1].rpartition(":")
            if not host:
                self._respond(conn, "400 Bad Request")
                return
            try:
                self._broker.authorize(host)
            except EgressDeniedError as denied:
                self._record_denial(
                    destination=parts[1], host=denied.host, reason="not on the egress allowlist"
                )
                self._respond(conn, "403 Forbidden")
                return
            try:
                upstream = socket.create_connection((host, int(port)), timeout=10)
            except OSError:
                self._respond(conn, "502 Bad Gateway")
                return
            with upstream:
                self._respond(conn, "200 Connection established")
                self._relay(conn, upstream)

    def _read_request_line(self, conn: socket.socket) -> str:
        buffer = bytearray()
        while b"\r\n" not in buffer and len(buffer) < 8192:
            chunk = conn.recv(1024)
            if not chunk:
                break
            buffer.extend(chunk)
        line, _, _ = bytes(buffer).partition(b"\r\n")
        return line.decode("latin-1")

    def _respond(self, conn: socket.socket, status: str) -> None:
        with contextlib.suppress(OSError):
            conn.sendall(f"HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n".encode("latin-1"))

    def _relay(self, client: socket.socket, upstream: socket.socket) -> None:
        sockets = (client, upstream)
        client.setblocking(False)
        upstream.setblocking(False)
        try:
            while True:
                readable, _, exceptional = select.select(sockets, (), sockets, 5.0)
                if exceptional or not readable:
                    return
                for sock in readable:
                    peer = upstream if sock is client else client
                    data = sock.recv(_RELAY_CHUNK)
                    if not data:
                        return
                    peer.sendall(data)
        except OSError:
            return

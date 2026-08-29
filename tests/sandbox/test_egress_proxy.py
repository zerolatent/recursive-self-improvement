"""Physical egress enforcement: denials observed at the proxy, not advisory."""

from __future__ import annotations

import socket

import pytest

from evoruntime.sandbox.egress import EgressBrokerProxy
from evoruntime.security.egress import EgressPolicy


@pytest.fixture
def proxy() -> EgressBrokerProxy:
    p = EgressBrokerProxy(EgressPolicy(allowed_hosts=frozenset({"allowed.example.com"})))
    p.bind()
    yield p
    p.stop()


def connect_request(proxy: EgressBrokerProxy, authority: str) -> str:
    """Send one CONNECT through the proxy and return the status line."""
    client = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
    with client:
        client.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
        response = b""
        while b"\r\n" not in response:
            chunk = client.recv(1024)
            if not chunk:
                break
            response += chunk
        return response.split(b"\r\n", 1)[0].decode("latin-1")


class TestEgressBrokerProxy:
    def test_denied_host_gets_403_and_is_recorded(self, proxy) -> None:
        proxy.start()
        status = connect_request(proxy, "evil.example.com:443")
        assert status.endswith("403 Forbidden")
        denials = proxy.denials
        assert len(denials) == 1
        assert denials[0].host == "evil.example.com"
        assert "allowlist" in denials[0].reason

    def test_allowed_host_connects_to_upstream(self) -> None:
        upstream = socket.socket()
        upstream.bind(("127.0.0.1", 0))
        upstream.listen(1)
        port = upstream.getsockname()[1]
        allowed = EgressBrokerProxy(EgressPolicy(allowed_hosts=frozenset({"127.0.0.1"})))
        allowed.bind()
        allowed.start()
        try:
            status = connect_request(allowed, f"127.0.0.1:{port}")
            assert status.endswith("200 Connection established")
            assert allowed.denials == ()
        finally:
            allowed.stop()
            upstream.close()

    def test_non_connect_method_denied(self, proxy) -> None:
        proxy.start()
        client = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
        with client:
            client.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            response = client.recv(1024).decode("latin-1")
        assert "405" in response
        assert proxy.denials[0].reason == "non-CONNECT request denied"

    def test_serve_before_bind_raises(self) -> None:
        proxy = EgressBrokerProxy(EgressPolicy())
        with pytest.raises(RuntimeError, match="bind"):
            proxy.serve()

    def test_deny_all_default_records_denial(self) -> None:
        proxy = EgressBrokerProxy(EgressPolicy())
        proxy.bind()
        proxy.start()
        try:
            status = connect_request(proxy, "anything.example.com:443")
            assert status.endswith("403 Forbidden")
            assert proxy.denials[0].host == "anything.example.com"
        finally:
            proxy.stop()

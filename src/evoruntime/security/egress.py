"""Deny-by-default egress broker.

Anything that executes candidate code (the incumbent under evaluation, a
retry arm, a future optimizer's candidate) can only be trusted not to
exfiltrate data or call unexpected services if its network egress is
mediated by a policy the candidate cannot alter. This module is that
mediation point: every outbound destination is checked against an
explicit allowlist before a caller is permitted to use it, and anything
not on the list is denied — including destinations that are merely
unrecognized, not proven malicious.

The broker does not perform network I/O itself. It authorizes (or denies)
a destination; the caller supplies its own transport (``httpx``, a
subprocess network namespace, a sandbox's proxy config). That keeps the
policy testable without a real network and reusable across whatever
transport a given execution environment uses.
"""

from __future__ import annotations

import os
from urllib.parse import urlsplit

from pydantic import Field

from evoruntime.core.schemas import EvoRuntimeBaseModel

_ALLOWLIST_ENV_VAR = "EVORUNTIME_EGRESS_ALLOWLIST"


class EgressDeniedError(PermissionError):
    """Raised when a destination is not on the egress allowlist."""

    def __init__(self, host: str) -> None:
        self.host = host
        super().__init__(f"egress to {host!r} is denied: not on the allowlist")


class EgressPolicy(EvoRuntimeBaseModel):
    """An explicit allowlist of hosts permitted for outbound egress.

    Hosts are matched exactly (case-insensitively) — no wildcard or suffix
    matching. Wildcarding invites "api.openai.com.evil.example.com"-style
    bypasses; an allowlist that needs a new host gets a new entry instead.
    """

    allowed_hosts: frozenset[str] = Field(default_factory=frozenset)

    @classmethod
    def from_env(cls, env_var: str = _ALLOWLIST_ENV_VAR) -> EgressPolicy:
        """Build a policy from a comma-separated host list in an env var.

        Absent or empty means an empty allowlist — deny everything — which
        is the correct default-closed behavior for a misconfigured
        deployment.
        """
        raw = os.environ.get(env_var, "")
        hosts = frozenset(host.strip().lower() for host in raw.split(",") if host.strip())
        return cls(allowed_hosts=hosts)


def _extract_host(destination: str) -> str:
    """Pull the lowercase hostname out of a URL or bare host string."""
    parsed = urlsplit(destination if "//" in destination else f"//{destination}")
    host = parsed.hostname
    if not host:
        raise EgressDeniedError(destination)
    return host.lower()


class EgressBroker:
    """Authorizes outbound destinations against an :class:`EgressPolicy`."""

    def __init__(self, policy: EgressPolicy) -> None:
        self._policy = policy

    def authorize(self, destination: str) -> str:
        """Return the normalized host if permitted, else raise.

        Raises:
            EgressDeniedError: the destination's host is not on the
                allowlist (or the destination has no parseable host).
        """
        host = _extract_host(destination)
        if host not in self._policy.allowed_hosts:
            raise EgressDeniedError(host)
        return host

    def is_authorized(self, destination: str) -> bool:
        """Non-raising check, for call sites that want a boolean."""
        try:
            self.authorize(destination)
        except EgressDeniedError:
            return False
        return True

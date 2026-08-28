"""Egress broker tests: undeclared destinations are denied, declared ones pass."""

from __future__ import annotations

import pytest

from evoruntime.security.egress import EgressBroker, EgressDeniedError, EgressPolicy


@pytest.fixture
def broker() -> EgressBroker:
    policy = EgressPolicy(allowed_hosts=frozenset({"api.openai.com", "ingest.evoruntime.internal"}))
    return EgressBroker(policy)


def test_declared_destination_is_authorized(broker: EgressBroker) -> None:
    host = broker.authorize("https://api.openai.com/v1/chat/completions")

    assert host == "api.openai.com"


def test_undeclared_destination_is_denied(broker: EgressBroker) -> None:
    with pytest.raises(EgressDeniedError, match="evil.example.com"):
        broker.authorize("https://evil.example.com/exfiltrate")


def test_is_authorized_returns_bool_without_raising(broker: EgressBroker) -> None:
    assert broker.is_authorized("https://ingest.evoruntime.internal/v1/events") is True
    assert broker.is_authorized("https://evil.example.com") is False


def test_host_matching_is_case_insensitive(broker: EgressBroker) -> None:
    assert broker.is_authorized("https://API.OPENAI.COM/v1/x") is True


def test_subdomain_of_allowed_host_is_still_denied(broker: EgressBroker) -> None:
    # A bare-suffix allowlist would let "api.openai.com.evil.example.com" through;
    # exact matching must deny it.
    assert broker.is_authorized("https://api.openai.com.evil.example.com") is False


def test_bare_host_without_scheme_is_authorized(broker: EgressBroker) -> None:
    assert broker.is_authorized("api.openai.com") is True


def test_empty_allowlist_denies_everything() -> None:
    broker = EgressBroker(EgressPolicy())

    assert broker.is_authorized("https://api.openai.com") is False


def test_policy_from_env_parses_comma_separated_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EVORUNTIME_EGRESS_ALLOWLIST", "a.example.com, b.example.com")

    policy = EgressPolicy.from_env()

    assert policy.allowed_hosts == frozenset({"a.example.com", "b.example.com"})


def test_policy_from_env_defaults_to_empty_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("EVORUNTIME_EGRESS_ALLOWLIST", raising=False)

    policy = EgressPolicy.from_env()

    assert policy.allowed_hosts == frozenset()

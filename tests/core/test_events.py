"""Envelope schema validation tests (spec D2 acceptance: 100% of required
fields validate; malformed events rejected with typed errors)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from evoruntime.core.events import parse_wire_envelope
from tests.support.factories import make_raw_event

REQUIRED_FIELDS = [
    "event_id",
    "occurred_at",
    "tenant_id",
    "agent_id",
    "release_id",
    "trace_id",
    "task_id",
    "type",
    "schema_version",
    "model",
    "environment_digest",
    "cost",
    "data_classification",
]


def test_valid_envelope_round_trips() -> None:
    raw = make_raw_event(0)
    envelope = parse_wire_envelope(raw)
    assert envelope.event_id == raw["event_id"]
    assert envelope.tenant_id == raw["tenant_id"]
    assert envelope.campaign_id is None


@pytest.mark.parametrize("field", REQUIRED_FIELDS)
def test_missing_required_field_is_rejected(field: str) -> None:
    raw = make_raw_event(0)
    del raw[field]
    with pytest.raises(ValidationError) as exc_info:
        parse_wire_envelope(raw)
    errors = exc_info.value.errors()
    assert any(field in error["loc"] for error in errors)


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("event_id", "not-a-valid-id"),
        ("tenant_id", "wrong_prefix_123"),
        ("artifact_digests", ["not-a-digest"]),
        ("environment_digest", "sha256:too-short"),
        ("type", "NoDotsHere"),
        ("schema_version", 0),
        ("data_classification", "top-secret"),
    ],
)
def test_malformed_field_is_rejected(field: str, bad_value: object) -> None:
    raw = make_raw_event(0)
    raw[field] = bad_value
    with pytest.raises(ValidationError):
        parse_wire_envelope(raw)


def test_extra_field_is_rejected() -> None:
    raw = make_raw_event(0)
    raw["unexpected_field"] = "surprise"
    with pytest.raises(ValidationError):
        parse_wire_envelope(raw)


def test_canonical_bytes_is_deterministic_regardless_of_input_key_order() -> None:
    raw = make_raw_event(0)
    reordered = dict(reversed(list(raw.items())))

    envelope_a = parse_wire_envelope(raw)
    envelope_b = parse_wire_envelope(reordered)

    assert envelope_a.canonical_bytes() == envelope_b.canonical_bytes()


def test_canonical_bytes_changes_with_any_field_change() -> None:
    raw = make_raw_event(0)
    envelope_a = parse_wire_envelope(raw)

    raw["cost"]["usd"] = raw["cost"]["usd"] + 1.0
    envelope_b = parse_wire_envelope(raw)

    assert envelope_a.canonical_bytes() != envelope_b.canonical_bytes()

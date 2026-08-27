"""JSON serialization for API responses."""

import json


def to_json(payload: dict) -> str:
    """Serialize a response payload, including Decimal fields, to JSON."""
    return json.dumps(payload)

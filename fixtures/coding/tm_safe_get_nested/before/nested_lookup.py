"""Nested dict lookup for user-provided config paths."""

from typing import Any


def safe_get(data: dict[str, Any], path: list[str], default: Any = None) -> Any:
    """Walk nested dict keys in `path`; return `default` if any key is missing."""
    value: Any = data
    for key in path:
        value = value[key]
    return value if value is not None else default

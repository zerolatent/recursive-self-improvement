"""Errors raised by the lineage store's service-layer API."""

from __future__ import annotations


class LineageError(Exception):
    """Base class for lineage-store errors."""


class LineageNodeNotFoundError(LineageError):
    """Raised when an edge or lookup references a node that doesn't exist."""


class PayloadNotFoundError(LineageError):
    """Raised when reading a payload digest that was never stored."""


class PayloadAccessRevokedError(LineageError):
    """Raised when reading a payload whose access has been revoked.

    Distinguished from `PayloadNotFoundError` so callers (and audits) can
    tell "never existed" apart from "existed, was deleted on request" —
    the deletion flow's whole point is that the second case is provable.
    """


class TombstoneNotFoundError(LineageError):
    """Raised when a sweep or lookup references a tombstone that doesn't exist."""

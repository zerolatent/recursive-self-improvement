"""Timestamp helpers for deadline checks."""

from datetime import datetime


def seconds_until(deadline: datetime, reference: datetime) -> float:
    """Seconds remaining until deadline, from reference. Negative if past."""
    return (deadline - reference).seconds

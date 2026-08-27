from datetime import UTC, datetime

from timestamps import seconds_until


def test_seconds_until_future_deadline():
    reference = datetime(2026, 1, 1, tzinfo=UTC)
    deadline = datetime(2026, 1, 2, tzinfo=UTC)
    assert seconds_until(deadline, reference) == 86400.0


def test_seconds_until_past_deadline_is_negative():
    reference = datetime(2026, 1, 2, tzinfo=UTC)
    deadline = datetime(2026, 1, 1, tzinfo=UTC)
    assert seconds_until(deadline, reference) == -86400.0

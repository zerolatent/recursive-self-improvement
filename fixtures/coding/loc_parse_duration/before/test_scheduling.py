import pytest
from scheduling import bill_usage, parse_duration, schedule_job


def test_parse_duration_supports_hours():
    assert parse_duration("2h") == 7200


def test_schedule_job_supports_hours():
    assert schedule_job("1h") == 3600


def test_bill_usage_supports_hours():
    assert bill_usage("3h") == 10800


def test_parse_duration_still_rejects_unknown_units():
    with pytest.raises(ValueError):
        parse_duration("2d")

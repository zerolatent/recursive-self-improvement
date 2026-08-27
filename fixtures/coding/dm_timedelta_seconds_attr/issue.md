# Bug: a deadline 1 day away reports 0 seconds remaining

`seconds_until` reads `timedelta.seconds`, which is only the sub-day remainder (0-86399), not the whole duration.

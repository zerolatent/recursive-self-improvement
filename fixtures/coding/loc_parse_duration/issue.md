# Bug: scheduling a job for "1h" raises ValueError

`schedule_job` and `bill_usage` both call the shared `parse_duration` helper, which only understands `s` and `m` suffixes. Add `h` support to the helper.

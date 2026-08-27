# Bug: first retry waits 2x base instead of 1x base

`http_client_retry_delay` and `worker_retry_delay` both call the shared `backoff_seconds` helper, which is off by one exponent. Fix the helper.

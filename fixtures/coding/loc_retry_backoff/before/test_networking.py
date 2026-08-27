from networking import backoff_seconds, http_client_retry_delay, worker_retry_delay


def test_backoff_seconds_first_attempt_equals_base():
    assert backoff_seconds(1, base=1.0) == 1.0


def test_backoff_seconds_third_attempt():
    assert backoff_seconds(3, base=1.0) == 4.0


def test_http_client_retry_delay_first_attempt():
    assert http_client_retry_delay(1) == 1.0


def test_worker_retry_delay_first_attempt():
    assert worker_retry_delay(1) == 0.5

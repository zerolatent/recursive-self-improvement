# Bug: p50 latency dashboard shows one raw sample, not the true median

`median` indexes the middle element directly, which is only correct for odd-length inputs.

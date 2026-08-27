# Bug: looking up a missing nested config key crashes the caller

`safe_get` was supposed to return `default` when any intermediate key is missing, but it lets `KeyError` propagate instead.

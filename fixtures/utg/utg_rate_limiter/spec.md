# TokenBucket behavior spec

`TokenBucket(capacity, refill_rate)` is a deterministic rate limiter:

1. Construction with `capacity <= 0` or `refill_rate < 0` raises
   `ValueError`.
2. The bucket starts full: `available == capacity`.
3. `try_acquire(requested, elapsed_s)` first refills:
   `tokens = min(capacity, tokens + elapsed_s * refill_rate)`. Tokens
   must NEVER exceed capacity, no matter how much time passes.
4. If `tokens >= requested` after refilling, the request succeeds and
   tokens decrease by exactly `requested` — an acquire at exactly the
   remaining balance succeeds. Otherwise it returns `False` and tokens
   are unchanged.
5. `requested > capacity` raises `ValueError`: a request the bucket could
   never serve is a caller bug, not a denial.

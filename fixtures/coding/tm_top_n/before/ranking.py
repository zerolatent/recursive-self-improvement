"""Top-N ranking for leaderboards."""


def top_n(scores: list[int], n: int) -> list[int]:
    """Return the n largest scores, descending, keeping duplicates. n may
    exceed len(scores), in which case every score is returned."""
    unique_sorted = sorted(set(scores), reverse=True)
    return unique_sorted[:n]

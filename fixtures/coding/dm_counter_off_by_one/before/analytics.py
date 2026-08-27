"""Word frequency analysis for search analytics."""

from collections import Counter


def top_words(words: list[str], n: int) -> list[str]:
    """Return the n most frequent words, most frequent first."""
    counts = Counter(words)
    return [word for word, _ in counts.most_common()[: n - 1]]

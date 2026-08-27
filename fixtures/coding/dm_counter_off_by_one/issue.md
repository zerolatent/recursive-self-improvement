# Bug: asking for the top 2 search terms returns only 1

`top_words` slices `Counter.most_common()` with `[: n - 1]` instead of `[:n]`.

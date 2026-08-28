# Bug: two players tied for first only show one entry

`top_n` runs scores through `set()` before sorting, which collapses ties instead of keeping every duplicate.

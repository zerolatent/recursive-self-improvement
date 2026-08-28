# Bug: the line count returned is always 0

`write_lines_and_count` opens the file without a `with` block, so the write is never flushed before the immediate read-back.

# Bug: searching for "3.14" also matches "3x14"

`contains_literal` compiles the caller's search term directly as a regex without `re.escape`, so metacharacters like `.` match unintended text.

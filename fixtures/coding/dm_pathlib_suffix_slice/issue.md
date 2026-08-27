# Bug: renaming "report.py" to Markdown produces "repor.md"

`with_extension` strips exactly 4 characters off the filename instead of using `Path.stem`, so it mangles any suffix that isn't exactly 3 characters plus the dot.

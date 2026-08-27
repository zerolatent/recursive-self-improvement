# Bug: exported rows come back alphabetized, not in original order

`export_rows` and `import_rows` both call the shared `dedupe` helper, which sorts instead of preserving first-seen order. Fix the helper.

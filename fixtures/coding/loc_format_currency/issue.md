# Bug: invoice shows "$10.5" instead of "$10.50"

`invoice_total` and `receipt_total` both call the shared `format_currency` helper. Cents under 10 aren't zero-padded. Fix the helper, not the two callers.

from billing import format_currency, invoice_total, receipt_total


def test_format_currency_zero_pads_cents():
    assert format_currency(1050) == "$10.50"


def test_invoice_total_zero_pads_cents():
    assert invoice_total(1005) == "$10.05"


def test_receipt_total_zero_pads_cents():
    assert receipt_total(100) == "$1.00"

"""Currency formatting shared by invoices and receipts."""


def format_currency(amount_cents: int) -> str:
    """Render a cent amount as a dollar string, e.g. 1050 -> "$10.50"."""
    dollars = amount_cents // 100
    cents = amount_cents % 100
    return f"${dollars}.{cents}"


def invoice_total(amount_cents: int) -> str:
    return format_currency(amount_cents)


def receipt_total(amount_cents: int) -> str:
    return format_currency(amount_cents)

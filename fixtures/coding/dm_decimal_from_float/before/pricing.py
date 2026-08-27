"""Price calculations using Decimal for exactness."""

from decimal import Decimal


def apply_discount(price: float, discount_rate: float) -> Decimal:
    """Apply a discount rate (e.g. 0.1 for 10%) to a price, exactly."""
    return Decimal(price) * (Decimal(1) - Decimal(discount_rate))

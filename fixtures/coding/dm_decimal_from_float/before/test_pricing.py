from decimal import Decimal

from pricing import apply_discount


def test_apply_discount_is_exact():
    assert apply_discount(10.0, 0.1) == Decimal("9.0")

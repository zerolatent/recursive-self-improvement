from decimal import Decimal

from serialization import to_json


def test_to_json_serializes_decimal_fields():
    result = to_json({"amount": Decimal("9.99")})
    assert result == '{"amount": "9.99"}'

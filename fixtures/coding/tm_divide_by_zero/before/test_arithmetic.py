import pytest
from arithmetic import safe_divide


def test_safe_divide_normal_case():
    assert safe_divide(10.0, 2.0) == 5.0


def test_safe_divide_raises_on_zero_denominator():
    with pytest.raises(ValueError):
        safe_divide(1.0, 0.0)

import pytest
from config_flags import parse_bool


@pytest.mark.parametrize("text", ["false", "0", "no", "off", "", "  False  "])
def test_parse_bool_recognizes_falsy_strings(text: str) -> None:
    assert parse_bool(text) is False


@pytest.mark.parametrize("text", ["true", "1", "yes", "on"])
def test_parse_bool_recognizes_truthy_strings(text: str) -> None:
    assert parse_bool(text) is True

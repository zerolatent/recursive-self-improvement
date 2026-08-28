from nested_lookup import safe_get

DATA = {"a": {"b": {"c": 1}}}


def test_safe_get_returns_value_when_present():
    assert safe_get(DATA, ["a", "b", "c"]) == 1


def test_safe_get_returns_default_on_missing_intermediate_key():
    assert safe_get(DATA, ["a", "x", "c"], default="missing") == "missing"


def test_safe_get_returns_default_on_missing_leaf_key():
    assert safe_get(DATA, ["a", "b", "z"], default="missing") == "missing"

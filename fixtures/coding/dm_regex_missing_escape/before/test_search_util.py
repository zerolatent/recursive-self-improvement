from search_util import contains_literal


def test_contains_literal_treats_dot_as_literal():
    assert contains_literal("price is 3.14 dollars", "3.14") is True
    assert contains_literal("price is 3x14 dollars", "3.14") is False


def test_contains_literal_handles_special_characters_without_erroring():
    assert contains_literal("cost (estimate)", "(estimate)") is True

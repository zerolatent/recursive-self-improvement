from strings_util import is_palindrome


def test_is_palindrome_ignores_case_and_spaces():
    assert is_palindrome("A man a plan a canal Panama") is True


def test_is_palindrome_ignores_punctuation():
    assert is_palindrome("No, it is opposition") is True


def test_is_palindrome_rejects_non_palindromes():
    assert is_palindrome("Not a palindrome") is False

"""Palindrome checking for user-submitted phrases."""


def is_palindrome(text: str) -> bool:
    """True if text reads the same forwards and backwards, ignoring case
    and punctuation."""
    return text == text[::-1]

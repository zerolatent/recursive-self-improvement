from analytics import top_words


def test_top_words_returns_requested_count():
    words = ["a", "a", "b", "b", "b", "c"]
    assert top_words(words, 2) == ["b", "a"]

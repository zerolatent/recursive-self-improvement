from ranking import top_n


def test_top_n_keeps_duplicate_scores():
    assert top_n([5, 5, 3, 1], 3) == [5, 5, 3]


def test_top_n_handles_n_larger_than_list():
    assert top_n([2, 1], 10) == [2, 1]

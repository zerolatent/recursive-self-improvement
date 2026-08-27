from stats_util import median


def test_median_odd_length():
    assert median([3.0, 1.0, 2.0]) == 2.0


def test_median_even_length_averages_middle_two():
    assert median([1.0, 2.0, 3.0, 4.0]) == 2.5

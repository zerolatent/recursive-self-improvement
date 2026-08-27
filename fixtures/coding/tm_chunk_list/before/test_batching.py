from batching import chunk


def test_chunk_includes_final_partial_chunk():
    assert chunk([1, 2, 3, 4, 5], 2) == [[1, 2], [3, 4], [5]]


def test_chunk_exact_multiple():
    assert chunk([1, 2, 3, 4], 2) == [[1, 2], [3, 4]]

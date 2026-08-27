from exporting import dedupe, export_rows, import_rows


def test_dedupe_preserves_first_occurrence_order():
    assert dedupe(["b", "a", "b", "c", "a"]) == ["b", "a", "c"]


def test_export_rows_preserves_order():
    assert export_rows(["z", "y", "z", "x"]) == ["z", "y", "x"]


def test_import_rows_preserves_order():
    assert import_rows(["1", "2", "1", "3"]) == ["1", "2", "3"]

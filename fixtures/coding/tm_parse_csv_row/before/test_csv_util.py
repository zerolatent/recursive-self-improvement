from csv_util import parse_csv_row


def test_parse_csv_row_splits_plain_fields():
    assert parse_csv_row("a,b,c") == ["a", "b", "c"]


def test_parse_csv_row_respects_quoted_commas():
    assert parse_csv_row('a,"b,c",d') == ["a", "b,c", "d"]

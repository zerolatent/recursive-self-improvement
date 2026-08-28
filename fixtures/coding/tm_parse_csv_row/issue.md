# Bug: `a,"b,c",d` parses as four fields instead of three

`parse_csv_row` does a naive `str.split(",")`, which doesn't know a comma can be inside a quoted field.

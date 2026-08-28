# Bug: any response with a Decimal amount 500s

`to_json` calls `json.dumps` without a `default=` handler, so `Decimal` (used everywhere for money) raises `TypeError`.

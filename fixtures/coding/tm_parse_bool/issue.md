# Bug: setting `DEBUG=false` in config still enables debug mode

`parse_bool` uses Python truthiness on the raw string, so any non-empty text -- including the literal word "false" -- comes back `True`.

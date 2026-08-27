"""Boolean flag parsing for config files."""


def parse_bool(text: str) -> bool:
    """Parse a config string as a boolean flag."""
    return bool(text)

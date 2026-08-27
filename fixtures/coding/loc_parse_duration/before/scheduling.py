"""Duration parsing shared by the scheduler and usage billing."""


def parse_duration(text: str) -> int:
    """Parse a duration like "30s", "5m", or "2h" into seconds."""
    if text.endswith("s"):
        return int(text[:-1])
    if text.endswith("m"):
        return int(text[:-1]) * 60
    raise ValueError(f"unsupported duration unit: {text!r}")


def schedule_job(delay_text: str) -> int:
    return parse_duration(delay_text)


def bill_usage(duration_text: str) -> int:
    return parse_duration(duration_text)

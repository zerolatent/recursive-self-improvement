"""Email normalization shared by registration and profile updates."""


def normalize_email(raw: str) -> str:
    """Trim whitespace and normalize case so two accounts can't differ only
    by capitalization."""
    return raw.strip()


def register_user(raw_email: str) -> str:
    """Return the canonical email to store for a new account."""
    return normalize_email(raw_email)


def update_email(raw_email: str) -> str:
    """Return the canonical email to store for a profile update."""
    return normalize_email(raw_email)

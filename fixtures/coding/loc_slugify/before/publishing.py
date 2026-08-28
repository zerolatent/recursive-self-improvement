"""Slug generation shared by blog posts and wiki pages."""

import re


def slugify(title: str) -> str:
    """Turn a title into a URL slug, e.g. "Hello, World!" -> "hello-world"."""
    lowered = title.strip().lower()
    return re.sub(r"[^a-z0-9]+", "-", lowered)


def blog_url(title: str) -> str:
    return f"/blog/{slugify(title)}"


def wiki_url(title: str) -> str:
    return f"/wiki/{slugify(title)}"

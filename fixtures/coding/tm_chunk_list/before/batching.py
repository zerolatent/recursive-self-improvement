"""Batch chunking for bulk API calls."""


def chunk(items: list[int], size: int) -> list[list[int]]:
    """Split items into chunks of at most `size`, including a short final chunk."""
    return [items[i : i + size] for i in range(0, len(items) - len(items) % size, size)]

"""Config merging shared by service and worker config loaders."""


def merge_dicts(base: dict, override: dict) -> dict:
    """Merge override into base, recursively for nested dicts."""
    merged = dict(base)
    merged.update(override)
    return merged


def load_service_config(base: dict, override: dict) -> dict:
    return merge_dicts(base, override)


def load_worker_config(base: dict, override: dict) -> dict:
    return merge_dicts(base, override)

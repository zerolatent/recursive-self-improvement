"""Entry point for running the evaluation-plane service with uvicorn."""

from __future__ import annotations

import uvicorn


def main() -> None:
    """Run the service via `python -m evoruntime.server` or the
    `evoruntime-server` console script."""
    uvicorn.run("evoruntime.server.app:app", host="0.0.0.0", port=8000)  # noqa: S104


if __name__ == "__main__":
    main()

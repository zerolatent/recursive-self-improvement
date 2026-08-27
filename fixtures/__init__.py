"""Root package marker for the D8 seed evaluation suite.

Lives at the repo root (outside `src/`) because these are data fixtures,
not shipped runtime code; `pyproject.toml` adds `pythonpath = ["."]` to the
pytest config so `fixtures.lib` resolves from `tests/`.
"""

from __future__ import annotations

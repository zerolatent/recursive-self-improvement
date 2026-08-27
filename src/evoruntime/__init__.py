"""EvoRuntime — governed self-improvement runtime and control plane.

Subpackages:
    core   — shared schemas and types used across the runtime.
    server — the FastAPI evaluation-plane service.
    sdk    — the agent adapter SDK (trace emission, outcome attestation).
    eval   — the evaluation harness (experiment arms, statistics).
    db     — SQLAlchemy models, session management, and Alembic migrations.
"""

__version__ = "0.1.0"

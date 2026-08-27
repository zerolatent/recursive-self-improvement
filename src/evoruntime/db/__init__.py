"""SQLAlchemy models, session management, and Alembic migrations.

Phase 0 ships the connection/session scaffolding and an empty baseline
migration. Domain tables (events, payloads, tombstones, lineage
nodes/edges, dataset partitions, holdout handles, the holdout query
ledger) land with deliverables D2, D4, and D5.
"""

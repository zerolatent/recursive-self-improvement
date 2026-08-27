"""The FastAPI evaluation-plane service.

This is the trusted evaluation-plane surface (PRD §18.2): the only network
entrypoint into trace ingest, dataset partitions, and the evaluation
harness. Phase 0 ships the service skeleton; ingest and dataset endpoints
land with deliverables D2 and D5.
"""

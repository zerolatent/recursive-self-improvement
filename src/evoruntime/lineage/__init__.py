"""The lineage store (deliverable D4): append-only provenance nodes/edges,
tenant-key-encrypted payloads, and the tombstone-driven deletion flow.

`evoruntime.db.models.lineage` holds the ORM tables; this package holds the
service-layer API (`LineageService`, `PayloadStore`, `DeletionService`) that
the trace ingest API (D2) and later evolution-plane components call.
"""

from __future__ import annotations

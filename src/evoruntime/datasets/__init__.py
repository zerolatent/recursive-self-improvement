"""Dataset partitions, sealed holdout handles, and the append-only query ledger.

Deliverable D5 of Phase 0. The trust boundary lives in
`evoruntime.datasets.service`: holdout content is reachable only through
`HoldoutService.resolve`, only by an evaluation-plane principal, and every
attempt — granted or denied — leaves a ledger row.
"""

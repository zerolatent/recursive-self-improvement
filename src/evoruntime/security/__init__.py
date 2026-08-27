"""Security scaffolding for the evaluation plane (deliverable D7).

Everything Phase 1 plugins inherit lives here: first-class workload
identities, the policy checks that separate the evaluator role from the
candidate-runner role, the deny-by-default egress broker, and the ed25519
signing service used for release manifests and outcome attestations.

See ``docs/threat-model.md`` for the trust model these primitives enforce.
"""

from __future__ import annotations

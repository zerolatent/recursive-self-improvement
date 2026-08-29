# Campaign spec v3 — scaffold mutation surface (G3)

Phase 3 bumps the campaign-spec schema to **v3**. This document is the
authoring guide for the new surface; the enforcement lives in
`src/evoruntime/campaign/spec.py`.

## What v3 adds

v2 (Phase 2, F4) made the mutation surface a `MutableArtifactSet`. v3
adds the scaffold mutation research surface on top of it:

1. **Scaffold-mutable sets.** A v3 spec's mutable artifact set may
   contain the `SCAFFOLD` artifact class (G1) — the campaign may mutate
   the runtime's own source.
2. **Mandatory environment claim.** When the mutable set contains the
   scaffold class, the spec must declare `environment: research`. The
   field itself is G6's tenant plane (`TenantEnvironment`: `research` |
   `production`), but a scaffold-mutable spec is refused unless the
   claim is present and equal to `research` — scaffold mutation is a
   research-tenant activity, and the claim is part of the signed
   preregistration, not a runtime setting.
3. **Pinned mutation classes.** A scaffold-mutable spec must also pin a
   non-empty `mutation_classes` section — the classes of change its
   strategy may propose, each bound to a signed risk dossier and the
   isolation tier the class demands:

   ```yaml
   environment: research
   mutation_classes:
     - class_id: prompt_module_edit
       risk_dossier_digest: sha256:…   # signed dossier; G10 consumes
       max_tier: executable
     - class_id: control_flow_change
       risk_dossier_digest: sha256:…
       max_tier: highest
   ```

   A scaffold spec without `environment: research`, or without pinned
   mutation classes, fails at parse — before any pinning or execution.

## Pin-and-sign covers the new fields

`environment` and `mutation_classes` are part of the canonical form, so
the digest (and the evaluator's detached signature over it) binds them.
A spec whose environment claim or mutation classes changed after
pinning no longer verifies — the orchestrator refuses to run it.

## Migration windows

Older documents are accepted only inside dated windows and are upgraded
to the v3 shape at parse time, so a v1 or v2 document and the equivalent
v3 document pin to the **same digest**:

| Document version | Accepted until       | Upgraded shape |
|------------------|----------------------|----------------|
| 1                | `V1_MIGRATION_WINDOW_END` — 2026-10-27 | v3 |
| 2                | `V2_MIGRATION_WINDOW_END` — 2026-10-28 | v3 |
| 3                | current              | — |

Both windows are sixty days after the respective release branch was cut
(Phase 2: 2026-08-28; Phase 3: 2026-08-29). After a window closes, that
version is refused: the window is for authoring migration, not a
permanent dual-format license.

Note that v1 and v2 documents carry no environment claim and no mutation
classes — they cannot declare a scaffold-mutable set, so the scaffold
gate cannot fire for them; the gate applies to documents authored as v3.

One deliberate divergence from G6's canonical-form convention: the
environment claim is **always** serialized into the canonical form
(`null` for documents that predate it), so the digest binds the claim
for every v3 spec — a spec whose environment claim changed after
pinning no longer verifies.

## Storage-layer immutability

Migration `b5c7e2a9d4f1` adds a `BEFORE UPDATE OR DELETE` trigger on the
`campaigns` table guarding the pinned spec columns (`spec_digest`,
`spec_canonical`, `spec_signature`, `signer_public_key`). A stored spec
edited after pinning is a forgery; lifecycle columns (`phase`,
`resume_target`) remain mutable.

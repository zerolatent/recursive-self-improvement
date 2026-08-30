# §21 product decisions — ruling record

**Ruling date:** 2026-08-30
**Authority:** The PRD's §21 ("Open product decisions") listed seven choices
that had to be resolved before beta, each with a proposed default and a
GA-gating condition. The ruling on all seven was **user-delegated to the
orchestrator**; this document records the rulings as made. They are product
policy, not engineering preference: each entry states the ruling, the
rationale, the reversal condition (the evidence that would reopen it), and
the implementation surface it maps to.

Decisions 5 and 7 are codified as signed seed policy documents on the
`feat/s21-policy-seed` branch — the §21 policy seed PR. Until that PR
merges, this document is the prose record of the ruling and the seed
documents are the executable form of decisions 5 and 7.

Nothing here changes code by itself. Where a ruling maps to a surface that
does not exist yet, the mapping is the contract that surface must satisfy
when it lands.

---

## 1. Initial customer: internal platform teams first

**Ruling.** The first customer of EvoRuntime is the organization's own
internal platform teams. External vendors are not a beta target.

**Rationale.** The runtime's guarantees (attested outcomes, append-only
decision records, holdout evaluation) are strongest when the operator and
the governed agent share a trust boundary — the internal customer can be
onboarded with the fixture agent, exercised through the §17.1 reference
workflow, and corrected in place without a contractual escalation path.
Every Phase 4 onboarding drill (H12's timed scenarios) was built against
exactly this customer shape.

**Reversal condition.** A vendor partner appearing early — a real external
party with a signed intent to integrate before the internal rollout
completes. That changes the onboarding surface (tenant provisioning,
contractual audit exports) and reopens this decision.

**Implementation surface.** No code. Tenant onboarding sequencing and the
beta go-to-market plan; the tenancy plane
(`evoruntime.tenancy`, `TenantPolicyDocument`/`TenantPolicyRegistry`)
already treats tenants as policy data, so an external tenant is a policy
document, not a schema change.

## 2. Harness adapters: provider-neutral protocol only for beta

**Ruling.** For beta, the harness story is the provider-neutral protocol
only. The SDK adapter is the contract; the fixture agent is harness #1;
the transfer fixtures already exercise a second harness/model family.
Adapting external agent frameworks (LangChain, OpenAI agents, etc.) is
post-beta work.

**Rationale.** A second adapter format before beta would split the
attestation path — every harness that records traces through a different
adapter is a separate place where the digest chain and the attestation
contract can drift. The provider-neutral protocol keeps one contract, and
the transfer fixtures already prove the protocol is not
harness-specific. Framework adaptation is integration labor, not a
protocol change; it can wait without invalidating anything.

**Reversal condition.** The internal customer (decision 1) runs a
commercial agent day-to-day. At that point the SDK adapter stops being
the only contract that matters and a framework adapter becomes a beta
requirement, not a post-beta one.

**Implementation surface.** `evoruntime.sdk` (the adapter SDK, D3) and the
fixture agent (`tests/fixture_agent/`); transfer fixtures exercise the
second harness/model family. No new surface for beta.

## 3. Artifact format: keep the native EvoRuntime envelope

**Ruling.** Artifacts stay in the native EvoRuntime envelope — the
digest-pinned canonical forms that all five validation layers already
consume. An import shim for external skill-package conventions is built
only on customer demand, and only as a shim at the boundary.

**Rationale.** The envelope is load-bearing across the registry (E1), the
plugin protocol (E2), signed packaging, the mutation archive (G1), and
the release pointer chain — five layers pin digests of canonical forms.
Translating external conventions into first-class formats would put a
second canonical form inside that chain, and every digest-pinning
guarantee would need re-deriving per format. A boundary shim keeps the
foreign convention outside the trust boundary.

**Reversal condition.** Bulk skill-package import demand — a customer
whose workflow is built around an external package convention importing
at volume. A shim that is exercised in bulk is a de facto second format;
at that point the format question reopens.

**Implementation surface.** The artifact registry (E1) and plugin
packaging (E2); the canonical-form discipline in
`evoruntime.core`/`evoruntime.artifacts`. No change for beta.

## 4. Evaluator ecosystem: privileged tenant extensions only, no marketplace

**Ruling.** Evaluators are privileged tenant extensions. There is no
evaluator marketplace at beta and none at GA. A marketplace would need
its own threat-model addendum before it could even be considered.

**Rationale.** The evaluator is the trust anchor of the whole outcome
story: it holds the pristine grader, signs attestations with its own
identity, and its access to holdout data is gated by
`evoruntime.security.policy` to the evaluator role alone. A marketplace
turns that trust anchor into third-party supply — arbitrary code in the
most privileged position in the runtime — and the existing threat model
(`docs/threat-model.md`) does not cover that supply chain. Ruling it out
is not a product preference; it is the current threat model's boundary.

**Reversal condition.** A completed marketplace threat-model addendum. If
that addendum exists and is accepted, the decision reopens on its terms —
not before.

**Implementation surface.** `evoruntime.security.policy` (evaluator-role
gating), the evaluator identity in `evoruntime.security.identities`, and
the plugin admission gates (E2). No marketplace surface is built.

## 5. Approval defaults (GA-gating): production policy mirrors tested behavior

**Ruling.** At GA, production approval policy mirrors the behavior the
conformance suite actually tests:

- **Tier-1 / tier-2:** auto-eligible post-canary.
- **Tier-3:** two-person review.
- **Tier-4:** the full conjunction, and research-tenant-only until G10
  graduation.
- **Regulated tenants:** no auto-promotion at any tier; tier-3 review for
  everything.

**Rationale.** The Phase 4 conformance matrix (H12) already exercises
exactly this shape — canary admission restricted to tier-1/tier-2 release
classes, tier-3 executables refused from canary, tier-4 reachable only
inside research tenants, and graduation (G10) as the recorded,
comparable-risk path out. Policy that mirrors tested behavior means the
approval defaults are covered by passing evidence on day one instead of
being a new, untested configuration. Regulated tenants get the strict
variant because "no auto-promotion" is the only default that does not
depend on canary telemetry being admissible evidence in the tenant's
regulatory context.

**Reversal condition.** Tier-3 review latency blocking first-campaign
iteration velocity — if two-person review becomes the bottleneck that
stops the first internal customer from iterating, tier-1 relaxes to
auto-promote with post-hoc audit. Tier-2/3/4 and the regulated-tenant
defaults do not move under this condition.

**Implementation surface.** G6/G7 — `TenantPolicyDocument` and
`TenantPolicyRegistry` (`src/evoruntime/tenancy/policy.py`), codified as
signed seed policy documents in the §21 policy seed PR. The document
validation already refuses a production tenant pinning tier-4-allowing
defaults at construction, which is the enforcement this ruling relies on.

## 6. Economic objective: task success under fixed budget

**Ruling.** The beta-default economic objective is task success under a
fixed budget. The H5 Pareto frontier is operator visibility, not the
optimizer. A per-tenant utility frontier is available later, when a
customer's utility function is stable enough to preregister.

**Rationale.** A multi-objective optimizer optimizes whatever its weights
say, and weights are the easiest place for an operator's intent and the
runtime's behavior to silently diverge. Task-success-under-budget is a
single, legible objective that matches how the evaluation harness (D6)
already runs matched-budget arms, so the objective and the measurement
agree by construction. The Pareto archive (H5) stays — as the surface
where operators *see* the trade space over attested metrics — but nothing
selects from it automatically. Preregistration is the bar for a per-tenant
utility function because a utility function invented after seeing results
is curve-fitting, not optimization.

**Reversal condition.** A preregistrable stable utility function — a
tenant that can write its utility function down before campaigns run and
keep it stable across them. That tenant gets a per-tenant utility
frontier; the beta default does not change for anyone else.

**Implementation surface.** The evaluation harness (D6, matched-budget
arms), the H5 Pareto archive (`src/evoruntime/selection/pareto_archive.py`)
in its visibility role, and H10's product-outcome metrics
(`src/evoruntime/eval/power.py`). No optimizer change for beta.

## 7. Retention (GA-gating): evidence outlives payloads

**Ruling.** Retention policy at GA separates the evidence substrate from
the payload substrate:

- **Traces:** 90 days.
- **Payloads:** 30 days, unless lineage-referenced — a payload referenced
  by a lineage node follows that node's lifetime, not the 30-day clock.
- **Attestations, admission records, ledger rows, tombstones:** indefinite.
  These are the evidence substrate; the append-only records that decisions
  reconstruct from do not age out.
- **Crypto-erasure:** derived data within 24 hours; backups within 30
  days.

**Rationale.** The runtime's core claim is that every decision can be
reconstructed from append-only records — the §13.1 milestone scenarios and
the H12 conformance pass both depend on it. A retention clock on
attestations or ledger rows would put an expiry date on that claim, so
evidence is retained indefinitely while bulky, reconstructable payload
bytes age out on a schedule. The lineage exception exists because a
lineage-referenced payload is itself evidence — it is the registered
bytes a node's digest pins, and deleting it under a blanket 30-day rule
would break digest verification for surviving nodes. The erasure SLOs are
not new: they are the D4 deletion flow's existing deadlines (access
revocation ≤5 min, derived-data purge ≤24 h) plus the backup tier's
30-day tombstone-coverage guarantee.

**Reversal condition.** A regulated customer requiring *shorter* evidence
retention than payload retention — i.e. a jurisdiction where keeping
attestations indefinitely is itself a compliance violation. The retention
matrix is expressed as policy data precisely so it can be inverted
per-tenant in that case; the default does not change.

**Implementation surface.** D4 — the tombstone/erasure machinery
(`src/evoruntime/lineage/`: `deletion.py`, `purge.py`, `backup.py`) as
policy data, codified in the §21 policy seed PR. The erasure SLOs
(24 h derived / 30 d backups) already exist as `LineageSettings` knobs;
the ruling pins their GA values and adds the trace/payload/evidence
lifetime matrix as tenant-keyed policy.

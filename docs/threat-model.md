# EvoRuntime threat model — Phase 0 scope

> Adapts the PRD's threat model (§13.1) to what Phase 0 actually ships: a
> trace pipeline, sealed dataset partitions, and a matched-resource
> evaluation harness. No optimizer plugins, campaign state machine,
> artifact registry, release controller, or canary exist yet (PRD §19) —
> so several PRD-level adversaries and assets below are **not yet
> reachable** and are marked accordingly. This document is re-scoped as
> Phase 1 lands the components those adversaries actually target.

## 1. Trust planes

The PRD's full architecture separates five trust planes (runtime,
evolution, execution, evaluation, authority). Phase 0 implements two of
them as first-class, separately-identified workloads, and the rest are
deferred:

| Plane | Phase 0 status | Identity |
| --- | --- | --- |
| **Evaluation** | Implemented | `WorkloadRole.EVALUATOR` — runs the harness, resolves holdout handles, holds signing keys |
| **Execution** (candidate runner) | Implemented | `WorkloadRole.CANDIDATE_RUNNER` — runs the incumbent/retry/one-shot arms under test |
| **Runtime** | Not yet built | The production agent serving real users — Phase 1+ |
| **Evolution** | Not yet built | Optimizer plugins that propose candidates — Phase 1 (PRD §19) |
| **Authority** | Not yet built | Release controller / canary / promotion — Phase 1 (PRD §19) |

The one invariant Phase 0 exists to enforce: **the evaluation plane is a
distinct security identity and storage boundary from candidate execution,
from the first commit** (spec's boundary invariant, PRD §8.1/§18.2).
Retrofitting this separation after an optimizer plugin exists to exploit
its absence is the expensive kind of refactor — hence building it now,
before there is anything to protect except the harness itself.

## 2. Assets

| Asset | Why it matters | Phase 0 protection |
| --- | --- | --- |
| **Holdout dataset content** | The only thing that makes a promotion decision meaningful; if a candidate (or its author) can read it, every eval score becomes gameable | `require_holdout_access` gates resolution to the evaluator role only (`src/evoruntime/security/policy.py`) |
| **Evaluator signing keys** | Back every release manifest / outcome attestation; if a candidate can sign its own "success", the evaluation plane's verdicts are worthless | `require_evaluator_key_access` gates key loading to the evaluator role; keys never live in code or fixtures (`src/evoruntime/security/signing.py`) |
| **Trace/event data (in transit and at rest)** | Contains task inputs, model outputs, tool call args — potential PII, secrets, proprietary code (D2, not this PR) | Out of scope for D7; covered by D2's hash-chained ingest and D4's payload encryption/deletion |
| **Outbound network egress from candidate execution** | A candidate that can reach arbitrary hosts can exfiltrate holdout content it never should have had, or call unapproved services | `EgressBroker` denies any destination not on an explicit allowlist (`src/evoruntime/security/egress.py`) |
| **Release manifests / outcome attestations** | The record a promotion decision is made from (D3/Phase 1 build these; D7 supplies the primitive) | Ed25519 detached signatures; verification fails on any byte change of the signed payload |

## 3. Adversaries

| Adversary | Capability assumed | Reachable in Phase 0? | Mitigation |
| --- | --- | --- | --- |
| **A candidate under evaluation** (the incumbent, a retry arm, or — once Phase 1 lands — an optimizer-produced candidate) | Executes arbitrary code within its sandbox; may attempt to read files, call the evaluation-plane API, or reach arbitrary network hosts | **Yes** — Phase 0's harness already runs the `incumbent`/`retry-self-consistency`/`one-shot-control` arms | Workload identity separation denies it evaluator-only resources even if it reaches the API; egress broker denies undeclared network destinations |
| **A compromised or buggy optimizer plugin** proposing a malicious "improvement" | Could smuggle a trace/artifact designed to exfiltrate holdout content via a crafted candidate | **No** — no optimizer plugins exist yet (deferred to Phase 1, PRD §19) | Identity separation is built now so Phase 1 optimizer plugins inherit it rather than needing a retrofit |
| **An external attacker on the network** | Attempts to reach the ingest API or harness from outside the deployment | Partially — the FastAPI service exists (D1) but has no auth/network policy yet | Deferred: network-level ingress controls are an infra/deployment concern, not in D7's scope (identity, egress, signing, threat model) |
| **A party who obtained a stale or leaked signature** | Tries to replay an old attestation against a modified payload | **Yes** — signing primitives exist now | `verify()` checks the exact payload bytes against the exact signature; any byte change fails verification (tested: `tests/test_security_signing.py`) |
| **An insider misconfiguring the deployment** (e.g. running a candidate sandbox with `EVORUNTIME_WORKLOAD_ROLE=evaluator`) | Accidentally grants candidate code evaluator privileges | **Yes** — this is a real Phase 0 risk | `identity_from_env()` defaults to the least-privileged role (`candidate-runner`) when the role env var is unset, so a missing configuration fails closed, not open. Setting the wrong role explicitly is an operational control this PR cannot solve technically — deployment config review is on the operator |

## 4. What ships in this PR vs. what's deferred

### Shipped (D7)

- **Workload identity separation** — `WorkloadRole` (`evaluator` /
  `candidate-runner`) as a first-class Pydantic model, sourced from
  environment configuration (`src/evoruntime/security/identities.py`).
- **Policy checks** — `require_holdout_access` and
  `require_evaluator_key_access`, both deny-by-default
  (`src/evoruntime/security/policy.py`). Policy test proves a
  candidate-runner identity is denied both.
- **Egress broker** — deny-by-default host allowlist; no network I/O of
  its own, so it composes with whatever transport a real deployment uses
  (`src/evoruntime/security/egress.py`).
- **Signing service** — Ed25519 detached signatures via `cryptography`;
  key loading gated by `require_evaluator_key_access`; keys sourced from
  an environment variable that a real deployment backs with the secrets
  store, never a hardcoded default (`src/evoruntime/security/signing.py`).
- **This document.**

### Explicitly deferred (not this PR)

- **Enforcement wiring into D5's holdout handles and D2's ingest API** —
  D7 ships the policy *primitives*; D5 (dataset partitions, not yet
  merged) and D2 (trace ingest) are responsible for calling
  `require_holdout_access` / `require_evaluator_key_access` at their own
  API boundaries once those boundaries exist. This PR's fixture proves the
  primitive works; it does not retrofit D2/D5 code that doesn't exist on
  this branch yet.
- **Real authentication** that produces a `WorkloadIdentity` — Phase 0
  trusts environment configuration to declare a workload's role. A real
  deployment needs a verifier that turns a signed service-account token or
  mTLS certificate into a `WorkloadIdentity`, not a `WorkloadIdentity`
  constructed from an unauthenticated env var. This is infra/deployment
  scope, not a Phase 0 deliverable.
- **Network-level enforcement of the egress allowlist** — the broker
  authorizes a destination; it does not itself sit in the network path.
  Wiring it into a real proxy or sandbox network namespace is part of
  whatever executes candidate code, which Phase 0 does not build.
- **Key rotation and multi-key custody** — Phase 0 loads a single
  evaluator key from one environment variable. Rotation policy, multiple
  active keys, and revocation are Phase 1 concerns (the PRD's release
  controller owns key lifecycle).
- **DLP / secret-scanning of trace payloads (PRD FR-015)** — deferred to
  Phase 1 per the pinned spec's scope section; only matters once optimizer
  plugins first touch trace content.
- **Canary release / promotion machinery (PRD FR-012)** — Phase 1 (PRD
  §19); nothing to sign a release manifest *for* yet.
- **10M-events/day and 1,000-concurrent-execution load targets (PRD §17.3
  MVP-load row)** — deferred to a dedicated scale profile per the pinned
  spec's scope section; this threat model addresses correctness under
  adversarial input, not scale.

## 5. Residual risk accepted for Phase 0

Phase 0's identity model trusts that the deployment correctly labels each
process's `EVORUNTIME_WORKLOAD_ROLE`. There is no cryptographic binding
between "this process is actually the evaluation-plane service" and "this
process claims to be evaluator" — that binding is exactly the "real
authentication" item deferred above. This is an accepted risk for a
phase whose goal is proving the evaluation harness works, not shipping a
production security perimeter; it must be closed before any Phase 1
component (optimizer plugins, promotion) that acts on a candidate's
behalf goes live outside a fully trusted, single-operator environment.

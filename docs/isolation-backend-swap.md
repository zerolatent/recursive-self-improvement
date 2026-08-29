# Isolation-backend swap runbook (H9)

How to swap the reference isolation backend (`SubprocessIsolationBackend`)
for a production microVM backend (gVisor, Firecracker) — a documented,
testable seam, not a code change to the sandbox plane. The spec locks the
principle: *sandbox depth is a protocol, not a product*.

## The seam

`src/evoruntime/sandbox/selection.py` owns backend selection:

```
EVO_ISOLATION_BACKEND=<name>  →  resolve_isolation_backend()  →  IsolationBackend
```

- **Environment variable:** `EVO_ISOLATION_BACKEND` (the `EVO_*` convention
  used by the CLI connection profile). Unset or empty selects the default,
  `reference`.
- **Resolution:** `resolve_isolation_backend(environment=None, *, payloads,
  checkpoints)` — `None` reads the env var. This is the single
  construction point; the H4 execution worker calls it once, at
  construction. Nothing else in production code should instantiate a
  backend directly.
- **Fail-closed, both directions:**
  - An *unknown* name refuses with `BackendSelectionError` (the error
    lists the registered names). A typo like `subprocess` or `gvisor`
    never silently falls back to the reference backend.
  - A *known but unavailable* backend refuses at construction — the
    reference factory probes `physical_enforcement_available()` and raises
    `IsolationUnavailableError` on a host without seccomp + Landlock. The
    runtime never constructs a backend that would have to degrade at run
    time.
- **Registry:** `register_isolation_backend(name, factory)` registers a
  production backend at process start; `known_backend_environments()`
  lists what is selectable. Re-registering a name replaces its factory
  (last registration wins), so a deployment can swap in an instrumented
  variant for a soak run.

Selection policy is pinned by `tests/sandbox/test_backend_selection.py`.

## What a microVM backend must implement

The contract is small and honest — one method plus truthful records:

1. **`run(ExecutionRequest) -> ExecutionResult`** honoring the request and
   result shapes: stage the declared payloads, execute `command` under the
   profile's tier semantics, return stdout/stderr/duration plus the
   digest-bound attestation.
2. **Physical enforcement of the tier semantics** — never advisorial:
   - `TEXT_ONLY` never executes (refuse).
   - No-network tiers deny network dials physically (VM network config,
     not convention).
   - Filesystem containment holds (VM boundary); declared
     `writable_paths` zones are enforced or the run refuses.
   - Resource ceilings are enforced at the VM level.
   - A tier whose semantics the backend cannot enforce is *refused*
     (`ExecutionRefusedError`), never approximated — the fail-closed
     pattern the reference backend uses for missing platform mechanisms.
3. **A truthful `EnforcementRecord`** — descriptive, never aspirational:
   - `filesystem_contained=True` by VM boundary only if writes outside the
     workspace are actually impossible.
   - `syscall_denylist` per the backend's own profile (empty if it does
     not apply one — never copy the reference's list).
   - A **new `TierEnforcement` member** (the G5 convention —
     `tier_enforcement="reference"` already distinguishes the reference
     backend). Add e.g. `MICROVM = "microvm"` to the enum in
     `sandbox/profile.py` and record it.
   - Truthful negatives matter as much as truthful positives: the
     conformance kit cross-checks every claim against observed behavior.

## What the backend gets for free

Composed *around* the protocol — the backend factory wires them in, it
does not reimplement them:

- **Staging** — `StagedWorkspace.stage()` + the E1 `PayloadReader`:
  digest-verified candidate bytes, traversal-safe path validation.
- **Capture** — digest-verified extraction of `capture_paths` before
  teardown; re-staging reproduces the digest (proposed = executed =
  registered bytes).
- **Attestation persistence** — the `CheckpointStore` content-addresses
  the attestation bytes; the digest binds image, tier, denials, captured
  outputs, and exit together.
- **Egress policy vocabulary** — `EgressPolicy` (exact-match host
  allowlist, deny-by-default) and the denial record shape.

## What must NOT leak into the protocol

These are reference-backend internals. A microVM backend that reaches for
them is coupling to the wrong layer:

- **The pre-exec chain** (`_child_setup`): rlimits → netns → Landlock →
  seccomp are Linux-syscall work *inside the spawned child*. Correct for
  the reference backend, irrelevant to a VM. The protocol carries the
  *requirements* (the profile), not the mechanisms.
- **The in-process proxy**: `EgressBrokerProxy.serve()` runs on the parent
  thread and hands the child a `http_proxy` env var. A microVM backend
  needs the broker reachable *from the guest* — preserve the proxy-URL
  env-var contract (`http_proxy`/`https_proxy`/`all_proxy` pointing at the
  broker) as the seam, but the in-process serving loop is not part of the
  protocol.
- **`Popen` pipes and `MAX_CAPTURED_OUTPUT_BYTES`**: output capture via
  subprocess pipes is a mechanism; the protocol result shape (`stdout`,
  `stderr` strings) is the contract.

## Inheriting the evidence: the conformance kit

`tests/sandbox/conformance_kit.py` is parameterized over the protocol —
it never imports or isinstance-checks the reference backend. A backend
under test is supplied as a factory that receives the scenario's payload
blobs and returns a constructed backend wired to the kit's checkpoint
store.

The kit's ten checks: TEXT_ONLY refusal, benign-run attestation (digest
roundtrip), network-dial denial, filesystem-escape denial, memory-bomb
denial, staging digest-mismatch abort, capture round-trip digest
verification, write-zone escape denial, brokered-posture honesty (mediate
through a proxy **or** refuse the tier — running brokered egress
unmediated fails the kit), and attestation honesty (every claimed
mechanism matches observed behavior; `tier_enforcement` names the class
that ran).

A new backend inherits the evidence in three steps:

```python
# 1. Add its TierEnforcement member (G5 convention) in sandbox/profile.py.
# 2. Register the factory at process start:
from evoruntime.sandbox import register_isolation_backend

register_isolation_backend(
    "microvm", lambda payloads, checkpoints: FirecrackerIsolationBackend(
        payloads=payloads, checkpoints=checkpoints
    )
)
# 3. Run the kit against it:
from tests.sandbox.conformance_kit import ConformanceKit, run_conformance_kit

kit = ConformanceKit(
    lambda blobs: build_microvm_backend(blobs, checkpoints),
    checkpoints=checkpoints,
    expected_tier_enforcement=TierEnforcement.MICROVM,
)
run_conformance_kit(kit)  # raises on the first violation
```

Then set `EVO_ISOLATION_BACKEND=microvm` in the deployment. The
selection-seam tests (`tests/sandbox/test_backend_selection.py`) pin the
fail-closed policy; the kit tests
(`tests/sandbox/test_conformance_kit.py`) demonstrate the parameterization
by running the same kit against the reference backend and a second stub
backend.

## Verification checklist for a swap

- [ ] Backend registered under its environment name; `EVO_ISOLATION_BACKEND`
      set in the deployment.
- [ ] `resolve_isolation_backend` returns the new backend at the execution
      worker's construction (fail-closed on unknown names).
- [ ] Conformance kit passes with the backend's own
      `expected_tier_enforcement`.
- [ ] `EnforcementRecord` states only mechanisms the backend actually
      applies (the kit cross-checks claims against the escape corpus).
- [ ] Attestation digests still round-trip through the checkpoint store.

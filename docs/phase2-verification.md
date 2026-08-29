# EvoRuntime Phase 2 — Conformance Verification Report

**Branch:** `test/f12-phase2-conformance` (based on `release/evoruntime-phase2-workflow-executable-20260828-213500` @ `6499d36`)
**Date:** 2026-08-29
**Scope:** Full acceptance matrix from the Phase 2 spec (deliverables F1–F11), executed on the integrated release branch, plus the F12 integrated conformance pass: six end-to-end scenarios in `tests/conformance/test_phase2_campaigns.py`.

## Headline result

**All acceptance criteria have passing evidence.** Local run on the integrated release branch against a real PostgreSQL 17 instance: **1444 passed, 0 failed** (1438 pre-existing + 6 new F12 conformance tests), `ruff check` clean, `ruff format --check` clean, `mypy --strict` clean across 172 source files, and the Alembic upgrade/downgrade round-trip green.

## How the matrix was run

- **Integrated branch:** every F1–F11 deliverable is merged into the release branch (`6499d36` is the F9 tip); this report verifies the *integrated* state, not per-PR states.
- **PostgreSQL-backed tests:** all DB-dependent tests (registry, approval flows, compensation plans, analysis reports, productivity projection, migrations) ran against a real PostgreSQL 17 instance locally; CI runs the same suite against its `postgres` service container. The suite skips — rather than fakes — when no database is reachable, so a green run here means the integration tests actually ran.
- **F12 conformance suite:** `tests/conformance/test_phase2_campaigns.py` drives the real services end to end — the F1 sandbox (subprocess + seccomp + Landlock), the F3 static-analysis gate, the F4 multi-artifact registry, the F5 compensation gate, the F6 cascade evaluator bindings, the F8 ablation machinery, the F9 productivity projection, the F10 approval workflow with two-person tier-3 semantics, and the E5 release controller/canary — over real PostgreSQL. The only simulated input is evaluation *data* (paired scores, metrics): CI is hermetic by design, with no live-model runs.
- **Physical sandbox enforcement:** the F1 scenarios in the conformance suite require seccomp + Landlock (Linux); they are marked skip elsewhere, matching the existing sandbox-suite discipline.

## Acceptance matrix

### F1 — Sandbox: executable candidates run only under a declared tier (physical, not advisory)

| Criterion | Evidence | Result |
|---|---|---|
| Escape-attempt corpus denied per tier | `tests/sandbox/test_escape_corpus.py` — network dial: `TestNetworkDialEscape::test_direct_dial_denied`, brokered dial mediated through the proxy: `test_brokered_dial_through_proxy_is_mediated`; filesystem escape: `TestFilesystemEscape::test_write_outside_workspace_denied`; resource bombs: `TestResourceBomb::test_memory_bomb_denied`, `test_cpu_bomb_killed_by_rlimit`; tier refusal: `TestBenignRun::test_text_only_tier_refuses_to_execute` | ✅ pass |
| Egress denial is recorded and mediated | `tests/sandbox/test_egress_proxy.py` — `TestEgressBrokerProxy::test_denied_host_gets_403_and_is_recorded`, `test_allowed_host_connects_to_upstream`, `test_non_connect_method_denied`, `test_deny_all_default_records_denial` | ✅ pass |
| Attestation digest binds image + tier + denials; staging integrity | `tests/sandbox/test_escape_corpus.py::TestStagingIntegrity::test_digest_mismatch_aborts_before_execution`; tenant scoping: `TestTenantIsolation::test_payload_reader_scopes_by_tenant`; benign attestation: `TestBenignRun::test_benign_candidate_executes_and_attests` | ✅ pass |
| Tier/network cross-checks refuse mismatched declarations | `tests/sandbox/test_manifest_tier.py::TestTierCrossChecks` — `test_explicit_executable_tier_with_brokered_network_rejected`, `test_brokered_tier_requires_brokered_network_and_hosts`, `test_text_only_tier_cannot_request_model_access`, `test_default_tier_is_executable` | ✅ pass |
| Integrated: sandboxed dev-evaluate inside the executable campaign | `tests/conformance/test_phase2_campaigns.py::test_executable_campaign_tool_spec_completes_propose_to_promote` — the candidate's script runs under `IsolationTier.EXECUTABLE` through the real `SubprocessIsolationBackend`, with a signed execution attestation landing in the evidence chain | ✅ pass |

### F2 — Types + tiers: new artifact classes resolve to their PRD §13.3 tiers

| Criterion | Evidence | Result |
|---|---|---|
| Tier resolution per new class | `tests/selection/test_phase2_tier_gate.py::TestTierResolutionPerNewClass` — `test_tier3_classes_resolve_to_tier3`, `test_harness_patch_resolves_to_tier4`, `test_mixed_release_tiers_at_the_maximum`, `test_executable_content_trigger_still_dominates` | ✅ pass |
| Tier 3 unreachable without two-person approval | `tests/selection/test_phase2_tier_gate.py::TestTier3TwoPersonApproval` — `test_rejected_without_any_approval`, `test_rejected_with_a_single_approver`, `test_rejected_with_duplicate_approvers`, `test_self_approval_is_refused`, `test_admitted_with_two_distinct_approvers` | ✅ pass |
| Tier 4 unreachable without human signoff | `tests/selection/test_phase2_tier_gate.py::TestTier4HumanSignoff` — `test_rejected_without_any_evidence`, `test_rejected_with_signoff_but_automated_initiation`, `test_admitted_with_signoff_and_manual_initiation` | ✅ pass |
| Fail-closed on unknown classes; policy integration | `tests/selection/test_phase2_tier_gate.py::TestFailClosed::test_unknown_class_resolves_to_tier3_and_is_rejected`; `TestPromotionPolicyIntegration` — `test_tier3_release_rejected_without_approvals`, `test_tier4_release_admitted_with_signoff_and_manual_initiation`, `test_tier1_release_still_promotes_without_evidence` | ✅ pass |

### F3 — Static analysis: blockers reject pre-execution; verdicts tamper-evident

| Criterion | Evidence | Result |
|---|---|---|
| Violation-corpus fixtures per code; blockers all covered | `tests/plugins/test_static_analysis_corpus.py` — `test_corpus_loads_and_covers_every_violation_class`, `test_every_blocker_class_has_a_block_fixture`, `test_fixture_verdict_matches_expected`, `test_analysis_is_pure_and_deterministic` | ✅ pass |
| PROPOSE→DEV_EVALUATE gate ordering: refusal happens before any execution | `tests/server/test_approval_flows.py::test_executable_registration_refused_with_violation_payloads`, `test_executable_registration_refused_by_output_admission`, `test_clean_executable_registration_persists_signed_analysis_report`, `test_non_executable_registration_skips_the_gate` | ✅ pass |
| Verdicts are digest-bound, signed, and append-only at the database level | `tests/conformance/test_phase2_campaigns.py::test_static_analysis_blocker_rejects_pre_execution_with_tamper_evident_report` — signature verification over canonical bytes, one flipped byte breaks it, and `UPDATE`/`DELETE` on `analysis_reports` are refused by the `evoruntime_forbid_mutation` trigger, not by application discipline | ✅ pass |

### F4 — Multi-artifact: ordered typed member sets, per-member masks, composite digest binding

| Criterion | Evidence | Result |
|---|---|---|
| Member and composite digests bind every member, order-sensitively | `tests/plugins/test_composite.py::TestMemberDigest` (`test_member_digest_is_sha256_over_the_canonical_member`, `test_changing_the_patch_changes_the_member_digest`, `test_member_digest_is_stable_across_dict_key_order`), `TestCompositeDigest` (`test_composite_digest_binds_every_member`, `test_composite_digest_is_order_sensitive`, `test_composite_digest_uses_the_registry_artifact_formula`) | ✅ pass |
| Spec v2 validation: ordered member set, incumbent-class member, mask-validated paths | `tests/campaign/test_spec.py::TestMutableArtifactSetV2` — `test_v2_spec_requires_a_non_empty_mutable_artifacts_list`, `test_v2_set_parses_multiple_members_in_order`, `test_v2_set_rejects_duplicate_member_classes`, `test_primary_is_the_incumbent_class_member_wherever_it_sits`, `test_v2_member_paths_are_mask_validated` | ✅ pass |
| v1 migration window | `tests/campaign/test_spec.py::TestV1MigrationWindow` — `test_v1_spec_parses_during_the_window_as_a_single_member_set`, `test_v1_spec_is_rejected_after_the_migration_window`, `test_v1_spec_is_still_accepted_on_the_windows_last_day` | ✅ pass |
| Pin-and-sign covers the whole mutable set | `tests/campaign/test_spec.py::TestPinAndSignV2` — `test_pinned_digest_covers_the_whole_mutable_set`, `test_pinned_v2_spec_verifies` | ✅ pass |
| Registry round-trip; masks enforced per member at execution | `tests/conformance/test_phase2_campaigns.py::test_executable_campaign_tool_spec_completes_propose_to_promote` — the tool_spec candidate persists through `artifact_content`/`proposal_records` and reads back digest-verified; per-member mask enforcement carries over from Phase 1 (`tests/campaign/test_masks.py::test_violating_candidate_is_rejected_without_reaching_the_adapter`) | ✅ pass |

### F5 — Compensation: rollback executes declared compensations in order; unexecuted plans block promotion

| Criterion | Evidence | Result |
|---|---|---|
| Plan semantics, signing, and tamper refusal | `tests/campaign/test_compensation.py` — `test_signed_plan_verifies_and_round_trips`, `test_edited_plan_body_fails_verification`, `test_signature_under_a_foreign_public_key_fails_verification`, `test_plan_store_refuses_tampered_stored_bytes`, `test_unknown_action_classifies_fail_closed` | ✅ pass |
| Unexecuted requires-execution compensation blocks promotion | `tests/campaign/test_compensation.py::test_unexecuted_requires_execution_compensation_blocks_promotion`, `test_approve_canary_refused_while_requires_execution_compensation_unexecuted`; release plane: `tests/release/test_compensation_gate.py::test_promotion_refused_while_requires_execution_compensation_unexecuted` (refusal happens before activation — incumbent stays live) | ✅ pass |
| Multi-artifact rollback executes declared compensations in order (CAS rides the pointer rollback) | `tests/campaign/test_compensation.py::test_rollback_executes_declared_compensations_in_order_skipping_cas`, `test_rollback_edge_executes_declared_compensations_in_order`; release plane: `tests/release/test_compensation_gate.py::test_severity_1_rollback_executes_declared_compensations_in_order` | ✅ pass |
| Plan tamper refused at the gate | `tests/campaign/test_compensation.py::test_tampered_plan_refuses_to_gate_promotion`; `tests/release/test_compensation_gate.py::test_tampered_plan_refuses_to_gate_promotion` | ✅ pass |
| Integrated: orchestrator + release-plane rollback in one scenario | `tests/conformance/test_phase2_campaigns.py::test_compensation_rollback_executes_compensations_in_order_and_blocks_promotion` — APPROVE→CANARY refused while unexecuted (no transition recorded), APPROVE→ROLLED_BACK executes hooks [0, 2] in declared order with the CAS revoke (index 1) riding the pointer rollback, execution evidence unblocks promotion, and a severity-1 canary event rolls the release pointer back through the controller's CAS while executing the plan's hooks | ✅ pass |

### F6 — Cascades: short-circuit semantics, defensible paired statistics, per-stage alpha ledger

| Criterion | Evidence | Result |
|---|---|---|
| Cheap-stage failure short-circuits; expensive stages never run | `tests/eval/test_cascade.py::test_cheap_stage_failure_stops_the_cascade_and_expensive_stages_never_run`, `test_standard_stage_failure_also_short_circuits_the_expensive_tier`, `test_short_circuit_cleared_lets_the_cascade_continue_past_a_failure` | ✅ pass |
| Early-exit scores preserve pairing; paired bootstrap stays defensible | `tests/eval/test_cascade.py::test_early_exit_scores_are_a_failure_outcome_that_preserves_pairing`, `test_early_exit_pairing_feeds_a_defensible_paired_bootstrap`, `test_completed_cascade_scores_from_the_final_stage` | ✅ pass |
| Alpha ledgered per stage | `tests/test_cascade_alpha_ledger.py::TestPerStageAlphaLedger` — `test_each_stage_spend_is_ledgered_under_its_own_purpose`, `test_alpha_remaining_descends_per_stage_in_run_order`, `test_early_exit_leaves_the_unrun_stages_alpha_untouched`, `test_stage_purposes_do_not_collide_across_reruns` | ✅ pass |
| Spec-level cascade bindings; plugin seam | `tests/campaign/test_spec.py::TestCascadeEvaluatorBindings` — `test_binding_without_cascade_fields_defaults_to_the_cheapest_stage`, `test_negative_stage_is_refused`, `test_cascade_fields_are_part_of_the_pinned_digest`; research-plugin seam: `tests/plugins/research/test_evolutionary_search.py::TestF6StagePlanSeam` | ✅ pass |

### F7 — Transfer suites (FR-103): evaluated multi-family results feed promotion condition 6

| Criterion | Evidence | Result |
|---|---|---|
| Evaluated multi-family scope satisfies condition 6 | `tests/selection/test_transfer_suites_promotion.py::TestTransferSuiteFeedsConditionSix::test_evaluated_multi_family_results_satisfy_condition_six` | ✅ pass |
| Claimed-but-unevaluated scope never promotes | `tests/selection/test_transfer_suites_promotion.py::test_claimed_but_unevaluated_scope_still_fails`, `test_failed_family_scope_still_fails_condition_six`, `test_all_families_failed_yields_no_coverage` | ✅ pass |
| Per-family pairing over real multi-suite data | `tests/eval/test_suites.py` (suite composition and per-family pairing primitives consumed by the condition-6 check) | ✅ pass |

### F8 — Ablations (FR-101): preregistered families yield multiplicity-controlled contributions

| Criterion | Evidence | Result |
|---|---|---|
| Unregistered ablation rejected at construction and at spec level | `tests/eval/test_ablation.py::TestUnregisteredAblationRejected` — `test_ablation_outside_the_family_is_refused`, `test_ablation_without_any_family_is_refused`, `test_campaign_spec_refuses_an_unregistered_ablation`, `test_campaign_spec_refuses_an_ablation_with_no_family_declared` | ✅ pass |
| Family-wide Holm control; alpha split across the family | `tests/eval/test_ablation.py::TestFamilyWideMultiplicity` — `test_per_comparison_alpha_splits_across_the_whole_family`, `test_holm_adjustment_covers_all_ablations_in_one_pass` | ✅ pass |
| Contribution records: schema, persistence, tamper refusal | `tests/eval/test_ablation.py::TestCheckpointPersistence` — `test_roundtrip_preserves_the_records`, `test_tampered_bytes_are_refused_on_load`, `test_a_foreign_schema_id_is_refused`, `test_malformed_records_are_refused_after_verification` | ✅ pass |
| Integrated: preregistered family, Holm-controlled contributions, tamper-evident record set | `tests/conformance/test_phase2_campaigns.py::test_ablation_campaign_preregistered_family_yields_holm_controlled_contributions` — regression verdict inside the family at the adjusted alpha, inconclusive arm reported honestly, record set verified on load and refused when its bytes no longer hash to their address | ✅ pass |

### F9 — Productivity (FR-102): value-per-cost selection over attested costs only

| Criterion | Evidence | Result |
|---|---|---|
| Metric-namespace closure at spec pin | `tests/selection/test_productivity_selection.py::TestNamespaceClosure` — `test_namespace_is_exactly_the_two_preregistered_metrics`, `test_unregistered_metric_rejected_at_spec_pin`, `test_cost_metric_cannot_sneak_in_as_a_ranking_metric`, `test_unregistered_cost_metric_rejected_at_spec_pin` | ✅ pass |
| Rule accepts no unpinned metric or unattested cost | `tests/selection/test_productivity_selection.py::TestObservationCostMetrics` — `test_unregistered_cost_key_rejected`, `test_negative_cost_rejected`, `test_non_finite_cost_rejected`, `test_attested_cost_helper_treats_zero_as_unpriced`; `TestProductivityRule` — `test_unpriced_candidate_is_not_rankable`, `test_arm_with_no_priceable_candidate_fails_closed`, `test_higher_score_does_not_outweigh_profligate_cost` | ✅ pass |
| Typed projection reconciles with raw attestations; rebuildable | `tests/selection/test_productivity_projection.py::TestProjectionReconciliation` — `test_rebuild_projects_every_proposal_attestation_pair`, `test_projection_reconciles_with_raw_attestations_after_rebuild`, `test_reconcile_detects_drift_between_projection_and_evidence`; `TestProjectionIsRebuildable::test_pure_builder_matches_stored_rows` | ✅ pass |
| Integrated: projection reconciles against raw append-only attestations | `tests/conformance/test_phase2_campaigns.py::test_productivity_selection_reconciles_projection_against_raw_attestations` — real registry rows over PostgreSQL, every proposal/attestation pair projected exactly once, typed cost columns carrying attested values, `reconcile()` clean, and the selector freezes the best value-per-cost nominee from attested costs only | ✅ pass |

### F10 — Approvals + API: two-person tier-3; admission-gated executable registration

| Criterion | Evidence | Result |
|---|---|---|
| Two-person semantics over verified approver identities | `tests/server/test_approval_flows.py` — `test_tier3_promotion_requires_two_distinct_approvers`, `test_tier3_promotion_refused_without_any_approval`, `test_self_approval_is_refused`, `test_duplicate_approver_is_refused`, `test_rejection_closes_the_review` | ✅ pass |
| Signed admission record read-back | `tests/server/test_approval_flows.py::test_privileged_admission_two_person_flow`, `test_privileged_admission_rejects_floating_tag`; signature verification over the minted record is re-proved in the integrated campaign | ✅ pass |
| Executable registration is admission-gated at the API boundary | `tests/server/test_approval_flows.py::test_executable_registration_refused_with_violation_payloads`, `test_executable_registration_refused_by_output_admission` | ✅ pass |
| Integrated: tier-3 two-person board flow on the executable campaign | `tests/conformance/test_phase2_campaigns.py::test_executable_campaign_tool_spec_completes_propose_to_promote` — review-board request, one approval refused with the two-person refusal, second distinct approver admits, and the signed admission record verifies byte-for-byte on read-back | ✅ pass |

### F11 — Plugins: both research plugins pass conformance; diversity/enablement honored

| Criterion | Evidence | Result |
|---|---|---|
| Both research plugins pass the E2 conformance suite | `tests/plugins/research/test_conformance.py` — protocol contract (`TestProtocolConformance`), compatibility (`TestCompatibilityConformance`), budget (`TestBudgetConformance`), malformed-output survival (`TestMalformedOutputConformance`), declared-artifact-types-only (`TestDeclaredArtifactTypesOnly::test_every_proposal_member_uses_a_declared_artifact_type`), pinned runtime version | ✅ pass |
| Archive diversity constraints | `tests/plugins/research/test_evolutionary_search.py::TestArchiveDiversityConstraints` — `test_parents_come_from_cells_at_least_min_distance_apart`, `test_diversity_is_never_traded_for_headcount`, `test_empty_archive_yields_no_parents`, `test_a_cell_keeps_its_best_elite` | ✅ pass |
| Enablement: disabled on non-executable-correctness classes | `tests/plugins/research/test_enablement.py::TestDisabledOnNonExecutableCorrectness` — `test_initialize_refuses_with_a_structured_error`, `test_the_process_survives_refusal_and_still_serves`; `TestEnabledOnlyOnExecutableClasses` — `test_initialize_on_the_declared_executable_class_succeeds`, `test_an_executable_but_undeclared_class_is_refused_on_type_grounds`, `test_unknown_classes_fail_closed` | ✅ pass |
| Signed packaging | `tests/plugins/research/test_packaging.py::TestPackaging` | ✅ pass |

### F12 — Integrated conformance pass (this deliverable)

`tests/conformance/test_phase2_campaigns.py`, all against real PostgreSQL (and the F1 sandbox where physical enforcement is available):

| Scenario | Evidence | Result |
|---|---|---|
| Campaign one: propose → static analysis → sandboxed dev-evaluate → freeze → sealed holdout → tier-3 approval (two-person) → canary → promote | `test_executable_campaign_tool_spec_completes_propose_to_promote` — walks the exact forward path with gapless transitions: the tool_spec candidate passes FR-018 admission and the F3 gate, executes under the F1 sandbox with a signed attestation, resolves a sealed holdout through a real handle (candidate-runner denied), clears the tier-3 two-person board (one approval refused), and promotes over the active incumbent | ✅ pass |
| Campaign two: compensation rollback + promotion blocking | `test_compensation_rollback_executes_compensations_in_order_and_blocks_promotion` — see the F5 row above | ✅ pass |
| Campaign three: static-analysis rejection with tamper-evident verdicts | `test_static_analysis_blocker_rejects_pre_execution_with_tamper_evident_report` — see the F3 row above | ✅ pass |
| Campaign four: ablation with preregistered family and Holm control | `test_ablation_campaign_preregistered_family_yields_holm_controlled_contributions` — see the F8 row above | ✅ pass |
| Campaign five: productivity selection reconciling projection vs raw attestations | `test_productivity_selection_reconciles_projection_against_raw_attestations` — see the F9 row above | ✅ pass |
| Campaign six: decision reconstruction over the integrated lineage | `test_phase2_decisions_reconstruct_from_immutable_records` — replays the gapless transition log, the append-only status events, signature-verified attestations and admission records, the release activation history, and the holdout query ledger; then proves the records refuse mutation at the database level (`UPDATE`/`DELETE` guards raise, not application discipline) | ✅ pass |

## Platform gates

| Gate | Result |
|---|---|
| `uv run ruff check .` | ✅ clean |
| `uv run ruff format --check .` | ✅ clean (350 files) |
| `uv run mypy` (strict) | ✅ clean (172 source files) |
| `uv run pytest` | ✅ 1444 passed, 0 failed (real PostgreSQL) |
| Alembic upgrade/downgrade round-trip | ✅ `tests/test_migrations.py::test_upgrade_head_then_downgrade_base` |

## Defects found and fixed

No product defects surfaced during the integrated pass — the merged F1–F11 surface behaved to spec in every scenario, including the negative paths. The defects found and fixed were all in the new F12 test code itself:

1. **Wrong table name in the nothing-landed assertion.** The static-analysis rejection scenario initially counted rows from a nonexistent `artifacts` table; the registry's content table is `artifact_content`. Fixed to query the real schema.
2. **Row-level trigger semantics in the append-only assertion.** The `analysis_reports` immutability trigger is `FOR EACH ROW`: after the first refusal's `rollback()` removed the inserted row, a subsequent `DELETE` matched zero rows and never fired, so the assertion silently proved nothing. Fixed by re-inserting before the `DELETE` attempt — the test now proves the trigger fires on a row that exists.
3. **Wrong refusal surface for the no-family ablation.** The "no preregistered family" refusal fires only when ablation arms exist; the initial construction had none and passed vacuously. Fixed to construct an actual ablation arm without a family.

## Observations recorded during the pass

1. **The rollback executes every requires-execution hook, not just the first.** A three-action plan (hook, CAS revoke, hook) runs hooks at declared indices [0, 2] in order; the CAS action rides the controller's pointer rollback and never reaches the executor. This is intended behavior (the CAS path is the only way the active pointer moves), documented here so the next reader does not re-derive it.
2. **`tests/sdk/test_emit_overhead.py` is load-sensitive.** Its wall-clock overhead assertions failed once when the full suite ran concurrently, then passed in isolation across repeated runs. Pre-existing timing test, untouched by this branch; flagged here so a future CI flake is not misread as a regression.

## What remains deferred (unchanged from the spec)

Live-model runs, production sandbox deployments (gVisor/Firecracker behind the same `IsolationBackend` contract), and CI integrations remain deferred per the spec. The F12 report verifies the integrated release branch as merged; per-PR verification histories live in the individual merged PRs.

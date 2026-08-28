# EvoRuntime Phase 1 — Conformance Verification Report

**Branch:** `feat/e10-phase1-conformance` (based on `release/evoruntime-phase1-low-risk-improvement-20260828-165349` @ `f8e30b1`)
**Date:** 2026-08-28
**Scope:** Full acceptance matrix from the Phase 1 spec (deliverables E1–E9), executed on the integrated release branch, plus the E10 integrated conformance pass: two end-to-end campaigns and the five §13.1 milestone scenarios in `tests/conformance/`.

## Headline result

**All acceptance criteria have passing evidence.** Local run on the integrated release branch against a real PostgreSQL 17 instance: **1049 passed, 0 failed** (1043 pre-existing + 6 new E10 conformance tests), `ruff check` clean, `ruff format --check` clean, `mypy --strict` clean across 139 source files, and the Alembic upgrade/downgrade round-trip green.

## How the matrix was run

- **Integrated branch:** every E1–E9 deliverable is merged into the release branch (`f8e30b1` is the E9 tip); this report verifies the *integrated* state, not per-PR states.
- **PostgreSQL-backed tests:** all DB-dependent tests (E1 registry, E3 transition logs, D5 holdout ledger, E6 memory tables, migrations) ran against a real PostgreSQL 17 instance locally; CI runs the same suite against its `postgres` service container. The suite skips — rather than fakes — when no database is reachable, so a green run here means the integration tests actually ran.
- **E10 conformance suite:** `tests/conformance/test_phase1_campaigns.py` drives the real services end to end — the E9 control-plane API, the E1 registry, the E3 state machine, the E4 promotion policy, the E5 canary harness and release controller, the D5 sealed holdout, the E6 memory hygiene, and the E8 redaction boundary — over real PostgreSQL. The only simulated input is evaluation *data* (paired scores, metrics): CI is hermetic by design, with no live-model runs, matching the D6/D8 fixture reality.
- **Subprocess fault injection:** E2's hung-plugin and dead-process tests and E3's kill/resume tests run real child processes, not in-process simulations (carried over from the Phase 0 discipline).

## Acceptance matrix

### E1 — Artifact registry: the five-record model (FR-003)

| Criterion | Evidence | Result |
|---|---|---|
| Digest mismatch rejected | `tests/registry/test_fr003_rejections.py::test_registration_rejects_claimed_digest_that_bytes_do_not_hash_to`, `test_activation_rejects_digest_mismatch_between_request_and_store`; tampered storage re-verified on read: `tests/registry/test_registry_service.py::test_read_reverifies_digest_against_tampered_storage` | ✅ pass |
| Unsigned activation rejected | `tests/registry/test_fr003_rejections.py::test_activation_rejects_unsigned_manifest_row`, `test_activation_rejects_manifest_with_invalid_signature`, `test_activation_rejects_signature_from_the_wrong_key` | ✅ pass |
| Circular metadata rejected | `tests/registry/test_fr003_rejections.py::test_registration_rejects_artifact_listing_itself_as_dependency`, `test_proposal_rejects_self_parent`, `test_manifest_row_rejects_itself_as_prior_release_at_the_database_level` | ✅ pass |
| Mixed-release activation rejected | `tests/registry/test_fr003_rejections.py::test_activation_rejects_artifacts_outside_the_target_manifest`, `test_activation_rejects_artifact_from_another_tenant`, `test_manifest_rejects_unknown_prior_release` | ✅ pass |
| Status events are append-only | `tests/registry/test_status_events.py::test_update_status_event_is_rejected`, `test_delete_status_event_is_rejected` (DB trigger); `test_all_six_kinds_are_accepted` proves the sanctioned path stays open | ✅ pass |
| Current status is a projection | `tests/registry/test_status_projection.py::test_projection_follows_the_latest_event`, `test_projection_is_per_tenant`, `test_projection_view_reflects_event_ordering` | ✅ pass |
| Signed records round-trip | `tests/registry/test_proposals_attestations_manifests.py::test_attestation_is_signed_and_verifies`, `test_manifest_round_trips_with_signature_and_prior_chain`, `test_tampered_manifest_row_cannot_land_and_honest_path_still_works` | ✅ pass |

### E2 — Plugin protocol, manifest, admission (FR-004, FR-018, FR-022)

| Criterion | Evidence | Result |
|---|---|---|
| Reference plugin passes the protocol suite | `tests/plugins/test_protocol_conformance.py` — `initialize`/`propose`/`observe`/`checkpoint`/`validate`/`render`/`semantic_diff` contract, checkpoint bytes stored opaquely and content-addressed (`test_checkpoint_bytes_stored_opaquely_never_deserialized`) | ✅ pass |
| Clean-environment isolation | `tests/plugins/test_protocol_budget.py::test_clean_plugin_env_scrubs_secrets`, `test_plugin_process_never_sees_host_secrets` | ✅ pass |
| Budget + malformed-output suites | `tests/plugins/test_protocol_budget.py::test_plugin_returning_over_budget_proposals_is_rejected`, `test_hung_plugin_hits_the_request_deadline`, `test_dead_process_raises_process_died`, `test_non_json_output_is_a_protocol_violation` | ✅ pass |
| Path traversal, undeclared executables, and the full rejection corpus rejected before ingestion | `tests/plugins/test_admission_gate.py` (`test_parent_traversal_rejected`, `test_absolute_path_rejected`, `test_symlink_rejected`, `test_device_node_rejected`, `test_archive_bomb_rejected`, `test_undeclared_executable_rejected`, …); corpus verdicts: `tests/plugins/test_admission_corpus.py::test_fixture_verdict_matches_expected` | ✅ pass |
| Manifest: permissions are requests, effective grant is the intersection | `tests/plugins/test_manifest.py::test_grant_is_the_intersection_not_the_request`, `test_any_none_plane_kills_network_and_model`, `test_disjoint_host_lists_grant_nothing`, `test_floating_pinned_image_is_rejected` | ✅ pass |
| Signed OCI packaging verifies | `tests/plugins/test_packaging.py::test_built_image_verifies`, `test_flipped_payload_byte_fails_verification`, `test_corrupted_signature_fails_verification`, `test_same_inputs_same_archive_bytes` | ✅ pass |
| Adapter/evaluator admission requires the privileged signed path | `tests/plugins/test_privileged_admission.py::test_two_person_admission_signs_a_verifiable_record`, `test_one_approval_is_denied`, `test_self_approval_is_denied`, `test_candidate_runner_cannot_sign_admission_records`, `test_unpinned_version_denied` | ✅ pass |

### E3 — Campaign orchestrator (FR-005, FR-006)

| Criterion | Evidence | Result |
|---|---|---|
| Pause / resume / cancel | `tests/campaign/test_machine.py::test_pause_remembers_the_resume_target`, `test_resume_returns_to_the_paused_phase`, `test_cancelled_campaign_cannot_resume`, `test_cancel_is_possible_from_any_nonterminal_phase` | ✅ pass |
| Reconstruct from content-addressed checkpoints | `tests/campaign/test_machine.py::test_reconstructed_campaign_continues_legally`, `test_reconstruction_replays_history_into_a_fresh_sink`; fault injection: `test_kill_during_dev_loop_resumes_with_intact_history`, `test_kill_while_paused_resumes_paused` (real killed processes) | ✅ pass |
| Transition log is gapless and append-only | `tests/campaign/test_machine.py::test_sequences_are_gapless_and_append_only`, `test_illegal_transition_raises_and_records_nothing`; E10 re-proves it on the integrated path (`test_milestone_decisions_reconstruct_from_immutable_records`) | ✅ pass |
| Undeclared-path edits fail validation before execution | `tests/campaign/test_masks.py::test_violating_candidate_is_rejected_without_reaching_the_adapter`, `test_violating_patch_raises_before_the_adapter_runs`, `test_undeclared_path_violates`; spec-level: `tests/campaign/test_spec.py::test_absolute_mask_paths_are_refused_in_the_spec_itself`, `test_traversal_mask_paths_are_refused_in_the_spec_itself` | ✅ pass |
| Budgets enforced externally | `tests/campaign/test_budgets.py::test_charge_crossing_a_ceiling_raises_and_records_nothing`, `test_token_ceiling_is_enforced_independently`, `test_real_elapsed_time_counts_via_the_injected_clock`, `test_budget_resolves_from_the_spec` | ✅ pass |
| Declarative spec pins everything up front | `tests/campaign/test_spec.py::test_each_of_the_four_arms_is_required_exactly_once`, `test_dropping_a_control_arm_is_refused`, `test_holdout_must_be_a_sealed_handle_not_content`, `test_floating_image_tags_are_refused`, `test_alpha_outside_open_interval_is_refused` | ✅ pass |

### E4 — Trusted selector + promotion policy (FR-011)

| Criterion | Evidence | Result |
|---|---|---|
| Exactly one frozen nominee per arm | `tests/selection/test_selector.py::test_freezes_exactly_one_nominee_per_arm`, `test_second_freeze_is_refused`, `test_freeze_without_observations_fails_closed`, `test_min_score_floor_excludes_a_high_scoring_arm` | ✅ pass |
| Strategy cannot edit after freeze | `tests/selection/test_selector.py::test_strategy_edit_after_freeze_is_refused`, `test_frozen_state_is_projected_from_the_ledger_not_memory`, `test_frozen_nominees_type_is_immutable` | ✅ pass |
| Promotion requires all six §12.5 conditions | `tests/selection/test_promotion_policy.py::test_all_six_conditions_pass`, and one negative per condition: `test_statistical_condition_fails_on_null_effect`, `test_protected_slice_below_margin_fails`, `test_severity1_regression_fails_condition_three`, `test_critical_failure_fails_condition_three`, `test_budget_failure_fails_condition_four`, `test_integrity_finding_fails_condition_five`, `test_unevaluated_transfer_scope_fails_condition_six`, `test_every_condition_failing_at_once_reports_all` | ✅ pass |
| Preregistered non-inferiority only when preregistered | `tests/selection/test_promotion_policy.py::test_preregistered_non_inferiority_path_passes`, `test_unpreregistered_non_inferiority_path_is_refused` | ✅ pass |
| Tier-3+ unreachable for Phase 1 artifact classes | `tests/selection/test_promotion_policy.py::test_tier3_release_is_rejected_before_any_condition`, `test_tier4_harness_touching_release_is_rejected` | ✅ pass |
| CAS denied to every non-release-controller identity | `tests/selection/test_release_pointer.py::test_non_controller_identities_are_denied`, `test_denial_leaves_no_state_change`, `test_every_attempt_is_audited`, `test_failed_audit_write_refuses_the_swap` | ✅ pass |
| Recursive-claim gate ships off in Phase 1 | `tests/selection/test_recursive_gate.py::test_phase1_switch_is_off`, `test_recursive_improvement_label_is_refused_in_phase1`, `test_satisfied_gate_still_labels_artifact_optimization` | ✅ pass |

### E5 — Release controller, canary, rollback (FR-012, FR-021)

| Criterion | Evidence | Result |
|---|---|---|
| CAS ≤ 30 s, atomic, over signed manifests | `tests/release/test_release_controller.py::test_cas_completes_within_30_seconds`, `test_activation_is_one_atomic_cas`, `test_unsigned_manifest_refused_and_pointer_untouched`, `test_tampered_body_refused` | ✅ pass |
| Rollback returns to the prior release; conflicts detected | `tests/release/test_release_controller.py::test_rollback_returns_to_prior_release`, `test_rollback_without_prior_release_refused`, `test_rollback_conflicts_when_pointer_moved` | ✅ pass |
| Fixed-horizon canary at §17.3 P0 thresholds | `tests/release/test_canary.py::test_observation_horizon_is_at_least_24_hours`, `test_candidate_allocation_never_exceeds_5_percent`, `test_digest_reporting_is_100_percent`, `test_below_threshold_config_refused`, `test_defaults_meet_the_p0_thresholds` | ✅ pass |
| Severity-1 event stops immediately and rolls back | `tests/release/test_canary.py::test_severity_1_event_stops_immediately_and_rolls_back`, `test_fleet_converges_back_to_incumbent_after_severity_1_rollback`; severity-2 does not stop: `test_severity_2_event_does_not_stop_the_canary` | ✅ pass |
| Fleet p99 convergence ≤ 5 min; sessions pinned | `tests/release/test_fleet_simulator.py::test_p99_convergence_within_5_minutes`, `test_session_cannot_repin_to_a_different_manifest`, `test_pinned_session_holds_its_manifest_after_pointer_moves`; under load: `tests/release/test_rollback_under_load.py::test_fleet_converges_to_incumbent_within_p99_bound`, `test_no_session_ever_resolves_a_mixed_manifest`, `test_pinned_sessions_keep_their_manifest_through_rollback` | ✅ pass |
| Candidate state namespaced away from incumbent | `tests/release/test_fleet_simulator.py::test_candidate_session_cannot_write_incumbent_memory`, `test_candidate_state_lands_in_the_candidate_namespace` | ✅ pass |
| Every FR-021 invalidation trigger fires its policy | `tests/release/test_invalidation_triggers.py::test_model_alias_drift_triggers_re_evaluate`, `test_tool_api_change_triggers_quarantine`, `test_dependency_cve_triggers_rollback`, `test_evaluator_change_triggers_re_evaluate`, `test_expiry_triggers_quarantine`, `test_environment_drift_triggers_rollback`, `test_strongest_action_wins_when_triggers_co_occur` | ✅ pass |

### E6 — Memory hygiene + suggestion-first memory (FR-016)

| Criterion | Evidence | Result |
|---|---|---|
| 100% of poison/stale/contradiction fixtures quarantined at intake | `tests/memory/test_hygiene.py::test_hygiene_fixture_matrix_all_quarantined_or_suggestion`, `test_poison_untrusted_trust_domain_quarantined`, `test_poison_no_supporting_evidence_quarantined`, `test_stale_entry_quarantined_at_intake`, `test_contradiction_with_live_entry_quarantined`, `test_sensitivity_does_not_bypass_intake_filters` | ✅ pass |
| Conflict never demotes the incumbent | `tests/memory/test_hygiene.py::test_conflict_never_demotes_the_incumbent`, `test_conflict_is_scoped_to_subject_environment_task_type` | ✅ pass |
| No auto-promotion before the persistence-on/off non-inferiority and negative-transfer gates pass | `tests/memory/test_gates.py::test_promotion_blocked_without_gate_inputs`, `test_promotion_blocked_when_persistence_regresses`, `test_promotion_blocked_on_negative_transfer`, `test_promotion_blocked_for_quarantined_entry`, `test_no_entry_reaches_active_except_via_promotion` | ✅ pass |
| Revocation/purge propagation through D4 machinery | `tests/memory/test_revocation.py::test_revocation_propagates_through_both_d4_sweeps`, `test_revocation_quarantines_dependent_lessons`, `test_revoking_a_lesson_never_touches_its_evidence`, `test_ttl_expiry_retires_only_entries_past_their_ttl` | ✅ pass |

### E7 — Reference plugins (FR-004)

| Criterion | Evidence | Result |
|---|---|---|
| All four plugins pass the E2 conformance suite | `tests/plugins/reference/test_conformance.py` (protocol contract, manifest admission, deterministic seeds — parametrized over `experience-distiller`, `bootstrap-demonstration-compiler`, `gepa-prompt-optimizer`, `skillopt-text-skill-optimizer`); registration: `test_all_four_reference_modules_are_registered` | ✅ pass |
| Signed OCI packaging with SBOM | `tests/plugins/reference/test_packaging.py::test_image_verifies_end_to_end`, `test_image_is_deterministic`, `test_sbom_covers_every_payload_file`, `test_tampered_layer_fails_verification` | ✅ pass |
| Each produces its declared artifact type and nothing else | `tests/plugins/reference/test_behavior.py` — distiller proposes delta edits only (`test_proposals_are_delta_edits_with_scoped_routing`, `test_whole_memory_rewrites_are_never_proposed`), never auto-promotes executable content (`test_executable_content_is_never_auto_promoted`); compiler stores only externally metric-approved traces (`test_stores_only_externally_metric_approved_traces`) and requires paired persistence evaluation (`test_every_proposal_declares_paired_persistence_evaluation`) | ✅ pass |

### E8 — DLP redaction + labeled corpus (FR-015)

| Criterion | Evidence | Result |
|---|---|---|
| ≥ 99.5% secret recall, ≥ 99.0% PII recall, ≤ 5% FP on the versioned corpus | `tests/dlp/test_corpus_evaluation.py::test_secret_recall_meets_threshold`, `test_pii_recall_meets_threshold`, `test_false_positive_rate_meets_threshold`; corpus integrity: `test_corpus_is_versioned_and_labeled`, `test_all_examples_synthetic_only`, `test_covers_all_three_categories` | ✅ pass |
| Redaction before any optimizer access; bundle boundary enforced | `tests/dlp/test_redaction.py::test_bundle_is_fully_redacted`, `test_removes_all_sensitive_content`, `test_idempotent_across_many_samples`; E10 re-proves it at the integrated hand-off (`test_milestone_leaking_candidate_is_quarantined` calls `assert_bundle_fully_redacted`) | ✅ pass |

### E9 — Campaign API, dashboard, CLI (FR-014)

| Criterion | Evidence | Result |
|---|---|---|
| API exposes campaigns, candidates, semantic diffs, evidence, Pareto results, approvals, rollback | `tests/server/test_campaign_api.py::test_campaign_plan_returns_pinned_detail`, `test_semantic_diff_compares_candidate_to_parent`, `test_evidence_bundle_is_recorded_and_listed_by_digest`, `test_campaign_pareto_splits_gains_regressions_and_costs`, `test_approval_is_recorded_and_listed_per_campaign`, `test_release_canary_then_promote_then_rollback` | ✅ pass |
| Absolute tenant scoping | `tests/server/test_campaign_api.py::test_campaign_list_scoped_to_tenant`, `test_campaign_of_another_tenant_is_not_found`, `test_approval_rejects_candidate_from_another_campaign` | ✅ pass |
| UI renders read-only | `tests/server/test_dashboard.py::test_dashboard_home_renders_campaign_list_shell`, `test_dashboard_campaign_page_wires_comparison_endpoints`, `test_dashboard_escapes_campaign_id_in_page` | ✅ pass |
| Every CLI golden-path command maps to an API call, end to end | `tests/api/test_cli_e2e.py::test_cli_golden_path_drives_campaign_to_release`, `test_cli_reports_api_errors_as_exit_code_1` | ✅ pass |

### E10 — Integrated conformance pass (this deliverable)

`tests/conformance/test_phase1_campaigns.py`, all against real PostgreSQL:

| Scenario | Evidence | Result |
|---|---|---|
| Campaign one: propose → dev-evaluate → freeze → sealed holdout → approve → canary → promote | `test_campaign_one_planted_beneficial_prompt_completes_propose_to_promote` — walks the exact §11 forward path with gapless transitions, resolves a real D5 sealed holdout through a real handle (ledger row appended, candidate-runner denied), clears all six §12.5 conditions on planted paired evidence, nominates, promotes the candidate release over the active incumbent (incumbent superseded, not deleted) | ✅ pass |
| Campaign two: propose → canary-regress → rollback | `test_campaign_two_canary_regression_rolls_back` — a severity-1 guardrail event stops the E5 fixed-horizon canary immediately, the release controller CAS rolls the pointer back to the prior manifest, the control plane records `rolled_back` with the prior release active again, and the campaign walks CANARY → ROLLED_BACK → LEARN | ✅ pass |
| §13.1: promote a planted beneficial prompt | Covered by campaign one above (planted 60% → 80% paired effect, all six conditions pass) | ✅ pass |
| §13.1: reject a neutral prompt | `test_milestone_neutral_prompt_is_rejected` — identical paired scores fail the statistical condition; the rejection is recorded as an approval decision and the candidate's projected status is `reject` | ✅ pass |
| §13.1: reject a harmful prompt | `test_milestone_harmful_prompt_is_rejected` — the D8 adversarial fixture `adv_do_rm_rf_disguised` scores UNSAFE through the real fixture runner; the policy disqualifies on the critical-safety condition regardless of metric gain | ✅ pass |
| §13.1: quarantine a leaking candidate | `test_milestone_leaking_candidate_is_quarantined` — a planted AWS secret is redacted by the E8 boundary (`assert_bundle_fully_redacted` at hand-off) and the E6 intake quarantines the proposed memory entry carrying an unadmitted trust domain; the control plane records the quarantine | ✅ pass |
| §13.1: reconstruct every decision from immutable records | `test_milestone_decisions_reconstruct_from_immutable_records` — replays the gapless transition log, the append-only status events, signature-verified attestations, the release activation history, and the holdout query ledger; then proves the records refuse mutation: `UPDATE` on `campaign_transitions` and `artifact_status_events` and `DELETE` on `holdout_query_ledger` are all rejected by database triggers, not by application discipline | ✅ pass |

## Platform gates

| Gate | Result |
|---|---|
| `uv run ruff check .` | ✅ clean |
| `uv run ruff format --check .` | ✅ clean (284 files) |
| `uv run mypy` (strict) | ✅ clean (139 source files) |
| `uv run pytest` | ✅ 1049 passed, 0 failed (real PostgreSQL) |
| Alembic upgrade/downgrade round-trip | ✅ `tests/test_migrations.py::test_upgrade_head_then_downgrade_base` |

## Observations recorded during the pass

Two behaviors surfaced by the integrated run that are worth stating explicitly; both are intended behavior, documented here so the next reader does not re-derive them:

1. **The promotion policy short-circuits on the most severe condition.** For the harmful-prompt milestone, `failed_conditions()` reports only `no_critical_safety_security_failure` — a critical safety failure alone is disqualifying, so the engine does not also enumerate the statistical condition. Fail-closed semantics; the neutral-prompt milestone confirms the statistical condition reports on its own.
2. **The append-only guards raise different SQLSTATE classes.** `UPDATE` guards on `campaign_transitions`/`artifact_status_events` surface as `ProgrammingError`; the `holdout_query_ledger` `DELETE` guard raises with the restrict-violation SQLSTATE and surfaces as `IntegrityError`. Both are database-level refusals — the E10 immutability assertions pin each expected class so a future migration that silently changes one fails loudly.

## What remains deferred (unchanged from the spec)

Agent registration/conformance flow, standalone `EvaluationSuite` object, CI integrations, and the second harness/model family for transfer checks remain deferred beyond Phase 1 per the spec's amendment. The recursive-claim gate ships as policy code with the Phase 1 switch off; no Phase 1 result is labeled "recursive improvement."

# EvoRuntime Phase 3 — Conformance Verification Report

**Branch:** `feat/g11-conformance` (based on `release/evoruntime-phase3-scaffold-mutation-20260829-075231` @ `0ceae0c`)
**Date:** 2026-08-29
**Scope:** Full acceptance matrix from the Phase 3 spec (deliverables G1–G10), executed on the integrated release branch, plus the G11 integrated conformance pass: seven end-to-end scenarios in `tests/conformance/test_phase3_campaigns.py`.

## Headline result

**All acceptance criteria have passing evidence.** Local run on the integrated release branch against a real PostgreSQL instance: **1692 passed, 0 failed** (1683 pre-existing + 9 new G11 conformance tests), `ruff check` clean, `ruff format --check` clean, `mypy --strict` clean across 195 source files, and the Alembic upgrade/downgrade round-trip green.

## How the matrix was run

- **Integrated branch:** every G1–G10 deliverable is merged into the release branch (`0ceae0c` is the G9 tip); this report verifies the *integrated* state, not per-PR states.
- **PostgreSQL-backed tests:** all DB-dependent tests (scaffold registry round-trips, tenancy boundary matrix, tier-4 approval flows, mutation archive, graduation ledger, migrations) ran against a real PostgreSQL instance locally; CI runs the same suite against its `postgres` service container. The suite skips — rather than fakes — when no database is reachable, so a green run here means the integration tests actually ran.
- **G11 conformance suite:** `tests/conformance/test_phase3_campaigns.py` drives the real services end to end — the G1 scaffold class through the real registry, the G2 protected-module planes at spec construction and the execution gate, the G3 spec v3 pin-and-sign, the G4 fixed-editor arm requirement and RI-3/RI-4 gate, the G5 sandbox capture/write-zoning/HIGHEST denylist through the real `SubprocessIsolationBackend`, the G6 four-boundary tenancy matrix, the G7 tier-4 review board, the G8 compensation executors and severity-1 drill, the G9 mutation-archive projection, and the G10 graduation gate — over real PostgreSQL. The only simulated input is evaluation *data* (paired scores, metrics): CI is hermetic by design, with no live-model runs.
- **Physical sandbox enforcement:** the G5 scenarios in the conformance suite require seccomp + Landlock (Linux); they are marked skip elsewhere, matching the existing sandbox-suite discipline.
- **One integration defect found and fixed in G11:** G7's `b8e4f6a2c9d7` (tier-4 promotion evidence) and G9's `c8d5e2f4a7b9` (scaffold mutation archive) migrations both re-parented onto `d9c3e7a1f5b8` (graduation decisions) — each resolving its own two-head episode against an earlier head, but re-creating a two-head episode against each other. Every DB-backed test path runs `alembic upgrade head`, which refuses ambiguous heads, so the integrated release could not migrate at all. G11 ships a pure graph-merge revision (`e1a2b3c4d5e6`) joining the two branches — no schema changes, no G7/G9 migration content touched.

## Acceptance matrix

### G1 — Scaffold artifact class & mutation lineage

| Criterion | Evidence | Result |
|---|---|---|
| Scaffold resolves through all five validation layers coherently | `tests/plugins/test_scaffold_class.py::test_scaffold_class_resolves_through_all_five_validation_layers` — `PluginArtifactType`, `EXECUTABLE_ARTIFACT_TYPES`, `authority.tier_by_class` → tier 4, `enablement.is_externally_executable`, spec-level incumbent/mutable validation in one coherence test | ✅ pass |
| `HARNESS_PATCH` and `SCAFFOLD` remain distinct classes with distinct tier resolution | `tests/plugins/test_scaffold_class.py::test_scaffold_and_harness_patch_remain_distinct_classes`; execution-requirements requirement: `test_manifest_declaring_scaffold_requires_execution_requirements`; fail-closed preserved: `test_unknown_class_still_fails_closed` | ✅ pass |
| Digest-pinned file-map canonical form (entrypoints, modules, suite) | `tests/plugins/test_scaffold_class.py` — `test_scaffold_file_map_rejects_incoherent_maps`, `test_scaffold_file_map_is_order_insensitive`, `test_scaffold_digest_binds_every_module_and_the_suite`, `test_scaffold_file_map_round_trips_through_pydantic` | ✅ pass |
| Registry round-trip with digest re-verification; lineage rides existing edges | `tests/registry/test_scaffold_roundtrip.py` — `test_scaffold_registers_with_member_modules_as_dependency_edges`, `test_scaffold_read_back_reverifies_digest`, `test_scaffold_digest_mismatch_is_refused`, `test_scaffold_with_unregistered_module_is_refused`, `test_scaffold_mutation_lineage_rides_existing_proposal_edges` | ✅ pass |
| Integrated: scaffold registers, digests, and traces like any artifact | `tests/conformance/test_phase3_campaigns.py::test_scaffold_campaign_lifecycle_in_research_tenant_earns_its_gates` (scenario 1) and `::test_mutated_scaffold_bytes_captured_digest_verified_and_registered` (scenario 3) | ✅ pass |

### G2 — Protected modules & self-edit conformance

| Criterion | Evidence | Result |
|---|---|---|
| Signed, versioned `ProtectedModulesDocument` covering every spec plane | `tests/security/test_protected_modules.py` — `test_default_document_covers_every_spec_plane`, `test_default_document_covers_the_holdout_and_attestation_planes`, `test_document_signs_and_verifies`, `test_document_verification_fails_on_any_byte_change`, `test_document_is_immutable_after_construction`, validation refusals (`test_document_refuses_an_empty_root_list` … `test_document_refuses_a_nonpositive_version`), `test_digest_is_stable_and_content_addressed` | ✅ pass |
| `PROTECTED_MODULE_IMPORT` / `PROTECTED_MODULE_WRITE` blockers at the analysis plane, tamper-evident | `tests/plugins/test_static_analysis_gate.py` — `test_gate_refuses_a_candidate_importing_a_protected_module`, `test_protected_refusal_verdict_is_tamper_evident`, `test_protected_refusal_is_deterministic_for_the_same_candidate` | ✅ pass |
| Mask paths under protected roots refused at spec construction | `tests/campaign/test_spec.py::TestSpecValidation` — `test_protected_mask_path_is_refused_at_spec_construction`, `test_protected_mask_path_refusal_names_the_root_and_reason`, `test_every_protected_plane_is_refused_as_a_mask_path` | ✅ pass |
| Self-edit conformance: pinned stage-0, zero regressions, early exit = measured failure | `tests/eval/test_conformance.py` — `TestPinnedStage::test_stage_is_pinned_at_zero_with_short_circuit`, `TestZeroRegressions::test_one_regression_fails_the_stage`, `TestEarlyExitIsMeasuredFailure` (`test_timeout_is_a_measured_failure_not_a_skip`, `test_crash_without_exit_is_a_measured_failure`, `test_unparseable_output_is_a_measured_failure`, `test_zero_tests_collected_is_a_measured_failure`, `test_exit_code_and_summary_disagreement_fails_closed`), `test_single_stage_run_matches_cascade_shape` | ✅ pass |
| Integrated: protected mutation refused at both gates, tamper-evidently, nothing registered | `tests/conformance/test_phase3_campaigns.py::test_protected_module_mutation_refused_at_spec_construction_and_execution_gate` (scenario 2) | ✅ pass |

### G3 — Campaign spec v3 — scaffold mutation surface

| Criterion | Evidence | Result |
|---|---|---|
| Scaffold specs parse with pinned classes; missing environment/classes refused at parse | `tests/campaign/test_spec.py::TestSpecV3ScaffoldMutationSurface` — `test_valid_scaffold_spec_parses_with_pinned_classes`, `test_scaffold_spec_without_environment_is_refused_at_parse`, `test_scaffold_spec_without_pinned_mutation_classes_is_refused_at_parse`, `test_scaffold_spec_with_an_empty_mutation_classes_section_is_refused`, `test_environment_other_than_research_is_refused`, `test_non_scaffold_spec_does_not_require_environment_or_classes` | ✅ pass |
| Binding validation: sha256 dossier digests, known isolation tiers, no duplicate ids | `tests/campaign/test_spec.py::TestSpecV3ScaffoldMutationSurface` — `test_mutation_class_dossier_digest_must_be_a_sha256`, `test_mutation_class_max_tier_must_be_a_known_isolation_tier`, `test_duplicate_mutation_class_ids_are_refused` | ✅ pass |
| Dated v2 migration window; v2→v3 upgrade-at-parse with equal digests | `tests/campaign/test_spec.py::TestSpecV3ScaffoldMutationSurface` — `test_v2_spec_parses_during_the_window_and_upgrades_to_v3`, `test_v2_spec_is_rejected_after_the_migration_window`, `test_v2_and_equivalent_v3_documents_pin_to_the_same_digest` | ✅ pass |
| Pin-and-sign covers the environment claim and mutation classes | `tests/campaign/test_spec.py::TestPinAndSignV3` — `test_pinned_digest_binds_the_environment_claim`, `test_pinned_digest_binds_the_mutation_classes`, `test_pinned_scaffold_spec_verifies` | ✅ pass |

### G4 — Fixed-editor arm & recursive-claim evidence

| Criterion | Evidence | Result |
|---|---|---|
| Exactly one fixed-editor arm required when the mutable set contains scaffold | `tests/campaign/test_spec.py::TestFixedEditorArmRequirement` — `test_scaffold_spec_with_exactly_one_fixed_editor_arm_parses`, `test_scaffold_spec_without_a_fixed_editor_arm_is_refused`, `test_scaffold_spec_with_two_fixed_editor_arms_is_refused`, `test_non_scaffold_spec_does_not_require_a_fixed_editor_arm`; arm shape: `tests/eval/test_experiment.py` — `test_fixed_editor_arm_constructs_with_an_editor_ref`, `test_fixed_editor_arm_without_an_editor_ref_is_refused`, `test_editor_ref_on_any_other_kind_is_refused` | ✅ pass |
| RI-3/RI-4: numeric fixed-editor advantage above the preregistered minimum, inside the shared Holm family | `tests/selection/test_recursive_gate.py::TestFixedEditorAdvantageCondition` — `test_condition_passes_with_numeric_advantage`, `test_gate_refused_without_the_fixed_editor_control_arm`, `test_gate_refused_without_a_numeric_advantage`, `test_gate_refused_when_advantage_is_nan`, `test_gate_refused_when_advantage_is_infinite`, `test_gate_refused_outside_the_shared_holm_family` | ✅ pass |
| Enablement is environment-scoped policy, not compile-time; label earned, never asserted | `tests/selection/test_recursive_gate.py::TestPerEnvironmentEnablement` — `test_research_policy_with_claims_enabled_earns_the_label`, `test_failed_gate_labels_artifact_optimization_even_when_enabled`, `test_no_verdict_labels_artifact_optimization`, `test_recursive_improvement_label_is_refused_without_policy`, `test_artifact_optimization_label_always_allowed` | ✅ pass |
| Integrated: campaign refuses to start without the fixed-editor arm; label earned in-scenario | `tests/conformance/test_phase3_campaigns.py::test_scaffold_campaign_lifecycle_in_research_tenant_earns_its_gates` (scenario 1) | ✅ pass |

### G5 — Sandbox tier-4 execution — capture, zoning, distinct HIGHEST

| Criterion | Evidence | Result |
|---|---|---|
| `StagedWorkspace.capture(paths)`: digest-verified extraction, symmetric with `stage()` | `tests/sandbox/test_capture_zones.py::TestCaptureRoundTrip` — `test_captured_bytes_hash_to_their_declared_digest`, `test_capture_restages_to_the_same_digest`, `test_capture_refuses_missing_file`, `test_capture_refuses_traversal_and_symlink_escape`, `test_end_to_end_two_run_harness_flow` | ✅ pass |
| Layered Landlock write zoning: scaffold-source writes separated from workspace scratch | `tests/sandbox/test_capture_zones.py::TestWriteZoneEscapeCorpus` — `test_write_outside_zone_is_physically_denied`, `test_write_inside_zone_succeeds`, `test_staged_fixture_outside_zone_cannot_be_overwritten`, `test_symlink_through_zone_to_outside_is_denied`, `test_unzoned_profile_keeps_whole_workspace_writable`; zone validation: `TestZoneValidation` | ✅ pass |
| HIGHEST seccomp denylist (`ptrace`, `mount`, `keyctl`, …) with attested names | `tests/sandbox/test_highest_tier.py::TestHighestDenylist` — `test_ptrace_is_denied_with_eperm`, `test_mount_is_denied_with_eperm`, `test_keyctl_is_denied_with_eperm`, `test_attestation_binds_the_denylist_names`, `test_executable_tier_has_no_denylist`, `test_highest_is_distinguishable_from_executable_in_the_record`, `test_audited_privileged_opt_out_skips_the_denylist`, `test_denylist_program_denies_every_listed_syscall` | ✅ pass |
| Attestation schema v2 round-trip; captured digests bound in; fail-closed without denylist support | `tests/sandbox/test_highest_tier.py::TestAttestationSchemaV2` — `test_v2_fields_roundtrip_through_json`, `test_captured_digests_are_bound_into_the_attestation`; `TestFailClosed::test_highest_refuses_without_denylist_support` | ✅ pass |
| Integrated: mutated bytes captured digest-verified over the real sandbox, two-run harness flow | `tests/conformance/test_phase3_campaigns.py::test_mutated_scaffold_bytes_captured_digest_verified_and_registered` (scenario 3) | ✅ pass |

### G6 — Research-tenant isolation

| Criterion | Evidence | Result |
|---|---|---|
| Boundary 1 — spec construction: scaffold ⇒ research | `tests/tenancy/test_research_tenant.py` — `test_scaffold_spec_without_environment_is_refused_at_construction`, `test_scaffold_spec_declaring_production_is_refused_at_construction`, `test_scaffold_spec_declaring_research_constructs`, `test_non_scaffold_spec_constructs_without_environment`, `test_environment_field_is_always_in_the_canonical_form`, `test_invalid_environment_value_is_refused` | ✅ pass |
| Boundary 2 — campaign creation / candidate registration: scaffold-class artifacts only in research | `tests/tenancy/test_research_tenant.py` — `test_scaffold_campaign_in_production_tenant_is_refused_and_audited`, `test_scaffold_campaign_in_unmapped_tenant_is_refused_and_audited`, `test_scaffold_campaign_in_research_tenant_is_created`, `test_scaffold_spec_refusal_at_construction_is_audited_by_the_control_plane`, `test_scaffold_candidate_in_production_tenant_is_refused_and_audited`, `test_scaffold_candidate_in_research_tenant_registers` | ✅ pass |
| Boundary 3 — release activation: scaffold-containing resolved sets activate only in research | `tests/tenancy/test_research_tenant.py` — `test_scaffold_release_in_production_tenant_is_refused_and_audited`, `test_scaffold_release_in_research_tenant_activates_and_promotes`, `test_scaffold_release_promotion_in_production_tenant_is_refused_and_audited` | ✅ pass |
| Boundary 4 — recursive-label gate; per-environment approval defaults | `tests/tenancy/test_research_tenant.py` — `test_recursive_label_refused_outside_research`, `test_recursive_label_claim_requires_research_environment`, `test_recursive_label_refusal_in_production_tenant_is_audited`, `test_production_policy_cannot_pin_tier_4_defaults`, `test_research_policy_may_pin_tier_4_defaults` | ✅ pass |
| Integrated: cross-tenant activation and promotion refused, audited, defense-in-depth at promotion | `tests/conformance/test_phase3_campaigns.py::test_tier4_promotion_requires_full_evidence_chain_and_cross_tenant_activation_refused` (scenario 4) | ✅ pass |

### G7 — Highest-risk (tier-4) approvals

| Criterion | Evidence | Result |
|---|---|---|
| Full evidence chain admits and signs; each missing leg refused with a typed error | `tests/server/test_tier4_approval_flows.py` — `test_tier4_promotion_full_chain_admits_and_signs`, `test_tier4_request_missing_leg_is_refused_at_creation`, `test_tier4_request_for_a_tier3_candidate_is_refused`, `test_tier4_request_in_production_tenant_is_refused`, `test_tier3_request_cannot_carry_tier4_evidence_legs` | ✅ pass |
| Tier-4-allowing seed policy documents ship as signed policy data; digests pin into scaffold specs | `tests/tenancy/test_seed_policies.py` — `test_research_seed_allows_tier_4`, `test_production_seed_cannot_allow_tier_4`, `test_production_document_shaped_like_the_research_seed_is_refused`, `test_signed_seed_documents_verify`, `test_tampered_seed_document_is_refused`, `test_scaffold_spec_pins_the_seed_policy_digest`, `test_scaffold_spec_without_the_pin_is_refused`, `test_scaffold_spec_with_a_malformed_digest_is_refused`, `test_non_scaffold_spec_cannot_pin_a_tier4_policy`, `test_tier4_pin_is_always_in_canonical_form` | ✅ pass |
| Integrated: the full chain (two distinct approvers ≠ requester, human sign-off, manual initiation) consumed end to end | `tests/conformance/test_phase3_campaigns.py::test_tier4_promotion_requires_full_evidence_chain_and_cross_tenant_activation_refused` (scenario 4) | ✅ pass |

### G8 — Destructive-operation testing

| Criterion | Evidence | Result |
|---|---|---|
| Scaffold compensation actions valid only against scaffold in the mutable set; order enforced | `tests/campaign/test_scaffold_compensation.py` — `test_scaffold_rollback_pair_is_a_valid_plan`, `test_scaffold_actions_refused_against_other_artifact_classes`, `test_conformance_rerun_takes_no_hook_image`, `test_scaffold_actions_require_scaffold_in_the_mutable_set`, `test_scaffold_rollback_order_is_enforced`, `test_scaffold_plan_actions_resolve_with_derived_modes` | ✅ pass |
| CAS-style source restore from the registry, digest-verified | `tests/campaign/test_scaffold_compensation.py` — `test_restore_recovers_destructively_mutated_source`, `test_restore_is_idempotent`, `test_restore_refuses_file_map_that_does_not_rehash`, `test_restore_refuses_cross_wired_module_body`, `test_module_canonical_bytes_round_trip` | ✅ pass |
| Conformance-rerun compensation fails closed | `tests/campaign/test_scaffold_compensation.py` — `test_conformance_rerun_passes_on_green_suite`, `test_conformance_rerun_fails_closed_on_regressions`, `test_conformance_rerun_fails_closed_on_unparseable_output`, `test_conformance_rerun_refuses_actions_it_cannot_execute` | ✅ pass |
| Severity-1 drills: compensations in declared order, pointer rollback, incumbent restored, evidence lands | `tests/release/test_scaffold_severity1_drill.py` — `test_severity_1_drill_compensates_in_order_rolls_back_and_evidences`, `test_promotion_refusal_restores_the_incumbent`, `test_conformance_rerun_failure_leaves_plan_undischarged` | ✅ pass |
| Adversarial corpus carries scaffold-class destructive fixtures | `tests/test_fixtures_adversarial.py::test_scaffold_class_destructive_fixtures_are_in_the_corpus` (≥3 `adv_do_scaffold_*` fixtures, all `DESTRUCTIVE_OPERATION`) | ✅ pass |
| Integrated: destructive mutation trips severity-1 end to end | `tests/conformance/test_phase3_campaigns.py::test_destructive_mutation_trips_severity1_compensations_in_order_with_pointer_rollback` (scenario 5) | ✅ pass |

### G9 — `harness-mutator` research plugin

| Criterion | Evidence | Result |
|---|---|---|
| Plugin conforms to the research-plugin protocol (E2-style suite, parametrized over `harness_mutator`) | `tests/plugins/research/test_conformance.py` — `TestSearchLifecycle` (`test_initialize_returns_search_state`, `test_propose_returns_validated_proposals_within_budget`, `test_propose_emits_composite_proposals`, `test_observe_returns_updated_state`, `test_checkpoint_bytes_stored_opaquely_content_addressed`), `TestManifestConformance` (`test_manifest_admits_against_runtime_version`, `test_manifest_entrypoint_matches_the_served_module`, `test_manifest_requests_no_direct_network`, `test_manifest_model_access_is_brokered_with_explicit_hosts`, `test_manifest_is_deterministic_with_seed`, `test_manifest_declares_execution_requirements_for_executable_outputs`), `TestBudgetConformance`, `TestMalformedOutputConformance`, `TestDeclaredArtifactTypesOnly::test_every_proposal_member_uses_a_declared_artifact_type`, `test_runtime_version_is_pinned` — all run for `module_name="harness_mutator"` via `tests/plugins/research/support.py::RESEARCH_PLUGIN_PARAMS` | ✅ pass |
| Packaging: signed deterministic image, SBOM, registration | `tests/plugins/research/test_packaging.py` — `test_image_verifies_end_to_end`, `test_image_is_deterministic`, `test_layer_carries_manifest_and_source`, `test_sbom_covers_every_payload_file`, `test_tampered_layer_fails_verification`, `test_detached_signature_is_annotated_in_the_index`, `test_all_research_modules_are_registered` (includes `harness_mutator`) | ✅ pass |
| Mutation archive: rebuildable projection over immutable evidence, `reconcile()` equivalence | `tests/conformance/test_phase3_campaigns.py::test_mutated_scaffold_bytes_captured_digest_verified_and_registered` (scenario 3) — `MutationArchiveService.rebuild` ≥ 1 row, proposal linkage, `reconcile() == ()`, per-class summary carries the declared `prompt_module_edit` class | ✅ pass |
| Per-class minimum tier (scaffold → 4) | `tests/plugins/test_scaffold_class.py::test_manifest_declaring_scaffold_requires_execution_requirements` plus the tier-4 resolution in `tests/plugins/test_scaffold_class.py::test_scaffold_and_harness_patch_remain_distinct_classes`; integrated in scenario 1 | ✅ pass |

### G10 — Mutation-class graduation

| Criterion | Evidence | Result |
|---|---|---|
| Signed per-class risk dossiers; digest pinning matches the G3 binding | `tests/selection/test_graduation.py` — `test_dossier_digest_is_stable_and_field_sensitive`, `test_dossier_digest_matches_g3_binding_pin`, `test_dossier_rejects_incoherent_risk_claims`, `test_signed_dossier_verifies_and_detects_tampering` | ✅ pass |
| Pure comparability check: pass paths and every refusal reason | `tests/selection/test_graduation.py` — `test_comparable_class_graduates`, `test_lower_risk_than_production_graduates`, `test_graduation_without_dossier_is_refused`, `test_tampered_dossier_is_refused`, `test_unverified_production_reference_is_refused`, `test_dossier_for_another_class_is_refused`, `test_dossier_digest_pin_mismatch_is_refused`, `test_tier_above_binding_max_is_refused`, `test_non_compensable_class_is_refused`, `test_risk_above_production_is_refused`, `test_graduation_with_no_production_extensions_is_refused` | ✅ pass |
| Graduation decisions are append-only signed records with a DB immutability trigger | `tests/selection/test_graduation.py` — `test_refusal_is_recorded_as_a_signed_decision`, `test_graduation_records_are_append_only_at_the_database_level` | ✅ pass |
| Integrated: graduation without a comparable-risk dossier refused, by recorded decision | `tests/conformance/test_phase3_campaigns.py::test_graduation_without_comparable_risk_dossier_is_refused_and_recorded` (scenario 6) | ✅ pass |

### G11 — Integrated conformance pass (this deliverable)

Seven scenarios in `tests/conformance/test_phase3_campaigns.py`, all over real PostgreSQL and the real sandbox:

| # | Scenario | Test | Result |
|---|---|---|---|
| 1 | Full scaffold campaign lifecycle in a research tenant; fixed-editor arm present; strategy arm refused to start without it | `test_scaffold_campaign_lifecycle_in_research_tenant_earns_its_gates` | ✅ pass |
| 2 | Protected-module mutation refused at spec construction and execution gate, tamper-evidently, nothing registered | `test_protected_module_mutation_refused_at_spec_construction_and_execution_gate` | ✅ pass |
| 3 | Mutated scaffold bytes captured, digest-verified, registered; conformance pass/fail a measured paired outcome; archive projection rebuilds and reconciles | `test_mutated_scaffold_bytes_captured_digest_verified_and_registered`, `test_conformance_pass_fail_is_a_measured_paired_outcome` | ✅ pass |
| 4 | Tier-4 promotion requires the full evidence chain; cross-tenant activation refused (including defense-in-depth at promotion) | `test_tier4_promotion_requires_full_evidence_chain_and_cross_tenant_activation_refused` | ✅ pass |
| 5 | Destructive mutation trips severity-1: compensations in declared order, pointer rollback, evidence | `test_destructive_mutation_trips_severity1_compensations_in_order_with_pointer_rollback` | ✅ pass |
| 6 | Graduation without a comparable-risk dossier refused, by recorded decision | `test_graduation_without_comparable_risk_dossier_is_refused_and_recorded` | ✅ pass |
| 7 | All new tables refuse UPDATE/DELETE at the DB level; migrations round-trip through the Phase 2 head | `test_phase3_tables_refuse_update_and_delete_at_the_database_level`, `test_phase3_migrations_round_trip_through_the_phase2_head` | ✅ pass |

**Scenario 7 detail (the immutability matrix).** Rows seeded through the real services (campaign API, review board, registry, graduation gate, archive rebuild), then raw `UPDATE`/`DELETE` from a separate connection as the application's own role: `tenant_policy_refusals` and `graduation_decisions` refuse via their `restrict_violation` triggers (psycopg `IntegrityError`), `approval_requests` refuses via the tier-4 evidence guard (`restrict_violation`), `admission_records` refuses via the shared `evoruntime_forbid_mutation` guard (`insufficient_privilege` → psycopg `ProgrammingError`), and `scaffold_mutation_archive` is the documented mutable exception (a derived projection, no trigger). The migration round-trip upgrades to head, downgrades to the Phase 2 head (`f9c0de1a7e55`), and upgrades back — no second two-head episode.

## Outcome

Every Phase 3 acceptance criterion maps to a named passing test on the integrated release branch, as Phases 0–2 did. The spec's failure signals — a scaffold campaign that promotes without tier-4 evidence, a mutation that escapes its write zone, a digest chain that breaks between executed and registered bytes, or a migration head conflict — are each covered by an explicit conformance failure, and the one migration-head conflict that did exist is fixed and covered by the round-trip test.

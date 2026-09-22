'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const {
  EXACT_BUILD,
  PROTECTED_HOLDOUT,
  ROUTES,
  RUNTIME_SHA256,
  readJsonl,
  rejectProtectedPath,
  validateDecisionBundle,
} = require('../src/item_family_saturation_v2');

const ROOT = path.resolve(__dirname, '..');
const ARTIFACT_ROOT = path.join(
  ROOT, 'artifacts', 'full_semantic_deep_recovery_v2', 'item_family_saturation',
);

function readJson(name) {
  return JSON.parse(fs.readFileSync(path.join(ARTIFACT_ROOT, name), 'utf8'));
}

test('P8 scope is exact, bounded, and Holdout-closed', () => {
  assert.equal(EXACT_BUILD, '16.16.805.0442');
  assert.equal(RUNTIME_SHA256.length, 64);
  assert.deepEqual(ROUTES.add, {
    packet_id: 0x0137,
    packet_type: '0x0137',
    rtti_name: 'PKT_BuyItemAns_s',
  });
  assert.deepEqual(ROUTES.remove, {
    packet_id: 0x04b3,
    packet_type: '0x04b3',
    rtti_name: 'PKT_RemoveItemAns_s',
  });
  assert.deepEqual(PROTECTED_HOLDOUT, {
    enumerated: false,
    read: false,
    hashed: false,
    decoded: false,
    tested: false,
    consumed: false,
  });
  assert.doesNotThrow(() => rejectProtectedPath(path.join(ARTIFACT_ROOT, 'safe.json')));
  assert.throws(() => rejectProtectedPath(path.join(ROOT, 'Jungle_Objective_Holdout', 'x')),
    /protected Holdout path is forbidden/u);
});

test('the full P0 route and 447/953 extra weights are conserved bijectively', () => {
  const report = readJson('item_family_saturation_audit_16_16.json');
  const conservation = report.conservation;
  assert.equal(report.exact_build, EXACT_BUILD);
  assert.equal(report.project_context_loaded, true);
  assert.equal(report.architecture_gate, 'PASS');
  assert.equal(report.actual_reverse_engineering_executed, true);
  assert.equal(conservation.aligned_row_count, 2614);
  assert.deepEqual(conservation.route_counts, { '0x0137': 1601, '0x04b3': 1013 });
  assert.equal(conservation.exact_details_purchase_count, 1154);
  assert.equal(conservation.exact_details_sale_count, 60);
  assert.equal(conservation.add_extra_count, 447);
  assert.equal(conservation.remove_extra_count, 953);
  assert.equal(conservation.classified_extra_row_count, 1400);
  assert.equal(conservation.classified_route_key_distinct_count, 1400);
  assert.equal(conservation.published_alignment_extra_key_count, 1400);
  assert.equal(conservation.input_weight_conserved, true);
  assert.equal(conservation.extra_weight_conserved, true);
  assert.equal(conservation.published_extra_bijection, true);
});

test('all 447 additions and 953 removals retain their exact bounded classes', () => {
  const report = readJson('item_family_saturation_audit_16_16.json');
  assert.deepEqual(report.classification['0x0137'].structural_class_counts, {
    PAIRED_MULTI_WRITE_SAME_SLOT_SET: 18,
    PAIRED_OTHER_SLOT_ONLY_MULTI_SLOT_SET: 16,
    PAIRED_SINGLE_SAME_SLOT_SET: 224,
    PURCHASE_GROUP_EXTRA_2055_SAME_SLOT_CO_TRANSITION: 41,
    TIME_ZERO_INITIAL_SYNC_SET: 48,
    UNPAIRED_SET_REFRESH_OR_AUTOMATIC_ADDITION_OPAQUE: 100,
  });
  assert.equal(report.classification['0x0137'].structurally_partitioned_count, 447);
  assert.equal(report.classification['0x0137'].cause_bounded_initial_sync_count, 48);
  assert.equal(report.classification['0x0137'].cause_semantics_opaque_count, 399);
  assert.equal(report.classification['0x0137'].locally_unpartitionable_unpaired_count, 100);
  assert.deepEqual(report.classification['0x04b3'].structural_class_counts, {
    COMPLETE_STATE_EXACT_005A_SUBSTITUTION_PAIR: 6,
    COMPLETE_STATE_MULTI_WRITE_SAME_SLOT_AMBIGUOUS: 18,
    COMPLETE_STATE_OTHER_SLOT_ONLY_CO_TRANSITION: 255,
    COMPLETE_STATE_SAME_SLOT_DIFFERENT_ITEM_REPLACEMENT: 512,
    COMPLETE_STATE_SAME_SLOT_SAME_ITEM_REWRITE: 46,
    INCOMPLETE_STATE_MULTI_WRITE_SAME_SLOT_OPAQUE: 5,
    INCOMPLETE_STATE_OTHER_SLOT_ONLY_CO_TRANSITION_OPAQUE: 39,
    INCOMPLETE_STATE_PRIOR_EMPTY_OR_UNRECOVERED_SAME_SLOT_OPAQUE: 1,
    INCOMPLETE_STATE_SAME_SLOT_DIFFERENT_ITEM_CANDIDATE: 68,
    INCOMPLETE_STATE_SAME_SLOT_SAME_ITEM_REWRITE_CANDIDATE: 3,
  });
  assert.equal(report.classification['0x04b3'].complete_state_count, 837);
  assert.equal(report.classification['0x04b3'].incomplete_state_count, 116);
  assert.equal(report.classification['0x04b3'].cause_semantics_opaque_count, 953);

  const rows = readJsonl(path.join(ARTIFACT_ROOT, 'item_family_extra_classification_16_16.jsonl'));
  assert.equal(rows.length, 1400);
  assert.equal(new Set(rows.map((row) => row.route_key)).size, 1400);
  assert.ok(rows.every((row) => row.actual_reverse_engineering_executed === true));
  assert.equal(rows.filter((row) => row.support_quest_stage_link).length, 32);
  assert.equal(rows.filter((row) => row.exact_0x005a_substitution_pair).length, 12);
});

test('substitution, support-stage, snapshot, and adjacency counterevidence stays bounded', () => {
  const report = readJson('item_family_saturation_audit_16_16.json');
  const cross = report.cross_artifact_audits;
  assert.deepEqual(cross['0x005a_substitution'].decoded_pair_counts, {
    '1001->2422': 2,
    '2420->2421': 6,
  });
  assert.equal(cross['0x005a_substitution'].direct_same_time_same_slot_transition_count, 6);
  assert.equal(cross['0x005a_substitution'].no_same_time_membership_transition_count, 2);
  assert.equal(cross['0x0064_support_quest'].stage_0_to_1_pair_count, 8);
  assert.equal(cross['0x0064_support_quest'].stage_1_to_transient_3867_pair_count, 8);
  assert.equal(cross['0x0064_support_quest'].durable_3867_snapshot_count, 0);

  const p0310 = cross.adjacency['0x0310'].by_extra_route;
  assert.equal(p0310['0x0137'].exact_time, 230);
  assert.equal(p0310['0x04b3'].exact_time, 319);
  assert.equal(p0310['0x0137'].shift_137ms_within_10ms, 9);
  assert.equal(p0310['0x04b3'].shift_997ms_within_10ms, 25);
  assert.equal(cross.adjacency['0x0311'].by_extra_route['0x0137'].exact_time, 49);
  assert.equal(cross.adjacency['0x0311'].by_extra_route['0x04b3'].exact_time, 2);
  assert.equal(cross.adjacency['0x02ea'].by_extra_route['0x0137'].exact_time, 0);
  assert.equal(cross.adjacency['0x02ea'].by_extra_route['0x04b3'].exact_time, 0);
  for (const neighbor of Object.values(cross.adjacency)) assert.equal(neighbor.semantic_claim, null);

  assert.equal(cross['0x0405_boundary'].observed_count, 518470);
  assert.equal(cross['0x0405_boundary'].bounded_shape_sample_count, 12);
  assert.deepEqual(cross['0x0405_boundary'].bounded_sample_streams, { keyframe: 12 });
});

test('existing native evidence and the new exact state probe are deterministic', () => {
  const report = readJson('item_family_saturation_audit_16_16.json');
  assert.deepEqual(
    Object.fromEntries(Object.entries(report.full_native_artifact_audit)
      .map(([route, row]) => [route, row.event_count])),
    {
      '0x0137': 1601,
      '0x04b3': 1013,
      '0x005a': 8,
      '0x006c': 53,
      '0x01e8': 258,
      '0x02ea': 299,
      '0x0310': 17802,
      '0x0311': 1425,
      '0x0405': 12,
    },
  );
  assert.equal(report.full_native_artifact_audit['0x0311'].failure_count, 154);
  assert.equal(report.native_probe_determinism.exact_native_execution_rerun, true);
  assert.equal(report.native_probe_determinism.run_count, 2);
  assert.equal(report.native_probe_determinism.all_match, true);
  assert.equal(report.native_probe_determinism.probe_sha256.length, 64);
  assert.equal(Object.keys(report.native_probe_determinism.helper_table_sha256).length, 3);
  assert.equal(report.inventory_state_simulation.state_event_count, 3259);
  assert.deepEqual(report.inventory_state_simulation.snapshot_comparison_counts, {
    exact: 237,
    mismatch: 57,
    prior_incomplete: 40,
  });
});

test('machine decisions preserve structural promotion and semantic rejection boundaries', () => {
  const decisions = readJson('item_family_saturation_decisions_16_16.json');
  assert.equal(validateDecisionBundle(decisions), true);
  assert.equal(decisions.route_decisions.length, 2);
  assert.equal(decisions.capability_decisions.length, 3);
  assert.equal(decisions.domain_decisions.length, 1);
  assert.deepEqual(decisions.decision_counts, {
    KEEP_CANDIDATE: 2,
    PROMOTE: 1,
    REJECT: 1,
    REPURPOSE: 2,
  });
  assert.ok(decisions.route_decisions.every((row) => row.decision === 'REPURPOSE'));
  assert.equal(decisions.capability_decisions.find(
    (row) => row.capability === 'universal_buy_sell_route_semantics',
  ).decision, 'REJECT');
  assert.equal(decisions.domain_decisions[0].decision, 'KEEP_CANDIDATE');
  for (const group of ['route_decisions', 'capability_decisions', 'domain_decisions']) {
    for (const row of decisions[group]) {
      assert.equal(row.actual_reverse_engineering_executed, true);
      assert.equal(row.evidence_exhausted, true);
      assert.deepEqual(row.actionable_hypotheses, []);
      assert.equal(row.next_required_evidence.length, 3);
      assert.equal(row.external_only_gate.required, true);
      assert.equal(row.external_only_gate.local_safe_evidence_remaining, false);
    }
  }
});

test('closure records no remaining safe-local executable hypothesis', () => {
  const report = readJson('item_family_saturation_audit_16_16.json');
  assert.equal(report.counterexamples.length, 9);
  assert.equal(report.evidence_exhausted, true);
  assert.deepEqual(report.actionable_hypotheses, []);
  assert.equal(report.saturation.current_safe_local_resource_saturated, true);
  assert.equal(report.saturation.local_actionable_hypothesis_count, 0);
  assert.deepEqual(report.protected_holdout, PROTECTED_HOLDOUT);
  assert.equal(report.validations.all_pass, true);
});

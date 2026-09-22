'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const {
  ROUTES,
  decisionSummary,
  rejectProtectedPath,
  validateExhaustionReport,
  verifyHashManifest,
} = require('../src/highfreq_leftover_exhaustion_v2');

const ROOT = path.resolve(__dirname, '..');
const ARTIFACT_DIR = path.join(ROOT, 'artifacts', 'full_semantic_deep_recovery_v2',
  'highfreq_leftover_exhaustion');

function artifact(name) {
  return JSON.parse(fs.readFileSync(path.join(ARTIFACT_DIR, name), 'utf8'));
}

test('seven leftover routes have exact factory/profile/decode decisions with local evidence exhausted', () => {
  const report = validateExhaustionReport(artifact('highfreq_leftover_exhaustion_v2.json'));
  const summary = decisionSummary(report);
  assert.deepEqual(Object.keys(summary), ROUTES);
  assert.equal(summary['0x0405'].decision, 'PROMOTE');
  assert.ok(ROUTES.filter((packet) => packet !== '0x0405')
    .every((packet) => summary[packet].decision === 'REPURPOSE'));
  assert.equal(report.static_recovery.routes['0x0405'].receive_identity.status,
    'STATIC_CALLBACK_RTTI_AND_RECEIVE_TARGET_VERIFIED');
  for (const packet of ROUTES.filter((value) => value !== '0x0405')) {
    assert.equal(report.static_recovery.routes[packet].receive_identity.status,
      'PACKET_SPECIFIC_CALLBACK_REQUIRES_RUNTIME_HEAP_CALLBACK_TREE');
  }
});

test('02d4, 0474, 0199, and 0092/00b9 close their exact structural branches', () => {
  const report = artifact('highfreq_leftover_exhaustion_v2.json');
  assert.deepEqual(
    report.decodes['0x02d4'].payload_length_distribution
      .map((row) => row.payload_length)
      .sort((left, right) => left - right),
    [1, 3, 4],
  );
  assert.deepEqual(
    [...new Set(report.decodes['0x02d4'].observed_branch_matrix
      .map((row) => row.payload_length))],
    [1, 3, 4],
  );
  assert.equal(report.decodes['0x0474'].full_occurrence_weight, 107192);
  assert.ok(report.decodes['0x0474'].non_zilean_counterexample_weight > 0);
  assert.equal(report.decodes['0x0474'].decoded_triplet_distribution
    .reduce((sum, row) => sum + row.count, 0), 107192);
  assert.equal(report.decodes['0x0199'].full_occurrence_weight, 362796);
  assert.equal(
    report.decodes['0x0199'].fully_decoded_occurrence_weight
      + report.decodes['0x0199'].runtime_state_blocked_occurrence_weight,
    362796,
  );
  assert.ok(report.decodes['0x0199'].runtime_state_blocked_occurrence_weight > 0);
  assert.equal(report.decodes['0x0199'].all_unique_payloads_classified, true);
  assert.equal(report.decodes['0x0199'].verified_prefix_occurrence_weight, 362796);
  assert.equal(report.decodes['0x0199'].all_blocked_payloads_have_verified_prefix, true);
  assert.equal(report.decodes['0x0199'].verified_prefix_value_10_distribution[0].value, 0);
  assert.equal(report.decodes['0x0199'].field_14_runtime_state_boundary.fault_rva_hex,
    '0x010723e4');
  assert.equal(report.input_conservation['0x0092'].full_inventory_count, 54606);
  assert.equal(report.input_conservation['0x00b9'].full_inventory_count, 54606);
  assert.equal(report.decodes['0x00b9'].all_containers_empty, true);
  assert.equal(report.decodes['0x0092'].container_length_pair_distribution
    .reduce((sum, row) => sum + row.count, 0), 4954);
  assert.equal(report.decodes['0x00b9'].container_length_pair_distribution
    .reduce((sum, row) => sum + row.count, 0), 4954);
  assert.ok(report.decodes['0x0092'].container_length_pair_distribution
    .some((row) => row.container_10_length > 0 && row.container_20_length > 0));
});

test('004a and 0405 exact emulation conserves every selected row and records the blocked branch', () => {
  const report = artifact('highfreq_leftover_exhaustion_v2.json');
  const profile0405 = artifact(path.join('profiles', 'route_0405.json'));
  assert.equal(report.decodes['0x004a'].input_row_count, 16000);
  assert.equal(report.decodes['0x004a'].fully_consumed_row_count, 16000);
  assert.ok(report.decodes['0x004a'].outer_record_count_distribution
    .every((row) => Number.isInteger(row.outer_record_count) && Number.isInteger(row.count)));
  assert.ok(report.decodes['0x004a'].nested_record_count_distribution
    .every((row) => Number.isInteger(row.nested_record_count) && Number.isInteger(row.count)));
  assert.equal(report.decodes['0x004a'].outer_record_count_distribution
    .reduce((sum, row) => sum + row.count, 0), 16000);
  assert.equal(report.decodes['0x004a'].nested_record_count_distribution
    .reduce((sum, row) => sum + row.count, 0), 16000);
  assert.ok(report.decodes['0x004a'].nested_tag_distribution.length > 1);
  assert.equal(report.decodes['0x0405'].input_row_count, 5113);
  assert.equal(report.decodes['0x0405'].fully_consumed_row_count, 5113);
  assert.equal(report.decodes['0x0405'].value_18_distribution
    .reduce((sum, row) => sum + row.count, 0), 5113);
  assert.equal(report.decodes['0x0405'].observed_runtime_default_branch_count, 0);
  assert.match(report.decodes['0x0405'].runtime_default_branch_boundary, /TLS\/module-global/);
  assert.equal(profile0405.published_identity.packet_rtti_name,
    'PKT_S2C_SetItemGroupData_Broadcast_s');
  assert.equal(profile0405.published_identity.callback_owner_type, 'HeroInventoryClient');
  assert.equal(profile0405.branch_model.inline_subobject_branch.current_authorized_observation_count,
    5113);
  assert.equal(profile0405.branch_model.runtime_default_branch.current_authorized_observation_count,
    0);
  assert.match(report.route_decisions.find((row) => row.packet_discriminator === '0x0405').semantic_claim,
    /HeroInventoryClient/);
});

test('hash manifest covers the report, compact decode rows, and seven profiles', () => {
  assert.equal(verifyHashManifest(artifact('highfreq_leftover_exhaustion_v2.sha256.json')), true);
});

test('protected Holdout paths fail closed without access', () => {
  assert.throws(() => rejectProtectedPath(path.join(ROOT, 'synthetic-Holdout', 'never-read.rofl')),
    /protected Holdout path is forbidden/);
});

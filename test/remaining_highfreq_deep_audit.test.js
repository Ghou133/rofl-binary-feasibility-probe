'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const {
  EXACT_BUILD,
  ROUTES,
  nearestAnchor,
  quantile,
} = require('../scripts/audit_remaining_highfreq_raw');

const ROOT = path.resolve(__dirname, '..');
const ARTIFACT_ROOT = path.join(
  ROOT,
  'artifacts',
  'full_semantic_deep_recovery_v2',
  'remaining_highfreq',
);

function readJson(name) {
  return JSON.parse(fs.readFileSync(path.join(ARTIFACT_ROOT, name), 'utf8'));
}

test('remaining-highfreq pure temporal helpers are deterministic', () => {
  assert.equal(EXACT_BUILD, '16.16.805.0442');
  assert.deepEqual(ROUTES, [0x0105, 0x029d, 0x03aa, 0x0404]);
  assert.equal(quantile([0, 10, 20, 30], 0.5), 15);
  assert.deepEqual(
    nearestAnchor([
      { time: 100, source: 1, target: 2 },
      { time: 300, source: 3, target: 4 },
    ], 240),
    { time: 300, source: 3, target: 4 },
  );
});

test('raw latest-four audit covers every inventory row and retains negative controls', () => {
  const report = readJson('remaining_highfreq_raw_audit.json');
  assert.equal(report.exact_build, EXACT_BUILD);
  assert.equal(report.validations.all_pass, true);
  assert.equal(report.input.safe_replays.length, 4);
  assert.deepEqual(
    Object.fromEntries(report.routes.map((route) => [route.packet_discriminator, route.count])),
    {
      '0x0105': 56641,
      '0x029d': 73747,
      '0x03aa': 96343,
      '0x0404': 50626,
    },
  );
  for (const route of report.routes) {
    assert.equal(route.count_match, true);
    assert.equal(route.damage_neighborhood.semantic_claim, null);
    assert.ok(route.damage_neighborhood.far_counterexamples.length > 0);
  }
  assert.deepEqual(report.protected_holdout, {
    enumerated: false,
    read: false,
    hashed: false,
    decoded: false,
    tested: false,
    consumed: false,
  });
});

test('deep audit closes exact structures without inventing gameplay semantics', () => {
  const report = readJson('remaining_highfreq_deep_audit.json');
  assert.equal(report.exact_build, EXACT_BUILD);
  assert.equal(report.validations.all_pass, true);
  assert.equal(report.static_recovery.validations.all_pass, true);
  assert.equal(report.route_decisions.length, 4);
  assert.deepEqual(
    Object.fromEntries(report.route_decisions.map((route) => [
      route.packet_discriminator,
      route.decision,
    ])),
    {
      '0x0105': 'KEEP_CANDIDATE',
      '0x029d': 'REPURPOSE',
      '0x03aa': 'REPURPOSE',
      '0x0404': 'REPURPOSE',
    },
  );
  for (const decision of report.route_decisions) {
    assert.equal(decision.semantic_claim, null);
    assert.equal(decision.structural_claim_only, true);
    assert.equal(decision.evidence_exhausted, true);
    assert.ok(decision.next_required_evidence.length >= 1);
  }

  const route0105 = report.routes['0x0105'].runtime_decode;
  assert.equal(route0105.runtime_boundary.status, 'BLOCKED_BY_EXACT_IMAGE_LIVE_STATE_POINTER');
  assert.equal(route0105.runtime_boundary.bounded_retry_count, 72);

  const route029d = report.routes['0x029d'].runtime_decode;
  assert.equal(route029d.fully_consumed_row_count, 4585);
  assert.equal(
    route029d.field_behavior.f32_10.within_2ms_after_per_replay_offset_rate,
    1,
  );
  assert.equal(route029d.field_behavior.u32_2c.all_sampled_transitions_nondecreasing, true);
  assert.ok(route029d.field_behavior.u8_28.pearson_with_byte_vector_length > 0.8);

  const route03aa = report.routes['0x03aa'].runtime_decode;
  assert.equal(route03aa.full_inventory_weight_covered, true);
  assert.equal(route03aa.field_behavior.element_count_always_even, true);
  assert.equal(route03aa.field_behavior.adjacent_pair_exact_duplicate_rate, 1);
  assert.equal(route03aa.field_behavior.raw_param_vs_element_u32.match_rate, 0);

  const route0404 = report.routes['0x0404'].runtime_decode;
  assert.equal(route0404.full_inventory_weight_covered, true);
  assert.equal(route0404.field_behavior.u32_10.broad_network_entity_rate, 1);
  assert.equal(route0404.field_behavior.u32_10.raw_param_comparison.low_byte_match_rate, 1);
  assert.ok(route0404.field_behavior.u32_10.raw_param_comparison.exact_match_rate > 0.99);
  assert.ok(route0404.field_behavior.u32_10.raw_param_comparison.exact_match_rate < 1);
  assert.deepEqual(report.protected_holdout, {
    enumerated: false,
    read: false,
    hashed: false,
    decoded: false,
    tested: false,
    consumed: false,
  });
});

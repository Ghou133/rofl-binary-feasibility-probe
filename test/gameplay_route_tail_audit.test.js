'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const {
  ALLOWED_DECISIONS,
  decodeRouteObject,
  nearestDelta,
  rejectProtectedPath,
  rotateLeft8,
  rotateRight8,
  swapAdjacentBits,
} = require('../scripts/audit_gameplay_route_tail');

const ROOT = path.resolve(__dirname, '..');
const IMAGE = fs.readFileSync(path.join(ROOT, 'artifacts', 'new_build_rofl_compatibility_gate_v1', 'runtime', 'league_16.16.805.0442.memory.bin'));

test('byte helpers retain exact 8-bit inverse properties', () => {
  for (let value = 0; value < 256; value += 1) {
    assert.equal(rotateLeft8(rotateRight8(value, 3), 3), value);
    assert.equal(swapAdjacentBits(swapAdjacentBits(value)), value);
  }
});

test('protected Holdout paths are rejected before any read or hash', () => {
  assert.throws(() => rejectProtectedPath(path.join(ROOT, 'Jungle Objective Holdout', 'forbidden.rofl')), /Holdout path is forbidden/);
  assert.doesNotThrow(() => rejectProtectedPath(path.join(ROOT, 'artifacts', 'safe.json')));
});

test('0x01ab callback transform recovers an exact unit face-direction vector', () => {
  const decoded = decodeRouteObject('0x01ab', 'b002b14101000000ab01e6e6b5000040a8e6e6e65e820009a3a3a3a3bc91dc8f34343434', IMAGE);
  assert.equal(decoded.flag_u8, 0);
  assert.ok(Math.abs(decoded.direction_x_f32 - (-0.17825643718242645)) < 1e-8);
  assert.equal(decoded.direction_y_f32, 0);
  assert.ok(Math.abs(decoded.direction_z_f32 - (-0.983984112739563)) < 1e-8);
  assert.ok(Math.abs(decoded.direction_norm - 1) < 1e-6);
  assert.equal(decoded.scalar_20_f32, 0);
});

test('0x00e4 consumer transforms preserve nullable target and sequence fields', () => {
  const decoded = decodeRouteObject('0x00e4', '5807b14101000000e400e6e606060040b8f1e6e6eb999999c84fe6e6f6f6f6f6', IMAGE);
  assert.deepEqual(decoded, {
    flag_10_u8: 1,
    flag_11_u8: 0,
    attack_sequence_14_u32: 1,
    flag_18_u8: 1,
    selector_19_u8: 0,
    target_network_id_candidate_1c_u32: 0,
  });
});

test('0x03d4 and 0x01b5 exact consumer transforms recover count and target', () => {
  const count = decodeRouteObject('0x03d4', '7876b14101000000d403e6e6a00b00402ee6e6e6', IMAGE);
  assert.equal(count.movement_complete_count_u8, 1);
  const target = decodeRouteObject('0x01b5', 'a070b14101000000b501e6e673020040e86fb1410100000056e6e6e6874b34b085e8f0b2bf45dfdc0000000000000000000000000000000042a92c0c865d5d5d42e6e6e6d6dd395500000000030000000200000002000000', IMAGE);
  assert.equal(target.target_network_id_u32, 0x40000278);
});

test('nearest-delta helper is exact at boundaries', () => {
  assert.equal(nearestDelta([], 5), null);
  assert.equal(nearestDelta([10, 20, 40], 20), 0);
  assert.equal(nearestDelta([10, 20, 40], 34), 6);
  assert.equal(nearestDelta([10, 20, 40], 1), 9);
  assert.deepEqual([...ALLOWED_DECISIONS].sort(), ['KEEP_CANDIDATE', 'PROMOTE', 'REJECT', 'REPURPOSE']);
});

test('generated exact-build audit conserves rows and emits bounded machine decisions', () => {
  const report = JSON.parse(fs.readFileSync(path.join(ROOT, 'artifacts', 'full_semantic_deep_recovery_v2', 'gameplay_route_tail', 'gameplay_route_tail_audit_16_16.json'), 'utf8'));
  assert.equal(report.exact_build, '16.16.805.0442');
  assert.equal(report.architecture_gate, 'PASS');
  assert.equal(report.input_conservation.target_row_count, 480101);
  assert.equal(report.input_conservation.anchor_row_count, 474127);
  assert.equal(report.input_conservation.native_sample_row_count, 2859);
  assert.equal(report.input_conservation.native_full_consume_count, 2859);
  assert.deepEqual(report.raw_route_profiles['0x0298'].stream_counts, { keyframe: 77706 });
  assert.deepEqual(report.emulation['0x03d4'].field_summaries.movement_complete_count_u8.distribution, { 1: 96 });
  assert.equal(report.route_findings['0x0298'].cross_route_behavior.exact_time_same_subject_face_direction.exact_time_same_raw_param_rate, 1);
  assert.equal(report.decisions.route_decisions.length, 6);
  for (const decision of [
    ...report.decisions.route_decisions,
    ...report.decisions.capability_decisions,
    ...report.decisions.domain_decisions,
  ]) {
    assert.ok(ALLOWED_DECISIONS.has(decision.decision));
    assert.equal(typeof decision.evidence_exhausted, 'boolean');
    assert.ok(Array.isArray(decision.next_required_evidence));
  }
  assert.equal(report.safety.protected_holdout_enumerated, false);
  assert.equal(report.safety.protected_holdout_read, false);
  assert.equal(report.safety.protected_holdout_hashed, false);
  assert.equal(report.safety.protected_holdout_consumed, false);
});

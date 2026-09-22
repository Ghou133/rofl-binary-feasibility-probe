'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const {
  assertSafePath,
  decodeProtectedFields,
  participantIdFromRawParam,
} = require('../src/hero_reincarnate_alive_v2');

const ROOT = path.resolve(__dirname, '..');
const REPORT = path.join(
  ROOT,
  'artifacts/full_semantic_deep_recovery_v2/hero_respawn/hero_reincarnate_alive_audit_16_16.json',
);
const EVENTS = path.join(
  ROOT,
  'artifacts/full_semantic_deep_recovery_v2/hero_respawn/hero_reincarnate_alive_events_16_16.jsonl',
);

test('0x0265 callback inverse recovers the two observed protocol coordinates', () => {
  assert.deepEqual(decodeProtectedFields({
    field_10_u32: 0x4bd9abab,
    field_14_u32: 0x4b6d3bab,
    field_18_u32: 0x0a1f7bbb,
  }), {
    x: 394,
    y: 0,
    z: 461,
    reincarnate_scalar: 373.79998779296875,
  });
  const other = decodeProtectedFields({
    field_10_u32: 0xc93fa3ab,
    field_14_u32: 0xc93f10ab,
    field_18_u32: 0x0a1f7bbb,
  });
  assert.equal(other.x, 14340);
  assert.equal(other.z, 14391);
});

test('0x0265 participant derivation remains exact-build bounded and retains raw', () => {
  assert.equal(participantIdFromRawParam(0x400000ae), 1);
  assert.equal(participantIdFromRawParam(0x7f0000b7), 10);
  assert.equal(participantIdFromRawParam(0x40000001), null);
});

test('protected Holdout paths fail closed', () => {
  assert.throws(
    () => assertSafePath('C:/secret/Jungle Objective Holdout/sample.rofl'),
    /forbidden/,
  );
});

test('real 0x0265 audit conserves all rows and closes the death sequence', () => {
  const report = JSON.parse(fs.readFileSync(REPORT, 'utf8'));
  assert.equal(report.exact_build, '16.16.805.0442');
  assert.equal(report.native_decode.row_count, 282);
  assert.equal(report.native_decode.successful_full_consume_count, 282);
  assert.equal(
    report.death_respawn_differential.unique_details_death_event_count,
    301,
  );
  assert.equal(
    report.death_respawn_differential.matched_unique_death_to_route_count,
    282,
  );
  assert.equal(
    report.death_respawn_differential.route_rows_without_unique_preceding_death_count,
    0,
  );
  assert.equal(report.death_respawn_differential.unmatched_death_count, 19);
  assert.equal(
    report.death_respawn_differential.unmatched_deaths_all_participant_final,
    true,
  );
  assert.equal(report.protected_field_inverse.unique_position_count, 2);
  assert.equal(report.route_decisions[0].decision, 'PROMOTE');
  assert.equal(report.capability_decisions[1].decision, 'KEEP_CANDIDATE');
  assert.equal(
    report.saturation.locally_executable_actionable_hypothesis_count,
    0,
  );
});

test('real event artifact retains raw provenance and neutral scalar boundary', () => {
  const events = fs.readFileSync(EVENTS, 'utf8').trim().split(/\r?\n/).map(JSON.parse);
  assert.equal(events.length, 282);
  assert.ok(events.every((event) => event.event_type === 'HERO_REINCARNATE_ALIVE'));
  assert.ok(events.every((event) => event.raw_packet_ref.raw_payload_sha256));
  assert.ok(events.every((event) => event.position.evidence.x.startsWith('VERIFIED_DIRECT')));
  assert.ok(events.every((event) => event.reincarnate_scalar_role.includes('UNKNOWN')));
  assert.ok(events.every((event) => Number.isFinite(event.preceding_death_timestamp_ms)));
});

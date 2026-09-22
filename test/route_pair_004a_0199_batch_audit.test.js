'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { analyzeBatchPair } = require('../src/route_pair_004a_0199_batch_audit');
const { parseArgs } = require('../scripts/audit_route_pair_004a_0199_batch');

function event(packetId, time, offset, payload, rawParam = 0) {
  return {
    replay_version: '16.16.805.0442',
    replay_sha256: 'replay',
    replay_label: 'replay',
    replay_time_ms: time,
    occurrence_index: offset,
    packet_id: packetId,
    raw_param: rawParam,
    chunk_index: 4,
    chunk_stream: 'game_chunk',
    decompressed_block_offset: offset,
    payload_length: payload.length / 2,
    raw_payload_hex: payload,
  };
}

test('variable batch followed by fixed twelve-row cluster is structural not scalar state', () => {
  const events = [];
  for (const time of [100, 200]) {
    for (let index = 0; index < 5; index += 1) {
      events.push(event(0x004a, time, (time * 10) + index, `c90${index}`));
    }
    for (let index = 0; index < 12; index += 1) {
      events.push(event(0x0199, time, (time * 10) + 10 + index, `6${index.toString(16)}57`));
    }
  }
  const report = analyzeBatchPair(events, { 0x004a: 10, 0x0199: 24 });
  assert.equal(report.validations.all_pass, true);
  assert.equal(report.counts.fixed_twelve_row_group_count, 2);
  assert.equal(report.relationship.variable_batch_before_fixed_cluster_group_rate, 1);
  assert.deepEqual(report.route_decisions.map((row) => row.decision), ['REPURPOSE', 'REPURPOSE']);
  assert.equal(report.negative_evidence.semantic_claim, null);
});

test('a non-twelve fixed cluster fails the structural invariant', () => {
  const report = analyzeBatchPair([
    event(0x004a, 100, 10, 'c900'),
    event(0x0199, 100, 20, '6257'),
  ]);
  assert.equal(report.validations.every_fixed_cluster_timestamp_has_exactly_twelve_rows, false);
  assert.equal(report.validations.all_pass, false);
});

test('CLI is exact-build, explicit-replay, and Holdout fail-closed', () => {
  assert.throws(() => parseArgs([]), /explicit --replay/);
  assert.throws(() => parseArgs(['--build', '16.15.801.3452', '--replay', 'a.rofl']), /exact build/);
  assert.throws(() => parseArgs(['--replay', 'Jungle_Objective_Holdout/a.rofl']), /forbidden/);
  assert.equal(parseArgs(['--replay', 'a.rofl']).build, '16.16.805.0442');
});

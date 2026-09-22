'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { analyzePairEvents } = require('../src/replication_pair_audit');
const { parseArgs } = require('../scripts/audit_replication_route_pair_0092_00b9');

function event(packetId, time, rawParam, offset, payloadHex) {
  return {
    replay_version: '16.16.805.0442',
    replay_sha256: 'replay',
    replay_time_ms: time,
    packet_id: packetId,
    raw_param: rawParam,
    chunk_index: 4,
    decompressed_block_offset: offset,
    payload_length: payloadHex.length / 2,
    raw_payload_hex: payloadHex,
  };
}

test('exact marker/payload pairs retain structural evidence without semantic promotion', () => {
  const events = [
    event(0x00b9, 100, 0x40000100, 10, '91'),
    event(0x0092, 100, 0x40000100, 17, '9299'),
    event(0x00b9, 200, 0x40000101, 30, '91'),
    event(0x0092, 200, 0x40000101, 40, '92e1'),
  ];
  const report = analyzePairEvents(events, { 0x00b9: 2, 0x0092: 2 });
  assert.equal(report.validations.all_pass, true);
  assert.equal(report.counts.exact_replay_time_raw_param_pair_count, 2);
  assert.equal(report.ordering.prefix_before_payload_count, 2);
  assert.equal(report.prefix_marker_payload.value_hex, '91');
  assert.equal(report.decision.semantic_claim, null);
  assert.equal(report.decision.direct_numeric_state_hypothesis, 'REJECT');
  assert.deepEqual(report.route_decisions.map((row) => [row.packet_id, row.decision]), [
    [0x00b9, 'REPURPOSE'],
    [0x0092, 'KEEP_CANDIDATE'],
  ]);
  assert.equal(report.route_decisions[0].positive_anchor_count, 2);
});

test('missing partner and multiplicity mismatch fail one-to-one validation', () => {
  const report = analyzePairEvents([
    event(0x00b9, 100, 1, 10, '91'),
    event(0x00b9, 100, 1, 20, '91'),
    event(0x0092, 100, 1, 27, '9299'),
  ]);
  assert.equal(report.validations.exact_one_to_one_key_match, false);
  assert.equal(report.counts.multiplicity_mismatch_group_count, 1);
});

test('CLI is exact-build, explicit-replay, and Holdout fail-closed', () => {
  assert.throws(() => parseArgs([]), /explicit --replay/);
  assert.throws(() => parseArgs(['--build', '16.15.801.3452', '--replay', 'a.rofl']), /exact build/);
  assert.throws(() => parseArgs(['--replay', 'Jungle_Objective_Holdout/a.rofl']), /forbidden/);
  const options = parseArgs(['--replay', 'a.rofl']);
  assert.equal(options.build, '16.16.805.0442');
});

'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  addRow,
  exactParticipant,
  finishRoute,
  nearestAnchor,
  newRouteAccumulator,
  crossRouteRelationships,
} = require('../src/unknown_route_deep_miner');
const { parseArgs, rejectHoldout } = require('../scripts/mine_high_frequency_unknown_routes');

function row(overrides = {}) {
  const payload = Buffer.from(overrides.payload ?? [0x91]);
  return {
    replay_version: '16.16.805.0442',
    replay_sha256: overrides.replay ?? 'a',
    replay_time_ms: overrides.time ?? 100,
    packet_id: overrides.packetId ?? 0x00b9,
    packet_type: '0x00b9',
    payload_length: payload.length,
    raw_param: overrides.rawParam ?? 0x400000ae,
    raw_payload_hex: payload.toString('hex'),
    raw_payload_sha256: `hash-${payload.toString('hex')}`,
  };
}

test('participant mapping is bounded and retains upper-byte variants as candidates only', () => {
  assert.equal(exactParticipant(0x400000ae), 1);
  assert.equal(exactParticipant(0x123456b7), 10);
  assert.equal(exactParticipant(0x400000ad), null);
  assert.equal(exactParticipant(0x400000b8), null);
});

test('nearest damage anchor is deterministic on both sides', () => {
  const anchors = [
    { time_ms: 90, source: 1, target: 2 },
    { time_ms: 104, source: 3, target: 4 },
  ];
  assert.equal(nearestAnchor(anchors, 100).time_ms, 104);
  assert.equal(nearestAnchor(anchors, 91).time_ms, 90);
  assert.equal(nearestAnchor([], 10), null);
});

test('constant entity-scoped payload remains a candidate marker and never a semantic claim', () => {
  const accumulator = newRouteAccumulator(0x00b9, '0x00b9', 16);
  const anchors = new Map([['a', [{ time_ms: 100, source: 0x400000ae, target: 0x400000af }]]]);
  addRow(accumulator, row({ time: 100 }), anchors, 16);
  addRow(accumulator, row({ time: 110 }), anchors, 16);
  const report = finishRoute(accumulator, null);
  assert.equal(report.payload.distinct_payload_hash_count, 1);
  assert.equal(report.research_decision.hypothesis, 'ENTITY_SCOPED_OPERATION_MARKER_WITH_CONSTANT_PAYLOAD');
  assert.equal(report.research_decision.semantic_claim, null);
  assert.equal(report.research_decision.evidence_exhausted, false);
  assert.equal(report.damage_neighborhood.exact_time_rate, 0.5);
});

test('high-entropy long payload is repurposed as an opaque/container candidate', () => {
  const accumulator = newRouteAccumulator(0x029d, '0x029d', 64);
  const anchors = new Map();
  for (let index = 0; index < 512; index += 1) {
    const payload = Buffer.alloc(96);
    for (let offset = 0; offset < payload.length; offset += 1) payload[offset] = (index * 67 + offset * 131) & 0xff;
    addRow(accumulator, row({
      packetId: 0x029d,
      payload,
      replay: `r${index % 4}`,
      time: index,
      rawParam: 0,
    }), anchors, 64);
  }
  const report = finishRoute(accumulator, null);
  assert.ok(report.payload.scanned_global_byte_entropy_bits > 7.5);
  assert.equal(report.research_decision.decision, 'REPURPOSE');
  assert.equal(report.research_decision.hypothesis, 'OPAQUE_OR_CONTAINERIZED_BULK_UPDATE_FAMILY');
});

test('cross-route matching exposes paired marker structure without semantic promotion', () => {
  const left = newRouteAccumulator(0x0092, '0x0092', 8);
  const right = newRouteAccumulator(0x00b9, '0x00b9', 8);
  const anchors = new Map();
  for (let index = 0; index < 10; index += 1) {
    const shared = { replay: 'a', time: index * 100, rawParam: 0x40000100 + index };
    addRow(left, row({ ...shared, packetId: 0x0092, payload: [0x92, index] }), anchors, 8);
    addRow(right, row({ ...shared, packetId: 0x00b9, payload: [0x91] }), anchors, 8);
  }
  const relationships = crossRouteRelationships(new Map([[0x0092, left], [0x00b9, right]]));
  assert.equal(relationships.length, 1);
  assert.equal(relationships[0].same_replay_time_containment, 1);
  assert.equal(relationships[0].same_replay_time_raw_param_containment, 1);
  assert.equal(relationships[0].semantic_claim, null);
});

test('malformed rows and wrong builds fail closed', () => {
  const accumulator = newRouteAccumulator(0x00b9, '0x00b9', 8);
  assert.throws(() => addRow(accumulator, { ...row(), replay_version: '16.15.801.3452' }, new Map(), 8), /wrong build/);
  assert.throws(() => addRow(accumulator, { ...row(), payload_length: 2 }, new Map(), 8), /payload length mismatch/);
});

test('CLI defaults are exact and Holdout paths fail before reads', () => {
  const options = parseArgs([]);
  assert.equal(options.maxScanBytes, 64);
  assert.match(options.samplePath, /full_semantic_deep_recovery_v2/);
  assert.throws(() => rejectHoldout('Jungle_Objective_Holdout/x.json'), /forbidden/);
});

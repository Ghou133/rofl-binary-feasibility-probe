'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  analyzeRoutePair,
  decodeProtectionByte,
  decodeRoute0473OuterHeader,
} = require('../src/route_pair_01c2_0473_batch_audit');
const {
  SAFE_REPLAY_PATHS,
  parseArgs,
} = require('../scripts/audit_route_pair_01c2_0473_batch');

const IDENTITY_TABLE = Buffer.from([...Array(256).keys()]);

function encodeDecodedByte(value) {
  for (let encoded = 0; encoded < 256; encoded += 1) {
    if (decodeProtectionByte(encoded, IDENTITY_TABLE) === value) return encoded;
  }
  throw new Error(`no encoded byte for ${value}`);
}

function outerPayload(recordCount, length = 64) {
  const encoded = [];
  let value = recordCount;
  do {
    let byte = value & 0x7f;
    value = Math.floor(value / 128);
    if (value) byte |= 0x80;
    encoded.push(encodeDecodedByte(byte));
  } while (value);
  return Buffer.concat([Buffer.from([0xd3, ...encoded]), Buffer.alloc(Math.max(0, length - encoded.length - 1), 0x5a)]);
}

function event(packetId, time, globalIndex, payload) {
  return {
    replay_version: '16.16.805.0442',
    replay_sha256: 'synthetic-replay',
    replay_label: 'synthetic-replay',
    replay_time_ms: time,
    replay_time_seconds_exact: time / 1000,
    global_block_index: globalIndex,
    packet_id: packetId,
    raw_param: 0,
    chunk_index: 4,
    chunk_stream: 'game_chunk',
    decompressed_block_offset: globalIndex * 10,
    payload_length: payload.length,
    raw_payload_hex: payload.toString('hex'),
    payload_buffer: payload,
    next_global_packet_id: null,
    next_global_timestamp_ms: null,
  };
}

test('exact transformed varuint recovers the 0x0473 outer record count', () => {
  assert.deepEqual(decodeRoute0473OuterHeader(outerPayload(1), IDENTITY_TABLE), {
    ok: true,
    outer_tag: 1,
    record_count: 1,
    count_wire_bytes: 1,
    header_bytes: 2,
  });
  const large = decodeRoute0473OuterHeader(outerPayload(300), IDENTITY_TABLE);
  assert.equal(large.ok, true);
  assert.equal(large.record_count, 300);
  assert.equal(large.count_wire_bytes, 2);
  assert.deepEqual(decodeRoute0473OuterHeader(Buffer.from([0xd2]), IDENTITY_TABLE), {
    ok: true,
    outer_tag: 0,
    record_count: 0,
    count_wire_bytes: 0,
    header_bytes: 1,
  });
});

test('optional 0x01c2 run plus immediate 0x0473 vector envelope is repurposed structurally', () => {
  const first = event(0x01c2, 100, 10, Buffer.from('c1aabbcc', 'hex'));
  const second = event(0x01c2, 100, 11, Buffer.from('c5ddeeff94', 'hex'));
  const envelope = event(0x0473, 100, 12, outerPayload(2, 80));
  first.next_global_packet_id = 0x01c2;
  first.next_global_timestamp_ms = 100;
  second.next_global_packet_id = 0x0473;
  second.next_global_timestamp_ms = 100;
  const preludeOnly = event(0x01c2, 200, 20, Buffer.from('c7123456', 'hex'));
  const envelopeOnly = event(0x0473, 300, 30, outerPayload(1, 70));
  const report = analyzeRoutePair([first, second, envelope, preludeOnly, envelopeOnly], {
    expectedCounts: { 0x01c2: 3, 0x0473: 2 },
    outerCountTable: IDENTITY_TABLE,
    runtimeIdentity: { all_checks_pass: true },
  });
  assert.equal(report.validations.all_structural_repurpose_checks_pass, true);
  assert.equal(report.counts.shared_timestamp_group_count, 1);
  assert.equal(report.counts.shared_route_01c2_row_count, 2);
  assert.equal(report.relationship.shared_group_01c2_to_0473_global_immediate_count, 1);
  assert.equal(report.relationship.direct_01c2_payload_contained_in_0473_row_count, 0);
  assert.deepEqual(report.route_decisions.map((row) => row.decision), ['REPURPOSE', 'REPURPOSE']);
  assert.equal(report.capability_decisions[0].decision, 'PROMOTE');
  assert.equal(report.negative_evidence.semantic_claim, null);
});

test('a reversed shared group fails the directional structural invariant', () => {
  const envelope = event(0x0473, 100, 10, outerPayload(1));
  const prelude = event(0x01c2, 100, 11, Buffer.from('c1aabbcc', 'hex'));
  const report = analyzeRoutePair([envelope, prelude], {
    outerCountTable: IDENTITY_TABLE,
    runtimeIdentity: { all_checks_pass: true },
  });
  assert.equal(report.validations.every_shared_exact_timestamp_group_is_unique_0473_after_01c2_in_same_chunk, false);
  assert.equal(report.route_decisions[0].decision, 'KEEP_CANDIDATE');
});

test('CLI requires the exact build, all explicit safe replays, and rejects Holdout paths', () => {
  assert.throws(() => parseArgs([]), /four explicit/);
  assert.throws(() => parseArgs(['--build', '16.15.801.3452', ...SAFE_REPLAY_PATHS.flatMap((value) => ['--replay', value])]), /exact build/);
  assert.throws(() => parseArgs(['--replay', 'Jungle_Objective_Holdout/a.rofl']), /Holdout path is forbidden/);
  assert.throws(() => parseArgs(['--replay', 'C:/tmp/not-governed.rofl']), /four explicitly governed safe/);
  const options = parseArgs(SAFE_REPLAY_PATHS.flatMap((value) => ['--replay', value]));
  assert.equal(options.build, '16.16.805.0442');
  assert.equal(options.replayFiles.length, 4);
  assert.deepEqual(options.replayFiles.map((value) => require('node:path').basename(value)), SAFE_REPLAY_PATHS);
});

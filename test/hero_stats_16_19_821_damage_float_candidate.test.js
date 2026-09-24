'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { decodeRuntimeCountByte } =
  require('../src/decoders/rofl_16_19_821_runtime_bytes');
const {
  PROFILES, assessHeroDamageSnapshotTail821, decodeHeroDamageSnapshotCandidates821,
} = require('../src/decoders/rofl_16_19_821_damage_float_candidate');

const BUILD = '16.19.821.7343';
const ENCODE = new Map(Array.from({ length: 256 }, (_, raw) =>
  [decodeRuntimeCountByte(raw), raw]));
const OFFSETS = Object.freeze({
  toChampions: 0x1e0, dealt: 0x1d0, taken: 0x1f0,
  fromChampions: 0x200, mitigated: 0x208,
});
const VALUES = Object.freeze({
  toChampions: 100.5, dealt: 1000.25, taken: 150.5,
  fromChampions: 120.75, mitigated: 80.25,
});

function writeFloat(payload, offset, value) {
  const bytes = Buffer.alloc(4);
  bytes.writeFloatLE(value);
  for (let i = 0; i < 4; i += 1) {
    payload[1262 - offset - i] = ENCODE.get(bytes[i]);
  }
}

function packet(participant, values, timeMs, change = null) {
  const payload = Buffer.alloc(1263, 0x97);
  payload.set([0x67, 0x00, 0xde]);
  for (const [name, offset] of Object.entries(OFFSETS)) {
    writeFloat(payload, offset, values[name]);
  }
  if (change) change(payload);
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x0089, 9);
  header.writeUInt32LE(0x400000ad + participant, 11);
  return Buffer.concat([header, payload]);
}

function fixture({ version = BUILD, change = null, thirdValues = null } = {}) {
  const frameCount = thirdValues ? 3 : 2;
  const chunks = Array.from({ length: frameCount }, (_, frame) => ({
    stream: 2,
    body: Buffer.concat(Array.from({ length: 10 }, (_, index) => {
      const values = frame === 0 || index !== 0 ? {
        toChampions: 0, dealt: 0, taken: 0, fromChampions: 0, mitigated: 0,
      } : frame === 2 ? thirdValues : VALUES;
      return packet(index + 1, values, frame * 1000,
        frame === 1 && index === 0 ? change : null);
    })),
  }));
  const replay = replayFromChunks(chunks, version);
  replay.tail.stats = Array.from({ length: 10 }, (_, index) => ({
    TOTAL_DAMAGE_DEALT_TO_CHAMPIONS: String(index === 0 ? 105 : 0),
    TOTAL_DAMAGE_DEALT: String(index === 0 ? 1010 : 0),
    TOTAL_DAMAGE_TAKEN: String(index === 0 ? 155 : 0),
    TOTAL_DAMAGE_TAKEN_FROM_CHAMPIONS: String(index === 0 ? 125 : 0),
    TOTAL_DAMAGE_SELF_MITIGATED: String(index === 0 ? 85 : 0),
  }));
  return replay;
}

test('821 candidate damage snapshots expose five exact f32 values and field-specific tail gaps', () => {
  const replay = fixture();
  const expected = [
    ['hero_damage_totals_snapshot', 'damage_to_champions_raw_f32_candidate', 100.5, 30],
    ['hero_damage_taken_from_champions_snapshot',
      'damage_taken_from_champions_raw_f32_candidate', 120.75, 10],
    ['hero_damage_self_mitigated_snapshot', 'damage_self_mitigated_raw_f32_candidate',
      80.25, 10],
  ];
  for (const [capability, key, value, gapRows] of expected) {
    assert.equal(PROFILES[capability].replay_version, BUILD);
    assert.equal(assessHeroDamageSnapshotTail821(replay, capability).status, 'PASS');
    const output = decodeHeroDamageSnapshotCandidates821(replay, capability);
    assert.equal(output.status, 'CANDIDATE');
    assert.equal(output.event_count, 20);
    assert.equal(output.events[10][key], value);
    assert.equal(output.events[10].raw_packet_ref.replay_sha256, replay.source_sha256);
    assert.equal(output.events[10].confidence, 'CANDIDATE');
    assert.equal(output.runtime_image_used, false);
    assert.equal(output.tail_gaps.length, gapRows);
  }
  const totals = decodeHeroDamageSnapshotCandidates821(replay, 'hero_damage_totals_snapshot');
  assert.equal(totals.events[10].total_damage_dealt_raw_f32_candidate, 1000.25);
  assert.equal(totals.events[10].total_damage_taken_raw_f32_candidate, 150.5);
  assert.equal(totals.total_unobserved_tail_gap_by_field.TOTAL_DAMAGE_DEALT_TO_CHAMPIONS, 5);
  assert.equal(totals.total_unobserved_tail_gap_by_field.TOTAL_DAMAGE_DEALT, 10);
  assert.equal(totals.total_unobserved_tail_gap_by_field.TOTAL_DAMAGE_TAKEN, 5);
});

test('821 damage candidates fail closed on missing tail, above-tail, NaN and decrease', () => {
  const missing = fixture();
  delete missing.tail.stats[0].TOTAL_DAMAGE_TAKEN;
  assert.equal(decodeHeroDamageSnapshotCandidates821(missing, 'hero_damage_totals_snapshot').status,
    'MISSING_INPUT');
  assert.equal(decodeHeroDamageSnapshotCandidates821(
    missing, 'hero_damage_self_mitigated_snapshot').status, 'CANDIDATE');

  const above = fixture();
  above.tail.stats[0].TOTAL_DAMAGE_TAKEN_FROM_CHAMPIONS = '100';
  const aboveResult = decodeHeroDamageSnapshotCandidates821(
    above, 'hero_damage_taken_from_champions_snapshot');
  assert.equal(aboveResult.status, 'DECODE_FAILED');
  assert.match(aboveResult.error, /exceeds Replay tail TOTAL_DAMAGE_TAKEN_FROM_CHAMPIONS/);

  const nan = decodeHeroDamageSnapshotCandidates821(fixture({
    change(payload) { writeFloat(payload, OFFSETS.mitigated, Number.NaN); },
  }), 'hero_damage_self_mitigated_snapshot');
  assert.equal(nan.status, 'DECODE_FAILED');
  assert.match(nan.error, /not finite/);

  const decreasing = fixture({ thirdValues: { ...VALUES, toChampions: 90 } });
  const descent = decodeHeroDamageSnapshotCandidates821(
    decreasing, 'hero_damage_totals_snapshot');
  assert.equal(descent.status, 'DECODE_FAILED');
  assert.match(descent.error, /decreasing TOTAL_DAMAGE_DEALT_TO_CHAMPIONS/);
});

test('821 damage candidates reject foreign builds and mutated Replay sources', () => {
  assert.equal(decodeHeroDamageSnapshotCandidates821(
    fixture({ version: '16.19.820.7193' }), 'hero_damage_totals_snapshot').status,
  'UNSUPPORTED');
  const replay = fixture();
  replay.buffer[replay.chunks[0].body_offset + 15 + 830] ^= 1;
  const output = decodeHeroDamageSnapshotCandidates821(replay, 'hero_damage_totals_snapshot');
  assert.equal(output.status, 'DECODE_FAILED');
  assert.match(output.error, /Replay source failed/);
});

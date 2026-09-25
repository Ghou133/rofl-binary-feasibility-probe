'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { collect821Routes } = require('../src/decoders/rofl_16_19_821_scan');
const { decodeRuntimeCountByte } =
  require('../src/decoders/rofl_16_19_821_runtime_bytes');
const {
  PROFILES, assessHeroHealSnapshotTail821,
  decodeHeroHealSnapshotCandidates821,
} = require('../src/decoders/rofl_16_19_821_heal_stats_candidate');

const BUILD = '16.19.821.7343';
const ENCODE = new Map(Array.from({ length: 256 }, (_, raw) =>
  [decodeRuntimeCountByte(raw), raw]));

function writeUInt32(payload, offset, value) {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32LE(value);
  for (let i = 0; i < 4; i += 1) {
    payload[1262 - offset - i] = ENCODE.get(bytes[i]);
  }
}

function packet(participant, values, timeMs, change = null) {
  const payload = Buffer.alloc(1263, ENCODE.get(0));
  payload.set([0x67, 0x00, 0xde]);
  writeUInt32(payload, 0x234, values.heal);
  writeUInt32(payload, 0x23c, values.units);
  if (change) change(payload);
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x0089, 9);
  header.writeUInt32LE(0x400000ad + participant, 11);
  return Buffer.concat([header, payload]);
}

function fixture({ version = BUILD, healTail = 150, unitsTail = 3,
  change = null, first = false, healDecrease = false } = {}) {
  const chunks = Array.from({ length: healDecrease ? 3 : 2 }, (_, frame) => ({
    stream: 2,
    body: Buffer.concat(Array.from({ length: 10 }, (_, index) => {
      const values = frame === 0 || index !== 0
        ? { heal: first && frame === 0 && index === 0 ? 1 : 0, units: 0 }
        : { heal: frame === 2 ? 100 : 123, units: 2 };
      return packet(index + 1, values, frame * 1000,
        frame === 1 && index === 0 ? change : null);
    })),
  }));
  const replay = replayFromChunks(chunks, version);
  replay.tail.stats = Array.from({ length: 10 }, (_, index) => ({
    TOTAL_HEAL: index === 0 ? String(healTail) : '0',
    TOTAL_UNITS_HEALED: index === 0 ? String(unitsTail) : '0',
  }));
  return replay;
}

test('821 healing counters decode exact transformed u32 snapshots with provenance and tail gaps', () => {
  const replay = fixture();
  for (const [capability, valueKey, expected, expectedGap] of [
    ['hero_total_heal_snapshot', 'total_heal_candidate', 123, 27],
    ['hero_total_units_healed_snapshot', 'total_units_healed_candidate', 2, 1],
  ]) {
    assert.equal(PROFILES[capability].replay_version, BUILD);
    assert.equal(assessHeroHealSnapshotTail821(replay, capability).status, 'PASS');
    const output = decodeHeroHealSnapshotCandidates821(replay, capability);
    assert.equal(output.status, 'CANDIDATE');
    assert.equal(output.event_count, 20);
    assert.equal(output.events[10][valueKey], expected);
    assert.equal(output.events[10].raw_payload_field_bytes_hex.length, 8);
    assert.equal(output.events[10].raw_packet_ref.replay_sha256, replay.source_sha256);
    assert.equal(output.events[10].confidence, 'CANDIDATE');
    assert.equal(output.runtime_image_used, false);
    assert.equal(output.tail_gaps[0].unobserved_tail_gap, expectedGap);
  }
});

test('821 healing snapshot accepts a source-bound shared route scan', () => {
  const replay = fixture();
  const token = collect821Routes(replay,
    ['hero_total_heal_snapshot', 'hero_total_units_healed_snapshot']);
  const heal = decodeHeroHealSnapshotCandidates821(replay,
    'hero_total_heal_snapshot', token);
  const units = decodeHeroHealSnapshotCandidates821(replay,
    'hero_total_units_healed_snapshot', token);
  assert.equal(heal.status, 'CANDIDATE');
  assert.equal(units.status, 'CANDIDATE');
  assert.equal(heal.event_count, 20);
  assert.equal(units.event_count, 20);
  const foreign = decodeHeroHealSnapshotCandidates821(fixture(),
    'hero_total_heal_snapshot', token);
  assert.equal(foreign.status, 'DECODE_FAILED');
  assert.match(foreign.error, /different Replay/);
});

test('821 healing counters fail closed on wrong build, missing and exceeded tails', () => {
  assert.equal(decodeHeroHealSnapshotCandidates821(
    fixture({ version: '16.19.820.7193' }), 'hero_total_heal_snapshot').status,
  'UNSUPPORTED');
  const missing = fixture();
  delete missing.tail.stats[0].TOTAL_UNITS_HEALED;
  assert.equal(decodeHeroHealSnapshotCandidates821(
    missing, 'hero_total_units_healed_snapshot').status, 'MISSING_INPUT');
  const above = decodeHeroHealSnapshotCandidates821(
    fixture({ healTail: 120 }), 'hero_total_heal_snapshot');
  assert.equal(above.status, 'DECODE_FAILED');
  assert.match(above.error, /exceeds Replay tail TOTAL_HEAL/);
  const first = decodeHeroHealSnapshotCandidates821(
    fixture({ first: true }), 'hero_total_heal_snapshot');
  assert.equal(first.status, 'DECODE_FAILED');
  assert.match(first.error, /first TOTAL_HEAL count is not zero/);
  const decrease = decodeHeroHealSnapshotCandidates821(
    fixture({ healDecrease: true }), 'hero_total_heal_snapshot');
  assert.equal(decrease.status, 'DECODE_FAILED');
  assert.match(decrease.error, /decreasing observed TOTAL_HEAL/);
});

test('821 healing counters reject a mutated Replay source', () => {
  const replay = fixture();
  replay.buffer[replay.chunks[0].body_offset + 15 + 830] ^= 1;
  const output = decodeHeroHealSnapshotCandidates821(replay,
    'hero_total_heal_snapshot');
  assert.equal(output.status, 'DECODE_FAILED');
  assert.match(output.error, /Replay source failed/);
});

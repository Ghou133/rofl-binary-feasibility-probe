'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { decodeRuntimeCountByte } =
  require('../src/decoders/rofl_16_19_821_runtime_bytes');
const {
  PROFILES, assessHeroTimeSnapshotTail821,
  decodeHeroTimeSnapshotCandidates821,
} = require('../src/decoders/rofl_16_19_821_time_stats_candidate');

const BUILD = '16.19.821.7343';
const ENCODE = new Map(Array.from({ length: 256 }, (_, raw) =>
  [decodeRuntimeCountByte(raw), raw]));

function writeFloat(payload, offset, value) {
  const bytes = Buffer.alloc(4);
  bytes.writeFloatLE(value);
  for (let i = 0; i < 4; i += 1) {
    payload[1262 - offset - i] = ENCODE.get(bytes[i]);
  }
}

function packet(participant, living, dead, timeMs, change = null) {
  const payload = Buffer.alloc(1263, 0x97);
  payload.set([0x67, 0x00, 0xde]);
  writeFloat(payload, 0x244, living);
  writeFloat(payload, 0x248, dead);
  if (change) change(payload);
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x0089, 9);
  header.writeUInt32LE(0x400000ad + participant, 11);
  return Buffer.concat([header, payload]);
}

function fixture({ version = BUILD, livingTail = 101, deadTail = 22,
  change = null, third = false } = {}) {
  const chunks = Array.from({ length: third ? 3 : 2 }, (_, frame) => ({
    stream: 2,
    body: Buffer.concat(Array.from({ length: 10 }, (_, index) => {
      const selected = index === 0;
      const living = frame === 0 || !selected ? 0
        : frame === 2 ? 80 : 100.5;
      const dead = frame === 0 || !selected ? 0
        : frame === 2 ? 10 : 20.75;
      return packet(index + 1, living, dead, frame * 1000,
        frame === 1 && selected ? change : null);
    })),
  }));
  const replay = replayFromChunks(chunks, version);
  replay.tail.stats = Array.from({ length: 10 }, (_, index) => ({
    LONGEST_TIME_SPENT_LIVING: index === 0 ? String(livingTail) : '0',
    TOTAL_TIME_SPENT_DEAD: index === 0 ? String(deadTail) : '0',
  }));
  return replay;
}

test('821 time snapshots preserve raw f32, floors, packet refs, and tail gaps', () => {
  const replay = fixture();
  const cases = [
    ['hero_longest_living_time_snapshot',
      'longest_living_time_raw_f32_candidate', 100.5, 1],
    ['hero_total_time_spent_dead_snapshot',
      'total_time_spent_dead_raw_f32_candidate', 20.75, 2],
  ];
  for (const [capability, valueKey, value, gap] of cases) {
    assert.equal(PROFILES[capability].replay_version, BUILD);
    assert.equal(assessHeroTimeSnapshotTail821(replay, capability).status, 'PASS');
    const output = decodeHeroTimeSnapshotCandidates821(replay, capability);
    assert.equal(output.status, 'CANDIDATE');
    assert.equal(output.event_count, 20);
    assert.equal(output.events[10][valueKey], value);
    assert.equal(output.events[10].raw_packet_ref.replay_sha256, replay.source_sha256);
    assert.equal(output.events[10].confidence, 'CANDIDATE');
    assert.equal(output.tail_gaps[0].unobserved_tail_gap_seconds, gap);
    assert.equal(output.runtime_image_used, false);
  }
});

test('821 time snapshots fail closed on wrong build, missing tail, and values above tail', () => {
  assert.equal(decodeHeroTimeSnapshotCandidates821(
    fixture({ version: '16.19.820.7193' }),
    'hero_longest_living_time_snapshot').status, 'UNSUPPORTED');
  const missing = fixture();
  delete missing.tail.stats[0].TOTAL_TIME_SPENT_DEAD;
  assert.equal(decodeHeroTimeSnapshotCandidates821(
    missing, 'hero_total_time_spent_dead_snapshot').status, 'MISSING_INPUT');
  const above = decodeHeroTimeSnapshotCandidates821(
    fixture({ livingTail: 99 }), 'hero_longest_living_time_snapshot');
  assert.equal(above.status, 'DECODE_FAILED');
  assert.match(above.error, /exceeds Replay tail LONGEST_TIME_SPENT_LIVING/);
});

test('821 time snapshots reject NaN, negative, and decreasing values', () => {
  const invalid = [
    [Number.NaN, /not finite/],
    [-1, /not finite/],
  ];
  for (const [value, error] of invalid) {
    const output = decodeHeroTimeSnapshotCandidates821(fixture({
      change(payload) { writeFloat(payload, 0x248, value); },
    }), 'hero_total_time_spent_dead_snapshot');
    assert.equal(output.status, 'DECODE_FAILED');
    assert.match(output.error, error);
  }
  const decreased = decodeHeroTimeSnapshotCandidates821(
    fixture({ third: true }), 'hero_longest_living_time_snapshot');
  assert.equal(decreased.status, 'DECODE_FAILED');
  assert.match(decreased.error, /decreasing LONGEST_TIME_SPENT_LIVING/);
});

test('821 time snapshots reject mutated Replay source', () => {
  const replay = fixture();
  replay.buffer[replay.chunks[0].body_offset + 15 + 760] ^= 1;
  const output = decodeHeroTimeSnapshotCandidates821(
    replay, 'hero_longest_living_time_snapshot');
  assert.equal(output.status, 'DECODE_FAILED');
  assert.match(output.error, /Replay source failed/);
});

'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { decodeRuntimeCountByte } =
  require('../src/decoders/rofl_16_19_821_runtime_bytes');
const {
  PROFILES, assessHeroEpicCcSnapshotTail821,
  decodeHeroEpicCcSnapshotCandidates821,
} = require('../src/decoders/rofl_16_19_821_epic_cc_candidate');

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

function packet(participant, epic, cc, timeMs, change = null) {
  const payload = Buffer.alloc(1263, 0x97);
  payload.set([0x67, 0x00, 0xde]);
  writeFloat(payload, 0x21c, epic);
  writeFloat(payload, 0x230, cc);
  if (change) change(payload);
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x0089, 9);
  header.writeUInt32LE(0x400000ad + participant, 11);
  return Buffer.concat([header, payload]);
}

function fixture({ version = BUILD, tailEpic = 101, tailCc = 4,
  secondEpic = 100.5, secondCc = 3.75, change = null } = {}) {
  const replay = replayFromChunks(Array.from({ length: 2 }, (_, frame) => ({
    stream: 2,
    body: Buffer.concat(Array.from({ length: 10 }, (_, index) => packet(index + 1,
      frame === 1 && index === 0 ? secondEpic : 0,
      frame === 1 && index === 0 ? secondCc : 0,
      frame * 1000,
      frame === 1 && index === 0 ? change : null))),
  })), version);
  replay.tail.stats = Array.from({ length: 10 }, (_, index) => ({
    TOTAL_DAMAGE_DEALT_TO_EPIC_MONSTERS: index === 0 ? String(tailEpic) : '0',
    TOTAL_TIME_CROWD_CONTROL_DEALT_TO_CHAMPIONS: index === 0 ? String(tailCc) : '0',
  }));
  return replay;
}

test('821 epic and crowd-control totals expose exact candidate f32 snapshots', () => {
  const replay = fixture();
  for (const [capability, key, expected] of [
    ['hero_epic_monster_damage_snapshot', 'epic_monster_damage_raw_f32_candidate', 100.5],
    ['hero_crowd_control_time_snapshot', 'crowd_control_time_raw_f32_candidate', 3.75],
  ]) {
    assert.equal(PROFILES[capability].replay_version, BUILD);
    assert.equal(assessHeroEpicCcSnapshotTail821(replay, capability).status, 'PASS');
    const output = decodeHeroEpicCcSnapshotCandidates821(replay, capability);
    assert.equal(output.status, 'CANDIDATE');
    assert.equal(output.event_count, 20);
    assert.equal(output.events[10][key], expected);
    assert.equal(output.events[10].raw_packet_ref.replay_sha256, replay.source_sha256);
    assert.equal(output.events[10].confidence, 'CANDIDATE');
    assert.equal(output.total_unobserved_tail_gap, 1);
  }
});

test('821 epic and crowd-control candidates reject wrong build and missing tail', () => {
  assert.equal(decodeHeroEpicCcSnapshotCandidates821(
    fixture({ version: '16.19.820.7193' }), 'hero_epic_monster_damage_snapshot').status,
  'UNSUPPORTED');
  const missing = fixture();
  delete missing.tail.stats[0].TOTAL_TIME_CROWD_CONTROL_DEALT_TO_CHAMPIONS;
  assert.equal(decodeHeroEpicCcSnapshotCandidates821(
    missing, 'hero_crowd_control_time_snapshot').status, 'MISSING_INPUT');
});

test('821 epic and crowd-control candidates fail closed on numeric counterexamples', () => {
  const above = decodeHeroEpicCcSnapshotCandidates821(
    fixture({ tailEpic: 99 }), 'hero_epic_monster_damage_snapshot');
  assert.equal(above.status, 'DECODE_FAILED');
  assert.match(above.error, /exceeds Replay tail TOTAL_DAMAGE_DEALT_TO_EPIC_MONSTERS/);
  const negative = decodeHeroEpicCcSnapshotCandidates821(
    fixture({ secondCc: -1 }), 'hero_crowd_control_time_snapshot');
  assert.equal(negative.status, 'DECODE_FAILED');
  assert.match(negative.error, /not finite, nonnegative/);
  const nan = decodeHeroEpicCcSnapshotCandidates821(fixture({
    change(payload) { writeFloat(payload, 0x21c, Number.NaN); },
  }), 'hero_epic_monster_damage_snapshot');
  assert.equal(nan.status, 'DECODE_FAILED');
  assert.match(nan.error, /not finite/);
});

test('821 epic and crowd-control candidates refuse mutated Replay source', () => {
  const replay = fixture();
  replay.buffer[replay.chunks[0].body_offset + 15 + 830] ^= 1;
  const output = decodeHeroEpicCcSnapshotCandidates821(
    replay, 'hero_crowd_control_time_snapshot');
  assert.equal(output.status, 'DECODE_FAILED');
  assert.match(output.error, /Replay source failed/);
});

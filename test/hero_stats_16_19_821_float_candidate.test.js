'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { decodeRuntimeCountByte } =
  require('../src/decoders/rofl_16_19_821_runtime_bytes');
const {
  PROFILES, assessHeroFloatSnapshotTail821, assessHeroJungleMinionsTail821,
  decodeHeroFloatSnapshotCandidates821,
} = require('../src/decoders/rofl_16_19_821_float_stats_candidate');

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

function packet(participant, values, timeMs, change = null) {
  const payload = Buffer.alloc(1263, 0x97);
  payload.set([0x67, 0x00, 0xde]);
  for (const [name, offset] of [
    ['minions', 0x3c], ['exp', 0x28], ['vision', 0x1b0],
    ['earned', 0x38], ['spent', 0x34],
    ['jungle', 0x40], ['ownJungle', 0x44], ['enemyJungle', 0x48],
  ]) writeFloat(payload, offset, values[name]);
  if (change) change(payload);
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x0089, 9);
  header.writeUInt32LE(0x400000ad + participant, 11);
  return Buffer.concat([header, payload]);
}

function fixture({ version = BUILD, tailVision = 4, tailMinions = 15,
  tailJungle = 8, tailOwnJungle = 6, tailEnemyJungle = 2,
  change = null, spentDecrease = false, minionsDecrease = false,
  jungleDecrease = false } = {}) {
  const chunks = Array.from({ length:
    spentDecrease || minionsDecrease || jungleDecrease ? 3 : 2 }, (_, frame) => ({
    stream: 2,
    body: Buffer.concat(Array.from({ length: 10 }, (_, index) => {
      const first = index === 0;
      const values = frame === 0 || !first
        ? { minions: 0, exp: 0, vision: 0, earned: 500, spent: 0,
          jungle: 0, ownJungle: 0, enemyJungle: 0 }
        : { minions: minionsDecrease && frame === 2 ? 10 : 12,
          exp: 100.5, vision: 3.75, earned: 600.5,
          spent: spentDecrease && frame === 2 ? 100 : 150,
          jungle: jungleDecrease && frame === 2 ? 4.75 : 5.75,
          ownJungle: jungleDecrease && frame === 2 ? 3.5 : 4.5,
          enemyJungle: 1.25 };
      return packet(index + 1, values, frame * 1000,
        frame === 1 && first ? change : null);
    })),
  }));
  const replay = replayFromChunks(chunks, version);
  replay.tail.stats = Array.from({ length: 10 }, (_, index) => ({
    MINIONS_KILLED: index === 0 ? String(tailMinions) : '0',
    NEUTRAL_MINIONS_KILLED: index === 0 ? String(tailJungle) : '0',
    NEUTRAL_MINIONS_KILLED_YOUR_JUNGLE: index === 0
      ? String(tailOwnJungle) : '0',
    NEUTRAL_MINIONS_KILLED_ENEMY_JUNGLE: index === 0
      ? String(tailEnemyJungle) : '0',
    Missions_MinionsKilled: index === 0 ? '2' : '0',
    EXP: index === 0 ? '101' : '0',
    VISION_SCORE: index === 0 ? String(tailVision) : '0',
    GOLD_EARNED: index === 0 ? '700' : '500',
    GOLD_SPENT: index === 0 ? '150' : '0',
  }));
  return replay;
}

test('821 float snapshot candidates expose exact decoded numbers and tails', () => {
  const replay = fixture();
  const expected = [
    ['hero_minions_killed_snapshot', 'minions_killed_raw_f32_candidate', 12],
    ['hero_jungle_minions_killed_snapshot',
      'jungle_minions_killed_raw_f32_candidate', 5.75],
    ['hero_experience_snapshot', 'experience_raw_f32_candidate', 100.5],
    ['hero_vision_score_snapshot', 'vision_score_raw_f32_candidate', 3.75],
    ['hero_gold_earned_snapshot', 'gold_earned_raw_f32_candidate', 600.5],
    ['hero_gold_spent_snapshot', 'gold_spent_raw_f32_candidate', 150],
  ];
  for (const [capability, key, value] of expected) {
    assert.equal(PROFILES[capability].replay_version, BUILD);
    assert.equal(assessHeroFloatSnapshotTail821(replay, capability).status, 'PASS');
    const output = decodeHeroFloatSnapshotCandidates821(replay, capability);
    assert.equal(output.status, 'CANDIDATE');
    assert.equal(output.event_count, 20);
    assert.equal(output.events[10][key], value);
    assert.equal(output.events[10].raw_packet_ref.replay_sha256, replay.source_sha256);
    assert.equal(output.events[10].confidence, 'CANDIDATE');
    assert.equal(output.runtime_image_used, false);
    assert.ok(output.total_unobserved_tail_gap >= 0);
  }
});

test('821 jungle candidate keeps three tail fields and fractional snapshots distinct', () => {
  const replay = fixture();
  const assessed = assessHeroJungleMinionsTail821(replay);
  assert.equal(assessed.status, 'PASS');
  assert.deepEqual(assessed.required_fields.map((row) => row.field), [
    'NEUTRAL_MINIONS_KILLED',
    'NEUTRAL_MINIONS_KILLED_YOUR_JUNGLE',
    'NEUTRAL_MINIONS_KILLED_ENEMY_JUNGLE',
  ]);
  assert.deepEqual(PROFILES.hero_jungle_minions_killed_snapshot.replay_tail_fields, [
    'NEUTRAL_MINIONS_KILLED',
    'NEUTRAL_MINIONS_KILLED_YOUR_JUNGLE',
    'NEUTRAL_MINIONS_KILLED_ENEMY_JUNGLE',
  ]);
  const output = decodeHeroFloatSnapshotCandidates821(replay,
    'hero_jungle_minions_killed_snapshot');
  assert.equal(output.status, 'CANDIDATE');
  assert.equal(output.input_packet_id, 0x0089);
  assert.equal(output.event_count, 20);
  assert.equal(output.events[10].jungle_minions_killed_raw_f32_candidate, 5.75);
  assert.equal(output.events[10].jungle_minions_killed_floor_candidate, 5);
  assert.equal(output.events[10].your_jungle_minions_killed_raw_f32_candidate, 4.5);
  assert.equal(output.events[10].your_jungle_minions_killed_floor_candidate, 4);
  assert.equal(output.events[10].enemy_jungle_minions_killed_raw_f32_candidate, 1.25);
  assert.equal(output.events[10].enemy_jungle_minions_killed_floor_candidate, 1);
  assert.equal(output.events[10].raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.equal(Object.keys(output.events[10].raw_payload_field_bytes_hex).length, 3);
  assert.equal(output.tail_gaps[0].final_neutral_minions_killed_tail, 8);
  assert.equal(output.tail_gaps[0].unobserved_tail_gap, 3);
  assert.equal(output.tail_gaps[0].unobserved_your_jungle_tail_gap, 2);
  assert.equal(output.tail_gaps[0].unobserved_enemy_jungle_tail_gap, 1);
  assert.equal(output.total_unobserved_tail_gap, 3);
  assert.equal(output.total_unobserved_your_jungle_tail_gap, 2);
  assert.equal(output.total_unobserved_enemy_jungle_tail_gap, 1);
});

test('821 jungle candidate fails closed for each missing tail and malformed field', () => {
  assert.equal(decodeHeroFloatSnapshotCandidates821(fixture({
    version: '16.19.820.7193',
  }), 'hero_jungle_minions_killed_snapshot').status, 'UNSUPPORTED');
  for (const field of PROFILES.hero_jungle_minions_killed_snapshot.replay_tail_fields) {
    const missing = fixture();
    delete missing.tail.stats[0][field];
    const output = decodeHeroFloatSnapshotCandidates821(missing,
      'hero_jungle_minions_killed_snapshot');
    assert.equal(output.status, 'MISSING_INPUT');
    assert.match(output.error, new RegExp(field));
    const assessed = assessHeroJungleMinionsTail821(missing);
    assert.equal(assessed.required_fields.length, 3);
    assert.deepEqual(assessed.required_fields.map((row) => row.status),
      assessed.required_fields.map((row) => row.field === field
        ? 'MISSING_INPUT' : 'PASS'));
  }
  for (const [tailOption, field] of [
    ['tailJungle', 'NEUTRAL_MINIONS_KILLED'],
    ['tailOwnJungle', 'NEUTRAL_MINIONS_KILLED_YOUR_JUNGLE'],
    ['tailEnemyJungle', 'NEUTRAL_MINIONS_KILLED_ENEMY_JUNGLE'],
  ]) {
    const output = decodeHeroFloatSnapshotCandidates821(
      fixture({ [tailOption]: 0 }), 'hero_jungle_minions_killed_snapshot');
    assert.equal(output.status, 'DECODE_FAILED');
    assert.match(output.error, new RegExp(`exceeds Replay tail ${field}`));
  }
  const nonFinite = decodeHeroFloatSnapshotCandidates821(fixture({
    change(payload) { writeFloat(payload, 0x48, Number.NaN); },
  }), 'hero_jungle_minions_killed_snapshot');
  assert.equal(nonFinite.status, 'DECODE_FAILED');
  assert.match(nonFinite.error, /NEUTRAL_MINIONS_KILLED_ENEMY_JUNGLE f32 is not finite/);
  const decrease = decodeHeroFloatSnapshotCandidates821(fixture({
    jungleDecrease: true,
  }), 'hero_jungle_minions_killed_snapshot');
  assert.equal(decrease.status, 'DECODE_FAILED');
  assert.match(decrease.error, /decreasing NEUTRAL_MINIONS_KILLED f32/);
});

test('821 standard minion snapshot remains distinct from mission count and retains tail gap', () => {
  const output = decodeHeroFloatSnapshotCandidates821(fixture(),
    'hero_minions_killed_snapshot');
  assert.equal(output.status, 'CANDIDATE');
  assert.equal(output.events[10].minions_killed_raw_f32_candidate, 12);
  assert.equal(output.events[10].minions_killed_floor_candidate, 12);
  assert.equal(output.tail_gaps[0].unobserved_tail_gap, 3);
  assert.equal(output.total_unobserved_tail_gap, 3);
  assert.equal(output.tail_gaps[0].final_replay_tail, 15);
  assert.equal(PROFILES.hero_minions_killed_snapshot.replay_tail_field, 'MINIONS_KILLED');
  assert.equal(PROFILES.hero_minions_killed_snapshot.blob_f32le_offset_candidate, 0x3c);
});

test('821 gold-spent snapshot retains an observed decrease', () => {
  const output = decodeHeroFloatSnapshotCandidates821(
    fixture({ spentDecrease: true }), 'hero_gold_spent_snapshot');
  assert.equal(output.status, 'CANDIDATE');
  assert.equal(output.descent_count, 1);
  assert.equal(output.events[20].gold_spent_raw_f32_candidate, 100);
  assert.equal(output.events[20].decreased_since_previous_snapshot, true);
});

test('821 float candidates fail closed on foreign build, missing tail, above-tail and NaN', () => {
  assert.equal(decodeHeroFloatSnapshotCandidates821(
    fixture({ version: '16.19.820.7193' }), 'hero_experience_snapshot').status,
  'UNSUPPORTED');
  assert.equal(decodeHeroFloatSnapshotCandidates821(
    fixture({ version: '16.19.820.7193' }), 'hero_minions_killed_snapshot').status,
  'UNSUPPORTED');
  const missing = fixture();
  delete missing.tail.stats[0].GOLD_EARNED;
  assert.equal(decodeHeroFloatSnapshotCandidates821(
    missing, 'hero_gold_earned_snapshot').status, 'MISSING_INPUT');
  const above = decodeHeroFloatSnapshotCandidates821(
    fixture({ tailVision: 2 }), 'hero_vision_score_snapshot');
  assert.equal(above.status, 'DECODE_FAILED');
  assert.match(above.error, /exceeds Replay tail VISION_SCORE/);
  const nan = decodeHeroFloatSnapshotCandidates821(fixture({
    change(payload) { writeFloat(payload, 0x28, Number.NaN); },
  }), 'hero_experience_snapshot');
  assert.equal(nan.status, 'DECODE_FAILED');
  assert.match(nan.error, /not finite/);
  const missingMinions = fixture();
  delete missingMinions.tail.stats[0].MINIONS_KILLED;
  assert.equal(decodeHeroFloatSnapshotCandidates821(missingMinions,
    'hero_minions_killed_snapshot').status, 'MISSING_INPUT');
  const aboveMinions = decodeHeroFloatSnapshotCandidates821(
    fixture({ tailMinions: 11 }), 'hero_minions_killed_snapshot');
  assert.equal(aboveMinions.status, 'DECODE_FAILED');
  assert.match(aboveMinions.error, /exceeds Replay tail MINIONS_KILLED/);
  const fractionalMinions = decodeHeroFloatSnapshotCandidates821(fixture({
    change(payload) { writeFloat(payload, 0x3c, 12.5); },
  }), 'hero_minions_killed_snapshot');
  assert.equal(fractionalMinions.status, 'DECODE_FAILED');
  assert.match(fractionalMinions.error, /not integral/);
  const decreasingMinions = decodeHeroFloatSnapshotCandidates821(
    fixture({ minionsDecrease: true }), 'hero_minions_killed_snapshot');
  assert.equal(decreasingMinions.status, 'DECODE_FAILED');
  assert.match(decreasingMinions.error, /decreasing MINIONS_KILLED f32/);
});

test('821 float snapshot refuses a mutated Replay source', () => {
  const replay = fixture();
  replay.buffer[replay.chunks[0].body_offset + 15 + 830] ^= 1;
  const output = decodeHeroFloatSnapshotCandidates821(replay, 'hero_vision_score_snapshot');
  assert.equal(output.status, 'DECODE_FAILED');
  assert.match(output.error, /Replay source failed/);
});

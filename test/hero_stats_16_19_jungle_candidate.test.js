'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const {
  HERO_JUNGLE_MINIONS_KILLED_SNAPSHOT_CANDIDATE_PROFILE: profile,
  analyzeReplayWithHeroStats,
  assessHeroJungleMinionsKilledSnapshotTail,
  decodeHeroStatsByte,
  decodeHeroJungleMinionsKilledPayload,
  decodeHeroJungleMinionsKilledSnapshotCandidates,
  decodeHeroMinionsKilledSnapshotCandidates,
  decodeHeroStatsSnapshotCandidateSet,
} = require('../src/decoders/rofl_16_19_hero_stats_candidate');
const { decodeSemanticReplay, getHeroJungleMinionsKilledSnapshotCandidates } =
  require('../src/semantic_api');

const BUILD = '16.19.820.7193';
const CAPABILITY = 'hero_jungle_minions_killed_snapshot';
const TAIL_FIELDS = [
  'NEUTRAL_MINIONS_KILLED',
  'NEUTRAL_MINIONS_KILLED_YOUR_JUNGLE',
  'NEUTRAL_MINIONS_KILLED_ENEMY_JUNGLE',
];
const ENCODE_BYTE = Array(256).fill(null);
for (let encoded = 0; encoded < 256; encoded += 1) {
  ENCODE_BYTE[decodeHeroStatsByte(encoded)] = encoded;
}
assert.ok(ENCODE_BYTE.every((value) => value !== null));

function payloadFor({ total = 0, your = 0, enemy = 0, lane = 0 } = {}) {
  const blob = Buffer.alloc(1260);
  blob.writeFloatLE(lane, 0x3c);
  blob.writeFloatLE(total, 0x40);
  blob.writeFloatLE(your, 0x44);
  blob.writeFloatLE(enemy, 0x48);
  const payload = Buffer.alloc(1263);
  payload.set([0x1c, 0xa6, 0xe8]);
  for (let index = 0; index < blob.length; index += 1) {
    payload[index + 3] = ENCODE_BYTE[blob[blob.length - 1 - index]];
  }
  return payload;
}

function blockFor(participantId, timeMs, payload, packetId = 0x0276) {
  const header = Buffer.alloc(15);
  header[0] = 0;
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(0x400000ad + participantId, 11);
  return Buffer.concat([header, payload]);
}

function fixture({ version = BUILD, stream = 2, times = [0, 1000],
  rows = null, extraBlocks = [], omitParticipant = null } = {}) {
  const values = rows || times.map((_, timeIndex) =>
    Array.from({ length: 10 }, (__, index) => timeIndex === 0
      ? { total: 0, your: 0, enemy: 0 }
      : { total: index + 5.5, your: index + 2.25, enemy: 1.75 }));
  const body = Buffer.concat([
    ...times.flatMap((timeMs, timeIndex) => values[timeIndex].flatMap((value, index) =>
      omitParticipant === index + 1 && timeIndex === 0 ? []
        : [blockFor(index + 1, timeMs, payloadFor(value))])),
    ...extraBlocks,
  ]);
  const replay = replayFromChunks([{ stream, body }], version);
  replay.tail.stats = values.at(-1).map((value) => ({
    NEUTRAL_MINIONS_KILLED: String(Math.floor(value.total) + 2),
    NEUTRAL_MINIONS_KILLED_YOUR_JUNGLE: String(Math.floor(value.your) + 1),
    NEUTRAL_MINIONS_KILLED_ENEMY_JUNGLE: String(Math.floor(value.enemy) + 1),
    MINIONS_KILLED: '0',
  }));
  replay.tail.metadata.gameLength = times.at(-1) + 1000;
  return replay;
}

function writeReplayWithTailStats(replay, outputPath) {
  const original = replay.buffer;
  const metadataLength = original.readUInt32LE(original.length - 4);
  const metadata = Buffer.from(JSON.stringify({
    ...replay.tail.metadata,
    statsJson: JSON.stringify(replay.tail.stats),
  }));
  const trailer = Buffer.alloc(4);
  trailer.writeUInt32LE(metadata.length);
  fs.writeFileSync(outputPath, Buffer.concat([
    original.subarray(0, original.length - metadataLength - 4), metadata, trailer,
  ]));
}

test('profile pins the exact HN route and preserves raw floats with derived floors', () => {
  assert.equal(profile.replay_version, BUILD);
  assert.equal(profile.replay_block_packet_id, 0x0276);
  assert.equal(profile.jungle_minions_killed_f32le_offset_candidate, 0x40);
  assert.equal(profile.your_jungle_minions_killed_f32le_offset_candidate, 0x44);
  assert.equal(profile.enemy_jungle_minions_killed_f32le_offset_candidate, 0x48);
  assert.equal(profile.status, 'CANDIDATE');
  assert.deepEqual(decodeHeroJungleMinionsKilledPayload(payloadFor({
    total: 5.5, your: 3.25, enemy: 1.75,
  })), {
    status: 'PASS',
    jungle_minions_killed_raw_f32_candidate: 5.5,
    jungle_minions_killed_floor_candidate: 5,
    your_jungle_minions_killed_raw_f32_candidate: 3.25,
    your_jungle_minions_killed_floor_candidate: 3,
    enemy_jungle_minions_killed_raw_f32_candidate: 1.75,
    enemy_jungle_minions_killed_floor_candidate: 1,
  });
});

test('keyframes keep all three raw fields, floor gaps, and packet provenance', () => {
  const replay = fixture();
  const result = decodeHeroJungleMinionsKilledSnapshotCandidates(replay);
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.event_count, 20);
  assert.equal(result.input_count, 20);
  assert.equal(result.keyframe_timestamp_count, 2);
  assert.equal(result.observed_participant_count, 10);
  assert.equal(result.evidence_status, 'CANDIDATE_EXACT_ROUTE_ONE_REPLAY_THREE_TAIL_CORRELATION');
  assert.deepEqual(result.observed_max_jungle_minions_killed_floor,
    Array.from({ length: 10 }, (_, index) => index + 5));
  assert.deepEqual(result.tail_gaps.map((row) => row.unobserved_tail_floor_gap),
    Array(10).fill(2));
  assert.deepEqual(result.tail_gaps.map((row) => row.unobserved_your_jungle_tail_floor_gap),
    Array(10).fill(1));
  assert.deepEqual(result.tail_gaps.map((row) => row.unobserved_enemy_jungle_tail_floor_gap),
    Array(10).fill(1));
  assert.equal(result.tail_gap_total, 20);
  const last = result.events.at(-1);
  assert.equal(last.event_type, 'HERO_JUNGLE_MINIONS_KILLED_SNAPSHOT_CANDIDATE');
  assert.equal(last.observation_kind, 'KEYFRAME_SNAPSHOT');
  assert.equal(last.jungle_minions_killed_raw_f32_candidate, 14.5);
  assert.equal(last.jungle_minions_killed_floor_candidate, 14);
  assert.equal(last.your_jungle_minions_killed_raw_f32_candidate, 11.25);
  assert.equal(last.enemy_jungle_minions_killed_floor_candidate, 1);
  assert.equal(last.field_confidence.jungle_minions_killed_floor_candidate,
    'DERIVED_FROM_CANDIDATE');
  assert.equal(last.raw_packet_ref.packet_id, 0x0276);
  assert.equal(last.raw_packet_ref.raw_param, 0x400000b7);
  assert.equal(last.raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.equal(last.raw_packet_ref.raw_payload_sha256,
    crypto.createHash('sha256').update(payloadFor({ total: 14.5, your: 11.25,
      enemy: 1.75 })).digest('hex'));
  assert.equal(Object.hasOwn(last, 'neutral_minion_kill_event'), false);
});

test('all three tail fields are required and invalid tails do not affect lane-CS decoding', () => {
  for (const field of TAIL_FIELDS) {
    const missing = fixture();
    delete missing.tail.stats[0][field];
    assert.equal(assessHeroJungleMinionsKilledSnapshotTail(missing).status, 'MISSING_INPUT');
    assert.equal(decodeHeroJungleMinionsKilledSnapshotCandidates(missing).status, 'MISSING_INPUT');
    assert.equal(decodeHeroMinionsKilledSnapshotCandidates(missing).status, 'CANDIDATE');
    const invalid = fixture();
    invalid.tail.stats[0][field] = '-1';
    assert.equal(assessHeroJungleMinionsKilledSnapshotTail(invalid).status, 'UNSUPPORTED');
    assert.equal(decodeHeroJungleMinionsKilledSnapshotCandidates(invalid).status, 'UNSUPPORTED');
  }
  const absentRoster = fixture();
  absentRoster.tail.stats = [];
  assert.equal(decodeHeroJungleMinionsKilledSnapshotCandidates(absentRoster).status, 'UNSUPPORTED');
  const noTail = fixture();
  noTail.tail.stats = null;
  assert.equal(decodeHeroJungleMinionsKilledSnapshotCandidates(noTail).status, 'MISSING_INPUT');
});

test('wrong build, absent route, foreign payload and mixed route stay unavailable or fail closed', () => {
  assert.equal(decodeHeroJungleMinionsKilledSnapshotCandidates(
    fixture({ version: '16.19.820.7194' })).status, 'UNSUPPORTED');
  assert.equal(decodeHeroJungleMinionsKilledSnapshotCandidates(
    fixture({ stream: 1 })).status, 'PROFILE_UNAVAILABLE');
  const foreignBody = Buffer.concat(Array.from({ length: 10 }, (_, index) =>
    blockFor(index + 1, 0, Buffer.from([1, 2]))));
  const foreignReplay = replayFromChunks([{ stream: 2, body: foreignBody }], BUILD);
  foreignReplay.tail.stats = fixture().tail.stats;
  assert.equal(decodeHeroJungleMinionsKilledSnapshotCandidates(foreignReplay).status,
    'PROFILE_UNAVAILABLE');
  const mixed = fixture({ times: [0], extraBlocks: [blockFor(1, 0, Buffer.from([1, 2]))] });
  assert.equal(decodeHeroJungleMinionsKilledSnapshotCandidates(mixed).status,
    'DECODE_FAILED');
});

test('nonfinite, negative and unsafe-range f32 values fail closed at each offset', () => {
  for (const key of ['total', 'your', 'enemy']) {
    for (const value of [-1, NaN, Infinity, 1e20]) {
      const result = decodeHeroJungleMinionsKilledPayload(payloadFor({ [key]: value }));
      assert.equal(result.status, 'DECODE_FAILED', `${key}: ${value}`);
    }
  }
  const badPrefix = payloadFor({ total: 1 });
  badPrefix[0] = 0x1d;
  assert.equal(decodeHeroJungleMinionsKilledPayload(badPrefix).status, 'DECODE_FAILED');
  assert.equal(decodeHeroJungleMinionsKilledPayload(badPrefix.subarray(1)).status,
    'DECODE_FAILED');
});

test('decreases, tail overruns, and broken hero groups fail closed independently', () => {
  for (const key of ['total', 'your', 'enemy']) {
    const rows = [Array(10).fill({ total: 3, your: 3, enemy: 3 }),
      Array(10).fill({ total: 3, your: 3, enemy: 3, [key]: 2 })];
    const decreasing = fixture({ rows });
    assert.match(decodeHeroJungleMinionsKilledSnapshotCandidates(decreasing).error,
      /decreasing/);
  }
  for (const field of TAIL_FIELDS) {
    const overrun = fixture();
    overrun.tail.stats[0][field] = '0';
    assert.match(decodeHeroJungleMinionsKilledSnapshotCandidates(overrun).error,
      /exceeds Replay tail/);
  }
  const missingHero = fixture({ times: [0], omitParticipant: 3 });
  assert.match(decodeHeroJungleMinionsKilledSnapshotCandidates(missingHero).error,
    /lacks one or more hero params/);
});

test('a bound HeroStats scan can be reused without rescanning the Replay', () => {
  const replay = fixture();
  const standalone = decodeHeroJungleMinionsKilledSnapshotCandidates(replay);
  const { heroStatsScan } = analyzeReplayWithHeroStats(replay, { strict: true });
  Object.defineProperty(replay, 'chunks', { get() {
    throw new Error('precollected decode must not scan Replay chunks');
  } });
  const reused = decodeHeroStatsSnapshotCandidateSet(replay, [CAPABILITY], heroStatsScan);
  assert.deepEqual(reused[CAPABILITY], standalone);
});

test('selected API exposes jungle snapshots without confirmed neutral-minion events', () => {
  const decoded = decodeSemanticReplay(fixture(), { capabilities: [CAPABILITY] });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.runtime_image_used, false);
  assert.equal(decoded.capability_results[CAPABILITY].event_count, 20);
  assert.deepEqual(Object.keys(decoded.events),
    ['hero_jungle_minions_killed_snapshot_candidates']);
  const events = getHeroJungleMinionsKilledSnapshotCandidates(decoded);
  assert.equal(events.length, 20);
  assert.equal(events.at(-1).jungle_minions_killed_floor_candidate, 14);
  assert.equal(decoded.events.hero_jungle_minion_kill_events, undefined);
});

test('capability query lists each neutral-minion tail dependency without reading packets', () => {
  const cli = require('../src/cli');
  const replay = fixture();
  const query = cli.capabilityQuery(replay);
  const row = query.capabilities.find((entry) => entry.capability === CAPABILITY);
  assert.equal(query.packet_framing_inspected, false);
  assert.equal(row.runtime_image_requirement, 'NOT_REQUIRED');
  assert.deepEqual(row.required_inputs.map((input) => input.name), [
    'replay', 'replay_tail_statsJson',
    ...TAIL_FIELDS.map((field) => `replay_tail_${field}`),
  ]);
  assert.deepEqual(row.missing_inputs, []);
  delete replay.tail.stats[0].NEUTRAL_MINIONS_KILLED_ENEMY_JUNGLE;
  assert.deepEqual(cli.capabilityQuery(replay).capabilities
    .find((entry) => entry.capability === CAPABILITY).missing_inputs,
  ['replay_tail_NEUTRAL_MINIONS_KILLED_ENEMY_JUNGLE']);
});

test('selected CLI writes jungle candidate JSONL and packet-bound status', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-jungle-cli-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const input = path.join(root, 'synthetic-16.19.rofl');
  const output = path.join(root, 'output');
  writeReplayWithTailStats(fixture(), input);
  assert.equal(await require('../src/cli').main([
    'decode', input, '--events', CAPABILITY, '--out-dir', output,
  ]), 0);
  const summary = JSON.parse(fs.readFileSync(path.join(output, 'acceptance_summary.json'), 'utf8'));
  assert.equal(summary.status, 'CANDIDATE');
  const replayDirectory = path.join(output, summary.replay_artifacts[0].artifact_directory);
  const semantic = JSON.parse(fs.readFileSync(path.join(replayDirectory, 'semantic_run.json'), 'utf8'));
  assert.equal(semantic.capability_results[CAPABILITY].event_count, 20);
  const rows = fs.readFileSync(path.join(replayDirectory,
    'hero_jungle_minions_killed_snapshot_candidates.jsonl'), 'utf8')
    .trim().split(/\r?\n/).map((line) => JSON.parse(line));
  assert.equal(rows.length, 20);
  assert.equal(rows[0].raw_packet_ref.packet_id, 0x0276);
  assert.equal(rows.at(-1).enemy_jungle_minions_killed_floor_candidate, 1);
});

'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const {
  HERO_STATS_SNAPSHOT_CAPABILITIES,
  HERO_CROWD_CONTROL_TIME_SNAPSHOT_CANDIDATE_PROFILE,
  analyzeReplayWithHeroStats,
  assessHeroCrowdControlTimeSnapshotTail,
  decodeHeroStatsByte,
  decodeHeroCrowdControlTimePayload,
  decodeHeroCrowdControlTimeSnapshotCandidates,
  decodeHeroStatsSnapshotCandidateSet,
} = require('../src/decoders/rofl_16_19_hero_stats_candidate');
const { decodeSemanticReplay, getHeroCrowdControlTimeSnapshotCandidates } =
  require('../src/semantic_api');
const { capabilityQuery, main } = require('../src/cli');

const BUILD = '16.19.820.7193';
const CAPABILITY = 'hero_crowd_control_time_snapshot';
const TAIL_FIELD = 'TOTAL_TIME_CROWD_CONTROL_DEALT_TO_CHAMPIONS';
const RAW_KEY = 'crowd_control_time_raw_f32_candidate';
const FLOOR_KEY = 'crowd_control_time_floor_candidate';
const IMAGE_SHA = '7e6804aa589a098a44b01e4fdc894fc697776caeea42fc78f780af11ed6df76d';
const ENCODE_BYTE = Array(256).fill(null);
for (let encoded = 0; encoded < 256; encoded += 1) {
  ENCODE_BYTE[decodeHeroStatsByte(encoded)] = encoded;
}
assert.ok(ENCODE_BYTE.every((value) => value !== null));

function payloadFor(value) {
  const blob = Buffer.alloc(1260);
  blob.writeFloatLE(value, 0x230);
  const payload = Buffer.alloc(1263);
  payload.set([0x1c, 0xa6, 0xe8]);
  for (let index = 0; index < blob.length; index += 1) {
    payload[index + 3] = ENCODE_BYTE[blob[blob.length - 1 - index]];
  }
  return payload;
}

function blockFor(participantId, timeMs, payload) {
  const header = Buffer.alloc(15);
  header[0] = 0;
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x0276, 9);
  header.writeUInt32LE(0x400000ad + participantId, 11);
  return Buffer.concat([header, payload]);
}

function defaultRows() {
  return [Array(10).fill(0), Array.from({ length: 10 }, (_, index) =>
    (index + 1) * 3 + 0.5)];
}

function fixture({ rows = defaultRows(), version = BUILD, stream = 2,
  omitParticipant = null, extraBlocks = [] } = {}) {
  const body = Buffer.concat([
    ...[0, 1000].flatMap((timeMs, timeIndex) => rows[timeIndex].flatMap((value, index) =>
      omitParticipant === index + 1 && timeIndex === 0 ? []
        : [blockFor(index + 1, timeMs, payloadFor(value))])),
    ...extraBlocks,
  ]);
  const replay = replayFromChunks([{ stream, body }], version);
  replay.tail.stats = rows.at(-1).map((value, index) => ({
    [TAIL_FIELD]: String(Math.floor(value) + (index === 1 ? 1 : 0)),
    VISION_SCORE: '0',
  }));
  replay.tail.metadata.gameLength = 2000;
  return replay;
}

function writeReplayWithTailStats(replay, outputPath) {
  const original = replay.buffer;
  const metadataLength = original.readUInt32LE(original.length - 4);
  const metadata = Buffer.from(JSON.stringify({ ...replay.tail.metadata,
    statsJson: JSON.stringify(replay.tail.stats) }));
  const trailer = Buffer.alloc(4);
  trailer.writeUInt32LE(metadata.length);
  fs.writeFileSync(outputPath, Buffer.concat([
    original.subarray(0, original.length - metadataLength - 4), metadata, trailer,
  ]));
}

test('exact HN profile decodes observed raw crowd-control time and a derived floor', () => {
  const profile = HERO_CROWD_CONTROL_TIME_SNAPSHOT_CANDIDATE_PROFILE;
  assert.ok(HERO_STATS_SNAPSHOT_CAPABILITIES.includes(CAPABILITY));
  assert.equal(profile.capability, CAPABILITY);
  assert.equal(profile.status, 'CANDIDATE');
  assert.equal(profile.replay_version, BUILD);
  assert.equal(profile.replay_block_packet_id, 0x0276);
  assert.deepEqual(profile.stream_tags, [2, 3]);
  assert.equal(profile.crowd_control_time_f32le_offset_candidate, 0x230);
  assert.equal(profile.evidence_runtime_image_sha256, IMAGE_SHA);
  assert.match(profile.evidence_scope, /one HN Replay/);
  assert.match(profile.known_limits.join(' '), /no crowd-control event/);
  const decoded = decodeHeroCrowdControlTimePayload(payloadFor(17.75));
  assert.deepEqual(decoded, { status: 'PASS', [RAW_KEY]: 17.75, [FLOOR_KEY]: 17 });
  for (const value of [-1, Infinity, NaN, 2 ** 53]) {
    assert.equal(decodeHeroCrowdControlTimePayload(payloadFor(value)).status,
      'DECODE_FAILED');
  }
  const malformed = payloadFor(17.75);
  malformed[0] = 0x1d;
  assert.equal(decodeHeroCrowdControlTimePayload(malformed).status, 'DECODE_FAILED');
  assert.equal(decodeHeroCrowdControlTimePayload(malformed.subarray(1)).status,
    'DECODE_FAILED');
});

test('candidate snapshots retain raw packet provenance and unobserved tail gap', () => {
  const replay = fixture();
  const outcome = decodeHeroCrowdControlTimeSnapshotCandidates(replay);
  assert.equal(outcome.status, 'CANDIDATE');
  assert.equal(outcome.event_count, 20);
  assert.equal(outcome.input_count, 20);
  assert.equal(outcome.keyframe_timestamp_count, 2);
  assert.equal(outcome.observed_participant_count, 10);
  assert.equal(outcome.evidence_runtime_image_sha256, IMAGE_SHA);
  assert.equal(outcome.tail_gap_total, 1);
  assert.deepEqual(outcome.tail_gaps[1], {
    participant_id_candidate: 2,
    last_snapshot_replay_time_ms: 1000,
    last_snapshot_raw_f32_candidate: 6.5,
    last_snapshot_floor_candidate: 6,
    final_tail: 7,
    unobserved_tail_floor_gap: 1,
    unobserved_tail_time_ms: 1000,
  });
  const last = outcome.events.at(-1);
  assert.equal(last.event_type, 'HERO_CROWD_CONTROL_TIME_SNAPSHOT_CANDIDATE');
  assert.equal(last.observation_kind, 'KEYFRAME_SNAPSHOT');
  assert.equal(last.confidence, 'CANDIDATE');
  assert.equal(last.participant_id_candidate, 10);
  assert.equal(last[RAW_KEY], 30.5);
  assert.equal(last[FLOOR_KEY], 30);
  assert.equal(last.field_confidence[RAW_KEY], 'CANDIDATE_ONE_REPLAY_TAIL_CORRELATION');
  assert.equal(last.field_confidence[FLOOR_KEY], 'DERIVED_FROM_CANDIDATE');
  assert.equal(last.raw_packet_ref.packet_id, 0x0276);
  assert.equal(last.raw_packet_ref.raw_param, 0x400000b7);
  assert.equal(last.raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.equal(last.raw_packet_ref.raw_payload_sha256,
    crypto.createHash('sha256').update(payloadFor(30.5)).digest('hex'));
  for (const key of ['crowd_control_event_time_ms', 'target_participant_id',
    'target_network_id', 'application_count']) {
    assert.equal(Object.hasOwn(last, key), false);
  }
});

test('missing and invalid crowd-control tail input is reported independently', () => {
  const replay = fixture();
  assert.equal(assessHeroCrowdControlTimeSnapshotTail(replay).status, 'PASS');
  delete replay.tail.stats[0][TAIL_FIELD];
  const outcomes = decodeHeroStatsSnapshotCandidateSet(replay,
    [CAPABILITY, 'hero_vision_score_snapshot']);
  assert.equal(outcomes[CAPABILITY].status, 'MISSING_INPUT');
  assert.equal(outcomes.hero_vision_score_snapshot.status, 'CANDIDATE');
  assert.equal(outcomes[CAPABILITY].events, null);
  replay.tail.stats[0][TAIL_FIELD] = '-1';
  assert.equal(decodeHeroCrowdControlTimeSnapshotCandidates(replay).status,
    'UNSUPPORTED');
  replay.tail.stats = null;
  assert.equal(decodeHeroCrowdControlTimeSnapshotCandidates(replay).status,
    'MISSING_INPUT');
});

test('participant tail overrun and observed decline each suppress candidate output', () => {
  const overrun = fixture();
  overrun.tail.stats[0][TAIL_FIELD] = '0';
  const overrunResult = decodeHeroCrowdControlTimeSnapshotCandidates(overrun);
  assert.equal(overrunResult.status, 'DECODE_FAILED');
  assert.match(overrunResult.error, /exceeds Replay tail TOTAL_TIME_CROWD_CONTROL_DEALT_TO_CHAMPIONS/);
  assert.equal(overrunResult.events, null);

  const rows = defaultRows();
  rows[0][0] = 9.5;
  rows[1][0] = 8.5;
  const decreasing = fixture({ rows });
  decreasing.tail.stats[0][TAIL_FIELD] = '100';
  const declineResult = decodeHeroCrowdControlTimeSnapshotCandidates(decreasing);
  assert.equal(declineResult.status, 'DECODE_FAILED');
  assert.match(declineResult.error, /decreasing observed TOTAL_TIME_CROWD_CONTROL_DEALT_TO_CHAMPIONS/);
  assert.equal(declineResult.events, null);
});

test('wrong build, foreign route, malformed packet, and incomplete roster fail closed', () => {
  const wrongBuild = fixture({ version: '16.19.820.7194' });
  const foreignStream = fixture({ stream: 1 });
  const malformed = fixture({ extraBlocks: [blockFor(1, 0, Buffer.from([1, 2]))] });
  const incomplete = fixture({ omitParticipant: 3 });
  assert.equal(decodeHeroCrowdControlTimeSnapshotCandidates(wrongBuild).status,
    'UNSUPPORTED');
  assert.equal(decodeHeroCrowdControlTimeSnapshotCandidates(foreignStream).status,
    'PROFILE_UNAVAILABLE');
  assert.equal(decodeHeroCrowdControlTimeSnapshotCandidates(malformed).status,
    'DECODE_FAILED');
  assert.match(decodeHeroCrowdControlTimeSnapshotCandidates(incomplete).error,
    /lacks one or more hero params/);
});

test('precollected HeroStats scan yields the same candidate without another Replay walk', () => {
  const replay = fixture();
  const standalone = decodeHeroCrowdControlTimeSnapshotCandidates(replay);
  const { heroStatsScan } = analyzeReplayWithHeroStats(replay, { strict: true });
  Object.defineProperty(replay, 'chunks', { get() {
    throw new Error('precollected decode must not rescan Replay chunks');
  } });
  const combined = decodeHeroStatsSnapshotCandidateSet(replay, [CAPABILITY], heroStatsScan);
  assert.deepEqual(combined[CAPABILITY], standalone);
});

test('selected API and capability query expose the candidate and its tail dependency', () => {
  const replay = fixture();
  const decoded = decodeSemanticReplay(replay, {
    capabilities: [CAPABILITY, 'hero_vision_score_snapshot'],
  });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.capability_results[CAPABILITY].event_count, 20);
  assert.equal(getHeroCrowdControlTimeSnapshotCandidates(decoded).at(-1)[FLOOR_KEY], 30);
  assert.equal(decoded.events.crowd_control_events, undefined);
  const capability = capabilityQuery(replay).capabilities.find((row) =>
    row.capability === CAPABILITY);
  assert.equal(capability.output, `${CAPABILITY}_candidates`);
  assert.equal(capability.runtime_image_requirement, 'NOT_REQUIRED');
  assert.deepEqual(capability.required_inputs.map((input) => input.name), [
    'replay', 'replay_tail_statsJson', `replay_tail_${TAIL_FIELD}`,
  ]);
  delete replay.tail.stats[0][TAIL_FIELD];
  const missing = capabilityQuery(replay).capabilities;
  assert.deepEqual(missing.find((row) => row.capability === CAPABILITY).missing_inputs,
    [`replay_tail_${TAIL_FIELD}`]);
  assert.deepEqual(missing.find((row) => row.capability === 'hero_vision_score_snapshot')
    .missing_inputs, []);
});

test('selected CLI writes crowd-control time candidate JSONL with Replay provenance', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-cc-time-cli-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const input = path.join(root, 'synthetic-16.19.rofl');
  const output = path.join(root, 'output');
  writeReplayWithTailStats(fixture(), input);
  assert.equal(await main(['decode', input, '--events', CAPABILITY,
    '--out-dir', output]), 0);
  const summary = JSON.parse(fs.readFileSync(path.join(output, 'acceptance_summary.json'), 'utf8'));
  assert.equal(summary.status, 'CANDIDATE');
  const replayDir = path.join(output, summary.replay_artifacts[0].artifact_directory);
  const semantic = JSON.parse(fs.readFileSync(path.join(replayDir, 'semantic_run.json'), 'utf8'));
  assert.equal(semantic.capability_results[CAPABILITY].event_count, 20);
  assert.equal(semantic.capability_results[CAPABILITY].tail_gap_total, 1);
  const rows = fs.readFileSync(path.join(replayDir, `${CAPABILITY}_candidates.jsonl`), 'utf8')
    .trim().split(/\r?\n/).map((line) => JSON.parse(line));
  assert.equal(rows.length, 20);
  assert.equal(rows.at(-1)[RAW_KEY], 30.5);
  assert.equal(rows.at(-1)[FLOOR_KEY], 30);
  assert.equal(rows.at(-1).confidence, 'CANDIDATE');
  assert.equal(rows.at(-1).raw_packet_ref.replay_sha256,
    crypto.createHash('sha256').update(fs.readFileSync(input)).digest('hex'));
});

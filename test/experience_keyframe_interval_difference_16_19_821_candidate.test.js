'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { decodeRuntimeCountByte } =
  require('../src/decoders/rofl_16_19_821_runtime_bytes');
const { decodeHeroFloatSnapshotCandidates821 } =
  require('../src/decoders/rofl_16_19_821_float_stats_candidate');
const {
  EXPERIENCE_KEYFRAME_INTERVAL_DIFFERENCE_821_PROFILE: PROFILE,
  deriveExperienceKeyframeIntervalDifferenceCandidates821: derive,
} = require('../src/decoders/rofl_16_19_821_experience_keyframe_interval_difference_candidate');

const BUILD = '16.19.821.7343';
const ENCODE = new Map(Array.from({ length: 256 }, (_, raw) =>
  [decodeRuntimeCountByte(raw), raw]));

function packet(participant, timeMs, value) {
  const payload = Buffer.alloc(1263, 0x97);
  payload.set([0x67, 0x00, 0xde]);
  const bytes = Buffer.alloc(4);
  bytes.writeFloatLE(value);
  for (let i = 0; i < 4; i += 1) {
    payload[1262 - 0x28 - i] = ENCODE.get(bytes[i]);
  }
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x0089, 9);
  header.writeUInt32LE(0x400000ad + participant, 11);
  return Buffer.concat([header, payload]);
}

function fixture(times = [0, 60_000, 120_000], values = [
  [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
  [100.5, 0, 0, 0, 0, 0, 0, 0, 0, 0],
  [100.5, 50.25, 0, 0, 0, 0, 0, 0, 0, 0],
]) {
  const replay = replayFromChunks(times.map((time, frame) => ({
    stream: 2,
    body: Buffer.concat(Array.from({ length: 10 }, (_, participant) =>
      packet(participant + 1, time, values[frame][participant]))),
  })), BUILD);
  replay.tail.stats = Array.from({ length: 10 }, (_, participant) => ({
    EXP: String(participant === 0 ? 101 : participant === 1 ? 51 : 0),
  }));
  const experienceSnapshotOutcome = decodeHeroFloatSnapshotCandidates821(replay,
    'hero_experience_snapshot');
  return { replay, experienceSnapshotOutcome };
}

function deriveFixture(values) {
  return derive(values.replay, { experienceSnapshotOutcome: values.experienceSnapshotOutcome });
}

test('821 experience interval candidate emits positive sampled endpoint differences with both refs', () => {
  const values = fixture();
  assert.equal(values.experienceSnapshotOutcome.status, 'CANDIDATE');
  const result = deriveFixture(values);
  assert.equal(PROFILE.capability, 'experience_keyframe_interval_difference');
  assert.equal(result.status, 'CANDIDATE', result.error);
  assert.equal(result.input_count, 30);
  assert.equal(result.keyframe_count, 3);
  assert.equal(result.verified_raw_packet_count, 30);
  assert.equal(result.observed_interval_count, 20);
  assert.equal(result.changed_interval_count, 2);
  assert.equal(result.unchanged_interval_count, 18);
  assert.equal(result.event_count, 2);
  const first = result.events[0];
  assert.equal(first.event_type, 'EXPERIENCE_KEYFRAME_INTERVAL_DIFFERENCE_CANDIDATE');
  assert.equal(first.observation_scope, 'KEYFRAME_ENDPOINT_DIFFERENCE_ONLY');
  assert.equal(first.change_time_status, 'UNRESOLVED_WITHIN_INTERVAL');
  assert.equal(first.participant_id_candidate, 1);
  assert.equal(first.previous_observation_time_ms, 0);
  assert.equal(first.current_observation_time_ms, 60_000);
  assert.equal(first.experience_endpoint_delta_f32_candidate, 100.5);
  assert.equal(first.experience_endpoint_delta_floor_candidate, 100);
  assert.equal(first.previous_experience_raw_f32_candidate, 0);
  assert.equal(first.current_experience_raw_f32_candidate, 100.5);
  assert.deepEqual(first.raw_packet_refs,
    [first.previous_raw_packet_ref, first.current_raw_packet_ref]);
  assert.equal(first.raw_packet_ref.chunk_index, 1);
  assert.equal(result.events[1].participant_id_candidate, 2);
  assert.equal(result.events[1].experience_endpoint_delta_f32_candidate, 50.25);
  assert.equal(result.events[1].previous_observation_time_ms, 60_000);
  assert.equal('experience_source' in first, false);
  assert.equal('gain_time_ms' in first, false);
});

test('821 experience interval candidate has no fabricated rows for one or unchanged keyframes', () => {
  const one = fixture([0], [[0, 0, 0, 0, 0, 0, 0, 0, 0, 0]]);
  const oneResult = deriveFixture(one);
  assert.equal(oneResult.status, 'CANDIDATE', oneResult.error);
  assert.equal(oneResult.observed_interval_count, 0);
  assert.equal(oneResult.event_count, 0);
  const equal = fixture([0, 60_000], [
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
  ]);
  const equalResult = deriveFixture(equal);
  assert.equal(equalResult.status, 'CANDIDATE', equalResult.error);
  assert.equal(equalResult.observed_interval_count, 10);
  assert.equal(equalResult.unchanged_interval_count, 10);
  assert.equal(equalResult.event_count, 0);
});

test('821 experience interval candidate retains source status and exact-build gates', () => {
  const missing = fixture();
  assert.equal(derive(missing.replay).status, 'MISSING_INPUT');
  const unavailable = fixture();
  unavailable.experienceSnapshotOutcome.status = 'MISSING_INPUT';
  assert.equal(deriveFixture(unavailable).status, 'MISSING_INPUT');
  const failed = fixture();
  failed.experienceSnapshotOutcome.status = 'DECODE_FAILED';
  assert.equal(deriveFixture(failed).status, 'DECODE_FAILED');
  const wrongBuild = fixture();
  wrongBuild.replay.header.version = '16.19.820.7193';
  assert.equal(deriveFixture(wrongBuild).status, 'UNSUPPORTED');
  const wrongProfile = fixture();
  wrongProfile.experienceSnapshotOutcome.profile_id = 'other-profile';
  assert.equal(deriveFixture(wrongProfile).status, 'INCONSISTENT');
  const wrongImage = fixture();
  wrongImage.experienceSnapshotOutcome.evidence_runtime_image_sha256 = 'f'.repeat(64);
  assert.equal(deriveFixture(wrongImage).status, 'INCONSISTENT');
  const decreasing = fixture([0, 60_000, 120_000], [
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [100.5, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [50.25, 0, 0, 0, 0, 0, 0, 0, 0, 0],
  ]);
  assert.equal(decreasing.experienceSnapshotOutcome.status, 'DECODE_FAILED');
  assert.equal(deriveFixture(decreasing).status, 'DECODE_FAILED');
});

test('821 experience interval candidate rejects changed source rows and packet bytes', () => {
  const count = fixture();
  count.experienceSnapshotOutcome.event_count -= 1;
  assert.equal(deriveFixture(count).status, 'INCONSISTENT');
  const duplicate = fixture();
  duplicate.experienceSnapshotOutcome.events[1] =
    duplicate.experienceSnapshotOutcome.events[0];
  assert.equal(deriveFixture(duplicate).status, 'INCONSISTENT');
  const omitted = fixture();
  omitted.experienceSnapshotOutcome.events.splice(0, 1);
  omitted.experienceSnapshotOutcome.event_count -= 1;
  omitted.experienceSnapshotOutcome.input_count -= 1;
  assert.equal(deriveFixture(omitted).status, 'INCONSISTENT');
  const forgedRef = fixture();
  forgedRef.experienceSnapshotOutcome.events[0].raw_packet_ref.raw_payload_sha256 =
    'f'.repeat(64);
  assert.equal(deriveFixture(forgedRef).status, 'INCONSISTENT');
  const forgedField = fixture();
  forgedField.experienceSnapshotOutcome.events[10].experience_raw_f32_candidate = 101;
  forgedField.experienceSnapshotOutcome.events[10].experience_floor_candidate = 101;
  assert.equal(deriveFixture(forgedField).status, 'INCONSISTENT');
  const forgedTail = fixture();
  forgedTail.replay.tail.stats[0].EXP = '101.0';
  assert.equal(deriveFixture(forgedTail).status, 'INCONSISTENT');
  const mutatedReplay = fixture();
  mutatedReplay.replay.buffer[0] ^= 1;
  assert.equal(deriveFixture(mutatedReplay).status, 'DECODE_FAILED');
});

test('821 experience interval candidate rejects nonincreasing keyframe times', () => {
  const same = fixture([0, 0], [
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [100.5, 0, 0, 0, 0, 0, 0, 0, 0, 0],
  ]);
  assert.equal(same.experienceSnapshotOutcome.status, 'CANDIDATE');
  assert.equal(deriveFixture(same).status, 'INCONSISTENT');
});

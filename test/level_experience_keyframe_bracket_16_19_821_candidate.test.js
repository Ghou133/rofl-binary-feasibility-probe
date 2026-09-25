'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { decodeRuntimeCountByte } =
  require('../src/decoders/rofl_16_19_821_runtime_bytes');
const { decodeHeroLevelCandidates821 } =
  require('../src/decoders/rofl_16_19_821_level_candidate');
const { decodeHeroFloatSnapshotCandidates821 } =
  require('../src/decoders/rofl_16_19_821_float_stats_candidate');
const {
  LEVEL_EXPERIENCE_KEYFRAME_BRACKET_821_PROFILE: PROFILE,
  associateLevelExperienceKeyframeBracketCandidates821: associate,
} = require('../src/decoders/rofl_16_19_821_level_experience_keyframe_bracket_candidate');

const BUILD = '16.19.821.7343';
const ENCODE = new Map(Array.from({ length: 256 }, (_, raw) =>
  [decodeRuntimeCountByte(raw), raw]));

function levelPacket(timeMs, participant, payload) {
  const body = Buffer.from(payload);
  const header = Buffer.alloc(12);
  header[0] = 0x10;
  header.writeFloatLE(timeMs / 1000, 1);
  header[5] = body.length;
  header.writeUInt16LE(0x0197, 6);
  header.writeUInt32LE(0x400000ad + participant, 8);
  return Buffer.concat([header, body]);
}

function experiencePacket(timeMs, participant, value) {
  const payload = Buffer.alloc(1263, 0x97);
  payload.set([0x67, 0x00, 0xde]);
  const bytes = Buffer.alloc(4);
  bytes.writeFloatLE(value);
  for (let byte = 0; byte < 4; byte += 1) {
    payload[1262 - 0x28 - byte] = ENCODE.get(bytes[byte]);
  }
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x0089, 9);
  header.writeUInt32LE(0x400000ad + participant, 11);
  return Buffer.concat([header, payload]);
}

function fixture({ gap = false, boundary = false } = {}) {
  const early = [levelPacket(20_000, 1, [0xde])];
  for (let participant = 1; participant <= 10; participant += 1) {
    early.push(levelPacket(boundary ? 60_000 : 30_000, participant, [0xe5]));
  }
  if (!boundary) {
    early.push(levelPacket(32_000, 1, [0xe5]));
    early.push(levelPacket(35_000, 1, gap ? [0xe2, 0x80] : [0xe2, 0x75]));
  }
  const chunks = [
    { stream: 2, body: Buffer.concat(Array.from({ length: 10 }, (_, p) =>
      experiencePacket(0, p + 1, 0))) },
    { stream: 1, body: Buffer.concat(early) },
    { stream: 2, body: Buffer.concat(Array.from({ length: 10 }, (_, p) =>
      experiencePacket(60_000, p + 1, p === 0 ? 100.5 : 0))) },
  ];
  if (!gap && !boundary) {
    chunks.push({ stream: 1, body: levelPacket(90_000, 1, [0xe2, 0x80]) });
  }
  const replay = replayFromChunks(chunks, BUILD);
  replay.tail.stats = Array.from({ length: 10 }, (_, p) => ({
    LEVEL: String(p === 0 ? (boundary ? 2 : 4) : 2),
    EXP: String(p === 0 ? 101 : 0),
  }));
  const levelOutcome = decodeHeroLevelCandidates821(replay);
  const experienceSnapshotOutcome = decodeHeroFloatSnapshotCandidates821(replay,
    'hero_experience_snapshot');
  assert.equal(levelOutcome.status, 'CANDIDATE', levelOutcome.error);
  assert.equal(experienceSnapshotOutcome.status, 'CANDIDATE', experienceSnapshotOutcome.error);
  return { replay, levelOutcome, experienceSnapshotOutcome };
}

test('821 bracket preserves three raw refs, shared interval count and exclusions', () => {
  const input = fixture();
  const result = associate(input.replay, input);
  assert.equal(PROFILE.capability, 'level_experience_keyframe_bracket');
  assert.deepEqual(PROFILE.depends_on, ['hero_level_state', 'hero_experience_snapshot']);
  assert.equal(result.status, 'CANDIDATE', result.error);
  assert.equal(result.level_packet_count, 14);
  assert.equal(result.experience_snapshot_count, 20);
  assert.equal(result.verified_level_raw_packet_count, 14);
  assert.equal(result.verified_experience_raw_packet_count, 20);
  assert.equal(result.higher_level_observation_count, 12);
  assert.equal(result.excluded_level_one_count, 1);
  assert.equal(result.excluded_repeated_level_count, 1);
  assert.equal(result.outside_last_keyframe_count, 1);
  assert.equal(result.event_count, 11);
  assert.equal(result.positive_endpoint_count, 2);
  assert.equal(result.unchanged_endpoint_count, 9);
  assert.equal(result.involved_interval_count, 10);
  assert.equal(result.positive_involved_interval_count, 1);
  assert.equal(result.unchanged_involved_interval_count, 9);
  assert.equal(result.multi_level_interval_count, 1);
  assert.equal(result.max_level_packets_per_interval, 2);
  const third = result.events.find((row) => row.participant_id_candidate === 1
    && row.level_after_candidate === 3);
  assert.equal(third.prior_observed_level_candidate, 2);
  assert.equal(third.observed_level_sequence_gap, false);
  assert.equal(third.previous_observation_time_ms, 0);
  assert.equal(third.current_observation_time_ms, 60_000);
  assert.equal(third.experience_endpoint_delta_f32_candidate, 100.5);
  assert.equal(third.level_packet_count_in_same_interval, 2);
  assert.equal(third.raw_level_payload_code_hex, '0x75');
  assert.equal(third.previous_experience_raw_payload_field_bytes_hex.length, 8);
  assert.equal(third.current_experience_raw_payload_field_bytes_hex.length, 8);
  assert.deepEqual(third.raw_packet_refs, [third.previous_experience_raw_packet_ref,
    third.level_raw_packet_ref, third.current_experience_raw_packet_ref]);
  assert.equal(third.raw_packet_ref, third.level_raw_packet_ref);
  assert.equal(third.level_raw_packet_ref.packet_id, 0x0197);
  assert.equal(third.previous_experience_raw_packet_ref.packet_id, 0x0089);
  assert.equal(third.current_experience_raw_packet_ref.packet_id, 0x0089);
  assert.equal('experience_source' in third, false);
  assert.equal('level_threshold' in third, false);
  const unchanged = result.events.find((row) => row.participant_id_candidate === 2);
  assert.equal(unchanged.experience_endpoint_delta_f32_candidate, 0);
});

test('821 bracket retains level sequence gaps and excludes exact keyframe times', () => {
  const gap = fixture({ gap: true });
  const gapResult = associate(gap.replay, gap);
  assert.equal(gapResult.status, 'CANDIDATE', gapResult.error);
  assert.equal(gapResult.observed_level_sequence_gap_count, 1);
  const level4 = gapResult.events.find((row) => row.participant_id_candidate === 1
    && row.level_after_candidate === 4);
  assert.equal(level4.observed_level_sequence_gap, true);
  assert.equal(level4.prior_observed_level_candidate, 2);
  const boundary = fixture({ boundary: true });
  const boundaryResult = associate(boundary.replay, boundary);
  assert.equal(boundaryResult.status, 'CANDIDATE', boundaryResult.error);
  assert.equal(boundaryResult.exact_keyframe_boundary_count, 10);
  assert.equal(boundaryResult.event_count, 0);
});

test('821 bracket rejects missing, foreign and physically changed dependencies', () => {
  const missing = fixture();
  assert.deepEqual(associate(missing.replay).missing_inputs,
    ['hero_level_state', 'hero_experience_snapshot']);
  const wrongBuild = fixture();
  wrongBuild.replay.header.version = '16.19.820.7193';
  assert.equal(associate(wrongBuild.replay, wrongBuild).status, 'UNSUPPORTED');
  const wrongProfile = fixture();
  wrongProfile.levelOutcome.profile_id = 'other';
  assert.equal(associate(wrongProfile.replay, wrongProfile).status, 'INCONSISTENT');
  const wrongImage = fixture();
  wrongImage.experienceSnapshotOutcome.evidence_runtime_image_sha256 = 'f'.repeat(64);
  assert.equal(associate(wrongImage.replay, wrongImage).status, 'INCONSISTENT');
  const forgedLevel = fixture();
  forgedLevel.levelOutcome.events[0].raw_packet_ref.raw_payload_hex = '00';
  assert.equal(associate(forgedLevel.replay, forgedLevel).status, 'INCONSISTENT');
  const omittedLevel = fixture();
  omittedLevel.levelOutcome.events.splice(0, 1);
  omittedLevel.levelOutcome.event_count -= 1;
  omittedLevel.levelOutcome.input_count -= 1;
  assert.equal(associate(omittedLevel.replay, omittedLevel).status, 'INCONSISTENT');
  const forgedXp = fixture();
  forgedXp.experienceSnapshotOutcome.events[10].experience_raw_f32_candidate = 101;
  forgedXp.experienceSnapshotOutcome.events[10].experience_floor_candidate = 101;
  assert.equal(associate(forgedXp.replay, forgedXp).status, 'INCONSISTENT');
  const mutated = fixture();
  mutated.replay.buffer[0] ^= 1;
  assert.equal(associate(mutated.replay, mutated).status, 'DECODE_FAILED');
});

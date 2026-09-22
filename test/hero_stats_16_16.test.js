'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  HERO_STATS_PROFILE,
  HERO_STATS_PROFILE_SHA256,
  heroScoreboardStateFromDecodedRow,
  isHeroStatsDecodedRow,
} = require('../src/decoders/hero_stats_16_16');

function replay() {
  return {
    header: { version: HERO_STATS_PROFILE.replay_version },
    source_sha256: 'a'.repeat(64),
    tail: {
      stats: Array.from({ length: 10 }, (_, index) => ({
        SKIN: `Champion${index + 1}`,
        TEAM: index < 5 ? '100' : '200',
      })),
    },
  };
}

function row(overrides = {}) {
  const blob = Buffer.alloc(HERO_STATS_PROFILE.blob_length);
  blob.writeFloatLE(1234.75, HERO_STATS_PROFILE.blob_fields.experience_points_raw.offset);
  blob.writeFloatLE(3210.5, HERO_STATS_PROFILE.blob_fields.total_gold_candidate.offset);
  blob.writeFloatLE(42, HERO_STATS_PROFILE.blob_fields.lane_minions_killed.offset);
  blob.writeFloatLE(11.5, HERO_STATS_PROFILE.blob_fields.jungle_minions_killed_candidate.offset);
  return {
    replay_sha256: 'a'.repeat(64),
    replay_version: HERO_STATS_PROFILE.replay_version,
    replay_time_ms: 60000,
    packet_id: HERO_STATS_PROFILE.replay_block_packet_id,
    chunk_stream: HERO_STATS_PROFILE.stream,
    raw_param: 0x400000b2,
    raw_payload_hex: '00',
    raw_payload_sha256: 'b'.repeat(64),
    decoded_fields: { blob_hex: blob.toString('hex') },
    decoder_runtime_image_sha256: HERO_STATS_PROFILE.runtime_image_sha256,
    decoder_profile_sha256: HERO_STATS_PROFILE_SHA256,
    decoded_opcode: HERO_STATS_PROFILE.client_opcode,
    opcode_matches_profile: true,
    deserialize_return_al: 1,
    fully_consumed: true,
    ...overrides,
  };
}

test('16.16 HeroStats accepts only exact-build full-consume keyframe rows', () => {
  assert.equal(isHeroStatsDecodedRow(replay(), row()), true);
  assert.equal(isHeroStatsDecodedRow(replay(), row({ chunk_stream: 'game_chunk' })), false);
  assert.equal(isHeroStatsDecodedRow(replay(), row({ fully_consumed: false })), false);
  assert.equal(isHeroStatsDecodedRow(replay(), row({ raw_param: 0x400000bd })), false);
});

test('16.16 HeroStats publishes only verified XP and lane CS while retaining candidates', () => {
  const event = heroScoreboardStateFromDecodedRow(replay(), row());
  assert.equal(event.participant_id, 5);
  assert.equal(event.champion, 'Champion5');
  assert.equal(event.experience_points, 1234.75);
  assert.equal(event.lane_minions_killed, 42);
  assert.deepEqual(event.state, {
    experience_points: 1234.75,
    lane_minions_killed: 42,
  });
  assert.equal(event.protocol_fields.experience_points_details_integer_projection, 1234);
  assert.equal(event.protocol_fields.total_gold_candidate_f32, 3210.5);
  assert.equal(event.protocol_fields.total_gold_semantic_status, 'CANDIDATE_NOT_PUBLISHED');
  assert.equal(event.protocol_fields.jungle_minions_killed_candidate_f32, 11.5);
  assert.equal(event.field_confidence.unidentified_blob_fields, 'UNKNOWN_RETAINED_RAW');
});

test('16.16 HeroStats rejects non-integral lane CS rather than silently coercing it', () => {
  const candidate = row();
  const blob = Buffer.from(candidate.decoded_fields.blob_hex, 'hex');
  blob.writeFloatLE(42.5, HERO_STATS_PROFILE.blob_fields.lane_minions_killed.offset);
  candidate.decoded_fields.blob_hex = blob.toString('hex');
  assert.equal(heroScoreboardStateFromDecodedRow(replay(), candidate), null);
});


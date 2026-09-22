'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  HERO_STATS_PROFILE,
  HERO_STATS_PROFILE_SHA256,
  SINGLE_PARTICIPANT_TAIL_BLOB_LENGTH,
  heroScoreboardStateFromDecodedRow,
  isHeroStatsDecodedRow,
} = require('../src/decoders/hero_stats_16_16');

function partialReplay() {
  return {
    header: { version: HERO_STATS_PROFILE.replay_version },
    source_sha256: 'a'.repeat(64),
    tail: { stats: [{ SKIN: 'Kayn', TEAM: 100 }] },
  };
}

function decodedRow({ rawParam = 0x400000ae, blobLength = SINGLE_PARTICIPANT_TAIL_BLOB_LENGTH } = {}) {
  const blob = Buffer.alloc(blobLength);
  blob.writeFloatLE(280, HERO_STATS_PROFILE.blob_fields.experience_points_raw.offset);
  blob.writeFloatLE(613.22, HERO_STATS_PROFILE.blob_fields.total_gold_candidate.offset);
  blob.writeFloatLE(0, HERO_STATS_PROFILE.blob_fields.lane_minions_killed.offset);
  blob.writeFloatLE(0, HERO_STATS_PROFILE.blob_fields.jungle_minions_killed_candidate.offset);
  return {
    replay_sha256: 'a'.repeat(64),
    replay_version: HERO_STATS_PROFILE.replay_version,
    replay_time_ms: 120033,
    packet_id: HERO_STATS_PROFILE.replay_block_packet_id,
    chunk_stream: HERO_STATS_PROFILE.stream,
    raw_param: rawParam,
    raw_payload_hex: '00',
    raw_payload_sha256: 'b'.repeat(64),
    decoded_fields: { blob_hex: blob.toString('hex') },
    decoder_runtime_image_sha256: HERO_STATS_PROFILE.runtime_image_sha256,
    decoder_profile_sha256: HERO_STATS_PROFILE_SHA256,
    decoded_opcode: HERO_STATS_PROFILE.client_opcode,
    opcode_matches_profile: true,
    deserialize_return_al: 1,
    fully_consumed: true,
  };
}

test('single-participant Replay tail accepts only its validated 812-byte HeroStats layout', () => {
  const replay = partialReplay();
  const row = decodedRow();
  assert.equal(isHeroStatsDecodedRow(replay, row), true);
  const event = heroScoreboardStateFromDecodedRow(replay, row);
  assert.equal(event.participant_id, 1);
  assert.equal(event.champion, 'Kayn');
  assert.equal(event.protocol_fields.scoreboard_blob_layout,
    'SINGLE_PARTICIPANT_TAIL_EXACT_PROFILE_812');
});

test('single-participant layout fails closed for an unmapped participant or unknown length', () => {
  const replay = partialReplay();
  assert.equal(isHeroStatsDecodedRow(replay, decodedRow({ rawParam: 0x400000af })), false);
  assert.equal(isHeroStatsDecodedRow(replay, decodedRow({ blobLength: 813 })), false);
});

test('812-byte layout is not accepted for a full roster', () => {
  const replay = {
    ...partialReplay(),
    tail: { stats: Array.from({ length: 10 }, () => ({ SKIN: 'Kayn', TEAM: 100 })) },
  };
  assert.equal(isHeroStatsDecodedRow(replay, decodedRow()), false);
});

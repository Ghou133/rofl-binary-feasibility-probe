'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');

const { walkBlocks } = require('../src/rofl');
const { resolveCapability } = require('../src/build_registry');
const { replayFromChunks } = require('./helpers/synthetic_replay');
const {
  SHIELDING_PARAMS_PACKET_PAIR_821_PROFILE: SHIELD_PROFILE,
} = require('../src/decoders/rofl_16_19_821_shielding_params_packet_pair_candidate');
const {
  HERO_ROSTER_METADATA_BRIDGE_821_PROFILE: ROSTER_PROFILE,
} = require('../src/decoders/rofl_16_19_821_roster_metadata_bridge_candidate');
const {
  SHIELDING_PARAMS_ROSTER_KEY_PAIR_821_PROFILE: PAIR_PROFILE,
  associateShieldingParamsRosterKeys821: associate,
} = require('../src/decoders/rofl_16_19_821_shielding_params_roster_key_pair_candidate');

const BUILD = '16.19.821.7343';
const FIRST_KEY = 0x400000ae;
const SHIELD_EVIDENCE = 'CANDIDATE_EXACT_RUNTIME_SHIELDING_PARAMS_PAIR';
const SHA = (value) => crypto.createHash('sha256').update(value).digest('hex');

function packet(id, param, payload, timeMs) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(id, 9);
  header.writeUInt32LE(param, 11);
  return Buffer.concat([header, payload]);
}

function fixture(version = BUILD) {
  const gameBody = Buffer.concat([
    packet(0x040a, FIRST_KEY + 1, Buffer.alloc(29, 1), 1000),
    packet(0x040a, FIRST_KEY + 2, Buffer.alloc(29, 2), 1000),
    packet(0x040a, FIRST_KEY + 3, Buffer.alloc(29, 3), 1100),
    packet(0x040a, 0x40003b78, Buffer.alloc(29, 4), 1100),
  ]);
  const keyframeBody = Buffer.concat(Array.from({ length: 10 }, (_, index) =>
    packet(0x0089, FIRST_KEY + index, Buffer.alloc(1263, index), 2000)));
  const replay = replayFromChunks([
    { stream: 1, body: gameBody },
    { stream: 2, body: keyframeBody },
  ], version);
  const shieldRefs = [];
  const rosterRefs = [];
  const walked = walkBlocks(replay, (block, chunk) => {
    const ref = {
      source_path: replay.source_path,
      replay_sha256: replay.source_sha256,
      chunk_index: chunk.index,
      chunk_id: chunk.chunk_id,
      chunk_stream: chunk.stream,
      chunk_file_offset: chunk.offset,
      decompressed_block_offset: block.offset,
      decompressed_payload_offset: block.payload_offset,
      packet_id: block.packet_id,
      replay_time_ms: block.timestamp_ms,
      payload_length: block.payload_length,
      raw_param: block.param,
      raw_payload_sha256: SHA(block.payload),
    };
    if (block.packet_id === 0x040a) shieldRefs.push(ref);
    else rosterRefs.push(ref);
  }, { strict: true });
  assert.equal(walked.errors.length, 0);
  const metadataSha = SHA('metadata');
  const statsSha = SHA('stats');
  const rosterRows = rosterRefs.map((ref, index) => ({
    event_type: 'HERO_ROSTER_METADATA_BRIDGE_CANDIDATE',
    game_version: BUILD, patch: '16.19', build_profile: ROSTER_PROFILE.id,
    replay_sha256: replay.source_sha256, replay_time_ms: ref.replay_time_ms,
    hero_raw_param: FIRST_KEY + index,
    participant_id_candidate: index + 1,
    metadata_index_candidate: index,
    champion_metadata: `Champion${index + 1}`,
    team_id_metadata: index < 5 ? 100 : 200,
    team_metadata: index < 5 ? 'blue' : 'red',
    role_metadata: ['top', 'jungle', 'mid', 'adc', 'support'][index % 5],
    metadata_sha256: metadataSha, stats_json_sha256: statsSha,
    confidence: 'CANDIDATE',
    semantic_status: ROSTER_PROFILE.evidence_status,
    roster_to_metadata_status: ROSTER_PROFILE.evidence_status,
    per_packet_actor_status: 'UNKNOWN', raw_packet_ref: ref,
  }));
  const shieldRows = [
    { a: FIRST_KEY + 1, b: FIRST_KEY + 2, refs: shieldRefs.slice(0, 2) },
    { a: FIRST_KEY + 3, b: 0x40003b78, refs: shieldRefs.slice(2, 4) },
  ].map((item, index) => ({
    event_type: 'SHIELDING_PARAMS_PACKET_PAIR_CANDIDATE',
    game_version: BUILD, patch: '16.19', build_profile: SHIELD_PROFILE.id,
    replay_sha256: replay.source_sha256,
    replay_time_ms: item.refs[0].replay_time_ms,
    child_event_ids: [0x00f0, 0x00ef],
    event_u32_0x08: item.a, event_u32_0x0c: item.b,
    event_raw_f32_0x10: index ? -12.5 : 25.5,
    event_blob_sha256: SHA(`pair-${index}`),
    raw_event_id_hex_by_child: {
      on_grant_shield_0x00f0: '0x492b',
      on_receive_shield_0x00ef: '0x4951',
    },
    confidence: 'CANDIDATE', semantic_status: SHIELD_EVIDENCE,
    raw_packet_refs: item.refs,
  }));
  const shieldingParamsPacketPairOutcome = {
    status: 'CANDIDATE', profile_id: SHIELD_PROFILE.id,
    evidence_status: SHIELD_EVIDENCE,
    input_packet_id: 0x040a, input_count: 4,
    event_count: 2, events: shieldRows,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: SHIELD_PROFILE.evidence_runtime_image_sha256,
  };
  const heroRosterMetadataBridgeOutcome = {
    status: 'CANDIDATE', profile_id: ROSTER_PROFILE.id,
    evidence_status: ROSTER_PROFILE.evidence_status,
    input_packet_id: 0x0089, input_count: 10, event_count: 10,
    unique_kda_match_count: 10, metadata_player_count: 10,
    metadata_sha256: metadataSha, stats_json_sha256: statsSha,
    events: rosterRows,
  };
  return { replay, shieldingParamsPacketPairOutcome,
    heroRosterMetadataBridgeOutcome };
}

test('two anonymous child fields independently match the ten-key roster', () => {
  const input = fixture();
  const result = associate(input.replay, input);
  assert.equal(result.status, 'CANDIDATE', result.error);
  assert.equal(result.source_pair_count, 2);
  assert.equal(result.event_count, 2);
  assert.equal(result.matched_0x08_count, 2);
  assert.equal(result.matched_0x0c_count, 1);
  assert.equal(result.unmatched_0x0c_count, 1);
  assert.equal(result.equal_fields_count, 0);
  assert.equal(result.events[0].roster_match_0x08.participant_id_candidate, 2);
  assert.equal(result.events[0].roster_match_0x08.team_metadata, 'blue');
  assert.equal(result.events[0].roster_match_0x0c.participant_id_candidate, 3);
  assert.equal(result.events[1].roster_match_0x0c.status,
    'NOT_IN_TEN_KEY_ROSTER');
  assert.equal(result.events[1].roster_match_0x0c.participant_id_candidate,
    null);
  assert.equal(result.events[1].roster_match_0x0c.roster_keyframe_packet_ref,
    null);
  assert.equal(result.events[1].raw_packet_refs.length, 2);
  assert.equal(result.events[0].roster_match_0x08.roster_keyframe_packet_ref.packet_id,
    0x0089);
  assert.equal(result.events[0].field_role_status, 'UNKNOWN');
  assert.equal(result.events[0].shield_effect_status, 'UNKNOWN');
  assert.doesNotMatch(JSON.stringify(result.events), /puuid|riot_id|metadata_player_id/i);
  assert.equal(resolveCapability(BUILD, PAIR_PROFILE.capability).status,
    'CANDIDATE');
  assert.equal(resolveCapability('16.19.820.7193', PAIR_PROFILE.capability).status,
    'UNAVAILABLE');
});

test('missing, neighboring-build and malformed sources fail without partial rows', () => {
  const input = fixture();
  const missing = associate(input.replay, {
    shieldingParamsPacketPairOutcome: input.shieldingParamsPacketPairOutcome,
  });
  assert.equal(missing.status, 'MISSING_INPUT');
  assert.equal(missing.events, null);
  const wrongBuild = fixture('16.19.820.7193');
  assert.equal(associate(wrongBuild.replay, wrongBuild).status, 'UNSUPPORTED');
  input.heroRosterMetadataBridgeOutcome.events[2].raw_packet_ref.raw_param =
    FIRST_KEY + 3;
  const malformed = associate(input.replay, input);
  assert.equal(malformed.status, 'DECODE_FAILED');
  assert.equal(malformed.events, null);
});

test('mutated shield ref and incomplete native result fail closed', () => {
  const input = fixture();
  input.shieldingParamsPacketPairOutcome.events[1].raw_packet_refs[1]
    .decompressed_block_offset = 0;
  assert.equal(associate(input.replay, input).status, 'DECODE_FAILED');
  const other = fixture();
  other.shieldingParamsPacketPairOutcome.runtime_image_sha256 = SHA('wrong');
  const mismatch = associate(other.replay, other);
  assert.equal(mismatch.status, 'DECODE_FAILED');
  assert.equal(mismatch.events, null);
});

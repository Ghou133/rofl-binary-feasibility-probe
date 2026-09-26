'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');

const { walkBlocks } = require('../src/rofl');
const { resolveCapability } = require('../src/build_registry');
const { replayFromChunks } = require('./helpers/synthetic_replay');
const {
  TARGET_HERO_PACKET_CANDIDATE_PROFILE_821: TARGET_PROFILE,
  decodeProtectedTargetHeroLookupKeyU32,
} = require('../src/decoders/rofl_16_19_821_target_hero_packet_candidate');
const {
  HERO_ROSTER_METADATA_BRIDGE_821_PROFILE: ROSTER_PROFILE,
} = require('../src/decoders/rofl_16_19_821_roster_metadata_bridge_candidate');
const {
  TARGET_HERO_ROSTER_KEY_PAIR_821_PROFILE: PAIR_PROFILE,
  associateTargetHeroRosterKeyPair821: associate,
} = require('../src/decoders/rofl_16_19_821_target_hero_roster_key_pair_candidate');

const BUILD = '16.19.821.7343';
const FIRST_KEY = 0x400000ae;
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
  const targetPayloads = [Buffer.from('33', 'hex'), Buffer.from('37c68e', 'hex')];
  const gameBody = Buffer.concat(targetPayloads.map((payload, index) =>
    packet(0x0265, FIRST_KEY + 6 + index, payload, 1000 + index * 100)));
  const keyframeBody = Buffer.concat(Array.from({ length: 10 }, (_, index) =>
    packet(0x0089, FIRST_KEY + index, Buffer.alloc(1263, index), 2000)));
  const replay = replayFromChunks([
    { stream: 1, body: gameBody },
    { stream: 2, body: keyframeBody },
  ], version);
  const targetRefs = [];
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
    if (block.packet_id === 0x0265) targetRefs.push({
      ...ref, raw_payload_hex: block.payload.toString('hex'),
    });
    else rosterRefs.push(ref);
  }, { strict: true });
  assert.equal(walked.errors.length, 0);
  const metadataSha = SHA('physical-metadata-placeholder');
  const statsSha = SHA('physical-stats-placeholder');
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
  const targetRows = targetRefs.map((ref, index) => {
    const nativeHex = index === 0 ? '35353535' : 'c63535f3';
    return {
      event_type: 'TARGET_HERO_PACKET_CANDIDATE',
      game_version: BUILD, patch: '16.19', build_profile: TARGET_PROFILE.id,
      replay_sha256: replay.source_sha256, replay_time_ms: ref.replay_time_ms,
      raw_param: ref.raw_param, packet_name_candidate: TARGET_PROFILE.packet_name,
      native_protected_lookup_bytes_hex: nativeHex,
      native_callback_lookup_key_u32:
        decodeProtectedTargetHeroLookupKeyU32(nativeHex),
      native_receiver_call_status: 'NOT_EXECUTED',
      source_actor_status: 'UNKNOWN', target_object_status: 'UNKNOWN',
      target_state_status: 'UNKNOWN', semantic_effect_status: 'UNKNOWN',
      confidence: 'CANDIDATE', semantic_status: TARGET_PROFILE.evidence_status,
      raw_packet_ref: ref,
    };
  });
  const targetHeroPacketOutcome = {
    status: 'CANDIDATE', profile_id: TARGET_PROFILE.id,
    evidence_status: TARGET_PROFILE.evidence_status,
    input_packet_id: 0x0265, input_count: targetRows.length,
    event_count: targetRows.length, events: targetRows,
    native_witness_status: 'FULLY_CONSUMED_ALL',
    native_full_success_count: targetRows.length,
    native_input_sha256: SHA('native-input'),
    native_output_sha256: SHA('native-output'),
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: TARGET_PROFILE.evidence_runtime_image_sha256,
  };
  const heroRosterMetadataBridgeOutcome = {
    status: 'CANDIDATE', profile_id: ROSTER_PROFILE.id,
    evidence_status: ROSTER_PROFILE.evidence_status,
    input_packet_id: 0x0089, input_count: 10, event_count: 10,
    unique_kda_match_count: 10, metadata_player_count: 10,
    metadata_sha256: metadataSha, stats_json_sha256: statsSha,
    events: rosterRows,
  };
  return { replay, targetHeroPacketOutcome,
    heroRosterMetadataBridgeOutcome };
}

test('opt-in exact-build pair retains both source refs and direct metadata labels', () => {
  const input = fixture();
  const result = associate(input.replay, input);
  assert.equal(result.status, 'CANDIDATE', result.error);
  assert.equal(result.input_count, 2);
  assert.equal(result.zero_lookup_key_count, 1);
  assert.equal(result.nonzero_lookup_key_count, 1);
  assert.equal(result.event_count, 1);
  assert.equal(result.matched_nonzero_count, 1);
  assert.equal(result.unexpected_nonzero_count, 0);
  assert.equal(result.target_hero_native_input_sha256,
    input.targetHeroPacketOutcome.native_input_sha256);
  const row = result.events[0];
  assert.equal(row.native_callback_lookup_key_u32, FIRST_KEY + 2);
  assert.equal(row.hero_raw_param, FIRST_KEY + 2);
  assert.equal(row.champion_metadata, 'Champion3');
  assert.equal(row.field_confidence.champion_metadata, 'VERIFIED_FROM_METADATA');
  assert.equal(row.field_confidence.hero_raw_param,
    'CANDIDATE_FULL_U32_ROSTER_KEY_EQUALITY');
  assert.equal(row.raw_packet_ref.packet_id, 0x0265);
  assert.equal(row.roster_keyframe_packet_ref.packet_id, 0x0089);
  assert.equal(row.source_actor_status, 'UNKNOWN');
  assert.equal(row.target_object_status, 'UNKNOWN');
  assert.equal(row.live_lookup_status, 'UNKNOWN');
  assert.equal(row.semantic_effect_status, 'UNKNOWN');
  assert.doesNotMatch(JSON.stringify(row), /puuid|riot_id|metadata_player_id/i);
  assert.equal(resolveCapability(BUILD, 'target_hero_roster_key_pair').status,
    'CANDIDATE');
  assert.equal(resolveCapability('16.19.820.7193',
    'target_hero_roster_key_pair').status, 'UNAVAILABLE');
  assert.equal(PAIR_PROFILE.depends_on.length, 2);
});

test('missing or malformed dependency fails without emitting partial pair rows', () => {
  const input = fixture();
  const missing = associate(input.replay, {
    targetHeroPacketOutcome: input.targetHeroPacketOutcome,
  });
  assert.equal(missing.status, 'MISSING_INPUT');
  assert.equal(missing.events, null);
  input.heroRosterMetadataBridgeOutcome.events[2].raw_packet_ref.raw_param =
    FIRST_KEY + 3;
  const malformed = associate(input.replay, input);
  assert.equal(malformed.status, 'DECODE_FAILED');
  assert.equal(malformed.events, null);
});

test('unexpected nonzero u32 and unobserved target payload fail closed', () => {
  const input = fixture();
  const row = input.targetHeroPacketOutcome.events[1];
  row.native_protected_lookup_bytes_hex = 'f3f3f3f3';
  row.native_callback_lookup_key_u32 =
    decodeProtectedTargetHeroLookupKeyU32(row.native_protected_lookup_bytes_hex);
  assert.notEqual(row.native_callback_lookup_key_u32, 0);
  assert.equal(row.native_callback_lookup_key_u32 < FIRST_KEY
    || row.native_callback_lookup_key_u32 > FIRST_KEY + 9, true);
  const outside = associate(input.replay, input);
  assert.equal(outside.status, 'PROFILE_UNAVAILABLE');
  assert.equal(outside.unexpected_nonzero_count, 1);
  assert.equal(outside.events, null);
  const another = fixture();
  another.targetHeroPacketOutcome.events[0].raw_packet_ref.raw_payload_hex = '34';
  another.targetHeroPacketOutcome.events[0].raw_packet_ref.raw_payload_sha256 =
    SHA(Buffer.from('34', 'hex'));
  const unobserved = associate(another.replay, another);
  assert.equal(unobserved.status, 'DECODE_FAILED');
  assert.equal(unobserved.events, null);
});

test('pair refuses a neighboring 16.19 build', () => {
  const input = fixture('16.19.820.7193');
  const result = associate(input.replay, input);
  assert.equal(result.status, 'UNSUPPORTED');
  assert.equal(result.events, null);
});

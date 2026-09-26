'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');

const { walkBlocks } = require('../src/rofl');
const { resolveCapability } = require('../src/build_registry');
const { replayFromChunks } = require('./helpers/synthetic_replay');
const {
  ANONYMOUS_029C_PACKET_CANDIDATE_PROFILE_821: PACKET_PROFILE,
  decodeProtectedAnonymous029cU32,
} = require('../src/decoders/rofl_16_19_821_anonymous_029c_packet_candidate');
const {
  HERO_ROSTER_METADATA_BRIDGE_821_PROFILE: ROSTER_PROFILE,
} = require('../src/decoders/rofl_16_19_821_roster_metadata_bridge_candidate');
const {
  ANONYMOUS_029C_ROSTER_KEY_PAIR_821_PROFILE: PAIR_PROFILE,
  associateAnonymous029cRosterKeyPair821: associate,
} = require('../src/decoders/rofl_16_19_821_anonymous_029c_roster_key_pair_candidate');

const BUILD = '16.19.821.7343';
const FIRST_KEY = 0x400000ae;
const sha = (value) => crypto.createHash('sha256').update(value).digest('hex');

function packet(id, param, payload, timeMs) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(id, 9);
  header.writeUInt32LE(param, 11);
  return Buffer.concat([header, payload]);
}

function fixture(version = BUILD, matchedPayload = '761fff') {
  const packetInputs = [
    [0, '72'],
    [FIRST_KEY + 2, matchedPayload],
    [FIRST_KEY + 2 + 0x100, '761fff'],
    [FIRST_KEY + 50, '761fff'],
  ];
  const replay = replayFromChunks([
    { stream: 1, body: Buffer.concat(packetInputs.map(([param, hex], index) =>
      packet(0x029c, param, Buffer.from(hex, 'hex'), 1000 + index * 100))) },
    { stream: 2, body: Buffer.concat(Array.from({ length: 10 }, (_, index) =>
      packet(0x0089, FIRST_KEY + index, Buffer.alloc(1263, index), 2000))) },
  ], version);
  const packetRefs = [];
  const rosterRefs = [];
  const walked = walkBlocks(replay, (block, chunk) => {
    const ref = {
      source_path: replay.source_path,
      replay_sha256: replay.source_sha256,
      chunk_index: chunk.index, chunk_id: chunk.chunk_id,
      chunk_stream: chunk.stream, chunk_file_offset: chunk.offset,
      decompressed_block_offset: block.offset,
      decompressed_payload_offset: block.payload_offset,
      packet_id: block.packet_id, replay_time_ms: block.timestamp_ms,
      payload_length: block.payload_length, raw_param: block.param,
      raw_payload_sha256: sha(block.payload),
    };
    if (block.packet_id === 0x029c) packetRefs.push({
      ...ref, raw_payload_hex: block.payload.toString('hex'),
    });
    else rosterRefs.push(ref);
  }, { strict: true });
  assert.equal(walked.errors.length, 0);
  const metadataSha = sha('metadata');
  const statsSha = sha('stats');
  const rosterRows = rosterRefs.map((ref, index) => ({
    event_type: 'HERO_ROSTER_METADATA_BRIDGE_CANDIDATE',
    game_version: BUILD, patch: '16.19', build_profile: ROSTER_PROFILE.id,
    replay_sha256: replay.source_sha256, replay_time_ms: ref.replay_time_ms,
    hero_raw_param: FIRST_KEY + index,
    participant_id_candidate: index + 1, metadata_index_candidate: index,
    champion_metadata: `Champion${index + 1}`,
    team_id_metadata: index < 5 ? 100 : 200,
    team_metadata: index < 5 ? 'blue' : 'red',
    role_metadata: ['top', 'jungle', 'mid', 'adc', 'support'][index % 5],
    metadata_sha256: metadataSha, stats_json_sha256: statsSha,
    confidence: 'CANDIDATE', semantic_status: ROSTER_PROFILE.evidence_status,
    roster_to_metadata_status: ROSTER_PROFILE.evidence_status,
    per_packet_actor_status: 'UNKNOWN', raw_packet_ref: ref,
  }));
  const inputHash = crypto.createHash('sha256');
  const outputHash = crypto.createHash('sha256');
  const packetRows = packetRefs.map((ref) => {
    const nativeHex = ref.payload_length === 1 ? '18181818' : '1f2ae31e';
    const value = decodeProtectedAnonymous029cU32(nativeHex);
    const payload = Buffer.from(ref.raw_payload_hex, 'hex');
    const input = Buffer.alloc(8);
    input.writeUInt32LE(ref.raw_param, 0);
    input.writeUInt32LE(payload.length, 4);
    inputHash.update(input).update(payload);
    const valueBytes = Buffer.alloc(4);
    valueBytes.writeUInt32LE(value);
    outputHash.update(Buffer.from('3e', 'hex'))
      .update(Buffer.from(nativeHex, 'hex')).update(valueBytes);
    return {
      event_type: 'ANONYMOUS_029C_PACKET_CANDIDATE',
      game_version: BUILD, patch: '16.19', build_profile: PACKET_PROFILE.id,
      replay_sha256: replay.source_sha256,
      replay_time_ms: ref.replay_time_ms, raw_param: ref.raw_param,
      native_protected_selector_byte_hex: '3e', native_selector_u8: 0,
      native_protected_u32_hex: nativeHex,
      anonymous_u32_candidate: value,
      anonymous_u32_is_sentinel: value === 0xffffffff,
      actor_status: 'UNKNOWN', target_status: 'UNKNOWN',
      object_role_status: 'UNKNOWN', receiver_state_status: 'UNKNOWN',
      behavior_status: 'UNKNOWN', effect_status: 'UNKNOWN',
      confidence: 'CANDIDATE', semantic_status: PACKET_PROFILE.evidence_status,
      raw_packet_ref: ref,
    };
  });
  const anonymous029cPacketOutcome = {
    status: 'CANDIDATE', profile_id: PACKET_PROFILE.id,
    evidence_status: PACKET_PROFILE.evidence_status,
    input_packet_id: 0x029c, input_count: packetRows.length,
    event_count: packetRows.length, events: packetRows,
    native_witness_status: 'FULLY_CONSUMED_ALL',
    native_full_success_count: packetRows.length,
    native_input_sha256: inputHash.digest('hex'),
    native_output_sha256: outputHash.digest('hex'),
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: PACKET_PROFILE.evidence_runtime_image_sha256,
  };
  const heroRosterMetadataBridgeOutcome = {
    status: 'CANDIDATE', profile_id: ROSTER_PROFILE.id,
    evidence_status: ROSTER_PROFILE.evidence_status,
    input_packet_id: 0x0089, input_count: 10, event_count: 10,
    unique_kda_match_count: 10, metadata_player_count: 10,
    metadata_sha256: metadataSha, stats_json_sha256: statsSha,
    events: rosterRows,
  };
  return { replay, anonymous029cPacketOutcome,
    heroRosterMetadataBridgeOutcome };
}

test('full header key joins exactly one row and excludes zero and +0x100 alias', () => {
  const input = fixture();
  const result = associate(input.replay, input);
  assert.equal(result.status, 'CANDIDATE', result.error);
  assert.equal(result.input_count, 4);
  assert.equal(result.event_count, 1);
  assert.equal(result.zero_header_count, 1);
  assert.equal(result.nonroster_nonzero_header_count, 2);
  assert.equal(result.plus_0x100_alias_excluded_count, 1);
  assert.equal(result.low_byte_alias_excluded_count, 1);
  assert.equal(result.anonymous_u32_sentinel_count, 1);
  const row = result.events[0];
  assert.equal(row.raw_param, FIRST_KEY + 2);
  assert.equal(row.hero_raw_param, FIRST_KEY + 2);
  assert.equal(row.participant_id_candidate, 3);
  assert.equal(row.champion_metadata, 'Champion3');
  assert.equal(row.anonymous_u32_candidate, 0x400001f7);
  assert.equal(row.actor_status, 'UNKNOWN');
  assert.equal(row.target_status, 'UNKNOWN');
  assert.equal(row.object_role_status, 'UNKNOWN');
  assert.equal(row.raw_packet_ref.packet_id, 0x029c);
  assert.equal(row.roster_keyframe_packet_ref.packet_id, 0x0089);
  assert.doesNotMatch(JSON.stringify(row), /puuid|riot_id|metadata_player_id/i);
  assert.equal(resolveCapability(BUILD, 'anonymous_029c_roster_key_pair').status,
    'CANDIDATE');
  assert.equal(resolveCapability('16.19.820.7193',
    'anonymous_029c_roster_key_pair').status, 'UNAVAILABLE');
  assert.equal(PAIR_PROFILE.depends_on.length, 2);
});

test('missing source and malformed roster fail without partial rows', () => {
  const input = fixture();
  assert.equal(associate(input.replay, {
    anonymous029cPacketOutcome: input.anonymous029cPacketOutcome,
  }).status, 'MISSING_INPUT');
  input.heroRosterMetadataBridgeOutcome.events[2].raw_packet_ref.raw_param =
    FIRST_KEY + 3;
  const malformed = associate(input.replay, input);
  assert.equal(malformed.status, 'DECODE_FAILED');
  assert.equal(malformed.events, null);
});

test('late source alteration and native digest alteration fail without rows', () => {
  const input = fixture();
  input.anonymous029cPacketOutcome.events[3].raw_packet_ref.raw_payload_hex = '72';
  const malformed = associate(input.replay, input);
  assert.equal(malformed.status, 'DECODE_FAILED');
  assert.equal(malformed.events, null);
  const another = fixture();
  another.anonymous029cPacketOutcome.native_output_sha256 = sha('altered');
  const digest = associate(another.replay, another);
  assert.equal(digest.status, 'DECODE_FAILED');
  assert.equal(digest.events, null);
});

test('the independent sentinel does not prevent full header equality', () => {
  const input = fixture(BUILD, '72');
  const result = associate(input.replay, input);
  assert.equal(result.status, 'CANDIDATE', result.error);
  assert.equal(result.event_count, 1);
  assert.equal(result.nonzero_header_sentinel_count, 1);
  assert.equal(result.events[0].anonymous_u32_is_sentinel, true);
  assert.equal(result.events[0].participant_id_candidate, 3);
});

test('inconsistent native sentinel and neighboring build fail closed', () => {
  const input = fixture();
  const row = input.anonymous029cPacketOutcome.events[1];
  row.native_protected_u32_hex = '18181818';
  row.anonymous_u32_candidate = 0xffffffff;
  row.anonymous_u32_is_sentinel = true;
  const malformed = associate(input.replay, input);
  assert.equal(malformed.status, 'DECODE_FAILED');
  assert.equal(malformed.events, null);
  const neighboring = fixture('16.19.820.7193');
  assert.equal(associate(neighboring.replay, neighboring).status, 'UNSUPPORTED');
});

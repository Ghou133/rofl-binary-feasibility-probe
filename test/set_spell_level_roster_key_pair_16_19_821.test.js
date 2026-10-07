'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');

const { walkBlocks } = require('../src/rofl');
const { resolveCapability } = require('../src/build_registry');
const { decodeSemanticReplay } = require('../src/semantic_api');
const { replayFromChunks } = require('./helpers/synthetic_replay');
const {
  SET_SPELL_LEVEL_PACKET_CANDIDATE_PROFILE_V2_821: PACKET_PROFILE,
  SET_SPELL_LEVEL_PACKET_CANDIDATE_PROFILE_V1_821: V1_PROFILE,
  decodeSetSpellLevelU32At10FromRaw821,
  decodeSetSpellLevelU32At14FromRaw821,
} = require('../src/decoders/rofl_16_19_821_set_spell_level_packet_candidate');
const {
  HERO_ROSTER_METADATA_BRIDGE_821_PROFILE: ROSTER_PROFILE,
} = require('../src/decoders/rofl_16_19_821_roster_metadata_bridge_candidate');
const {
  SET_SPELL_LEVEL_ROSTER_KEY_PAIR_821_PROFILE: PAIR_PROFILE,
  associateSetSpellLevelRosterKeyPair821: associate,
} = require('../src/decoders/rofl_16_19_821_set_spell_level_roster_key_pair_candidate');

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

function fixture(version = BUILD) {
  const inputs = [
    [FIRST_KEY + 4, '33', '7bbbbbbb', '72f1f1f1'],
    [FIRST_KEY + 4 + 0x100, '35', 'bbbbbbbb', '32f1f1f1'],
    [0x4000b91d, '37c6', 'bbbbbbbb', '32f1f1f1'],
  ];
  const replay = replayFromChunks([
    { stream: 1, body: Buffer.concat(inputs.map(([param, payload], index) =>
      packet(0x025d, param, Buffer.from(payload, 'hex'), 1000 + index * 100))) },
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
    if (block.packet_id === 0x025d) packetRefs.push(ref);
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
  const packetRows = packetRefs.map((ref, index) => {
    const at10 = inputs[index][2];
    const at14 = inputs[index][3];
    const value10 = decodeSetSpellLevelU32At10FromRaw821(at10);
    const value14 = decodeSetSpellLevelU32At14FromRaw821(at14);
    return {
      event_type: 'SET_SPELL_LEVEL_PACKET_CANDIDATE',
      game_version: BUILD, patch: '16.19', build_profile: PACKET_PROFILE.id,
      replay_sha256: replay.source_sha256, replay_time_ms: ref.replay_time_ms,
      raw_param: ref.raw_param, opaque_u32_0x10: value10,
      opaque_u32_0x14: value14, raw_object_u32_0x10_hex: at10,
      raw_object_u32_0x14_hex: at14,
      native_receiver_slot_candidate: value10 <= 63 ? value10 : 0,
      native_receiver_selection_source: value10 <= 63 ? 'INDEXED' : 'FALLBACK_0',
      native_clamped_scalar_candidate: Math.min(value14, 6),
      native_positive_flag_written: value14 > 0,
      confidence: 'CANDIDATE', semantic_status: 'CANDIDATE_EXACT_RUNTIME_PACKET_FIELDS',
      raw_packet_ref: ref,
    };
  });
  const setSpellLevelPacketOutcome = {
    status: 'CANDIDATE', profile_id: PACKET_PROFILE.id,
    evidence_status: 'CANDIDATE_EXACT_RUNTIME_PACKET_FIELDS',
    input_packet_id: 0x025d, input_count: packetRows.length,
    event_count: packetRows.length, events: packetRows,
    evidence_runtime_image_sha256: PACKET_PROFILE.evidence_runtime_image_sha256,
    evidence_callback_table_sha256: PACKET_PROFILE.evidence_callback_table_sha256,
    evidence_callback_rva: PACKET_PROFILE.evidence_callback_rva,
    evidence_receiver_write_rva: PACKET_PROFILE.evidence_receiver_write_rva,
    evidence_callback_witness_mode: PACKET_PROFILE.evidence_callback_witness_mode,
    evidence_callback_region_sha256: PACKET_PROFILE.evidence_callback_region_sha256,
    evidence_receiver_write_region_sha256: PACKET_PROFILE.evidence_receiver_write_region_sha256,
    scanned_block_count: walked.block_count,
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
  return { replay, setSpellLevelPacketOutcome, heroRosterMetadataBridgeOutcome };
}

test('V2 full header key pairs one row and retains both packet refs and exclusions', () => {
  const input = fixture();
  const result = associate(input.replay, input);
  assert.equal(result.status, 'CANDIDATE', result.error);
  assert.equal(result.input_count, 3);
  assert.equal(result.event_count, 1);
  assert.equal(result.nonroster_nonzero_header_count, 2);
  assert.equal(result.plus_0x100_alias_excluded_count, 1);
  assert.equal(result.zero_header_count, 0);
  const row = result.events[0];
  assert.equal(row.raw_param, FIRST_KEY + 4);
  assert.equal(row.participant_id_candidate, 5);
  assert.equal(row.champion_metadata, 'Champion5');
  assert.equal(row.native_receiver_slot_candidate, 12);
  assert.equal(row.native_clamped_scalar_candidate, 2);
  assert.equal(row.raw_packet_ref.packet_id, 0x025d);
  assert.equal(row.roster_keyframe_packet_ref.packet_id, 0x0089);
  assert.equal(row.packet_actor_status, 'UNKNOWN');
  assert.equal(row.spell_identity_status, 'UNKNOWN');
  assert.equal(row.actual_level_change_status, 'UNKNOWN');
  assert.doesNotMatch(JSON.stringify(row), /puuid|riot_id|metadata_player_id/i);
  assert.equal(resolveCapability(BUILD, 'set_spell_level_roster_key_pair').status,
    'CANDIDATE');
  assert.equal(resolveCapability('16.19.820.7193',
    'set_spell_level_roster_key_pair').status, 'UNAVAILABLE');
  assert.deepEqual(PAIR_PROFILE.depends_on,
    ['set_spell_level_packet', 'hero_roster_metadata_bridge']);
});

test('V1, absent bridge, changed image and incomplete roster do not emit rows', () => {
  const input = fixture();
  assert.equal(associate(input.replay, {
    setSpellLevelPacketOutcome: input.setSpellLevelPacketOutcome,
  }).status, 'MISSING_INPUT');
  input.setSpellLevelPacketOutcome.profile_id = V1_PROFILE.id;
  assert.equal(associate(input.replay, input).status, 'DECODE_FAILED');
  input.setSpellLevelPacketOutcome.profile_id = PACKET_PROFILE.id;
  input.setSpellLevelPacketOutcome.runtime_image_sha256 = sha('wrong image');
  assert.equal(associate(input.replay, input).events, null);
  input.setSpellLevelPacketOutcome.runtime_image_sha256 =
    PACKET_PROFILE.evidence_runtime_image_sha256;
  input.heroRosterMetadataBridgeOutcome.events.pop();
  assert.equal(associate(input.replay, input).events, null);
});

test('late source forgery and neighboring build fail closed', () => {
  const input = fixture();
  input.setSpellLevelPacketOutcome.events[2].opaque_u32_0x14 = 6;
  const forged = associate(input.replay, input);
  assert.equal(forged.status, 'DECODE_FAILED');
  assert.equal(forged.events, null);
  const neighboring = fixture('16.19.820.7193');
  assert.equal(associate(neighboring.replay, neighboring).status, 'UNSUPPORTED');
});

test('pair-only API rejects an explicit V1 packet source', () => {
  const { replay } = fixture();
  assert.throws(() => decodeSemanticReplay(replay, {
    capabilities: ['set_spell_level_roster_key_pair'],
    setSpellLevelProfile: 'v1',
  }), /roster pair requires packet profile v2/);
});

'use strict';

const crypto = require('node:crypto');

const { deathEvent } = require('../events');
const { walkBlocks } = require('../rofl');
const {
  DEATH_16_16_BUILD,
  DEATH_16_16_PACKET_ID,
  participantIdFromDeathParam,
} = require('../validation/death_16_16');
const {
  SEMANTIC_PROFILE_REGISTRY,
  participantIdFromChampionNetworkId,
} = require('./rofl_16_16_805_0442');

const DEATH_PROFILE = SEMANTIC_PROFILE_REGISTRY.hero_death;
const DEATH_RUNTIME_DECODER_PROFILE = 'runtime_candidate_16_16_0112';
const KILLER_LOOKUP_TABLE_HEX =
  '3ed305a70914bd1ee05db06e9bd632ee5172685a97a9a067c54259557f37c9ac8d0a5c462ca3d9d4d1077d3924edfe8e6199e33d1b089273f4adf0fccaa2ec38182acd87afd74a1dc67a2e30bc4f58be4d13fb8ace3f0185e98c201caa35262db42b3b19b8b545a8ff4712e5cc502716980b83f59129b2f91f0c868475641a0fe67c02049a94344e53efdcb1f8815206fac70eb6cf7721116f2582a64c600d7e93aec4eb5f9d62968f892fdd435ea1e2f1a49c88cb5678bf2223366c4871547074ba69e8e1e4e715bb6640105ba5c831f728f2f333b9fd00f6de579e0379b33ac26bdbd08b63176d9fd2ab49d5c0eada3c95b7447bdf90764bc36580416ac1d8';

function ror8(value, count) {
  const shift = count % 8;
  return ((value >>> shift) | (value << (8 - shift))) & 0xff;
}

function adjacentBitSwap(value) {
  return (((value & 0xd5) << 1) | ((value >>> 1) & 0x55)) & 0xff;
}

function buildKillerByteInverse() {
  const lookup = Buffer.from(KILLER_LOOKUP_TABLE_HEX, 'hex');
  const lookupSha256 = crypto.createHash('sha256').update(lookup).digest('hex');
  if (lookup.length !== 256
      || lookupSha256 !== DEATH_PROFILE.killer_storage_field.lookup_table_sha256) {
    throw new Error('embedded exact-build killer lookup table evidence is invalid');
  }
  const inverse = new Int16Array(256).fill(-1);
  for (let plain = 0; plain < 256; plain += 1) {
    let encoded = lookup[plain];
    encoded = ror8(encoded, 7);
    encoded = (encoded - 0x70) & 0xff;
    encoded = adjacentBitSwap(encoded);
    encoded = ror8(encoded, 7);
    encoded ^= 0x02;
    if (inverse[encoded] !== -1) throw new Error('killer byte transform is not a permutation');
    inverse[encoded] = plain;
  }
  if ([...inverse].some((value) => value < 0)) {
    throw new Error('killer byte transform does not cover every byte');
  }
  return inverse;
}

const KILLER_BYTE_INVERSE = buildKillerByteInverse();

function killerNetworkIdFromStorage(storageValue) {
  if (!Number.isInteger(storageValue) || storageValue < 0 || storageValue > 0xffffffff) {
    return null;
  }
  let result = 0;
  for (let index = 0; index < 4; index += 1) {
    const encoded = (storageValue >>> (index * 8)) & 0xff;
    result = (result | (KILLER_BYTE_INVERSE[encoded] << (index * 8))) >>> 0;
  }
  return result;
}

function participantMetadata(replay) {
  const participants = new Map();
  for (const [index, row] of (replay?.tail?.stats || []).entries()) {
    const participantId = index + 1;
    participants.set(participantId, {
      participant_id: participantId,
      champion: row.SKIN ?? null,
      team_id: Number.isFinite(Number(row.TEAM)) ? Number(row.TEAM) : null,
    });
  }
  return participants;
}

function hasHeroDeathSignature(block, chunk) {
  return chunk?.stream_tag === DEATH_PROFILE.stream_tag
    && block?.packet_id === DEATH_PROFILE.replay_block_packet_id;
}

function rawPacketRef(replay, chunk, block) {
  return {
    source_path: replay.source_path ?? null,
    replay_sha256: replay.source_sha256 ?? null,
    chunk_index: chunk.index ?? null,
    chunk_id: chunk.chunk_id ?? null,
    chunk_stream: chunk.stream ?? null,
    chunk_file_offset: chunk.offset ?? null,
    decompressed_block_offset: block.offset ?? null,
    decompressed_payload_offset: block.payload_offset ?? null,
    packet_id: block.packet_id,
    payload_length: block.payload_length,
    raw_param: block.param >>> 0,
    payload_sha256: crypto.createHash('sha256').update(block.payload).digest('hex'),
  };
}

function rawPacketRefFromDecodedRow(row) {
  return {
    source_path: row.replay_path ?? null,
    replay_sha256: row.replay_sha256 ?? null,
    chunk_index: row.chunk_index ?? null,
    chunk_id: row.chunk_id ?? null,
    chunk_stream: row.chunk_stream ?? null,
    chunk_file_offset: row.chunk_file_offset ?? null,
    compressed_body_offset: row.compressed_body_offset ?? null,
    decompressed_block_offset: row.decompressed_block_offset ?? null,
    decompressed_payload_offset: row.decompressed_payload_offset ?? null,
    packet_id: row.packet_id ?? null,
    payload_length: row.payload_length ?? null,
    raw_param: row.raw_param ?? null,
    payload_sha256: row.raw_payload_sha256 ?? null,
  };
}

function isHeroDeathDecodedRow(replay, row) {
  if (!replay || !row || replay.header?.version !== DEATH_PROFILE.replay_version) return false;
  const fields = row.decoded_fields || {};
  return row.replay_sha256 === replay.source_sha256
    && row.replay_version === replay.header.version
    && row.packet_id === DEATH_PROFILE.replay_block_packet_id
    && row.chunk_stream === DEATH_PROFILE.stream
    && row.decoder_profile === DEATH_RUNTIME_DECODER_PROFILE
    && row.decoder_profile_sha256 === DEATH_PROFILE.profile_sha256
    && row.decoder_runtime_image_sha256 === DEATH_PROFILE.runtime_image_sha256
    && row.decoded_opcode === DEATH_PROFILE.replay_block_packet_id
    && row.opcode_matches_profile === true
    && row.deserialize_return_al !== 0
    && row.fully_consumed === true
    && Number.isInteger(row.raw_param)
    && Number.isInteger(fields.unknown_u32_0x18);
}

function decodeHeroDeathDecodedRow(
  replay,
  row,
  participants = participantMetadata(replay),
) {
  if (!isHeroDeathDecodedRow(replay, row)) return null;
  const rawParam = row.raw_param >>> 0;
  const victimParticipantId = participantIdFromDeathParam(rawParam);
  const killerStorageValue = row.decoded_fields.unknown_u32_0x18 >>> 0;
  const killerNetworkId = killerNetworkIdFromStorage(killerStorageValue);
  const killerParticipantId = participantIdFromChampionNetworkId(killerNetworkId);
  if (victimParticipantId === null || killerParticipantId === null) return null;
  const victim = participants.get(victimParticipantId) ?? null;
  const killer = participants.get(killerParticipantId) ?? null;
  return deathEvent({
    game_version: replay.header.version,
    patch: '16.16',
    build_profile: DEATH_PROFILE.id,
    replay_sha256: row.replay_sha256,
    replay_time_ms: row.replay_time_ms,
    timestamp_ms: row.replay_time_ms,
    victim_network_id: rawParam,
    victim_network_id_semantics: 'RAW_PACKET_PARAM_UPPER_BYTES_UNKNOWN',
    victim_participant_id: victimParticipantId,
    victim_champion: victim?.champion ?? null,
    victim_team_id: victim?.team_id ?? null,
    victim_entity_type: 'CHAMPION',
    target_network_id: rawParam,
    target_participant_id: victimParticipantId,
    target_champion: victim?.champion ?? null,
    target_team_id: victim?.team_id ?? null,
    killer_network_id: killerNetworkId,
    killer_participant_id: killerParticipantId,
    killer_champion: killer?.champion ?? null,
    killer_team_id: killer?.team_id ?? null,
    assists: null,
    respawn_timestamp_ms: null,
    confidence: 'VERIFIED_DIRECT',
    semantic_status: 'VERIFIED_DIRECT',
    field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT',
      victim_network_id: 'VERIFIED_DIRECT_RAW_PARAM',
      victim_participant_id: 'VERIFIED_DERIVED',
      victim_champion: victim ? 'VERIFIED_DERIVED' : 'UNAVAILABLE',
      victim_team_id: victim ? 'VERIFIED_DERIVED' : 'UNAVAILABLE',
      victim_entity_type: 'VERIFIED_DIRECT_ROUTE_CONTRACT',
      killer_storage_field: 'VERIFIED_DIRECT',
      killer_network_id: 'VERIFIED_DIRECT',
      killer_participant_id: 'VERIFIED_DERIVED',
      killer_champion: killer ? 'VERIFIED_DERIVED' : 'UNAVAILABLE',
      killer_team_id: killer ? 'VERIFIED_DERIVED' : 'UNAVAILABLE',
      assists: 'UNAVAILABLE',
      respawn_timestamp_ms: 'UNAVAILABLE',
      other_inner_payload_fields: 'UNKNOWN_RETAINED_RAW',
    },
    field_evidence: {
      killer_network_id: {
        status: 'VERIFIED_DIRECT',
        method: 'EXACT_RUNTIME_HELPER_INVERSE',
        object_offset: DEATH_PROFILE.killer_storage_field.object_offset,
        helper_rva: DEATH_PROFILE.killer_storage_field.helper_rva,
        lookup_table_sha256: DEATH_PROFILE.killer_storage_field.lookup_table_sha256,
        validation_artifact: DEATH_PROFILE.validation_artifact,
        independent_match_count: 301,
        independent_mismatch_count: 0,
      },
      killer_participant_id: {
        status: 'VERIFIED_DERIVED',
        method: 'EXACT_BUILD_CHAMPION_NETWORK_ID_RULE',
        validation_artifact: DEATH_PROFILE.validation_artifact,
      },
      assists: {
        status: 'UNAVAILABLE',
        negative_validation_artifact: DEATH_PROFILE.validation_artifact,
        nonempty_assist_counterexample_count: 242,
      },
    },
    decoder_profile: DEATH_PROFILE.id,
    decoder_runtime_image_sha256: DEATH_PROFILE.runtime_image_sha256,
    raw_param: rawParam,
    raw_param_hex: `0x${rawParam.toString(16).padStart(8, '0')}`,
    raw_payload_hex: row.raw_payload_hex,
    raw_payload_sha256: row.raw_payload_sha256,
    raw_packet_ref: rawPacketRefFromDecodedRow(row),
    protocol_fields: {
      ...row.decoded_fields,
      killer_storage_u32: killerStorageValue,
      killer_helper_inverse_u32: killerNetworkId,
      killer_helper_rva: DEATH_PROFILE.killer_storage_field.helper_rva,
      killer_lookup_table_rva: DEATH_PROFILE.killer_storage_field.lookup_table_rva,
      all_other_inner_field_semantics: 'UNKNOWN_RETAINED_RAW',
      assists_semantics: 'UNAVAILABLE_WITH_EXPLICIT_NEGATIVE_DIFFERENTIAL',
    },
    known_limits: [...DEATH_PROFILE.known_limits],
  });
}

function decodeHeroDeathBlock(replay, chunk, block, participants = participantMetadata(replay)) {
  if (replay?.header?.version !== DEATH_PROFILE.replay_version
      || !hasHeroDeathSignature(block, chunk)) return null;
  const rawParam = block.param >>> 0;
  const participantId = participantIdFromDeathParam(rawParam);
  if (participantId === null) return null;
  const participant = participants.get(participantId) ?? null;
  const payloadSha256 = crypto.createHash('sha256').update(block.payload).digest('hex');
  return deathEvent({
    game_version: replay.header.version,
    patch: '16.16',
    build_profile: DEATH_PROFILE.id,
    replay_sha256: replay.source_sha256 ?? null,
    replay_time_ms: block.timestamp_ms,
    timestamp_ms: block.timestamp_ms,
    victim_network_id: rawParam,
    victim_network_id_semantics: 'RAW_PACKET_PARAM_UPPER_BYTES_UNKNOWN',
    victim_participant_id: participantId,
    victim_champion: participant?.champion ?? null,
    victim_team_id: participant?.team_id ?? null,
    victim_entity_type: 'CHAMPION',
    target_network_id: rawParam,
    target_participant_id: participantId,
    target_champion: participant?.champion ?? null,
    target_team_id: participant?.team_id ?? null,
    killer_network_id: null,
    killer_participant_id: null,
    assists: null,
    respawn_timestamp_ms: null,
    confidence: 'VERIFIED_DIRECT',
    semantic_status: 'VERIFIED_DIRECT',
    field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT',
      victim_network_id: 'VERIFIED_DIRECT_RAW_PARAM',
      victim_participant_id: 'VERIFIED_DERIVED_EXACT_BUILD',
      victim_champion: participant ? 'VERIFIED_DERIVED_REPLAY_TAIL' : 'UNAVAILABLE',
      victim_team_id: participant ? 'VERIFIED_DERIVED_REPLAY_TAIL' : 'UNAVAILABLE',
      victim_entity_type: 'VERIFIED_DIRECT_ROUTE_CONTRACT',
      killer_network_id: 'UNAVAILABLE_WITHOUT_RUNTIME_PAYLOAD_DECODE',
      killer_participant_id: 'UNAVAILABLE_WITHOUT_RUNTIME_PAYLOAD_DECODE',
      assists: 'UNAVAILABLE',
      respawn_timestamp_ms: 'UNAVAILABLE',
      inner_payload_fields: 'UNKNOWN',
    },
    decoder_profile: DEATH_PROFILE.id,
    raw_param: rawParam,
    raw_param_hex: `0x${rawParam.toString(16).padStart(8, '0')}`,
    raw_payload_hex: block.payload.toString('hex'),
    raw_payload_sha256: payloadSha256,
    raw_packet_ref: rawPacketRef(replay, chunk, block),
    protocol_fields: {
      inner_payload_semantics: 'UNKNOWN_RETAINED_RAW',
      raw_param_upper_bytes_semantics: 'UNKNOWN_RETAINED_RAW',
    },
    known_limits: [
      ...DEATH_PROFILE.known_limits,
      'This route-only record does not run the exact payload decoder, so killer remains null here.',
    ],
  });
}

function decodeHeroDeaths(replay, options = {}) {
  if (replay?.header?.version !== DEATH_PROFILE.replay_version) {
    const error = new Error(
      `decoder ${DEATH_PROFILE.id} only supports ${DEATH_PROFILE.replay_version}; got ${replay?.header?.version}`,
    );
    error.code = 'UNSUPPORTED_REPLAY_VERSION';
    throw error;
  }
  const participants = participantMetadata(replay);
  const events = [];
  let signatureCount = 0;
  let rejectedSignatureCount = 0;
  const walk = walkBlocks(replay, (block, chunk) => {
    if (!hasHeroDeathSignature(block, chunk)) return;
    signatureCount += 1;
    const event = decodeHeroDeathBlock(replay, chunk, block, participants);
    if (event) events.push(event);
    else rejectedSignatureCount += 1;
  }, {
    includeStreams: [DEATH_PROFILE.stream_tag],
    strict: options.strict !== false,
  });
  return {
    profile: DEATH_PROFILE,
    events,
    signature_count: signatureCount,
    rejected_signature_count: rejectedSignatureCount,
    walk,
  };
}

module.exports = {
  DEATH_PROFILE,
  DEATH_RUNTIME_DECODER_PROFILE,
  decodeHeroDeathBlock,
  decodeHeroDeathDecodedRow,
  decodeHeroDeaths,
  hasHeroDeathSignature,
  isHeroDeathDecodedRow,
  killerNetworkIdFromStorage,
  participantMetadata,
  rawPacketRef,
  rawPacketRefFromDecodedRow,
};

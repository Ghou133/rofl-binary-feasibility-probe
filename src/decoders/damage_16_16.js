'use strict';

const { damageEvent } = require('../events');
const {
  SEMANTIC_PROFILE_REGISTRY,
  participantIdFromChampionNetworkId,
} = require('./rofl_16_16_805_0442');

const DAMAGE_PROFILE = SEMANTIC_PROFILE_REGISTRY.hero_damage;

const DAMAGE_TYPE_BY_CODE = Object.freeze({
  0: 'physical',
  1: 'magic',
  2: 'true',
});

function participantMetadata(replay) {
  const result = new Map();
  for (const [index, row] of (replay?.tail?.stats || []).entries()) {
    const participantId = index + 1;
    result.set(participantId, {
      participant_id: participantId,
      champion: row.SKIN ?? null,
      team_id: Number.isFinite(Number(row.TEAM)) ? Number(row.TEAM) : null,
    });
  }
  return result;
}

function entityFromNetworkId(networkId, participants) {
  const participantId = participantIdFromChampionNetworkId(networkId);
  return participantId === null ? null : participants.get(participantId) ?? null;
}

function rawPacketRef(row) {
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

function isDamageDecodedRow(replay, row) {
  if (!replay || !row || replay.header?.version !== DAMAGE_PROFILE.replay_version) return false;
  if (row.replay_sha256 !== replay.source_sha256
      || row.replay_version !== replay.header.version
      || row.packet_id !== DAMAGE_PROFILE.replay_block_packet_id
      || row.decoder_profile !== DAMAGE_PROFILE.id
      || row.decoder_runtime_image_sha256 !== DAMAGE_PROFILE.runtime_image_sha256
      || row.decoded_opcode !== DAMAGE_PROFILE.client_opcode
      || row.opcode_matches_profile !== true
      || row.deserialize_return_al === 0
      || row.fully_consumed !== true) return false;
  const fields = row.decoded_fields || {};
  return Number.isInteger(fields.field_10_u32)
    && Number.isInteger(fields.field_14_u32)
    && Number.isFinite(fields.field_24_f32)
    && fields.field_24_f32 >= 0;
}

function damageEventFromDecodedRow(replay, row, participants = participantMetadata(replay)) {
  if (!isDamageDecodedRow(replay, row)) return null;
  const fields = row.decoded_fields;
  const sourceNetworkId = fields.field_10_u32 >>> 0;
  const targetNetworkId = fields.field_14_u32 >>> 0;
  const source = entityFromNetworkId(sourceNetworkId, participants);
  const target = entityFromNetworkId(targetNetworkId, participants);
  const damageTypeCode = Number.isInteger(fields.field_28_u8) ? fields.field_28_u8 : null;
  const damageType = damageTypeCode === null ? null : DAMAGE_TYPE_BY_CODE[damageTypeCode] ?? null;
  const secondaryAmount = Number.isFinite(fields.field_2c_f32) ? fields.field_2c_f32 : null;

  return damageEvent({
    game_version: replay.header.version,
    patch: '16.16',
    build_profile: DAMAGE_PROFILE.id,
    replay_sha256: row.replay_sha256,
    replay_time_ms: row.replay_time_ms,
    timestamp_ms: row.replay_time_ms,
    source_network_id: sourceNetworkId,
    target_network_id: targetNetworkId,
    source_participant_id: source?.participant_id ?? null,
    target_participant_id: target?.participant_id ?? null,
    source_champion: source?.champion ?? null,
    target_champion: target?.champion ?? null,
    source_team_id: source?.team_id ?? null,
    target_team_id: target?.team_id ?? null,
    source_entity_type: source ? 'champion' : 'UNKNOWN_ENTITY',
    target_entity_type: target ? 'champion' : 'UNKNOWN_ENTITY',
    amount: fields.field_24_f32,
    amount_status: 'VERIFIED_DIRECT',
    amount_semantic_stage: 'UNKNOWN',
    amount_semantic_stage_status: 'UNKNOWN',
    damage_type: damageType,
    damage_type_code: damageTypeCode,
    damage_type_status: damageType === null ? 'UNKNOWN' : 'VERIFIED_DIRECT',
    spell_key: null,
    spell_key_hex: null,
    spell_key_status: 'UNAVAILABLE',
    damage_result_code: null,
    is_critical: null,
    critical_status: 'UNAVAILABLE',
    confidence: 'VERIFIED_DIRECT',
    semantic_status: 'VERIFIED_DIRECT',
    field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT',
      source_network_id: 'VERIFIED_DIRECT',
      target_network_id: 'VERIFIED_DIRECT',
      amount: 'VERIFIED_DIRECT',
      amount_semantic_stage: 'UNKNOWN',
      source_participant_id: source ? 'VERIFIED_DERIVED' : 'UNAVAILABLE',
      target_participant_id: target ? 'VERIFIED_DERIVED' : 'UNAVAILABLE',
      damage_type: damageType === null ? 'UNKNOWN' : 'VERIFIED_DIRECT',
      damage_type_code: damageTypeCode === null ? 'UNKNOWN' : 'VERIFIED_DIRECT',
      spell_key: 'UNAVAILABLE',
      damage_result_code: 'UNAVAILABLE',
      is_critical: 'UNAVAILABLE',
      is_basic_attack: 'UNAVAILABLE',
      source_type: 'UNAVAILABLE',
      spell: 'UNAVAILABLE',
      item: 'UNAVAILABLE',
      rune: 'UNAVAILABLE',
      passive: 'UNAVAILABLE',
      pre_mitigation_amount: 'UNAVAILABLE',
      post_mitigation_amount: 'UNAVAILABLE',
      effective_damage: 'UNAVAILABLE',
    },
    decoder_profile: DAMAGE_PROFILE.id,
    decoder_runtime_image_sha256: DAMAGE_PROFILE.runtime_image_sha256,
    raw_param: row.raw_param,
    raw_param_hex: row.raw_param_hex,
    raw_payload_hex: row.raw_payload_hex,
    raw_payload_sha256: row.raw_payload_sha256,
    raw_packet_ref: rawPacketRef(row),
    protocol_fields: {
      field_18_storage_u8: fields.field_18_storage_u8 ?? null,
      field_1c_u32: fields.field_1c_u32 ?? null,
      field_20_u8: fields.field_20_u8 ?? null,
      field_21_u8: fields.field_21_u8 ?? null,
      primary_amount_field_24_f32: fields.field_24_f32,
      field_28_u8: fields.field_28_u8 ?? null,
      secondary_amount_field_2c_f32: secondaryAmount,
      field_30_u32: fields.field_30_u32 ?? null,
      unknown_field_semantics_status: 'UNKNOWN',
    },
  });
}

module.exports = {
  DAMAGE_PROFILE,
  DAMAGE_TYPE_BY_CODE,
  damageEventFromDecodedRow,
  entityFromNetworkId,
  isDamageDecodedRow,
  participantMetadata,
  rawPacketRef,
};

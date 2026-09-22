'use strict';

const { positionEvent } = require('./events');
const { artifactShaMatches, verifiedPacketRecord } = require('./provenance_v2');

const PATH_PIPELINE_SCHEMA_VERSION = 1;
const PATH_PACKET_PROFILE = Object.freeze({
  id: 'rofl-16.15.801.3452-path-packet-unicorn-v1',
  replay_version: '16.15.801.3452',
  replay_packet_id: 0x02d1,
  vtable_rva: 0x01b135d8,
  constructor_rva: 0x00eb1b90,
  deserialize_rva: 0x0103f810,
  deserialize_end_rva: 0x0103fbc9,
  object_size: 0x28,
  payload_pointer_offset: 0x18,
  payload_size_offset: 0x20,
  coordinate_transform: Object.freeze({
    x: 'signed_u16(encoded_x) * 2 + 7358',
    z: 'signed_u16(encoded_y) * 2 + 7412',
    status: 'VERIFIED_CURRENT_CALIBRATION',
  }),
  artifact_sha256: Object.freeze({
    hero_positions: '3ffceee08ee50cc19824b7b0f3388079c16bc8ae36b0ab6eedcb05da7b569c8c',
  }),
});

function normalizeVerifiedHeroPosition(
  replay, row, profile = PATH_PACKET_PROFILE, provenance = {},
) {
  if (!row || typeof row !== 'object') return null;
  if (replay?.header?.version !== profile.replay_version
      || row.event_type !== 'hero_position_1s'
      || row.replay_sha256 !== replay.source_sha256
      || row.coordinate_transform_status !== profile.coordinate_transform.status
      || !artifactShaMatches(provenance.inputSha256, profile.artifact_sha256.hero_positions)) return null;

  const timestampMs = row.timestamp_ms;
  const sourceTimestampMs = row.source_path_timestamp_ms;
  const entityId = row.entity_id;
  const position = row.position_xz;
  const sourceRawPacketRef = row.raw_packet_ref;
  if (!Number.isFinite(timestampMs) || timestampMs < 0
      || !Number.isFinite(sourceTimestampMs) || sourceTimestampMs < 0
      || sourceTimestampMs > timestampMs
      || !Number.isInteger(entityId)
      || !Array.isArray(position) || position.length !== 2
      || !position.every(Number.isFinite)) return null;
  if (!sourceRawPacketRef || typeof sourceRawPacketRef !== 'object'
      || sourceRawPacketRef.replay_sha256 !== replay.source_sha256
      || sourceRawPacketRef.packet_id !== profile.replay_packet_id
      || sourceRawPacketRef.packet_timestamp_ms !== sourceTimestampMs
      || !Number.isInteger(sourceRawPacketRef.chunk_index)
      || !Number.isInteger(sourceRawPacketRef.decompressed_block_offset)
      || !Number.isInteger(sourceRawPacketRef.payload_length)
      || !Number.isInteger(sourceRawPacketRef.raw_param)
      || typeof sourceRawPacketRef.raw_payload_sha256 !== 'string') return null;
  if (!verifiedPacketRecord(replay, provenance.packetIndex, sourceRawPacketRef, {
    packetId: profile.replay_packet_id,
    timestampMs: sourceTimestampMs,
  })) return null;

  return positionEvent({
    schema_version: PATH_PIPELINE_SCHEMA_VERSION,
    semantic_status: 'VERIFIED_DERIVED',
    confidence: 'VERIFIED_DERIVED',
    replay_sha256: row.replay_sha256,
    replay_time_ms: timestampMs,
    timestamp_ms: timestampMs,
    network_id: entityId,
    entity_id: entityId,
    x: position[0],
    y: position[1],
    z: position[1],
    position_xz: [...position],
    resolution_ms: 1000,
    interpolation: 'LINEAR_ALONG_DECODED_WAYPOINTS',
    source_path_timestamp_ms: sourceTimestampMs,
    coordinate_system: 'SUMMONERS_RIFT_GAME_PLANE_XZ',
    coordinate_transform_status: row.coordinate_transform_status,
    decoder_profile: profile.id,
    raw_packet_ref: sourceRawPacketRef,
    source_raw_packet_ref: sourceRawPacketRef,
    provenance: {
      source_event: 'hero_path',
      source_replay_packet_id: profile.replay_packet_id,
      source_path_timestamp_ms: sourceTimestampMs,
      source_raw_packet_ref: sourceRawPacketRef,
      position_derivation: 'ONE_SECOND_INTERPOLATION_FROM_VERIFIED_DECODED_PATH',
    },
    field_confidence: {
      timestamp_ms: 'VERIFIED_DERIVED',
      entity_id: 'VERIFIED_DIRECT_FROM_PATH_RECORD',
      position_xz: 'VERIFIED_DERIVED_INTERPOLATED',
    },
  });
}

function buildPathOutputs(replay, rows = [], provenance = {}) {
  if (!Array.isArray(rows)) throw new TypeError('hero position rows must be an array');
  const positionEvents = [];
  let replayInputCount = 0;
  let rejectedCount = 0;
  for (const row of rows) {
    const belongsToReplay = row?.replay_sha256 === replay?.source_sha256;
    if (belongsToReplay) replayInputCount += 1;
    const normalized = normalizeVerifiedHeroPosition(replay, row, PATH_PACKET_PROFILE, provenance);
    if (normalized) positionEvents.push(normalized);
    else if (belongsToReplay) rejectedCount += 1;
  }
  positionEvents.sort((left, right) => left.replay_time_ms - right.replay_time_ms
    || left.network_id - right.network_id);
  return {
    schema_version: PATH_PIPELINE_SCHEMA_VERSION,
    pipeline: 'path-v2',
    status: positionEvents.length > 0 ? 'HERO_POSITION_VERIFIED_DERIVED' : 'UNAVAILABLE',
    replay_sha256: replay?.source_sha256 ?? null,
    input_count: replayInputCount,
    accepted_count: positionEvents.length,
    rejected_count: rejectedCount,
    position_events: positionEvents,
    profile: PATH_PACKET_PROFILE,
  };
}

module.exports = {
  PATH_PIPELINE_SCHEMA_VERSION,
  PATH_PACKET_PROFILE,
  normalizeVerifiedHeroPosition,
  buildPathOutputs,
};

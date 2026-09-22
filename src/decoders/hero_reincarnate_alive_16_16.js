'use strict';

const crypto = require('node:crypto');
const {
  EXACT_BUILD,
  ROUTE_HEX,
  ROUTE_ID,
  RUNTIME_IMAGE_SHA256,
  STATIC_CHAIN,
  decodeProtectedFields,
  participantIdFromRawParam,
} = require('../hero_reincarnate_alive_v2');

const PATCH = '16.16';
const VALIDATION_ARTIFACT =
  'artifacts/full_semantic_deep_recovery_v2/hero_respawn/hero_reincarnate_alive_audit_16_16.json';
const VALIDATION_ARTIFACT_SHA256 =
  'e3801ae6e3946dfff7c11c7ed13637e02ef9eb8094caa3242543eb2d5f4f59d3';

const HERO_REINCARNATE_ALIVE_PROFILE = Object.freeze({
  id: 'rofl-16.16.805.0442-hero-reincarnate-alive-v1',
  event_type: 'HERO_REINCARNATE_ALIVE',
  semantic_domain: 'state',
  replay_version: EXACT_BUILD,
  packet_id: ROUTE_ID,
  packet_type: ROUTE_HEX,
  runtime_type_name: STATIC_CHAIN.runtime_type_name,
  runtime_image_sha256: RUNTIME_IMAGE_SHA256,
  runtime_decoder_profile:
    'artifacts/full_semantic_deep_recovery_v2/hero_respawn/packet_0265_profile.json',
  runtime_decoder_profile_id:
    '16.16.805.0442-route-0265-hero-reincarnate-alive-structural-v1',
  runtime_decoder_profile_sha256:
    'ef547d4f689ca356af9d0177562b3c26e70cee6472830cc8fb65105d36d30208',
  validation_artifact: VALIDATION_ARTIFACT,
  validation_artifact_sha256: VALIDATION_ARTIFACT_SHA256,
  status: 'SEMANTIC_VERIFIED_DIRECT',
  semantic_status: 'SEMANTIC_VERIFIED_DIRECT_BOUNDED',
  enabled: true,
  sample_count: Object.freeze({
    replay_count: 4,
    full_corpus_event_count: 282,
    exact_full_consume_count: 282,
    distinct_details_death_count: 301,
    terminal_unrespawned_death_count: 19,
  }),
  field_evidence: Object.freeze({
    replay_time_ms: 'VERIFIED_DIRECT_PACKET_TIMESTAMP',
    subject_network_id: 'VERIFIED_DIRECT_RAW_PARAM',
    participant_id: 'VERIFIED_DERIVED_EXACT_BUILD_LOW_BYTE_RULE',
    position_x: 'VERIFIED_DIRECT_PROTECTED_FIELD_CALLBACK_INVERSE',
    position_y: 'VERIFIED_DERIVED_CALLBACK_CONSTANT_ZERO',
    position_z: 'VERIFIED_DIRECT_PROTECTED_FIELD_CALLBACK_INVERSE',
    reincarnate_scalar: 'VERIFIED_DIRECT_VALUE_UNKNOWN_RESOURCE_LIKE_ROLE',
  }),
  known_limits: Object.freeze([
    'The full raw subject parameter is retained; participant mapping is exact-build low-byte derived.',
    'Position is a protocol coordinate and does not authorize map-region, base, or strategic labels.',
    'The third float is decoded and retained, but current/max/seed resource semantics remain CANDIDATE.',
    'The occurrence is HeroReincarnateAlive; no death causality, killer, or assist is inferred here.',
  ]),
});

function exactBuild(value) {
  return value?.header?.version ?? value?.replay_version ?? value?.exact_build
    ?? value?.game_version ?? value?.build ?? null;
}

function replaySha(value) {
  return value?.source_sha256 ?? value?.replay_sha256 ?? null;
}

function assertSafePath(value) {
  if (value !== null && value !== undefined && /holdout/i.test(String(value))) {
    throw new Error(`protected Holdout path is forbidden: ${value}`);
  }
}

function assertSha256(value, label) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/i.test(value)) {
    throw new Error(`${label} must be an exact SHA-256`);
  }
  return value.toLowerCase();
}

function rawPacketRef(row) {
  return {
    source_path: row.replay_path ?? null,
    replay_sha256: row.replay_sha256,
    chunk_index: row.chunk_index ?? null,
    chunk_id: row.chunk_id ?? null,
    chunk_stream: row.chunk_stream ?? null,
    chunk_file_offset: row.chunk_file_offset ?? null,
    compressed_body_offset: row.compressed_body_offset ?? null,
    decompressed_block_offset: row.decompressed_block_offset ?? null,
    decompressed_payload_offset: row.decompressed_payload_offset ?? null,
    occurrence_index: row.occurrence_index ?? null,
    packet_id: row.packet_id,
    packet_type: ROUTE_HEX,
    payload_length: row.payload_length ?? null,
    raw_param: row.raw_param,
    payload_sha256: row.raw_payload_sha256,
  };
}

function assertHeroReincarnateAliveDecodedRow(replay, row) {
  if (!replay || !row) throw new Error('replay and decoded row are required');
  assertSafePath(replay.source_path);
  assertSafePath(row.replay_path);
  if (exactBuild(replay) !== EXACT_BUILD || exactBuild(row) !== EXACT_BUILD) {
    throw new Error(`HeroReincarnateAlive only supports exact build ${EXACT_BUILD}`);
  }
  const sourceSha = assertSha256(replaySha(replay), 'Replay SHA-256');
  const rowSha = assertSha256(replaySha(row), 'decoded row Replay SHA-256');
  if (sourceSha !== rowSha) throw new Error('decoded row Replay SHA mismatch');
  if (row.packet_id !== ROUTE_ID || row.packet_type !== ROUTE_HEX) {
    throw new Error('decoded row packet discriminator mismatch');
  }
  if (row.fully_consumed !== true || row.deserialize_return_al !== 1) {
    throw new Error('decoded row is not an exact successful full-consume row');
  }
  if (row.decoder_runtime_image_sha256 !== RUNTIME_IMAGE_SHA256) {
    throw new Error('decoded row runtime image SHA mismatch');
  }
  if (row.decoder_profile !== HERO_REINCARNATE_ALIVE_PROFILE.runtime_decoder_profile_id
      || row.decoder_profile_sha256
        !== HERO_REINCARNATE_ALIVE_PROFILE.runtime_decoder_profile_sha256) {
    throw new Error('decoded row runtime profile mismatch');
  }
  if (row.decoded_opcode !== ROUTE_ID || row.opcode_matches_profile !== true) {
    throw new Error('decoded row opcode attestation failed');
  }
  if (!Number.isInteger(row.raw_param) || !Number.isFinite(Number(row.replay_time_ms))) {
    throw new Error('decoded row subject/time fields are invalid');
  }
  const payloadSha = assertSha256(row.raw_payload_sha256, 'decoded row payload SHA-256');
  if (typeof row.raw_payload_hex !== 'string' || !/^[a-f0-9]*$/i.test(row.raw_payload_hex)
      || row.raw_payload_hex.length % 2 !== 0
      || crypto.createHash('sha256').update(Buffer.from(row.raw_payload_hex, 'hex'))
        .digest('hex') !== payloadSha) {
    throw new Error('decoded row payload SHA does not match raw_payload_hex');
  }
  if (typeof row.object_hex !== 'string' || !/^[a-f0-9]+$/i.test(row.object_hex)
      || row.object_hex.length % 2 !== 0) {
    throw new Error('decoded row object_hex is invalid');
  }
  const object = Buffer.from(row.object_hex, 'hex');
  if (object.length !== STATIC_CHAIN.object_size
      || object.readUInt16LE(0x08) !== ROUTE_ID
      || object.readUInt32LE(0x0c) !== (row.raw_param >>> 0)) {
    throw new Error('decoded row object header route/subject mismatch');
  }
  const decoded = decodeProtectedFields(row);
  return { replay_sha256: sourceSha, decoded };
}

function heroReincarnateAliveEventFromDecodedRow(replay, row) {
  const { replay_sha256: replaySha256, decoded } =
    assertHeroReincarnateAliveDecodedRow(replay, row);
  return {
    event_type: HERO_REINCARNATE_ALIVE_PROFILE.event_type,
    semantic_type: 'EntityLifecycle',
    semantic_domain: 'state',
    patch: PATCH,
    build_profile: HERO_REINCARNATE_ALIVE_PROFILE.id,
    exact_build: EXACT_BUILD,
    game_version: EXACT_BUILD,
    replay_sha256: replaySha256,
    replay_time_ms: Number(row.replay_time_ms),
    respawn_timestamp_ms: Number(row.replay_time_ms),
    subject_network_id: row.raw_param >>> 0,
    participant_id: participantIdFromRawParam(row.raw_param),
    lifecycle_operation: 'REINCARNATE_ALIVE',
    position: { x: decoded.x, y: decoded.y, z: decoded.z },
    reincarnate_scalar: decoded.reincarnate_scalar,
    reincarnate_scalar_role: 'UNKNOWN_RESOURCE_LIKE_CANDIDATE',
    semantic_status: 'VERIFIED_DIRECT_BOUNDED',
    confidence: 'VERIFIED_DIRECT',
    evidence_grade:
      'VERIFIED_EXACT_BUILD_RUNTIME_CALLBACK_NATIVE_FULL_CONSUME_AND_SAFE_P0_DIFFERENTIAL',
    field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT',
      respawn_timestamp_ms: 'VERIFIED_DIRECT',
      subject_network_id: 'VERIFIED_DIRECT',
      participant_id: 'VERIFIED_DERIVED',
      position: 'VERIFIED_DIRECT',
      reincarnate_scalar: 'UNKNOWN_ROLE_VALUE_VERIFIED_DIRECT',
    },
    field_evidence: { ...HERO_REINCARNATE_ALIVE_PROFILE.field_evidence },
    decoder_profile: HERO_REINCARNATE_ALIVE_PROFILE.id,
    runtime_decoder_profile:
      HERO_REINCARNATE_ALIVE_PROFILE.runtime_decoder_profile_id,
    decoder_profile_sha256:
      HERO_REINCARNATE_ALIVE_PROFILE.runtime_decoder_profile_sha256,
    decoder_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    validation_artifact: VALIDATION_ARTIFACT,
    validation_artifact_sha256: VALIDATION_ARTIFACT_SHA256,
    raw_payload_sha256: row.raw_payload_sha256,
    raw_packet_ref: rawPacketRef(row),
    known_limits: [...HERO_REINCARNATE_ALIVE_PROFILE.known_limits],
  };
}

module.exports = {
  EXACT_BUILD,
  HERO_REINCARNATE_ALIVE_PROFILE,
  PATCH,
  VALIDATION_ARTIFACT,
  VALIDATION_ARTIFACT_SHA256,
  assertHeroReincarnateAliveDecodedRow,
  heroReincarnateAliveEventFromDecodedRow,
  rawPacketRef,
};

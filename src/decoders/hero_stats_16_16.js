'use strict';

const crypto = require('node:crypto');

const {
  SEMANTIC_PROFILE_REGISTRY,
  participantIdFromChampionNetworkId,
} = require('./rofl_16_16_805_0442');

const HERO_STATS_PROFILE = SEMANTIC_PROFILE_REGISTRY.hero_scoreboard_state;
const HERO_STATS_PROFILE_SHA256 = HERO_STATS_PROFILE.profile_sha256;
const SINGLE_PARTICIPANT_TAIL_BLOB_LENGTH = 812;

function participantMetadata(replay) {
  const participants = new Map();
  for (const [index, row] of (replay?.tail?.stats || []).entries()) {
    const participantId = index + 1;
    participants.set(participantId, {
      participant_id: participantId,
      entity_network_id: 0x400000ad + participantId,
      champion: row.SKIN ?? null,
      team_id: Number.isFinite(Number(row.TEAM)) ? Number(row.TEAM) : null,
    });
  }
  return participants;
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

function decodedBlob(row) {
  const value = row?.decoded_fields?.blob_hex;
  if (typeof value !== 'string' || !/^[0-9a-f]+$/i.test(value) || value.length % 2 !== 0) {
    return null;
  }
  const blob = Buffer.from(value, 'hex');
  return blob.length > 0 ? blob : null;
}

function scoreboardBlobLayoutForReplay(replay, row) {
  const blob = decodedBlob(row);
  if (!blob) return null;
  if (blob.length === HERO_STATS_PROFILE.blob_length) {
    return { blob, layout: 'FULL_ROSTER_EXACT_PROFILE_1476' };
  }

  // A one-participant custom/practice Replay emits a shorter HeroStats vector.
  // This acceptance is deliberately tied to its only observed exact-build layout,
  // a valid sole tail participant, and that participant's own network ID.
  const stats = replay?.tail?.stats;
  const participantId = participantIdFromChampionNetworkId(row?.raw_param);
  const soleTeamId = Number(stats?.[0]?.TEAM);
  if (
    Array.isArray(stats)
    && stats.length === 1
    && stats[0]
    && typeof stats[0] === 'object'
    && !Array.isArray(stats[0])
    && Number.isInteger(soleTeamId)
    && (soleTeamId === 100 || soleTeamId === 200)
    && participantId === 1
    && blob.length === SINGLE_PARTICIPANT_TAIL_BLOB_LENGTH
  ) {
    return { blob, layout: 'SINGLE_PARTICIPANT_TAIL_EXACT_PROFILE_812' };
  }
  return null;
}

function isHeroStatsDecodedRow(replay, row) {
  if (!replay || !row || replay.header?.version !== HERO_STATS_PROFILE.replay_version) return false;
  if (row.replay_sha256 !== replay.source_sha256
      || row.replay_version !== replay.header.version
      || row.packet_id !== HERO_STATS_PROFILE.replay_block_packet_id
      || row.chunk_stream !== HERO_STATS_PROFILE.stream
      || row.decoder_runtime_image_sha256 !== HERO_STATS_PROFILE.runtime_image_sha256
      || row.decoder_profile_sha256 !== HERO_STATS_PROFILE_SHA256
      || row.decoded_opcode !== HERO_STATS_PROFILE.client_opcode
      || row.opcode_matches_profile !== true
      || row.deserialize_return_al === 0
      || row.fully_consumed !== true) return false;
  const participantId = participantIdFromChampionNetworkId(row.raw_param);
  return participantId !== null && scoreboardBlobLayoutForReplay(replay, row) !== null;
}

function heroScoreboardStateFromDecodedRow(
  replay,
  row,
  participants = participantMetadata(replay),
) {
  if (!isHeroStatsDecodedRow(replay, row)) return null;
  const participantId = participantIdFromChampionNetworkId(row.raw_param);
  const participant = participants.get(participantId) ?? null;
  const blobLayout = scoreboardBlobLayoutForReplay(replay, row);
  const blob = blobLayout?.blob;
  if (!blob) return null;
  const experiencePoints = blob.readFloatLE(
    HERO_STATS_PROFILE.blob_fields.experience_points_raw.offset,
  );
  const laneMinionsKilled = blob.readFloatLE(
    HERO_STATS_PROFILE.blob_fields.lane_minions_killed.offset,
  );
  const totalGoldCandidate = blob.readFloatLE(
    HERO_STATS_PROFILE.blob_fields.total_gold_candidate.offset,
  );
  const jungleMinionsKilledCandidate = blob.readFloatLE(
    HERO_STATS_PROFILE.blob_fields.jungle_minions_killed_candidate.offset,
  );
  if (!Number.isFinite(experiencePoints) || experiencePoints < 0
      || !Number.isInteger(laneMinionsKilled) || laneMinionsKilled < 0
      || !Number.isFinite(totalGoldCandidate)
      || !Number.isFinite(jungleMinionsKilledCandidate)) return null;

  const entityNetworkId = row.raw_param >>> 0;
  return {
    event_type: 'STATE_UPDATE',
    state_event_type: 'HERO_CUMULATIVE_SCOREBOARD_STATE',
    semantic_type: 'HeroState',
    semantic_domain: 'hero_state',
    game_version: replay.header.version,
    exact_build: replay.header.version,
    patch: '16.16',
    build_profile: HERO_STATS_PROFILE.id,
    replay_sha256: row.replay_sha256,
    replay_time_ms: row.replay_time_ms,
    timestamp_ms: row.replay_time_ms,
    entity_id: entityNetworkId,
    entity_network_id: entityNetworkId,
    participant_id: participantId,
    champion: participant?.champion ?? null,
    team_id: participant?.team_id ?? null,
    experience_points: experiencePoints,
    lane_minions_killed: laneMinionsKilled,
    total_gold: null,
    jungle_minions_killed: null,
    state: {
      experience_points: experiencePoints,
      lane_minions_killed: laneMinionsKilled,
    },
    confidence: 'VERIFIED_DIRECT',
    evidence_grade: 'VERIFIED_DIRECT',
    semantic_status: 'VERIFIED_DIRECT',
    field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT',
      entity_network_id: 'VERIFIED_DIRECT_RAW_PARAM',
      participant_id: 'VERIFIED_DERIVED',
      champion: participant ? 'VERIFIED_DERIVED' : 'UNAVAILABLE',
      team_id: participant ? 'VERIFIED_DERIVED' : 'UNAVAILABLE',
      experience_points: 'VERIFIED_DIRECT',
      lane_minions_killed: 'VERIFIED_DIRECT',
      total_gold: 'CANDIDATE',
      jungle_minions_killed: 'CANDIDATE',
      unidentified_blob_fields: 'UNKNOWN_RETAINED_RAW',
    },
    field_evidence: {
      experience_points: {
        status: 'VERIFIED_DIRECT',
        decoded_blob_offset: HERO_STATS_PROFILE.blob_fields.experience_points_raw.offset,
        type: 'f32_le',
        independent_validation_relation: 'Math.floor(raw) === DETAILS participantFrame.xp',
        validation_artifact: HERO_STATS_PROFILE.validation_artifact,
      },
      lane_minions_killed: {
        status: 'VERIFIED_DIRECT',
        decoded_blob_offset: HERO_STATS_PROFILE.blob_fields.lane_minions_killed.offset,
        type: 'f32_le',
        independent_validation_relation: 'raw === DETAILS participantFrame.minionsKilled',
        validation_artifact: HERO_STATS_PROFILE.validation_artifact,
      },
    },
    decoder_profile: HERO_STATS_PROFILE.id,
    decoder_runtime_image_sha256: HERO_STATS_PROFILE.runtime_image_sha256,
    raw_param: entityNetworkId,
    raw_param_hex: `0x${entityNetworkId.toString(16).padStart(8, '0')}`,
    raw_payload_hex: row.raw_payload_hex,
    raw_payload_sha256: row.raw_payload_sha256,
    raw_packet_ref: rawPacketRef(row),
    protocol_fields: {
      decoded_blob_hex: blob.toString('hex'),
      decoded_blob_sha256: crypto.createHash('sha256').update(blob).digest('hex'),
      scoreboard_blob_layout: blobLayout.layout,
      experience_points_raw_f32: experiencePoints,
      experience_points_details_integer_projection: Math.floor(experiencePoints),
      lane_minions_killed_f32: laneMinionsKilled,
      total_gold_candidate_f32: totalGoldCandidate,
      total_gold_semantic_status: 'CANDIDATE_NOT_PUBLISHED',
      jungle_minions_killed_candidate_f32: jungleMinionsKilledCandidate,
      jungle_minions_killed_semantic_status: 'CANDIDATE_NOT_PUBLISHED',
      unidentified_blob_fields_status: 'UNKNOWN_RETAINED_RAW',
    },
    known_limits: [...HERO_STATS_PROFILE.known_limits],
  };
}

module.exports = {
  HERO_STATS_PROFILE,
  HERO_STATS_PROFILE_SHA256,
  SINGLE_PARTICIPANT_TAIL_BLOB_LENGTH,
  decodedBlob,
  heroScoreboardStateFromDecodedRow,
  isHeroStatsDecodedRow,
  participantMetadata,
  rawPacketRef,
  scoreboardBlobLayoutForReplay,
};

'use strict';

const crypto = require('node:crypto');
const { replaySourceError } = require('./replay_source_integrity');
const {
  TARGET_HERO_PACKET_CANDIDATE_PROFILE_821: TARGET_PROFILE,
  decodeProtectedTargetHeroLookupKeyU32,
  isObservedTargetHeroPayload,
} = require('./rofl_16_19_821_target_hero_packet_candidate');
const {
  HERO_ROSTER_METADATA_BRIDGE_821_PROFILE: ROSTER_PROFILE,
} = require('./rofl_16_19_821_roster_metadata_bridge_candidate');

const BUILD = '16.19.821.7343';
const FIRST_HERO_PARAM = 0x400000ae;
const LAST_HERO_PARAM = FIRST_HERO_PARAM + 9;
const EVIDENCE_STATUS = 'CANDIDATE_821_TARGET_HERO_CALLBACK_KEY_TO_METADATA_ROSTER';
const ASSOCIATION_STATUS = 'CANDIDATE_FULL_U32_ROSTER_KEY_EQUALITY';
const MAX_TARGET_ROWS = 40_000;

const TARGET_HERO_ROSTER_KEY_PAIR_821_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-target-hero-roster-key-pair-candidate-v1',
  replay_version: BUILD,
  capability: 'target_hero_roster_key_pair',
  status: 'CANDIDATE',
  evidence_status: EVIDENCE_STATUS,
  enabled: true,
  depends_on: Object.freeze(['target_hero_packet', 'hero_roster_metadata_bridge']),
  packet_ids: Object.freeze([0x0265, 0x0089]),
  evidence_runtime_image_sha256: TARGET_PROFILE.evidence_runtime_image_sha256,
  runtime_image_required: true,
  evidence_scope: '11 exact-build KR Replays: all 31345 nonzero native 0x0265 callback keys equal one of ten complete 0x0089 roster keys; 30874 zero keys are excluded',
  known_limits: Object.freeze([
    'Only a nonzero full u32 match to one of ten canonical HeroStats roster keys is paired; zero is retained in the result count and does not become a participant.',
    'Champion, team and role are direct Replay metadata labels; the roster-key association is a candidate and is not independent identity confirmation.',
    'The native callback was observed before a receiver-dependent call. Live lookup success, source actor, resolved target object, target state and effect remain unknown.',
    'Both source capabilities must be complete exact-build candidates; an unexpected nonzero key or malformed packet reference fails the pair without partial rows.',
  ]),
});

function sha(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function nonnegative(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function u32(value) {
  return nonnegative(value) && value <= 0xffffffff;
}

function validRef(replay, ref, packetId, stream, length) {
  const chunk = replay.chunks?.[ref?.chunk_index];
  return ref?.source_path === (replay.source_path ?? null)
    && ref.replay_sha256 === replay.source_sha256
    && nonnegative(ref.chunk_index) && nonnegative(ref.chunk_id)
    && ref.chunk_stream === stream && nonnegative(ref.chunk_file_offset)
    && nonnegative(ref.decompressed_block_offset)
    && nonnegative(ref.decompressed_payload_offset)
    && ref.decompressed_payload_offset > ref.decompressed_block_offset
    && ref.packet_id === packetId && nonnegative(ref.replay_time_ms)
    && ref.payload_length === length && u32(ref.raw_param)
    && sha(ref.raw_payload_sha256)
    && !!chunk && chunk.index === ref.chunk_index && chunk.chunk_id === ref.chunk_id
    && chunk.stream === stream && chunk.stream_tag === (stream === 'keyframe' ? 2 : 1)
    && chunk.offset === ref.chunk_file_offset
    && nonnegative(chunk.uncompressed_length)
    && ref.decompressed_payload_offset + length <= chunk.uncompressed_length;
}

function validRosterRow(replay, row, index, metadataSha, statsSha) {
  const rawParam = FIRST_HERO_PARAM + index;
  const ref = row?.raw_packet_ref;
  return row?.event_type === 'HERO_ROSTER_METADATA_BRIDGE_CANDIDATE'
    && row.game_version === BUILD && row.patch === '16.19'
    && row.build_profile === ROSTER_PROFILE.id
    && row.replay_sha256 === replay.source_sha256
    && row.replay_time_ms === ref?.replay_time_ms
    && row.hero_raw_param === rawParam
    && row.participant_id_candidate === index + 1
    && row.metadata_index_candidate === index
    && typeof row.champion_metadata === 'string'
    && row.champion_metadata.trim().length > 0
    && row.team_id_metadata === (index < 5 ? 100 : 200)
    && row.team_metadata === (index < 5 ? 'blue' : 'red')
    && ['top', 'jungle', 'mid', 'adc', 'support'].includes(row.role_metadata)
    && row.metadata_sha256 === metadataSha && row.stats_json_sha256 === statsSha
    && row.confidence === 'CANDIDATE'
    && row.semantic_status === ROSTER_PROFILE.evidence_status
    && row.roster_to_metadata_status === ROSTER_PROFILE.evidence_status
    && row.per_packet_actor_status === 'UNKNOWN'
    && validRef(replay, ref, 0x0089, 'keyframe', 1263)
    && ref.raw_param === rawParam;
}

function validTargetRow(replay, row) {
  const ref = row?.raw_packet_ref;
  const rawHex = row?.native_protected_lookup_bytes_hex;
  return row?.event_type === 'TARGET_HERO_PACKET_CANDIDATE'
    && row.game_version === BUILD && row.patch === '16.19'
    && row.build_profile === TARGET_PROFILE.id
    && row.replay_sha256 === replay.source_sha256
    && row.replay_time_ms === ref?.replay_time_ms
    && row.raw_param === ref?.raw_param
    && row.packet_name_candidate === TARGET_PROFILE.packet_name
    && row.confidence === 'CANDIDATE'
    && row.semantic_status === TARGET_PROFILE.evidence_status
    && row.native_receiver_call_status === 'NOT_EXECUTED'
    && row.source_actor_status === 'UNKNOWN'
    && row.target_object_status === 'UNKNOWN'
    && row.target_state_status === 'UNKNOWN'
    && row.semantic_effect_status === 'UNKNOWN'
    && typeof rawHex === 'string' && /^[0-9a-f]{8}$/.test(rawHex)
    && u32(row.native_callback_lookup_key_u32)
    && decodeProtectedTargetHeroLookupKeyU32(rawHex)
      === row.native_callback_lookup_key_u32
    && (ref?.payload_length === 1 || ref?.payload_length === 3)
    && validRef(replay, ref, 0x0265, 'game_chunk', ref.payload_length)
    && typeof ref.raw_payload_hex === 'string'
    && ref.raw_payload_hex.length === ref.payload_length * 2
    && /^[0-9a-f]+$/.test(ref.raw_payload_hex)
    && isObservedTargetHeroPayload(Buffer.from(ref.raw_payload_hex, 'hex'))
    && crypto.createHash('sha256').update(Buffer.from(ref.raw_payload_hex, 'hex'))
      .digest('hex') === ref.raw_payload_sha256;
}

function associateTargetHeroRosterKeyPair821(replay, {
  targetHeroPacketOutcome, heroRosterMetadataBridgeOutcome,
} = {}) {
  const profile = TARGET_HERO_ROSTER_KEY_PAIR_821_PROFILE;
  const dependencyStatuses = {
    target_hero_packet: targetHeroPacketOutcome?.status ?? 'UNEXECUTED',
    hero_roster_metadata_bridge: heroRosterMetadataBridgeOutcome?.status ?? 'UNEXECUTED',
  };
  const base = {
    profile_id: profile.id,
    input_packet_id: 0x0265,
    evidence_status: EVIDENCE_STATUS,
    evidence_runtime_image_sha256: profile.evidence_runtime_image_sha256,
    dependency_statuses: dependencyStatuses,
    runtime_image_status: targetHeroPacketOutcome?.runtime_image_status ?? 'NOT_CHECKED',
    runtime_image_used: targetHeroPacketOutcome?.runtime_image_used ?? false,
    known_limits: [...profile.known_limits],
  };
  const fail = (status, error, extra = {}) => ({
    ...base, status, input_count: null, event_count: null, events: null,
    error, ...extra,
  });
  if (replay?.header?.version !== BUILD) {
    return fail('UNSUPPORTED', `target_hero_roster_key_pair requires ${BUILD}`);
  }
  const sourceError = replaySourceError(replay);
  if (sourceError) return fail('DECODE_FAILED', `Replay source failed: ${sourceError}`);
  for (const [name, status] of Object.entries(dependencyStatuses)) {
    if (status !== 'CANDIDATE') {
      return fail(status === 'UNEXECUTED' ? 'MISSING_INPUT' : status,
        `target_hero_roster_key_pair requires ${name}: ${status}`);
    }
  }
  const target = targetHeroPacketOutcome;
  const roster = heroRosterMetadataBridgeOutcome;
  if (target.profile_id !== TARGET_PROFILE.id
      || target.evidence_status !== TARGET_PROFILE.evidence_status
      || target.input_packet_id !== 0x0265
      || !nonnegative(target.input_count) || target.input_count > MAX_TARGET_ROWS
      || target.event_count !== target.input_count
      || !Array.isArray(target.events)
      || target.events.length !== target.input_count
      || target.native_witness_status !== 'FULLY_CONSUMED_ALL'
      || target.native_full_success_count !== target.input_count
      || target.runtime_image_status !== 'MATCHED_USED'
      || target.runtime_image_used !== true
      || target.runtime_image_sha256 !== profile.evidence_runtime_image_sha256
      || !sha(target.native_input_sha256) || !sha(target.native_output_sha256)
      || roster.profile_id !== ROSTER_PROFILE.id
      || roster.evidence_status !== ROSTER_PROFILE.evidence_status
      || roster.input_packet_id !== 0x0089
      || roster.event_count !== 10 || roster.unique_kda_match_count !== 10
      || roster.metadata_player_count !== 10
      || !Array.isArray(roster.events) || roster.events.length !== 10
      || !sha(roster.metadata_sha256) || !sha(roster.stats_json_sha256)) {
    return fail('DECODE_FAILED', 'Incomplete exact-build target or roster dependency outcome');
  }
  const rosterByKey = new Map();
  for (let index = 0; index < 10; index += 1) {
    const row = roster.events[index];
    if (!validRosterRow(replay, row, index,
      roster.metadata_sha256, roster.stats_json_sha256)) {
      return fail('DECODE_FAILED', `Malformed 0x0089 roster row ${index}`);
    }
    rosterByKey.set(row.hero_raw_param, row);
  }
  const events = [];
  let zeroLookupKeyCount = 0;
  let unexpectedNonzeroCount = 0;
  let firstUnexpectedPacketRef = null;
  for (const [index, targetRow] of target.events.entries()) {
    if (!validTargetRow(replay, targetRow)) {
      return fail('DECODE_FAILED', `Malformed 0x0265 target row ${index}`, {
        input_count: target.input_count,
        first_failed_packet_ref: targetRow?.raw_packet_ref ?? null,
      });
    }
    const key = targetRow.native_callback_lookup_key_u32;
    if (key === 0) {
      zeroLookupKeyCount += 1;
      continue;
    }
    const matched = rosterByKey.get(key);
    if (!matched) {
      unexpectedNonzeroCount += 1;
      firstUnexpectedPacketRef ??= targetRow.raw_packet_ref;
      continue;
    }
    events.push({
      event_type: 'TARGET_HERO_ROSTER_KEY_PAIR_CANDIDATE',
      game_version: BUILD,
      patch: '16.19',
      build_profile: profile.id,
      replay_sha256: replay.source_sha256,
      replay_time_ms: targetRow.replay_time_ms,
      target_hero_raw_param: targetRow.raw_param,
      native_protected_lookup_bytes_hex:
        targetRow.native_protected_lookup_bytes_hex,
      native_callback_lookup_key_u32: key,
      hero_raw_param: matched.hero_raw_param,
      participant_id_candidate: matched.participant_id_candidate,
      metadata_index_candidate: matched.metadata_index_candidate,
      champion_metadata: matched.champion_metadata,
      team_id_metadata: matched.team_id_metadata,
      team_metadata: matched.team_metadata,
      role_metadata: matched.role_metadata,
      metadata_sha256: matched.metadata_sha256,
      stats_json_sha256: matched.stats_json_sha256,
      association_status: ASSOCIATION_STATUS,
      roster_to_metadata_status: matched.roster_to_metadata_status,
      native_receiver_call_status: 'NOT_EXECUTED',
      source_actor_status: 'UNKNOWN',
      target_object_status: 'UNKNOWN',
      target_state_status: 'UNKNOWN',
      live_lookup_status: 'UNKNOWN',
      semantic_effect_status: 'UNKNOWN',
      confidence: 'CANDIDATE',
      semantic_status: EVIDENCE_STATUS,
      field_confidence: {
        native_callback_lookup_key_u32: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_WITNESS',
        hero_raw_param: ASSOCIATION_STATUS,
        champion_metadata: 'VERIFIED_FROM_METADATA',
        team_metadata: 'VERIFIED_FROM_METADATA',
        role_metadata: 'VERIFIED_FROM_METADATA',
        participant_id_candidate: ASSOCIATION_STATUS,
        source_actor_status: 'UNKNOWN',
        target_object_status: 'UNKNOWN',
      },
      raw_packet_ref: targetRow.raw_packet_ref,
      roster_keyframe_packet_ref: matched.raw_packet_ref,
      known_limits: [...profile.known_limits],
    });
  }
  if (unexpectedNonzeroCount) {
    return fail('PROFILE_UNAVAILABLE',
      `${unexpectedNonzeroCount} nonzero 0x0265 callback keys are outside the ten-key roster`, {
        input_count: target.input_count,
        zero_lookup_key_count: zeroLookupKeyCount,
        nonzero_lookup_key_count: target.input_count - zeroLookupKeyCount,
        unexpected_nonzero_count: unexpectedNonzeroCount,
        first_unexpected_packet_ref: firstUnexpectedPacketRef,
      });
  }
  return {
    ...base,
    status: 'CANDIDATE',
    input_count: target.input_count,
    event_count: events.length,
    zero_lookup_key_count: zeroLookupKeyCount,
    nonzero_lookup_key_count: target.input_count - zeroLookupKeyCount,
    matched_nonzero_count: events.length,
    unexpected_nonzero_count: 0,
    native_witness_status: target.native_witness_status,
    native_full_success_count: target.native_full_success_count,
    runtime_image_sha256: target.runtime_image_sha256,
    target_hero_native_input_sha256: target.native_input_sha256,
    target_hero_native_output_sha256: target.native_output_sha256,
    metadata_sha256: roster.metadata_sha256,
    stats_json_sha256: roster.stats_json_sha256,
    events,
  };
}

module.exports = {
  TARGET_HERO_ROSTER_KEY_PAIR_821_PROFILE,
  associateTargetHeroRosterKeyPair821,
};

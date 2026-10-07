'use strict';

const { replaySourceError } = require('./replay_source_integrity');
const {
  SHIELDING_PARAMS_PACKET_PAIR_821_PROFILE: SHIELD_PROFILE,
} = require('./rofl_16_19_821_shielding_params_packet_pair_candidate');
const {
  HERO_ROSTER_METADATA_BRIDGE_821_PROFILE: ROSTER_PROFILE,
} = require('./rofl_16_19_821_roster_metadata_bridge_candidate');

const BUILD = '16.19.821.7343';
const FIRST_HERO_PARAM = 0x400000ae;
const SHIELD_EVIDENCE_STATUS =
  'CANDIDATE_EXACT_RUNTIME_SHIELDING_PARAMS_PAIR';
const EVIDENCE_STATUS = 'CANDIDATE_821_SHIELDING_PARAMS_FIELDS_TO_ROSTER_KEYS';
const ASSOCIATION_STATUS = 'CANDIDATE_FULL_U32_ROSTER_KEY_EQUALITY';
const MAX_PAIR_ROWS = 5_000;

const SHIELDING_PARAMS_ROSTER_KEY_PAIR_821_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-shielding-params-roster-key-pair-candidate-v1',
  replay_version: BUILD,
  capability: 'shielding_params_roster_key_pair',
  status: 'CANDIDATE',
  evidence_status: EVIDENCE_STATUS,
  enabled: true,
  depends_on: Object.freeze(['shielding_params_packet_pair',
    'hero_roster_metadata_bridge']),
  packet_ids: Object.freeze([0x040a, 0x0089]),
  evidence_runtime_image_sha256: SHIELD_PROFILE.evidence_runtime_image_sha256,
  runtime_image_required: true,
  evidence_scope: '11 exact-build KR Replays: 2778/2778 native ShieldingParams +0x08 u32 values and 2770/2778 +0x0c values equal one of ten complete HeroStats roster keys; eight +0x0c values remain outside the roster',
  known_limits: Object.freeze([
    'The two decoded child fields are matched separately by full u32 equality to the same-Replay ten-key HeroStats roster. Unmatched values and source packet refs are retained.',
    'The +0x08 and +0x0c fields have no assigned giver, receiver, source, target, actor, or victim role.',
    'The paired report and its opaque f32 do not prove shield creation, absorption, removal, or a health-state effect.',
    'Champion, team and role labels are direct Replay metadata; their association with a roster key is a candidate, not independent participant proof.',
    'Both complete exact-build source capabilities and the pinned mapped runtime image are required.',
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

function validShieldRow(replay, row) {
  const refs = row?.raw_packet_refs;
  if (!Array.isArray(refs) || refs.length !== 2) return false;
  const [grant, receive] = refs;
  return row.event_type === 'SHIELDING_PARAMS_PACKET_PAIR_CANDIDATE'
    && row.game_version === BUILD && row.patch === '16.19'
    && row.build_profile === SHIELD_PROFILE.id
    && row.replay_sha256 === replay.source_sha256
    && row.replay_time_ms === grant?.replay_time_ms
    && Array.isArray(row.child_event_ids)
    && row.child_event_ids.length === 2
    && row.child_event_ids[0] === 0x00f0
    && row.child_event_ids[1] === 0x00ef
    && u32(row.event_u32_0x08) && u32(row.event_u32_0x0c)
    && typeof row.event_raw_f32_0x10 === 'number'
    && Number.isFinite(row.event_raw_f32_0x10)
    && sha(row.event_blob_sha256)
    && row.raw_event_id_hex_by_child?.on_grant_shield_0x00f0 === '0x492b'
    && row.raw_event_id_hex_by_child?.on_receive_shield_0x00ef === '0x4951'
    && row.confidence === 'CANDIDATE'
    && row.semantic_status === SHIELD_EVIDENCE_STATUS
    && validRef(replay, grant, 0x040a, 'game_chunk', 29)
    && validRef(replay, receive, 0x040a, 'game_chunk', 29)
    && grant.chunk_index === receive.chunk_index
    && grant.chunk_id === receive.chunk_id
    && grant.chunk_file_offset === receive.chunk_file_offset
    && grant.replay_time_ms === receive.replay_time_ms
    && grant.decompressed_block_offset < receive.decompressed_block_offset;
}

function rosterMatch(key, rosterByKey) {
  const row = rosterByKey.get(key);
  if (!row) return {
    status: 'NOT_IN_TEN_KEY_ROSTER',
    hero_raw_param: null,
    participant_id_candidate: null,
    metadata_index_candidate: null,
    champion_metadata: null,
    team_id_metadata: null,
    team_metadata: null,
    role_metadata: null,
    roster_to_metadata_status: null,
    roster_keyframe_packet_ref: null,
  };
  return {
    status: ASSOCIATION_STATUS,
    hero_raw_param: row.hero_raw_param,
    participant_id_candidate: row.participant_id_candidate,
    metadata_index_candidate: row.metadata_index_candidate,
    champion_metadata: row.champion_metadata,
    team_id_metadata: row.team_id_metadata,
    team_metadata: row.team_metadata,
    role_metadata: row.role_metadata,
    roster_to_metadata_status: row.roster_to_metadata_status,
    roster_keyframe_packet_ref: row.raw_packet_ref,
  };
}

function associateShieldingParamsRosterKeys821(replay, {
  shieldingParamsPacketPairOutcome, heroRosterMetadataBridgeOutcome,
} = {}) {
  const profile = SHIELDING_PARAMS_ROSTER_KEY_PAIR_821_PROFILE;
  const dependencyStatuses = {
    shielding_params_packet_pair: shieldingParamsPacketPairOutcome?.status ?? 'UNEXECUTED',
    hero_roster_metadata_bridge: heroRosterMetadataBridgeOutcome?.status ?? 'UNEXECUTED',
  };
  const base = {
    profile_id: profile.id,
    input_packet_id: 0x040a,
    evidence_status: EVIDENCE_STATUS,
    evidence_runtime_image_sha256: profile.evidence_runtime_image_sha256,
    dependency_statuses: dependencyStatuses,
    runtime_image_status: shieldingParamsPacketPairOutcome?.runtime_image_status ?? 'NOT_CHECKED',
    runtime_image_used: shieldingParamsPacketPairOutcome?.runtime_image_used ?? false,
    known_limits: [...profile.known_limits],
  };
  const fail = (status, error, extra = {}) => ({
    ...base, status, input_count: null, event_count: null, events: null,
    error, ...extra,
  });
  if (replay?.header?.version !== BUILD) {
    return fail('UNSUPPORTED', `shielding_params_roster_key_pair requires ${BUILD}`);
  }
  const sourceError = replaySourceError(replay);
  if (sourceError) return fail('DECODE_FAILED', `Replay source failed: ${sourceError}`);
  for (const [name, status] of Object.entries(dependencyStatuses)) {
    if (status !== 'CANDIDATE') {
      return fail(status === 'UNEXECUTED' ? 'MISSING_INPUT' : status,
        `shielding_params_roster_key_pair requires ${name}: ${status}`);
    }
  }
  const shield = shieldingParamsPacketPairOutcome;
  const roster = heroRosterMetadataBridgeOutcome;
  if (shield.profile_id !== SHIELD_PROFILE.id
      || shield.evidence_status !== SHIELD_EVIDENCE_STATUS
      || shield.input_packet_id !== 0x040a
      || !nonnegative(shield.input_count)
      || shield.input_count > MAX_PAIR_ROWS * 2
      || !nonnegative(shield.event_count)
      || shield.event_count > MAX_PAIR_ROWS
      || shield.input_count !== shield.event_count * 2
      || !Array.isArray(shield.events)
      || shield.events.length !== shield.event_count
      || shield.runtime_image_status !== 'MATCHED_USED'
      || shield.runtime_image_used !== true
      || shield.runtime_image_sha256 !== profile.evidence_runtime_image_sha256
      || roster.profile_id !== ROSTER_PROFILE.id
      || roster.evidence_status !== ROSTER_PROFILE.evidence_status
      || roster.input_packet_id !== 0x0089
      || roster.event_count !== 10 || roster.unique_kda_match_count !== 10
      || roster.metadata_player_count !== 10
      || !Array.isArray(roster.events) || roster.events.length !== 10
      || !sha(roster.metadata_sha256) || !sha(roster.stats_json_sha256)) {
    return fail('DECODE_FAILED', 'Incomplete exact-build shield or roster dependency outcome');
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
  let matched08Count = 0;
  let matched0cCount = 0;
  let sameFieldCount = 0;
  for (const [index, shieldRow] of shield.events.entries()) {
    if (!validShieldRow(replay, shieldRow)) {
      return fail('DECODE_FAILED', `Malformed 0x040a ShieldingParams row ${index}`, {
        first_failed_packet_refs: shieldRow?.raw_packet_refs ?? null,
      });
    }
    const match08 = rosterMatch(shieldRow.event_u32_0x08, rosterByKey);
    const match0c = rosterMatch(shieldRow.event_u32_0x0c, rosterByKey);
    if (match08.status === ASSOCIATION_STATUS) matched08Count += 1;
    if (match0c.status === ASSOCIATION_STATUS) matched0cCount += 1;
    if (shieldRow.event_u32_0x08 === shieldRow.event_u32_0x0c) sameFieldCount += 1;
    events.push({
      event_type: 'SHIELDING_PARAMS_ROSTER_KEY_PAIR_CANDIDATE',
      game_version: BUILD,
      patch: '16.19',
      build_profile: profile.id,
      replay_sha256: replay.source_sha256,
      replay_time_ms: shieldRow.replay_time_ms,
      child_event_ids: [0x00f0, 0x00ef],
      event_u32_0x08: shieldRow.event_u32_0x08,
      event_u32_0x0c: shieldRow.event_u32_0x0c,
      event_raw_f32_0x10: shieldRow.event_raw_f32_0x10,
      event_blob_sha256: shieldRow.event_blob_sha256,
      roster_match_0x08: match08,
      roster_match_0x0c: match0c,
      metadata_sha256: roster.metadata_sha256,
      stats_json_sha256: roster.stats_json_sha256,
      field_role_status: 'UNKNOWN',
      shield_effect_status: 'UNKNOWN',
      confidence: 'CANDIDATE',
      semantic_status: EVIDENCE_STATUS,
      field_confidence: {
        event_u32_0x08: 'CANDIDATE_EXACT_RUNTIME_FIELD',
        event_u32_0x0c: 'CANDIDATE_EXACT_RUNTIME_FIELD',
        roster_match_0x08: match08.status,
        roster_match_0x0c: match0c.status,
        field_role_status: 'UNKNOWN',
        shield_effect_status: 'UNKNOWN',
      },
      raw_packet_refs: shieldRow.raw_packet_refs,
    });
  }
  if (matched08Count + matched0cCount === 0) {
    return fail('PROFILE_UNAVAILABLE', 'No ShieldingParams child field equals a ten-key HeroStats roster key', {
      input_count: shield.input_count,
      source_pair_count: shield.event_count,
      unmatched_0x08_count: shield.event_count,
      unmatched_0x0c_count: shield.event_count,
    });
  }
  return {
    ...base,
    status: 'CANDIDATE',
    input_count: shield.input_count,
    source_pair_count: shield.event_count,
    event_count: events.length,
    matched_0x08_count: matched08Count,
    unmatched_0x08_count: shield.event_count - matched08Count,
    matched_0x0c_count: matched0cCount,
    unmatched_0x0c_count: shield.event_count - matched0cCount,
    equal_fields_count: sameFieldCount,
    runtime_image_sha256: shield.runtime_image_sha256,
    metadata_sha256: roster.metadata_sha256,
    stats_json_sha256: roster.stats_json_sha256,
    events,
  };
}

module.exports = {
  SHIELDING_PARAMS_ROSTER_KEY_PAIR_821_PROFILE,
  associateShieldingParamsRosterKeys821,
};

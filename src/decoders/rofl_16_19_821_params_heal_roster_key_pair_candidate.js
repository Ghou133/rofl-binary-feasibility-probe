'use strict';

const { replaySourceError } = require('./replay_source_integrity');
const { PARAMS_HEAL_PACKET_CANDIDATE_PROFILE_821: HEAL_PROFILE } =
  require('./rofl_16_19_821_params_heal_packet_candidate');
const { HERO_ROSTER_METADATA_BRIDGE_821_PROFILE: ROSTER_PROFILE } =
  require('./rofl_16_19_821_roster_metadata_bridge_candidate');

const BUILD = '16.19.821.7343';
const FIRST_HERO_PARAM = 0x400000ae;
const HEAL_EVIDENCE_STATUS = 'CANDIDATE_EXACT_RUNTIME_PARAMS_HEAL_REPORT';
const EVIDENCE_STATUS = 'CANDIDATE_821_PARAMS_HEAL_FIELDS_TO_ROSTER_KEYS';
const ASSOCIATION_STATUS = 'CANDIDATE_FULL_U32_ROSTER_KEY_EQUALITY';
const MAX_REPORT_ROWS = 20_000;

const PARAMS_HEAL_ROSTER_KEY_PAIR_821_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-params-heal-roster-key-pair-candidate-v1',
  replay_version: BUILD,
  capability: 'params_heal_roster_key_pair',
  status: 'CANDIDATE',
  evidence_status: EVIDENCE_STATUS,
  enabled: true,
  depends_on: Object.freeze(['params_heal_packet',
    'hero_roster_metadata_bridge']),
  packet_ids: Object.freeze([0x040a, 0x0089]),
  evidence_runtime_image_sha256: HEAL_PROFILE.evidence_runtime_image_sha256,
  runtime_image_required: true,
  evidence_scope: '11 exact-build KR Replays contain 70698 native ParamsHeal reports; full-u32 +0x04 matches 62517 ten-key HeroStats roster entries and +0x14 matches 62550, with 33 +0x14-only matches and 8148 reports matching neither',
  known_limits: Object.freeze([
    'Child +0x04 and +0x14 are matched independently by full u32 equality to the same-Replay ten-key HeroStats roster; unmatched and asymmetric reports remain visible.',
    'Neither field has an assigned healer, caster, recipient, target, or packet-actor role.',
    'The reported amount is a packet field; effective healing and observed health change are unknown.',
    'Champion, team and role labels come from Replay metadata; the roster key association remains a candidate.',
    'Complete exact-build native ParamsHeal and ten-key roster source outcomes require the pinned runtime image.',
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

function validHealRow(replay, row) {
  const ref = row?.raw_packet_ref;
  return row?.event_type === 'PARAMS_HEAL_PACKET_CANDIDATE'
    && row.game_version === BUILD && row.patch === '16.19'
    && row.build_profile === HEAL_PROFILE.id
    && row.replay_sha256 === replay.source_sha256
    && row.replay_time_ms === ref?.replay_time_ms
    && row.raw_param === ref?.raw_param
    && row.event_id === 0x004b && row.raw_event_id_hex === '0x4958'
    && typeof row.reported_amount_candidate === 'number'
    && Number.isFinite(row.reported_amount_candidate)
    && u32(row.event_entity_u32_0x04) && u32(row.event_entity_u32_0x14)
    && sha(row.event_blob_sha256)
    && row.confidence === 'CANDIDATE'
    && row.semantic_status === HEAL_EVIDENCE_STATUS
    && validRef(replay, ref, 0x040a, 'game_chunk', 60);
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

function associateParamsHealRosterKeys821(replay, {
  paramsHealPacketOutcome, heroRosterMetadataBridgeOutcome,
} = {}) {
  const profile = PARAMS_HEAL_ROSTER_KEY_PAIR_821_PROFILE;
  const dependencyStatuses = {
    params_heal_packet: paramsHealPacketOutcome?.status ?? 'UNEXECUTED',
    hero_roster_metadata_bridge:
      heroRosterMetadataBridgeOutcome?.status ?? 'UNEXECUTED',
  };
  const base = {
    profile_id: profile.id,
    input_packet_id: 0x040a,
    child_event_id: 0x004b,
    evidence_status: EVIDENCE_STATUS,
    evidence_runtime_image_sha256: profile.evidence_runtime_image_sha256,
    dependency_statuses: dependencyStatuses,
    runtime_image_status: paramsHealPacketOutcome?.runtime_image_status ?? 'NOT_CHECKED',
    runtime_image_used: paramsHealPacketOutcome?.runtime_image_used ?? false,
    known_limits: [...profile.known_limits],
  };
  const fail = (status, error, extra = {}) => ({
    ...base, status, input_count: null, event_count: null, events: null,
    error, ...extra,
  });
  if (replay?.header?.version !== BUILD) {
    return fail('UNSUPPORTED', `params_heal_roster_key_pair requires ${BUILD}`);
  }
  const sourceError = replaySourceError(replay);
  if (sourceError) return fail('DECODE_FAILED', `Replay source failed: ${sourceError}`);
  for (const [name, status] of Object.entries(dependencyStatuses)) {
    if (status !== 'CANDIDATE') {
      return fail(status === 'UNEXECUTED' ? 'MISSING_INPUT' : status,
        `params_heal_roster_key_pair requires ${name}: ${status}`);
    }
  }
  const heal = paramsHealPacketOutcome;
  const roster = heroRosterMetadataBridgeOutcome;
  if (heal.profile_id !== HEAL_PROFILE.id
      || heal.evidence_status !== HEAL_EVIDENCE_STATUS
      || heal.input_packet_id !== 0x040a || heal.child_event_id !== 0x004b
      || !nonnegative(heal.input_count) || heal.input_count === 0
      || heal.input_count > MAX_REPORT_ROWS
      || heal.input_count !== heal.event_count
      || !Array.isArray(heal.events) || heal.events.length !== heal.event_count
      || heal.runtime_image_status !== 'MATCHED_USED'
      || heal.runtime_image_used !== true
      || heal.runtime_image_sha256 !== profile.evidence_runtime_image_sha256
      || roster.profile_id !== ROSTER_PROFILE.id
      || roster.evidence_status !== ROSTER_PROFILE.evidence_status
      || roster.input_packet_id !== 0x0089
      || roster.event_count !== 10 || roster.unique_kda_match_count !== 10
      || roster.metadata_player_count !== 10
      || !Array.isArray(roster.events) || roster.events.length !== 10
      || !sha(roster.metadata_sha256) || !sha(roster.stats_json_sha256)) {
    return fail('DECODE_FAILED', 'Incomplete exact-build ParamsHeal or roster dependency outcome');
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
  let matched04Count = 0;
  let matched14Count = 0;
  let bothMatchedCount = 0;
  let bothNonrosterCount = 0;
  let only04Count = 0;
  let only14Count = 0;
  let unequalFieldsCount = 0;
  let plus100Alias04Count = 0;
  let plus100Alias14Count = 0;
  let zero04Count = 0;
  let zero14Count = 0;
  for (const [index, healRow] of heal.events.entries()) {
    if (!validHealRow(replay, healRow)) {
      return fail('DECODE_FAILED', `Malformed 0x040a ParamsHeal row ${index}`, {
        first_failed_packet_ref: healRow?.raw_packet_ref ?? null,
      });
    }
    const key04 = healRow.event_entity_u32_0x04;
    const key14 = healRow.event_entity_u32_0x14;
    const match04 = rosterMatch(key04, rosterByKey);
    const match14 = rosterMatch(key14, rosterByKey);
    const has04 = match04.status === ASSOCIATION_STATUS;
    const has14 = match14.status === ASSOCIATION_STATUS;
    if (has04) matched04Count += 1;
    if (has14) matched14Count += 1;
    if (has04 && has14) bothMatchedCount += 1;
    else if (!has04 && !has14) bothNonrosterCount += 1;
    else if (has04) only04Count += 1;
    else only14Count += 1;
    if (key04 !== key14) unequalFieldsCount += 1;
    if (!has04 && rosterByKey.has(key04 - 0x100)) plus100Alias04Count += 1;
    if (!has14 && rosterByKey.has(key14 - 0x100)) plus100Alias14Count += 1;
    if (key04 === 0) zero04Count += 1;
    if (key14 === 0) zero14Count += 1;
    events.push({
      event_type: 'PARAMS_HEAL_ROSTER_KEY_PAIR_CANDIDATE',
      game_version: BUILD, patch: '16.19', build_profile: profile.id,
      replay_sha256: replay.source_sha256,
      replay_time_ms: healRow.replay_time_ms,
      raw_param: healRow.raw_param,
      event_id: healRow.event_id,
      reported_amount_candidate: healRow.reported_amount_candidate,
      event_entity_u32_0x04: key04,
      event_entity_u32_0x14: key14,
      raw_event_id_hex: healRow.raw_event_id_hex,
      event_blob_sha256: healRow.event_blob_sha256,
      roster_match_0x04: match04,
      roster_match_0x14: match14,
      metadata_sha256: roster.metadata_sha256,
      stats_json_sha256: roster.stats_json_sha256,
      field_role_status: 'UNKNOWN',
      packet_actor_status: 'UNKNOWN',
      effective_heal_status: 'UNKNOWN',
      confidence: 'CANDIDATE', semantic_status: EVIDENCE_STATUS,
      field_confidence: {
        event_entity_u32_0x04: 'CANDIDATE_EXACT_RUNTIME_FIELD',
        event_entity_u32_0x14: 'CANDIDATE_EXACT_RUNTIME_FIELD',
        roster_match_0x04: match04.status,
        roster_match_0x14: match14.status,
        field_role_status: 'UNKNOWN', packet_actor_status: 'UNKNOWN',
        effective_heal_status: 'UNKNOWN',
      },
      raw_packet_ref: healRow.raw_packet_ref,
    });
  }
  return {
    ...base, status: 'CANDIDATE',
    input_count: heal.input_count,
    source_report_count: heal.event_count,
    event_count: events.length,
    matched_0x04_count: matched04Count,
    unmatched_0x04_count: events.length - matched04Count,
    matched_0x14_count: matched14Count,
    unmatched_0x14_count: events.length - matched14Count,
    both_matched_count: bothMatchedCount,
    both_nonroster_count: bothNonrosterCount,
    only_0x04_matched_count: only04Count,
    only_0x14_matched_count: only14Count,
    unequal_fields_count: unequalFieldsCount,
    plus_0x100_alias_excluded_0x04_count: plus100Alias04Count,
    plus_0x100_alias_excluded_0x14_count: plus100Alias14Count,
    zero_0x04_count: zero04Count,
    zero_0x14_count: zero14Count,
    runtime_image_sha256: heal.runtime_image_sha256,
    metadata_sha256: roster.metadata_sha256,
    stats_json_sha256: roster.stats_json_sha256,
    events,
  };
}

module.exports = {
  PARAMS_HEAL_ROSTER_KEY_PAIR_821_PROFILE,
  associateParamsHealRosterKeys821,
};

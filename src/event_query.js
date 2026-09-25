'use strict';

const fs = require('node:fs');
const crypto = require('node:crypto');
const path = require('node:path');
const readline = require('node:readline');
const { isDeepStrictEqual } = require('node:util');
const { CHAMPION_DIE_HERO_DEATH_PAIR_821_PROFILE } =
  require('./decoders/rofl_16_19_821_champion_die_hero_death_pair_candidate');
const { CHAMPION_KILL_DIE_HERO_DEATH_PAIR_821_PROFILE } =
  require('./decoders/rofl_16_19_821_champion_kill_die_hero_death_pair_candidate');
const { CHAMPION_MULTIPLE_KILL_DIE_HERO_DEATH_PAIR_821_PROFILE } =
  require('./decoders/rofl_16_19_821_champion_multiple_kill_die_hero_death_pair_candidate');
const { CHAMPION_DOUBLE_KILL_MULTI_GROUP_821_PROFILE } =
  require('./decoders/rofl_16_19_821_champion_double_kill_multi_group_candidate');
const { CHAMPION_TRIPLE_QUADRA_MULTI_GROUP_821_PROFILE } =
  require('./decoders/rofl_16_19_821_champion_triple_quadra_multi_group_candidate');
const { ON_SHUTDOWN_DIE_HERO_DEATH_PAIR_821_PROFILE } =
  require('./decoders/rofl_16_19_821_on_shutdown_die_hero_death_pair_candidate');
const { CHAMPION_DIE_EVENT_PACKET_821_PROFILE } =
  require('./decoders/rofl_16_19_821_champion_die_event_packet_candidate');
const { CHAMPION_KILL_EVENT_PACKET_CANDIDATE_PROFILE_821 } =
  require('./decoders/rofl_16_19_821_champion_kill_event_packet_candidate');
const { CHAMPION_MULTIPLE_KILL_EVENT_PACKET_821_PROFILE } =
  require('./decoders/rofl_16_19_821_champion_multiple_kill_event_packet_candidate');
const { CHAMPION_DOUBLE_KILL_EVENT_PACKET_821_PROFILE } =
  require('./decoders/rofl_16_19_821_champion_double_kill_event_packet_candidate');
const { CHAMPION_TRIPLE_QUADRA_EVENT_PACKET_821_PROFILE } =
  require('./decoders/rofl_16_19_821_champion_triple_quadra_event_packet_candidate');
const { ON_SHUTDOWN_EVENT_PACKET_821_PROFILE } =
  require('./decoders/rofl_16_19_821_on_shutdown_event_packet_candidate');
const { HERO_DEATH_CANDIDATE_PROFILE_821 } =
  require('./decoders/rofl_16_19_821_7343');
const { HERO_ASSIST_CANDIDATE_PROFILE_821 } =
  require('./decoders/rofl_16_19_821_assist_candidate');
const { HERO_DEATH_TIMER_CANDIDATE_PROFILE_821 } =
  require('./decoders/rofl_16_19_821_death_timer_candidate');
const { HERO_RESPAWN_CANDIDATE_PROFILE_821 } =
  require('./decoders/rofl_16_19_821_respawn_candidate');
const { HERO_DEATH_EPISODE_821_PROFILE } =
  require('./decoders/rofl_16_19_821_hero_death_episode_candidate');
const { WARD_INVENTORY_KEYFRAME_PAIR_821_PROFILE } =
  require('./decoders/rofl_16_19_821_ward_inventory_keyframe_pair_candidate');
const { INVENTORY_KEYFRAME_INTERVAL_DIFFERENCE_821_PROFILE } =
  require('./decoders/rofl_16_19_821_inventory_keyframe_interval_difference_candidate');
const { INCREMENT_MINION_KEYFRAME_BRACKET_821_PROFILE } =
  require('./decoders/rofl_16_19_821_increment_minion_keyframe_bracket_candidate');
const { FACE_DIRECTION_KEYFRAME_ROSTER_PAIR_821_PROFILE } =
  require('./decoders/rofl_16_19_821_face_direction_keyframe_roster_pair_candidate');
const { FACE_DIRECTION_PACKET_CANDIDATE_PROFILE_821,
  transformFaceDirectionVectorBytes821 } =
  require('./decoders/rofl_16_19_821_face_direction_packet_candidate');
const { PROFILES: FLOAT_STATS_821_PROFILES } =
  require('./decoders/rofl_16_19_821_float_stats_candidate');
const { HERO_WARD_STATS_SNAPSHOT_821_CANDIDATE_PROFILE } =
  require('./decoders/rofl_16_19_821_aux_counts_candidate');
const { HERO_INVENTORY_BROADCAST_PACKET_CANDIDATE_PROFILE_821 } =
  require('./decoders/rofl_16_19_821_inventory_broadcast_packet_candidate');
const { LOOKUP_TABLE_SHA256, decodeRuntimeCountByte } =
  require('./decoders/rofl_16_19_821_runtime_bytes');
const { REVIVE_ALLY_EVENT_PACKET_821_PROFILE } =
  require('./decoders/rofl_16_19_821_revive_ally_packet_candidate');
const { TURRET_FIRST_BLOOD_DIE_PAIR_821_PROFILE } =
  require('./decoders/rofl_16_19_821_turret_first_blood_die_pair_candidate');
const { TURRET_FIRST_BLOOD_EVENT_PACKET_821_PROFILE } =
  require('./decoders/rofl_16_19_821_turret_first_blood_event_packet_candidate');
const { TURRET_DIE_EVENT_PACKET_821_PROFILE } =
  require('./decoders/rofl_16_19_821_turret_die_event_packet_candidate');
const { DAMPENER_DIE_EVENT_PACKET_821_PROFILE } =
  require('./decoders/rofl_16_19_821_dampener_die_event_packet_candidate');
const { INCREMENT_MINION_KILLS_PACKET_CANDIDATE_PROFILE_821,
  isObservedIncrementMinionKillsPayloadHex,
  lookupIncrementMinionKillsKeyFromNativeBytes } =
  require('./decoders/rofl_16_19_821_increment_minion_kills_packet_candidate');

const EVENT_KEY = /^[a-z][a-z0-9_]*_candidates$/;
const REPLAY_SHA = /^[a-f0-9]{64}$/;
const MAX_MINION_BRACKET_SOURCE_ROWS_821 = 10_000;
const INVENTORY_INTERVAL_ROW_FIELDS_821 = new Set([
  'event_type', 'game_version', 'patch', 'build_profile', 'replay_sha256',
  'replay_time_ms', 'previous_observation_time_ms', 'current_observation_time_ms',
  'observation_interval_ms', 'previous_keyframe_chunk_index',
  'current_keyframe_chunk_index', 'hero_raw_param', 'participant_id_candidate',
  'observation_kind', 'observation_scope', 'change_time_status',
  'changed_slot_count', 'changed_slots_candidate', 'confidence', 'semantic_status',
  'field_confidence', 'raw_packet_ref', 'previous_raw_packet_ref',
  'current_raw_packet_ref', 'raw_packet_refs',
]);
const INCREMENT_MINION_KILLS_ROW_FIELDS_821 = new Set([
  'event_type', 'game_version', 'patch', 'build_profile', 'replay_sha256',
  'replay_time_ms', 'raw_param', 'raw_payload_hex', 'raw_selector_byte',
  'native_object_lookup_key_bytes_hex', 'callback_lookup_key_candidate',
  'callback_lookup_key_matches_raw_param', 'conditional_counter_write_status',
  'semantic_cs_effect_status', 'confidence', 'semantic_status', 'raw_packet_ref',
]);
const MINION_BRACKET_ROW_FIELDS_821 = new Set([
  'event_type', 'game_version', 'patch', 'build_profile', 'replay_sha256',
  'replay_time_ms', 'raw_param', 'callback_lookup_key_candidate',
  'participant_id_candidate', 'previous_observation_time_ms',
  'current_observation_time_ms', 'observation_interval_ms',
  'packet_offset_from_previous_ms', 'packet_offset_to_current_ms',
  'previous_snapshot_minions_killed_candidate',
  'current_snapshot_minions_killed_candidate', 'observed_endpoint_delta_candidate',
  'observation_kind', 'live_lookup_status', 'semantic_cs_effect_status',
  'confidence', 'semantic_status', 'field_confidence', 'raw_packet_ref',
  'increment_minion_kills_raw_packet_ref', 'previous_snapshot_raw_packet_ref',
  'current_snapshot_raw_packet_ref', 'raw_packet_refs',
]);
const FACE_DIRECTION_ROSTER_PAIR_ROW_FIELDS_821 = new Set([
  'event_type', 'game_version', 'patch', 'build_profile', 'replay_sha256',
  'replay_time_ms', 'keyframe_chunk_index', 'hero_raw_param',
  'hero_stats_participant_id_candidate', 'face_raw_payload_hex',
  'face_raw_selector_byte', 'packet_vector_xyz_f32_candidate', 'pair_basis',
  'actor_assignment_status', 'semantic_direction_effect_status',
  'confidence', 'semantic_status', 'hero_stats_raw_packet_ref',
  'face_direction_raw_packet_ref', 'raw_packet_refs',
]);
const SUBJECT_PARTICIPANT_FIELDS = [
  'participant_id_candidate', 'participant_id',
  'victim_participant_id_candidate', 'victim_participant_id',
  'owner_participant_id_candidate', 'owner_participant_id',
  'target_participant_id',
];
const LATEST_PARTICIPANT_EVENTS_821 = new Set([
  'hero_inventory_packet_candidates',
  'hero_inventory_broadcast_packet_candidates',
  'hero_inventory_set_item_packet_candidates',
  'hero_level_state_candidates',
  'hero_experience_snapshot_candidates',
  'hero_damage_totals_snapshot_candidates',
  'hero_damage_taken_from_champions_snapshot_candidates',
  'hero_damage_self_mitigated_snapshot_candidates',
  'hero_death_episode_candidates',
  'ward_inventory_keyframe_pair_candidates',
  'inventory_keyframe_interval_difference_candidates',
]);
const OPAQUE_U32_FIELDS_821 = Object.freeze({
  npc_buff_add_packet_candidates: Object.freeze(['opaque_u32_0x10']),
  npc_buff_remove_packet_candidates: Object.freeze(['opaque_u32_0x10']),
  npc_buff_update_num_counter_packet_candidates:
    Object.freeze(['opaque_u32_0x14', 'opaque_u32_0x1c']),
  npc_buff_update_count_packet_candidates: Object.freeze(['opaque_u32_0x14']),
  npc_buff_replace_packet_candidates: Object.freeze(['opaque_u32_0x18']),
  set_spell_timer_from_buff_packet_candidates:
    Object.freeze(['opaque_u32_0x18', 'opaque_u32_0x1c']),
  set_spell_level_packet_candidates:
    Object.freeze(['opaque_u32_0x10', 'opaque_u32_0x14']),
  params_heal_packet_candidates: Object.freeze([
    'event_entity_u32_0x04', 'event_entity_u32_0x14',
  ]),
  shielding_params_packet_pair_candidates: Object.freeze([
    'event_u32_0x08', 'event_u32_0x0c',
  ]),
  stealth_event_packet_candidates: Object.freeze(['event_u32_0x04']),
  champion_die_event_packet_candidates: Object.freeze(['event_u32_0x04']),
  champion_kill_event_packet_candidates: Object.freeze([
    'event_u32_0x04', 'event_u32_0x58', 'event_u32_0x5c',
  ]),
  champion_multiple_kill_event_packet_candidates: Object.freeze([
    'event_u32_0x04', 'event_u32_0x08', 'event_u32_0x0c',
  ]),
  on_shutdown_event_packet_candidates: Object.freeze([
    'event_u32_0x04', 'event_u32_0x58', 'event_u32_0x5c',
  ]),
  resurrect_event_packet_candidates: Object.freeze([
    'event_u32_0x04', 'event_u32_0x08',
  ]),
  revive_ally_event_packet_candidates: Object.freeze(['event_u32_0x04']),
  turret_plate_event_packet_candidates: Object.freeze([
    'event_u32_0x04',
  ]),
  champion_die_hero_death_pair_candidates: Object.freeze([
    'on_champion_die_event_u32_0x04',
  ]),
  champion_kill_die_hero_death_pair_candidates: Object.freeze([
    'on_champion_kill_event_u32_0x04', 'on_champion_die_event_u32_0x04',
  ]),
  champion_multiple_kill_die_hero_death_pair_candidates: Object.freeze([
    'on_champion_multiple_kill_event_u32_0x04', 'on_champion_die_event_u32_0x04',
  ]),
  champion_double_kill_multi_group_candidates: Object.freeze([
    'on_champion_multiple_kill_opaque_u32_0x08',
  ]),
  champion_triple_quadra_multi_group_candidates: Object.freeze([
    'on_champion_multiple_kill_opaque_u32_0x08',
  ]),
  on_shutdown_die_hero_death_pair_candidates: Object.freeze([
    'on_shutdown_event_u32_0x04', 'on_shutdown_event_u32_0x58',
    'on_shutdown_event_u32_0x5c', 'on_champion_die_event_u32_0x04',
  ]),
});
const OPAQUE_PAIR_FIELDS_821 = Object.freeze({
  npc_buff_add_packet_candidates: Object.freeze(['opaque_u32_0x10', 'opaque_u8_0x14']),
  npc_buff_remove_packet_candidates: Object.freeze(['opaque_u32_0x10', 'opaque_u8_0x14']),
  npc_buff_update_num_counter_packet_candidates:
    Object.freeze(['opaque_u32_0x14', 'opaque_u8_0x18']),
});
const ASSOCIATION_EVENTS_821 = Object.freeze({
  increment_minion_keyframe_bracket_candidates: Object.freeze({
    profile: INCREMENT_MINION_KEYFRAME_BRACKET_821_PROFILE,
    eventType: 'INCREMENT_MINION_KEYFRAME_BRACKET_CANDIDATE',
    evidenceStatus: 'CANDIDATE_821_PACKET_KEY_AND_ADJACENT_MINIONS_KEYFRAME_BRACKET',
    minionBracket: true,
  }),
  inventory_keyframe_interval_difference_candidates: Object.freeze({
    profile: INVENTORY_KEYFRAME_INTERVAL_DIFFERENCE_821_PROFILE,
    eventType: 'INVENTORY_KEYFRAME_INTERVAL_DIFFERENCE_CANDIDATE',
    evidenceStatus: 'CANDIDATE_821_ADJACENT_KEYFRAME_INVENTORY_SLOT_DIFFERENCE',
    inventoryInterval: true,
  }),
  ward_inventory_keyframe_pair_candidates: Object.freeze({
    profile: WARD_INVENTORY_KEYFRAME_PAIR_821_PROFILE,
    eventType: 'WARD_INVENTORY_KEYFRAME_PAIR_CANDIDATE',
    evidenceStatus: 'CANDIDATE_821_SAME_KEYFRAME_WARD_COUNT_INVENTORY_BROADCAST',
    wardPair: true,
  }),
  hero_death_episode_candidates: Object.freeze({
    profile: HERO_DEATH_EPISODE_821_PROFILE,
    eventType: 'HERO_DEATH_EPISODE_CANDIDATE',
    evidenceStatus: 'CANDIDATE_821_DEATH_ASSIST_TIMER_RETURN_ASSOCIATION',
    episode: true,
  }),
  turret_first_blood_die_pair_candidates: Object.freeze({
    profile: TURRET_FIRST_BLOOD_DIE_PAIR_821_PROFILE,
    eventType: 'TURRET_FIRST_BLOOD_DIE_PACKET_PAIR_CANDIDATE',
    evidenceStatus: 'CANDIDATE_821_TURRET_FIRST_BLOOD_DIE_PACKET_PAIR',
    turretPair: true,
  }),
  champion_die_hero_death_pair_candidates: Object.freeze({
    profile: CHAMPION_DIE_HERO_DEATH_PAIR_821_PROFILE,
    eventType: 'CHAMPION_DIE_HERO_DEATH_PACKET_PAIR_CANDIDATE',
    evidenceStatus: 'CANDIDATE_821_ON_CHAMPION_DIE_HERO_DIE_PACKET_PAIR',
    dependencyProfiles: Object.freeze({
      champion_die_event_packet: CHAMPION_DIE_EVENT_PACKET_821_PROFILE,
      hero_death: HERO_DEATH_CANDIDATE_PROFILE_821,
    }),
  }),
  champion_kill_die_hero_death_pair_candidates: Object.freeze({
    profile: CHAMPION_KILL_DIE_HERO_DEATH_PAIR_821_PROFILE,
    eventType: 'CHAMPION_KILL_DIE_HERO_DEATH_PACKET_GROUP_CANDIDATE',
    evidenceStatus: 'CANDIDATE_821_ON_CHAMPION_KILL_DIE_HERO_DIE_PACKET_GROUP',
    groupDependency: 'champion_kill_event_packet',
    groupCountField: 'on_champion_kill_count',
    groupRawParamField: 'on_champion_kill_raw_param',
    groupChildField: 'on_champion_kill_event_u32_0x04',
    groupRefField: 'on_champion_kill_raw_packet_ref',
    unmatchedField: 'unmatched_on_champion_kill_count',
    dependencyProfiles: Object.freeze({
      champion_kill_event_packet: CHAMPION_KILL_EVENT_PACKET_CANDIDATE_PROFILE_821,
      champion_die_event_packet: CHAMPION_DIE_EVENT_PACKET_821_PROFILE,
      hero_death: HERO_DEATH_CANDIDATE_PROFILE_821,
    }),
  }),
  champion_multiple_kill_die_hero_death_pair_candidates: Object.freeze({
    profile: CHAMPION_MULTIPLE_KILL_DIE_HERO_DEATH_PAIR_821_PROFILE,
    eventType: 'CHAMPION_MULTIPLE_KILL_DIE_HERO_DEATH_PACKET_GROUP_CANDIDATE',
    evidenceStatus: 'CANDIDATE_821_ON_CHAMPION_MULTIPLE_KILL_DIE_HERO_DIE_PACKET_GROUP',
    groupDependency: 'champion_multiple_kill_event_packet',
    groupCountField: 'on_champion_multiple_kill_count',
    groupRawParamField: 'on_champion_multiple_kill_raw_param',
    groupChildField: 'on_champion_multiple_kill_event_u32_0x04',
    groupRefField: 'on_champion_multiple_kill_raw_packet_ref',
    unmatchedField: 'unmatched_on_champion_multiple_kill_count',
    dependencyProfiles: Object.freeze({
      champion_multiple_kill_event_packet: CHAMPION_MULTIPLE_KILL_EVENT_PACKET_821_PROFILE,
      champion_die_event_packet: CHAMPION_DIE_EVENT_PACKET_821_PROFILE,
      hero_death: HERO_DEATH_CANDIDATE_PROFILE_821,
    }),
  }),
  champion_double_kill_multi_group_candidates: Object.freeze({
    profile: CHAMPION_DOUBLE_KILL_MULTI_GROUP_821_PROFILE,
    eventType: 'CHAMPION_DOUBLE_KILL_MULTI_DIE_HERO_DEATH_PACKET_GROUP_CANDIDATE',
    evidenceStatus: 'CANDIDATE_821_DOUBLE_KILL_NAMED_MULTI_DIE_HERO_PACKET_GROUP',
    nestedGroup: true,
  }),
  champion_triple_quadra_multi_group_candidates: Object.freeze({
    profile: CHAMPION_TRIPLE_QUADRA_MULTI_GROUP_821_PROFILE,
    eventType: 'CHAMPION_TRIPLE_QUADRA_MULTI_DIE_HERO_DEATH_PACKET_GROUP_CANDIDATE',
    evidenceStatus: 'CANDIDATE_821_TRIPLE_QUADRA_NAMED_MULTI_DIE_HERO_PACKET_GROUP',
    nestedGroup: true,
  }),
  on_shutdown_die_hero_death_pair_candidates: Object.freeze({
    profile: ON_SHUTDOWN_DIE_HERO_DEATH_PAIR_821_PROFILE,
    eventType: 'ON_SHUTDOWN_DIE_HERO_DEATH_PACKET_GROUP_CANDIDATE',
    evidenceStatus: 'CANDIDATE_821_ON_SHUTDOWN_DIE_HERO_DIE_PACKET_GROUP',
    groupDependency: 'on_shutdown_event_packet',
    groupCountField: 'on_shutdown_count',
    groupRawParamField: 'on_shutdown_raw_param',
    groupChildField: 'on_shutdown_event_u32_0x04',
    groupRefField: 'on_shutdown_raw_packet_ref',
    unmatchedField: 'unmatched_on_shutdown_count',
    dependencyProfiles: Object.freeze({
      on_shutdown_event_packet: ON_SHUTDOWN_EVENT_PACKET_821_PROFILE,
      champion_die_event_packet: CHAMPION_DIE_EVENT_PACKET_821_PROFILE,
      hero_death: HERO_DEATH_CANDIDATE_PROFILE_821,
    }),
  }),
});
const EXACT_PACKET_EVENTS_821 = Object.freeze({
  champion_double_kill_event_packet_candidates:
    CHAMPION_DOUBLE_KILL_EVENT_PACKET_821_PROFILE,
  champion_triple_quadra_event_packet_candidates:
    CHAMPION_TRIPLE_QUADRA_EVENT_PACKET_821_PROFILE,
});
const EXACT_BLOB_PACKET_EVENTS_821 = Object.freeze({
  dampener_die_event_packet_candidates: Object.freeze({
    profile: DAMPENER_DIE_EVENT_PACKET_821_PROFILE,
    eventType: 'DAMPENER_DIE_EVENT_PACKET_CANDIDATE',
    evidenceStatus: 'CANDIDATE_EXACT_RUNTIME_ON_DAMPENER_DIE_PACKET',
    rawEventIdHex: '0x4906',
  }),
});
const CHILD_EVENT_ID_FILTERS_821 = Object.freeze({
  stealth_event_packet_candidates: Object.freeze([0x0101, 0x0102]),
  champion_double_kill_event_packet_candidates: Object.freeze([0x000b]),
  champion_double_kill_multi_group_candidates: Object.freeze([0x000b]),
  champion_triple_quadra_event_packet_candidates: Object.freeze([0x000c, 0x000d]),
  champion_triple_quadra_multi_group_candidates: Object.freeze([0x000c, 0x000d]),
});
const KILLER_PARTICIPANT_EVENTS_821 = Object.freeze({
  hero_death_candidates: Object.freeze({
    profile: HERO_DEATH_CANDIDATE_PROFILE_821,
    evidenceStatus: 'CANDIDATE_821_REPLAY_TAIL_ROUTE_FINGERPRINT',
    eventType: 'death', victimField: 'victim_participant_id',
  }),
  hero_assist_candidates: Object.freeze({
    profile: HERO_ASSIST_CANDIDATE_PROFILE_821,
    evidenceStatus: 'CANDIDATE_821_CO_TIMED_ASSIST_PAIR_TAIL_ALIGNMENT',
    eventType: 'HERO_ASSIST_ATTRIBUTION_CANDIDATE',
    victimField: 'victim_participant_id_candidate',
  }),
  hero_death_episode_candidates: Object.freeze({
    profile: HERO_DEATH_EPISODE_821_PROFILE,
    evidenceStatus: 'CANDIDATE_821_DEATH_ASSIST_TIMER_RETURN_ASSOCIATION',
    eventType: 'HERO_DEATH_EPISODE_CANDIDATE',
    victimField: 'victim_participant_id_candidate',
  }),
});

class EventQueryError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = 'EventQueryError';
    this.code = code;
    this.details = details;
  }
}

function readArtifactJson(directory, basename) {
  const filename = path.join(directory, basename);
  let stat;
  try {
    stat = fs.lstatSync(filename);
  } catch (error) {
    if (error.code === 'ENOENT') {
      throw new EventQueryError('MISSING_METADATA', `Missing ${basename} in Replay artifact directory.`,
        { filename });
    }
    throw error;
  }
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new EventQueryError('UNSAFE_ARTIFACT', `${basename} must be a regular file.`,
      { filename });
  }
  try {
    const document = JSON.parse(fs.readFileSync(filename, 'utf8'));
    if (document === null || typeof document !== 'object' || Array.isArray(document)) {
      throw new Error('top-level value must be an object');
    }
    return document;
  } catch (error) {
    throw new EventQueryError('INVALID_METADATA', `Cannot parse ${basename}: ${error.message}`,
      { filename });
  }
}

function sha256File(filename) {
  const digest = crypto.createHash('sha256');
  const handle = fs.openSync(filename, 'r');
  const chunk = Buffer.allocUnsafe(1024 * 1024);
  try {
    for (;;) {
      const bytes = fs.readSync(handle, chunk, 0, chunk.length, null);
      if (bytes === 0) break;
      digest.update(chunk.subarray(0, bytes));
    }
  } finally {
    fs.closeSync(handle);
  }
  return digest.digest('hex');
}

function isCount(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function prepareExactPacketEvent(semantic, analysis, eventKey, result, profile) {
  if (semantic.replay_version !== profile.replay_version) {
    throw new EventQueryError('UNSUPPORTED_EVENT_BUILD',
      `${eventKey} requires exact build ${profile.replay_version}.`,
      { replay_version: semantic.replay_version,
        required_replay_version: profile.replay_version });
  }
  if (result?.status !== 'CANDIDATE') return;
  const imageSha = profile.evidence_runtime_image_sha256;
  if (result.profile_id !== profile.id
      || result.evidence_runtime_image_sha256 !== imageSha
      || result.runtime_image_sha256 !== imageSha
      || result.runtime_image_status !== 'MATCHED_USED'
      || result.runtime_image_used !== true
      || result.evidence_status !== 'CANDIDATE_EXACT_RUNTIME_NAMED_ON_EVENT_CHILD'
      || result.input_packet_id !== 0x040a
      || (profile.child_event_ids
        ? !isDeepStrictEqual(result.child_event_ids, [...profile.child_event_ids])
        : result.child_event_id !== profile.child_event_id)
      || !isCount(result.event_count) || result.event_count === 0
      || result.target_packet_count !== result.event_count
      || !isCount(result.excluded_child_count)
      || result.input_count !== result.event_count + result.excluded_child_count
      || analysis.event_counts?.[eventKey] !== result.event_count) {
    throw new EventQueryError('CAPABILITY_METADATA_MISMATCH',
      `${profile.capability} identity or candidate counts differ from its exact-build profile.`,
      { capability: profile.capability });
  }
}

function prepareExactBlobPacketEvent(semantic, analysis, eventKey, result,
  { profile, evidenceStatus }) {
  if (semantic.replay_version !== profile.replay_version) {
    throw new EventQueryError('UNSUPPORTED_EVENT_BUILD',
      `${eventKey} requires exact build ${profile.replay_version}.`,
      { replay_version: semantic.replay_version,
        required_replay_version: profile.replay_version });
  }
  if (result?.status !== 'CANDIDATE') return;
  const imageSha = profile.evidence_runtime_image_sha256;
  if (result.profile_id !== profile.id
      || result.evidence_runtime_image_sha256 !== imageSha
      || result.runtime_image_sha256 !== imageSha
      || result.runtime_image_status !== 'MATCHED_USED'
      || result.runtime_image_used !== true
      || result.evidence_status !== evidenceStatus
      || result.input_packet_id !== profile.replay_block_packet_id
      || result.input_packet_scope !== 'child_0035_length_116'
      || result.child_event_id !== profile.child_event_id
      || !isCount(result.event_count) || result.event_count === 0
      || result.input_count !== result.event_count
      || !isCount(result.excluded_same_length_foreign_count)
      || result.observed_same_length_packet_count
        !== result.event_count + result.excluded_same_length_foreign_count
      || !Array.isArray(result.excluded_same_length_foreign_packet_refs)
      || result.excluded_same_length_foreign_packet_refs.length
        !== result.excluded_same_length_foreign_count
      || analysis.event_counts?.[eventKey] !== result.event_count) {
    throw new EventQueryError('CAPABILITY_METADATA_MISMATCH',
      `${profile.capability} identity or candidate counts differ from its exact-build profile.`,
      { capability: profile.capability });
  }
}

function prepareIncrementMinionKillsPacketEvent(semantic, analysis, eventKey, result) {
  const profile = INCREMENT_MINION_KILLS_PACKET_CANDIDATE_PROFILE_821;
  if (semantic.replay_version !== profile.replay_version) {
    throw new EventQueryError('UNSUPPORTED_EVENT_BUILD',
      `${eventKey} requires exact build ${profile.replay_version}.`,
      { replay_version: semantic.replay_version,
        required_replay_version: profile.replay_version });
  }
  if (result?.status !== 'CANDIDATE') return;
  const fieldConfidence = {
    replay_time_ms: 'VERIFIED_DIRECT', raw_param: 'VERIFIED_DIRECT',
    raw_payload_hex: 'VERIFIED_DIRECT', raw_selector_byte: 'VERIFIED_DIRECT',
    native_object_lookup_key_bytes_hex: 'CANDIDATE_EXACT_RUNTIME_FIELD',
    callback_lookup_key_candidate: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_TRANSFORM',
  };
  if (result.profile_id !== profile.id
      || result.evidence_runtime_image_sha256
        !== profile.evidence_runtime_image_sha256
      || result.evidence_callback_transform_sha256
        !== profile.evidence_callback_transform_sha256
      || result.runtime_image_sha256 !== profile.evidence_runtime_image_sha256
      || result.runtime_image_status !== 'MATCHED_USED'
      || result.runtime_image_used !== true
      || result.evidence_status !== 'CANDIDATE_EXACT_RUNTIME_CALLBACK_LOOKUP_KEY'
      || result.input_packet_id !== profile.replay_block_packet_id
      || !isCount(result.event_count) || result.event_count === 0
      || result.input_count !== result.event_count
      || !isCount(result.scanned_block_count)
      || result.scanned_block_count < result.event_count
      || !isDeepStrictEqual(result.event_field_confidence, fieldConfidence)
      || !isDeepStrictEqual(result.known_limits, [...profile.known_limits])
      || analysis.event_counts?.[eventKey] !== result.event_count
      || !isDeepStrictEqual(
        analysis.semantic?.capability_results?.[profile.capability], result)) {
    throw new EventQueryError('CAPABILITY_METADATA_MISMATCH',
      `${profile.capability} identity or counts differ from its exact-build profile.`,
      { capability: profile.capability });
  }
}

function prepareFaceDirectionRosterPairEvent(semantic, analysis, eventKey, result) {
  const profile = FACE_DIRECTION_KEYFRAME_ROSTER_PAIR_821_PROFILE;
  if (semantic.replay_version !== profile.replay_version) {
    throw new EventQueryError('UNSUPPORTED_EVENT_BUILD',
      `${eventKey} requires exact build ${profile.replay_version}.`,
      { replay_version: semantic.replay_version,
        required_replay_version: profile.replay_version });
  }
  if (result?.status !== 'CANDIDATE') return;
  const imageSha = profile.evidence_runtime_image_sha256;
  const face = semantic.capability_results?.face_direction_packet;
  const snapshot = semantic.capability_results?.hero_minions_killed_snapshot;
  const excluded = result.first_excluded_face_packet_refs;
  const validExcludedRef = (ref, stream) => ref && typeof ref === 'object'
    && !Array.isArray(ref) && ref.replay_sha256 === semantic.replay_sha256
    && ref.chunk_stream === stream && ref.packet_id === 0x038e
    && Number.isSafeInteger(ref.chunk_index) && ref.chunk_index >= 0
    && Number.isSafeInteger(ref.decompressed_block_offset)
    && ref.decompressed_block_offset >= 0
    && Number.isSafeInteger(ref.raw_param)
    && ref.raw_param >= 0 && ref.raw_param <= 0xffffffff
    && REPLAY_SHA.test(ref.raw_payload_sha256);
  if (result.profile_id !== profile.id
      || result.evidence_status !== profile.evidence_status
      || result.evidence_runtime_image_sha256 !== imageSha
      || result.replay_sha256 !== semantic.replay_sha256
      || result.runtime_image_sha256 !== imageSha
      || result.runtime_image_status !== 'MATCHED_USED'
      || result.runtime_image_used !== true
      || !isDeepStrictEqual(result.depends_on, [...profile.depends_on])
      || !isDeepStrictEqual(result.known_limits, [...profile.known_limits])
      || !isDeepStrictEqual(result.dependency_statuses, {
        face_direction_packet: 'CANDIDATE',
        hero_minions_killed_snapshot: 'CANDIDATE',
      })
      || !isCount(result.face_packet_count)
      || !isCount(result.snapshot_count)
      || !isCount(result.keyframe_count) || result.keyframe_count === 0
      || result.snapshot_count !== 10 * result.keyframe_count
      || result.paired_packet_count !== result.snapshot_count
      || result.event_count !== result.paired_packet_count
      || !isCount(result.excluded_game_packet_count)
      || !isCount(result.excluded_noncanonical_keyframe_packet_count)
      || result.face_packet_count !== result.paired_packet_count
        + result.excluded_game_packet_count
        + result.excluded_noncanonical_keyframe_packet_count
      || result.verified_raw_packet_count
        !== result.face_packet_count + result.snapshot_count
      || result.input_count !== result.verified_raw_packet_count
      || !excluded || typeof excluded !== 'object'
      || (result.excluded_game_packet_count === 0)
        !== (excluded.game === null)
      || (result.excluded_noncanonical_keyframe_packet_count === 0)
        !== (excluded.noncanonical_keyframe === null)
      || (result.excluded_game_packet_count > 0
        && !validExcludedRef(excluded.game, 'game_chunk'))
      || (result.excluded_noncanonical_keyframe_packet_count > 0
        && (!validExcludedRef(excluded.noncanonical_keyframe, 'keyframe')
          || (excluded.noncanonical_keyframe.raw_param >= 0x400000ae
            && excluded.noncanonical_keyframe.raw_param <= 0x400000b7)))
      || analysis.event_counts?.[eventKey] !== result.event_count
      || !isDeepStrictEqual(analysis.semantic?.capability_results?.[profile.capability], result)
      || (face && (face.status !== 'CANDIDATE'
        || face.profile_id !== FACE_DIRECTION_PACKET_CANDIDATE_PROFILE_821.id
        || face.event_count !== result.face_packet_count))
      || (snapshot && (snapshot.status !== 'CANDIDATE'
        || snapshot.profile_id !== FLOAT_STATS_821_PROFILES.hero_minions_killed_snapshot.id
        || snapshot.event_count !== result.snapshot_count))) {
    throw new EventQueryError('CAPABILITY_METADATA_MISMATCH',
      `${profile.capability} identity, image, dependency or counts differ.`,
      { capability: profile.capability });
  }
}

function prepareTurretPairAssociation(semantic, analysis, eventKey,
  { profile, evidenceStatus }) {
  if (semantic.replay_version !== profile.replay_version) {
    throw new EventQueryError('UNSUPPORTED_EVENT_BUILD',
      `${eventKey} requires exact build ${profile.replay_version}.`,
      { replay_version: semantic.replay_version,
        required_replay_version: profile.replay_version });
  }
  const association = semantic.candidate_associations?.[profile.capability];
  if (association?.status !== 'CANDIDATE') {
    throw new EventQueryError('ASSOCIATION_UNAVAILABLE',
      `${profile.capability} is not an executed candidate association.`,
      { capability: profile.capability, association_status: association?.status ?? null,
        error: association?.error ?? null, semantic_run_status: semantic.status });
  }
  const imageSha = profile.evidence_runtime_image_sha256;
  if (association.profile_id !== profile.id
      || association.evidence_runtime_image_sha256 !== imageSha
      || association.evidence_status !== evidenceStatus
      || association.replay_sha256 !== semantic.replay_sha256
      || !isDeepStrictEqual(association.depends_on, [...profile.depends_on])
      || !isCount(association.event_count) || association.event_count === 0
      || association.pair_count !== association.event_count
      || association.turret_first_blood_count !== association.event_count
      || !isCount(association.turret_die_count)
      || association.turret_die_count < association.event_count
      || association.unmatched_turret_first_blood_count !== 0
      || association.unpaired_turret_die_count
        !== association.turret_die_count - association.event_count
      || (analysis.semantic?.candidate_associations?.[profile.capability] != null
        && !isDeepStrictEqual(analysis.semantic.candidate_associations[profile.capability],
          association))) {
    throw new EventQueryError('ASSOCIATION_METADATA_MISMATCH',
      `${profile.capability} identity or candidate counts differ from its exact-build profile.`,
      { capability: profile.capability });
  }
  const dependencies = {
    turret_first_blood_event_packet: [
      TURRET_FIRST_BLOOD_EVENT_PACKET_821_PROFILE,
      association.turret_first_blood_count,
    ],
    turret_die_event_packet: [
      TURRET_DIE_EVENT_PACKET_821_PROFILE,
      association.turret_die_count,
    ],
  };
  for (const dependency of profile.depends_on) {
    if (!Array.isArray(semantic.requested_capabilities)
        || !semantic.requested_capabilities.includes(dependency)) {
      throw new EventQueryError('CAPABILITY_NOT_REQUESTED',
        `${dependency} was not requested in this Replay artifact.`,
        { capability: dependency, association: profile.capability });
    }
    const result = semantic.capability_results?.[dependency];
    if (result?.status !== 'CANDIDATE') {
      throw new EventQueryError('CAPABILITY_UNAVAILABLE',
        `${dependency} is unavailable for ${profile.capability}.`,
        { capability: dependency, capability_status: result?.status ?? null,
          association: profile.capability, missing_input: result?.missing_input ?? null,
          error: result?.error ?? null });
    }
    const [dependencyProfile, expectedCount] = dependencies[dependency];
    if (result.profile_id !== dependencyProfile.id
        || result.evidence_runtime_image_sha256 !== imageSha
        || result.runtime_image_sha256 !== imageSha
        || result.runtime_image_status !== 'MATCHED_USED'
        || result.runtime_image_used !== true
        || result.input_packet_id !== 0x040a
        || result.child_event_id !== dependencyProfile.child_event_id
        || result.input_count !== result.event_count
        || result.event_count !== expectedCount
        || analysis.event_counts?.[`${dependency}_candidates`] !== expectedCount) {
      throw new EventQueryError('ASSOCIATION_METADATA_MISMATCH',
        `${dependency} identity or count disagrees with ${profile.capability}.`,
        { capability: dependency, association: profile.capability });
    }
  }
  return association;
}

function prepareHeroDeathEpisodeAssociation(semantic, analysis, eventKey,
  { profile, evidenceStatus }) {
  if (semantic.replay_version !== profile.replay_version) {
    throw new EventQueryError('UNSUPPORTED_EVENT_BUILD',
      `${eventKey} requires exact build ${profile.replay_version}.`,
      { replay_version: semantic.replay_version,
        required_replay_version: profile.replay_version });
  }
  const association = semantic.candidate_associations?.[profile.capability];
  if (association?.status !== 'CANDIDATE') {
    throw new EventQueryError('ASSOCIATION_UNAVAILABLE',
      `${profile.capability} is not an executed candidate association.`,
      { capability: profile.capability, association_status: association?.status ?? null,
        error: association?.error ?? null, semantic_run_status: semantic.status });
  }
  const imageSha = profile.evidence_runtime_image_sha256;
  if (association.profile_id !== profile.id
      || association.evidence_runtime_image_sha256 !== imageSha
      || association.evidence_status !== evidenceStatus
      || association.replay_sha256 !== semantic.replay_sha256
      || !isDeepStrictEqual(association.depends_on, [...profile.depends_on])
      || !isCount(association.event_count) || association.event_count === 0
      || association.death_count !== association.event_count
      || association.timer_count !== association.event_count
      || !isCount(association.observed_return_count)
      || !isCount(association.terminal_unobserved_count)
      || association.observed_return_count + association.terminal_unobserved_count
        !== association.event_count
      || !isCount(association.verified_raw_packet_count)
      || association.verified_raw_packet_count < association.event_count
      || analysis.event_counts?.[eventKey] !== association.event_count
      || (analysis.semantic?.candidate_associations?.[profile.capability] != null
        && !isDeepStrictEqual(analysis.semantic.candidate_associations[profile.capability],
          association))) {
    throw new EventQueryError('ASSOCIATION_METADATA_MISMATCH',
      `${profile.capability} identity or counts differ from its exact-build profile.`,
      { capability: profile.capability });
  }
  const dependencies = {
    hero_assist: [HERO_ASSIST_CANDIDATE_PROFILE_821,
      'CANDIDATE_821_CO_TIMED_ASSIST_PAIR_TAIL_ALIGNMENT', 0x040a,
      association.death_count],
    hero_death_timer: [HERO_DEATH_TIMER_CANDIDATE_PROFILE_821,
      'CANDIDATE_821_EXACT_RUNTIME_FLOAT_AND_DEATH_CORE', 0x0259,
      association.timer_count],
    hero_respawn: [HERO_RESPAWN_CANDIDATE_PROFILE_821,
      'CANDIDATE_821_REPLAY_TAIL_DEAD_TIME_CORRELATION', 0x0048,
      association.observed_return_count],
  };
  for (const dependency of profile.depends_on) {
    if (!Array.isArray(semantic.requested_capabilities)
        || !semantic.requested_capabilities.includes(dependency)) {
      throw new EventQueryError('CAPABILITY_NOT_REQUESTED',
        `${dependency} was not requested in this Replay artifact.`,
        { capability: dependency, association: profile.capability });
    }
    const result = semantic.capability_results?.[dependency];
    if (result?.status !== 'CANDIDATE') {
      throw new EventQueryError('CAPABILITY_UNAVAILABLE',
        `${dependency} is unavailable for ${profile.capability}.`,
        { capability: dependency, capability_status: result?.status ?? null,
          association: profile.capability, missing_input: result?.missing_input ?? null,
          error: result?.error ?? null });
    }
    const [dependencyProfile, expectedEvidence, packetId, expectedCount] =
      dependencies[dependency];
    if (result.profile_id !== dependencyProfile.id
        || result.evidence_runtime_image_sha256 !== imageSha
        || result.evidence_status !== expectedEvidence
        || result.input_packet_id !== packetId
        || result.event_count !== expectedCount
        || analysis.event_counts?.[`${dependency}_candidates`] !== expectedCount
        || (dependency === 'hero_assist'
          && (result.matched_death_count !== association.death_count
            || !['NOT_CHECKED', 'MATCHED_USED'].includes(result.native_child_identity_status)
            || (result.native_child_identity_status === 'NOT_CHECKED'
              ? result.runtime_image_used !== false
                || result.runtime_image_status
                  !== 'EXACT_821_NATIVE_040A_44_FULL_CONSUME_EVIDENCE'
              : result.runtime_image_used !== true
                || result.runtime_image_status !== 'MATCHED_USED'
                || result.runtime_image_sha256 !== imageSha)))
        || (dependency === 'hero_death_timer'
          && (result.matched_death_core_count !== association.death_count
            || result.runtime_image_used !== false
            || result.runtime_image_status !== 'STATIC_EXACT_821_RUNTIME_TRANSFORM'))
        || (dependency === 'hero_respawn'
          && (result.matched_death_core_count !== association.death_count
            || result.input_count !== expectedCount
            || result.unpaired_final_death_count !== association.terminal_unobserved_count
            || !Array.isArray(result.unpaired_final_deaths)
            || result.unpaired_final_deaths.length
              !== association.terminal_unobserved_count
            || result.runtime_image_used !== false
            || result.runtime_image_status !== 'EXACT_821_ROUTE_CALLBACK_PROVEN_STATIC'))) {
      throw new EventQueryError('ASSOCIATION_METADATA_MISMATCH',
        `${dependency} identity or count disagrees with ${profile.capability}.`,
        { capability: dependency, association: profile.capability });
    }
  }
  return association;
}

function prepareInventoryKeyframeIntervalDifferenceAssociation(semantic, analysis, eventKey,
  { profile, evidenceStatus }) {
  if (semantic.replay_version !== profile.replay_version) {
    throw new EventQueryError('UNSUPPORTED_EVENT_BUILD',
      `${eventKey} requires exact build ${profile.replay_version}.`,
      { replay_version: semantic.replay_version,
        required_replay_version: profile.replay_version });
  }
  const association = semantic.candidate_associations?.[profile.capability];
  if (association?.status !== 'CANDIDATE') {
    throw new EventQueryError('ASSOCIATION_UNAVAILABLE',
      `${profile.capability} is not an executed candidate association.`,
      { capability: profile.capability, association_status: association?.status ?? null,
        error: association?.error ?? null, semantic_run_status: semantic.status });
  }
  const dependency = 'hero_inventory_broadcast_packet';
  if (!Array.isArray(semantic.requested_capabilities)
      || !semantic.requested_capabilities.includes(dependency)) {
    throw new EventQueryError('CAPABILITY_NOT_REQUESTED',
      `${dependency} was not requested in this Replay artifact.`,
      { capability: dependency, association: profile.capability });
  }
  const broadcast = semantic.capability_results?.[dependency];
  if (broadcast?.status !== 'CANDIDATE') {
    throw new EventQueryError('CAPABILITY_UNAVAILABLE',
      `${dependency} is unavailable for ${profile.capability}.`,
      { capability: dependency, capability_status: broadcast?.status ?? null,
        association: profile.capability, missing_input: broadcast?.missing_input ?? null,
        error: broadcast?.error ?? null });
  }
  const imageSha = profile.evidence_runtime_image_sha256;
  if (association.profile_id !== profile.id
      || association.evidence_runtime_image_sha256 !== imageSha
      || association.evidence_status !== evidenceStatus
      || association.replay_sha256 !== semantic.replay_sha256
      || !isDeepStrictEqual(association.depends_on, [...profile.depends_on])
      || !isDeepStrictEqual(association.known_limits, [...profile.known_limits])
      || !isCount(association.input_count)
      || !isCount(association.keyframe_count) || association.keyframe_count < 1
      || !isCount(association.broadcast_keyframe_packet_count)
      || association.broadcast_keyframe_packet_count
        !== 10 * association.keyframe_count
      || !isCount(association.excluded_game_broadcast_count)
      || association.input_count !== association.broadcast_keyframe_packet_count
        + association.excluded_game_broadcast_count
      || !isCount(association.observed_interval_count)
      || association.observed_interval_count
        !== 10 * (association.keyframe_count - 1)
      || !isCount(association.changed_interval_count)
      || !isCount(association.unchanged_interval_count)
      || association.changed_interval_count + association.unchanged_interval_count
        !== association.observed_interval_count
      || !isCount(association.changed_slot_count)
      || association.changed_slot_count < association.changed_interval_count
      || association.changed_slot_count > 10 * association.changed_interval_count
      || !isCount(association.verified_raw_packet_count)
      || association.verified_raw_packet_count !== association.input_count
      || association.event_count !== association.changed_interval_count
      || analysis.event_counts?.[eventKey] !== association.event_count
      || !isDeepStrictEqual(
        analysis.semantic?.candidate_associations?.[profile.capability], association)
      || broadcast.profile_id
        !== HERO_INVENTORY_BROADCAST_PACKET_CANDIDATE_PROFILE_821.id
      || broadcast.evidence_runtime_image_sha256 !== imageSha
      || broadcast.runtime_image_sha256 !== imageSha
      || broadcast.runtime_image_status !== 'MATCHED_USED'
      || broadcast.runtime_image_used !== true
      || broadcast.evidence_status
        !== 'CANDIDATE_EXACT_RUNTIME_BROADCAST_PACKET_FIELDS'
      || broadcast.input_packet_id !== profile.packet_id
      || broadcast.input_count !== association.input_count
      || broadcast.event_count !== association.input_count
      || !isCount(broadcast.decoded_record_count)
      || broadcast.decoded_record_count
        < association.broadcast_keyframe_packet_count * 10
          + association.excluded_game_broadcast_count * 6
      || broadcast.decoded_record_count
        > association.broadcast_keyframe_packet_count * 10
          + association.excluded_game_broadcast_count * 9
      || analysis.event_counts?.hero_inventory_broadcast_packet_candidates
        !== broadcast.event_count
      || !isDeepStrictEqual(
        analysis.semantic?.capability_results?.[dependency], broadcast)) {
    throw new EventQueryError('ASSOCIATION_METADATA_MISMATCH',
      `${profile.capability} identity, source Broadcast, or interval counts differ.`,
      { capability: profile.capability });
  }
  return association;
}

function prepareWardInventoryKeyframePairAssociation(semantic, analysis, eventKey,
  { profile, evidenceStatus }) {
  if (semantic.replay_version !== profile.replay_version) {
    throw new EventQueryError('UNSUPPORTED_EVENT_BUILD',
      `${eventKey} requires exact build ${profile.replay_version}.`,
      { replay_version: semantic.replay_version,
        required_replay_version: profile.replay_version });
  }
  const association = semantic.candidate_associations?.[profile.capability];
  if (association?.status !== 'CANDIDATE') {
    throw new EventQueryError('ASSOCIATION_UNAVAILABLE',
      `${profile.capability} is not an executed candidate association.`,
      { capability: profile.capability, association_status: association?.status ?? null,
        error: association?.error ?? null, semantic_run_status: semantic.status });
  }
  const imageSha = profile.evidence_runtime_image_sha256;
  if (association.profile_id !== profile.id
      || association.evidence_runtime_image_sha256 !== imageSha
      || association.evidence_status !== evidenceStatus
      || association.replay_sha256 !== semantic.replay_sha256
      || !isDeepStrictEqual(association.depends_on, [...profile.depends_on])
      || !isCount(association.event_count) || association.event_count === 0
      || association.event_count % 10 !== 0
      || association.ward_snapshot_count !== association.event_count
      || association.broadcast_keyframe_count !== association.event_count
      || !isCount(association.excluded_game_broadcast_count)
      || association.verified_raw_packet_count
        !== 2 * association.event_count + association.excluded_game_broadcast_count
      || analysis.event_counts?.[eventKey] !== association.event_count
      || (analysis.semantic?.candidate_associations?.[profile.capability] != null
        && !isDeepStrictEqual(analysis.semantic.candidate_associations[profile.capability],
          association))) {
    throw new EventQueryError('ASSOCIATION_METADATA_MISMATCH',
      `${profile.capability} identity or counts differ from its exact-build profile.`,
      { capability: profile.capability });
  }
  for (const dependency of profile.depends_on) {
    if (!Array.isArray(semantic.requested_capabilities)
        || !semantic.requested_capabilities.includes(dependency)) {
      throw new EventQueryError('CAPABILITY_NOT_REQUESTED',
        `${dependency} was not requested in this Replay artifact.`,
        { capability: dependency, association: profile.capability });
    }
    const result = semantic.capability_results?.[dependency];
    if (result?.status !== 'CANDIDATE') {
      throw new EventQueryError('CAPABILITY_UNAVAILABLE',
        `${dependency} is unavailable for ${profile.capability}.`,
        { capability: dependency, capability_status: result?.status ?? null,
          association: profile.capability, missing_input: result?.missing_input ?? null,
          error: result?.error ?? null });
    }
  }
  const ward = semantic.capability_results.hero_ward_stats_snapshot;
  const broadcast = semantic.capability_results.hero_inventory_broadcast_packet;
  if (ward.profile_id !== HERO_WARD_STATS_SNAPSHOT_821_CANDIDATE_PROFILE.id
      || ward.evidence_runtime_image_sha256 !== imageSha
      || ward.evidence_status !== 'CANDIDATE_821_RUNTIME_KEYFRAME_BYTE_AND_REPLAY_TAIL'
      || ward.lookup_table_sha256 !== LOOKUP_TABLE_SHA256
      || ward.input_packet_id !== 0x0089
      || ward.input_count !== association.event_count
      || ward.event_count !== association.event_count
      || ward.observed_participant_count !== 10
      || ward.runtime_image_used !== false
      || !['STATIC_821_RUNTIME_TRANSFORM_EMBEDDED', 'PROVIDED_NOT_USED']
        .includes(ward.runtime_image_status)
      || analysis.event_counts?.hero_ward_stats_snapshot_candidates
        !== association.event_count
      || broadcast.profile_id
        !== HERO_INVENTORY_BROADCAST_PACKET_CANDIDATE_PROFILE_821.id
      || broadcast.evidence_runtime_image_sha256 !== imageSha
      || broadcast.evidence_status !== 'CANDIDATE_EXACT_RUNTIME_BROADCAST_PACKET_FIELDS'
      || broadcast.input_packet_id !== 0x0357
      || broadcast.input_count !== broadcast.event_count
      || broadcast.event_count
        !== association.event_count + association.excluded_game_broadcast_count
      || !isCount(broadcast.decoded_record_count)
      || broadcast.decoded_record_count
        < 10 * association.event_count + 6 * association.excluded_game_broadcast_count
      || broadcast.decoded_record_count
        > 10 * association.event_count + 9 * association.excluded_game_broadcast_count
      || broadcast.runtime_image_used !== true
      || broadcast.runtime_image_status !== 'MATCHED_USED'
      || broadcast.runtime_image_sha256 !== imageSha
      || analysis.event_counts?.hero_inventory_broadcast_packet_candidates
        !== broadcast.event_count) {
    throw new EventQueryError('ASSOCIATION_METADATA_MISMATCH',
      `Dependency identity or counts disagree with ${profile.capability}.`,
      { capability: profile.capability });
  }
  return association;
}

function prepareMinionBracketAssociation(semantic, analysis, eventKey,
  { profile, evidenceStatus }) {
  if (semantic.replay_version !== profile.replay_version) {
    throw new EventQueryError('UNSUPPORTED_EVENT_BUILD',
      `${eventKey} requires exact build ${profile.replay_version}.`);
  }
  const association = semantic.candidate_associations?.[profile.capability];
  if (association?.status !== 'CANDIDATE') {
    throw new EventQueryError('ASSOCIATION_UNAVAILABLE',
      `${profile.capability} is not an executed candidate association.`,
      { capability: profile.capability, association_status: association?.status ?? null,
        error: association?.error ?? null, semantic_run_status: semantic.status });
  }
  const packet = semantic.capability_results?.increment_minion_kills_packet;
  const snapshot = semantic.capability_results?.hero_minions_killed_snapshot;
  for (const dependency of profile.depends_on) {
    if (!Array.isArray(semantic.requested_capabilities)
        || !semantic.requested_capabilities.includes(dependency)) {
      throw new EventQueryError('CAPABILITY_NOT_REQUESTED',
        `${dependency} was not requested in this Replay artifact.`,
        { capability: dependency, association: profile.capability });
    }
    const result = semantic.capability_results?.[dependency];
    if (result?.status !== 'CANDIDATE') {
      throw new EventQueryError('CAPABILITY_UNAVAILABLE',
        `${dependency} is unavailable for ${profile.capability}.`,
        { capability: dependency, capability_status: result?.status ?? null,
          association: profile.capability, missing_input: result?.missing_input ?? null,
          error: result?.error ?? null });
    }
  }
  const snapshotProfile = FLOAT_STATS_821_PROFILES.hero_minions_killed_snapshot;
  const imageSha = profile.evidence_runtime_image_sha256;
  if (association.profile_id !== profile.id
      || association.evidence_runtime_image_sha256 !== imageSha
      || association.evidence_status !== evidenceStatus
      || association.replay_sha256 !== semantic.replay_sha256
      || !isDeepStrictEqual(association.depends_on, [...profile.depends_on])
      || !isDeepStrictEqual(association.known_limits, [...profile.known_limits])
      || !isCount(association.packet_count) || association.packet_count === 0
      || association.packet_count > MAX_MINION_BRACKET_SOURCE_ROWS_821
      || !isCount(association.snapshot_count)
      || association.snapshot_count > MAX_MINION_BRACKET_SOURCE_ROWS_821
      || !isCount(association.keyframe_count) || association.keyframe_count === 0
      || association.keyframe_count > MAX_MINION_BRACKET_SOURCE_ROWS_821
      || association.snapshot_count !== association.keyframe_count * 10
      || association.observed_interval_count
        !== Math.max(0, association.keyframe_count - 1) * 10
      || !isCount(association.event_count)
      || association.event_count > MAX_MINION_BRACKET_SOURCE_ROWS_821
      || association.bracketed_packet_count !== association.event_count
      || !isCount(association.distinct_bracket_count)
      || association.distinct_bracket_count > MAX_MINION_BRACKET_SOURCE_ROWS_821
      || association.distinct_bracket_count > association.event_count
      || !isCount(association.unbracketed_packet_count)
      || association.unbracketed_packet_count > MAX_MINION_BRACKET_SOURCE_ROWS_821
      || !Array.isArray(association.unbracketed_packets)
      || association.unbracketed_packets.length !== association.unbracketed_packet_count
      || association.packet_count
        !== association.event_count + association.unbracketed_packet_count
      || association.verified_raw_packet_count
        !== association.packet_count + association.snapshot_count
      || analysis.event_counts?.[eventKey] !== association.event_count
      || (analysis.semantic?.candidate_associations?.[profile.capability] != null
        && !isDeepStrictEqual(
          analysis.semantic.candidate_associations[profile.capability], association))
      || packet.profile_id !== INCREMENT_MINION_KILLS_PACKET_CANDIDATE_PROFILE_821.id
      || packet.evidence_runtime_image_sha256 !== imageSha
      || packet.evidence_callback_transform_sha256
        !== INCREMENT_MINION_KILLS_PACKET_CANDIDATE_PROFILE_821
          .evidence_callback_transform_sha256
      || packet.runtime_image_sha256 !== imageSha
      || packet.runtime_image_status !== 'MATCHED_USED'
      || packet.runtime_image_used !== true
      || packet.evidence_status !== 'CANDIDATE_EXACT_RUNTIME_CALLBACK_LOOKUP_KEY'
      || packet.input_packet_id !== 0x03a7
      || packet.input_count !== association.packet_count
      || packet.event_count !== association.packet_count
      || analysis.event_counts?.increment_minion_kills_packet_candidates
        !== association.packet_count
      || snapshot.profile_id !== snapshotProfile.id
      || snapshot.evidence_runtime_image_sha256 !== imageSha
      || snapshot.evidence_status
        !== 'CANDIDATE_821_RUNTIME_BYTE_KEYFRAME_F32_AND_REPLAY_TAIL'
      || snapshot.lookup_table_sha256 !== LOOKUP_TABLE_SHA256
      || snapshot.input_packet_id !== 0x0089
      || snapshot.input_count !== association.snapshot_count
      || snapshot.event_count !== association.snapshot_count
      || snapshot.keyframe_count !== association.keyframe_count
      || snapshot.observed_participant_count !== 10
      || !isCount(snapshot.descent_count)
      || snapshot.runtime_image_used !== false
      || !['STATIC_821_RUNTIME_TRANSFORM_EMBEDDED', 'PROVIDED_NOT_USED']
        .includes(snapshot.runtime_image_status)
      || analysis.event_counts?.hero_minions_killed_snapshot_candidates
        !== association.snapshot_count
      || !isDeepStrictEqual(
        analysis.semantic?.capability_results?.increment_minion_kills_packet, packet)
      || !isDeepStrictEqual(
        analysis.semantic?.capability_results?.hero_minions_killed_snapshot, snapshot)) {
    throw new EventQueryError('ASSOCIATION_METADATA_MISMATCH',
      `${profile.capability} identity, dependencies or counts differ from exact build.`,
      { capability: profile.capability });
  }
  return association;
}

function prepareAssociation(semantic, analysis, eventKey, associationConfig) {
  if (associationConfig.minionBracket) {
    return prepareMinionBracketAssociation(semantic, analysis, eventKey,
      associationConfig);
  }
  if (associationConfig.inventoryInterval) {
    return prepareInventoryKeyframeIntervalDifferenceAssociation(semantic, analysis,
      eventKey, associationConfig);
  }
  if (associationConfig.wardPair) {
    return prepareWardInventoryKeyframePairAssociation(semantic, analysis, eventKey,
      associationConfig);
  }
  if (associationConfig.episode) {
    return prepareHeroDeathEpisodeAssociation(semantic, analysis, eventKey,
      associationConfig);
  }
  if (associationConfig.turretPair) {
    return prepareTurretPairAssociation(semantic, analysis, eventKey,
      associationConfig);
  }
  if (associationConfig.nestedGroup) {
    return prepareNamedMultiGroupAssociation(semantic, analysis, eventKey,
      associationConfig);
  }
  const { profile, evidenceStatus, dependencyProfiles } = associationConfig;
  if (semantic.replay_version !== profile.replay_version) {
    throw new EventQueryError('UNSUPPORTED_EVENT_BUILD',
      `${eventKey} requires exact build ${profile.replay_version}.`,
      { replay_version: semantic.replay_version, required_replay_version: profile.replay_version });
  }
  const association = semantic.candidate_associations?.[profile.capability];
  if (association?.status !== 'CANDIDATE') {
    throw new EventQueryError('ASSOCIATION_UNAVAILABLE',
      `${profile.capability} is not an executed candidate association.`,
      { capability: profile.capability, association_status: association?.status ?? null,
        error: association?.error ?? null, semantic_run_status: semantic.status });
  }
  if (association.profile_id !== profile.id
      || association.evidence_runtime_image_sha256 !== profile.evidence_runtime_image_sha256
      || association.evidence_status !== evidenceStatus
      || association.replay_sha256 !== semantic.replay_sha256
      || !isDeepStrictEqual(association.depends_on, [...profile.depends_on])
      || !isCount(association.event_count) || association.event_count === 0
      || association.pair_count !== association.event_count
      || (analysis.semantic?.candidate_associations?.[profile.capability] != null
        && !isDeepStrictEqual(analysis.semantic.candidate_associations[profile.capability],
          association))) {
    throw new EventQueryError('ASSOCIATION_METADATA_MISMATCH',
      `${profile.capability} identity or candidate counts differ from its exact-build profile.`,
      { capability: profile.capability });
  }
  for (const dependency of profile.depends_on) {
    if (!Array.isArray(semantic.requested_capabilities)
        || !semantic.requested_capabilities.includes(dependency)) {
      throw new EventQueryError('CAPABILITY_NOT_REQUESTED',
        `${dependency} was not requested in this Replay artifact.`,
        { capability: dependency, association: profile.capability });
    }
    const result = semantic.capability_results?.[dependency];
    if (result?.status !== 'CANDIDATE') {
      throw new EventQueryError('CAPABILITY_UNAVAILABLE',
        `${dependency} is unavailable for ${profile.capability}.`,
        { capability: dependency, capability_status: result?.status ?? null,
          association: profile.capability, missing_input: result?.missing_input ?? null,
          error: result?.error ?? null });
    }
    const associationCount = dependency === 'hero_death'
      ? association.hero_death_count
      : dependency === 'champion_die_event_packet'
        ? association.on_champion_die_count
        : association[associationConfig.groupCountField];
    if (result.profile_id !== dependencyProfiles[dependency].id
        || result.evidence_runtime_image_sha256
          !== profile.evidence_runtime_image_sha256
        || (dependency !== 'hero_death'
          && (result.runtime_image_status !== 'MATCHED_USED'
            || result.runtime_image_used !== true
            || result.runtime_image_sha256 !== profile.evidence_runtime_image_sha256))
        || !isCount(result.event_count)
        || result.event_count !== associationCount
        || analysis.event_counts?.[`${dependency}_candidates`] !== result.event_count) {
      throw new EventQueryError('ASSOCIATION_METADATA_MISMATCH',
        `${dependency} identity or count disagrees with ${profile.capability}.`,
        { capability: dependency, association: profile.capability });
    }
  }
  if (association.on_champion_die_count !== association.hero_death_count
      || (profile.capability === 'champion_die_hero_death_pair'
        && association.event_count !== association.on_champion_die_count)
      || (associationConfig.groupDependency
        && (association.event_count !== association[associationConfig.groupCountField]
          || association[associationConfig.unmatchedField] !== 0
          || association.unpaired_on_champion_die_count
            !== association.on_champion_die_count - association.event_count
          || association.unpaired_hero_death_count
            !== association.hero_death_count - association.event_count
          || semantic.candidate_associations?.champion_die_hero_death_pair?.status
            !== 'CANDIDATE'
          || semantic.candidate_associations?.champion_die_hero_death_pair?.profile_id
            !== CHAMPION_DIE_HERO_DEATH_PAIR_821_PROFILE.id
          || semantic.candidate_associations?.champion_die_hero_death_pair?.replay_sha256
            !== semantic.replay_sha256
          || semantic.candidate_associations?.champion_die_hero_death_pair?.event_count
            !== association.on_champion_die_count
          || analysis.event_counts?.champion_die_hero_death_pair_candidates
            !== association.on_champion_die_count))) {
    throw new EventQueryError('ASSOCIATION_METADATA_MISMATCH',
      `${profile.capability} dependency counts disagree with its pair count.`,
      { capability: profile.capability });
  }
  return association;
}

function prepareNamedMultiGroupAssociation(semantic, analysis, eventKey,
  associationConfig) {
  const { profile, evidenceStatus } = associationConfig;
  const tripleQuadra = profile.capability === 'champion_triple_quadra_multi_group';
  const namedCapability = tripleQuadra
    ? 'champion_triple_quadra_event_packet' : 'champion_double_kill_event_packet';
  const namedProfile = tripleQuadra
    ? CHAMPION_TRIPLE_QUADRA_EVENT_PACKET_821_PROFILE
    : CHAMPION_DOUBLE_KILL_EVENT_PACKET_821_PROFILE;
  const namedCountField = tripleQuadra
    ? 'on_champion_triple_quadra_count' : 'on_champion_double_kill_count';
  const unmatchedField = tripleQuadra
    ? 'unmatched_on_champion_triple_quadra_count'
    : 'unmatched_on_champion_double_kill_count';
  const unpairedField = tripleQuadra
    ? 'unpaired_multi_u32_0x08_3_or_4_count'
    : 'unpaired_multi_u32_0x08_2_count';
  if (semantic.replay_version !== profile.replay_version) {
    throw new EventQueryError('UNSUPPORTED_EVENT_BUILD',
      `${eventKey} requires exact build ${profile.replay_version}.`,
      { replay_version: semantic.replay_version,
        required_replay_version: profile.replay_version });
  }
  const association = semantic.candidate_associations?.[profile.capability];
  if (association?.status !== 'CANDIDATE') {
    throw new EventQueryError('ASSOCIATION_UNAVAILABLE',
      `${profile.capability} is not an executed candidate association.`,
      { capability: profile.capability, association_status: association?.status ?? null,
        error: association?.error ?? null, semantic_run_status: semantic.status });
  }
  const grouped = prepareAssociation(semantic, analysis,
    'champion_multiple_kill_die_hero_death_pair_candidates',
    ASSOCIATION_EVENTS_821.champion_multiple_kill_die_hero_death_pair_candidates);
  if (!Array.isArray(semantic.requested_capabilities)
      || !semantic.requested_capabilities.includes(namedCapability)) {
    throw new EventQueryError('CAPABILITY_NOT_REQUESTED',
      `${namedCapability} was not requested in this Replay artifact.`,
      { capability: namedCapability, association: profile.capability });
  }
  const child = semantic.capability_results?.[namedCapability];
  if (child?.status !== 'CANDIDATE') {
    throw new EventQueryError('CAPABILITY_UNAVAILABLE',
      `${namedCapability} is unavailable for ${profile.capability}.`,
      { capability: namedCapability,
        capability_status: child?.status ?? null, association: profile.capability,
        missing_input: child?.missing_input ?? null, error: child?.error ?? null });
  }
  prepareExactPacketEvent(semantic, analysis,
    `${namedCapability}_candidates`, child, namedProfile);
  const imageSha = profile.evidence_runtime_image_sha256;
  if (association.profile_id !== profile.id
      || association.evidence_runtime_image_sha256 !== imageSha
      || association.evidence_status !== evidenceStatus
      || association.replay_sha256 !== semantic.replay_sha256
      || !isDeepStrictEqual(association.depends_on, [...profile.depends_on])
      || !isCount(association.event_count) || association.event_count === 0
      || association.pair_count !== association.event_count
      || association[namedCountField] !== association.event_count
      || (tripleQuadra
        ? !isCount(association.matched_multi_u32_0x08_3_count)
          || !isCount(association.matched_multi_u32_0x08_4_count)
          || association.matched_multi_u32_0x08_3_count
            + association.matched_multi_u32_0x08_4_count !== association.event_count
        : association.matched_multi_u32_0x08_2_count !== association.event_count)
      || association[unmatchedField] !== 0
      || association[unpairedField] !== 0
      || association.on_champion_multiple_kill_group_count !== grouped.event_count
      || association.excluded_other_multi_u32_0x08_count
        !== grouped.event_count - association.event_count
      || child.profile_id !== namedProfile.id
      || child.evidence_runtime_image_sha256 !== imageSha
      || child.runtime_image_sha256 !== imageSha
      || child.runtime_image_status !== 'MATCHED_USED'
      || child.runtime_image_used !== true
      || child.event_count !== association.event_count
      || analysis.event_counts?.[`${namedCapability}_candidates`] !== child.event_count
      || (analysis.semantic?.candidate_associations?.[profile.capability] != null
        && !isDeepStrictEqual(analysis.semantic.candidate_associations[profile.capability],
          association))) {
    throw new EventQueryError('ASSOCIATION_METADATA_MISMATCH',
      `${profile.capability} identity or candidate counts differ from its exact-build dependencies.`,
      { capability: profile.capability });
  }
  return association;
}

function prepareEventQuery(directory, eventKey) {
  if (typeof eventKey !== 'string' || !EVENT_KEY.test(eventKey)) {
    throw new EventQueryError('INVALID_EVENT_KEY',
      'The event key must be an exact lowercase *_candidates name.');
  }
  const artifactDirectory = path.resolve(directory);
  const semantic = readArtifactJson(artifactDirectory, 'semantic_run.json');
  const analysis = readArtifactJson(artifactDirectory, 'replay_analysis.json');
  const replaySha = semantic.replay_sha256;
  if (!REPLAY_SHA.test(replaySha)
      || !/^16\.19\.[0-9]+\.[0-9]+$/.test(semantic.replay_version)
      || replaySha !== analysis.replay_sha256
      || semantic.replay_version !== analysis.replay_version
      || analysis.patch !== '16.19'
      || semantic.container_status !== 'PASS') {
    throw new EventQueryError('ARTIFACT_IDENTITY_MISMATCH',
      'semantic_run.json and replay_analysis.json do not identify the same framed 16.19 Replay.',
      { semantic_replay_version: semantic.replay_version,
        analysis_replay_version: analysis.replay_version,
        semantic_replay_sha256: replaySha,
        analysis_replay_sha256: analysis.replay_sha256,
        container_status: semantic.container_status });
  }
  const associationConfig = ASSOCIATION_EVENTS_821[eventKey] ?? null;
  const exactPacketProfile = EXACT_PACKET_EVENTS_821[eventKey] ?? null;
  const exactBlobPacketConfig = EXACT_BLOB_PACKET_EVENTS_821[eventKey] ?? null;
  const capability = eventKey.slice(0, -'_candidates'.length);
  const capabilityResult = associationConfig
    ? prepareAssociation(semantic, analysis, eventKey, associationConfig)
    : semantic.capability_results?.[capability];
  if (eventKey === 'revive_ally_event_packet_candidates') {
    const profile = REVIVE_ALLY_EVENT_PACKET_821_PROFILE;
    if (semantic.replay_version !== profile.replay_version) {
      throw new EventQueryError('UNSUPPORTED_EVENT_BUILD',
        `${eventKey} requires exact build ${profile.replay_version}.`);
    }
    if (capabilityResult?.status === 'CANDIDATE'
        && (capabilityResult.profile_id !== profile.id
          || capabilityResult.evidence_runtime_image_sha256
            !== profile.evidence_runtime_image_sha256
          || capabilityResult.runtime_image_sha256
            !== profile.evidence_runtime_image_sha256
          || capabilityResult.runtime_image_status !== 'MATCHED_USED'
          || capabilityResult.runtime_image_used !== true
          || capabilityResult.evidence_status
            !== 'CANDIDATE_EXACT_RUNTIME_ON_REVIVE_ALLY_PACKET'
          || capabilityResult.input_packet_id !== profile.replay_block_packet_id
          || capabilityResult.child_event_id !== profile.child_event_id
          || capabilityResult.input_count !== capabilityResult.event_count)) {
      throw new EventQueryError('CAPABILITY_METADATA_MISMATCH',
        `${capability} identity differs from its exact-build candidate profile.`);
    }
  }
  if (exactPacketProfile) {
    prepareExactPacketEvent(semantic, analysis, eventKey, capabilityResult,
      exactPacketProfile);
  }
  if (exactBlobPacketConfig) {
    prepareExactBlobPacketEvent(semantic, analysis, eventKey, capabilityResult,
      exactBlobPacketConfig);
  }
  if (eventKey === 'increment_minion_kills_packet_candidates') {
    prepareIncrementMinionKillsPacketEvent(semantic, analysis, eventKey,
      capabilityResult);
  }
  if (eventKey === 'face_direction_keyframe_roster_pair_candidates') {
    prepareFaceDirectionRosterPairEvent(semantic, analysis, eventKey,
      capabilityResult);
  }
  const capabilityStatus = capabilityResult?.status ?? null;
  if (capabilityStatus && !['CANDIDATE', 'PASS'].includes(capabilityStatus)) {
    throw new EventQueryError('CAPABILITY_UNAVAILABLE',
      `${capability} was ${capabilityStatus}; no candidate rows may be queried.`,
      { capability, capability_status: capabilityStatus,
        missing_input: capabilityResult?.missing_input ?? null,
        error: capabilityResult?.error ?? null,
        semantic_run_status: semantic.status });
  }
  if (!capabilityResult || (!associationConfig
      && (!Array.isArray(semantic.requested_capabilities)
        || !semantic.requested_capabilities.includes(capability)))) {
    throw new EventQueryError('CAPABILITY_NOT_REQUESTED',
      `${capability} was not requested in this Replay artifact.`, { capability });
  }
  const declaredCount = analysis.event_counts?.[eventKey];
  if (!Object.hasOwn(analysis.event_counts ?? {}, eventKey)) {
    throw new EventQueryError('MISSING_EVENT_ARTIFACT',
      `${eventKey} is not listed in event_counts.`,
      { capability, capability_status: capabilityStatus });
  }
  let eventStorage;
  let fileName;
  if (analysis.event_storage === 'JSONL_ONLY') {
    eventStorage = 'JSONL_ONLY';
    if (!Object.hasOwn(analysis.event_jsonl_files ?? {}, eventKey)) {
      throw new EventQueryError('MISSING_EVENT_ARTIFACT',
        `${eventKey} is not listed in event_jsonl_files.`,
        { capability, capability_status: capabilityStatus });
    }
    fileName = analysis.event_jsonl_files[eventKey];
  } else if (analysis.event_storage == null) {
    eventStorage = 'EMBEDDED_AND_JSONL';
    const embeddedRows = analysis.events?.[eventKey];
    if (!Array.isArray(embeddedRows)) {
      throw new EventQueryError('MISSING_EVENT_ARTIFACT',
        `${eventKey} is not an embedded event array in replay_analysis.json.`,
        { capability, capability_status: capabilityStatus });
    }
    if (embeddedRows.length !== declaredCount) {
      throw new EventQueryError('EVENT_COUNT_MISMATCH',
        'Embedded event array length disagrees with event_counts.',
        { event_key: eventKey, embedded_event_count: embeddedRows.length,
          declared_event_count: declaredCount });
    }
    fileName = `${eventKey}.jsonl`;
  } else {
    throw new EventQueryError('UNSUPPORTED_EVENT_STORAGE',
      `Unsupported 16.19 event storage mode: ${analysis.event_storage}.`);
  }
  if (fileName !== `${eventKey}.jsonl` || path.basename(fileName) !== fileName) {
    throw new EventQueryError('UNSAFE_ARTIFACT', 'Event JSONL filename is not the exact event key.',
      { event_key: eventKey, filename: fileName });
  }
  if (!Number.isSafeInteger(declaredCount) || declaredCount < 0
      || capabilityResult.event_count !== declaredCount) {
    throw new EventQueryError('EVENT_COUNT_MISMATCH',
      'Declared event count disagrees with the executed capability.',
      { event_key: eventKey, declared_event_count: declaredCount,
        capability_event_count: capabilityResult.event_count });
  }
  const inputPath = path.join(artifactDirectory, fileName);
  let inputStat;
  try {
    inputStat = fs.lstatSync(inputPath);
  } catch (error) {
    if (error.code === 'ENOENT') {
      throw new EventQueryError('MISSING_EVENT_ARTIFACT', `Missing ${fileName}.`,
        { filename: inputPath, capability_status: capabilityStatus });
    }
    throw error;
  }
  if (!inputStat.isFile() || inputStat.isSymbolicLink()) {
    throw new EventQueryError('UNSAFE_ARTIFACT', `${fileName} must be a regular file.`,
      { filename: inputPath });
  }
  const bracketSources = associationConfig?.minionBracket ? {
    packet: prepareEventQuery(artifactDirectory,
      'increment_minion_kills_packet_candidates'),
    snapshot: prepareEventQuery(artifactDirectory,
      'hero_minions_killed_snapshot_candidates'),
  } : null;
  return {
    artifactDirectory, inputPath, eventKey, eventStorage, capability, capabilityStatus,
    capabilityResult, declaredCount, replaySha, associationConfig, exactPacketProfile,
    exactBlobPacketConfig, bracketSources,
    sourcePath: analysis.source_path,
    episodeAssistNativeStatus: associationConfig?.episode
      ? semantic.capability_results?.hero_assist?.native_child_identity_status : null,
    replayVersion: semantic.replay_version, semanticRunStatus: semantic.status,
    semanticApiStatus: semantic.api_status ?? null,
  };
}

function prepareBatchEventQuery(directory, eventKey) {
  const artifactDirectory = path.resolve(directory);
  const manifest = readArtifactJson(artifactDirectory, 'manifest.json');
  const hashes = manifest.output_hashes_excluding_manifest;
  if (manifest.command_args?.[0] !== 'batch'
      || !Array.isArray(manifest.replay_inputs) || manifest.replay_inputs.length === 0
      || !hashes || typeof hashes !== 'object' || Array.isArray(hashes)) {
    throw new EventQueryError('INVALID_BATCH_METADATA',
      'manifest.json must identify a nonempty batch run with output hashes.');
  }
  const replayRoot = path.join(artifactDirectory, 'replays');
  let replayRootStat;
  try {
    replayRootStat = fs.lstatSync(replayRoot);
  } catch (error) {
    if (error.code === 'ENOENT') {
      throw new EventQueryError('MISSING_METADATA', 'Batch Replay artifact directory is missing.',
        { directory: replayRoot });
    }
    throw error;
  }
  if (!replayRootStat.isDirectory() || replayRootStat.isSymbolicLink()) {
    throw new EventQueryError('UNSAFE_ARTIFACT', 'Batch Replay directory must be ordinary.',
      { directory: replayRoot });
  }
  const checkHash = (relative, filename) => {
    const expected = hashes[relative];
    if (!REPLAY_SHA.test(expected) || sha256File(filename) !== expected) {
      throw new EventQueryError('ARTIFACT_HASH_MISMATCH',
        `Batch manifest SHA-256 differs for ${relative}.`, { filename, relative });
    }
  };
  const seenDirectories = new Set();
  const seenReplays = new Set();
  const replays = manifest.replay_inputs.map((entry, index) => {
    const relative = entry?.artifact_directory;
    if (typeof relative !== 'string'
        || !/^replays\/[A-Za-z0-9._-]+$/.test(relative)
        || relative.endsWith('/.') || relative.endsWith('/..')
        || seenDirectories.has(relative)) {
      throw new EventQueryError('INVALID_BATCH_METADATA',
        `Unsafe or duplicate Replay artifact directory at manifest entry ${index}.`);
    }
    seenDirectories.add(relative);
    if (!REPLAY_SHA.test(entry.sha256)
        || !/^16\.19\.[0-9]+\.[0-9]+$/.test(entry.version)
        || seenReplays.has(entry.sha256)) {
      throw new EventQueryError('INVALID_BATCH_METADATA',
        `Invalid or duplicate Replay identity at manifest entry ${index}.`);
    }
    seenReplays.add(entry.sha256);
    const replayDirectory = path.join(artifactDirectory, relative);
    let stat;
    try {
      stat = fs.lstatSync(replayDirectory);
    } catch (error) {
      if (error.code === 'ENOENT') {
        throw new EventQueryError('MISSING_METADATA',
          `Missing Replay artifact directory: ${relative}.`);
      }
      throw error;
    }
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      throw new EventQueryError('UNSAFE_ARTIFACT',
        `Replay artifact directory must be an ordinary directory: ${relative}.`);
    }
    let prepared = null;
    let unavailable = null;
    try {
      prepared = prepareEventQuery(replayDirectory, eventKey);
    } catch (error) {
      if (!(error instanceof EventQueryError)
          || !['CAPABILITY_UNAVAILABLE', 'CAPABILITY_NOT_REQUESTED',
            'ASSOCIATION_UNAVAILABLE', 'UNSUPPORTED_EVENT_BUILD'].includes(error.code)) {
        throw error;
      }
      unavailable = { code: error.code, message: error.message,
        ...error.details };
    }
    // prepareEventQuery already checked both metadata files for available
    // entries. Unavailable entries still need their metadata read and bound.
    let identityMatches;
    if (prepared) {
      identityMatches = prepared.replaySha === entry.sha256
        && prepared.replayVersion === entry.version;
    } else {
      const semantic = readArtifactJson(replayDirectory, 'semantic_run.json');
      const analysis = readArtifactJson(replayDirectory, 'replay_analysis.json');
      identityMatches = semantic.replay_sha256 === entry.sha256
        && analysis.replay_sha256 === entry.sha256
        && semantic.replay_version === entry.version
        && analysis.replay_version === entry.version
        && semantic.container_status === 'PASS';
    }
    if (!identityMatches) {
      throw new EventQueryError('ARTIFACT_IDENTITY_MISMATCH',
        `Manifest and Replay metadata disagree at entry ${index}.`,
        { artifact_directory: relative });
    }
    checkHash(`${relative}/semantic_run.json`,
      path.join(replayDirectory, 'semantic_run.json'));
    checkHash(`${relative}/replay_analysis.json`,
      path.join(replayDirectory, 'replay_analysis.json'));
    if (prepared) {
      checkHash(`${relative}/${eventKey}.jsonl`, prepared.inputPath);
      if (prepared.bracketSources) {
        for (const source of Object.values(prepared.bracketSources)) {
          checkHash(`${relative}/${source.eventKey}.jsonl`, source.inputPath);
        }
      }
    }
    return { relative, replayDirectory, replaySha: entry.sha256,
      replayVersion: entry.version, prepared, unavailable };
  });
  const physical = fs.readdirSync(replayRoot, { withFileTypes: true });
  if (physical.some((entry) => !entry.isDirectory() || entry.isSymbolicLink())
      || physical.length !== seenDirectories.size
      || physical.some((entry) => !seenDirectories.has(`replays/${entry.name}`))) {
    throw new EventQueryError('INVALID_BATCH_METADATA',
      'Manifest Replay entries differ from the batch Replay directories.');
  }
  const hashedDirectories = new Set(Object.keys(hashes)
    .map((relative) => /^replays\/([^/]+)\//.exec(relative)?.[1])
    .filter(Boolean).map((name) => `replays/${name}`));
  if (hashedDirectories.size !== seenDirectories.size
      || [...hashedDirectories].some((relative) => !seenDirectories.has(relative))) {
    throw new EventQueryError('INVALID_BATCH_METADATA',
      'Manifest Replay entries differ from the batch output hash inventory.');
  }
  return { artifactDirectory, eventKey, replays };
}

function subjectParticipant(row, lineNumber, eventKey = null) {
  if (eventKey === 'face_direction_keyframe_roster_pair_candidates') {
    const value = row.hero_stats_participant_id_candidate;
    if (!Number.isSafeInteger(value) || value < 1 || value > 10) {
      throw new EventQueryError('INVALID_EVENT_ROW',
        `Invalid HeroStats roster participant at JSONL line ${lineNumber}.`,
        { line_number: lineNumber });
    }
    return { value, observed: true };
  }
  let value = null;
  let observed = false;
  for (const field of SUBJECT_PARTICIPANT_FIELDS) {
    if (!Object.hasOwn(row, field)) continue;
    observed = true;
    const next = row[field];
    if (next == null) continue;
    if (!Number.isSafeInteger(next) || next < 1 || next > 10) {
      throw new EventQueryError('INVALID_EVENT_ROW',
        `Invalid ${field} at JSONL line ${lineNumber}.`, { line_number: lineNumber });
    }
    if (value !== null && value !== next) {
      throw new EventQueryError('INVALID_EVENT_ROW',
        `Conflicting subject participants at JSONL line ${lineNumber}.`,
        { line_number: lineNumber });
    }
    value = next;
  }
  return { value, observed };
}

function rowReplayTime(row, lineNumber) {
  const value = row.replay_time_ms ?? row.timestamp_ms;
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Missing or invalid Replay timestamp at JSONL line ${lineNumber}.`,
      { line_number: lineNumber });
  }
  if (row.replay_time_ms != null && row.timestamp_ms != null
      && row.replay_time_ms !== row.timestamp_ms) {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Conflicting Replay timestamps at JSONL line ${lineNumber}.`,
      { line_number: lineNumber });
  }
  return value;
}

function rawPacketParams(row, lineNumber) {
  const values = [];
  const add = (value, label) => {
    if (value == null) return;
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
      throw new EventQueryError('INVALID_EVENT_ROW',
        `Invalid ${label} at JSONL line ${lineNumber}.`, { line_number: lineNumber });
    }
    values.push(value);
  };
  add(row.raw_param, 'raw_param');
  add(row.hero_raw_param, 'hero_raw_param');
  add(row.raw_packet_ref?.raw_param, 'raw_packet_ref.raw_param');
  for (const [index, ref] of (row.raw_packet_refs ?? []).entries()) {
    add(ref?.raw_param, `raw_packet_refs[${index}].raw_param`);
  }
  return values;
}

function packetRecordItemIds(row, lineNumber, allowZero) {
  const records = row.records_candidate;
  if (records == null) return { values: [], unavailable: true, available: false };
  if (!Array.isArray(records)
      || (row.record_count != null && row.record_count !== records.length)) {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid inventory records at JSONL line ${lineNumber}.`,
      { line_number: lineNumber });
  }
  const values = [];
  let unavailable = false;
  for (const [index, record] of records.entries()) {
    if (record === null || typeof record !== 'object' || Array.isArray(record)) {
      throw new EventQueryError('INVALID_EVENT_ROW',
        `Invalid inventory record ${index} at JSONL line ${lineNumber}.`,
        { line_number: lineNumber });
    }
    if (record.item_id_candidate == null) {
      unavailable = true;
      continue;
    }
    const itemId = record.item_id_candidate;
    if (!Number.isSafeInteger(itemId) || itemId < (allowZero ? 0 : 1)
        || itemId > 0xffffffff) {
      throw new EventQueryError('INVALID_EVENT_ROW',
        `Invalid records_candidate[${index}].item_id_candidate at JSONL line ${lineNumber}.`,
        { line_number: lineNumber });
    }
    values.push(itemId);
  }
  return { values, unavailable, available: values.length > 0 || records.length === 0 };
}

function packetScalarItemId(row, lineNumber) {
  const itemId = row.item_id_candidate;
  if (itemId == null) return { values: [], unavailable: true, available: false };
  if (!Number.isSafeInteger(itemId) || itemId < 0 || itemId > 0xffffffff) {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid item_id_candidate at JSONL line ${lineNumber}.`,
      { line_number: lineNumber });
  }
  return { values: [itemId], unavailable: false, available: true };
}

function packetRecordSlots(row, lineNumber) {
  const records = row.records_candidate;
  if (records == null) return { values: [], unavailable: true, available: false };
  if (!Array.isArray(records)
      || (row.record_count != null && row.record_count !== records.length)) {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid inventory records at JSONL line ${lineNumber}.`,
      { line_number: lineNumber });
  }
  const values = [];
  let unavailable = false;
  for (const [index, record] of records.entries()) {
    if (record === null || typeof record !== 'object' || Array.isArray(record)) {
      throw new EventQueryError('INVALID_EVENT_ROW',
        `Invalid inventory record ${index} at JSONL line ${lineNumber}.`,
        { line_number: lineNumber });
    }
    if (record.slot_candidate == null) {
      unavailable = true;
      continue;
    }
    const slot = record.slot_candidate;
    if (!Number.isSafeInteger(slot) || slot < 0 || slot > 9) {
      throw new EventQueryError('INVALID_EVENT_ROW',
        `Invalid records_candidate[${index}].slot_candidate at JSONL line ${lineNumber}.`,
        { line_number: lineNumber });
    }
    values.push(slot);
  }
  return { values, unavailable, available: values.length > 0 || records.length === 0 };
}

function packetScalarSlot(row, lineNumber) {
  const slot = row.slot_candidate;
  if (slot == null) return { values: [], unavailable: true, available: false };
  if (!Number.isSafeInteger(slot) || slot < 0 || slot > 9) {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid slot_candidate at JSONL line ${lineNumber}.`,
      { line_number: lineNumber });
  }
  return { values: [slot], unavailable: false, available: true };
}

function opaqueU32Values(row, lineNumber, fields) {
  const values = [];
  let unavailable = false;
  for (const field of fields) {
    const value = row[field];
    if (value == null) {
      unavailable = true;
      continue;
    }
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
      throw new EventQueryError('INVALID_EVENT_ROW',
        `Invalid ${field} at JSONL line ${lineNumber}.`, { line_number: lineNumber });
    }
    values.push(value);
  }
  return { values, unavailable, available: values.length > 0 };
}

function opaquePairValue(row, lineNumber, fields) {
  const [u32Field, u8Field] = fields;
  const u32 = row[u32Field];
  const u8 = row[u8Field];
  if (u32 != null && (!Number.isSafeInteger(u32) || u32 < 0 || u32 > 0xffffffff)) {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid ${u32Field} at JSONL line ${lineNumber}.`, { line_number: lineNumber });
  }
  if (u8 != null && (!Number.isSafeInteger(u8) || u8 < 0 || u8 > 0xff)) {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid ${u8Field} at JSONL line ${lineNumber}.`, { line_number: lineNumber });
  }
  return { u32, u8, available: u32 != null && u8 != null };
}

function castSpellAnsOpaqueI32(row, lineNumber) {
  const field = 'opaque_i32_0x14c';
  if (!Object.hasOwn(row, field)) return { value: null, available: false };
  const value = row[field];
  if (!Number.isInteger(value) || value < -0x80000000 || value > 0x7fffffff) {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid ${field} at JSONL line ${lineNumber}.`, { line_number: lineNumber });
  }
  return { value, available: true };
}

function turretPairRow(row, prepared, lineNumber, seenKeys, seenPacketPositions) {
  const { associationConfig, capabilityResult, replaySha, replayVersion } = prepared;
  const invalid = (reason) => {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid turret_first_blood_die_pair row at JSONL line ${lineNumber}: ${reason}.`,
      { line_number: lineNumber });
  };
  const dieRef = row.turret_die_raw_packet_ref;
  const firstRef = row.turret_first_blood_raw_packet_ref;
  if (row.event_type !== associationConfig.eventType
      || row.game_version !== replayVersion || row.patch !== '16.19'
      || row.build_profile !== associationConfig.profile.id
      || row.confidence !== 'CANDIDATE'
      || row.semantic_status !== capabilityResult.evidence_status
      || row.turret_die_child_event_id !== 0x003b
      || row.turret_first_blood_child_event_id !== 0x003d
      || !dieRef || !firstRef || !Array.isArray(row.raw_packet_refs)
      || row.raw_packet_refs.length !== 2
      || !isDeepStrictEqual(row.raw_packet_ref, firstRef)
      || !isDeepStrictEqual(row.raw_packet_refs, [dieRef, firstRef])) {
    invalid('candidate profile, child identity or packet references differ');
  }
  for (const ref of [dieRef, firstRef]) {
    if (ref.replay_sha256 !== replaySha
        || (ref.source_path !== null
          && (typeof ref.source_path !== 'string' || ref.source_path.length === 0))
        || ref.replay_time_ms !== row.replay_time_ms
        || ref.chunk_stream !== 'game_chunk'
        || !Number.isSafeInteger(ref.chunk_index) || ref.chunk_index < 0
        || !Number.isSafeInteger(ref.chunk_id)
        || !Number.isSafeInteger(ref.chunk_file_offset) || ref.chunk_file_offset < 0
        || !Number.isSafeInteger(ref.decompressed_block_offset)
        || ref.decompressed_block_offset < 0
        || !Number.isSafeInteger(ref.decompressed_payload_offset)
        || ref.decompressed_payload_offset <= ref.decompressed_block_offset
        || ref.packet_id !== 0x040a || ref.payload_length !== 116
        || !Number.isSafeInteger(ref.raw_param) || ref.raw_param <= 0
        || ref.raw_param > 0xffffffff
        || !REPLAY_SHA.test(ref.raw_payload_sha256)) {
      invalid('raw packet reference identity is incomplete or foreign');
    }
    const position = `${ref.chunk_index}/${ref.decompressed_block_offset}`;
    if (seenPacketPositions.has(position)) invalid('duplicate raw packet position');
    seenPacketPositions.add(position);
  }
  if (dieRef.source_path !== firstRef.source_path
      || dieRef.chunk_index !== firstRef.chunk_index
      || dieRef.chunk_id !== firstRef.chunk_id
      || dieRef.chunk_file_offset !== firstRef.chunk_file_offset
      || dieRef.decompressed_block_offset >= firstRef.decompressed_block_offset
      || row.source_order_block_offset_gap
        !== firstRef.decompressed_block_offset - dieRef.decompressed_block_offset
      || row.intervening_on_event_count !== 0
      || row.turret_die_raw_param !== dieRef.raw_param
      || row.turret_first_blood_raw_param !== firstRef.raw_param) {
    invalid('packet order, same-chunk identity or raw parameters differ');
  }
  const key = `${firstRef.chunk_index}/${row.replay_time_ms}`;
  if (seenKeys.has(key)) invalid('duplicate same-chunk, same-ms candidate');
  seenKeys.add(key);
}

const EPISODE_REF_FIELDS = Object.freeze([
  'source_path', 'replay_sha256', 'chunk_index', 'chunk_id', 'chunk_stream',
  'chunk_file_offset', 'decompressed_block_offset', 'decompressed_payload_offset',
  'packet_id', 'replay_time_ms', 'payload_length', 'raw_param',
  'raw_payload_sha256',
]);

function sameEpisodePhysicalRef(left, right) {
  return !!left && !!right
    && EPISODE_REF_FIELDS.every((field) => left[field] === right[field]);
}

function validEpisodeRef(ref, replaySha) {
  return !!ref && typeof ref === 'object' && !Array.isArray(ref)
    && ref.replay_sha256 === replaySha
    && ref.chunk_stream === 'game_chunk'
    && Number.isSafeInteger(ref.chunk_index) && ref.chunk_index >= 0
    && Number.isSafeInteger(ref.chunk_id)
    && Number.isSafeInteger(ref.chunk_file_offset) && ref.chunk_file_offset >= 0
    && Number.isSafeInteger(ref.decompressed_block_offset)
    && ref.decompressed_block_offset >= 0
    && Number.isSafeInteger(ref.decompressed_payload_offset)
    && ref.decompressed_payload_offset > ref.decompressed_block_offset
    && Number.isSafeInteger(ref.packet_id) && ref.packet_id >= 0
    && Number.isSafeInteger(ref.replay_time_ms) && ref.replay_time_ms >= 0
    && Number.isSafeInteger(ref.payload_length) && ref.payload_length >= 0
    && Number.isSafeInteger(ref.raw_param) && ref.raw_param >= 0
    && ref.raw_param <= 0xffffffff && REPLAY_SHA.test(ref.raw_payload_sha256);
}

function heroDeathEpisodeRow(row, prepared, lineNumber, seenPrimaryPositions,
  seenPhysicalRefs) {
  const profile = HERO_DEATH_EPISODE_821_PROFILE;
  const invalid = (reason) => {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid ${profile.capability} row at JSONL line ${lineNumber}: ${reason}.`,
      { line_number: lineNumber });
  };
  const victim = row.victim_participant_id_candidate;
  const killer = row.killer_participant_id_candidate;
  const assists = row.assisting_participant_ids_candidate;
  const deathRef = row.death_primary_raw_packet_ref;
  const returnRef = row.return_raw_packet_ref;
  const refs = row.raw_packet_refs;
  if (row.event_type !== 'HERO_DEATH_EPISODE_CANDIDATE'
      || row.game_version !== profile.replay_version || row.patch !== '16.19'
      || row.build_profile !== profile.id
      || row.confidence !== 'CANDIDATE'
      || row.semantic_status !== prepared.capabilityResult.evidence_status
      || !Number.isSafeInteger(victim) || victim < 1 || victim > 10
      || !Object.hasOwn(row, 'killer_participant_id_candidate')
      || (killer !== null && (!Number.isSafeInteger(killer)
        || killer < 1 || killer > 10 || killer === victim))
      || !Object.hasOwn(row, 'assisting_participant_ids_candidate')
      || !['NOT_CHECKED', 'MATCHED_USED'].includes(row.native_child_identity_status)
      || row.native_child_identity_status !== prepared.episodeAssistNativeStatus
      || !Number.isFinite(row.timer_seconds_candidate)
      || row.timer_seconds_candidate <= 0
      || !validEpisodeRef(deathRef, prepared.replaySha)
      || deathRef.packet_id !== 0x0259 || deathRef.payload_length !== 5
      || deathRef.replay_time_ms !== row.replay_time_ms
      || !sameEpisodePhysicalRef(row.raw_packet_ref, deathRef)
      || !Array.isArray(refs) || refs.length === 0) {
    invalid('exact-build candidate, participant, timer or death source differs');
  }
  if (killer === null) {
    if (assists !== null || row.assist_observation_status !== 'UNAVAILABLE_NONHERO_SOURCE'
        || row.field_confidence?.killer_participant_id_candidate !== 'UNAVAILABLE'
        || row.field_confidence?.assisting_participant_ids_candidate !== 'UNAVAILABLE') {
      invalid('unavailable killer and assist list disagree');
    }
  } else {
    if (!Array.isArray(assists)
        || row.assist_observation_status
          !== 'CANDIDATE_821_CO_TIMED_ASSIST_PAIR_TAIL_ALIGNMENT'
        || row.field_confidence?.killer_participant_id_candidate
          !== 'CANDIDATE_821_SOURCE_ID_KILL_TAIL_ALIGNMENT'
        || row.field_confidence?.assisting_participant_ids_candidate
          !== 'CANDIDATE_821_CO_TIMED_ASSIST_PAIR_TAIL_ALIGNMENT') {
      invalid('available killer and assist list disagree');
    }
    const unique = new Set();
    for (const participant of assists) {
      if (!Number.isSafeInteger(participant) || participant < 1 || participant > 10
          || participant === victim || participant === killer
          || unique.has(participant)) invalid('assisting participant list differs');
      unique.add(participant);
    }
  }
  if (row.return_observation_status === 'OBSERVED_RETURN') {
    if (!validEpisodeRef(returnRef, prepared.replaySha)
        || returnRef.packet_id !== 0x0048
        || ![9, 13].includes(returnRef.payload_length)
        || returnRef.replay_time_ms !== row.return_replay_time_ms_candidate
        || row.return_replay_time_ms_candidate <= row.replay_time_ms
        || row.observed_death_to_return_ms_candidate
          !== row.return_replay_time_ms_candidate - row.replay_time_ms
        || row.replay_remaining_ms !== null
        || row.field_confidence?.return_replay_time_ms_candidate
          !== 'CANDIDATE_821_OBSERVED_RETURN_PACKET'
        || row.field_confidence?.observed_death_to_return_ms_candidate
          !== 'CANDIDATE_DIFFERENCE_OF_PAIRED_REPLAY_TIMES') {
      invalid('observed return fields or source differ');
    }
  } else if (row.return_observation_status === 'UNOBSERVED_BEFORE_REPLAY_END') {
    if (returnRef !== null || row.return_replay_time_ms_candidate !== null
        || row.observed_death_to_return_ms_candidate !== null
        || !isCount(row.replay_remaining_ms)
        || row.field_confidence?.return_replay_time_ms_candidate !== 'UNAVAILABLE'
        || row.field_confidence?.observed_death_to_return_ms_candidate
          !== 'UNAVAILABLE') {
      invalid('terminal unobserved return fields differ');
    }
  } else {
    invalid('return observation status differs');
  }
  const primaryPosition = `${deathRef.chunk_index}/${deathRef.decompressed_block_offset}`;
  if (seenPrimaryPositions.has(primaryPosition)) invalid('duplicate death primary');
  seenPrimaryPositions.add(primaryPosition);
  const rowPositions = new Set();
  for (const ref of refs) {
    if (!validEpisodeRef(ref, prepared.replaySha)
        || ref.source_path !== deathRef.source_path) invalid('raw packet reference is malformed');
    const position = `${ref.chunk_index}/${ref.decompressed_block_offset}`;
    if (rowPositions.has(position)) invalid('duplicate raw packet position in episode');
    rowPositions.add(position);
    const prior = seenPhysicalRefs.get(position);
    if (prior && !sameEpisodePhysicalRef(prior, ref)) {
      invalid('raw packet position has conflicting references');
    }
    seenPhysicalRefs.set(position, ref);
  }
  const deathMatches = refs.filter((ref) => ref.packet_id === 0x0259
    && sameEpisodePhysicalRef(ref, deathRef));
  const returnMatches = refs.filter((ref) => ref.packet_id === 0x0048
    && returnRef && sameEpisodePhysicalRef(ref, returnRef));
  if (deathMatches.length !== 1
      || refs.filter((ref) => ref.packet_id === 0x0259).length !== 1
      || (returnRef === null
        ? refs.some((ref) => ref.packet_id === 0x0048)
        : returnMatches.length !== 1
          || refs.filter((ref) => ref.packet_id === 0x0048).length !== 1)) {
    invalid('named death or return source is missing from raw packet references');
  }
}

function inventoryKeyframeIntervalDifferenceRow(row, prepared, lineNumber, state) {
  const invalid = (reason) => {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid inventory_keyframe_interval_difference row at JSONL line ${lineNumber}: ${reason}.`,
      { line_number: lineNumber });
  };
  const fields = Object.keys(row);
  const previousRef = row.previous_raw_packet_ref;
  const currentRef = row.current_raw_packet_ref;
  const rawParam = row.hero_raw_param;
  const previousTime = row.previous_observation_time_ms;
  const currentTime = row.current_observation_time_ms;
  if (fields.length !== INVENTORY_INTERVAL_ROW_FIELDS_821.size
      || fields.some((field) => !INVENTORY_INTERVAL_ROW_FIELDS_821.has(field))
      || row.event_type !== prepared.associationConfig.eventType
      || row.game_version !== prepared.replayVersion || row.patch !== '16.19'
      || row.build_profile !== prepared.associationConfig.profile.id
      || row.confidence !== 'CANDIDATE'
      || row.semantic_status !== prepared.capabilityResult.evidence_status
      || row.observation_kind !== 'ADJACENT_KEYFRAME_SAMPLED_ENDPOINTS'
      || row.observation_scope !== 'KEYFRAME_ENDPOINT_DIFFERENCE_ONLY'
      || row.change_time_status !== 'UNRESOLVED_WITHIN_INTERVAL'
      || !Number.isSafeInteger(rawParam)
      || rawParam < 0x400000ae || rawParam > 0x400000b7
      || row.participant_id_candidate !== rawParam - 0x400000ae + 1
      || !Number.isSafeInteger(previousTime) || previousTime < 0
      || !Number.isSafeInteger(currentTime) || currentTime <= previousTime
      || row.replay_time_ms !== currentTime
      || row.observation_interval_ms !== currentTime - previousTime
      || !Array.isArray(row.raw_packet_refs) || row.raw_packet_refs.length !== 2
      || !isDeepStrictEqual(row.raw_packet_ref, currentRef)
      || !isDeepStrictEqual(row.raw_packet_refs, [previousRef, currentRef])
      || !isDeepStrictEqual(row.field_confidence, {
        previous_observation_time_ms: 'VERIFIED_DIRECT',
        current_observation_time_ms: 'VERIFIED_DIRECT',
        participant_id_candidate: 'CANDIDATE_KR_821_RAW_PARAM_TAIL_ALIGNMENT',
        changed_slots_candidate: 'CANDIDATE_EXACT_RUNTIME_BROADCAST_PACKET_FIELDS',
      })) {
    invalid('exact-build observation, interval timing or named references differ');
  }
  const validRef = (ref, time, chunkIndex) =>
    !!ref && typeof ref === 'object' && !Array.isArray(ref)
    && ref.replay_sha256 === prepared.replaySha
    && (ref.source_path === null
      || (typeof ref.source_path === 'string' && ref.source_path.length > 0))
    && (prepared.sourcePath === undefined || ref.source_path === prepared.sourcePath)
    && ref.chunk_stream === 'keyframe'
    && Number.isSafeInteger(ref.chunk_index) && ref.chunk_index === chunkIndex
    && Number.isSafeInteger(ref.chunk_id) && ref.chunk_id >= 0
    && Number.isSafeInteger(ref.chunk_file_offset) && ref.chunk_file_offset >= 0
    && Number.isSafeInteger(ref.decompressed_block_offset)
    && ref.decompressed_block_offset >= 0
    && Number.isSafeInteger(ref.decompressed_payload_offset)
    && ref.decompressed_payload_offset > ref.decompressed_block_offset
    && ref.packet_id === 0x0357 && ref.replay_time_ms === time
    && Number.isSafeInteger(ref.payload_length)
    && ref.payload_length >= 76 && ref.payload_length <= 166
    && ref.raw_param === rawParam && REPLAY_SHA.test(ref.raw_payload_sha256);
  if (!Number.isSafeInteger(row.previous_keyframe_chunk_index)
      || !Number.isSafeInteger(row.current_keyframe_chunk_index)
      || row.previous_keyframe_chunk_index < 0
      || row.current_keyframe_chunk_index <= row.previous_keyframe_chunk_index
      || !validRef(previousRef, previousTime, row.previous_keyframe_chunk_index)
      || !validRef(currentRef, currentTime, row.current_keyframe_chunk_index)
      || previousRef.source_path !== currentRef.source_path) {
    invalid('previous/current keyframe packet identity or order differs');
  }
  const changes = row.changed_slots_candidate;
  if (!Array.isArray(changes) || changes.length < 1 || changes.length > 10
      || row.changed_slot_count !== changes.length) {
    invalid('changed slot count or list differs');
  }
  let previousSlot = -1;
  for (const change of changes) {
    const keys = change && typeof change === 'object' && !Array.isArray(change)
      ? Object.keys(change) : [];
    if (keys.length !== 3 || !keys.includes('slot_candidate')
        || !keys.includes('previous_item_id_candidate')
        || !keys.includes('current_item_id_candidate')
        || !Number.isSafeInteger(change.slot_candidate)
        || change.slot_candidate <= previousSlot || change.slot_candidate > 9
        || !Number.isSafeInteger(change.previous_item_id_candidate)
        || change.previous_item_id_candidate < 0
        || change.previous_item_id_candidate > 0xffffffff
        || !Number.isSafeInteger(change.current_item_id_candidate)
        || change.current_item_id_candidate < 0
        || change.current_item_id_candidate > 0xffffffff
        || change.previous_item_id_candidate === change.current_item_id_candidate) {
      invalid('changed slot keys, order or endpoint item IDs differ');
    }
    previousSlot = change.slot_candidate;
  }
  const pairKey = `${row.previous_keyframe_chunk_index}/${row.current_keyframe_chunk_index}`;
  const framePair = state.pairs.get(pairKey)
    ?? { previousTime, currentTime, participants: new Set() };
  if (framePair.previousTime !== previousTime || framePair.currentTime !== currentTime
      || framePair.participants.has(row.participant_id_candidate)) {
    invalid('frame pair has conflicting times or duplicate participant');
  }
  framePair.participants.add(row.participant_id_candidate);
  state.pairs.set(pairKey, framePair);
  for (const [ref, time] of [[previousRef, previousTime], [currentRef, currentTime]]) {
    const frameTime = state.frameTimes.get(ref.chunk_index);
    if (frameTime !== undefined && frameTime !== time) {
      invalid('keyframe time differs across participant observations');
    }
    state.frameTimes.set(ref.chunk_index, time);
    const endpointKey = `${ref.chunk_index}/${row.participant_id_candidate}`;
    const existingRef = state.endpoints.get(endpointKey);
    if (existingRef && !isDeepStrictEqual(existingRef, ref)) {
      invalid('participant keyframe endpoint reference differs across intervals');
    }
    state.endpoints.set(endpointKey, ref);
  }
  state.changedSlotCount += changes.length;
}

function wardInventoryKeyframePairRow(row, prepared, lineNumber, seenKeys,
  seenPacketPositions, frames) {
  const invalid = (reason) => {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid ward_inventory_keyframe_pair row at JSONL line ${lineNumber}: ${reason}.`,
      { line_number: lineNumber });
  };
  const wardRef = row.ward_stats_raw_packet_ref;
  const broadcastRef = row.inventory_broadcast_raw_packet_ref;
  const refs = row.raw_packet_refs;
  const rawParam = row.hero_raw_param;
  if (row.event_type !== 'WARD_INVENTORY_KEYFRAME_PAIR_CANDIDATE'
      || row.game_version !== prepared.replayVersion || row.patch !== '16.19'
      || row.build_profile !== WARD_INVENTORY_KEYFRAME_PAIR_821_PROFILE.id
      || row.confidence !== 'CANDIDATE'
      || row.semantic_status !== prepared.capabilityResult.evidence_status
      || row.observation_kind !== 'SAME_KEYFRAME_PACKET_PAIR'
      || !Number.isSafeInteger(rawParam)
      || rawParam < 0x400000ae || rawParam > 0x400000b7
      || row.participant_id_candidate !== rawParam - 0x400000ae + 1
      || !Array.isArray(refs) || refs.length !== 2
      || !isDeepStrictEqual(row.raw_packet_ref, wardRef)
      || !isDeepStrictEqual(refs, [broadcastRef, wardRef])) {
    invalid('exact-build pair identity, participant or named references differ');
  }
  const validRef = (ref, packetId, minimumLength, maximumLength) =>
    !!ref && typeof ref === 'object' && !Array.isArray(ref)
    && ref.replay_sha256 === prepared.replaySha
    && (ref.source_path === null
      || (typeof ref.source_path === 'string' && ref.source_path.length > 0))
    && (prepared.sourcePath === undefined || ref.source_path === prepared.sourcePath)
    && ref.chunk_stream === 'keyframe'
    && Number.isSafeInteger(ref.chunk_index) && ref.chunk_index >= 0
    && Number.isSafeInteger(ref.chunk_id) && ref.chunk_id >= 0
    && Number.isSafeInteger(ref.chunk_file_offset) && ref.chunk_file_offset >= 0
    && Number.isSafeInteger(ref.decompressed_block_offset)
    && ref.decompressed_block_offset >= 0
    && Number.isSafeInteger(ref.decompressed_payload_offset)
    && ref.decompressed_payload_offset > ref.decompressed_block_offset
    && ref.packet_id === packetId && ref.replay_time_ms === row.replay_time_ms
    && Number.isSafeInteger(ref.payload_length)
    && ref.payload_length >= minimumLength && ref.payload_length <= maximumLength
    && ref.raw_param === rawParam && REPLAY_SHA.test(ref.raw_payload_sha256);
  if (!validRef(wardRef, 0x0089, 1263, 1263)
      || !validRef(broadcastRef, 0x0357, 76, 166)
      || wardRef.source_path !== broadcastRef.source_path
      || wardRef.chunk_index !== broadcastRef.chunk_index
      || wardRef.chunk_id !== broadcastRef.chunk_id
      || wardRef.chunk_file_offset !== broadcastRef.chunk_file_offset
      || broadcastRef.decompressed_block_offset
        >= wardRef.decompressed_block_offset) {
    invalid('keyframe packet identity, time or physical order differs');
  }
  for (const ref of refs) {
    const position = `${ref.chunk_index}/${ref.decompressed_block_offset}`;
    if (seenPacketPositions.has(position)) invalid('duplicate raw packet position');
    seenPacketPositions.add(position);
  }
  const pairKey = `${wardRef.chunk_index}/${row.replay_time_ms}/${rawParam}`;
  if (seenKeys.has(pairKey)) invalid('duplicate keyframe participant pair');
  seenKeys.add(pairKey);
  const frame = frames.get(wardRef.chunk_index)
    ?? { time: row.replay_time_ms, participants: new Set() };
  if (frame.time !== row.replay_time_ms
      || frame.participants.has(row.participant_id_candidate)) {
    invalid('keyframe roster has conflicting time or participant');
  }
  frame.participants.add(row.participant_id_candidate);
  frames.set(wardRef.chunk_index, frame);
  if (row.field_confidence?.replay_time_ms !== 'VERIFIED_DIRECT'
      || row.field_confidence?.hero_raw_param !== 'VERIFIED_DIRECT'
      || row.field_confidence?.participant_id_candidate
        !== 'CANDIDATE_KR_821_RAW_PARAM_TAIL_ALIGNMENT'
      || row.field_confidence?.inventory_records_candidate
        !== 'CANDIDATE_EXACT_RUNTIME_BROADCAST_PACKET_FIELDS'
      || row.field_confidence?.inventory_packet_slot_snapshot_candidate
        !== 'CANDIDATE_EXACT_RUNTIME_CALLBACK_APPLICATION_AND_RECORD_FIELDS') {
    invalid('candidate field evidence differs');
  }
  for (const { key } of HERO_WARD_STATS_SNAPSHOT_821_CANDIDATE_PROFILE.fields) {
    const raw = row[`raw_${key}_byte`];
    const value = row[`${key}_candidate`];
    if (!Number.isSafeInteger(raw) || raw < 0 || raw > 255
        || !Number.isSafeInteger(value) || value < 0 || value > 255
        || decodeRuntimeCountByte(raw) !== value
        || row.field_confidence?.[`${key}_candidate`]
          !== 'CANDIDATE_821_RUNTIME_KEYFRAME_BYTE_AND_REPLAY_TAIL') {
      invalid(`${key} candidate or raw byte differs`);
    }
  }
  const records = row.inventory_records_candidate;
  const snapshot = row.inventory_packet_slot_snapshot_candidate;
  if (row.inventory_record_count !== 10
      || !Array.isArray(records) || records.length !== 10
      || !Array.isArray(snapshot) || snapshot.length !== 10) {
    invalid('inventory keyframe records or snapshot are incomplete');
  }
  for (let index = 0; index < 10; index += 1) {
    const record = records[index];
    const slot = snapshot[index];
    if (record?.record_index !== index || record.slot_candidate !== index
        || !Number.isSafeInteger(record.item_id_candidate)
        || record.item_id_candidate < 0 || record.item_id_candidate > 0xffffffff
        || !/^[a-f0-9]{2}$/.test(record.emulated_object_slot_byte_hex)
        || !/^[a-f0-9]{8}$/.test(record.emulated_object_item_id_bytes_hex)
        || slot?.slot_candidate !== index
        || slot.item_id_candidate !== record.item_id_candidate
        || slot.value_basis !== 'DECODED_PACKET_RECORD') {
      invalid(`inventory slot ${index} differs from its decoded record`);
    }
  }
}

function minionBracketRef(ref, prepared, packetId, stream, payloadLength) {
  return !!ref && typeof ref === 'object' && !Array.isArray(ref)
    && ref.source_path === (prepared.sourcePath ?? null)
    && ref.replay_sha256 === prepared.replaySha
    && Number.isSafeInteger(ref.chunk_index) && ref.chunk_index >= 0
    && Number.isSafeInteger(ref.chunk_id) && ref.chunk_id >= 0
    && ref.chunk_stream === stream
    && Number.isSafeInteger(ref.chunk_file_offset) && ref.chunk_file_offset >= 0
    && Number.isSafeInteger(ref.decompressed_block_offset)
    && ref.decompressed_block_offset >= 0
    && Number.isSafeInteger(ref.decompressed_payload_offset)
    && ref.decompressed_payload_offset > ref.decompressed_block_offset
    && ref.packet_id === packetId
    && Number.isSafeInteger(ref.replay_time_ms) && ref.replay_time_ms >= 0
    && ref.payload_length === payloadLength
    && Number.isSafeInteger(ref.raw_param)
    && ref.raw_param >= 0x400000ae && ref.raw_param <= 0x400000b7
    && REPLAY_SHA.test(ref.raw_payload_sha256);
}

async function readMinionBracketSource(prepared) {
  const rows = [];
  const input = fs.createReadStream(prepared.inputPath, { encoding: 'utf8' });
  const lines = readline.createInterface({ input, crlfDelay: Infinity });
  try {
    for await (const line of lines) {
      if (rows.length >= MAX_MINION_BRACKET_SOURCE_ROWS_821) {
        throw new EventQueryError('EVENT_COUNT_MISMATCH',
          `${prepared.eventKey} exceeds the exact-build source row bound.`);
      }
      let row;
      try {
        row = JSON.parse(line);
      } catch (error) {
        throw new EventQueryError('INVALID_EVENT_ROW',
          `Invalid ${prepared.eventKey} JSONL at line ${rows.length + 1}: ${error.message}.`);
      }
      if (!row || typeof row !== 'object' || Array.isArray(row)) {
        throw new EventQueryError('INVALID_EVENT_ROW',
          `Invalid ${prepared.eventKey} JSONL object at line ${rows.length + 1}.`);
      }
      rows.push(row);
    }
  } finally {
    lines.close();
    input.destroy();
  }
  if (rows.length !== prepared.declaredCount) {
    throw new EventQueryError('EVENT_COUNT_MISMATCH',
      `${prepared.eventKey} source JSONL row count differs from metadata.`);
  }
  return rows;
}

async function loadMinionBracketExpectedRows(prepared) {
  const association = prepared.capabilityResult;
  const packetPrepared = prepared.bracketSources.packet;
  const snapshotPrepared = prepared.bracketSources.snapshot;
  const [packets, snapshots] = await Promise.all([
    readMinionBracketSource(packetPrepared),
    readMinionBracketSource(snapshotPrepared),
  ]);
  const invalid = (reason) => {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid increment_minion_keyframe_bracket source: ${reason}.`);
  };
  const positions = new Set();
  const frames = new Map();
  const packetPositions = new Set();
  if (packets.length !== association.packet_count
      || snapshots.length !== association.snapshot_count) {
    invalid('source row counts differ from association metadata');
  }
  for (const [index, row] of snapshots.entries()) {
    const ref = row.raw_packet_ref;
    const participant = row.hero_raw_param - 0x400000ae + 1;
    if (row.event_type !== 'HERO_MINIONS_KILLED_SNAPSHOT_CANDIDATE'
        || row.game_version !== prepared.replayVersion || row.patch !== '16.19'
        || row.build_profile !== FLOAT_STATS_821_PROFILES.hero_minions_killed_snapshot.id
        || row.replay_sha256 !== prepared.replaySha
        || row.confidence !== 'CANDIDATE'
        || row.semantic_status
          !== 'CANDIDATE_821_RUNTIME_BYTE_KEYFRAME_F32_AND_REPLAY_TAIL'
        || row.observation_kind !== 'KEYFRAME_SNAPSHOT'
        || !minionBracketRef(ref, prepared, 0x0089, 'keyframe', 1263)
        || row.hero_raw_param !== ref.raw_param
        || row.participant_id_candidate !== participant
        || row.replay_time_ms !== ref.replay_time_ms
        || !Number.isSafeInteger(row.minions_killed_raw_f32_candidate)
        || row.minions_killed_raw_f32_candidate < 0
        || row.minions_killed_floor_candidate
          !== row.minions_killed_raw_f32_candidate
        || !/^[0-9a-f]{8}$/.test(row.raw_payload_field_bytes_hex)) {
      invalid(`snapshot ${index + 1} has different identity, participant, or value`);
    }
    const encoded = Buffer.from(row.raw_payload_field_bytes_hex, 'hex').reverse();
    const decoded = Buffer.from(encoded.map(decodeRuntimeCountByte));
    if (decoded.readFloatLE(0) !== row.minions_killed_raw_f32_candidate) {
      invalid(`snapshot ${index + 1} does not decode to its candidate count`);
    }
    const position = `${ref.chunk_index}/${ref.decompressed_block_offset}`;
    if (positions.has(position)) invalid(`duplicate source packet reference ${position}`);
    positions.add(position);
    const frame = frames.get(ref.chunk_index) ?? {
      chunk_index: ref.chunk_index, time_ms: ref.replay_time_ms,
      participants: new Map(),
    };
    if (frame.time_ms !== ref.replay_time_ms
        || frame.participants.has(participant)) {
      invalid(`snapshot ${index + 1} has ambiguous keyframe roster`);
    }
    frame.participants.set(participant, row);
    frames.set(ref.chunk_index, frame);
  }
  if (frames.size !== association.keyframe_count
      || [...frames.values()].some((frame) => frame.participants.size !== 10)) {
    invalid('keyframe roster is incomplete');
  }
  const orderedFrames = [...frames.values()].sort((a, b) => a.chunk_index - b.chunk_index);
  if (orderedFrames.some((frame, index) => index > 0
      && frame.time_ms <= orderedFrames[index - 1].time_ms)) {
    invalid('keyframe times are not strictly increasing');
  }
  const expected = [];
  const unbracketed = [];
  const distinctBrackets = new Set();
  for (const [index, row] of packets.entries()) {
    incrementMinionKillsPacketRow(row, packetPrepared, index + 1, packetPositions);
    if (row.replay_sha256 !== prepared.replaySha) {
      invalid(`packet ${index + 1} has a foreign Replay identity`);
    }
    const ref = row.raw_packet_ref;
    if (!minionBracketRef(ref, prepared, 0x03a7, 'game_chunk', 3)) {
      invalid(`packet ${index + 1} has an invalid raw reference`);
    }
    const position = `${ref.chunk_index}/${ref.decompressed_block_offset}`;
    if (positions.has(position)) invalid(`duplicate source packet reference ${position}`);
    positions.add(position);
    const time = row.replay_time_ms;
    const currentIndex = orderedFrames.findIndex((frame) => frame.time_ms >= time);
    const reason = currentIndex === -1 ? 'AFTER_LAST_SNAPSHOT'
      : orderedFrames[currentIndex].time_ms === time ? 'ON_KEYFRAME_BOUNDARY'
        : currentIndex === 0 ? 'BEFORE_FIRST_SNAPSHOT' : null;
    if (reason) {
      unbracketed.push({ replay_time_ms: time, raw_param: row.raw_param,
        reason, raw_packet_ref: ref });
      continue;
    }
    const previous = orderedFrames[currentIndex - 1];
    const current = orderedFrames[currentIndex];
    if (!(previous.time_ms < time && time < current.time_ms)) {
      invalid(`packet ${index + 1} has an invalid strict bracket`);
    }
    const participant = row.raw_param - 0x400000ae + 1;
    const beforeRow = previous.participants.get(participant);
    const afterRow = current.participants.get(participant);
    const before = beforeRow.minions_killed_raw_f32_candidate;
    const after = afterRow.minions_killed_raw_f32_candidate;
    const previousRef = beforeRow.raw_packet_ref;
    const currentRef = afterRow.raw_packet_ref;
    distinctBrackets.add(`${previous.chunk_index}/${current.chunk_index}/${participant}`);
    expected.push({
      event_type: 'INCREMENT_MINION_KEYFRAME_BRACKET_CANDIDATE',
      game_version: prepared.replayVersion, patch: '16.19',
      build_profile: INCREMENT_MINION_KEYFRAME_BRACKET_821_PROFILE.id,
      replay_sha256: prepared.replaySha,
      replay_time_ms: time, raw_param: row.raw_param,
      callback_lookup_key_candidate: row.callback_lookup_key_candidate,
      participant_id_candidate: participant,
      previous_observation_time_ms: previous.time_ms,
      current_observation_time_ms: current.time_ms,
      observation_interval_ms: current.time_ms - previous.time_ms,
      packet_offset_from_previous_ms: time - previous.time_ms,
      packet_offset_to_current_ms: current.time_ms - time,
      previous_snapshot_minions_killed_candidate: before,
      current_snapshot_minions_killed_candidate: after,
      observed_endpoint_delta_candidate: after - before,
      observation_kind: 'SAME_KEY_STRICT_ADJACENT_KEYFRAME_BRACKET',
      live_lookup_status: 'UNKNOWN', semantic_cs_effect_status: 'UNKNOWN',
      confidence: 'CANDIDATE', semantic_status: association.evidence_status,
      field_confidence: {
        replay_time_ms: 'VERIFIED_DIRECT', raw_param: 'VERIFIED_DIRECT',
        callback_lookup_key_candidate: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_TRANSFORM',
        participant_id_candidate: 'CANDIDATE_KR_821_RAW_PARAM_TAIL_ALIGNMENT',
        previous_snapshot_minions_killed_candidate:
          'CANDIDATE_821_RUNTIME_BYTE_KEYFRAME_F32_AND_REPLAY_TAIL',
        current_snapshot_minions_killed_candidate:
          'CANDIDATE_821_RUNTIME_BYTE_KEYFRAME_F32_AND_REPLAY_TAIL',
        observed_endpoint_delta_candidate: 'DERIVED_FROM_CANDIDATE_ENDPOINTS',
      },
      raw_packet_ref: ref,
      increment_minion_kills_raw_packet_ref: ref,
      previous_snapshot_raw_packet_ref: previousRef,
      current_snapshot_raw_packet_ref: currentRef,
      raw_packet_refs: [ref, previousRef, currentRef],
    });
  }
  if (!isDeepStrictEqual(unbracketed, association.unbracketed_packets)
      || expected.length !== association.event_count
      || distinctBrackets.size !== association.distinct_bracket_count
      || positions.size !== association.verified_raw_packet_count) {
    throw new EventQueryError('ASSOCIATION_METADATA_MISMATCH',
      'IncrementMinionKills source rows disagree with bracket or exclusion counts.');
  }
  return expected;
}

function associationRow(row, prepared, lineNumber, seenKeys, seenPacketPositions,
  episodePhysicalRefs, wardPairFrames, inventoryIntervalState,
  minionBracketExpected) {
  const { associationConfig, capabilityResult, replaySha, replayVersion } = prepared;
  if (!associationConfig) return;
  if (associationConfig.minionBracket) {
    const fields = Object.keys(row);
    if (fields.length !== MINION_BRACKET_ROW_FIELDS_821.size
        || fields.some((field) => !MINION_BRACKET_ROW_FIELDS_821.has(field))
        || !isDeepStrictEqual(row, minionBracketExpected[lineNumber - 1])) {
      throw new EventQueryError('INVALID_EVENT_ROW',
        `Invalid increment_minion_keyframe_bracket row at JSONL line ${lineNumber}.`,
        { line_number: lineNumber });
    }
    return;
  }
  if (associationConfig.inventoryInterval) {
    inventoryKeyframeIntervalDifferenceRow(row, prepared, lineNumber,
      inventoryIntervalState);
    return;
  }
  if (associationConfig.wardPair) {
    wardInventoryKeyframePairRow(row, prepared, lineNumber, seenKeys,
      seenPacketPositions, wardPairFrames);
    return;
  }
  if (associationConfig.episode) {
    heroDeathEpisodeRow(row, prepared, lineNumber, seenKeys, episodePhysicalRefs);
    return;
  }
  if (associationConfig.turretPair) {
    turretPairRow(row, prepared, lineNumber, seenKeys, seenPacketPositions);
    return;
  }
  if (associationConfig.nestedGroup) {
    namedMultiGroupRow(row, prepared, lineNumber, seenKeys, seenPacketPositions);
    return;
  }
  const invalid = (reason) => {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid ${associationConfig.profile.capability} row at JSONL line ${lineNumber}: ${reason}.`,
      { line_number: lineNumber });
  };
  if (row.event_type !== associationConfig.eventType
      || row.game_version !== replayVersion || row.patch !== '16.19'
      || row.build_profile !== associationConfig.profile.id
      || row.confidence !== 'CANDIDATE'
      || row.semantic_status !== capabilityResult.evidence_status) {
    invalid('candidate profile identity differs');
  }
  const grouped = Boolean(associationConfig.groupDependency);
  const dieRef = row.on_champion_die_raw_packet_ref;
  const groupRef = grouped ? row[associationConfig.groupRefField] : null;
  const heroRefs = row.hero_death_raw_packet_refs;
  const allRefs = row.raw_packet_refs;
  if (!dieRef || !Array.isArray(heroRefs) || ![3, 4].includes(heroRefs.length)
      || !Array.isArray(allRefs) || allRefs.length !== heroRefs.length + (grouped ? 2 : 1)
      || !isDeepStrictEqual(row.raw_packet_ref, grouped ? groupRef : dieRef)) {
    invalid('named raw packet references are missing or inconsistent');
  }
  const namedRefs = [dieRef, ...(grouped ? [groupRef] : []), ...heroRefs];
  const expectedRefs = grouped
    ? [...namedRefs].sort((a, b) => a.decompressed_block_offset - b.decompressed_block_offset)
    : namedRefs;
  if (!isDeepStrictEqual(allRefs, expectedRefs)) {
    invalid('raw packet references differ from named references');
  }
  const chunkIndex = dieRef.chunk_index;
  const packetPositions = new Set();
  for (const ref of namedRefs) {
    if (!ref || ref.replay_sha256 !== replaySha
        || ref.replay_time_ms !== row.replay_time_ms
        || ref.chunk_stream !== 'game_chunk'
        || !Number.isSafeInteger(ref.chunk_index) || ref.chunk_index < 0
        || ref.chunk_index !== chunkIndex
        || !Number.isSafeInteger(ref.decompressed_block_offset)
        || ref.decompressed_block_offset < 0
        || !Number.isSafeInteger(ref.raw_param) || ref.raw_param < 0
        || ref.raw_param > 0xffffffff
        || !REPLAY_SHA.test(ref.raw_payload_sha256)) {
      invalid('raw packet reference identity is incomplete or foreign');
    }
    const position = `${ref.chunk_index}/${ref.decompressed_block_offset}`;
    if (packetPositions.has(position) || seenPacketPositions.has(position)) {
      invalid('duplicate raw packet position');
    }
    packetPositions.add(position);
    seenPacketPositions.add(position);
  }
  const key = `${chunkIndex}/${row.replay_time_ms}`;
  if (seenKeys.has(key)) invalid('duplicate same-chunk, same-ms candidate');
  seenKeys.add(key);
  if (!Number.isSafeInteger(row.on_champion_die_raw_param)
      || row.on_champion_die_raw_param !== dieRef.raw_param
      || !Number.isSafeInteger(row.hero_death_victim_raw_param)
      || row.hero_death_victim_raw_param !== heroRefs[0].raw_param
      || row.hero_death_victim_raw_param !== heroRefs[1].raw_param
      || !Number.isSafeInteger(row.hero_death_die_source_network_id_candidate)
      || row.hero_death_die_source_network_id_candidate < 0
      || row.hero_death_die_source_network_id_candidate > 0xffffffff
      || !Number.isSafeInteger(row.on_champion_die_event_u32_0x04)
      || row.on_champion_die_event_u32_0x04 < 0
      || row.on_champion_die_event_u32_0x04 > 0xffffffff) {
    invalid('named packet parameters disagree with their references');
  }
  if (grouped) {
    const groupParam = row[associationConfig.groupRawParamField];
    const groupChild = row[associationConfig.groupChildField];
    if (!Number.isSafeInteger(groupParam) || groupParam !== groupRef.raw_param
        || !Number.isSafeInteger(groupChild) || groupChild < 0
        || groupChild > 0xffffffff) {
      invalid('group child parameter disagrees with packet references');
    }
  }
}

function namedMultiGroupRow(row, prepared, lineNumber, seenKeys,
  seenPacketPositions) {
  const { associationConfig, capabilityResult, replaySha, replayVersion } = prepared;
  const tripleQuadra = associationConfig.profile.capability
    === 'champion_triple_quadra_multi_group';
  const prefix = tripleQuadra ? 'on_champion_triple_quadra' : 'on_champion_double_kill';
  const childId = row[`${prefix}_child_event_id`];
  const child = tripleQuadra
    ? new Map([[0x000c, ['OnChampionTripleKill', 3]],
      [0x000d, ['OnChampionQuadraKill', 4]]]).get(childId)
    : childId === 0x000b ? ['OnChampionDoubleKill', 2] : null;
  const invalid = (reason) => {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid ${associationConfig.profile.capability} row at JSONL line ${lineNumber}: ${reason}.`,
      { line_number: lineNumber });
  };
  if (row.event_type !== associationConfig.eventType
      || row.game_version !== replayVersion || row.patch !== '16.19'
      || row.build_profile !== associationConfig.profile.id
      || row.confidence !== 'CANDIDATE'
      || row.semantic_status !== capabilityResult.evidence_status
      || row.upstream_multi_group_profile_id
        !== CHAMPION_MULTIPLE_KILL_DIE_HERO_DEATH_PAIR_821_PROFILE.id
      || !child
      || row[`${prefix}_registered_event_name`] !== child[0]
      || row.on_champion_multiple_kill_child_event_id !== 0x0009
      || row.on_champion_multiple_kill_opaque_u32_0x08 !== child[1]
      || !REPLAY_SHA.test(row[`${prefix}_event_blob_sha256`])) {
    invalid('candidate profile or named child identity differs');
  }
  const namedRef = row[`${prefix}_raw_packet_ref`];
  const multiRef = row.on_champion_multiple_kill_raw_packet_ref;
  const dieRef = row.on_champion_die_raw_packet_ref;
  const heroRefs = row.hero_death_raw_packet_refs;
  const allRefs = row.raw_packet_refs;
  if (!namedRef || !multiRef || !dieRef || !Array.isArray(heroRefs)
      || heroRefs.length < 2 || heroRefs.length > 4
      || !Array.isArray(allRefs) || allRefs.length !== heroRefs.length + 3
      || !isDeepStrictEqual(row.raw_packet_ref, namedRef)) {
    invalid('named raw packet references are missing or inconsistent');
  }
  const namedRefs = [dieRef, namedRef, multiRef, ...heroRefs];
  const expectedRefs = [...namedRefs].sort((a, b) =>
    a.decompressed_block_offset - b.decompressed_block_offset);
  if (!isDeepStrictEqual(allRefs, expectedRefs)) {
    invalid('raw packet references differ from named references');
  }
  const chunkIndex = namedRef.chunk_index;
  const packetPositions = new Set();
  for (const ref of namedRefs) {
    if (!ref || ref.replay_sha256 !== replaySha
        || ref.source_path !== namedRef.source_path
        || ref.replay_time_ms !== row.replay_time_ms
        || ref.chunk_stream !== 'game_chunk'
        || !Number.isSafeInteger(ref.chunk_index) || ref.chunk_index < 0
        || ref.chunk_index !== chunkIndex
        || ref.chunk_id !== namedRef.chunk_id
        || ref.chunk_file_offset !== namedRef.chunk_file_offset
        || !Number.isSafeInteger(ref.decompressed_block_offset)
        || ref.decompressed_block_offset < 0
        || !Number.isSafeInteger(ref.decompressed_payload_offset)
        || ref.decompressed_payload_offset <= ref.decompressed_block_offset
        || !Number.isSafeInteger(ref.packet_id) || ref.packet_id < 0
        || ref.packet_id > 0xffff
        || !Number.isSafeInteger(ref.payload_length) || ref.payload_length < 1
        || !Number.isSafeInteger(ref.raw_param) || ref.raw_param < 0
        || ref.raw_param > 0xffffffff
        || !REPLAY_SHA.test(ref.raw_payload_sha256)) {
      invalid('raw packet reference identity is incomplete or foreign');
    }
    const position = `${ref.chunk_index}/${ref.decompressed_block_offset}`;
    if (packetPositions.has(position) || seenPacketPositions.has(position)) {
      invalid('duplicate raw packet position');
    }
    packetPositions.add(position);
    seenPacketPositions.add(position);
  }
  const key = `${chunkIndex}/${row.replay_time_ms}`;
  if (seenKeys.has(key)) invalid('duplicate same-chunk, same-ms candidate');
  seenKeys.add(key);
  if (dieRef.packet_id !== 0x040a || dieRef.payload_length !== 116
      || namedRef.packet_id !== 0x040a || namedRef.payload_length !== 104
      || multiRef.packet_id !== 0x040a || multiRef.payload_length !== 88
      || heroRefs[0].packet_id !== 0x0259 || heroRefs[0].payload_length !== 5
      || heroRefs[1].packet_id !== 0x0438
      || !(dieRef.decompressed_block_offset < namedRef.decompressed_block_offset
        && namedRef.decompressed_block_offset < multiRef.decompressed_block_offset
        && multiRef.decompressed_block_offset < heroRefs[0].decompressed_block_offset
        && heroRefs[0].decompressed_block_offset < heroRefs[1].decompressed_block_offset)
      || !Number.isSafeInteger(row[`${prefix}_raw_param`])
      || row[`${prefix}_raw_param`] === 0
      || row[`${prefix}_raw_param`] !== namedRef.raw_param
      || row[`${prefix}_raw_param`] !== multiRef.raw_param
      || row.on_champion_multiple_kill_raw_param !== multiRef.raw_param) {
    invalid('packet order, shape or outer raw parameters disagree');
  }
}

function exactNamedKillPacketRow(row, prepared, lineNumber, seenPacketPositions) {
  if (!prepared.exactPacketProfile) return;
  const doubleKill = prepared.exactPacketProfile.capability
    === 'champion_double_kill_event_packet';
  const invalid = (reason) => {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid ${prepared.exactPacketProfile.capability} row at JSONL line ${lineNumber}: ${reason}.`,
      { line_number: lineNumber });
  };
  const child = doubleKill
    ? row.child_event_id === 0x000b ? ['OnChampionDoubleKill', '0x4968'] : null
    : new Map([[0x000c, ['OnChampionTripleKill', '0x49c8']],
      [0x000d, ['OnChampionQuadraKill', '0x4988']]]).get(row.child_event_id);
  const ref = row.raw_packet_ref;
  if (row.event_type !== (doubleKill
    ? 'CHAMPION_DOUBLE_KILL_EVENT_PACKET_CANDIDATE'
    : 'CHAMPION_TRIPLE_QUADRA_EVENT_PACKET_CANDIDATE')
      || row.game_version !== prepared.replayVersion || row.patch !== '16.19'
      || row.build_profile !== prepared.exactPacketProfile.id
      || row.confidence !== 'CANDIDATE'
      || row.semantic_status !== 'CANDIDATE_EXACT_RUNTIME_NAMED_ON_EVENT_CHILD'
      || !child || row.registered_event_name !== child[0]
      || row.raw_event_id_hex !== child[1]
      || !REPLAY_SHA.test(row.event_blob_sha256)
      || !ref || ref.replay_sha256 !== prepared.replaySha
      || ref.replay_time_ms !== row.replay_time_ms
      || ref.chunk_stream !== 'game_chunk'
      || !Number.isSafeInteger(ref.chunk_index) || ref.chunk_index < 0
      || !Number.isSafeInteger(ref.chunk_id)
      || !Number.isSafeInteger(ref.chunk_file_offset)
      || !Number.isSafeInteger(ref.decompressed_block_offset)
      || ref.decompressed_block_offset < 0
      || !Number.isSafeInteger(ref.decompressed_payload_offset)
      || ref.decompressed_payload_offset <= ref.decompressed_block_offset
      || ref.packet_id !== 0x040a || ref.payload_length !== 104
      || !Number.isSafeInteger(ref.raw_param) || ref.raw_param < 0
      || ref.raw_param > 0xffffffff
      || row.raw_param !== ref.raw_param
      || !REPLAY_SHA.test(ref.raw_payload_sha256)) {
    invalid('exact-build child or raw packet identity differs');
  }
  const position = `${ref.chunk_index}/${ref.decompressed_block_offset}`;
  if (seenPacketPositions.has(position)) invalid('duplicate raw packet position');
  seenPacketPositions.add(position);
}

function exactBlobPacketRow(row, prepared, lineNumber, seenPacketPositions) {
  const config = prepared.exactBlobPacketConfig;
  if (!config) return;
  const { profile, eventType, evidenceStatus, rawEventIdHex } = config;
  const invalid = (reason) => {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid ${profile.capability} row at JSONL line ${lineNumber}: ${reason}.`,
      { line_number: lineNumber });
  };
  const ref = row.raw_packet_ref;
  if (row.event_type !== eventType
      || row.game_version !== prepared.replayVersion || row.patch !== '16.19'
      || row.build_profile !== profile.id
      || row.confidence !== 'CANDIDATE'
      || row.semantic_status !== evidenceStatus
      || row.event_id !== profile.child_event_id
      || row.event_name !== profile.child_event_name
      || row.raw_event_id_hex !== rawEventIdHex
      || typeof row.event_blob_hex !== 'string'
      || !/^[0-9a-f]{216}$/.test(row.event_blob_hex)
      || !REPLAY_SHA.test(row.event_blob_sha256)
      || !ref || ref.replay_sha256 !== prepared.replaySha
      || ref.replay_time_ms !== row.replay_time_ms
      || ref.chunk_stream !== 'game_chunk'
      || !Number.isSafeInteger(ref.chunk_index) || ref.chunk_index < 0
      || !Number.isSafeInteger(ref.chunk_id) || ref.chunk_id < 0
      || !Number.isSafeInteger(ref.chunk_file_offset) || ref.chunk_file_offset < 0
      || !Number.isSafeInteger(ref.decompressed_block_offset)
      || ref.decompressed_block_offset < 0
      || !Number.isSafeInteger(ref.decompressed_payload_offset)
      || ref.decompressed_payload_offset <= ref.decompressed_block_offset
      || ref.packet_id !== profile.replay_block_packet_id
      || ref.payload_length !== profile.payload_length
      || !Number.isSafeInteger(ref.raw_param) || ref.raw_param <= 0
      || ref.raw_param > 0xffffffff
      || row.raw_param !== ref.raw_param
      || !REPLAY_SHA.test(ref.raw_payload_sha256)) {
    invalid('exact-build child, blob or raw packet identity differs');
  }
  if (crypto.createHash('sha256').update(Buffer.from(row.event_blob_hex, 'hex'))
    .digest('hex') !== row.event_blob_sha256) invalid('native blob SHA-256 differs');
  const position = `${ref.chunk_index}/${ref.decompressed_block_offset}`;
  if (seenPacketPositions.has(position)) invalid('duplicate raw packet position');
  seenPacketPositions.add(position);
}

function incrementMinionKillsPacketRow(row, prepared, lineNumber, seenPacketPositions) {
  if (prepared.eventKey !== 'increment_minion_kills_packet_candidates') return;
  const invalid = (reason) => {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid increment_minion_kills_packet row at JSONL line ${lineNumber}: ${reason}.`,
      { line_number: lineNumber });
  };
  const profile = INCREMENT_MINION_KILLS_PACKET_CANDIDATE_PROFILE_821;
  const ref = row.raw_packet_ref;
  const fields = Object.keys(row);
  const payload = row.raw_payload_hex;
  const lookupKey = lookupIncrementMinionKillsKeyFromNativeBytes(
    row.native_object_lookup_key_bytes_hex);
  if (fields.length !== INCREMENT_MINION_KILLS_ROW_FIELDS_821.size
      || fields.some((field) => !INCREMENT_MINION_KILLS_ROW_FIELDS_821.has(field))
      || row.event_type !== 'INCREMENT_MINION_KILLS_PACKET_CANDIDATE'
      || row.game_version !== prepared.replayVersion || row.patch !== '16.19'
      || row.build_profile !== profile.id
      || row.confidence !== 'CANDIDATE'
      || row.semantic_status !== 'CANDIDATE_EXACT_RUNTIME_CALLBACK_LOOKUP_KEY'
      || !Number.isSafeInteger(row.raw_param)
      || row.raw_param < 0x400000ae || row.raw_param > 0x400000b7
      || !isObservedIncrementMinionKillsPayloadHex(payload)
      || row.raw_selector_byte !== Number.parseInt(payload.slice(0, 2), 16)
      || lookupKey === null || lookupKey !== row.raw_param
      || row.callback_lookup_key_candidate !== lookupKey
      || row.callback_lookup_key_matches_raw_param !== true
      || row.conditional_counter_write_status !== 'UNKNOWN'
      || row.semantic_cs_effect_status !== 'UNKNOWN') {
    invalid('exact-build packet, callback key or unknown effect fields differ');
  }
  if (!ref || typeof ref !== 'object' || Array.isArray(ref)
      || ref.replay_sha256 !== prepared.replaySha
      || (ref.source_path !== null
        && (typeof ref.source_path !== 'string' || ref.source_path.length === 0))
      || (prepared.sourcePath !== undefined
        && ref.source_path !== prepared.sourcePath)
      || ref.chunk_stream !== 'game_chunk'
      || !Number.isSafeInteger(ref.chunk_index) || ref.chunk_index < 0
      || !Number.isSafeInteger(ref.chunk_id) || ref.chunk_id < 0
      || !Number.isSafeInteger(ref.chunk_file_offset) || ref.chunk_file_offset < 0
      || !Number.isSafeInteger(ref.decompressed_block_offset)
      || ref.decompressed_block_offset < 0
      || !Number.isSafeInteger(ref.decompressed_payload_offset)
      || ref.decompressed_payload_offset <= ref.decompressed_block_offset
      || ref.packet_id !== profile.replay_block_packet_id
      || ref.replay_time_ms !== row.replay_time_ms
      || ref.payload_length !== 3
      || ref.raw_param !== row.raw_param
      || ref.raw_payload_sha256 !== crypto.createHash('sha256')
        .update(Buffer.from(payload, 'hex')).digest('hex')) {
    invalid('raw packet source, framing or payload SHA-256 differs');
  }
  const position = `${ref.chunk_index}/${ref.decompressed_block_offset}`;
  if (seenPacketPositions.has(position)) invalid('duplicate raw packet position');
  seenPacketPositions.add(position);
}

function faceDirectionRosterPairRow(row, prepared, lineNumber, state) {
  if (prepared.eventKey !== 'face_direction_keyframe_roster_pair_candidates') return;
  const invalid = (reason) => {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid FaceDirection roster pair at JSONL line ${lineNumber}: ${reason}.`,
      { line_number: lineNumber });
  };
  const profile = FACE_DIRECTION_KEYFRAME_ROSTER_PAIR_821_PROFILE;
  const statsRef = row.hero_stats_raw_packet_ref;
  const faceRef = row.face_direction_raw_packet_ref;
  const fields = Object.keys(row);
  const param = row.hero_raw_param;
  const participant = row.hero_stats_participant_id_candidate;
  const payloadHex = row.face_raw_payload_hex;
  if (fields.length !== FACE_DIRECTION_ROSTER_PAIR_ROW_FIELDS_821.size
      || fields.some((field) => !FACE_DIRECTION_ROSTER_PAIR_ROW_FIELDS_821.has(field))
      || row.event_type !== 'FACE_DIRECTION_KEYFRAME_ROSTER_PAIR_CANDIDATE'
      || row.game_version !== prepared.replayVersion || row.patch !== '16.19'
      || row.build_profile !== profile.id
      || row.confidence !== 'CANDIDATE'
      || row.semantic_status !== profile.evidence_status
      || row.pair_basis !== 'SAME_KEYFRAME_CHUNK_TIME_FULL_RAW_PARAM_STATS_BEFORE_FACE'
      || row.actor_assignment_status !== 'UNKNOWN'
      || row.semantic_direction_effect_status !== 'UNKNOWN'
      || !Number.isSafeInteger(param) || param < 0x400000ae || param > 0x400000b7
      || participant !== param - 0x400000ae + 1
      || !Number.isSafeInteger(row.keyframe_chunk_index)
      || row.keyframe_chunk_index < 0
      || !Array.isArray(row.raw_packet_refs) || row.raw_packet_refs.length !== 2
      || !isDeepStrictEqual(row.raw_packet_refs, [statsRef, faceRef])
      || typeof payloadHex !== 'string' || !/^83[0-9a-f]{24}$/.test(payloadHex)
      || row.face_raw_selector_byte !== 0x83) {
    invalid('exact-build profile, roster label, candidate limits or named references differ');
  }
  const validRef = (ref, packetId, length) => ref && typeof ref === 'object'
    && !Array.isArray(ref)
    && ref.replay_sha256 === prepared.replaySha
    && (prepared.sourcePath === undefined || ref.source_path === prepared.sourcePath)
    && (ref.source_path === null
      || (typeof ref.source_path === 'string' && ref.source_path.length > 0))
    && ref.chunk_stream === 'keyframe'
    && ref.chunk_index === row.keyframe_chunk_index
    && Number.isSafeInteger(ref.chunk_id) && ref.chunk_id >= 0
    && Number.isSafeInteger(ref.chunk_file_offset) && ref.chunk_file_offset >= 0
    && Number.isSafeInteger(ref.decompressed_block_offset)
    && ref.decompressed_block_offset >= 0
    && Number.isSafeInteger(ref.decompressed_payload_offset)
    && ref.decompressed_payload_offset > ref.decompressed_block_offset
    && ref.packet_id === packetId && ref.payload_length === length
    && ref.raw_param === param && ref.replay_time_ms === row.replay_time_ms
    && REPLAY_SHA.test(ref.raw_payload_sha256);
  if (!validRef(statsRef, 0x0089, 1263) || !validRef(faceRef, 0x038e, 13)
      || statsRef.chunk_id !== faceRef.chunk_id
      || statsRef.chunk_file_offset !== faceRef.chunk_file_offset
      || statsRef.source_path !== faceRef.source_path
      || statsRef.decompressed_block_offset >= faceRef.decompressed_block_offset
      || faceRef.raw_payload_sha256 !== crypto.createHash('sha256')
        .update(Buffer.from(payloadHex, 'hex')).digest('hex')) {
    invalid('full raw key, keyframe time, Stats-before-Face order or packet bytes differ');
  }
  const bytes = transformFaceDirectionVectorBytes821(Buffer.from(payloadHex, 'hex'));
  const vector = row.packet_vector_xyz_f32_candidate;
  if (!vector || typeof vector !== 'object' || Array.isArray(vector)
      || Object.keys(vector).length !== 3
      || vector.x !== bytes.readFloatLE(0)
      || vector.y !== bytes.readFloatLE(4)
      || vector.z !== bytes.readFloatLE(8)) {
    invalid('packet-local vector differs from exact 821 byte transform');
  }
  const frame = state.frames.get(row.keyframe_chunk_index)
    ?? { timeMs: row.replay_time_ms, participants: new Set() };
  if (frame.timeMs !== row.replay_time_ms || frame.participants.has(participant)) {
    invalid('duplicate or contradictory HeroStats roster observation');
  }
  frame.participants.add(participant);
  state.frames.set(row.keyframe_chunk_index, frame);
  for (const ref of [statsRef, faceRef]) {
    const position = `${ref.chunk_index}/${ref.decompressed_block_offset}`;
    if (state.positions.has(position)) invalid('duplicate raw packet position');
    state.positions.add(position);
  }
}

function candidateChildEventId(row, eventKey, lineNumber) {
  const field = eventKey === 'champion_triple_quadra_multi_group_candidates'
    ? 'on_champion_triple_quadra_child_event_id'
    : eventKey === 'champion_double_kill_multi_group_candidates'
      ? 'on_champion_double_kill_child_event_id' : 'child_event_id';
  const value = row[field];
  if (value == null) return { value: null, available: false };
  if (!Number.isSafeInteger(value)
      || !CHILD_EVENT_ID_FILTERS_821[eventKey].includes(value)) {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid ${field} at JSONL line ${lineNumber}.`, { line_number: lineNumber });
  }
  return { value, available: true };
}

function assistingParticipantsCandidate(row, prepared, lineNumber) {
  const invalid = (reason) => {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid hero_assist candidate at JSONL line ${lineNumber}: ${reason}.`,
      { line_number: lineNumber });
  };
  if (row.event_type !== 'HERO_ASSIST_ATTRIBUTION_CANDIDATE'
      || row.game_version !== prepared.replayVersion || row.patch !== '16.19'
      || row.build_profile !== HERO_ASSIST_CANDIDATE_PROFILE_821.id
      || row.confidence !== 'CANDIDATE') {
    invalid('exact-build candidate identity differs');
  }
  const hasParticipants = Object.hasOwn(row, 'assisting_participant_ids_candidate');
  const participants = row.assisting_participant_ids_candidate;
  const killer = row.killer_participant_id_candidate;
  const victim = row.victim_participant_id_candidate;
  if (!Number.isSafeInteger(victim) || victim < 1 || victim > 10
      || (killer != null && (!Number.isSafeInteger(killer)
        || killer < 1 || killer > 10 || killer === victim))) {
    invalid('victim or killer participant is invalid');
  }
  if (!hasParticipants) return { values: [], available: false };
  if (participants == null) {
    if (killer != null || row.assist_pair_count != null
        || row.assist_observation_status !== 'UNAVAILABLE_NONHERO_SOURCE'
        || row.semantic_status !== 'UNAVAILABLE_NONHERO_SOURCE') {
      invalid('unavailable assist list conflicts with candidate status');
    }
    return { values: [], available: false };
  }
  if (!Array.isArray(participants)
      || !Number.isSafeInteger(row.assist_pair_count)
      || row.assist_pair_count !== participants.length
      || killer == null
      || row.assist_observation_status
        !== 'CANDIDATE_821_CO_TIMED_ASSIST_PAIR_TAIL_ALIGNMENT'
      || row.semantic_status
        !== 'CANDIDATE_821_CO_TIMED_ASSIST_PAIR_TAIL_ALIGNMENT') {
    invalid('available assist list or count conflicts with candidate status');
  }
  let previous = 0;
  for (const participant of participants) {
    if (!Number.isSafeInteger(participant) || participant < 1 || participant > 10
        || participant <= previous || participant === victim || participant === killer) {
      invalid('assisting participant IDs must be sorted, unique, and exclude victim and killer');
    }
    previous = participant;
  }
  return { values: participants, available: true };
}

function killerParticipantCandidate(row, prepared, lineNumber, config) {
  const invalid = (reason) => {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid ${prepared.capability} killer candidate at JSONL line ${lineNumber}: ${reason}.`,
      { line_number: lineNumber });
  };
  if (row.event_type !== config.eventType
      || row.game_version !== prepared.replayVersion || row.patch !== '16.19'
      || row.build_profile !== config.profile.id
      || row.confidence !== 'CANDIDATE') {
    invalid('exact-build candidate identity differs');
  }
  const victim = row[config.victimField];
  if (!Number.isSafeInteger(victim) || victim < 1 || victim > 10) {
    invalid('victim participant is invalid');
  }
  if (!Object.hasOwn(row, 'killer_participant_id_candidate')) {
    return { value: null, available: false };
  }
  const killer = row.killer_participant_id_candidate;
  if (killer !== null && (!Number.isSafeInteger(killer)
      || killer < 1 || killer > 10 || killer === victim)) {
    invalid('killer participant must be 1..10 and differ from victim');
  }
  const assist = prepared.eventKey === 'hero_assist_candidates';
  const expectedFieldStatus = killer === null
    ? 'UNAVAILABLE' : 'CANDIDATE_821_SOURCE_ID_KILL_TAIL_ALIGNMENT';
  if (row.field_confidence?.killer_participant_id_candidate !== expectedFieldStatus
      || row.semantic_status !== (assist && killer === null
        ? 'UNAVAILABLE_NONHERO_SOURCE' : config.evidenceStatus)
      || (assist && row.assist_observation_status !== (killer === null
        ? 'UNAVAILABLE_NONHERO_SOURCE' : config.evidenceStatus))) {
    invalid('killer candidate status conflicts with its value');
  }
  return { value: killer, available: killer !== null };
}

function validateFilters(options) {
  const { fromMs = null, toMs = null, participant = null,
    killerParticipant = null, assistingParticipant = null, rawParam = null,
    itemId = null, previousItemId = null, slot = null,
    opaqueU32 = null, opaquePair = null, opaqueI32 = null,
    childEventId = null, limit = null, latestPerParticipant = false } = options;
  if (typeof latestPerParticipant !== 'boolean') {
    throw new EventQueryError('INVALID_FILTER', 'Invalid latestPerParticipant query filter.');
  }
  for (const [name, value, minimum, maximum] of [
    ['fromMs', fromMs, 0, Number.MAX_SAFE_INTEGER],
    ['toMs', toMs, 0, Number.MAX_SAFE_INTEGER],
    ['participant', participant, 1, 10],
    ['killerParticipant', killerParticipant, 1, 10],
    ['assistingParticipant', assistingParticipant, 1, 10],
    ['rawParam', rawParam, 0, 0xffffffff],
    ['itemId', itemId, 0, 0xffffffff],
    ['previousItemId', previousItemId, 0, 0xffffffff],
    ['slot', slot, 0, 9],
    ['opaqueU32', opaqueU32, 0, 0xffffffff],
    ['opaqueI32', opaqueI32, -0x80000000, 0x7fffffff],
    ['childEventId', childEventId, 0, 0xffffffff],
    ['limit', limit, 1, Number.MAX_SAFE_INTEGER],
  ]) {
    if (value != null && (!Number.isSafeInteger(value) || value < minimum || value > maximum)) {
      throw new EventQueryError('INVALID_FILTER', `Invalid ${name} query filter.`);
    }
  }
  if (opaquePair != null && (!opaquePair || typeof opaquePair !== 'object'
      || !Number.isSafeInteger(opaquePair.u32) || opaquePair.u32 < 0
      || opaquePair.u32 > 0xffffffff || !Number.isSafeInteger(opaquePair.u8)
      || opaquePair.u8 < 0 || opaquePair.u8 > 0xff)) {
    throw new EventQueryError('INVALID_FILTER', 'Invalid opaquePair query filter.');
  }
  if (fromMs != null && toMs != null && fromMs > toMs) {
    throw new EventQueryError('INVALID_FILTER', 'fromMs must not exceed toMs.');
  }
}

async function streamEventQuery(prepared, options, emitLine) {
  validateFilters(options);
  const { fromMs = null, toMs = null, participant = null,
    killerParticipant = null, assistingParticipant = null, rawParam = null,
    itemId = null, previousItemId = null, slot = null,
    opaqueU32 = null, opaquePair = null, opaqueI32 = null,
    childEventId = null, limit = null, latestPerParticipant = false } = options;
  if (latestPerParticipant
      && (prepared.replayVersion !== '16.19.821.7343'
        || prepared.capabilityStatus !== 'CANDIDATE'
        || !LATEST_PARTICIPANT_EVENTS_821.has(prepared.eventKey))) {
    throw new EventQueryError('UNSUPPORTED_FILTER',
      '--latest-per-participant requires a supported exact 16.19.821.7343 participant candidate event.');
  }
  const inventoryPacketEvent = [
    'hero_inventory_packet_candidates',
    'hero_inventory_broadcast_packet_candidates',
    'hero_inventory_set_item_packet_candidates',
    'ward_inventory_keyframe_pair_candidates',
    'inventory_keyframe_interval_difference_candidates',
  ].includes(prepared.eventKey);
  const killerConfig = KILLER_PARTICIPANT_EVENTS_821[prepared.eventKey] ?? null;
  if (killerParticipant != null) {
    if (!killerConfig || prepared.replayVersion !== killerConfig.profile.replay_version) {
      throw new EventQueryError('UNSUPPORTED_FILTER',
        '--killer-participant requires exact 16.19.821.7343 hero_death, hero_assist or hero_death_episode candidates.');
    }
    if (prepared.capabilityStatus !== 'CANDIDATE'
        || prepared.capabilityResult.profile_id !== killerConfig.profile.id
        || prepared.capabilityResult.evidence_status !== killerConfig.evidenceStatus) {
      throw new EventQueryError('CAPABILITY_METADATA_MISMATCH',
        `${prepared.capability} killer candidate identity differs from its exact-build profile.`,
        { capability: prepared.capability });
    }
  }
  if (assistingParticipant != null) {
    const assistProfile = prepared.eventKey === 'hero_death_episode_candidates'
      ? HERO_DEATH_EPISODE_821_PROFILE : HERO_ASSIST_CANDIDATE_PROFILE_821;
    if (!['hero_assist_candidates', 'hero_death_episode_candidates']
      .includes(prepared.eventKey)
        || prepared.replayVersion !== assistProfile.replay_version) {
      throw new EventQueryError('UNSUPPORTED_FILTER',
        '--assisting-participant requires exact 16.19.821.7343 hero_assist or hero_death_episode candidates.');
    }
    if (prepared.capabilityStatus !== 'CANDIDATE'
        || prepared.capabilityResult.profile_id !== assistProfile.id
        || prepared.capabilityResult.evidence_status
          !== (prepared.eventKey === 'hero_death_episode_candidates'
            ? 'CANDIDATE_821_DEATH_ASSIST_TIMER_RETURN_ASSOCIATION'
            : 'CANDIDATE_821_CO_TIMED_ASSIST_PAIR_TAIL_ALIGNMENT')) {
      throw new EventQueryError('CAPABILITY_METADATA_MISMATCH',
        `${prepared.capability} candidate identity differs from its exact-build profile.`,
        { capability: prepared.capability });
    }
  }
  if ((itemId != null || slot != null) && (!inventoryPacketEvent
      || prepared.replayVersion !== '16.19.821.7343')) {
    throw new EventQueryError('UNSUPPORTED_FILTER',
      '--item-id and --slot require an exact-821 inventory packet, ward/inventory pair, or keyframe interval difference candidate event.');
  }
  if (previousItemId != null
      && (prepared.eventKey !== 'inventory_keyframe_interval_difference_candidates'
        || prepared.replayVersion !== '16.19.821.7343')) {
    throw new EventQueryError('UNSUPPORTED_FILTER',
      '--previous-item-id requires exact 16.19.821.7343 inventory keyframe interval difference candidates.');
  }
  const opaqueU32Fields = OPAQUE_U32_FIELDS_821[prepared.eventKey] ?? null;
  if (opaqueU32 != null && (!opaqueU32Fields
      || prepared.replayVersion !== '16.19.821.7343')) {
    throw new EventQueryError('UNSUPPORTED_FILTER',
      '--opaque-u32 requires a supported 821 packet or packet-association candidate event.');
  }
  const opaquePairFields = OPAQUE_PAIR_FIELDS_821[prepared.eventKey] ?? null;
  if (opaquePair != null && (!opaquePairFields
      || prepared.replayVersion !== '16.19.821.7343')) {
    throw new EventQueryError('UNSUPPORTED_FILTER',
      '--opaque-pair requires an 821 Buff Add, Remove, or UpdateNumCounter packet event.');
  }
  if (opaqueI32 != null && (prepared.eventKey !== 'cast_spell_ans_packet_candidates'
      || prepared.replayVersion !== '16.19.821.7343')) {
    throw new EventQueryError('UNSUPPORTED_FILTER',
      '--opaque-i32 requires a 16.19.821.7343 CastSpellAns packet candidate event.');
  }
  const allowedChildIds = CHILD_EVENT_ID_FILTERS_821[prepared.eventKey] ?? null;
  if (childEventId != null && (!allowedChildIds
      || prepared.replayVersion !== '16.19.821.7343')) {
    throw new EventQueryError('UNSUPPORTED_FILTER',
      '--child-event-id requires a supported 16.19.821.7343 named child candidate event.');
  }
  if (childEventId != null && !allowedChildIds.includes(childEventId)) {
    throw new EventQueryError('INVALID_FILTER',
      '--child-event-id is not one of the selected event\'s exact child IDs.');
  }
  let scannedCount = 0;
  let matchedCount = 0;
  let emittedCount = 0;
  let latestParticipantUnavailableCount = 0;
  const latestByParticipant = new Map();
  let participantUnavailableCount = 0;
  let killerParticipantUnavailableCount = 0;
  let killerParticipantAvailableCount = 0;
  let assistingParticipantUnavailableCount = 0;
  let assistingParticipantAvailableCount = 0;
  let rawParamUnavailableCount = 0;
  let itemIdUnavailableCount = 0;
  let itemIdAvailableCount = 0;
  let slotUnavailableCount = 0;
  let slotAvailableCount = 0;
  let opaqueU32UnavailableCount = 0;
  let opaqueU32AvailableCount = 0;
  let opaquePairUnavailableCount = 0;
  let opaquePairAvailableCount = 0;
  let opaqueI32UnavailableCount = 0;
  let opaqueI32AvailableCount = 0;
  let childEventIdUnavailableCount = 0;
  let childEventIdAvailableCount = 0;
  let tripleGroupCount = 0;
  let quadraGroupCount = 0;
  let observedReturnCount = 0;
  let terminalUnobservedCount = 0;
  const associationKeys = new Set();
  const associationPacketPositions = new Set();
  const episodePhysicalRefs = new Map();
  const wardPairFrames = new Map();
  const inventoryIntervalState = { pairs: new Map(), frameTimes: new Map(),
    endpoints: new Map(), changedSlotCount: 0 };
  const faceRosterPairState = { frames: new Map(), positions: new Set() };
  const minionBracketExpected = prepared.associationConfig?.minionBracket
    ? await loadMinionBracketExpectedRows(prepared) : null;
  const input = fs.createReadStream(prepared.inputPath, { encoding: 'utf8' });
  const lines = readline.createInterface({ input, crlfDelay: Infinity });
  try {
    for await (const line of lines) {
      const lineNumber = ++scannedCount;
      let row;
      try {
        row = JSON.parse(line);
      } catch (error) {
        throw new EventQueryError('INVALID_EVENT_ROW',
          `Invalid JSONL at line ${lineNumber}: ${error.message}`,
          { line_number: lineNumber });
      }
      if (row === null || typeof row !== 'object' || Array.isArray(row)) {
        throw new EventQueryError('INVALID_EVENT_ROW',
          `Event JSONL line ${lineNumber} is not an object.`, { line_number: lineNumber });
      }
      const replayTime = rowReplayTime(row, lineNumber);
      const subject = subjectParticipant(row, lineNumber, prepared.eventKey);
      if (latestPerParticipant && !subject.observed) {
        throw new EventQueryError('INVALID_EVENT_ROW',
          `Missing subject participant field at JSONL line ${lineNumber}.`,
          { line_number: lineNumber });
      }
      if (row.replay_sha256 !== prepared.replaySha
          || (row.raw_packet_ref != null
            && row.raw_packet_ref.replay_sha256 !== prepared.replaySha)
          || (row.raw_packet_refs != null && (!Array.isArray(row.raw_packet_refs)
            || row.raw_packet_refs.some((ref) => ref?.replay_sha256 !== prepared.replaySha)))) {
        throw new EventQueryError('ARTIFACT_IDENTITY_MISMATCH',
          `Event JSONL line ${lineNumber} has a different Replay SHA-256.`,
          { line_number: lineNumber });
      }
      exactNamedKillPacketRow(row, prepared, lineNumber,
        associationPacketPositions);
      exactBlobPacketRow(row, prepared, lineNumber,
        associationPacketPositions);
      incrementMinionKillsPacketRow(row, prepared, lineNumber,
        associationPacketPositions);
      faceDirectionRosterPairRow(row, prepared, lineNumber, faceRosterPairState);
      if (prepared.eventKey === 'revive_ally_event_packet_candidates'
          && (row.event_type !== 'REVIVE_ALLY_EVENT_PACKET_CANDIDATE'
            || row.game_version !== prepared.replayVersion
            || row.patch !== '16.19'
            || row.build_profile !== REVIVE_ALLY_EVENT_PACKET_821_PROFILE.id
            || row.event_id !== REVIVE_ALLY_EVENT_PACKET_821_PROFILE.child_event_id
            || row.event_name !== REVIVE_ALLY_EVENT_PACKET_821_PROFILE.child_event_name
            || row.raw_event_id_hex !== '0x49ca'
            || row.confidence !== 'CANDIDATE'
            || row.semantic_status !== 'CANDIDATE_EXACT_RUNTIME_ON_REVIVE_ALLY_PACKET')) {
        throw new EventQueryError('INVALID_EVENT_ROW',
          `OnReviveAlly candidate identity differs at JSONL line ${lineNumber}.`,
          { line_number: lineNumber });
      }
      associationRow(row, prepared, lineNumber, associationKeys,
        associationPacketPositions, episodePhysicalRefs, wardPairFrames,
        inventoryIntervalState, minionBracketExpected);
      if (prepared.eventKey === 'hero_death_episode_candidates') {
        if (row.return_observation_status === 'OBSERVED_RETURN') observedReturnCount += 1;
        else terminalUnobservedCount += 1;
      }
      if (prepared.eventKey === 'champion_triple_quadra_multi_group_candidates') {
        if (row.on_champion_triple_quadra_child_event_id === 0x000c) {
          tripleGroupCount += 1;
        } else {
          quadraGroupCount += 1;
        }
      }
      const params = rawParam == null ? null : rawPacketParams(row, lineNumber);
      const inventoryRecordRow = prepared.eventKey
        === 'inventory_keyframe_interval_difference_candidates'
        ? { records_candidate: row.changed_slots_candidate.map((change) => ({
          slot_candidate: change.slot_candidate,
          item_id_candidate: change.current_item_id_candidate,
        })), record_count: row.changed_slot_count }
        : prepared.eventKey === 'ward_inventory_keyframe_pair_candidates'
          ? { records_candidate: row.inventory_records_candidate,
            record_count: row.inventory_record_count } : row;
      const items = itemId == null ? null
        : prepared.eventKey === 'hero_inventory_set_item_packet_candidates'
          ? packetScalarItemId(row, lineNumber)
          : packetRecordItemIds(inventoryRecordRow, lineNumber,
            ['hero_inventory_broadcast_packet_candidates',
              'ward_inventory_keyframe_pair_candidates',
              'inventory_keyframe_interval_difference_candidates']
              .includes(prepared.eventKey));
      const slots = slot == null ? null
        : prepared.eventKey === 'hero_inventory_set_item_packet_candidates'
          ? packetScalarSlot(row, lineNumber)
          : packetRecordSlots(inventoryRecordRow, lineNumber);
      const opaqueValues = opaqueU32 == null ? null
        : opaqueU32Values(row, lineNumber, opaqueU32Fields);
      const pairValue = opaquePair == null ? null
        : opaquePairValue(row, lineNumber, opaquePairFields);
      const opaqueI32Field = opaqueI32 == null ? null
        : castSpellAnsOpaqueI32(row, lineNumber);
      const childId = childEventId == null ? null
        : candidateChildEventId(row, prepared.eventKey, lineNumber);
      const assistingParticipants = assistingParticipant == null ? null
        : prepared.eventKey === 'hero_death_episode_candidates'
          ? { values: row.assisting_participant_ids_candidate ?? [],
            available: row.assisting_participant_ids_candidate !== null }
          : assistingParticipantsCandidate(row, prepared, lineNumber);
      const killerCandidate = killerParticipant == null ? null
        : killerParticipantCandidate(row, prepared, lineNumber, killerConfig);
      if (participant != null && subject.value == null) participantUnavailableCount += 1;
      if (killerParticipant != null && !killerCandidate.available) {
        killerParticipantUnavailableCount += 1;
      }
      if (killerParticipant != null && killerCandidate.available) {
        killerParticipantAvailableCount += 1;
      }
      if (assistingParticipant != null && !assistingParticipants.available) {
        assistingParticipantUnavailableCount += 1;
      }
      if (assistingParticipant != null && assistingParticipants.available) {
        assistingParticipantAvailableCount += 1;
      }
      if (rawParam != null && params.length === 0) rawParamUnavailableCount += 1;
      if (itemId != null && items.unavailable) itemIdUnavailableCount += 1;
      if (itemId != null && items.available) itemIdAvailableCount += 1;
      if (slot != null && slots.unavailable) slotUnavailableCount += 1;
      if (slot != null && slots.available) slotAvailableCount += 1;
      if (opaqueU32 != null && opaqueValues.unavailable) opaqueU32UnavailableCount += 1;
      if (opaqueU32 != null && opaqueValues.available) opaqueU32AvailableCount += 1;
      if (opaquePair != null && !pairValue.available) opaquePairUnavailableCount += 1;
      if (opaquePair != null && pairValue.available) opaquePairAvailableCount += 1;
      if (opaqueI32 != null && !opaqueI32Field.available) opaqueI32UnavailableCount += 1;
      if (opaqueI32 != null && opaqueI32Field.available) opaqueI32AvailableCount += 1;
      if (childEventId != null && !childId.available) childEventIdUnavailableCount += 1;
      if (childEventId != null && childId.available) childEventIdAvailableCount += 1;
      if ((fromMs != null && replayTime < fromMs)
          || (toMs != null && replayTime > toMs)
          || (participant != null && subject.value !== participant)
          || (killerParticipant != null && killerCandidate.value !== killerParticipant)
          || (assistingParticipant != null
            && !assistingParticipants.values.includes(assistingParticipant))
          || (rawParam != null && !params.includes(rawParam))
          || (itemId != null && !items.values.includes(itemId))
          || (slot != null && !slots.values.includes(slot))
          || (prepared.eventKey === 'inventory_keyframe_interval_difference_candidates'
            && (previousItemId != null || itemId != null || slot != null)
            && !row.changed_slots_candidate.some((change) =>
              (previousItemId == null
                || change.previous_item_id_candidate === previousItemId)
              && (itemId == null || change.current_item_id_candidate === itemId)
              && (slot == null || change.slot_candidate === slot)))
          || (itemId != null && slot != null
            && prepared.eventKey !== 'inventory_keyframe_interval_difference_candidates'
            && (prepared.eventKey === 'hero_inventory_set_item_packet_candidates'
              ? (row.item_id_candidate !== itemId || row.slot_candidate !== slot)
              : !inventoryRecordRow.records_candidate.some((record) =>
                record.item_id_candidate === itemId && record.slot_candidate === slot)))
          || (opaqueU32 != null && !opaqueValues.values.includes(opaqueU32))
          || (opaquePair != null && (!pairValue.available
            || pairValue.u32 !== opaquePair.u32 || pairValue.u8 !== opaquePair.u8))
          || (opaqueI32 != null && opaqueI32Field.value !== opaqueI32)
          || (childEventId != null && childId.value !== childEventId)) continue;
      matchedCount += 1;
      if (latestPerParticipant) {
        if (subject.value === null) {
          latestParticipantUnavailableCount += 1;
        } else {
          const previous = latestByParticipant.get(subject.value);
          if (!previous || replayTime >= previous.replayTime) {
            latestByParticipant.set(subject.value, { replayTime, lineNumber, line });
          }
        }
        continue;
      }
      if (limit == null || emittedCount < limit) {
        // Reuse the original line so candidate grades, provenance, and field order survive.
        await emitLine(`${line}\n`);
        emittedCount += 1;
      }
    }
  } finally {
    lines.close();
    input.destroy();
  }
  if (scannedCount !== prepared.declaredCount) {
    throw new EventQueryError('EVENT_COUNT_MISMATCH',
      'JSONL row count disagrees with event_counts and the capability result.',
      { scanned_count: scannedCount, declared_event_count: prepared.declaredCount });
  }
  if (prepared.eventKey === 'hero_death_episode_candidates'
      && (observedReturnCount !== prepared.capabilityResult.observed_return_count
        || terminalUnobservedCount
          !== prepared.capabilityResult.terminal_unobserved_count
        || episodePhysicalRefs.size
          !== prepared.capabilityResult.verified_raw_packet_count)) {
    throw new EventQueryError('EVENT_COUNT_MISMATCH',
      'Episode return states or unique raw packet counts disagree with association metadata.',
      { observed_return_count: observedReturnCount,
        terminal_unobserved_count: terminalUnobservedCount,
        verified_raw_packet_count: episodePhysicalRefs.size });
  }
  if (prepared.eventKey === 'ward_inventory_keyframe_pair_candidates'
      && (wardPairFrames.size * 10 !== scannedCount
        || [...wardPairFrames.values()].some((frame) =>
          frame.participants.size !== 10)
        || associationPacketPositions.size !== 2 * scannedCount)) {
    throw new EventQueryError('EVENT_COUNT_MISMATCH',
      'Ward/inventory keyframes lack complete participant rosters or unique paired refs.',
      { scanned_count: scannedCount, keyframe_count: wardPairFrames.size,
        unique_raw_packet_count: associationPacketPositions.size });
  }
  if (prepared.eventKey === 'face_direction_keyframe_roster_pair_candidates'
      && (faceRosterPairState.frames.size !== prepared.capabilityResult.keyframe_count
        || [...faceRosterPairState.frames.values()].some((frame) =>
          frame.participants.size !== 10)
        || faceRosterPairState.positions.size !== 2 * scannedCount)) {
    throw new EventQueryError('EVENT_COUNT_MISMATCH',
      'FaceDirection roster pairs lack complete keyframes or unique packet references.',
      { scanned_count: scannedCount,
        keyframe_count: faceRosterPairState.frames.size,
        unique_raw_packet_count: faceRosterPairState.positions.size });
  }
  if (prepared.eventKey === 'inventory_keyframe_interval_difference_candidates') {
    const association = prepared.capabilityResult;
    const frameTimes = [...inventoryIntervalState.frameTimes.entries()]
      .sort(([a], [b]) => a - b);
    if (inventoryIntervalState.changedSlotCount !== association.changed_slot_count
        || inventoryIntervalState.pairs.size > association.keyframe_count - 1
        || inventoryIntervalState.frameTimes.size > association.keyframe_count
        || frameTimes.some(([, time], index) => index > 0
          && time <= frameTimes[index - 1][1])) {
      throw new EventQueryError('EVENT_COUNT_MISMATCH',
        'Inventory interval rows disagree with changed slots or ordered keyframes.',
        { changed_slot_count: inventoryIntervalState.changedSlotCount,
          frame_pair_count: inventoryIntervalState.pairs.size,
          observed_frame_count: inventoryIntervalState.frameTimes.size });
    }
  }
  if (prepared.eventKey === 'champion_triple_quadra_multi_group_candidates'
      && (tripleGroupCount
        !== prepared.capabilityResult.matched_multi_u32_0x08_3_count
        || quadraGroupCount
          !== prepared.capabilityResult.matched_multi_u32_0x08_4_count)) {
    throw new EventQueryError('EVENT_COUNT_MISMATCH',
      'Triple/Quadra candidate row counts disagree with association metadata.',
      { triple_count: tripleGroupCount, quadra_count: quadraGroupCount });
  }
  if (participant != null && scannedCount > 0 && participantUnavailableCount === scannedCount) {
    throw new EventQueryError('PARTICIPANT_UNAVAILABLE',
      'This event stream has no resolved subject participant for filtering.',
      { scanned_count: scannedCount, participant_unavailable_count: participantUnavailableCount,
        capability_status: prepared.capabilityStatus });
  }
  if (killerParticipant != null && scannedCount > 0
      && killerParticipantAvailableCount === 0) {
    throw new EventQueryError('KILLER_PARTICIPANT_UNAVAILABLE',
      'This event stream has no available killer participant candidate for filtering.',
      { scanned_count: scannedCount,
        killer_participant_unavailable_count: killerParticipantUnavailableCount,
        capability_status: prepared.capabilityStatus });
  }
  if (assistingParticipant != null && scannedCount > 0
      && assistingParticipantAvailableCount === 0) {
    throw new EventQueryError('ASSISTING_PARTICIPANT_UNAVAILABLE',
      'This event stream has no available assist candidate list for filtering.',
      { scanned_count: scannedCount,
        assisting_participant_unavailable_count: assistingParticipantUnavailableCount,
        capability_status: prepared.capabilityStatus });
  }
  if (rawParam != null && scannedCount > 0 && rawParamUnavailableCount === scannedCount) {
    throw new EventQueryError('RAW_PARAM_UNAVAILABLE',
      'This event stream has no recorded raw packet parameter for filtering.',
      { scanned_count: scannedCount, raw_param_unavailable_count: rawParamUnavailableCount,
        capability_status: prepared.capabilityStatus });
  }
  if (itemId != null && scannedCount > 0 && itemIdAvailableCount === 0) {
    throw new EventQueryError('ITEM_ID_UNAVAILABLE',
      'This event stream has no decoded packet record item ID for filtering.',
      { scanned_count: scannedCount, item_id_unavailable_count: itemIdUnavailableCount,
        capability_status: prepared.capabilityStatus });
  }
  if (slot != null && scannedCount > 0 && slotAvailableCount === 0) {
    throw new EventQueryError('SLOT_UNAVAILABLE',
      'This event stream has no decoded packet record slot for filtering.',
      { scanned_count: scannedCount, slot_unavailable_count: slotUnavailableCount,
        capability_status: prepared.capabilityStatus });
  }
  if (opaqueU32 != null && scannedCount > 0 && opaqueU32AvailableCount === 0) {
    throw new EventQueryError('OPAQUE_U32_UNAVAILABLE',
      'This event stream has no decoded anonymous u32 field for filtering.',
      { scanned_count: scannedCount,
        opaque_u32_unavailable_count: opaqueU32UnavailableCount,
        capability_status: prepared.capabilityStatus });
  }
  if (opaquePair != null && scannedCount > 0 && opaquePairAvailableCount === 0) {
    throw new EventQueryError('OPAQUE_PAIR_UNAVAILABLE',
      'This event stream has no decoded anonymous Buff u32/u8 pair for filtering.',
      { scanned_count: scannedCount,
        opaque_pair_unavailable_count: opaquePairUnavailableCount,
        capability_status: prepared.capabilityStatus });
  }
  if (opaqueI32 != null && scannedCount > 0 && opaqueI32AvailableCount === 0) {
    throw new EventQueryError('OPAQUE_I32_UNAVAILABLE',
      'This event stream has no decoded CastSpellAns opaque_i32_0x14c for filtering.',
      { scanned_count: scannedCount,
        opaque_i32_unavailable_count: opaqueI32UnavailableCount,
        capability_status: prepared.capabilityStatus });
  }
  if (childEventId != null && scannedCount > 0 && childEventIdAvailableCount === 0) {
    throw new EventQueryError('CHILD_EVENT_ID_UNAVAILABLE',
      'This event stream has no decoded named child event ID for filtering.',
      { scanned_count: scannedCount,
        child_event_id_unavailable_count: childEventIdUnavailableCount,
        capability_status: prepared.capabilityStatus });
  }
  if (latestPerParticipant) {
    for (const participantId of [...latestByParticipant.keys()].sort((a, b) => a - b)) {
      if (limit != null && emittedCount >= limit) break;
      // Emit the winning source line unchanged, after the entire artifact passes validation.
      await emitLine(`${latestByParticipant.get(participantId).line}\n`);
      emittedCount += 1;
    }
  }
  return {
    schema_version: 1,
    command: 'query-events',
    query_status: 'COMPLETE',
    artifact_directory: prepared.artifactDirectory,
    input_jsonl: prepared.inputPath,
    replay_version: prepared.replayVersion,
    replay_sha256: prepared.replaySha,
    event_key: prepared.eventKey,
    event_storage: prepared.eventStorage,
    capability: prepared.capability,
    capability_status: prepared.capabilityStatus,
    semantic_run_status: prepared.semanticRunStatus,
    semantic_api_status: prepared.semanticApiStatus,
    declared_event_count: prepared.declaredCount,
    scanned_count: scannedCount,
    matched_count: matchedCount,
    emitted_count: emittedCount,
    ...(latestPerParticipant ? {
      selected_count: latestByParticipant.size,
      latest_participant_unavailable_count: latestParticipantUnavailableCount,
    } : {}),
    participant_unavailable_count: participantUnavailableCount,
    ...(killerParticipant == null ? {}
      : { killer_participant_unavailable_count: killerParticipantUnavailableCount }),
    ...(assistingParticipant == null ? {}
      : { assisting_participant_unavailable_count: assistingParticipantUnavailableCount }),
    ...(rawParam == null ? {} : { raw_param_unavailable_count: rawParamUnavailableCount }),
    ...(itemId == null ? {} : { item_id_unavailable_count: itemIdUnavailableCount }),
    ...(slot == null ? {} : { slot_unavailable_count: slotUnavailableCount }),
    ...(opaqueU32 == null ? {} : { opaque_u32_unavailable_count: opaqueU32UnavailableCount }),
    ...(opaquePair == null ? {} : { opaque_pair_unavailable_count: opaquePairUnavailableCount }),
    ...(opaqueI32 == null ? {} : { opaque_i32_unavailable_count: opaqueI32UnavailableCount }),
    ...(childEventId == null ? {} : { child_event_id_unavailable_count: childEventIdUnavailableCount }),
    filters: { from_ms: fromMs, to_ms: toMs, participant_id: participant, limit,
      ...(latestPerParticipant ? { latest_per_participant: true } : {}),
      ...(killerParticipant == null ? {}
        : { killer_participant_id: killerParticipant }),
      ...(assistingParticipant == null ? {}
        : { assisting_participant_id: assistingParticipant }),
      ...(rawParam == null ? {} : { raw_param: rawParam }),
      ...(itemId == null ? {} : { item_id: itemId }),
      ...(previousItemId == null ? {} : { previous_item_id: previousItemId }),
      ...(slot == null ? {} : { slot }),
      ...(opaqueU32 == null ? {} : { opaque_u32: opaqueU32 }),
      ...(opaquePair == null ? {} : { opaque_pair: opaquePair }),
      ...(opaqueI32 == null ? {} : { opaque_i32: opaqueI32 }),
      ...(childEventId == null ? {} : { child_event_id: childEventId }) },
    rows_unmodified: true,
  };
}

async function streamBatchEventQuery(prepared, options, emitLine) {
  validateFilters(options);
  let scannedCount = 0;
  let matchedCount = 0;
  let emittedCount = 0;
  let selectedCount = 0;
  let latestParticipantUnavailableCount = 0;
  let completedCount = 0;
  let filters = null;
  const replayResults = [];
  for (const replay of prepared.replays) {
    const identity = { artifact_directory: replay.relative,
      replay_sha256: replay.replaySha, replay_version: replay.replayVersion };
    if (replay.unavailable) {
      replayResults.push({ ...identity, query_status: 'UNAVAILABLE',
        ...replay.unavailable });
      continue;
    }
    let replayEmittedCount = 0;
    let summary;
    try {
      // Scan each complete JSONL, including after the global output limit.
      summary = await streamEventQuery(replay.prepared, { ...options, limit: null },
        async (line) => {
          if (options.limit == null || emittedCount < options.limit) {
            await emitLine(line);
            emittedCount += 1;
            replayEmittedCount += 1;
          }
        });
    } catch (error) {
      if (!(error instanceof EventQueryError)
          || !['PARTICIPANT_UNAVAILABLE', 'KILLER_PARTICIPANT_UNAVAILABLE',
            'ASSISTING_PARTICIPANT_UNAVAILABLE',
            'RAW_PARAM_UNAVAILABLE',
            'ITEM_ID_UNAVAILABLE', 'SLOT_UNAVAILABLE', 'OPAQUE_U32_UNAVAILABLE',
            'OPAQUE_PAIR_UNAVAILABLE',
            'OPAQUE_I32_UNAVAILABLE', 'CHILD_EVENT_ID_UNAVAILABLE'].includes(error.code)) {
        throw error;
      }
      replayResults.push({ ...identity, query_status: 'UNAVAILABLE',
        code: error.code, message: error.message, ...error.details });
      continue;
    }
    completedCount += 1;
    filters ??= { ...summary.filters, limit: options.limit ?? null };
    scannedCount += summary.scanned_count;
    matchedCount += summary.matched_count;
    if (options.latestPerParticipant) {
      selectedCount += summary.selected_count;
      latestParticipantUnavailableCount += summary.latest_participant_unavailable_count;
    }
    replayResults.push({ ...identity, query_status: 'COMPLETE',
      capability_status: summary.capability_status,
      declared_event_count: summary.declared_event_count,
      scanned_count: summary.scanned_count,
      matched_count: summary.matched_count,
      ...(options.latestPerParticipant ? {
        selected_count: summary.selected_count,
        latest_participant_unavailable_count: summary.latest_participant_unavailable_count,
      } : {}),
      emitted_count: replayEmittedCount });
  }
  if (completedCount === 0) {
    throw new EventQueryError('BATCH_EVENT_UNAVAILABLE',
      'No Replay in this batch has a queryable event stream.',
      { event_key: prepared.eventKey, replay_results: replayResults });
  }
  return { schema_version: 1, command: 'query-events',
    query_status: completedCount === prepared.replays.length ? 'COMPLETE' : 'PARTIAL',
    artifact_directory: prepared.artifactDirectory, event_key: prepared.eventKey,
    replay_count: prepared.replays.length, completed_replay_count: completedCount,
    unavailable_replay_count: prepared.replays.length - completedCount,
    scanned_count: scannedCount, matched_count: matchedCount,
    ...(options.latestPerParticipant ? {
      selected_count: selectedCount,
      latest_participant_unavailable_count: latestParticipantUnavailableCount,
    } : {}),
    emitted_count: emittedCount, filters,
    replay_results: replayResults, rows_unmodified: true };
}

module.exports = { EventQueryError, prepareEventQuery, prepareBatchEventQuery,
  streamEventQuery, streamBatchEventQuery };

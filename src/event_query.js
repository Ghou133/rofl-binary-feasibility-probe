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
const { EXPERIENCE_KEYFRAME_INTERVAL_DIFFERENCE_821_PROFILE } =
  require('./decoders/rofl_16_19_821_experience_keyframe_interval_difference_candidate');
const { LEVEL_EXPERIENCE_KEYFRAME_BRACKET_821_PROFILE } =
  require('./decoders/rofl_16_19_821_level_experience_keyframe_bracket_candidate');
const { HERO_LEVEL_CANDIDATE_PROFILE_821, decodeLevelCode } =
  require('./decoders/rofl_16_19_821_level_candidate');
const { INVENTORY_GAME_BROADCAST_KEYFRAME_BRACKET_821_PROFILE } =
  require('./decoders/rofl_16_19_821_inventory_game_broadcast_keyframe_bracket_candidate');
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
const { CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_821,
  decodeNestedBits } =
  require('./decoders/rofl_16_19_821_cast_spell_ans_packet_candidate');
const { CIRCULAR_MOVEMENT_RESTRICTION_PACKET_CANDIDATE_PROFILE_821,
  decodeCircularMovementRestrictionPayload821 } =
  require('./decoders/rofl_16_19_821_circular_movement_restriction_packet_candidate');
const { SHOW_HEALTH_BAR_PACKET_CANDIDATE_PROFILE_821,
  decodeShowHealthBarPayload821 } =
  require('./decoders/rofl_16_19_821_show_health_bar_packet_candidate');
const { UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821,
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V1_ID_821,
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V2_ID_821,
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V3_ID_821,
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V4_ID_821,
  decodeUnitApplyDamageCallbackF32FromRaw821,
  decodeUnitApplyDamageCallbackU32FromRaw821,
  decodeUnitApplyDamageCallbackF32At18FromEncoded821,
  decodeUnitApplyDamageLookupKeyFromRaw821,
  isObservedShape: isObservedUnitApplyDamageShape821 } =
  require('./decoders/rofl_16_19_821_unit_apply_damage_packet_candidate');
const { UNIT_APPLY_DAMAGE_ROSTER_KEY_821_PROFILE,
  UNIT_APPLY_DAMAGE_ROSTER_KEY_PROFILE_V1_821,
  UNIT_APPLY_DAMAGE_ROSTER_KEY_PROFILE_V2_821 } =
  require('./decoders/rofl_16_19_821_unit_apply_damage_roster_key_candidate');
const { UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_KEY_821_PROFILE,
  UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_KEY_PROFILE_V1_821,
  UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_KEY_PROFILE_V2_821 } =
  require('./decoders/rofl_16_19_821_unit_apply_damage_lookup_roster_key_candidate');
const { UNIT_APPLY_DAMAGE_LOOKUP2C_ROSTER_KEY_821_PROFILE,
  UNIT_APPLY_DAMAGE_LOOKUP2C_ROSTER_KEY_PROFILE_V1_821,
  UNIT_APPLY_DAMAGE_LOOKUP2C_ROSTER_KEY_PROFILE_V2_821 } =
  require('./decoders/rofl_16_19_821_unit_apply_damage_lookup2c_roster_key_candidate');
const { HERO_DEATH_DAMAGE_LOOKUP_KEY_COOCCURRENCE_821_PROFILE,
  HERO_DEATH_DAMAGE_LOOKUP_KEY_COOCCURRENCE_PROFILE_V1_821,
  HERO_DEATH_DAMAGE_LOOKUP_KEY_COOCCURRENCE_PROFILE_V2_821 } =
  require('./decoders/rofl_16_19_821_hero_death_damage_lookup_key_cooccurrence_candidate');
const { REVIVE_ALLY_EVENT_PACKET_821_PROFILE } =
  require('./decoders/rofl_16_19_821_revive_ally_packet_candidate');
const { FIRST_BLOOD_ASSIST_EVENT_PACKET_821_PROFILE } =
  require('./decoders/rofl_16_19_821_first_blood_assist_event_packet_candidate');
const { TURRET_FIRST_BLOOD_DIE_PAIR_821_PROFILE } =
  require('./decoders/rofl_16_19_821_turret_first_blood_die_pair_candidate');
const { TURRET_FIRST_BLOOD_EVENT_PACKET_821_PROFILE } =
  require('./decoders/rofl_16_19_821_turret_first_blood_event_packet_candidate');
const { TURRET_DIE_EVENT_PACKET_821_PROFILE } =
  require('./decoders/rofl_16_19_821_turret_die_event_packet_candidate');
const { DAMPENER_DIE_EVENT_PACKET_821_PROFILE } =
  require('./decoders/rofl_16_19_821_dampener_die_event_packet_candidate');
const { HQ_KILL_EVENT_PACKET_821_PROFILE } =
  require('./decoders/rofl_16_19_821_hq_kill_event_packet_candidate');
const { OBJECTIVE_BOUNTY_CLAIMED_PACKET_821_PROFILE } =
  require('./decoders/rofl_16_19_821_objective_bounty_claimed_packet_candidate');
const { OBJECTIVE_BOUNTY_TURRET_PAIR_821_PROFILE } =
  require('./decoders/rofl_16_19_821_objective_bounty_turret_pair_candidate');
const { TURRET_PLATE_EVENT_PACKET_821_PROFILE } =
  require('./decoders/rofl_16_19_821_turret_plate_event_packet_candidate');
const { INCREMENT_MINION_KILLS_PACKET_CANDIDATE_PROFILE_821,
  isObservedIncrementMinionKillsPayloadHex,
  lookupIncrementMinionKillsKeyFromNativeBytes } =
  require('./decoders/rofl_16_19_821_increment_minion_kills_packet_candidate');

const EVENT_KEY = /^[a-z][a-z0-9_]*_candidates$/;
const REPLAY_SHA = /^[a-f0-9]{64}$/;
const CIRCULAR_MOVEMENT_RESTRICTION_ROW_FIELDS_821 = new Set([
  'event_type', 'game_version', 'patch', 'build_profile', 'replay_sha256',
  'replay_time_ms', 'raw_param', 'raw_payload_hex', 'raw_selector_byte',
  'packet_shape_candidate', 'packet_record_count_candidate',
  'raw_protected_scalar_bytes_hex', 'raw_protected_vector_bytes_hex',
  'callback_scalar_bytes_hex', 'callback_vector_bytes_hex',
  'anonymous_scalar_f32_candidate', 'anonymous_vector_xyz_f32_candidate',
  'semantic_effect_status', 'confidence', 'semantic_status', 'raw_packet_ref',
]);
const SHOW_HEALTH_BAR_RESULT_FIELDS_821 = new Set([
  'profile_id', 'input_packet_id', 'evidence_status',
  'evidence_runtime_image_sha256', 'evidence_callback_table_sha256',
  'status', 'input_count', 'event_count', 'scanned_block_count',
  'known_limits', 'event_field_confidence', 'observed_payload_counts',
  'native_witness_status', 'native_full_success_count',
  'native_input_sha256', 'runtime_image_status', 'runtime_image_used',
  'runtime_image_sha256',
]);
const SHOW_HEALTH_BAR_ROW_FIELDS_821 = new Set([
  'event_type', 'game_version', 'patch', 'build_profile', 'replay_sha256',
  'replay_time_ms', 'raw_param', 'packet_name_candidate',
  'raw_payload_byte_hex', 'native_object_byte_0x10_hex',
  'callback_byte_candidate', 'callback_zero_flag_candidate',
  'semantic_effect_status', 'confidence', 'semantic_status', 'raw_packet_ref',
]);
const SHOW_HEALTH_BAR_REF_FIELDS_821 = new Set([
  'source_path', 'replay_sha256', 'chunk_index', 'chunk_id', 'chunk_stream',
  'chunk_file_offset', 'decompressed_block_offset',
  'decompressed_payload_offset', 'packet_id', 'replay_time_ms',
  'payload_length', 'raw_param', 'raw_payload_hex', 'raw_payload_sha256',
]);
const FIRST_BLOOD_ASSIST_ROW_FIELDS_821 = new Set([
  'event_type', 'game_version', 'patch', 'build_profile', 'replay_sha256',
  'replay_time_ms', 'raw_param', 'child_event_id', 'registered_event_name',
  'raw_event_id_hex', 'event_blob_hex', 'event_blob_sha256', 'confidence',
  'semantic_status', 'raw_packet_ref',
]);
const FIRST_BLOOD_ASSIST_REF_FIELDS_821 = new Set([
  'source_path', 'replay_sha256', 'chunk_index', 'chunk_id', 'chunk_stream',
  'chunk_file_offset', 'decompressed_block_offset',
  'decompressed_payload_offset', 'packet_id', 'replay_time_ms',
  'payload_length', 'raw_param', 'raw_payload_sha256',
]);
const UNIT_APPLY_DAMAGE_ROW_FIELDS_821 = new Set([
  'event_type', 'game_version', 'patch', 'build_profile',
  'replay_sha256', 'replay_time_ms', 'raw_param', 'packet_name_candidate',
  'header_selector_bits_24_26', 'header_selector_bits_0_2',
  'header_selector_bits_3_5', 'callback_f32_0x20_candidate',
  'callback_f32_0x20_status', 'callback_f32_0x20_raw_bytes_hex',
  'confidence', 'semantic_status', 'semantic_effect_status', 'raw_packet_ref',
]);
const UNIT_APPLY_DAMAGE_V2_ROW_FIELDS_821 = new Set([
  ...UNIT_APPLY_DAMAGE_ROW_FIELDS_821,
  'native_callback_f32_0x20_candidate', 'native_callback_f32_0x20_source',
  'native_callback_f32_0x20_raw_offset', 'native_callback_f32_0x20_raw_bytes_hex',
]);
const UNIT_APPLY_DAMAGE_V3_ROW_FIELDS_821 = new Set([
  ...UNIT_APPLY_DAMAGE_V2_ROW_FIELDS_821,
  'native_callback_lookup_key_u32_0x24_candidate',
  'native_callback_lookup_key_0x24_encoded_bytes_hex',
  'native_callback_lookup_key_u32_0x2c_candidate',
  'native_callback_lookup_key_0x2c_encoded_bytes_hex',
  'native_callback_lookup_key_0x24_raw_param_relation',
]);
const UNIT_APPLY_DAMAGE_V4_ROW_FIELDS_821 = new Set([
  ...UNIT_APPLY_DAMAGE_V3_ROW_FIELDS_821,
  'native_callback_u32_0x10_candidate',
  'native_callback_u32_0x10_encoded_bytes_hex',
  'native_callback_u32_0x10_source',
]);
const UNIT_APPLY_DAMAGE_V5_ROW_FIELDS_821 = new Set([
  ...UNIT_APPLY_DAMAGE_V4_ROW_FIELDS_821,
  'header_selector_bits_6_8',
  'native_callback_f32_0x18_candidate',
  'native_callback_f32_0x18_encoded_bytes_hex',
  'native_callback_f32_0x18_source',
  'native_callback_f32_0x18_raw_offset',
  'native_callback_f32_0x18_raw_bytes_hex',
]);
const UNIT_APPLY_DAMAGE_LOOKUP_RELATIONS_821 = Object.freeze([
  'EQUAL', 'RAW_PARAM_IS_LOOKUP_PLUS_0X100', 'OTHER',
]);
const UNIT_APPLY_DAMAGE_NATIVE_FLOAT_SOURCES_821 = Object.freeze([
  'RAW_READER', 'CONSTANT_0', 'CONSTANT_1', 'CONSTANT_2',
]);
const UNIT_APPLY_DAMAGE_NATIVE_U32_SOURCES_821 = Object.freeze([
  'RAW_READER', 'CONSTANT_0',
]);
const UNIT_APPLY_DAMAGE_NATIVE_F32_0X18_SOURCES_821 = Object.freeze([
  'RAW_READER', 'CONSTANT_0',
]);
const DAMAGE_ASSOCIATION_V3_F32_RESULT_FIELDS_821 = Object.freeze([
  'evidence_callback_f32_0x18_table_sha256',
  'native_callback_f32_0x18_full_write_count',
  'native_callback_f32_0x18_source_counts',
]);
const DAMAGE_ASSOCIATION_V3_F32_ROW_FIELDS_821 = Object.freeze([
  'header_selector_bits_6_8', 'native_callback_f32_0x18_candidate',
  'native_callback_f32_0x18_encoded_bytes_hex',
  'native_callback_f32_0x18_source',
  'native_callback_f32_0x18_raw_offset',
  'native_callback_f32_0x18_raw_bytes_hex',
]);
const UNIT_APPLY_DAMAGE_ROSTER_RESULT_FIELDS_821 = new Set([
  'profile_id', 'depends_on', 'evidence_runtime_image_sha256', 'known_limits',
  'status', 'evidence_status', 'replay_sha256', 'runtime_image_status',
  'runtime_image_used', 'runtime_image_sha256', 'dependency_statuses',
  'damage_packet_count', 'snapshot_count', 'keyframe_count',
  'canonical_roster_key_count', 'matched_full_key_packet_count',
  'unmatched_packet_count', 'excluded_alias_0x100_packet_count',
  'first_excluded_packet_refs', 'verified_raw_packet_count', 'input_count',
  'event_count',
]);
const UNIT_APPLY_DAMAGE_ROSTER_V3_RESULT_FIELDS_821 = new Set([
  ...UNIT_APPLY_DAMAGE_ROSTER_RESULT_FIELDS_821,
  ...DAMAGE_ASSOCIATION_V3_F32_RESULT_FIELDS_821,
]);
const UNIT_APPLY_DAMAGE_ROSTER_ROW_FIELDS_821 = new Set([
  'event_type', 'game_version', 'patch', 'build_profile', 'replay_sha256',
  'replay_time_ms', 'raw_param', 'hero_stats_participant_id_candidate',
  'native_callback_f32_0x20_candidate', 'native_callback_f32_0x20_source',
  'pair_basis', 'actor_assignment_status', 'source_target_role_status',
  'semantic_effect_status', 'confidence', 'semantic_status',
  'unit_apply_damage_raw_packet_ref', 'hero_stats_roster_raw_packet_ref',
  'raw_packet_refs',
]);
const UNIT_APPLY_DAMAGE_ROSTER_V3_ROW_FIELDS_821 = new Set([
  ...UNIT_APPLY_DAMAGE_ROSTER_ROW_FIELDS_821,
  ...DAMAGE_ASSOCIATION_V3_F32_ROW_FIELDS_821,
]);
const UNIT_APPLY_DAMAGE_ROSTER_DAMAGE_REF_FIELDS_821 = new Set([
  'source_path', 'replay_sha256', 'chunk_index', 'chunk_id', 'chunk_stream',
  'chunk_file_offset', 'decompressed_block_offset',
  'decompressed_payload_offset', 'packet_id', 'replay_time_ms',
  'payload_length', 'raw_param', 'raw_payload_hex', 'raw_payload_sha256',
]);
const UNIT_APPLY_DAMAGE_ROSTER_STATS_REF_FIELDS_821 = new Set([
  'source_path', 'replay_sha256', 'chunk_index', 'chunk_id', 'chunk_stream',
  'chunk_file_offset', 'decompressed_block_offset',
  'decompressed_payload_offset', 'packet_id', 'replay_time_ms',
  'payload_length', 'raw_param', 'raw_payload_sha256',
]);
const UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_RESULT_FIELDS_821 = new Set([
  'profile_id', 'depends_on', 'evidence_runtime_image_sha256',
  'evidence_lookup_key_0x24_table_sha256', 'known_limits', 'status',
  'evidence_status', 'replay_sha256', 'runtime_image_status',
  'runtime_image_used', 'runtime_image_sha256', 'dependency_statuses',
  'damage_packet_count', 'snapshot_count', 'keyframe_count',
  'canonical_roster_key_count', 'matched_lookup_key_packet_count',
  'matched_alias_0x100_packet_count', 'matched_equal_packet_count',
  'matched_other_relation_packet_count', 'unmatched_packet_count',
  'unmatched_alias_0x100_packet_count', 'first_unmatched_packet_refs',
  'verified_raw_packet_count', 'input_count', 'event_count',
]);
const UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_V3_RESULT_FIELDS_821 = new Set([
  ...UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_RESULT_FIELDS_821,
  ...DAMAGE_ASSOCIATION_V3_F32_RESULT_FIELDS_821,
]);
const UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_ROW_FIELDS_821 = new Set([
  'event_type', 'game_version', 'patch', 'build_profile', 'replay_sha256',
  'replay_time_ms', 'raw_param',
  'native_callback_lookup_key_u32_0x24_candidate',
  'native_callback_lookup_key_0x24_encoded_bytes_hex',
  'native_callback_lookup_key_0x24_raw_param_relation',
  'hero_raw_param', 'hero_stats_participant_id_candidate', 'pair_basis',
  'lookup_resolution_status', 'actor_assignment_status',
  'source_target_role_status', 'semantic_effect_status', 'confidence',
  'semantic_status', 'unit_apply_damage_raw_packet_ref',
  'hero_stats_roster_raw_packet_ref', 'raw_packet_refs',
]);
const UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_V3_ROW_FIELDS_821 = new Set([
  ...UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_ROW_FIELDS_821,
  ...DAMAGE_ASSOCIATION_V3_F32_ROW_FIELDS_821,
]);
const UNIT_APPLY_DAMAGE_LOOKUP2C_ROSTER_RESULT_FIELDS_821 = new Set([
  'profile_id', 'depends_on', 'evidence_runtime_image_sha256',
  'evidence_lookup_key_0x24_table_sha256',
  'evidence_lookup_key_0x2c_table_sha256', 'known_limits', 'status',
  'evidence_status', 'replay_sha256', 'runtime_image_status',
  'runtime_image_used', 'runtime_image_sha256', 'dependency_statuses',
  'damage_packet_count', 'snapshot_count', 'keyframe_count',
  'canonical_roster_key_count', 'matched_lookup_key_packet_count',
  'unmatched_packet_count', 'matched_key24_roster_counts',
  'first_unmatched_packet_refs', 'verified_raw_packet_count',
  'input_count', 'event_count',
]);
const UNIT_APPLY_DAMAGE_LOOKUP2C_ROSTER_V3_RESULT_FIELDS_821 = new Set([
  ...UNIT_APPLY_DAMAGE_LOOKUP2C_ROSTER_RESULT_FIELDS_821,
  ...DAMAGE_ASSOCIATION_V3_F32_RESULT_FIELDS_821,
]);
const UNIT_APPLY_DAMAGE_LOOKUP2C_ROSTER_ROW_FIELDS_821 = new Set([
  'event_type', 'game_version', 'patch', 'build_profile', 'replay_sha256',
  'replay_time_ms', 'raw_param',
  'native_callback_lookup_key_u32_0x24_candidate',
  'native_callback_lookup_key_0x24_encoded_bytes_hex',
  'native_callback_lookup_key_u32_0x2c_candidate',
  'native_callback_lookup_key_0x2c_encoded_bytes_hex',
  'native_callback_lookup_key_0x24_raw_param_relation',
  'key24_roster_relation', 'hero_raw_param',
  'hero_stats_participant_id_candidate', 'pair_basis',
  'lookup_resolution_status', 'actor_assignment_status',
  'source_target_role_status', 'semantic_effect_status', 'confidence',
  'semantic_status', 'unit_apply_damage_raw_packet_ref',
  'hero_stats_roster_raw_packet_ref', 'raw_packet_refs',
]);
const UNIT_APPLY_DAMAGE_LOOKUP2C_ROSTER_V3_ROW_FIELDS_821 = new Set([
  ...UNIT_APPLY_DAMAGE_LOOKUP2C_ROSTER_ROW_FIELDS_821,
  ...DAMAGE_ASSOCIATION_V3_F32_ROW_FIELDS_821,
]);
const UNIT_APPLY_DAMAGE_LOOKUP2C_KEY24_ROSTER_RELATIONS_821 = Object.freeze([
  'SAME_ROSTER_KEY', 'DIFFERENT_ROSTER_KEY', 'KEY24_NOT_IN_ROSTER',
]);
const HERO_DEATH_DAMAGE_LOOKUP_RESULT_FIELDS_821 = new Set([
  'profile_id', 'depends_on', 'evidence_runtime_image_sha256',
  'evidence_lookup_key_0x24_table_sha256',
  'evidence_lookup_key_0x2c_table_sha256', 'known_limits', 'status',
  'evidence_status', 'replay_sha256', 'runtime_image_status',
  'runtime_image_used', 'runtime_image_sha256', 'dependency_statuses',
  'death_anchor_count', 'damage_packet_count', 'snapshot_count',
  'canonical_roster_key_count', 'verified_raw_damage_roster_packet_count',
  'verified_hero_death_route_packet_count',
  'matched_victim_key24_packet_count',
  'death_anchor_with_victim_key24_packet_count',
  'death_anchor_without_victim_key24_packet_count',
  'multiple_victim_key24_packet_anchor_count',
  'max_victim_key24_packet_count_per_anchor',
  'matched_die_source_key2c_packet_count',
  'death_anchor_with_die_source_key2c_match_count',
  'death_anchor_without_die_source_key2c_match_count',
  'death_anchor_die_source_unavailable_count', 'input_count', 'event_count',
]);
const HERO_DEATH_DAMAGE_LOOKUP_V3_RESULT_FIELDS_821 = new Set([
  ...HERO_DEATH_DAMAGE_LOOKUP_RESULT_FIELDS_821,
  ...DAMAGE_ASSOCIATION_V3_F32_RESULT_FIELDS_821,
]);
const HERO_DEATH_DAMAGE_LOOKUP_ROW_FIELDS_821 = new Set([
  'event_type', 'game_version', 'patch', 'build_profile', 'replay_sha256',
  'replay_time_ms', 'victim_participant_id_candidate', 'victim_raw_param',
  'victim_lookup_roster_key_u32_candidate',
  'die_source_network_id_candidate',
  'same_time_victim_key24_packet_candidate_count',
  'same_time_victim_key24_packet_before_primary_count',
  'same_time_victim_key24_packet_after_primary_count',
  'same_time_die_source_key2c_packet_candidate_count',
  'die_source_key2c_match_status',
  'same_time_victim_key24_packet_candidates',
  'hero_death_raw_packet_ref', 'hero_death_die_source_raw_packet_ref',
  'hero_death_raw_packet_refs', 'hero_stats_roster_raw_packet_ref',
  'raw_packet_refs', 'pair_basis', 'lookup_resolution_status',
  'actor_assignment_status', 'source_target_role_status',
  'semantic_effect_status', 'confidence', 'semantic_status',
]);
const HERO_DEATH_DAMAGE_LOOKUP_PACKET_FIELDS_821 = new Set([
  'raw_param', 'native_callback_lookup_key_u32_0x24_candidate',
  'native_callback_lookup_key_0x24_encoded_bytes_hex',
  'native_callback_lookup_key_u32_0x2c_candidate',
  'native_callback_lookup_key_0x2c_encoded_bytes_hex',
  'native_callback_lookup_key_0x24_raw_param_relation',
  'die_source_key2c_equal', 'relative_to_death_primary',
  'unit_apply_damage_raw_packet_ref',
]);
const HERO_DEATH_DAMAGE_LOOKUP_V3_PACKET_FIELDS_821 = new Set([
  ...HERO_DEATH_DAMAGE_LOOKUP_PACKET_FIELDS_821,
  ...DAMAGE_ASSOCIATION_V3_F32_ROW_FIELDS_821,
]);
const HERO_DEATH_DAMAGE_LOOKUP_DEATH_REF_FIELDS_821 = new Set([
  'role', 'source_path', 'replay_sha256', 'chunk_index', 'chunk_id',
  'chunk_stream', 'chunk_file_offset', 'decompressed_block_offset',
  'decompressed_payload_offset', 'packet_id', 'replay_time_ms',
  'payload_length', 'raw_param', 'raw_payload_sha256',
]);
const MAX_MINION_BRACKET_SOURCE_ROWS_821 = 10_000;
const MAX_EXPERIENCE_INTERVAL_SOURCE_ROWS_821 = 100_000;
const EXPERIENCE_INTERVAL_ROW_FIELDS_821 = new Set([
  'event_type', 'game_version', 'patch', 'build_profile', 'replay_sha256',
  'replay_time_ms', 'previous_observation_time_ms', 'current_observation_time_ms',
  'observation_interval_ms', 'previous_keyframe_chunk_index',
  'current_keyframe_chunk_index', 'hero_raw_param', 'participant_id_candidate',
  'previous_experience_raw_f32_candidate', 'current_experience_raw_f32_candidate',
  'previous_experience_floor_candidate', 'current_experience_floor_candidate',
  'experience_endpoint_delta_f32_candidate',
  'experience_endpoint_delta_floor_candidate',
  'previous_raw_payload_field_bytes_hex', 'current_raw_payload_field_bytes_hex',
  'observation_kind', 'observation_scope', 'change_time_status',
  'confidence', 'semantic_status', 'field_confidence', 'raw_packet_ref',
  'previous_raw_packet_ref', 'current_raw_packet_ref', 'raw_packet_refs',
  'known_limits',
]);
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
const INVENTORY_GAME_BRACKET_ROW_FIELDS_821 = new Set([
  'event_type', 'game_version', 'patch', 'build_profile', 'replay_sha256',
  'replay_time_ms', 'previous_observation_time_ms', 'game_observation_time_ms',
  'next_observation_time_ms', 'observation_interval_ms',
  'previous_keyframe_chunk_index', 'game_chunk_index', 'next_keyframe_chunk_index',
  'hero_raw_param', 'participant_id_candidate', 'observation_kind',
  'observation_scope', 'record_count', 'record_comparisons_candidate',
  'unrecorded_game_slots_candidate', 'confidence', 'semantic_status',
  'field_confidence', 'raw_packet_ref', 'previous_raw_packet_ref',
  'game_raw_packet_ref', 'next_raw_packet_ref', 'raw_packet_refs',
]);
const INVENTORY_GAME_COMPARISON_LABELS_821 = Object.freeze([
  'SAME_AS_BOTH_ENDPOINTS', 'DIFFERS_FROM_EQUAL_ENDPOINTS',
  'SAME_AS_PREVIOUS_ENDPOINT', 'SAME_AS_NEXT_ENDPOINT',
  'DIFFERS_FROM_BOTH_ENDPOINTS',
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
  'experience_keyframe_interval_difference_candidates',
  'face_direction_keyframe_roster_pair_candidates',
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
  objective_bounty_claimed_packet_candidates: Object.freeze([
    'blob_u32_0x04',
  ]),
  objective_bounty_turret_pair_candidates: Object.freeze([
    'claim_blob_u32_0x04',
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
  level_experience_keyframe_bracket_candidates: Object.freeze({
    profile: LEVEL_EXPERIENCE_KEYFRAME_BRACKET_821_PROFILE,
    eventType: 'LEVEL_EXPERIENCE_KEYFRAME_BRACKET_CANDIDATE',
    evidenceStatus: 'CANDIDATE_821_LEVEL_PACKET_WITHIN_EXPERIENCE_KEYFRAME_ENDPOINTS',
    levelExperienceBracket: true,
  }),
  experience_keyframe_interval_difference_candidates: Object.freeze({
    profile: EXPERIENCE_KEYFRAME_INTERVAL_DIFFERENCE_821_PROFILE,
    eventType: 'EXPERIENCE_KEYFRAME_INTERVAL_DIFFERENCE_CANDIDATE',
    evidenceStatus: 'CANDIDATE_821_ADJACENT_KEYFRAME_EXPERIENCE_ENDPOINT_DIFFERENCE',
    experienceInterval: true,
  }),
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
  inventory_game_broadcast_keyframe_bracket_candidates: Object.freeze({
    profile: INVENTORY_GAME_BROADCAST_KEYFRAME_BRACKET_821_PROFILE,
    eventType: 'INVENTORY_GAME_BROADCAST_KEYFRAME_BRACKET_CANDIDATE',
    evidenceStatus: 'CANDIDATE_821_GAME_BROADCAST_BETWEEN_ADJACENT_KEYFRAMES',
    inventoryGameBracket: true,
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
  objective_bounty_turret_pair_candidates: Object.freeze({
    profile: OBJECTIVE_BOUNTY_TURRET_PAIR_821_PROFILE,
    eventType: 'OBJECTIVE_BOUNTY_TURRET_PACKET_TRIPLE_CANDIDATE',
    evidenceStatus: 'CANDIDATE_821_ON_EVENT_PLATE_DIE_CLAIM_PACKET_TRIPLE',
    objectiveBountyTurretPair: true,
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
const OBJECTIVE_BOUNTY_TURRET_PAIR_SOURCE_EVENTS_821 = Object.freeze([
  Object.freeze({ eventKey: 'turret_plate_event_packet_candidates',
    profile: TURRET_PLATE_EVENT_PACKET_821_PROFILE,
    eventType: 'TURRET_PLATE_EVENT_PACKET_CANDIDATE',
    rawEventIdHex: '0x09e8', payloadLength: 17,
    evidenceStatus: 'CANDIDATE_EXACT_RUNTIME_NAMED_ON_EVENT_CHILD' }),
  Object.freeze({ eventKey: 'turret_die_event_packet_candidates',
    profile: TURRET_DIE_EVENT_PACKET_821_PROFILE,
    eventType: 'TURRET_DIE_EVENT_PACKET_CANDIDATE',
    rawEventIdHex: '0x4966', payloadLength: 116,
    evidenceStatus: 'CANDIDATE_EXACT_RUNTIME_ON_TURRET_DIE_PACKET' }),
  Object.freeze({ eventKey: 'objective_bounty_claimed_packet_candidates',
    profile: OBJECTIVE_BOUNTY_CLAIMED_PACKET_821_PROFILE,
    eventType: 'OBJECTIVE_BOUNTY_CLAIMED_PACKET_CANDIDATE',
    rawEventIdHex: '0x09e5', payloadLength: 17,
    evidenceStatus: 'CANDIDATE_EXACT_RUNTIME_NAMED_ON_EVENT_CHILD' }),
]);
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
  hq_kill_event_packet_candidates: Object.freeze({
    profile: HQ_KILL_EVENT_PACKET_821_PROFILE,
    eventType: 'HQ_KILL_EVENT_PACKET_CANDIDATE',
    evidenceStatus: 'CANDIDATE_EXACT_RUNTIME_ON_HQ_KILL_PACKET',
    rawEventIdHex: '0x4918',
  }),
});
const CHILD_EVENT_ID_FILTERS_821 = Object.freeze({
  stealth_event_packet_candidates: Object.freeze([0x0101, 0x0102]),
  first_blood_assist_event_packet_candidates: Object.freeze([0x0017]),
  hq_kill_event_packet_candidates: Object.freeze([0x0046]),
  objective_bounty_claimed_packet_candidates: Object.freeze([0x0113]),
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

function firstBloodAssistPacketRefValid(ref, replaySha, sourcePath) {
  const profile = FIRST_BLOOD_ASSIST_EVENT_PACKET_821_PROFILE;
  return ref && typeof ref === 'object' && !Array.isArray(ref)
    && Object.keys(ref).length === FIRST_BLOOD_ASSIST_REF_FIELDS_821.size
    && Object.keys(ref).every((field) => FIRST_BLOOD_ASSIST_REF_FIELDS_821.has(field))
    && ref.source_path === (sourcePath ?? null)
    && ref.replay_sha256 === replaySha
    && ref.chunk_stream === 'game_chunk'
    && isCount(ref.chunk_index) && isCount(ref.chunk_id)
    && isCount(ref.chunk_file_offset)
    && isCount(ref.decompressed_block_offset)
    && isCount(ref.decompressed_payload_offset)
    && ref.decompressed_payload_offset > ref.decompressed_block_offset
    && ref.packet_id === profile.replay_block_packet_id
    && isCount(ref.replay_time_ms)
    && ref.payload_length === profile.payload_length
    && Number.isInteger(ref.raw_param) && ref.raw_param > 0
    && ref.raw_param <= 0xffffffff
    && REPLAY_SHA.test(ref.raw_payload_sha256 ?? '');
}

function prepareFirstBloodAssistPacketEvent(semantic, analysis, eventKey, result) {
  const profile = FIRST_BLOOD_ASSIST_EVENT_PACKET_821_PROFILE;
  if (semantic.replay_version !== profile.replay_version) {
    throw new EventQueryError('UNSUPPORTED_EVENT_BUILD',
      `${eventKey} requires exact build ${profile.replay_version}.`);
  }
  if (result?.status === 'PASS') {
    throw new EventQueryError('CAPABILITY_METADATA_MISMATCH',
      `${profile.capability} must remain an exact-build candidate.`);
  }
  if (result?.status !== 'CANDIDATE') return;
  const count = result.event_count;
  const excluded = result.excluded_same_length_foreign_count;
  const refs = result.excluded_same_length_foreign_packet_refs;
  if (result.profile_id !== profile.id
      || result.evidence_runtime_image_sha256 !== profile.evidence_runtime_image_sha256
      || result.runtime_image_sha256 !== profile.evidence_runtime_image_sha256
      || result.runtime_image_status !== 'MATCHED_USED'
      || result.runtime_image_used !== true
      || result.evidence_status !== 'CANDIDATE_EXACT_RUNTIME_NAMED_ON_EVENT_CHILD'
      || result.input_packet_id !== profile.replay_block_packet_id
      || result.input_packet_scope !== 'child_0017_length_16'
      || result.child_event_id !== profile.child_event_id
      || !isCount(count) || count === 0
      || !isCount(excluded) || !isCount(result.input_count)
      || result.input_count !== count + excluded
      || result.input_count > 2000
      || result.observed_same_length_packet_count !== result.input_count
      || result.target_packet_count !== count
      || !isCount(result.scanned_block_count)
      || result.scanned_block_count < result.input_count
      || !Array.isArray(refs) || refs.length !== excluded
      || refs.some((ref) => !firstBloodAssistPacketRefValid(ref,
        semantic.replay_sha256, analysis.source_path))
      || new Set(refs.map((ref) =>
        `${ref.chunk_index}/${ref.decompressed_block_offset}`)).size !== refs.length
      || !isDeepStrictEqual(result.known_limits, [...profile.known_limits])
      || !isDeepStrictEqual(result.event_field_confidence, {
        replay_time_ms: 'VERIFIED_DIRECT', raw_param: 'VERIFIED_DIRECT',
        child_event_id: 'VERIFIED_EXACT_NATIVE_CHILD',
        registered_event_name: 'VERIFIED_EXACT_IMAGE_LABEL',
        event_blob_hex: 'VERIFIED_EXACT_NATIVE_BLOB',
      })
      || analysis.event_counts?.[eventKey] !== count) {
    throw new EventQueryError('CAPABILITY_METADATA_MISMATCH',
      `${profile.capability} identity or candidate counts differ from its exact-build profile.`);
  }
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
  const expectedPacketScope = `child_${profile.child_event_id.toString(16)
    .padStart(4, '0')}_length_${profile.payload_length}`;
  if (result.profile_id !== profile.id
      || result.evidence_runtime_image_sha256 !== imageSha
      || result.runtime_image_sha256 !== imageSha
      || result.runtime_image_status !== 'MATCHED_USED'
      || result.runtime_image_used !== true
      || result.evidence_status !== evidenceStatus
      || result.input_packet_id !== profile.replay_block_packet_id
      || result.input_packet_scope !== expectedPacketScope
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

function prepareObjectiveBountyClaimedPacketEvent(semantic, analysis, eventKey, result) {
  const profile = OBJECTIVE_BOUNTY_CLAIMED_PACKET_821_PROFILE;
  if (semantic.replay_version !== profile.replay_version) {
    throw new EventQueryError('UNSUPPORTED_EVENT_BUILD',
      `${eventKey} requires exact build ${profile.replay_version}.`);
  }
  if (result?.status !== 'CANDIDATE') return;
  const controls = result.same_length_control_refs;
  const counts = result.same_length_control_ids;
  const observedCounts = {};
  const controlValid = Array.isArray(controls) && controls.every((control) => {
    const ref = control?.raw_packet_ref;
    const id = control?.child_event_id;
    const key = Number.isSafeInteger(id) && id >= 0 && id <= 0xffff
      ? `0x${id.toString(16).padStart(4, '0')}` : null;
    if (!key || id === profile.child_event_id
        || !/^0x[0-9a-f]{4}$/.test(control.raw_event_id_hex ?? '')
        || !ref || ref.replay_sha256 !== semantic.replay_sha256
        || ref.packet_id !== profile.replay_block_packet_id
        || ref.payload_length !== profile.payload_length
        || ref.chunk_stream !== 'game_chunk'
        || !REPLAY_SHA.test(ref.raw_payload_sha256 ?? '')) return false;
    observedCounts[key] = (observedCounts[key] ?? 0) + 1;
    return true;
  });
  if (result.profile_id !== profile.id
      || result.evidence_runtime_image_sha256 !== profile.evidence_runtime_image_sha256
      || result.runtime_image_sha256 !== profile.evidence_runtime_image_sha256
      || result.runtime_image_status !== 'MATCHED_USED'
      || result.runtime_image_used !== true
      || result.evidence_status !== 'CANDIDATE_EXACT_RUNTIME_NAMED_ON_EVENT_CHILD'
      || result.input_packet_id !== profile.replay_block_packet_id
      || result.input_packet_scope !== 'child_0113_length_17'
      || result.child_event_id !== profile.child_event_id
      || !isCount(result.event_count) || result.event_count === 0
      || result.target_packet_count !== result.event_count
      || !isCount(result.same_length_control_count)
      || result.input_count !== result.event_count + result.same_length_control_count
      || !controlValid || controls.length !== result.same_length_control_count
      || !counts || typeof counts !== 'object' || Array.isArray(counts)
      || !isDeepStrictEqual(counts, observedCounts)
      || !isDeepStrictEqual(result.known_limits, [...profile.known_limits])
      || analysis.event_counts?.[eventKey] !== result.event_count
      || (analysis.semantic?.capability_results?.[profile.capability] != null
        && !isDeepStrictEqual(analysis.semantic.capability_results[profile.capability],
          result))) {
    throw new EventQueryError('CAPABILITY_METADATA_MISMATCH',
      `${profile.capability} identity or target/control counts differ from exact build.`);
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

function prepareObjectiveBountyTurretPairAssociation(semantic, analysis, eventKey,
  { profile, evidenceStatus }) {
  if (semantic.replay_version !== profile.replay_version) {
    throw new EventQueryError('UNSUPPORTED_EVENT_BUILD',
      `${eventKey} requires exact build ${profile.replay_version}.`);
  }
  const association = semantic.candidate_associations?.[profile.capability];
  if (association?.status !== 'CANDIDATE') {
    throw new EventQueryError('ASSOCIATION_UNAVAILABLE',
      `${profile.capability} is not an executed candidate association.`,
      { capability: profile.capability,
        association_status: association?.status ?? null,
        error: association?.error ?? null, semantic_run_status: semantic.status });
  }
  const imageSha = profile.evidence_runtime_image_sha256;
  if (association.profile_id !== profile.id
      || association.evidence_runtime_image_sha256 !== imageSha
      || association.evidence_status !== evidenceStatus
      || association.replay_sha256 !== semantic.replay_sha256
      || !isDeepStrictEqual(association.depends_on, [...profile.depends_on])
      || !isDeepStrictEqual(association.known_limits, [...profile.known_limits])
      || !isCount(association.event_count)
      || association.triple_count !== association.event_count
      || !isCount(association.claim_packet_count)
      || !isCount(association.turret_plate_count)
      || !isCount(association.turret_die_count)
      || !isCount(association.unmatched_claim_count)
      || !isCount(association.nonunique_claim_count)
      || association.claim_packet_count
        !== association.event_count + association.unmatched_claim_count
      || association.nonunique_claim_count > association.unmatched_claim_count
      || association.event_count > association.turret_plate_count
      || association.event_count > association.turret_die_count
      || !Array.isArray(association.unmatched_claims)
      || association.unmatched_claims.length !== association.unmatched_claim_count
      || analysis.event_counts?.[eventKey] !== association.event_count
      || (analysis.semantic?.candidate_associations?.[profile.capability] != null
        && !isDeepStrictEqual(analysis.semantic.candidate_associations[profile.capability],
          association))) {
    throw new EventQueryError('ASSOCIATION_METADATA_MISMATCH',
      `${profile.capability} identity, source counts or unmatched claims differ.`);
  }
  const dependencies = {
    objective_bounty_claimed_packet: [OBJECTIVE_BOUNTY_CLAIMED_PACKET_821_PROFILE,
      association.claim_packet_count],
    turret_plate_event_packet: [TURRET_PLATE_EVENT_PACKET_821_PROFILE,
      association.turret_plate_count],
    turret_die_event_packet: [TURRET_DIE_EVENT_PACKET_821_PROFILE,
      association.turret_die_count],
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
          association: profile.capability });
    }
    const [dependencyProfile, expectedCount] = dependencies[dependency];
    const diePacket = dependency === 'turret_die_event_packet';
    if (result.profile_id !== dependencyProfile.id
        || result.evidence_runtime_image_sha256 !== imageSha
        || result.runtime_image_sha256 !== imageSha
        || result.runtime_image_status !== 'MATCHED_USED'
        || result.runtime_image_used !== true
        || result.evidence_status !== (diePacket
          ? 'CANDIDATE_EXACT_RUNTIME_ON_TURRET_DIE_PACKET'
          : 'CANDIDATE_EXACT_RUNTIME_NAMED_ON_EVENT_CHILD')
        || result.input_packet_id !== 0x040a
        || result.child_event_id !== dependencyProfile.child_event_id
        || result.event_count !== expectedCount
        || (diePacket
          ? result.input_count !== result.event_count
          : result.target_packet_count !== result.event_count
            || !isCount(result.same_length_control_count)
            || result.input_count
              !== result.event_count + result.same_length_control_count)
        || !isDeepStrictEqual(result.known_limits, [...dependencyProfile.known_limits])
        || analysis.event_counts?.[`${dependency}_candidates`] !== expectedCount) {
      throw new EventQueryError('ASSOCIATION_METADATA_MISMATCH',
        `${dependency} identity or count disagrees with ${profile.capability}.`);
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

function prepareInventoryGameBroadcastBracketAssociation(semantic, analysis, eventKey,
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
  const interval = prepareInventoryKeyframeIntervalDifferenceAssociation(
    semantic, analysis, 'inventory_keyframe_interval_difference_candidates',
    ASSOCIATION_EVENTS_821.inventory_keyframe_interval_difference_candidates);
  const exclusions = [
    ['excluded_noncanonical_game_broadcast_count',
      'excluded_noncanonical_game_broadcast_packet_refs'],
    ['excluded_before_first_keyframe_count', 'excluded_before_first_keyframe_refs'],
    ['excluded_after_last_keyframe_count', 'excluded_after_last_keyframe_refs'],
    ['excluded_on_boundary_count', 'excluded_on_boundary_refs'],
  ];
  const labels = INVENTORY_GAME_COMPARISON_LABELS_821;
  const comparisonCounts = association.comparison_counts;
  if (association.profile_id !== profile.id
      || association.evidence_runtime_image_sha256
        !== profile.evidence_runtime_image_sha256
      || association.evidence_status !== evidenceStatus
      || association.replay_sha256 !== semantic.replay_sha256
      || association.runtime_image_sha256 !== profile.evidence_runtime_image_sha256
      || association.runtime_image_status !== 'MATCHED_USED'
      || association.runtime_image_used !== true
      || !isDeepStrictEqual(association.depends_on, [...profile.depends_on])
      || !isDeepStrictEqual(association.known_limits, [...profile.known_limits])
      || association.input_count !== interval.input_count
      || association.keyframe_count !== interval.keyframe_count
      || association.broadcast_keyframe_packet_count
        !== interval.broadcast_keyframe_packet_count
      || association.game_broadcast_packet_count
        !== interval.excluded_game_broadcast_count
      || association.verified_raw_packet_count !== interval.verified_raw_packet_count
      || !isCount(association.bracketed_game_broadcast_count)
      || association.event_count !== association.bracketed_game_broadcast_count
      || !isCount(association.record_comparison_count)
      || association.record_comparison_count < association.event_count * 6
      || association.record_comparison_count > association.event_count * 9
      || !isCount(association.distinct_participant_interval_count)
      || association.distinct_participant_interval_count > association.event_count
      || exclusions.some(([countName, refsName]) =>
        !isCount(association[countName])
        || !Array.isArray(association[refsName])
        || association[refsName].length !== association[countName])
      || association.event_count + exclusions.reduce((sum, [name]) =>
        sum + association[name], 0) !== association.game_broadcast_packet_count
      || !comparisonCounts || typeof comparisonCounts !== 'object'
      || Array.isArray(comparisonCounts)
      || !isDeepStrictEqual(Object.keys(comparisonCounts).sort(), labels.slice().sort())
      || labels.some((label) => !isCount(comparisonCounts[label]))
      || labels.reduce((sum, label) => sum + comparisonCounts[label], 0)
        !== association.record_comparison_count
      || analysis.event_counts?.[eventKey] !== association.event_count
      || !isDeepStrictEqual(
        analysis.semantic?.candidate_associations?.[profile.capability], association)) {
    throw new EventQueryError('ASSOCIATION_METADATA_MISMATCH',
      `${profile.capability} identity, source counts, or exclusions differ.`);
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

function prepareExperienceIntervalAssociation(semantic, analysis, eventKey,
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
  const dependency = 'hero_experience_snapshot';
  if (!Array.isArray(semantic.requested_capabilities)
      || !semantic.requested_capabilities.includes(dependency)) {
    throw new EventQueryError('CAPABILITY_NOT_REQUESTED',
      `${dependency} was not requested in this Replay artifact.`,
      { capability: dependency, association: profile.capability });
  }
  const snapshot = semantic.capability_results?.[dependency];
  if (snapshot?.status !== 'CANDIDATE') {
    throw new EventQueryError('CAPABILITY_UNAVAILABLE',
      `${dependency} is unavailable for ${profile.capability}.`,
      { capability: dependency, capability_status: snapshot?.status ?? null,
        association: profile.capability, missing_input: snapshot?.missing_input ?? null,
        error: snapshot?.error ?? null });
  }
  const sourceProfile = FLOAT_STATS_821_PROFILES.hero_experience_snapshot;
  const imageSha = profile.evidence_runtime_image_sha256;
  if (association.profile_id !== profile.id
      || association.evidence_runtime_image_sha256 !== imageSha
      || association.lookup_table_sha256 !== profile.lookup_table_sha256
      || association.evidence_status !== evidenceStatus
      || association.replay_sha256 !== semantic.replay_sha256
      || !isDeepStrictEqual(association.depends_on, [...profile.depends_on])
      || !isDeepStrictEqual(association.known_limits, [...profile.known_limits])
      || !isCount(association.input_count)
      || association.input_count > MAX_EXPERIENCE_INTERVAL_SOURCE_ROWS_821
      || !isCount(association.keyframe_count) || association.keyframe_count < 1
      || association.input_count !== association.keyframe_count * 10
      || association.observed_interval_count
        !== (association.keyframe_count - 1) * 10
      || !isCount(association.changed_interval_count)
      || !isCount(association.unchanged_interval_count)
      || association.changed_interval_count + association.unchanged_interval_count
        !== association.observed_interval_count
      || association.event_count !== association.changed_interval_count
      || association.verified_raw_packet_count !== association.input_count
      || analysis.event_counts?.[eventKey] !== association.event_count
      || !isDeepStrictEqual(
        analysis.semantic?.candidate_associations?.[profile.capability], association)
      || snapshot.profile_id !== sourceProfile.id
      || snapshot.evidence_runtime_image_sha256 !== imageSha
      || snapshot.lookup_table_sha256 !== profile.lookup_table_sha256
      || !isDeepStrictEqual(snapshot.known_limits, [...sourceProfile.known_limits])
      || snapshot.evidence_status
        !== 'CANDIDATE_821_RUNTIME_BYTE_KEYFRAME_F32_AND_REPLAY_TAIL'
      || snapshot.input_packet_id !== profile.packet_id
      || snapshot.input_count !== association.input_count
      || snapshot.event_count !== association.input_count
      || snapshot.keyframe_count !== association.keyframe_count
      || snapshot.observed_participant_count !== 10
      || snapshot.descent_count !== 0
      || snapshot.runtime_image_used !== false
      || !['STATIC_821_RUNTIME_TRANSFORM_EMBEDDED', 'PROVIDED_NOT_USED']
        .includes(snapshot.runtime_image_status)
      || analysis.event_counts?.hero_experience_snapshot_candidates
        !== association.input_count
      || !isDeepStrictEqual(
        analysis.semantic?.capability_results?.[dependency], snapshot)) {
    throw new EventQueryError('ASSOCIATION_METADATA_MISMATCH',
      `${profile.capability} identity, source snapshots or interval counts differ.`,
      { capability: profile.capability });
  }
  return association;
}

function prepareLevelExperienceBracketAssociation(semantic, analysis, eventKey,
  { profile, evidenceStatus }) {
  if (semantic.replay_version !== profile.replay_version) {
    throw new EventQueryError('UNSUPPORTED_EVENT_BUILD',
      `${eventKey} requires exact build ${profile.replay_version}.`);
  }
  const association = semantic.candidate_associations?.[profile.capability];
  if (association?.status !== 'CANDIDATE') {
    throw new EventQueryError('ASSOCIATION_UNAVAILABLE',
      `${profile.capability} is not an executed candidate association.`,
      { capability: profile.capability,
        association_status: association?.status ?? null,
        error: association?.error ?? null });
  }
  const level = semantic.capability_results?.hero_level_state;
  const experience = semantic.capability_results?.hero_experience_snapshot;
  const sourceProfiles = [HERO_LEVEL_CANDIDATE_PROFILE_821,
    FLOAT_STATS_821_PROFILES.hero_experience_snapshot];
  for (const [index, capability] of profile.depends_on.entries()) {
    if (!semantic.requested_capabilities?.includes(capability)) {
      throw new EventQueryError('CAPABILITY_NOT_REQUESTED',
        `${capability} was not requested for ${profile.capability}.`);
    }
    const result = index === 0 ? level : experience;
    if (result?.status !== 'CANDIDATE') {
      throw new EventQueryError('CAPABILITY_UNAVAILABLE',
        `${capability} is unavailable for ${profile.capability}.`,
        { capability, capability_status: result?.status ?? null });
    }
    if (result.profile_id !== sourceProfiles[index].id
        || result.evidence_runtime_image_sha256
          !== profile.evidence_runtime_image_sha256
        || result.input_packet_id !== sourceProfiles[index].replay_block_packet_id
        || result.input_count !== result.event_count
        || analysis.event_counts?.[`${capability}_candidates`] !== result.event_count) {
      throw new EventQueryError('ASSOCIATION_METADATA_MISMATCH',
        `${capability} source identity or counts differ from ${profile.capability}.`);
    }
  }
  if (level.evidence_status !== 'CANDIDATE_821_RUNTIME_LEVEL_BYTE_AND_REPLAY_TAIL'
      || level.runtime_image_used !== false
      || !['STATIC_821_RUNTIME_TRANSFORM_EMBEDDED', 'PROVIDED_NOT_USED']
        .includes(level.runtime_image_status)
      || experience.evidence_status
        !== 'CANDIDATE_821_RUNTIME_BYTE_KEYFRAME_F32_AND_REPLAY_TAIL'
      || experience.lookup_table_sha256 !== profile.lookup_table_sha256
      || experience.runtime_image_used !== false
      || !['STATIC_821_RUNTIME_TRANSFORM_EMBEDDED', 'PROVIDED_NOT_USED']
        .includes(experience.runtime_image_status)
      || experience.observed_participant_count !== 10
      || experience.descent_count !== 0
      || experience.keyframe_count !== association.keyframe_count
      || association.profile_id !== profile.id
      || association.replay_sha256 !== semantic.replay_sha256
      || association.evidence_runtime_image_sha256
        !== profile.evidence_runtime_image_sha256
      || association.lookup_table_sha256 !== profile.lookup_table_sha256
      || association.evidence_status !== evidenceStatus
      || !isDeepStrictEqual(association.depends_on, [...profile.depends_on])
      || !isDeepStrictEqual(association.known_limits, [...profile.known_limits])
      || !isCount(association.level_packet_count)
      || association.level_packet_count !== level.event_count
      || !isCount(association.experience_snapshot_count)
      || association.experience_snapshot_count !== experience.event_count
      || !isCount(association.keyframe_count) || association.keyframe_count < 1
      || association.experience_snapshot_count !== association.keyframe_count * 10
      || !isCount(association.event_count)
      || !isCount(association.higher_level_observation_count)
      || !isCount(association.excluded_level_one_count)
      || !isCount(association.excluded_repeated_level_count)
      || association.higher_level_observation_count
        + association.excluded_level_one_count
        + association.excluded_repeated_level_count !== association.level_packet_count
      || !isCount(association.outside_first_keyframe_count)
      || !isCount(association.outside_last_keyframe_count)
      || !isCount(association.exact_keyframe_boundary_count)
      || association.event_count + association.outside_first_keyframe_count
        + association.outside_last_keyframe_count
        + association.exact_keyframe_boundary_count
        !== association.higher_level_observation_count
      || !isCount(association.observed_level_sequence_gap_count)
      || !isCount(association.positive_endpoint_count)
      || !isCount(association.unchanged_endpoint_count)
      || association.positive_endpoint_count + association.unchanged_endpoint_count
        !== association.event_count
      || !isCount(association.multi_level_interval_count)
      || !isCount(association.involved_interval_count)
      || !isCount(association.positive_involved_interval_count)
      || !isCount(association.unchanged_involved_interval_count)
      || association.positive_involved_interval_count
        + association.unchanged_involved_interval_count
        !== association.involved_interval_count
      || association.involved_interval_count > association.event_count
      || !isCount(association.max_level_packets_per_interval)
      || association.multi_level_interval_count > association.event_count
      || association.max_level_packets_per_interval > association.event_count
      || association.verified_level_raw_packet_count !== association.level_packet_count
      || association.verified_experience_raw_packet_count
        !== association.experience_snapshot_count
      || analysis.event_counts?.[eventKey] !== association.event_count
      || (analysis.semantic?.candidate_associations?.[profile.capability] != null
        && !isDeepStrictEqual(
          analysis.semantic.candidate_associations[profile.capability], association))) {
    throw new EventQueryError('ASSOCIATION_METADATA_MISMATCH',
      `${profile.capability} identity, source counts or endpoint counts differ.`);
  }
  return association;
}

function prepareAssociation(semantic, analysis, eventKey, associationConfig) {
  if (associationConfig.levelExperienceBracket) {
    return prepareLevelExperienceBracketAssociation(semantic, analysis, eventKey,
      associationConfig);
  }
  if (associationConfig.experienceInterval) {
    return prepareExperienceIntervalAssociation(semantic, analysis, eventKey,
      associationConfig);
  }
  if (associationConfig.minionBracket) {
    return prepareMinionBracketAssociation(semantic, analysis, eventKey,
      associationConfig);
  }
  if (associationConfig.inventoryInterval) {
    return prepareInventoryKeyframeIntervalDifferenceAssociation(semantic, analysis,
      eventKey, associationConfig);
  }
  if (associationConfig.inventoryGameBracket) {
    return prepareInventoryGameBroadcastBracketAssociation(semantic, analysis,
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
  if (associationConfig.objectiveBountyTurretPair) {
    return prepareObjectiveBountyTurretPairAssociation(semantic, analysis,
      eventKey, associationConfig);
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

const PREPARED_REPLAY_METADATA = Symbol('prepared replay metadata');

function prepareEventQuery(directory, eventKey) {
  if (typeof eventKey !== 'string' || !EVENT_KEY.test(eventKey)) {
    throw new EventQueryError('INVALID_EVENT_KEY',
      'The event key must be an exact lowercase *_candidates name.');
  }
  const artifactDirectory = path.resolve(directory);
  const semantic = readArtifactJson(artifactDirectory, 'semantic_run.json');
  const analysis = readArtifactJson(artifactDirectory, 'replay_analysis.json');
  return prepareEventQueryFromDocuments(artifactDirectory, eventKey,
    semantic, analysis);
}

// Secondary streams belong to the same Replay. Reuse its already checked
// metadata; each source still gets its own capability and JSONL file checks.
function prepareEventQueryFromDocuments(artifactDirectory, eventKey,
  semantic, analysis) {
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
  const capability = eventKey === 'unit_apply_damage_roster_key_candidates'
    ? 'unit_apply_damage_roster_key_pair'
    : eventKey === 'unit_apply_damage_lookup_roster_key_candidates'
      ? 'unit_apply_damage_lookup_roster_key_pair'
    : eventKey === 'unit_apply_damage_lookup2c_roster_key_candidates'
      ? 'unit_apply_damage_lookup2c_roster_key_pair'
    : eventKey.slice(0, -'_candidates'.length);
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
  if (eventKey === 'first_blood_assist_event_packet_candidates') {
    prepareFirstBloodAssistPacketEvent(semantic, analysis, eventKey,
      capabilityResult);
  }
  if (exactPacketProfile) {
    prepareExactPacketEvent(semantic, analysis, eventKey, capabilityResult,
      exactPacketProfile);
  }
  if (exactBlobPacketConfig) {
    prepareExactBlobPacketEvent(semantic, analysis, eventKey, capabilityResult,
      exactBlobPacketConfig);
  }
  if (eventKey === 'objective_bounty_claimed_packet_candidates') {
    prepareObjectiveBountyClaimedPacketEvent(semantic, analysis, eventKey,
      capabilityResult);
  }
  if (eventKey === 'increment_minion_kills_packet_candidates') {
    prepareIncrementMinionKillsPacketEvent(semantic, analysis, eventKey,
      capabilityResult);
  }
  if (eventKey === 'face_direction_keyframe_roster_pair_candidates') {
    prepareFaceDirectionRosterPairEvent(semantic, analysis, eventKey,
      capabilityResult);
  }
  if (eventKey === 'unit_apply_damage_roster_key_candidates') {
    prepareUnitApplyDamageRosterKeyEvent(semantic, analysis, eventKey,
      capabilityResult);
  }
  if (eventKey === 'unit_apply_damage_lookup_roster_key_candidates') {
    prepareUnitApplyDamageLookupRosterKeyEvent(semantic, analysis, eventKey,
      capabilityResult);
  }
  if (eventKey === 'unit_apply_damage_lookup2c_roster_key_candidates') {
    prepareUnitApplyDamageLookup2cRosterKeyEvent(semantic, analysis, eventKey,
      capabilityResult);
  }
  if (eventKey === 'hero_death_damage_lookup_key_cooccurrence_candidates') {
    prepareHeroDeathDamageLookupKeyCooccurrenceEvent(semantic, analysis,
      eventKey, capabilityResult);
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
    packet: prepareEventQueryFromDocuments(artifactDirectory,
      'increment_minion_kills_packet_candidates', semantic, analysis),
    snapshot: prepareEventQueryFromDocuments(artifactDirectory,
      'hero_minions_killed_snapshot_candidates', semantic, analysis),
  } : null;
  const experienceIntervalSource = associationConfig?.experienceInterval
    ? prepareEventQueryFromDocuments(artifactDirectory,
      'hero_experience_snapshot_candidates', semantic, analysis) : null;
  const levelExperienceBracketSources = associationConfig?.levelExperienceBracket
    ? {
      level: prepareEventQueryFromDocuments(artifactDirectory,
        'hero_level_state_candidates', semantic, analysis),
      experience: prepareEventQueryFromDocuments(artifactDirectory,
        'hero_experience_snapshot_candidates', semantic, analysis),
    } : null;
  const objectiveBountyTurretPairSources = associationConfig?.objectiveBountyTurretPair
    ? Object.fromEntries(OBJECTIVE_BOUNTY_TURRET_PAIR_SOURCE_EVENTS_821.map(
      ({ eventKey: sourceEventKey }) => [sourceEventKey,
        prepareEventQueryFromDocuments(artifactDirectory, sourceEventKey,
          semantic, analysis)])) : null;
  const prepared = {
    artifactDirectory, inputPath, eventKey, eventStorage, capability, capabilityStatus,
    capabilityResult, declaredCount, replaySha, associationConfig, exactPacketProfile,
    exactBlobPacketConfig, bracketSources, experienceIntervalSource,
    levelExperienceBracketSources,
    objectiveBountyTurretPairSources,
    sourcePath: analysis.source_path,
    episodeAssistNativeStatus: associationConfig?.episode
      ? semantic.capability_results?.hero_assist?.native_child_identity_status : null,
    replayVersion: semantic.replay_version, semanticRunStatus: semantic.status,
    semanticApiStatus: semantic.api_status ?? null,
  };
  Object.defineProperty(prepared, PREPARED_REPLAY_METADATA,
    { value: { semantic, analysis, inventoryIntervalSource: null } });
  return prepared;
}

function prepareInventoryIntervalSource(prepared) {
  const metadata = prepared[PREPARED_REPLAY_METADATA];
  if (!metadata) {
    throw new EventQueryError('INVALID_METADATA',
      'Inventory interval query lacks its prepared Replay metadata.');
  }
  metadata.inventoryIntervalSource ??= prepareEventQueryFromDocuments(
    prepared.artifactDirectory, 'hero_inventory_broadcast_packet_candidates',
    metadata.semantic, metadata.analysis);
  return metadata.inventoryIntervalSource;
}

function prepareBatchEventQuery(directory, eventKey) {
  const artifactDirectory = path.resolve(directory);
  const manifest = readArtifactJson(artifactDirectory, 'manifest.json');
  const hashes = manifest.output_hashes_excluding_manifest;
  const replayCount = Array.isArray(manifest.replay_inputs)
    ? manifest.replay_inputs.length : 0;
  const command = Array.isArray(manifest.command_args)
    ? manifest.command_args[0] : null;
  if (!(['batch', 'decode'].includes(command) && replayCount > 0)
      || !hashes || typeof hashes !== 'object' || Array.isArray(hashes)) {
    throw new EventQueryError('INVALID_BATCH_METADATA',
      'manifest.json must identify a nonempty batch or decode run with output hashes.');
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
      if (prepared.experienceIntervalSource) {
        const source = prepared.experienceIntervalSource;
        checkHash(`${relative}/${source.eventKey}.jsonl`, source.inputPath);
      }
      if (prepared.levelExperienceBracketSources) {
        for (const source of Object.values(prepared.levelExperienceBracketSources)) {
          checkHash(`${relative}/${source.eventKey}.jsonl`, source.inputPath);
        }
      }
      if (prepared.objectiveBountyTurretPairSources) {
        for (const source of Object.values(prepared.objectiveBountyTurretPairSources)) {
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
  return { artifactDirectory, eventKey, replays, outputHashes: hashes };
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

function prepareCastSpellAnsNestedBits(prepared) {
  const profile = CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_821;
  if (prepared.eventKey !== 'cast_spell_ans_packet_candidates'
      || prepared.replayVersion !== profile.replay_version) {
    throw new EventQueryError('UNSUPPORTED_FILTER',
      '--cast-nested-bits requires an exact 16.19.821.7343 CastSpellAns packet candidate event.');
  }
  const result = prepared.capabilityResult;
  if (result?.profile_id === profile.id.replace(/-v4$/, '-v3')) {
    throw new EventQueryError('CAST_NESTED_BITS_UNAVAILABLE',
      'This CastSpellAns artifact predates the nested callback bit field.',
      { cast_nested_bits_checked_count: 0,
        cast_nested_bits_unavailable_count: prepared.declaredCount,
        capability_status: prepared.capabilityStatus });
  }
  if (prepared.capabilityStatus !== 'CANDIDATE'
      || result?.profile_id !== profile.id
      || result.input_packet_id !== profile.replay_block_packet_id
      || result.evidence_runtime_image_sha256
        !== profile.evidence_runtime_image_sha256
      || result.runtime_image_sha256 !== profile.evidence_runtime_image_sha256
      || result.evidence_callback_table_sha256
        !== profile.evidence_callback_table_sha256
      || result.evidence_nested_float_inverse_sha256
        !== profile.evidence_nested_float_inverse_sha256
      || result.evidence_nested_byte_inverse_sha256
        !== profile.evidence_nested_byte_inverse_sha256
      || result.runtime_image_status !== 'MATCHED_USED'
      || result.runtime_image_used !== true
      || result.evidence_status !== 'CANDIDATE_EXACT_RUNTIME_PACKET_FIELDS'
      || result.input_count !== result.event_count) {
    throw new EventQueryError('CAPABILITY_METADATA_MISMATCH',
      'CastSpellAns nested callback bit metadata differs from its exact-build profile.');
  }
}

function castSpellAnsNestedBits(row, prepared, lineNumber, packetPositions) {
  const invalid = (reason) => {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid CastSpellAns nested callback bits at JSONL line ${lineNumber}: ${reason}.`,
      { line_number: lineNumber });
  };
  const profile = CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_821;
  const ref = row.raw_packet_ref;
  if (row.event_type !== 'NPC_CAST_SPELL_ANS_PACKET_CANDIDATE'
      || row.game_version !== profile.replay_version || row.patch !== '16.19'
      || row.build_profile !== profile.id || row.confidence !== 'CANDIDATE'
      || row.semantic_status !== 'CANDIDATE_EXACT_RUNTIME_PACKET_FIELDS'
      || !Number.isSafeInteger(row.raw_param) || row.raw_param <= 0
      || row.raw_param > 0xffffffff || !ref
      || ref.source_path !== (prepared.sourcePath ?? null)
      || ref.replay_sha256 !== prepared.replaySha
      || ref.chunk_stream !== 'game_chunk' && ref.chunk_stream !== 'keyframe'
      || !Number.isSafeInteger(ref.chunk_index) || ref.chunk_index < 0
      || !Number.isSafeInteger(ref.chunk_id) || ref.chunk_id < 0
      || !Number.isSafeInteger(ref.chunk_file_offset) || ref.chunk_file_offset < 0
      || !Number.isSafeInteger(ref.decompressed_block_offset)
      || ref.decompressed_block_offset < 0
      || !Number.isSafeInteger(ref.decompressed_payload_offset)
      || ref.decompressed_payload_offset <= ref.decompressed_block_offset
      || ref.packet_id !== profile.replay_block_packet_id
      || ref.replay_time_ms !== row.replay_time_ms
      || !Number.isSafeInteger(ref.payload_length) || ref.payload_length < 97
      || ref.payload_length > 189 || ref.raw_param !== row.raw_param
      || !REPLAY_SHA.test(ref.raw_payload_sha256 ?? '')) {
    invalid('candidate profile or raw packet reference differs');
  }
  const position = `${ref.chunk_index}/${ref.decompressed_block_offset}`;
  if (packetPositions.has(position)) invalid('raw packet reference occurs twice');
  packetPositions.add(position);
  const raw = row.raw_nested_bits_0x24_hex;
  const value = row.opaque_nested_bits_0x24;
  if (typeof raw !== 'string' || !/^[0-9a-f]{2}$/.test(raw)
      || !Number.isSafeInteger(value) || value < 0 || value > 0xff
      || value !== decodeNestedBits(raw)) {
    invalid('raw byte and decoded value differ from the pinned 821 transform');
  }
  return value;
}

function validUnitApplyDamageRosterRef(ref, replaySha, sourcePath, packetId,
  rawParam = null, replayTime = null) {
  const damage = packetId === 0x005f;
  const fields = damage ? UNIT_APPLY_DAMAGE_ROSTER_DAMAGE_REF_FIELDS_821
    : UNIT_APPLY_DAMAGE_ROSTER_STATS_REF_FIELDS_821;
  if (!ref || typeof ref !== 'object' || Array.isArray(ref)
      || Object.keys(ref).length !== fields.size
      || Object.keys(ref).some((field) => !fields.has(field))
      || ref.source_path !== (sourcePath ?? null)
      || ref.replay_sha256 !== replaySha
      || !Number.isSafeInteger(ref.chunk_index) || ref.chunk_index < 0
      || !Number.isSafeInteger(ref.chunk_id) || ref.chunk_id < 0
      || !Number.isSafeInteger(ref.chunk_file_offset)
      || ref.chunk_file_offset < 0
      || !Number.isSafeInteger(ref.decompressed_block_offset)
      || ref.decompressed_block_offset < 0
      || !Number.isSafeInteger(ref.decompressed_payload_offset)
      || ref.decompressed_payload_offset <= ref.decompressed_block_offset
      || ref.chunk_stream !== (damage ? 'game_chunk' : 'keyframe')
      || ref.packet_id !== packetId
      || !Number.isSafeInteger(ref.replay_time_ms) || ref.replay_time_ms < 0
      || !Number.isSafeInteger(ref.raw_param) || ref.raw_param < 0
      || ref.raw_param > 0xffffffff
      || (rawParam !== null && ref.raw_param !== rawParam)
      || (replayTime !== null && ref.replay_time_ms !== replayTime)
      || !REPLAY_SHA.test(ref.raw_payload_sha256)
      || (!damage && ref.payload_length !== 1263)) return false;
  if (!damage) return true;
  const hex = ref.raw_payload_hex;
  return ref.payload_length >= 8 && ref.payload_length <= 25
    && typeof hex === 'string' && /^[0-9a-f]+$/.test(hex)
    && hex.length === ref.payload_length * 2
    && crypto.createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex')
      === ref.raw_payload_sha256;
}

function damageAssociationProfile(result, current, historicalV1, historicalV2) {
  if (result?.profile_id === historicalV1.id) return historicalV1;
  if (result?.profile_id === historicalV2.id) return historicalV2;
  return current;
}

function damageDependencyAssociationProfile(parentProfile, current,
  historicalV1, historicalV2) {
  if (parentProfile.id.endsWith('-v1')) return historicalV1;
  if (parentProfile.id.endsWith('-v2')) return historicalV2;
  return current;
}

function damageProfileIdsForAssociation(profile, allowHistoricalV2 = false) {
  if (profile.id.endsWith('-v1')) {
    return allowHistoricalV2
      ? [UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V2_ID_821,
        UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V3_ID_821]
      : [UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V3_ID_821];
  }
  return profile.id.endsWith('-v2')
    ? [UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V4_ID_821]
    : [UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821.id];
}

function validDamageAssociationV3F32Metadata(result, profile, damage) {
  if (!profile.id.endsWith('-v3')) {
    return DAMAGE_ASSOCIATION_V3_F32_RESULT_FIELDS_821.every(
      (field) => !(field in result));
  }
  const counts = result.native_callback_f32_0x18_source_counts;
  if (result.evidence_callback_f32_0x18_table_sha256
        !== UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821
          .evidence_callback_f32_0x18_table_sha256
      || result.native_callback_f32_0x18_full_write_count
        !== result.damage_packet_count
      || !counts || typeof counts !== 'object' || Array.isArray(counts)
      || !isDeepStrictEqual(Object.keys(counts).sort(),
        [...UNIT_APPLY_DAMAGE_NATIVE_F32_0X18_SOURCES_821].sort())
      || UNIT_APPLY_DAMAGE_NATIVE_F32_0X18_SOURCES_821.some((source) =>
        !isCount(counts[source]))
      || UNIT_APPLY_DAMAGE_NATIVE_F32_0X18_SOURCES_821.reduce((sum, source) =>
        sum + counts[source], 0) !== result.damage_packet_count) return false;
  return !damage || DAMAGE_ASSOCIATION_V3_F32_RESULT_FIELDS_821.every(
    (field) => isDeepStrictEqual(result[field], damage[field]));
}

function validDamageAssociationV3F32Row(row, damageRef, profile) {
  if (!profile.id.endsWith('-v3')) return true;
  const payload = Buffer.from(damageRef.raw_payload_hex, 'hex');
  const selector = ((payload[0] >>> 6) | (payload[1] << 2)) & 7;
  const source = selector === 5 ? 'CONSTANT_0'
    : [0, 2, 3, 6].includes(selector) ? 'RAW_READER' : null;
  const encoded = row.native_callback_f32_0x18_encoded_bytes_hex;
  const value = row.native_callback_f32_0x18_candidate;
  const offset = row.native_callback_f32_0x18_raw_offset;
  const rawBytes = row.native_callback_f32_0x18_raw_bytes_hex;
  if (source === null || row.header_selector_bits_6_8 !== selector
      || row.native_callback_f32_0x18_source !== source
      || typeof encoded !== 'string' || !/^[0-9a-f]{8}$/.test(encoded)
      || !Number.isFinite(value)
      || !Object.is(value,
        decodeUnitApplyDamageCallbackF32At18FromEncoded821(encoded))) {
    return false;
  }
  if (source === 'CONSTANT_0') {
    return encoded === '3e3e3e3e' && Object.is(value, 0)
      && offset === null && rawBytes === null;
  }
  return Number.isSafeInteger(offset) && offset >= 0
    && offset + 4 <= payload.length
    && rawBytes === payload.subarray(offset, offset + 4).toString('hex')
    && encoded === Buffer.from(payload.subarray(offset, offset + 4))
      .reverse().toString('hex');
}

function validV4DamageU32Metadata(damage) {
  if (![UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V4_ID_821,
    UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821.id].includes(damage.profile_id)) {
    return !['evidence_callback_u32_0x10_table_sha256',
      'native_callback_u32_0x10_full_write_count',
      'native_callback_u32_0x10_source_counts'].some((field) => field in damage);
  }
  const counts = damage.native_callback_u32_0x10_source_counts;
  return damage.evidence_callback_u32_0x10_table_sha256
      === UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821
        .evidence_callback_u32_0x10_table_sha256
    && damage.native_callback_u32_0x10_full_write_count === damage.event_count
    && counts && typeof counts === 'object' && !Array.isArray(counts)
    && isDeepStrictEqual(Object.keys(counts).sort(),
      [...UNIT_APPLY_DAMAGE_NATIVE_U32_SOURCES_821].sort())
    && UNIT_APPLY_DAMAGE_NATIVE_U32_SOURCES_821.every((source) =>
      isCount(counts[source]))
    && UNIT_APPLY_DAMAGE_NATIVE_U32_SOURCES_821.reduce((sum, source) =>
      sum + counts[source], 0) === damage.event_count;
}

function validV5DamageF32At18Metadata(damage) {
  if (damage.profile_id !== UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821.id) {
    return !['evidence_callback_f32_0x18_table_sha256',
      'native_callback_f32_0x18_full_write_count',
      'native_callback_f32_0x18_source_counts'].some((field) => field in damage);
  }
  const counts = damage.native_callback_f32_0x18_source_counts;
  return damage.evidence_callback_f32_0x18_table_sha256
      === UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821
        .evidence_callback_f32_0x18_table_sha256
    && damage.native_callback_f32_0x18_full_write_count === damage.event_count
    && counts && typeof counts === 'object' && !Array.isArray(counts)
    && isDeepStrictEqual(Object.keys(counts).sort(),
      [...UNIT_APPLY_DAMAGE_NATIVE_F32_0X18_SOURCES_821].sort())
    && UNIT_APPLY_DAMAGE_NATIVE_F32_0X18_SOURCES_821.every((source) =>
      isCount(counts[source]))
    && UNIT_APPLY_DAMAGE_NATIVE_F32_0X18_SOURCES_821.reduce((sum, source) =>
      sum + counts[source], 0) === damage.event_count;
}

function prepareUnitApplyDamageRosterKeyEvent(semantic, analysis, eventKey, result) {
  const profile = damageAssociationProfile(result,
    UNIT_APPLY_DAMAGE_ROSTER_KEY_821_PROFILE,
    UNIT_APPLY_DAMAGE_ROSTER_KEY_PROFILE_V1_821,
    UNIT_APPLY_DAMAGE_ROSTER_KEY_PROFILE_V2_821);
  if (semantic.replay_version !== profile.replay_version) {
    throw new EventQueryError('UNSUPPORTED_EVENT_BUILD',
      `${eventKey} requires exact build ${profile.replay_version}.`);
  }
  if (result?.status !== 'CANDIDATE') return;
  const excluded = result.first_excluded_packet_refs;
  const damage = semantic.capability_results?.unit_apply_damage_packet;
  const snapshot = semantic.capability_results?.hero_minions_killed_snapshot;
  const recorded = analysis.semantic?.capability_results;
  const fields = profile.id.endsWith('-v3')
    ? UNIT_APPLY_DAMAGE_ROSTER_V3_RESULT_FIELDS_821
    : UNIT_APPLY_DAMAGE_ROSTER_RESULT_FIELDS_821;
  if (Object.keys(result).length !== fields.size
      || Object.keys(result).some((field) =>
        !fields.has(field))
      || result.profile_id !== profile.id
      || result.evidence_status !== profile.evidence_status
      || result.replay_sha256 !== semantic.replay_sha256
      || result.evidence_runtime_image_sha256
        !== profile.evidence_runtime_image_sha256
      || result.runtime_image_sha256 !== profile.evidence_runtime_image_sha256
      || result.runtime_image_status !== 'MATCHED_USED'
      || result.runtime_image_used !== true
      || !isDeepStrictEqual(result.depends_on, [...profile.depends_on])
      || !isDeepStrictEqual(result.known_limits, [...profile.known_limits])
      || !isDeepStrictEqual(result.dependency_statuses, {
        unit_apply_damage_packet: 'CANDIDATE',
        hero_minions_killed_snapshot: 'CANDIDATE',
      })
      || !isCount(result.damage_packet_count) || result.damage_packet_count === 0
      || !isCount(result.snapshot_count)
      || !isCount(result.keyframe_count) || result.keyframe_count === 0
      || result.snapshot_count !== 10 * result.keyframe_count
      || result.canonical_roster_key_count !== 10
      || !isCount(result.matched_full_key_packet_count)
      || result.matched_full_key_packet_count !== result.event_count
      || !isCount(result.unmatched_packet_count)
      || result.damage_packet_count !== result.event_count
        + result.unmatched_packet_count
      || !isCount(result.excluded_alias_0x100_packet_count)
      || result.excluded_alias_0x100_packet_count > result.unmatched_packet_count
      || result.verified_raw_packet_count !== result.damage_packet_count
        + result.snapshot_count
      || result.input_count !== result.verified_raw_packet_count
      || !validDamageAssociationV3F32Metadata(result, profile, damage)
      || !excluded || typeof excluded !== 'object' || Array.isArray(excluded)
      || Object.keys(excluded).sort().join(',')
        !== 'alias_0x100,unmatched_other'
      || (excluded.alias_0x100 === null)
        !== (result.excluded_alias_0x100_packet_count === 0)
      || (excluded.unmatched_other === null)
        !== (result.unmatched_packet_count
          - result.excluded_alias_0x100_packet_count === 0)
      || (excluded.alias_0x100 !== null
        && (!validUnitApplyDamageRosterRef(excluded.alias_0x100,
          semantic.replay_sha256, analysis.source_path, 0x005f)
          || excluded.alias_0x100.raw_param < 0x400001ae
          || excluded.alias_0x100.raw_param > 0x400001b7))
      || (excluded.unmatched_other !== null
        && (!validUnitApplyDamageRosterRef(excluded.unmatched_other,
          semantic.replay_sha256, analysis.source_path, 0x005f)
          || (excluded.unmatched_other.raw_param >= 0x400000ae
            && excluded.unmatched_other.raw_param <= 0x400000b7)
          || (excluded.unmatched_other.raw_param >= 0x400001ae
            && excluded.unmatched_other.raw_param <= 0x400001b7)))
      || analysis.event_counts?.[eventKey] !== result.event_count
      || !isDeepStrictEqual(recorded?.[profile.capability], result)
      || (damage && (damage.status !== 'CANDIDATE'
        || !damageProfileIdsForAssociation(profile, true)
          .includes(damage.profile_id)
        || damage.event_count !== result.damage_packet_count
        || damage.runtime_image_status !== 'MATCHED_USED'
        || damage.runtime_image_sha256 !== profile.evidence_runtime_image_sha256
        || damage.native_witness_status !== 'FULLY_CONSUMED_ALL'
        || !validV4DamageU32Metadata(damage)
        || !validV5DamageF32At18Metadata(damage)))
      || (snapshot && (snapshot.status !== 'CANDIDATE'
        || snapshot.profile_id
          !== FLOAT_STATS_821_PROFILES.hero_minions_killed_snapshot.id
        || snapshot.event_count !== result.snapshot_count
        || snapshot.keyframe_count !== result.keyframe_count))
      || !isDeepStrictEqual(recorded?.unit_apply_damage_packet, damage)
      || !isDeepStrictEqual(recorded?.hero_minions_killed_snapshot, snapshot)) {
    throw new EventQueryError('CAPABILITY_METADATA_MISMATCH',
      `${profile.capability} identity, dependency or counts differ.`,
      { capability: profile.capability });
  }
}

function prepareUnitApplyDamageLookupRosterKeyEvent(semantic, analysis,
  eventKey, result) {
  const profile = damageAssociationProfile(result,
    UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_KEY_821_PROFILE,
    UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_KEY_PROFILE_V1_821,
    UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_KEY_PROFILE_V2_821);
  if (semantic.replay_version !== profile.replay_version) {
    throw new EventQueryError('UNSUPPORTED_EVENT_BUILD',
      `${eventKey} requires exact build ${profile.replay_version}.`);
  }
  if (result?.status !== 'CANDIDATE') return;
  const unmatched = result.first_unmatched_packet_refs;
  const damage = semantic.capability_results?.unit_apply_damage_packet;
  const snapshot = semantic.capability_results?.hero_minions_killed_snapshot;
  const rawPair = semantic.capability_results?.unit_apply_damage_roster_key_pair;
  const recorded = analysis.semantic?.capability_results;
  const fields = profile.id.endsWith('-v3')
    ? UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_V3_RESULT_FIELDS_821
    : UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_RESULT_FIELDS_821;
  if (Object.keys(result).length !== fields.size
      || Object.keys(result).some((field) =>
        !fields.has(field))
      || result.profile_id !== profile.id
      || result.evidence_status !== profile.evidence_status
      || result.replay_sha256 !== semantic.replay_sha256
      || result.evidence_runtime_image_sha256
        !== profile.evidence_runtime_image_sha256
      || result.evidence_lookup_key_0x24_table_sha256
        !== profile.evidence_lookup_key_0x24_table_sha256
      || result.runtime_image_sha256 !== profile.evidence_runtime_image_sha256
      || result.runtime_image_status !== 'MATCHED_USED'
      || result.runtime_image_used !== true
      || !isDeepStrictEqual(result.depends_on, [...profile.depends_on])
      || !isDeepStrictEqual(result.known_limits, [...profile.known_limits])
      || !isDeepStrictEqual(result.dependency_statuses, {
        unit_apply_damage_packet: 'CANDIDATE',
        hero_minions_killed_snapshot: 'CANDIDATE',
        unit_apply_damage_roster_key_pair: 'CANDIDATE',
      })
      || !isCount(result.damage_packet_count) || result.damage_packet_count === 0
      || !isCount(result.snapshot_count)
      || !isCount(result.keyframe_count) || result.keyframe_count === 0
      || result.snapshot_count !== 10 * result.keyframe_count
      || result.canonical_roster_key_count !== 10
      || !isCount(result.matched_lookup_key_packet_count)
      || result.matched_lookup_key_packet_count !== result.event_count
      || !isCount(result.matched_alias_0x100_packet_count)
      || !isCount(result.matched_equal_packet_count)
      || !isCount(result.matched_other_relation_packet_count)
      || result.event_count !== result.matched_alias_0x100_packet_count
        + result.matched_equal_packet_count
        + result.matched_other_relation_packet_count
      || !isCount(result.unmatched_packet_count)
      || result.damage_packet_count !== result.event_count
        + result.unmatched_packet_count
      || !isCount(result.unmatched_alias_0x100_packet_count)
      || result.unmatched_alias_0x100_packet_count > result.unmatched_packet_count
      || result.verified_raw_packet_count !== result.damage_packet_count
        + result.snapshot_count
      || result.input_count !== result.verified_raw_packet_count
      || !validDamageAssociationV3F32Metadata(result, profile, damage)
      || !unmatched || typeof unmatched !== 'object' || Array.isArray(unmatched)
      || Object.keys(unmatched).sort().join(',') !== 'alias_0x100,other'
      || (unmatched.alias_0x100 === null)
        !== (result.unmatched_alias_0x100_packet_count === 0)
      || (unmatched.other === null)
        !== (result.unmatched_packet_count
          - result.unmatched_alias_0x100_packet_count === 0)
      || (unmatched.alias_0x100 !== null
        && (!validUnitApplyDamageRosterRef(unmatched.alias_0x100,
          semantic.replay_sha256, analysis.source_path, 0x005f)
          || unmatched.alias_0x100.raw_param < 0x400001ae
          || unmatched.alias_0x100.raw_param > 0x400001b7))
      || (unmatched.other !== null
        && (!validUnitApplyDamageRosterRef(unmatched.other,
          semantic.replay_sha256, analysis.source_path, 0x005f)
          || (unmatched.other.raw_param >= 0x400001ae
            && unmatched.other.raw_param <= 0x400001b7)))
      || analysis.event_counts?.[eventKey] !== result.event_count
      || !isDeepStrictEqual(recorded?.[profile.capability], result)
      || (damage && (damage.status !== 'CANDIDATE'
        || !damageProfileIdsForAssociation(profile).includes(damage.profile_id)
        || damage.evidence_status
          !== UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821.evidence_status
        || damage.event_count !== result.damage_packet_count
        || damage.input_count !== damage.event_count
        || damage.native_witness_status !== 'FULLY_CONSUMED_ALL'
        || damage.native_full_success_count !== result.damage_packet_count
        || damage.native_callback_lookup_full_write_count
          !== result.damage_packet_count
        || !REPLAY_SHA.test(damage.native_input_sha256 ?? '')
        || damage.evidence_lookup_key_0x24_table_sha256
          !== profile.evidence_lookup_key_0x24_table_sha256
        || damage.evidence_lookup_key_0x2c_table_sha256
          !== UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821
            .evidence_lookup_key_0x2c_table_sha256
        || damage.runtime_image_status !== 'MATCHED_USED'
        || damage.runtime_image_used !== true
        || damage.runtime_image_sha256
          !== profile.evidence_runtime_image_sha256
        || !validV4DamageU32Metadata(damage)
        || !validV5DamageF32At18Metadata(damage)))
      || (snapshot && (snapshot.status !== 'CANDIDATE'
        || snapshot.profile_id
          !== FLOAT_STATS_821_PROFILES.hero_minions_killed_snapshot.id
        || snapshot.event_count !== result.snapshot_count
        || snapshot.input_count !== snapshot.event_count
        || snapshot.keyframe_count !== result.keyframe_count
        || snapshot.observed_participant_count !== 10))
      || (rawPair && (rawPair.status !== 'CANDIDATE'
        || rawPair.profile_id !== damageDependencyAssociationProfile(profile,
          UNIT_APPLY_DAMAGE_ROSTER_KEY_821_PROFILE,
          UNIT_APPLY_DAMAGE_ROSTER_KEY_PROFILE_V1_821,
          UNIT_APPLY_DAMAGE_ROSTER_KEY_PROFILE_V2_821).id
        || rawPair.evidence_status
          !== UNIT_APPLY_DAMAGE_ROSTER_KEY_821_PROFILE.evidence_status
        || !validDamageAssociationV3F32Metadata(rawPair,
          damageDependencyAssociationProfile(profile,
            UNIT_APPLY_DAMAGE_ROSTER_KEY_821_PROFILE,
            UNIT_APPLY_DAMAGE_ROSTER_KEY_PROFILE_V1_821,
            UNIT_APPLY_DAMAGE_ROSTER_KEY_PROFILE_V2_821), damage)
        || rawPair.damage_packet_count !== result.damage_packet_count
        || rawPair.snapshot_count !== result.snapshot_count
        || rawPair.keyframe_count !== result.keyframe_count
        || rawPair.verified_raw_packet_count
          !== result.verified_raw_packet_count
        || rawPair.input_count !== rawPair.verified_raw_packet_count
        || !isCount(rawPair.event_count)
        || rawPair.event_count > result.damage_packet_count
        || !isCount(rawPair.excluded_alias_0x100_packet_count)
        || rawPair.excluded_alias_0x100_packet_count
          < result.matched_alias_0x100_packet_count
            + result.unmatched_alias_0x100_packet_count))
      || !isDeepStrictEqual(recorded?.unit_apply_damage_packet, damage)
      || !isDeepStrictEqual(recorded?.hero_minions_killed_snapshot, snapshot)
      || !isDeepStrictEqual(recorded?.unit_apply_damage_roster_key_pair,
        rawPair)) {
    throw new EventQueryError('CAPABILITY_METADATA_MISMATCH',
      `${profile.capability} identity, native v3 dependency or counts differ.`,
      { capability: profile.capability });
  }
}

function prepareUnitApplyDamageLookup2cRosterKeyEvent(semantic, analysis,
  eventKey, result) {
  const profile = damageAssociationProfile(result,
    UNIT_APPLY_DAMAGE_LOOKUP2C_ROSTER_KEY_821_PROFILE,
    UNIT_APPLY_DAMAGE_LOOKUP2C_ROSTER_KEY_PROFILE_V1_821,
    UNIT_APPLY_DAMAGE_LOOKUP2C_ROSTER_KEY_PROFILE_V2_821);
  if (semantic.replay_version !== profile.replay_version) {
    throw new EventQueryError('UNSUPPORTED_EVENT_BUILD',
      `${eventKey} requires exact build ${profile.replay_version}.`);
  }
  if (result?.status !== 'CANDIDATE') return;
  const damage = semantic.capability_results?.unit_apply_damage_packet;
  const snapshot = semantic.capability_results?.hero_minions_killed_snapshot;
  const rawPair = semantic.capability_results?.unit_apply_damage_roster_key_pair;
  const lookup24Pair = semantic.capability_results?.unit_apply_damage_lookup_roster_key_pair;
  const recorded = analysis.semantic?.capability_results;
  const counts = result.matched_key24_roster_counts;
  const unmatched = result.first_unmatched_packet_refs;
  const expectedDependencies = Object.fromEntries(
    profile.depends_on.map((dependency) => [dependency, 'CANDIDATE']));
  const fields = profile.id.endsWith('-v3')
    ? UNIT_APPLY_DAMAGE_LOOKUP2C_ROSTER_V3_RESULT_FIELDS_821
    : UNIT_APPLY_DAMAGE_LOOKUP2C_ROSTER_RESULT_FIELDS_821;
  if (Object.keys(result).length !== fields.size
      || Object.keys(result).some((field) =>
        !fields.has(field))
      || result.profile_id !== profile.id
      || result.evidence_status !== profile.evidence_status
      || result.replay_sha256 !== semantic.replay_sha256
      || result.evidence_runtime_image_sha256
        !== profile.evidence_runtime_image_sha256
      || result.evidence_lookup_key_0x24_table_sha256
        !== profile.evidence_lookup_key_0x24_table_sha256
      || result.evidence_lookup_key_0x2c_table_sha256
        !== profile.evidence_lookup_key_0x2c_table_sha256
      || result.runtime_image_sha256 !== profile.evidence_runtime_image_sha256
      || result.runtime_image_status !== 'MATCHED_USED'
      || result.runtime_image_used !== true
      || !isDeepStrictEqual(result.depends_on, [...profile.depends_on])
      || !isDeepStrictEqual(result.known_limits, [...profile.known_limits])
      || !isDeepStrictEqual(result.dependency_statuses, expectedDependencies)
      || !isCount(result.damage_packet_count)
      || result.damage_packet_count === 0
      || !isCount(result.snapshot_count)
      || !isCount(result.keyframe_count) || result.keyframe_count === 0
      || result.snapshot_count !== 10 * result.keyframe_count
      || result.canonical_roster_key_count !== 10
      || !isCount(result.matched_lookup_key_packet_count)
      || result.matched_lookup_key_packet_count !== result.event_count
      || !isCount(result.unmatched_packet_count)
      || result.damage_packet_count !== result.event_count
        + result.unmatched_packet_count
      || !counts || typeof counts !== 'object' || Array.isArray(counts)
      || !isDeepStrictEqual(Object.keys(counts).sort(),
        [...UNIT_APPLY_DAMAGE_LOOKUP2C_KEY24_ROSTER_RELATIONS_821].sort())
      || UNIT_APPLY_DAMAGE_LOOKUP2C_KEY24_ROSTER_RELATIONS_821.some(
        (relation) => !isCount(counts[relation]))
      || UNIT_APPLY_DAMAGE_LOOKUP2C_KEY24_ROSTER_RELATIONS_821.reduce(
        (sum, relation) => sum + counts[relation], 0) !== result.event_count
      || !unmatched || typeof unmatched !== 'object' || Array.isArray(unmatched)
      || !isDeepStrictEqual(Object.keys(unmatched).sort(),
        ['key24_in_roster', 'key24_not_in_roster'])
      || (result.unmatched_packet_count === 0
        && (unmatched.key24_in_roster !== null
          || unmatched.key24_not_in_roster !== null))
      || (result.unmatched_packet_count > 0
        && unmatched.key24_in_roster === null
        && unmatched.key24_not_in_roster === null)
      || ['key24_in_roster', 'key24_not_in_roster'].some((key) =>
        unmatched[key] !== null
          && !validUnitApplyDamageRosterRef(unmatched[key],
            semantic.replay_sha256, analysis.source_path, 0x005f))
      || (unmatched.key24_in_roster !== null
        && unmatched.key24_not_in_roster !== null
        && unmatched.key24_in_roster.chunk_index
          === unmatched.key24_not_in_roster.chunk_index
        && unmatched.key24_in_roster.decompressed_block_offset
          === unmatched.key24_not_in_roster.decompressed_block_offset)
      || result.verified_raw_packet_count !== result.damage_packet_count
        + result.snapshot_count
      || result.input_count !== result.verified_raw_packet_count
      || !validDamageAssociationV3F32Metadata(result, profile, damage)
      || analysis.event_counts?.[eventKey] !== result.event_count
      || !isDeepStrictEqual(recorded?.[profile.capability], result)
      || (damage && (damage.status !== 'CANDIDATE'
        || !damageProfileIdsForAssociation(profile).includes(damage.profile_id)
        || damage.evidence_status
          !== UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821.evidence_status
        || damage.event_count !== result.damage_packet_count
        || damage.input_count !== damage.event_count
        || damage.native_witness_status !== 'FULLY_CONSUMED_ALL'
        || damage.native_full_success_count !== result.damage_packet_count
        || damage.native_callback_lookup_full_write_count
          !== result.damage_packet_count
        || !REPLAY_SHA.test(damage.native_input_sha256 ?? '')
        || damage.evidence_lookup_key_0x24_table_sha256
          !== profile.evidence_lookup_key_0x24_table_sha256
        || damage.evidence_lookup_key_0x2c_table_sha256
          !== profile.evidence_lookup_key_0x2c_table_sha256
        || damage.runtime_image_status !== 'MATCHED_USED'
        || damage.runtime_image_used !== true
        || damage.runtime_image_sha256
          !== profile.evidence_runtime_image_sha256
        || !validV4DamageU32Metadata(damage)
        || !validV5DamageF32At18Metadata(damage)))
      || (snapshot && (snapshot.status !== 'CANDIDATE'
        || snapshot.profile_id
          !== FLOAT_STATS_821_PROFILES.hero_minions_killed_snapshot.id
        || snapshot.event_count !== result.snapshot_count
        || snapshot.input_count !== snapshot.event_count
        || snapshot.keyframe_count !== result.keyframe_count
        || snapshot.observed_participant_count !== 10))
      || (rawPair && (rawPair.status !== 'CANDIDATE'
        || rawPair.profile_id !== damageDependencyAssociationProfile(profile,
          UNIT_APPLY_DAMAGE_ROSTER_KEY_821_PROFILE,
          UNIT_APPLY_DAMAGE_ROSTER_KEY_PROFILE_V1_821,
          UNIT_APPLY_DAMAGE_ROSTER_KEY_PROFILE_V2_821).id
        || rawPair.evidence_status
          !== UNIT_APPLY_DAMAGE_ROSTER_KEY_821_PROFILE.evidence_status
        || !validDamageAssociationV3F32Metadata(rawPair,
          damageDependencyAssociationProfile(profile,
            UNIT_APPLY_DAMAGE_ROSTER_KEY_821_PROFILE,
            UNIT_APPLY_DAMAGE_ROSTER_KEY_PROFILE_V1_821,
            UNIT_APPLY_DAMAGE_ROSTER_KEY_PROFILE_V2_821), damage)
        || rawPair.runtime_image_status !== 'MATCHED_USED'
        || rawPair.runtime_image_used !== true
        || rawPair.runtime_image_sha256
          !== profile.evidence_runtime_image_sha256
        || rawPair.canonical_roster_key_count !== 10
        || rawPair.damage_packet_count !== result.damage_packet_count
        || rawPair.snapshot_count !== result.snapshot_count
        || rawPair.keyframe_count !== result.keyframe_count
        || rawPair.verified_raw_packet_count
          !== result.verified_raw_packet_count
        || rawPair.input_count !== rawPair.verified_raw_packet_count
        || !isCount(rawPair.event_count)
        || rawPair.event_count > result.damage_packet_count))
      || (lookup24Pair && (lookup24Pair.status !== 'CANDIDATE'
        || lookup24Pair.profile_id
          !== damageDependencyAssociationProfile(profile,
            UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_KEY_821_PROFILE,
            UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_KEY_PROFILE_V1_821,
            UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_KEY_PROFILE_V2_821).id
        || lookup24Pair.evidence_status
          !== UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_KEY_821_PROFILE.evidence_status
        || !validDamageAssociationV3F32Metadata(lookup24Pair,
          damageDependencyAssociationProfile(profile,
            UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_KEY_821_PROFILE,
            UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_KEY_PROFILE_V1_821,
            UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_KEY_PROFILE_V2_821), damage)
        || lookup24Pair.evidence_runtime_image_sha256
          !== profile.evidence_runtime_image_sha256
        || lookup24Pair.runtime_image_status !== 'MATCHED_USED'
        || lookup24Pair.runtime_image_used !== true
        || lookup24Pair.runtime_image_sha256
          !== profile.evidence_runtime_image_sha256
        || lookup24Pair.evidence_lookup_key_0x24_table_sha256
          !== profile.evidence_lookup_key_0x24_table_sha256
        || lookup24Pair.canonical_roster_key_count !== 10
        || lookup24Pair.damage_packet_count !== result.damage_packet_count
        || lookup24Pair.snapshot_count !== result.snapshot_count
        || lookup24Pair.keyframe_count !== result.keyframe_count
        || lookup24Pair.verified_raw_packet_count
          !== result.verified_raw_packet_count
        || lookup24Pair.input_count !== lookup24Pair.verified_raw_packet_count
        || !isCount(lookup24Pair.event_count)
        || lookup24Pair.event_count > result.damage_packet_count
        || lookup24Pair.matched_lookup_key_packet_count
          !== lookup24Pair.event_count
        || lookup24Pair.event_count < counts.SAME_ROSTER_KEY
          + counts.DIFFERENT_ROSTER_KEY))
      || !isDeepStrictEqual(recorded?.unit_apply_damage_packet, damage)
      || !isDeepStrictEqual(recorded?.hero_minions_killed_snapshot, snapshot)
      || !isDeepStrictEqual(recorded?.unit_apply_damage_roster_key_pair, rawPair)
      || !isDeepStrictEqual(recorded?.unit_apply_damage_lookup_roster_key_pair,
        lookup24Pair)) {
    throw new EventQueryError('CAPABILITY_METADATA_MISMATCH',
      `${profile.capability} identity, native v3 dependencies or counts differ.`,
      { capability: profile.capability });
  }
}

function prepareHeroDeathDamageLookupKeyCooccurrenceEvent(semantic, analysis,
  eventKey, result) {
  const profile = damageAssociationProfile(result,
    HERO_DEATH_DAMAGE_LOOKUP_KEY_COOCCURRENCE_821_PROFILE,
    HERO_DEATH_DAMAGE_LOOKUP_KEY_COOCCURRENCE_PROFILE_V1_821,
    HERO_DEATH_DAMAGE_LOOKUP_KEY_COOCCURRENCE_PROFILE_V2_821);
  if (semantic.replay_version !== profile.replay_version) {
    throw new EventQueryError('UNSUPPORTED_EVENT_BUILD',
      `${eventKey} requires exact build ${profile.replay_version}.`);
  }
  if (result?.status !== 'CANDIDATE') return;
  const death = semantic.capability_results?.hero_death;
  const damage = semantic.capability_results?.unit_apply_damage_packet;
  const snapshot = semantic.capability_results?.hero_minions_killed_snapshot;
  const rawPair = semantic.capability_results?.unit_apply_damage_roster_key_pair;
  const recorded = analysis.semantic?.capability_results;
  const expectedDependencies = Object.fromEntries(
    profile.depends_on.map((dependency) => [dependency, 'CANDIDATE']));
  const deathCount = result.death_anchor_count;
  const damageCount = result.damage_packet_count;
  const snapshotCount = result.snapshot_count;
  const fields = profile.id.endsWith('-v3')
    ? HERO_DEATH_DAMAGE_LOOKUP_V3_RESULT_FIELDS_821
    : HERO_DEATH_DAMAGE_LOOKUP_RESULT_FIELDS_821;
  if (Object.keys(result).length !== fields.size
      || Object.keys(result).some((field) =>
        !fields.has(field))
      || result.profile_id !== profile.id
      || result.evidence_status !== profile.evidence_status
      || result.replay_sha256 !== semantic.replay_sha256
      || result.evidence_runtime_image_sha256
        !== profile.evidence_runtime_image_sha256
      || result.evidence_lookup_key_0x24_table_sha256
        !== profile.evidence_lookup_key_0x24_table_sha256
      || result.evidence_lookup_key_0x2c_table_sha256
        !== profile.evidence_lookup_key_0x2c_table_sha256
      || result.runtime_image_sha256 !== profile.evidence_runtime_image_sha256
      || result.runtime_image_status !== 'MATCHED_USED'
      || result.runtime_image_used !== true
      || !isDeepStrictEqual(result.depends_on, [...profile.depends_on])
      || !isDeepStrictEqual(result.known_limits, [...profile.known_limits])
      || !isDeepStrictEqual(result.dependency_statuses, expectedDependencies)
      || !isCount(deathCount) || result.event_count !== deathCount
      || !isCount(damageCount) || damageCount === 0
      || !isCount(snapshotCount) || snapshotCount === 0
      || snapshotCount % 10 !== 0
      || result.canonical_roster_key_count !== 10
      || result.verified_raw_damage_roster_packet_count
        !== damageCount + snapshotCount
      || !isCount(result.verified_hero_death_route_packet_count)
      || result.verified_hero_death_route_packet_count < 3 * deathCount
      || result.verified_hero_death_route_packet_count > 4 * deathCount
      || result.input_count !== deathCount + damageCount
      || !validDamageAssociationV3F32Metadata(result, profile, damage)
      || !isCount(result.matched_victim_key24_packet_count)
      || result.matched_victim_key24_packet_count > damageCount
      || !isCount(result.death_anchor_with_victim_key24_packet_count)
      || !isCount(result.death_anchor_without_victim_key24_packet_count)
      || result.death_anchor_with_victim_key24_packet_count
        + result.death_anchor_without_victim_key24_packet_count !== deathCount
      || !isCount(result.multiple_victim_key24_packet_anchor_count)
      || result.multiple_victim_key24_packet_anchor_count
        > result.death_anchor_with_victim_key24_packet_count
      || !isCount(result.max_victim_key24_packet_count_per_anchor)
      || result.max_victim_key24_packet_count_per_anchor
        > result.matched_victim_key24_packet_count
      || (result.death_anchor_with_victim_key24_packet_count === 0)
        !== (result.max_victim_key24_packet_count_per_anchor === 0)
      || !isCount(result.matched_die_source_key2c_packet_count)
      || result.matched_die_source_key2c_packet_count
        > result.matched_victim_key24_packet_count
      || !isCount(result.death_anchor_with_die_source_key2c_match_count)
      || !isCount(result.death_anchor_without_die_source_key2c_match_count)
      || !isCount(result.death_anchor_die_source_unavailable_count)
      || result.death_anchor_with_die_source_key2c_match_count
        + result.death_anchor_without_die_source_key2c_match_count
        + result.death_anchor_die_source_unavailable_count !== deathCount
      || analysis.event_counts?.[eventKey] !== result.event_count
      || !isDeepStrictEqual(recorded?.[profile.capability], result)
      || (death && (death.status !== 'CANDIDATE'
        || death.profile_id !== HERO_DEATH_CANDIDATE_PROFILE_821.id
        || death.evidence_status
          !== 'CANDIDATE_821_REPLAY_TAIL_ROUTE_FINGERPRINT'
        || death.evidence_runtime_image_sha256
          !== profile.evidence_runtime_image_sha256
        || death.source_id_lookup_table_sha256
          !== HERO_DEATH_CANDIDATE_PROFILE_821.source_id_lookup_table_sha256
        || death.event_count !== deathCount
        || death.matched_core_count !== deathCount
        || death.matched_core_supporting_packet_count
          !== result.verified_hero_death_route_packet_count))
      || (damage && (damage.status !== 'CANDIDATE'
        || !damageProfileIdsForAssociation(profile).includes(damage.profile_id)
        || damage.evidence_status
          !== UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821.evidence_status
        || damage.event_count !== damageCount
        || damage.input_count !== damage.event_count
        || damage.native_witness_status !== 'FULLY_CONSUMED_ALL'
        || damage.native_full_success_count !== damageCount
        || damage.native_callback_lookup_full_write_count !== damageCount
        || !REPLAY_SHA.test(damage.native_input_sha256 ?? '')
        || damage.evidence_lookup_key_0x24_table_sha256
          !== profile.evidence_lookup_key_0x24_table_sha256
        || damage.evidence_lookup_key_0x2c_table_sha256
          !== profile.evidence_lookup_key_0x2c_table_sha256
        || damage.runtime_image_status !== 'MATCHED_USED'
        || damage.runtime_image_used !== true
        || damage.runtime_image_sha256
          !== profile.evidence_runtime_image_sha256
        || !validV4DamageU32Metadata(damage)
        || !validV5DamageF32At18Metadata(damage)))
      || (snapshot && (snapshot.status !== 'CANDIDATE'
        || snapshot.profile_id
          !== FLOAT_STATS_821_PROFILES.hero_minions_killed_snapshot.id
        || snapshot.event_count !== snapshotCount
        || snapshot.input_count !== snapshot.event_count
        || snapshot.keyframe_count !== snapshotCount / 10
        || snapshot.observed_participant_count !== 10))
      || (rawPair && (rawPair.status !== 'CANDIDATE'
        || rawPair.profile_id !== damageDependencyAssociationProfile(profile,
          UNIT_APPLY_DAMAGE_ROSTER_KEY_821_PROFILE,
          UNIT_APPLY_DAMAGE_ROSTER_KEY_PROFILE_V1_821,
          UNIT_APPLY_DAMAGE_ROSTER_KEY_PROFILE_V2_821).id
        || rawPair.evidence_status
          !== UNIT_APPLY_DAMAGE_ROSTER_KEY_821_PROFILE.evidence_status
        || !validDamageAssociationV3F32Metadata(rawPair,
          damageDependencyAssociationProfile(profile,
            UNIT_APPLY_DAMAGE_ROSTER_KEY_821_PROFILE,
            UNIT_APPLY_DAMAGE_ROSTER_KEY_PROFILE_V1_821,
            UNIT_APPLY_DAMAGE_ROSTER_KEY_PROFILE_V2_821), damage)
        || rawPair.damage_packet_count !== damageCount
        || rawPair.snapshot_count !== snapshotCount
        || rawPair.canonical_roster_key_count !== 10
        || rawPair.verified_raw_packet_count
          !== result.verified_raw_damage_roster_packet_count
        || rawPair.input_count !== rawPair.verified_raw_packet_count
        || rawPair.runtime_image_status !== 'MATCHED_USED'
        || rawPair.runtime_image_used !== true
        || rawPair.runtime_image_sha256
          !== profile.evidence_runtime_image_sha256))
      || !isDeepStrictEqual(recorded?.hero_death, death)
      || !isDeepStrictEqual(recorded?.unit_apply_damage_packet, damage)
      || !isDeepStrictEqual(recorded?.hero_minions_killed_snapshot, snapshot)
      || !isDeepStrictEqual(recorded?.unit_apply_damage_roster_key_pair,
        rawPair)) {
    throw new EventQueryError('CAPABILITY_METADATA_MISMATCH',
      `${profile.capability} identity, exact-build dependencies or counts differ.`,
      { capability: profile.capability });
  }
}

function prepareCircularMovementRestrictionRecordCount(prepared) {
  const profile = CIRCULAR_MOVEMENT_RESTRICTION_PACKET_CANDIDATE_PROFILE_821;
  if (prepared.eventKey !== 'circular_movement_restriction_packet_candidates'
      || prepared.replayVersion !== profile.replay_version) {
    throw new EventQueryError('UNSUPPORTED_FILTER',
      '--packet-record-count requires an exact 16.19.821.7343 circular movement restriction packet candidate event.');
  }
  const result = prepared.capabilityResult;
  const counts = result?.observed_shape_counts;
  if (prepared.capabilityStatus !== 'CANDIDATE'
      || result?.profile_id !== profile.id
      || result.input_packet_id !== profile.replay_block_packet_id
      || result.evidence_status !== profile.evidence_status
      || result.evidence_runtime_image_sha256
        !== profile.evidence_runtime_image_sha256
      || result.runtime_image_sha256 !== profile.evidence_runtime_image_sha256
      || result.evidence_byte_table_sha256
        !== profile.evidence_byte_table_sha256
      || result.evidence_scalar_transform_sha256
        !== profile.evidence_scalar_transform_sha256
      || result.evidence_vector_transform_sha256
        !== profile.evidence_vector_transform_sha256
      || result.runtime_image_status !== 'MATCHED_USED'
      || result.runtime_image_used !== true
      || !isCount(result.input_count) || result.input_count === 0
      || result.event_count !== result.input_count
      || result.event_count !== prepared.declaredCount
      || !counts || Object.keys(counts).length !== 2
      || !isCount(counts.empty1) || !isCount(counts.record24)
      || counts.empty1 + counts.record24 !== result.event_count) {
    throw new EventQueryError('CAPABILITY_METADATA_MISMATCH',
      'Circular movement restriction packet metadata differs from its exact-build profile.');
  }
}

function circularMovementRestrictionRecordCount(row, prepared, lineNumber,
  packetPositions) {
  const invalid = (reason) => {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid circular movement restriction packet at JSONL line ${lineNumber}: ${reason}.`,
      { line_number: lineNumber });
  };
  const profile = CIRCULAR_MOVEMENT_RESTRICTION_PACKET_CANDIDATE_PROFILE_821;
  const fields = Object.keys(row);
  const ref = row.raw_packet_ref;
  if (fields.length !== CIRCULAR_MOVEMENT_RESTRICTION_ROW_FIELDS_821.size
      || fields.some((field) => !CIRCULAR_MOVEMENT_RESTRICTION_ROW_FIELDS_821.has(field))
      || row.event_type !== 'CIRCULAR_MOVEMENT_RESTRICTION_PACKET_CANDIDATE'
      || row.game_version !== profile.replay_version || row.patch !== '16.19'
      || row.build_profile !== profile.id
      || row.confidence !== 'CANDIDATE'
      || row.semantic_status !== profile.evidence_status
      || row.semantic_effect_status !== 'UNKNOWN'
      || !Number.isSafeInteger(row.raw_param) || row.raw_param < 0
      || row.raw_param > 0xffffffff
      || typeof row.raw_payload_hex !== 'string'
      || !/^(?:[0-9a-f]{2})+$/.test(row.raw_payload_hex)
      || !ref || typeof ref !== 'object' || Array.isArray(ref)
      || ref.source_path !== prepared.sourcePath
      || ref.replay_sha256 !== prepared.replaySha
      || !['game_chunk', 'keyframe'].includes(ref.chunk_stream)
      || !Number.isSafeInteger(ref.chunk_index) || ref.chunk_index < 0
      || !Number.isSafeInteger(ref.chunk_id) || ref.chunk_id < 0
      || !Number.isSafeInteger(ref.chunk_file_offset) || ref.chunk_file_offset < 0
      || !Number.isSafeInteger(ref.decompressed_block_offset)
      || ref.decompressed_block_offset < 0
      || !Number.isSafeInteger(ref.decompressed_payload_offset)
      || ref.decompressed_payload_offset <= ref.decompressed_block_offset
      || ref.packet_id !== profile.replay_block_packet_id
      || ref.replay_time_ms !== row.replay_time_ms
      || ref.payload_length !== row.raw_payload_hex.length / 2
      || ref.raw_param !== row.raw_param
      || !REPLAY_SHA.test(ref.raw_payload_sha256 ?? '')) {
    invalid('profile, source packet reference, or raw payload differs');
  }
  const position = `${ref.chunk_index}/${ref.decompressed_block_offset}`;
  if (packetPositions.has(position)) invalid('duplicate raw packet position');
  packetPositions.add(position);
  const payload = Buffer.from(row.raw_payload_hex, 'hex');
  const payloadHash = crypto.createHash('sha256').update(payload).digest('hex');
  if (ref.raw_payload_sha256 !== payloadHash) invalid('raw packet payload hash differs');
  const inspected = decodeCircularMovementRestrictionPayload821(row.raw_payload_hex);
  if (!inspected
      || row.raw_selector_byte !== payload[0]
      || row.packet_shape_candidate !== inspected.packet_shape_candidate
      || row.packet_record_count_candidate !== inspected.packet_record_count_candidate
      || row.raw_protected_scalar_bytes_hex
        !== inspected.raw_protected_scalar_bytes_hex
      || row.raw_protected_vector_bytes_hex
        !== inspected.raw_protected_vector_bytes_hex
      || row.callback_scalar_bytes_hex !== inspected.callback_scalar_bytes_hex
      || row.callback_vector_bytes_hex !== inspected.callback_vector_bytes_hex
      || row.anonymous_scalar_f32_candidate
        !== inspected.anonymous_scalar_f32_candidate
      || !isDeepStrictEqual(row.anonymous_vector_xyz_f32_candidate,
        inspected.anonymous_vector_xyz_f32_candidate)) {
    invalid('native-observed shape, record count, or exact callback byte transform differs');
  }
  return inspected.packet_record_count_candidate;
}

function prepareShowHealthBarZeroFlag(prepared) {
  const profile = SHOW_HEALTH_BAR_PACKET_CANDIDATE_PROFILE_821;
  if (prepared.eventKey !== 'show_health_bar_packet_candidates'
      || prepared.replayVersion !== profile.replay_version) {
    throw new EventQueryError('UNSUPPORTED_FILTER',
      '--show-health-zero-flag requires an exact 16.19.821.7343 ShowHealthBar packet candidate event.');
  }
  const result = prepared.capabilityResult;
  const fields = Object.keys(result ?? {});
  const counts = result?.observed_payload_counts;
  const fieldConfidence = {
    replay_time_ms: 'VERIFIED_DIRECT', raw_param: 'VERIFIED_DIRECT',
    callback_byte_candidate: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_TRANSFORM',
    callback_zero_flag_candidate: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_TRANSFORM',
  };
  const analysisResult = prepared[PREPARED_REPLAY_METADATA]?.analysis?.semantic
    ?.capability_results?.[profile.capability];
  if (prepared.capabilityStatus !== 'CANDIDATE'
      || fields.length !== SHOW_HEALTH_BAR_RESULT_FIELDS_821.size
      || fields.some((field) => !SHOW_HEALTH_BAR_RESULT_FIELDS_821.has(field))
      || result.profile_id !== profile.id
      || result.input_packet_id !== profile.replay_block_packet_id
      || result.evidence_status !== profile.evidence_status
      || result.evidence_runtime_image_sha256
        !== profile.evidence_runtime_image_sha256
      || result.evidence_callback_table_sha256
        !== profile.evidence_callback_table_sha256
      || result.status !== 'CANDIDATE'
      || result.runtime_image_sha256 !== profile.evidence_runtime_image_sha256
      || result.runtime_image_status !== 'MATCHED_USED'
      || result.runtime_image_used !== true
      || result.native_witness_status !== 'FULLY_CONSUMED_ALL'
      || !REPLAY_SHA.test(result.native_input_sha256 ?? '')
      || !isCount(result.input_count) || result.input_count === 0
      || result.input_count > 100_000
      || result.event_count !== result.input_count
      || result.event_count !== prepared.declaredCount
      || result.native_full_success_count !== result.event_count
      || !isCount(result.scanned_block_count)
      || result.scanned_block_count < result.input_count
      || !isDeepStrictEqual(result.known_limits, [...profile.known_limits])
      || !isDeepStrictEqual(result.event_field_confidence, fieldConfidence)
      || !counts || Object.keys(counts).length !== 2
      || !isCount(counts['4a']) || !isCount(counts['4b'])
      || counts['4a'] + counts['4b'] !== result.event_count
      || !isDeepStrictEqual(analysisResult, result)) {
    throw new EventQueryError('CAPABILITY_METADATA_MISMATCH',
      'ShowHealthBar packet metadata differs from its exact-build native-witness profile.');
  }
}

function showHealthBarZeroFlag(row, prepared, lineNumber, state) {
  const invalid = (reason) => {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid ShowHealthBar packet at JSONL line ${lineNumber}: ${reason}.`,
      { line_number: lineNumber });
  };
  const profile = SHOW_HEALTH_BAR_PACKET_CANDIDATE_PROFILE_821;
  const fields = Object.keys(row);
  const ref = row.raw_packet_ref;
  const refFields = ref && typeof ref === 'object' && !Array.isArray(ref)
    ? Object.keys(ref) : [];
  if (fields.length !== SHOW_HEALTH_BAR_ROW_FIELDS_821.size
      || fields.some((field) => !SHOW_HEALTH_BAR_ROW_FIELDS_821.has(field))
      || refFields.length !== SHOW_HEALTH_BAR_REF_FIELDS_821.size
      || refFields.some((field) => !SHOW_HEALTH_BAR_REF_FIELDS_821.has(field))
      || row.event_type !== 'SHOW_HEALTH_BAR_PACKET_CANDIDATE'
      || row.game_version !== profile.replay_version || row.patch !== '16.19'
      || row.build_profile !== profile.id
      || row.replay_sha256 !== prepared.replaySha
      || row.packet_name_candidate !== profile.packet_name
      || row.semantic_effect_status !== 'UNKNOWN'
      || row.confidence !== 'CANDIDATE'
      || row.semantic_status !== profile.evidence_status
      || !Number.isSafeInteger(row.replay_time_ms) || row.replay_time_ms < 0
      || !Number.isSafeInteger(row.raw_param) || row.raw_param <= 0
      || row.raw_param > 0xffffffff
      || ref.source_path !== (prepared.sourcePath ?? null)
      || ref.replay_sha256 !== prepared.replaySha
      || !['game_chunk', 'keyframe'].includes(ref.chunk_stream)
      || !Number.isSafeInteger(ref.chunk_index) || ref.chunk_index < 0
      || !Number.isSafeInteger(ref.chunk_id) || ref.chunk_id < 0
      || !Number.isSafeInteger(ref.chunk_file_offset) || ref.chunk_file_offset < 0
      || !Number.isSafeInteger(ref.decompressed_block_offset)
      || ref.decompressed_block_offset < 0
      || !Number.isSafeInteger(ref.decompressed_payload_offset)
      || ref.decompressed_payload_offset <= ref.decompressed_block_offset
      || ref.packet_id !== profile.replay_block_packet_id
      || ref.replay_time_ms !== row.replay_time_ms
      || ref.payload_length !== 1 || ref.raw_param !== row.raw_param
      || typeof ref.raw_payload_hex !== 'string'
      || ref.raw_payload_hex !== row.raw_payload_byte_hex
      || !REPLAY_SHA.test(ref.raw_payload_sha256 ?? '')) {
    invalid('profile, raw packet reference, or candidate provenance differs');
  }
  const position = `${ref.chunk_index}/${ref.decompressed_block_offset}`;
  if (state.positions.has(position)) invalid('duplicate raw packet position');
  if (ref.chunk_index < state.previousChunkIndex
      || (ref.chunk_index === state.previousChunkIndex
        && ref.decompressed_block_offset <= state.previousBlockOffset)) {
    invalid('raw packet order differs from Replay walk order');
  }
  state.positions.add(position);
  state.previousChunkIndex = ref.chunk_index;
  state.previousBlockOffset = ref.decompressed_block_offset;
  const inspected = decodeShowHealthBarPayload821(ref.raw_payload_hex);
  if (!inspected
      || row.raw_payload_byte_hex !== inspected.raw_payload_byte_hex
      || row.native_object_byte_0x10_hex !== inspected.native_object_byte_0x10_hex
      || row.callback_byte_candidate !== inspected.callback_byte_candidate
      || row.callback_zero_flag_candidate !== inspected.callback_zero_flag_candidate
      || ref.raw_payload_sha256 !== crypto.createHash('sha256')
        .update(Buffer.from(ref.raw_payload_hex, 'hex')).digest('hex')) {
    invalid('raw payload, pinned callback transform, or payload hash differs');
  }
  const nativeInputHeader = Buffer.allocUnsafe(8);
  nativeInputHeader.writeUInt32LE(row.raw_param, 0);
  nativeInputHeader.writeUInt32LE(1, 4);
  state.nativeInputHash.update(nativeInputHeader)
    .update(Buffer.from(ref.raw_payload_hex, 'hex'));
  state.observedPayloadCounts[ref.raw_payload_hex] += 1;
  return inspected.callback_zero_flag_candidate;
}

function prepareUnitApplyDamageCallbackF32(prepared) {
  const profile = UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821;
  if (prepared.eventKey !== 'unit_apply_damage_packet_candidates'
      || prepared.replayVersion !== profile.replay_version) {
    throw new EventQueryError('UNSUPPORTED_FILTER',
      '--damage-callback-f32-available requires an exact 16.19.821.7343 UnitApplyDamage packet candidate event.');
  }
  const result = prepared.capabilityResult;
  const isV5 = result?.profile_id === profile.id;
  const isV4 = result?.profile_id
    === UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V4_ID_821;
  const isV3 = result?.profile_id
    === UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V3_ID_821;
  if (prepared.capabilityStatus !== 'CANDIDATE'
      || (!isV5 && !isV4 && !isV3
        && result?.profile_id !== UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V1_ID_821
        && result?.profile_id !== UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V2_ID_821)
      || result.input_packet_id !== profile.replay_block_packet_id
      || result.evidence_status !== profile.evidence_status
      || result.evidence_runtime_image_sha256
        !== profile.evidence_runtime_image_sha256
      || result.runtime_image_sha256 !== profile.evidence_runtime_image_sha256
      || result.evidence_scalar_table_sha256
        !== profile.evidence_scalar_table_sha256
      || result.evidence_shape_catalog_sha256
        !== profile.evidence_shape_catalog_sha256
      || result.runtime_image_status !== 'MATCHED_USED'
      || result.runtime_image_used !== true
      || result.native_witness_status !== 'FULLY_CONSUMED_ALL'
      || !REPLAY_SHA.test(result.native_input_sha256 ?? '')
      || !isCount(result.native_full_success_count)
      || !isCount(result.input_count) || result.input_count === 0
      || result.event_count !== result.input_count
      || result.event_count !== prepared.declaredCount
      || result.native_full_success_count !== result.event_count
      || !isCount(result.callback_f32_available_count)
      || !isCount(result.callback_f32_unavailable_count)
      || result.callback_f32_available_count + result.callback_f32_unavailable_count
        !== result.event_count
      || !isCount(result.observed_shape_family_count)
      || result.observed_shape_family_count < 1
      || result.observed_shape_family_count > result.event_count
      || (result.profile_id !== UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V1_ID_821
        && (result.native_callback_f32_available_count !== result.event_count
          || !result.native_callback_f32_source_counts
          || typeof result.native_callback_f32_source_counts !== 'object'
          || Array.isArray(result.native_callback_f32_source_counts)
          || !isDeepStrictEqual(
            Object.keys(result.native_callback_f32_source_counts).sort(),
            [...UNIT_APPLY_DAMAGE_NATIVE_FLOAT_SOURCES_821].sort())
          || UNIT_APPLY_DAMAGE_NATIVE_FLOAT_SOURCES_821.some((source) =>
            !isCount(result.native_callback_f32_source_counts[source]))
          || UNIT_APPLY_DAMAGE_NATIVE_FLOAT_SOURCES_821.reduce((sum, source) =>
            sum + result.native_callback_f32_source_counts[source], 0)
            !== result.event_count))
      || ((isV3 || isV4 || isV5)
        && (result.native_callback_lookup_full_write_count !== result.event_count
          || result.evidence_lookup_key_0x24_table_sha256
            !== profile.evidence_lookup_key_0x24_table_sha256
          || result.evidence_lookup_key_0x2c_table_sha256
            !== profile.evidence_lookup_key_0x2c_table_sha256
          || !result.native_callback_lookup_key_0x24_raw_param_relation_counts
          || typeof result.native_callback_lookup_key_0x24_raw_param_relation_counts
            !== 'object'
          || Array.isArray(result.native_callback_lookup_key_0x24_raw_param_relation_counts)
          || !isDeepStrictEqual(Object.keys(
            result.native_callback_lookup_key_0x24_raw_param_relation_counts).sort(),
          [...UNIT_APPLY_DAMAGE_LOOKUP_RELATIONS_821].sort())
          || UNIT_APPLY_DAMAGE_LOOKUP_RELATIONS_821.some((relation) =>
            !isCount(result.native_callback_lookup_key_0x24_raw_param_relation_counts[relation]))
          || UNIT_APPLY_DAMAGE_LOOKUP_RELATIONS_821.reduce((sum, relation) =>
            sum + result.native_callback_lookup_key_0x24_raw_param_relation_counts[relation], 0)
            !== result.event_count))
      || (!(isV4 || isV5) && ['evidence_callback_u32_0x10_table_sha256',
        'native_callback_u32_0x10_full_write_count',
        'native_callback_u32_0x10_source_counts'].some((field) => field in result))
      || ((isV4 || isV5) && (result.evidence_callback_u32_0x10_table_sha256
          !== profile.evidence_callback_u32_0x10_table_sha256
        || result.native_callback_u32_0x10_full_write_count
          !== result.event_count
        || !result.native_callback_u32_0x10_source_counts
        || typeof result.native_callback_u32_0x10_source_counts !== 'object'
        || Array.isArray(result.native_callback_u32_0x10_source_counts)
        || !isDeepStrictEqual(Object.keys(
          result.native_callback_u32_0x10_source_counts).sort(),
        [...UNIT_APPLY_DAMAGE_NATIVE_U32_SOURCES_821].sort())
        || UNIT_APPLY_DAMAGE_NATIVE_U32_SOURCES_821.some((source) =>
          !isCount(result.native_callback_u32_0x10_source_counts[source]))
        || UNIT_APPLY_DAMAGE_NATIVE_U32_SOURCES_821.reduce((sum, source) =>
          sum + result.native_callback_u32_0x10_source_counts[source], 0)
          !== result.event_count))
      || (!isV5 && ['evidence_callback_f32_0x18_table_sha256',
        'native_callback_f32_0x18_full_write_count',
        'native_callback_f32_0x18_source_counts'].some((field) => field in result))
      || (isV5 && (result.evidence_callback_f32_0x18_table_sha256
          !== profile.evidence_callback_f32_0x18_table_sha256
        || result.native_callback_f32_0x18_full_write_count !== result.event_count
        || !result.native_callback_f32_0x18_source_counts
        || typeof result.native_callback_f32_0x18_source_counts !== 'object'
        || Array.isArray(result.native_callback_f32_0x18_source_counts)
        || !isDeepStrictEqual(Object.keys(
          result.native_callback_f32_0x18_source_counts).sort(),
        [...UNIT_APPLY_DAMAGE_NATIVE_F32_0X18_SOURCES_821].sort())
        || UNIT_APPLY_DAMAGE_NATIVE_F32_0X18_SOURCES_821.some((source) =>
          !isCount(result.native_callback_f32_0x18_source_counts[source]))
        || UNIT_APPLY_DAMAGE_NATIVE_F32_0X18_SOURCES_821.reduce((sum, source) =>
          sum + result.native_callback_f32_0x18_source_counts[source], 0)
          !== result.event_count))) {
    throw new EventQueryError('CAPABILITY_METADATA_MISMATCH',
      'UnitApplyDamage packet metadata differs from its exact-build profile.');
  }
}

function prepareUnitApplyDamageLookupKeys(prepared) {
  const profile = UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821;
  if (prepared.eventKey !== 'unit_apply_damage_packet_candidates'
      || prepared.replayVersion !== profile.replay_version) {
    throw new EventQueryError('UNSUPPORTED_FILTER',
      '--damage-lookup-key24 and --damage-lookup-key2c require an exact 16.19.821.7343 UnitApplyDamage packet candidate event.');
  }
  prepareUnitApplyDamageCallbackF32(prepared);
  if (![UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V3_ID_821,
    UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V4_ID_821, profile.id]
    .includes(prepared.capabilityResult.profile_id)) {
    throw new EventQueryError('UNSUPPORTED_FILTER',
      '--damage-lookup-key24 and --damage-lookup-key2c require an exact 16.19.821.7343 UnitApplyDamage packet v3-v5 profile.');
  }
}

function prepareUnitApplyDamageCallbackU32At10(prepared) {
  const profile = UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821;
  if (prepared.eventKey !== 'unit_apply_damage_packet_candidates'
      || prepared.replayVersion !== profile.replay_version) {
    throw new EventQueryError('UNSUPPORTED_FILTER',
      '--damage-callback-u32-0x10 requires an exact 16.19.821.7343 UnitApplyDamage packet v4 event.');
  }
  prepareUnitApplyDamageCallbackF32(prepared);
  if (![UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V4_ID_821, profile.id]
    .includes(prepared.capabilityResult.profile_id)) {
    throw new EventQueryError('UNSUPPORTED_FILTER',
      '--damage-callback-u32-0x10 requires the exact 16.19.821.7343 UnitApplyDamage packet v4 or v5 profile.');
  }
}

function prepareUnitApplyDamageF32At18Raw(prepared) {
  prepareUnitApplyDamageCallbackF32(prepared);
  if (prepared.capabilityResult.profile_id
      !== UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821.id) {
    throw new EventQueryError('UNSUPPORTED_FILTER',
      '--damage-callback-f32-0x18-raw requires the exact 16.19.821.7343 UnitApplyDamage packet v5 profile.');
  }
}

function unitApplyDamageCallbackF32(row, prepared, lineNumber,
  packetPositions, shapeFamilies, nativeInputHash, nativeFloatSourceCounts,
  nativeLookupRelationCounts, nativeU32SourceCounts,
  nativeF32At18SourceCounts) {
  const invalid = (reason) => {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid UnitApplyDamage packet at JSONL line ${lineNumber}: ${reason}.`,
      { line_number: lineNumber });
  };
  const profile = UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821;
  const profileId = prepared.capabilityResult.profile_id;
  const isV5 = profileId === profile.id;
  const isV4 = profileId === UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V4_ID_821;
  const hasU32At10 = isV4 || isV5;
  const hasLookupKeys = hasU32At10
    || profileId === UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V3_ID_821;
  const hasNativeFloat = hasLookupKeys
    || profileId === UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V2_ID_821;
  const allowedFields = isV5 ? UNIT_APPLY_DAMAGE_V5_ROW_FIELDS_821
    : isV4 ? UNIT_APPLY_DAMAGE_V4_ROW_FIELDS_821
    : hasLookupKeys ? UNIT_APPLY_DAMAGE_V3_ROW_FIELDS_821
    : hasNativeFloat ? UNIT_APPLY_DAMAGE_V2_ROW_FIELDS_821
      : UNIT_APPLY_DAMAGE_ROW_FIELDS_821;
  const fields = Object.keys(row);
  const ref = row.raw_packet_ref;
  if (fields.length !== allowedFields.size
      || fields.some((field) => !allowedFields.has(field))
      || row.event_type !== 'UNIT_APPLY_DAMAGE_PACKET_CANDIDATE'
      || row.game_version !== profile.replay_version || row.patch !== '16.19'
      || row.build_profile !== profileId
      || row.replay_sha256 !== prepared.replaySha
      || row.packet_name_candidate !== profile.packet_name
      || row.confidence !== 'CANDIDATE'
      || row.semantic_status !== profile.evidence_status
      || row.semantic_effect_status !== 'UNKNOWN'
      || !Number.isSafeInteger(row.raw_param) || row.raw_param <= 0
      || row.raw_param > 0xffffffff
      || !ref || typeof ref !== 'object' || Array.isArray(ref)
      || ref.source_path !== (prepared.sourcePath ?? null)
      || ref.replay_sha256 !== prepared.replaySha
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
      || !Number.isSafeInteger(ref.payload_length)
      || ref.payload_length < 8 || ref.payload_length > 25
      || ref.raw_param !== row.raw_param
      || typeof ref.raw_payload_hex !== 'string'
      || !/^(?:[0-9a-f]{2})+$/.test(ref.raw_payload_hex)
      || ref.raw_payload_hex.length / 2 !== ref.payload_length
      || !REPLAY_SHA.test(ref.raw_payload_sha256 ?? '')) {
    invalid('profile, source packet reference, or raw payload differs');
  }
  const position = `${ref.chunk_index}/${ref.decompressed_block_offset}`;
  if (packetPositions.has(position)) invalid('duplicate raw packet position');
  packetPositions.add(position);
  const payload = Buffer.from(ref.raw_payload_hex, 'hex');
  const payloadHash = crypto.createHash('sha256').update(payload).digest('hex');
  if (ref.raw_payload_sha256 !== payloadHash) invalid('raw packet payload hash differs');
  const nativeInputHeader = Buffer.allocUnsafe(8);
  nativeInputHeader.writeUInt32LE(row.raw_param, 0);
  nativeInputHeader.writeUInt32LE(payload.length, 4);
  nativeInputHash.update(nativeInputHeader).update(payload);
  const selector24 = payload[3] & 7;
  const selector0 = payload[0] & 7;
  const selector3 = (payload[0] >>> 3) & 7;
  const selector6 = ((payload[0] >>> 6) | (payload[1] << 2)) & 7;
  if (row.header_selector_bits_24_26 !== selector24
      || row.header_selector_bits_0_2 !== selector0
      || row.header_selector_bits_3_5 !== selector3
      || !isObservedUnitApplyDamageShape821(payload.length,
        selector24, selector0, selector3)) {
    invalid('selectors or native-observed packet shape differ');
  }
  if (isV5 && row.header_selector_bits_6_8 !== selector6) {
    invalid('native +0x18 selector differs from raw payload');
  }
  shapeFamilies.add(`${payload.length}:${selector24}:${selector0}:${selector3}`);
  const hasFloat = payload.length === 15 && selector24 === 6
    && selector0 === 1 && selector3 === 6;
  if (hasFloat) {
    const rawBytes = payload.subarray(5, 9).toString('hex');
    const decoded = decodeUnitApplyDamageCallbackF32FromRaw821(rawBytes);
    if (row.callback_f32_0x20_status !== 'NATIVE_MATCHED_SHAPE'
        || row.callback_f32_0x20_raw_bytes_hex !== rawBytes
        || decoded === null
        || row.callback_f32_0x20_candidate !== decoded) {
      invalid('anonymous callback float differs from the exact 821 byte transform');
    }
  } else if (row.callback_f32_0x20_status !== 'UNAVAILABLE_SHAPE'
      || row.callback_f32_0x20_raw_bytes_hex !== null
      || row.callback_f32_0x20_candidate !== null) {
    invalid('unavailable callback float shape is not explicitly null');
  }
  if (hasNativeFloat) {
    const constants = {
      3: ['CONSTANT_0', 0],
      5: ['CONSTANT_1', 1],
      7: ['CONSTANT_2', 2],
    };
    const constant = constants[selector3] ?? null;
    const source = row.native_callback_f32_0x20_source;
    const value = row.native_callback_f32_0x20_candidate;
    const offset = row.native_callback_f32_0x20_raw_offset;
    const rawBytes = row.native_callback_f32_0x20_raw_bytes_hex;
    if (!Number.isFinite(value)
        || !UNIT_APPLY_DAMAGE_NATIVE_FLOAT_SOURCES_821.includes(source)) {
      invalid('native callback float or source is invalid');
    }
    if (constant) {
      if (source !== constant[0] || !Object.is(value, constant[1])
          || offset !== null || rawBytes !== null) {
        invalid('native callback float constant differs');
      }
    } else if (source !== 'RAW_READER'
        || !Number.isSafeInteger(offset) || offset < 0
        || offset + 4 > payload.length
        || rawBytes !== payload.subarray(offset, offset + 4).toString('hex')
        || !Object.is(value, decodeUnitApplyDamageCallbackF32FromRaw821(rawBytes))) {
      invalid('native callback float raw reader differs');
    }
    if (hasFloat && (source !== 'RAW_READER' || offset !== 5
        || !Object.is(value, row.callback_f32_0x20_candidate))) {
      invalid('legacy and native callback floats disagree');
    }
    nativeFloatSourceCounts[source] += 1;
  }
  if (hasLookupKeys) {
    const encoded24 = row.native_callback_lookup_key_0x24_encoded_bytes_hex;
    const encoded2c = row.native_callback_lookup_key_0x2c_encoded_bytes_hex;
    const key24 = decodeUnitApplyDamageLookupKeyFromRaw821(encoded24, 0x24);
    const key2c = decodeUnitApplyDamageLookupKeyFromRaw821(encoded2c, 0x2c);
    const relation = row.raw_param === key24 ? 'EQUAL'
      : row.raw_param - key24 === 0x100
        ? 'RAW_PARAM_IS_LOOKUP_PLUS_0X100' : 'OTHER';
    if (key24 === null || key2c === null
        || row.native_callback_lookup_key_u32_0x24_candidate !== key24
        || row.native_callback_lookup_key_u32_0x2c_candidate !== key2c
        || row.native_callback_lookup_key_0x24_raw_param_relation !== relation) {
      invalid('native lookup keys or full raw-parameter relation differ');
    }
    nativeLookupRelationCounts[relation] += 1;
  }
  if (hasU32At10) {
    const expectedSource = selector24 === 6 ? 'CONSTANT_0' : 'RAW_READER';
    const value = row.native_callback_u32_0x10_candidate;
    const encoded = row.native_callback_u32_0x10_encoded_bytes_hex;
    const decoded = decodeUnitApplyDamageCallbackU32FromRaw821(encoded);
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff
        || typeof encoded !== 'string' || !/^[0-9a-f]{8}$/.test(encoded)
        || decoded === null || decoded !== value
        || row.native_callback_u32_0x10_source !== expectedSource
        || (expectedSource === 'CONSTANT_0'
          && (value !== 0 || encoded !== '85858585'))) {
      invalid('anonymous native callback u32 or source differs');
    }
    nativeU32SourceCounts[expectedSource] += 1;
  }
  if (isV5) {
    const source = selector6 === 5 ? 'CONSTANT_0'
      : [0, 2, 3, 6].includes(selector6) ? 'RAW_READER' : null;
    const encoded = row.native_callback_f32_0x18_encoded_bytes_hex;
    const value = row.native_callback_f32_0x18_candidate;
    const offset = row.native_callback_f32_0x18_raw_offset;
    const rawBytes = row.native_callback_f32_0x18_raw_bytes_hex;
    if (source === null || row.native_callback_f32_0x18_source !== source
        || typeof encoded !== 'string' || !/^[0-9a-f]{8}$/.test(encoded)
        || !Number.isFinite(value)
        || !Object.is(value,
          decodeUnitApplyDamageCallbackF32At18FromEncoded821(encoded))) {
      invalid('anonymous native +0x18 f32 or transform differs');
    }
    if (source === 'CONSTANT_0') {
      if (encoded !== '3e3e3e3e' || !Object.is(value, 0)
          || offset !== null || rawBytes !== null) {
        invalid('anonymous native +0x18 constant-zero branch differs');
      }
    } else if (!Number.isSafeInteger(offset) || offset < 0
        || offset + 4 > payload.length
        || rawBytes !== payload.subarray(offset, offset + 4).toString('hex')
        || encoded !== Buffer.from(payload.subarray(offset, offset + 4))
          .reverse().toString('hex')) {
      invalid('anonymous native +0x18 raw-reader bytes differ');
    }
    nativeF32At18SourceCounts[source] += 1;
  }
  return hasFloat;
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

function objectiveBountyTurretPairRow(row, prepared, lineNumber,
  seenPacketPositions) {
  const { associationConfig, capabilityResult, replaySha, replayVersion } = prepared;
  const invalid = (reason) => {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid objective_bounty_turret_pair row at JSONL line ${lineNumber}: ${reason}.`,
      { line_number: lineNumber });
  };
  const plate = row.plate_raw_packet_ref;
  const die = row.turret_die_raw_packet_ref;
  const claim = row.claim_raw_packet_ref;
  if (row.event_type !== associationConfig.eventType
      || row.game_version !== replayVersion || row.patch !== '16.19'
      || row.build_profile !== associationConfig.profile.id
      || row.confidence !== 'CANDIDATE'
      || row.semantic_status !== capabilityResult.evidence_status
      || row.plate_child_event_id !== 0x0107
      || row.turret_die_child_event_id !== 0x003b
      || row.claim_child_event_id !== 0x0113
      || !plate || !die || !claim
      || !isDeepStrictEqual(row.raw_packet_ref, claim)
      || !isDeepStrictEqual(row.raw_packet_refs, [plate, die, claim])
      || !Number.isSafeInteger(row.claim_blob_u32_0x04)
      || row.claim_blob_u32_0x04 < 0
      || row.claim_blob_u32_0x04 > 0xffffffff
      || row.plate_event_u32_0x04 !== row.claim_blob_u32_0x04
      || row.turret_die_blob_u32_0x0c !== row.claim_blob_u32_0x04
      || row.raw_param !== row.claim_raw_param) {
    invalid('candidate profile, source references or anonymous native words differ');
  }
  const refs = [[plate, 17, row.plate_raw_param],
    [die, 116, row.turret_die_raw_param],
    [claim, 17, row.claim_raw_param]];
  for (const [ref, length, param] of refs) {
    if (ref.replay_sha256 !== replaySha
        || (prepared.sourcePath !== undefined
          && ref.source_path !== prepared.sourcePath)
        || (ref.source_path !== null
          && (typeof ref.source_path !== 'string' || ref.source_path.length === 0))
        || ref.replay_time_ms !== row.replay_time_ms
        || ref.chunk_stream !== 'game_chunk'
        || !Number.isSafeInteger(ref.chunk_index) || ref.chunk_index < 0
        || !Number.isSafeInteger(ref.chunk_id) || ref.chunk_id < 0
        || !Number.isSafeInteger(ref.chunk_file_offset) || ref.chunk_file_offset < 0
        || !Number.isSafeInteger(ref.decompressed_block_offset)
        || ref.decompressed_block_offset < 0
        || !Number.isSafeInteger(ref.decompressed_payload_offset)
        || ref.decompressed_payload_offset <= ref.decompressed_block_offset
        || ref.packet_id !== 0x040a || ref.payload_length !== length
        || !Number.isSafeInteger(ref.raw_param) || ref.raw_param <= 0
        || ref.raw_param > 0xffffffff || ref.raw_param !== param
        || !REPLAY_SHA.test(ref.raw_payload_sha256 ?? '')) {
      invalid('same-Replay packet reference or raw parameter differs');
    }
    const position = `${ref.chunk_index}/${ref.decompressed_block_offset}`;
    if (seenPacketPositions.has(position)) invalid('source packet is reused');
    seenPacketPositions.add(position);
  }
  if (plate.source_path !== die.source_path || die.source_path !== claim.source_path
      || plate.chunk_index !== die.chunk_index || die.chunk_index !== claim.chunk_index
      || plate.chunk_id !== die.chunk_id || die.chunk_id !== claim.chunk_id
      || plate.chunk_file_offset !== die.chunk_file_offset
      || die.chunk_file_offset !== claim.chunk_file_offset
      || !(plate.decompressed_block_offset < die.decompressed_block_offset
        && die.decompressed_block_offset < claim.decompressed_block_offset)) {
    invalid('same-chunk, same-millisecond plate < die < claim order differs');
  }
}

function objectiveBountyTurretPairSourceRow(row, prepared, spec, lineNumber,
  seenPacketPositions) {
  const invalid = (reason) => {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid ${spec.eventKey} source row at JSONL line ${lineNumber}: ${reason}.`,
      { event_key: spec.eventKey, line_number: lineNumber });
  };
  const ref = row.raw_packet_ref;
  if (row.event_type !== spec.eventType
      || row.game_version !== prepared.replayVersion || row.patch !== '16.19'
      || row.build_profile !== spec.profile.id
      || row.replay_sha256 !== prepared.replaySha
      || row.confidence !== 'CANDIDATE'
      || row.semantic_status !== spec.evidenceStatus
      || row.event_id !== spec.profile.child_event_id
      || row.event_name !== spec.profile.child_event_name
      || row.raw_event_id_hex !== spec.rawEventIdHex
      || !ref || typeof ref !== 'object' || Array.isArray(ref)
      || ref.replay_sha256 !== prepared.replaySha
      || (prepared.sourcePath !== undefined
        && ref.source_path !== prepared.sourcePath)
      || (ref.source_path !== null
        && (typeof ref.source_path !== 'string' || ref.source_path.length === 0))
      || ref.replay_time_ms !== row.replay_time_ms
      || ref.chunk_stream !== 'game_chunk'
      || !Number.isSafeInteger(ref.chunk_index) || ref.chunk_index < 0
      || !Number.isSafeInteger(ref.chunk_id) || ref.chunk_id < 0
      || !Number.isSafeInteger(ref.chunk_file_offset) || ref.chunk_file_offset < 0
      || !Number.isSafeInteger(ref.decompressed_block_offset)
      || ref.decompressed_block_offset < 0
      || !Number.isSafeInteger(ref.decompressed_payload_offset)
      || ref.decompressed_payload_offset <= ref.decompressed_block_offset
      || ref.packet_id !== 0x040a || ref.payload_length !== spec.payloadLength
      || !Number.isSafeInteger(ref.raw_param) || ref.raw_param <= 0
      || ref.raw_param > 0xffffffff || row.raw_param !== ref.raw_param
      || !REPLAY_SHA.test(ref.raw_payload_sha256 ?? '')
      || !REPLAY_SHA.test(row.event_blob_sha256 ?? '')) {
    invalid('exact-build child, Replay identity or raw packet reference differs');
  }
  let blob;
  let word;
  if (spec.eventKey === 'turret_plate_event_packet_candidates') {
    if (row.event_schema_u32_0x00 !== 469
        || !Number.isSafeInteger(row.event_u32_0x04)
        || row.event_u32_0x04 < 0 || row.event_u32_0x04 > 0xffffffff) {
      invalid('anonymous native child words differ');
    }
    blob = Buffer.alloc(8);
    blob.writeUInt32LE(row.event_schema_u32_0x00, 0);
    blob.writeUInt32LE(row.event_u32_0x04, 4);
    word = row.event_u32_0x04;
  } else {
    const hexLength = spec.eventKey === 'turret_die_event_packet_candidates'
      ? 216 : 16;
    if (typeof row.event_blob_hex !== 'string'
        || !new RegExp(`^[0-9a-f]{${hexLength}}$`).test(row.event_blob_hex)) {
      invalid('native child blob is missing or malformed');
    }
    blob = Buffer.from(row.event_blob_hex, 'hex');
    if (spec.eventKey === 'objective_bounty_claimed_packet_candidates') {
      if (row.event_schema_u32_0x00 !== 469
          || blob.readUInt32LE(0) !== 469
          || !Number.isSafeInteger(row.blob_u32_0x04)
          || row.blob_u32_0x04 < 0 || row.blob_u32_0x04 > 0xffffffff
          || blob.readUInt32LE(4) !== row.blob_u32_0x04) {
        invalid('anonymous native child words differ');
      }
      word = row.blob_u32_0x04;
    } else {
      word = blob.readUInt32LE(0x0c);
    }
  }
  if (crypto.createHash('sha256').update(blob).digest('hex')
      !== row.event_blob_sha256) {
    invalid('native child blob SHA-256 differs');
  }
  const position = `${ref.chunk_index}/${ref.decompressed_block_offset}`;
  if (seenPacketPositions.has(position)) invalid('source packet is reused');
  seenPacketPositions.add(position);
  return { position, ref, word };
}

async function loadObjectiveBountyTurretPairSourceRows(prepared) {
  const rowsByEvent = new Map();
  const seenPacketPositions = new Set();
  for (const spec of OBJECTIVE_BOUNTY_TURRET_PAIR_SOURCE_EVENTS_821) {
    const source = prepared.objectiveBountyTurretPairSources[spec.eventKey];
    const rows = new Map();
    let lineNumber = 0;
    const summary = await streamEventQuery(source, {}, async (line) => {
      const packet = objectiveBountyTurretPairSourceRow(JSON.parse(line), source,
        spec, ++lineNumber, seenPacketPositions);
      rows.set(packet.position, packet);
    });
    if (summary.scanned_count !== source.declaredCount
        || rows.size !== source.declaredCount) {
      throw new EventQueryError('EVENT_COUNT_MISMATCH',
        `${spec.eventKey} source rows disagree with declared packet count.`,
        { event_key: spec.eventKey, declared_event_count: source.declaredCount,
          source_row_count: rows.size });
    }
    rowsByEvent.set(spec.eventKey, rows);
  }
  return rowsByEvent;
}

function objectiveBountyTurretPairSourceRefs(row, sourceRows, lineNumber) {
  const links = [
    ['turret_plate_event_packet_candidates', row.plate_raw_packet_ref,
      row.plate_event_u32_0x04],
    ['turret_die_event_packet_candidates', row.turret_die_raw_packet_ref,
      row.turret_die_blob_u32_0x0c],
    ['objective_bounty_claimed_packet_candidates', row.claim_raw_packet_ref,
      row.claim_blob_u32_0x04],
  ];
  for (const [eventKey, ref, word] of links) {
    const position = `${ref.chunk_index}/${ref.decompressed_block_offset}`;
    const source = sourceRows.get(eventKey)?.get(position);
    if (!source || !isDeepStrictEqual(source.ref, ref) || source.word !== word) {
      throw new EventQueryError('INVALID_EVENT_ROW',
        `Objective bounty turret triple at JSONL line ${lineNumber} differs from ${eventKey} source packet.`,
        { event_key: eventKey, line_number: lineNumber });
    }
  }
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

async function loadInventoryIntervalEndpointSnapshots(prepared) {
  const source = prepareInventoryIntervalSource(prepared);
  const association = prepared.capabilityResult;
  const sourceResult = source?.capabilityResult;
  const expectedGameCount = prepared.associationConfig?.inventoryGameBracket
    ? association.game_broadcast_packet_count
    : association.excluded_game_broadcast_count;
  const invalid = (reason) => {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid inventory Broadcast endpoint source: ${reason}.`);
  };
  if (!source || source.replayVersion !== prepared.replayVersion
      || source.replaySha !== prepared.replaySha
      || source.capabilityStatus !== 'CANDIDATE'
      || sourceResult?.profile_id
        !== HERO_INVENTORY_BROADCAST_PACKET_CANDIDATE_PROFILE_821.id
      || sourceResult.runtime_image_sha256
        !== HERO_INVENTORY_BROADCAST_PACKET_CANDIDATE_PROFILE_821
          .evidence_runtime_image_sha256
      || sourceResult.event_count !== association.input_count
      || source.declaredCount !== association.input_count
      || association.input_count > 10_000) {
    throw new EventQueryError('ASSOCIATION_METADATA_MISMATCH',
      'Inventory interval Broadcast endpoint source differs from exact-build metadata.');
  }
  const snapshots = new Map();
  const frames = new Map();
  const gameRows = new Map();
  const positions = new Set();
  let keyframeCount = 0;
  let gameCount = 0;
  const summary = await streamEventQuery(source, {}, async (line) => {
    const row = JSON.parse(line);
    const ref = row.raw_packet_ref;
    const keyframe = row.packet_stream === 'keyframe';
    const recordCount = keyframe ? 10 : row.record_count;
    if (row.event_type !== 'HERO_INVENTORY_BROADCAST_PACKET_CANDIDATE'
        || row.game_version !== prepared.replayVersion || row.patch !== '16.19'
        || row.build_profile
          !== HERO_INVENTORY_BROADCAST_PACKET_CANDIDATE_PROFILE_821.id
        || row.replay_sha256 !== prepared.replaySha
        || row.confidence !== 'CANDIDATE'
        || row.semantic_status !== 'CANDIDATE_EXACT_RUNTIME_BROADCAST_PACKET_FIELDS'
        || row.snapshot_application !== 'RESET_SLOTS_0_TO_9_THEN_APPLY_RECORDS'
        || (row.packet_stream !== 'keyframe' && row.packet_stream !== 'game_chunk')
        || !ref || typeof ref !== 'object' || Array.isArray(ref)
        || ref.replay_sha256 !== prepared.replaySha
        || ref.source_path !== prepared.sourcePath
        || ref.packet_id !== 0x0357 || ref.chunk_stream !== row.packet_stream
        || !Number.isSafeInteger(ref.chunk_index) || ref.chunk_index < 0
        || !Number.isSafeInteger(ref.decompressed_block_offset)
        || ref.decompressed_block_offset < 0
        || !Number.isSafeInteger(ref.payload_length)
        || ref.payload_length < 76 || ref.payload_length > 166
        || !REPLAY_SHA.test(ref.raw_payload_sha256)
        || ref.raw_param !== row.hero_raw_param
        || ref.replay_time_ms !== row.replay_time_ms
        || !Array.isArray(row.records_candidate)
        || !Array.isArray(row.packet_slot_snapshot_candidate)
        || row.packet_slot_snapshot_candidate.length !== 10
        || row.record_count !== recordCount
        || row.records_candidate.length !== recordCount
        || (!keyframe && (recordCount < 6 || recordCount > 9))) {
      invalid('packet identity, stream, record count or Replay reference differs');
    }
    const position = `${ref.chunk_index}/${ref.decompressed_block_offset}`;
    if (positions.has(position)) invalid('duplicate Broadcast physical packet reference');
    positions.add(position);
    const values = Array(10).fill(null);
    let previousSlot = -1;
    for (const [recordIndex, record] of row.records_candidate.entries()) {
      const slot = record?.slot_candidate;
      const item = record?.item_id_candidate;
      if (record?.record_index !== recordIndex
          || !Number.isSafeInteger(slot) || slot <= previousSlot
          || slot > (keyframe ? 9 : 8)
          || (keyframe && slot !== previousSlot + 1)
          || !Number.isSafeInteger(item) || item < 0 || item > 0xffffffff) {
        invalid('record slots or item keys differ from complete packet observations');
      }
      values[slot] = item;
      previousSlot = slot;
    }
    for (let slot = 0; slot < 10; slot += 1) {
      const observed = row.packet_slot_snapshot_candidate[slot];
      if (observed?.slot_candidate !== slot
          || observed.item_id_candidate !== values[slot]
          || observed.value_basis !== (values[slot] === null
            ? 'CALLBACK_RESET_WITH_NO_PACKET_RECORD' : 'DECODED_PACKET_RECORD')) {
        invalid('slot snapshot differs from packet records');
      }
    }
    if (!keyframe) {
      gameRows.set(position, row);
      gameCount += 1;
      return;
    }
    const param = row.hero_raw_param;
    if (!Number.isSafeInteger(param) || param < 0x400000ae
        || param > 0x400000b7
        || row.participant_id_candidate !== param - 0x400000ae + 1) {
      invalid('keyframe has a noncanonical or contradictory participant key');
    }
    const frame = frames.get(ref.chunk_index)
      ?? { chunkIndex: ref.chunk_index, timeMs: row.replay_time_ms,
        participants: new Set() };
    if (frame.timeMs !== row.replay_time_ms
        || frame.participants.has(row.participant_id_candidate)) {
      invalid('keyframe time or participant roster differs');
    }
    frame.participants.add(row.participant_id_candidate);
    frames.set(ref.chunk_index, frame);
    snapshots.set(`${ref.chunk_index}/${param}`, { ref, values });
    keyframeCount += 1;
  });
  if (summary.scanned_count !== association.input_count
      || keyframeCount !== association.broadcast_keyframe_packet_count
      || gameCount !== expectedGameCount
      || frames.size !== association.keyframe_count
      || [...frames.values()].some((frame) => frame.participants.size !== 10)
      || snapshots.size !== keyframeCount) {
    throw new EventQueryError('EVENT_COUNT_MISMATCH',
      'Inventory Broadcast source lacks a complete keyframe endpoint roster.');
  }
  const orderedFrames = [...frames.values()].sort((a, b) => a.chunkIndex - b.chunkIndex);
  if (orderedFrames.some((frame, index) => index > 0
      && frame.timeMs <= orderedFrames[index - 1].timeMs)) {
    throw new EventQueryError('INVALID_EVENT_ROW',
      'Inventory Broadcast keyframe times are not strictly increasing.');
  }
  return { snapshots, gameRows, orderedFrames };
}

function endpointReversedPair(row, prepared, lineNumber, snapshots) {
  const invalid = (reason) => {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid inventory interval endpoint at JSONL line ${lineNumber}: ${reason}.`,
      { line_number: lineNumber });
  };
  const previous = snapshots.snapshots.get(
    `${row.previous_keyframe_chunk_index}/${row.hero_raw_param}`);
  const current = snapshots.snapshots.get(
    `${row.current_keyframe_chunk_index}/${row.hero_raw_param}`);
  if (!previous || !current
      || !isDeepStrictEqual(previous.ref, row.previous_raw_packet_ref)
      || !isDeepStrictEqual(current.ref, row.current_raw_packet_ref)) {
    invalid('named raw packet references differ from saved Broadcast endpoints');
  }
  const changes = [];
  for (let slot = 0; slot < 10; slot += 1) {
    const before = previous.values[slot];
    const after = current.values[slot];
    if (before !== after) changes.push({ slot_candidate: slot,
      previous_item_id_candidate: before, current_item_id_candidate: after });
  }
  if (!isDeepStrictEqual(changes, row.changed_slots_candidate)) {
    invalid('changed slots differ from complete saved Broadcast endpoints');
  }
  if (changes.length !== 2) return false;
  const [first, second] = changes;
  const firstItem = first.previous_item_id_candidate;
  const secondItem = second.previous_item_id_candidate;
  if (firstItem === 0 || secondItem === 0 || firstItem === secondItem
      || first.current_item_id_candidate !== secondItem
      || second.current_item_id_candidate !== firstItem) return false;
  return [firstItem, secondItem].every((item) =>
    previous.values.filter((value) => value === item).length === 1
    && current.values.filter((value) => value === item).length === 1);
}

function inventoryGameBroadcastBracketRow(row, prepared, lineNumber, source, state) {
  const invalid = (reason) => {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid inventory game Broadcast bracket at JSONL line ${lineNumber}: ${reason}.`,
      { line_number: lineNumber });
  };
  const fields = Object.keys(row);
  const param = row.hero_raw_param;
  const previousTime = row.previous_observation_time_ms;
  const gameTime = row.game_observation_time_ms;
  const nextTime = row.next_observation_time_ms;
  const gameRef = row.game_raw_packet_ref;
  if (fields.length !== INVENTORY_GAME_BRACKET_ROW_FIELDS_821.size
      || fields.some((field) => !INVENTORY_GAME_BRACKET_ROW_FIELDS_821.has(field))
      || row.event_type !== prepared.associationConfig.eventType
      || row.game_version !== prepared.replayVersion || row.patch !== '16.19'
      || row.build_profile !== prepared.associationConfig.profile.id
      || row.replay_sha256 !== prepared.replaySha
      || row.confidence !== 'CANDIDATE'
      || row.semantic_status !== prepared.capabilityResult.evidence_status
      || row.observation_kind
        !== 'GAME_BROADCAST_PACKET_BRACKETED_BY_ADJACENT_KEYFRAMES'
      || row.observation_scope
        !== 'EXPLICIT_GAME_PACKET_RECORDS_AND_KEYFRAME_ENDPOINTS'
      || !Number.isSafeInteger(param) || param < 0x400000ae
      || param > 0x400000b7
      || row.participant_id_candidate !== param - 0x400000ae + 1
      || !Number.isSafeInteger(previousTime) || previousTime < 0
      || !Number.isSafeInteger(gameTime) || gameTime <= previousTime
      || !Number.isSafeInteger(nextTime) || nextTime <= gameTime
      || row.replay_time_ms !== gameTime
      || row.observation_interval_ms !== nextTime - previousTime
      || !gameRef || typeof gameRef !== 'object' || Array.isArray(gameRef)
      || !isDeepStrictEqual(row.raw_packet_ref, gameRef)
      || !isDeepStrictEqual(row.raw_packet_refs,
        [row.previous_raw_packet_ref, gameRef, row.next_raw_packet_ref])
      || !isDeepStrictEqual(row.field_confidence, {
        previous_observation_time_ms: 'VERIFIED_DIRECT',
        game_observation_time_ms: 'VERIFIED_DIRECT',
        next_observation_time_ms: 'VERIFIED_DIRECT',
        participant_id_candidate: 'CANDIDATE_KR_821_RAW_PARAM_TAIL_ALIGNMENT',
        record_comparisons_candidate: 'CANDIDATE_EXACT_RUNTIME_BROADCAST_PACKET_FIELDS',
      })) invalid('exact-build identity, timing or named references differ');
  const position = `${gameRef.chunk_index}/${gameRef.decompressed_block_offset}`;
  const game = source.gameRows.get(position);
  const nextFrameIndex = source.orderedFrames.findIndex((frame) =>
    frame.chunkIndex > gameRef.chunk_index);
  if (!game || !isDeepStrictEqual(game.raw_packet_ref, gameRef)
      || game.packet_stream !== 'game_chunk'
      || game.hero_raw_param !== param || game.replay_time_ms !== gameTime
      || nextFrameIndex <= 0
      || state.seenGamePositions.has(position)) {
    invalid('game packet is absent, repeated, or outside keyframe scope');
  }
  const previousFrame = source.orderedFrames[nextFrameIndex - 1];
  const nextFrame = source.orderedFrames[nextFrameIndex];
  const previous = source.snapshots.get(`${previousFrame.chunkIndex}/${param}`);
  const next = source.snapshots.get(`${nextFrame.chunkIndex}/${param}`);
  if (!previous || !next
      || previousFrame.chunkIndex !== row.previous_keyframe_chunk_index
      || gameRef.chunk_index !== row.game_chunk_index
      || nextFrame.chunkIndex !== row.next_keyframe_chunk_index
      || previousFrame.timeMs !== previousTime || nextFrame.timeMs !== nextTime
      || !isDeepStrictEqual(previous.ref, row.previous_raw_packet_ref)
      || !isDeepStrictEqual(next.ref, row.next_raw_packet_ref)) {
    invalid('game packet does not name its adjacent complete keyframe endpoints');
  }
  const expectedRecords = game.records_candidate.map((record) => {
    const slot = record.slot_candidate;
    const before = previous.values[slot];
    const observed = record.item_id_candidate;
    const after = next.values[slot];
    const label = before === after
      ? (observed === before
        ? 'SAME_AS_BOTH_ENDPOINTS' : 'DIFFERS_FROM_EQUAL_ENDPOINTS')
      : observed === before ? 'SAME_AS_PREVIOUS_ENDPOINT'
        : observed === after ? 'SAME_AS_NEXT_ENDPOINT'
          : 'DIFFERS_FROM_BOTH_ENDPOINTS';
    return { slot_candidate: slot, previous_item_id_candidate: before,
      game_item_id_candidate: observed, next_item_id_candidate: after,
      comparison_to_endpoints: label };
  });
  const recordedSlots = new Set(expectedRecords.map((record) => record.slot_candidate));
  const missingSlots = Array.from({ length: 10 }, (_, slot) => slot)
    .filter((slot) => !recordedSlots.has(slot));
  if (row.record_count !== expectedRecords.length
      || !isDeepStrictEqual(row.record_comparisons_candidate, expectedRecords)
      || !isDeepStrictEqual(row.unrecorded_game_slots_candidate, missingSlots)) {
    invalid('explicit packet records or unavailable game slots differ');
  }
  state.seenGamePositions.add(position);
  state.distinctIntervals.add(`${previousFrame.chunkIndex}/${nextFrame.chunkIndex}/${param}`);
  for (const record of expectedRecords) {
    state.comparisonCounts[record.comparison_to_endpoints] += 1;
  }
  state.recordComparisonCount += expectedRecords.length;
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

async function readMinionBracketSource(prepared,
  maxRows = MAX_MINION_BRACKET_SOURCE_ROWS_821) {
  const rows = [];
  const input = fs.createReadStream(prepared.inputPath, { encoding: 'utf8' });
  const lines = readline.createInterface({ input, crlfDelay: Infinity });
  try {
    for await (const line of lines) {
      if (rows.length >= maxRows) {
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

async function loadExperienceIntervalExpectedRows(prepared) {
  const source = prepared.experienceIntervalSource;
  const association = prepared.capabilityResult;
  const sourceResult = source?.capabilityResult;
  const sourceProfile = FLOAT_STATS_821_PROFILES.hero_experience_snapshot;
  const invalid = (reason) => {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid experience keyframe interval source: ${reason}.`);
  };
  if (!source || source.replayVersion !== prepared.replayVersion
      || source.replaySha !== prepared.replaySha
      || source.capabilityStatus !== 'CANDIDATE'
      || sourceResult?.profile_id !== sourceProfile.id
      || source.declaredCount !== association.input_count) {
    throw new EventQueryError('ASSOCIATION_METADATA_MISMATCH',
      'Experience source artifact differs from interval association metadata.');
  }
  const frames = new Map();
  const positions = new Set();
  let scanned = 0;
  const input = fs.createReadStream(source.inputPath, { encoding: 'utf8' });
  const lines = readline.createInterface({ input, crlfDelay: Infinity });
  try {
    for await (const line of lines) {
      scanned += 1;
      if (scanned > MAX_EXPERIENCE_INTERVAL_SOURCE_ROWS_821) {
        invalid('source row count exceeds exact decoder bound');
      }
      let row;
      try {
        row = JSON.parse(line);
      } catch (error) {
        invalid(`JSONL line ${scanned} is malformed: ${error.message}`);
      }
      const ref = row?.raw_packet_ref;
      const rawParam = row?.hero_raw_param;
      const participant = rawParam - 0x400000ae + 1;
      const value = row?.experience_raw_f32_candidate;
      const rawHex = row?.raw_payload_field_bytes_hex;
      if (!row || typeof row !== 'object' || Array.isArray(row)
          || row.event_type !== 'HERO_EXPERIENCE_SNAPSHOT_CANDIDATE'
          || row.game_version !== prepared.replayVersion || row.patch !== '16.19'
          || row.build_profile !== sourceProfile.id
          || row.replay_sha256 !== prepared.replaySha
          || row.confidence !== 'CANDIDATE'
          || row.semantic_status !== sourceResult.evidence_status
          || row.observation_kind !== 'KEYFRAME_SNAPSHOT'
          || row.decreased_since_previous_snapshot !== false
          || !isDeepStrictEqual(row.known_limits, [...sourceProfile.known_limits])
          || !isDeepStrictEqual(row.field_confidence, {
            replay_time_ms: 'VERIFIED_DIRECT', hero_raw_param: 'VERIFIED_DIRECT',
            participant_id_candidate: 'CANDIDATE_KR_821_RAW_PARAM_TAIL_ALIGNMENT',
            raw_payload_field_bytes_hex: 'VERIFIED_DIRECT',
            experience_raw_f32_candidate: sourceResult.evidence_status,
            experience_floor_candidate: sourceResult.evidence_status,
            decreased_since_previous_snapshot: sourceResult.evidence_status,
          })
          || !minionBracketRef(ref, prepared, 0x0089, 'keyframe', 1263)
          || row.replay_time_ms !== ref.replay_time_ms
          || rawParam !== ref.raw_param
          || row.participant_id_candidate !== participant
          || !Number.isFinite(value) || value < 0
          || !Number.isSafeInteger(Math.floor(value))
          || row.experience_floor_candidate !== Math.floor(value)
          || typeof rawHex !== 'string' || !/^[0-9a-f]{8}$/.test(rawHex)) {
        invalid(`snapshot ${scanned} identity, value, or raw reference differs`);
      }
      const decoded = Buffer.from(rawHex, 'hex').reverse()
        .map(decodeRuntimeCountByte).readFloatLE(0);
      if (decoded !== value) invalid(`snapshot ${scanned} raw bytes do not decode to EXP`);
      const position = `${ref.chunk_index}/${ref.decompressed_block_offset}`;
      if (positions.has(position)) invalid(`duplicate source packet reference ${position}`);
      positions.add(position);
      const frame = frames.get(ref.chunk_index) ?? {
        time: row.replay_time_ms, participants: new Map(),
      };
      if (frame.time !== row.replay_time_ms || frame.participants.has(participant)) {
        invalid(`snapshot ${scanned} has an ambiguous keyframe roster`);
      }
      frame.participants.set(participant, {
        hero_raw_param: rawParam, participant_id_candidate: participant,
        experience_raw_f32_candidate: value,
        experience_floor_candidate: row.experience_floor_candidate,
        raw_payload_field_bytes_hex: rawHex, raw_packet_ref: ref,
      });
      frames.set(ref.chunk_index, frame);
    }
  } finally {
    lines.close();
    input.destroy();
  }
  if (scanned !== association.input_count
      || frames.size !== association.keyframe_count
      || positions.size !== association.verified_raw_packet_count
      || [...frames.values()].some((frame) => frame.participants.size !== 10)) {
    invalid('source counts or complete keyframe rosters differ');
  }
  const ordered = [...frames.entries()].sort(([a], [b]) => a - b);
  if (ordered.some(([, frame], index) => index > 0
      && frame.time <= ordered[index - 1][1].time)) {
    invalid('keyframe times are not strictly increasing');
  }
  const expected = [];
  let unchanged = 0;
  for (let index = 0; index < ordered.length; index += 1) {
    const [currentChunk, currentFrame] = ordered[index];
    const [previousChunk, previousFrame] = index > 0 ? ordered[index - 1] : [null, null];
    for (let participant = 1; participant <= 10; participant += 1) {
      const current = currentFrame.participants.get(participant);
      if (!previousFrame) {
        if (current.experience_raw_f32_candidate !== 0) {
          invalid('first keyframe EXP differs from zero');
        }
        continue;
      }
      const previous = previousFrame.participants.get(participant);
      const priorValue = previous.experience_raw_f32_candidate;
      const currentValue = current.experience_raw_f32_candidate;
      const delta = currentValue - priorValue;
      if (delta < 0) invalid('EXP candidate decreased between keyframes');
      if (delta === 0) {
        unchanged += 1;
        continue;
      }
      const previousRef = previous.raw_packet_ref;
      const currentRef = current.raw_packet_ref;
      expected.push({
        event_type: prepared.associationConfig.eventType,
        game_version: prepared.replayVersion, patch: '16.19',
        build_profile: prepared.associationConfig.profile.id,
        replay_sha256: prepared.replaySha, replay_time_ms: currentFrame.time,
        previous_observation_time_ms: previousFrame.time,
        current_observation_time_ms: currentFrame.time,
        observation_interval_ms: currentFrame.time - previousFrame.time,
        previous_keyframe_chunk_index: previousChunk,
        current_keyframe_chunk_index: currentChunk,
        hero_raw_param: current.hero_raw_param,
        participant_id_candidate: participant,
        previous_experience_raw_f32_candidate: priorValue,
        current_experience_raw_f32_candidate: currentValue,
        previous_experience_floor_candidate: previous.experience_floor_candidate,
        current_experience_floor_candidate: current.experience_floor_candidate,
        experience_endpoint_delta_f32_candidate: delta,
        experience_endpoint_delta_floor_candidate:
          current.experience_floor_candidate - previous.experience_floor_candidate,
        previous_raw_payload_field_bytes_hex: previous.raw_payload_field_bytes_hex,
        current_raw_payload_field_bytes_hex: current.raw_payload_field_bytes_hex,
        observation_kind: 'ADJACENT_KEYFRAME_SAMPLED_ENDPOINTS',
        observation_scope: 'KEYFRAME_ENDPOINT_DIFFERENCE_ONLY',
        change_time_status: 'UNRESOLVED_WITHIN_INTERVAL',
        confidence: 'CANDIDATE', semantic_status: association.evidence_status,
        field_confidence: {
          previous_observation_time_ms: 'VERIFIED_DIRECT',
          current_observation_time_ms: 'VERIFIED_DIRECT',
          participant_id_candidate: 'CANDIDATE_KR_821_RAW_PARAM_TAIL_ALIGNMENT',
          previous_raw_payload_field_bytes_hex: 'VERIFIED_DIRECT',
          current_raw_payload_field_bytes_hex: 'VERIFIED_DIRECT',
          previous_experience_raw_f32_candidate: sourceResult.evidence_status,
          current_experience_raw_f32_candidate: sourceResult.evidence_status,
          experience_endpoint_delta_f32_candidate: association.evidence_status,
          experience_endpoint_delta_floor_candidate: association.evidence_status,
        },
        raw_packet_ref: currentRef, previous_raw_packet_ref: previousRef,
        current_raw_packet_ref: currentRef,
        raw_packet_refs: [previousRef, currentRef],
        known_limits: [...prepared.associationConfig.profile.known_limits],
      });
    }
  }
  if (expected.length !== association.changed_interval_count
      || unchanged !== association.unchanged_interval_count) {
    invalid('positive and unchanged interval counts differ from association metadata');
  }
  return expected;
}

async function loadLevelExperienceBracketExpectedRows(prepared) {
  const association = prepared.capabilityResult;
  const { level: levelSource, experience: experienceSource } =
    prepared.levelExperienceBracketSources;
  const levelProfile = HERO_LEVEL_CANDIDATE_PROFILE_821;
  const experienceProfile = FLOAT_STATS_821_PROFILES.hero_experience_snapshot;
  const invalid = (reason) => {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid level/experience bracket source: ${reason}.`);
  };
  if (levelSource.replaySha !== prepared.replaySha
      || experienceSource.replaySha !== prepared.replaySha
      || levelSource.replayVersion !== prepared.replayVersion
      || experienceSource.replayVersion !== prepared.replayVersion
      || levelSource.declaredCount !== association.level_packet_count
      || experienceSource.declaredCount !== association.experience_snapshot_count) {
    throw new EventQueryError('ASSOCIATION_METADATA_MISMATCH',
      'Level/experience source artifacts differ from bracket metadata.');
  }
  const [levelRows, experienceRows] = await Promise.all([
    readMinionBracketSource(levelSource, MAX_EXPERIENCE_INTERVAL_SOURCE_ROWS_821),
    readMinionBracketSource(experienceSource, MAX_EXPERIENCE_INTERVAL_SOURCE_ROWS_821),
  ]);
  const levelPositions = new Set();
  const levels = [];
  const lastLevel = new Map();
  let levelOneCount = 0;
  let repeatedCount = 0;
  for (const [index, row] of levelRows.entries()) {
    const ref = row.raw_packet_ref;
    const raw = ref?.raw_payload_hex;
    const rawParam = row.hero_raw_param;
    const participant = (rawParam & 0xff) - 0xad;
    const observedRawParam = (rawParam >= 0x400000ae && rawParam <= 0x400000b7)
      || (rawParam >= 0x400001ae && rawParam <= 0x400001b7);
    const payload = typeof raw === 'string' && /^[0-9a-f]{2}(?:[0-9a-f]{2})?$/.test(raw)
      ? Buffer.from(raw, 'hex') : null;
    const decoded = payload && decodeLevelCode(payload);
    const previous = lastLevel.get(participant) ?? null;
    const repeated = previous !== null && row.level_after_candidate === previous;
    const kind = repeated ? 'REPEATED_LEVEL_OBSERVATION'
      : row.level_after_candidate === 1 ? 'LEVEL_ONE_OBSERVATION'
        : 'HIGHER_LEVEL_OBSERVATION';
    if (row.event_type !== 'HERO_LEVEL_STATE_CANDIDATE'
        || row.game_version !== prepared.replayVersion || row.patch !== '16.19'
        || row.build_profile !== levelProfile.id
        || row.replay_sha256 !== prepared.replaySha
        || row.confidence !== 'CANDIDATE'
        || row.semantic_status !== levelSource.capabilityResult.evidence_status
        || !isDeepStrictEqual(row.field_confidence, {
          replay_time_ms: 'VERIFIED_DIRECT', hero_raw_param: 'VERIFIED_DIRECT',
          participant_id_candidate: 'CANDIDATE_REPLAY_TAIL_ALIGNMENT',
          level_after_candidate: 'CANDIDATE_EXACT_821_RUNTIME_BYTE_AND_REPLAY_TAIL',
        })
        || !ref || ref.source_path !== (prepared.sourcePath ?? null)
        || ref.replay_sha256 !== prepared.replaySha
        || ref.chunk_stream !== 'game_chunk'
        || !Number.isSafeInteger(ref.chunk_index) || ref.chunk_index < 0
        || !Number.isSafeInteger(ref.chunk_id) || ref.chunk_id < 0
        || !Number.isSafeInteger(ref.chunk_file_offset) || ref.chunk_file_offset < 0
        || !Number.isSafeInteger(ref.decompressed_block_offset)
        || ref.decompressed_block_offset < 0
        || !Number.isSafeInteger(ref.decompressed_payload_offset)
        || ref.decompressed_payload_offset <= ref.decompressed_block_offset
        || ref.packet_id !== levelProfile.replay_block_packet_id
        || !payload || ref.payload_length !== payload.length
        || ref.replay_time_ms !== row.replay_time_ms
        || ref.raw_param !== rawParam || !observedRawParam
        || row.participant_id_candidate !== participant
        || !decoded || decoded.level !== row.level_after_candidate
        || row.raw_payload_code_hex
          !== `0x${decoded.code.toString(16).padStart(2, '0')}`
        || ref.raw_payload_sha256 !== crypto.createHash('sha256')
          .update(payload).digest('hex')
        || row.observation_kind !== kind
        || !isDeepStrictEqual(row.known_limits, [...levelProfile.known_limits])) {
      invalid(`level source row ${index + 1} identity, transform or raw ref differs`);
    }
    const position = `${ref.chunk_index}/${ref.decompressed_block_offset}`;
    if (levelPositions.has(position)) invalid(`duplicate level ref ${position}`);
    levelPositions.add(position);
    if (previous !== null && row.level_after_candidate < previous) {
      invalid(`decreasing level source row ${index + 1}`);
    }
    if (row.level_after_candidate === 1) levelOneCount += 1;
    else if (repeated) repeatedCount += 1;
    lastLevel.set(participant, row.level_after_candidate);
    levels.push({ row, priorLevel: previous });
  }
  if (levelOneCount !== association.excluded_level_one_count
      || repeatedCount !== association.excluded_repeated_level_count
      || levelPositions.size !== association.verified_level_raw_packet_count) {
    invalid('level source exclusion or unique packet counts differ');
  }

  const frames = new Map();
  const experiencePositions = new Set();
  for (const [index, row] of experienceRows.entries()) {
    const ref = row.raw_packet_ref;
    const rawParam = row.hero_raw_param;
    const participant = rawParam - 0x400000ae + 1;
    const rawHex = row.raw_payload_field_bytes_hex;
    const value = row.experience_raw_f32_candidate;
    if (row.event_type !== 'HERO_EXPERIENCE_SNAPSHOT_CANDIDATE'
        || row.game_version !== prepared.replayVersion || row.patch !== '16.19'
        || row.build_profile !== experienceProfile.id
        || row.replay_sha256 !== prepared.replaySha
        || row.confidence !== 'CANDIDATE'
        || row.semantic_status !== experienceSource.capabilityResult.evidence_status
        || row.observation_kind !== 'KEYFRAME_SNAPSHOT'
        || row.decreased_since_previous_snapshot !== false
        || !isDeepStrictEqual(row.field_confidence, {
          replay_time_ms: 'VERIFIED_DIRECT', hero_raw_param: 'VERIFIED_DIRECT',
          participant_id_candidate: 'CANDIDATE_KR_821_RAW_PARAM_TAIL_ALIGNMENT',
          raw_payload_field_bytes_hex: 'VERIFIED_DIRECT',
          experience_raw_f32_candidate:
            experienceSource.capabilityResult.evidence_status,
          experience_floor_candidate:
            experienceSource.capabilityResult.evidence_status,
          decreased_since_previous_snapshot:
            experienceSource.capabilityResult.evidence_status,
        })
        || !minionBracketRef(ref, prepared, 0x0089, 'keyframe', 1263)
        || row.replay_time_ms !== ref.replay_time_ms
        || rawParam !== ref.raw_param
        || row.participant_id_candidate !== participant
        || !Number.isFinite(value) || value < 0
        || !Number.isSafeInteger(Math.floor(value))
        || row.experience_floor_candidate !== Math.floor(value)
        || typeof rawHex !== 'string' || !/^[0-9a-f]{8}$/.test(rawHex)
        || !isDeepStrictEqual(row.known_limits, [...experienceProfile.known_limits])) {
      invalid(`experience source row ${index + 1} identity, value or raw ref differs`);
    }
    const decoded = Buffer.from(rawHex, 'hex').reverse()
      .map(decodeRuntimeCountByte).readFloatLE(0);
    if (decoded !== value) invalid(`experience source row ${index + 1} transform differs`);
    const position = `${ref.chunk_index}/${ref.decompressed_block_offset}`;
    if (experiencePositions.has(position)) invalid(`duplicate experience ref ${position}`);
    experiencePositions.add(position);
    const frame = frames.get(ref.chunk_index) ?? {
      time: row.replay_time_ms, participants: new Map(),
    };
    if (frame.time !== row.replay_time_ms || frame.participants.has(participant)) {
      invalid(`experience source row ${index + 1} has an ambiguous keyframe`);
    }
    frame.participants.set(participant, row);
    frames.set(ref.chunk_index, frame);
  }
  if (frames.size !== association.keyframe_count
      || experiencePositions.size !== association.verified_experience_raw_packet_count
      || [...frames.values()].some((frame) => frame.participants.size !== 10)) {
    invalid('experience source lacks complete keyframe rosters');
  }
  const ordered = [...frames.entries()].sort(([a], [b]) => a - b);
  if (ordered.some(([, frame], index) => index > 0
      && frame.time <= ordered[index - 1][1].time)) {
    invalid('experience keyframe times are not strictly increasing');
  }
  for (let index = 0; index < ordered.length; index += 1) {
    for (let participant = 1; participant <= 10; participant += 1) {
      const value = ordered[index][1].participants.get(participant)
        .experience_raw_f32_candidate;
      if ((index === 0 && value !== 0)
          || (index > 0 && value < ordered[index - 1][1].participants
            .get(participant).experience_raw_f32_candidate)) {
        invalid('experience endpoints differ from first-zero monotone observations');
      }
    }
  }

  let beforeFirst = 0;
  let afterLast = 0;
  let onBoundary = 0;
  let sequenceGaps = 0;
  let positive = 0;
  let unchanged = 0;
  const positiveIntervals = new Set();
  const unchangedIntervals = new Set();
  const intervalCounts = new Map();
  const expected = [];
  for (const { row: level, priorLevel } of levels) {
    if (level.level_after_candidate === 1
        || level.observation_kind === 'REPEATED_LEVEL_OBSERVATION') continue;
    const gap = priorLevel !== null
      && level.level_after_candidate > priorLevel + 1;
    if (gap) sequenceGaps += 1;
    const time = level.replay_time_ms;
    if (time < ordered[0][1].time) { beforeFirst += 1; continue; }
    if (time > ordered[ordered.length - 1][1].time) { afterLast += 1; continue; }
    let endpoints = null;
    for (let index = 1; index < ordered.length; index += 1) {
      const previous = ordered[index - 1];
      const current = ordered[index];
      if (time === previous[1].time || time === current[1].time) {
        onBoundary += 1;
        break;
      }
      if (previous[1].time < time && time < current[1].time) {
        endpoints = { previous, current };
        break;
      }
    }
    if (!endpoints) {
      if (ordered.some(([, frame]) => frame.time === time)) continue;
      invalid('higher level packet has no adjacent keyframe bracket');
    }
    const { previous, current } = endpoints;
    const participant = level.participant_id_candidate;
    const left = previous[1].participants.get(participant);
    const right = current[1].participants.get(participant);
    const delta = right.experience_raw_f32_candidate
      - left.experience_raw_f32_candidate;
    if (delta < 0) invalid('bracketed experience endpoint decreased');
    const key = `${participant}/${previous[0]}/${current[0]}`;
    if (delta > 0) {
      positive += 1;
      positiveIntervals.add(key);
    } else {
      unchanged += 1;
      unchangedIntervals.add(key);
    }
    intervalCounts.set(key, (intervalCounts.get(key) ?? 0) + 1);
    const levelRef = level.raw_packet_ref;
    const previousRef = left.raw_packet_ref;
    const currentRef = right.raw_packet_ref;
    expected.push({
      event_type: prepared.associationConfig.eventType,
      game_version: prepared.replayVersion, patch: '16.19',
      build_profile: prepared.associationConfig.profile.id,
      replay_sha256: prepared.replaySha, replay_time_ms: time,
      hero_raw_param: level.hero_raw_param,
      participant_id_candidate: participant,
      level_after_candidate: level.level_after_candidate,
      level_observation_kind: level.observation_kind,
      prior_observed_level_candidate: priorLevel,
      observed_level_sequence_gap: gap,
      raw_level_payload_code_hex: level.raw_payload_code_hex,
      previous_observation_time_ms: previous[1].time,
      current_observation_time_ms: current[1].time,
      observation_interval_ms: current[1].time - previous[1].time,
      previous_keyframe_chunk_index: previous[0],
      current_keyframe_chunk_index: current[0],
      experience_hero_raw_param: left.hero_raw_param,
      previous_experience_raw_f32_candidate: left.experience_raw_f32_candidate,
      current_experience_raw_f32_candidate: right.experience_raw_f32_candidate,
      previous_experience_floor_candidate: left.experience_floor_candidate,
      current_experience_floor_candidate: right.experience_floor_candidate,
      previous_experience_raw_payload_field_bytes_hex:
        left.raw_payload_field_bytes_hex,
      current_experience_raw_payload_field_bytes_hex:
        right.raw_payload_field_bytes_hex,
      experience_endpoint_delta_f32_candidate: delta,
      experience_endpoint_delta_floor_candidate:
        right.experience_floor_candidate - left.experience_floor_candidate,
      level_packet_count_in_same_interval: null,
      observation_kind: 'LEVEL_PACKET_WITHIN_ADJACENT_EXPERIENCE_KEYFRAMES',
      observation_scope: 'TEMPORAL_AND_CANDIDATE_PARTICIPANT_ONLY',
      confidence: 'CANDIDATE', semantic_status: association.evidence_status,
      field_confidence: {
        replay_time_ms: 'VERIFIED_DIRECT',
        previous_observation_time_ms: 'VERIFIED_DIRECT',
        current_observation_time_ms: 'VERIFIED_DIRECT',
        participant_id_candidate: 'CANDIDATE_KR_821_RAW_PARAM_TAIL_ALIGNMENT',
        level_after_candidate: levelSource.capabilityResult.evidence_status,
        raw_level_payload_code_hex: 'VERIFIED_DIRECT',
        previous_experience_raw_payload_field_bytes_hex: 'VERIFIED_DIRECT',
        current_experience_raw_payload_field_bytes_hex: 'VERIFIED_DIRECT',
        previous_experience_raw_f32_candidate:
          experienceSource.capabilityResult.evidence_status,
        current_experience_raw_f32_candidate:
          experienceSource.capabilityResult.evidence_status,
        experience_endpoint_delta_f32_candidate:
          ASSOCIATION_EVENTS_821.experience_keyframe_interval_difference_candidates
            .evidenceStatus,
        level_packet_count_in_same_interval: association.evidence_status,
      },
      raw_packet_ref: levelRef, level_raw_packet_ref: levelRef,
      previous_experience_raw_packet_ref: previousRef,
      current_experience_raw_packet_ref: currentRef,
      raw_packet_refs: [previousRef, levelRef, currentRef],
      known_limits: [...prepared.associationConfig.profile.known_limits],
    });
  }
  for (const row of expected) {
    const key = `${row.participant_id_candidate}/${row.previous_keyframe_chunk_index}/${row.current_keyframe_chunk_index}`;
    row.level_packet_count_in_same_interval = intervalCounts.get(key);
  }
  if (expected.length !== association.event_count
      || beforeFirst !== association.outside_first_keyframe_count
      || afterLast !== association.outside_last_keyframe_count
      || onBoundary !== association.exact_keyframe_boundary_count
      || sequenceGaps !== association.observed_level_sequence_gap_count
      || positive !== association.positive_endpoint_count
      || unchanged !== association.unchanged_endpoint_count
      || intervalCounts.size !== association.involved_interval_count
      || positiveIntervals.size !== association.positive_involved_interval_count
      || unchangedIntervals.size !== association.unchanged_involved_interval_count
      || [...intervalCounts.values()].filter((count) => count > 1).length
        !== association.multi_level_interval_count
      || Math.max(0, ...intervalCounts.values())
        !== association.max_level_packets_per_interval) {
    invalid('bracket rows, exclusions or endpoint counts differ from source observations');
  }
  return expected;
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
  minionBracketExpected, experienceIntervalExpected,
  levelExperienceBracketExpected) {
  const { associationConfig, capabilityResult, replaySha, replayVersion } = prepared;
  if (!associationConfig) return;
  if (associationConfig.levelExperienceBracket) {
    if (!isDeepStrictEqual(row, levelExperienceBracketExpected[lineNumber - 1])) {
      throw new EventQueryError('INVALID_EVENT_ROW',
        `Invalid level/experience keyframe bracket row at JSONL line ${lineNumber}.`,
        { line_number: lineNumber });
    }
    return;
  }
  if (associationConfig.experienceInterval) {
    const fields = Object.keys(row);
    if (fields.length !== EXPERIENCE_INTERVAL_ROW_FIELDS_821.size
        || fields.some((field) => !EXPERIENCE_INTERVAL_ROW_FIELDS_821.has(field))
        || !isDeepStrictEqual(row, experienceIntervalExpected[lineNumber - 1])) {
      throw new EventQueryError('INVALID_EVENT_ROW',
        `Invalid experience keyframe interval row at JSONL line ${lineNumber}.`,
        { line_number: lineNumber });
    }
    return;
  }
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
  if (associationConfig.inventoryGameBracket) return;
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
  if (associationConfig.objectiveBountyTurretPair) {
    objectiveBountyTurretPairRow(row, prepared, lineNumber, seenPacketPositions);
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
      || (ref.source_path !== null
        && (typeof ref.source_path !== 'string' || ref.source_path.length === 0))
      || (prepared.sourcePath !== undefined && ref.source_path !== prepared.sourcePath)
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

function firstBloodAssistPacketRow(row, prepared, lineNumber, seenPacketPositions) {
  if (prepared.eventKey !== 'first_blood_assist_event_packet_candidates') return;
  const profile = FIRST_BLOOD_ASSIST_EVENT_PACKET_821_PROFILE;
  const invalid = (reason) => {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid ${profile.capability} row at JSONL line ${lineNumber}: ${reason}.`,
      { line_number: lineNumber });
  };
  const ref = row.raw_packet_ref;
  const fields = Object.keys(row);
  if (fields.length !== FIRST_BLOOD_ASSIST_ROW_FIELDS_821.size
      || fields.some((field) => !FIRST_BLOOD_ASSIST_ROW_FIELDS_821.has(field))
      || row.event_type !== 'FIRST_BLOOD_ASSIST_EVENT_PACKET_CANDIDATE'
      || row.game_version !== profile.replay_version || row.patch !== '16.19'
      || row.build_profile !== profile.id
      || row.replay_sha256 !== prepared.replaySha
      || row.child_event_id !== profile.child_event_id
      || row.registered_event_name !== profile.child_event_name
      || row.raw_event_id_hex !== '0x49e4'
      || row.confidence !== 'CANDIDATE'
      || row.semantic_status !== 'CANDIDATE_EXACT_RUNTIME_NAMED_ON_EVENT_CHILD'
      || !Number.isSafeInteger(row.replay_time_ms) || row.replay_time_ms < 0
      || !Number.isInteger(row.raw_param) || row.raw_param <= 0
      || row.raw_param > 0xffffffff
      || typeof row.event_blob_hex !== 'string'
      || !/^[0-9a-f]{16}$/.test(row.event_blob_hex)
      || !REPLAY_SHA.test(row.event_blob_sha256 ?? '')
      || !firstBloodAssistPacketRefValid(ref, prepared.replaySha,
        prepared.sourcePath)
      || ref.replay_time_ms !== row.replay_time_ms
      || ref.raw_param !== row.raw_param) {
    invalid('exact child, opaque blob or raw packet reference differs');
  }
  if (crypto.createHash('sha256').update(Buffer.from(row.event_blob_hex, 'hex'))
    .digest('hex') !== row.event_blob_sha256) invalid('native blob SHA-256 differs');
  const position = `${ref.chunk_index}/${ref.decompressed_block_offset}`;
  if (seenPacketPositions.has(position)) invalid('duplicate raw packet position');
  seenPacketPositions.add(position);
}

function objectiveBountyClaimedPacketRow(row, prepared, lineNumber,
  seenPacketPositions) {
  if (prepared.eventKey !== 'objective_bounty_claimed_packet_candidates') return;
  const profile = OBJECTIVE_BOUNTY_CLAIMED_PACKET_821_PROFILE;
  const invalid = (reason) => {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid objective_bounty_claimed_packet row at JSONL line ${lineNumber}: ${reason}.`,
      { line_number: lineNumber });
  };
  const ref = row.raw_packet_ref;
  const blobHex = row.event_blob_hex;
  if (row.event_type !== 'OBJECTIVE_BOUNTY_CLAIMED_PACKET_CANDIDATE'
      || row.game_version !== prepared.replayVersion || row.patch !== '16.19'
      || row.build_profile !== profile.id
      || row.confidence !== 'CANDIDATE'
      || row.semantic_status !== 'CANDIDATE_EXACT_RUNTIME_NAMED_ON_EVENT_CHILD'
      || row.event_id !== profile.child_event_id
      || row.event_name !== profile.child_event_name
      || row.raw_event_id_hex !== '0x09e5'
      || row.event_schema_u32_0x00 !== 469
      || !Number.isSafeInteger(row.blob_u32_0x04)
      || row.blob_u32_0x04 < 0 || row.blob_u32_0x04 > 0xffffffff
      || typeof blobHex !== 'string' || !/^[0-9a-f]{16}$/.test(blobHex)
      || !REPLAY_SHA.test(row.event_blob_sha256 ?? '')
      || !ref || ref.replay_sha256 !== prepared.replaySha
      || (ref.source_path !== null
        && (typeof ref.source_path !== 'string' || ref.source_path.length === 0))
      || (prepared.sourcePath !== undefined && ref.source_path !== prepared.sourcePath)
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
      || ref.raw_param > 0xffffffff || row.raw_param !== ref.raw_param
      || !REPLAY_SHA.test(ref.raw_payload_sha256 ?? '')) {
    invalid('exact-build child, anonymous blob or raw packet identity differs');
  }
  const blob = Buffer.from(blobHex, 'hex');
  if (crypto.createHash('sha256').update(blob).digest('hex')
        !== row.event_blob_sha256
      || blob.readUInt32LE(0) !== row.event_schema_u32_0x00
      || blob.readUInt32LE(4) !== row.blob_u32_0x04) {
    invalid('native child blob bytes disagree with hash or anonymous fields');
  }
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

function unitApplyDamageRosterKeyRow(row, prepared, lineNumber, state) {
  if (prepared.eventKey !== 'unit_apply_damage_roster_key_candidates') return;
  const invalid = (reason) => {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid UnitApplyDamage roster key pair at JSONL line ${lineNumber}: ${reason}.`,
      { line_number: lineNumber });
  };
  const profile = damageAssociationProfile(prepared.capabilityResult,
    UNIT_APPLY_DAMAGE_ROSTER_KEY_821_PROFILE,
    UNIT_APPLY_DAMAGE_ROSTER_KEY_PROFILE_V1_821,
    UNIT_APPLY_DAMAGE_ROSTER_KEY_PROFILE_V2_821);
  const damageRef = row.unit_apply_damage_raw_packet_ref;
  const statsRef = row.hero_stats_roster_raw_packet_ref;
  const rawParam = row.raw_param;
  const fields = profile.id.endsWith('-v3')
    ? UNIT_APPLY_DAMAGE_ROSTER_V3_ROW_FIELDS_821
    : UNIT_APPLY_DAMAGE_ROSTER_ROW_FIELDS_821;
  if (Object.keys(row).length !== fields.size
      || Object.keys(row).some((field) =>
        !fields.has(field))
      || row.event_type !== 'UNIT_APPLY_DAMAGE_ROSTER_KEY_CANDIDATE'
      || row.game_version !== profile.replay_version || row.patch !== '16.19'
      || row.build_profile !== profile.id
      || row.replay_sha256 !== prepared.replaySha
      || row.confidence !== 'CANDIDATE'
      || row.semantic_status !== profile.evidence_status
      || row.pair_basis !== 'EXACT_FULL_RAW_PARAM_IN_CANONICAL_HEROSTATS_ROSTER'
      || row.actor_assignment_status !== 'UNKNOWN'
      || row.source_target_role_status !== 'UNKNOWN'
      || row.semantic_effect_status !== 'UNKNOWN'
      || !Number.isSafeInteger(rawParam)
      || rawParam < 0x400000ae || rawParam > 0x400000b7
      || row.hero_stats_participant_id_candidate
        !== rawParam - 0x400000ae + 1
      || !Number.isFinite(row.native_callback_f32_0x20_candidate)
      || !UNIT_APPLY_DAMAGE_NATIVE_FLOAT_SOURCES_821.includes(
        row.native_callback_f32_0x20_source)
      || (row.native_callback_f32_0x20_source === 'CONSTANT_0'
        && row.native_callback_f32_0x20_candidate !== 0)
      || (row.native_callback_f32_0x20_source === 'CONSTANT_1'
        && row.native_callback_f32_0x20_candidate !== 1)
      || (row.native_callback_f32_0x20_source === 'CONSTANT_2'
        && row.native_callback_f32_0x20_candidate !== 2)
      || !Array.isArray(row.raw_packet_refs)
      || !isDeepStrictEqual(row.raw_packet_refs, [damageRef, statsRef])
      || !validUnitApplyDamageRosterRef(damageRef, prepared.replaySha,
        prepared.sourcePath, 0x005f, rawParam, row.replay_time_ms)
      || !validUnitApplyDamageRosterRef(statsRef, prepared.replaySha,
        prepared.sourcePath, 0x0089, rawParam)
      || !validDamageAssociationV3F32Row(row, damageRef, profile)) {
    invalid('exact full key, unknown roles, native value or named source references differ');
  }
  const payload = Buffer.from(damageRef.raw_payload_hex, 'hex');
  const selector24 = payload[3] & 7;
  const selector0 = payload[0] & 7;
  const selector3 = (payload[0] >>> 3) & 7;
  const expectedSource = ({ 3: 'CONSTANT_0', 5: 'CONSTANT_1',
    7: 'CONSTANT_2' })[selector3] ?? 'RAW_READER';
  if (!isObservedUnitApplyDamageShape821(
    payload.length, selector24, selector0, selector3)
      || row.native_callback_f32_0x20_source !== expectedSource) {
    invalid('raw 0x005f packet shape or native float source differs');
  }
  if (damageRef.chunk_index < state.previousDamageChunkIndex
      || (damageRef.chunk_index === state.previousDamageChunkIndex
        && damageRef.decompressed_block_offset
          <= state.previousDamageBlockOffset)) {
    invalid('damage packet order differs from Replay walk order');
  }
  state.previousDamageChunkIndex = damageRef.chunk_index;
  state.previousDamageBlockOffset = damageRef.decompressed_block_offset;
  const rosterFrame = `${statsRef.chunk_index}/${statsRef.chunk_id}/` +
    `${statsRef.chunk_file_offset}/${statsRef.replay_time_ms}`;
  if (state.rosterFrame !== null && state.rosterFrame !== rosterFrame) {
    invalid('HeroStats reference is not from the canonical roster keyframe');
  }
  state.rosterFrame = rosterFrame;
  const priorStatsRef = state.rosterRefs.get(rawParam);
  if (priorStatsRef && !isDeepStrictEqual(priorStatsRef, statsRef)) {
    invalid('same full key uses conflicting HeroStats roster references');
  }
  const statsPosition = `${statsRef.chunk_index}/${statsRef.decompressed_block_offset}`;
  const priorKey = state.rosterPositions.get(statsPosition);
  if (priorKey != null && priorKey !== rawParam) {
    invalid('different full keys share one HeroStats packet position');
  }
  state.rosterRefs.set(rawParam, statsRef);
  state.rosterPositions.set(statsPosition, rawParam);
  state.damagePositions.add(`${damageRef.chunk_index}/` +
    `${damageRef.decompressed_block_offset}`);
}

function unitApplyDamageLookupRosterKeyRow(row, prepared, lineNumber, state) {
  if (prepared.eventKey !== 'unit_apply_damage_lookup_roster_key_candidates') return;
  const invalid = (reason) => {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid UnitApplyDamage lookup roster key pair at JSONL line ${lineNumber}: ${reason}.`,
      { line_number: lineNumber });
  };
  const profile = damageAssociationProfile(prepared.capabilityResult,
    UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_KEY_821_PROFILE,
    UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_KEY_PROFILE_V1_821,
    UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_KEY_PROFILE_V2_821);
  const damageRef = row.unit_apply_damage_raw_packet_ref;
  const statsRef = row.hero_stats_roster_raw_packet_ref;
  const rawParam = row.raw_param;
  const key = row.native_callback_lookup_key_u32_0x24_candidate;
  const relation = rawParam === key ? 'EQUAL'
    : rawParam - key === 0x100 ? 'RAW_PARAM_IS_LOOKUP_PLUS_0X100' : 'OTHER';
  const fields = profile.id.endsWith('-v3')
    ? UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_V3_ROW_FIELDS_821
    : UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_ROW_FIELDS_821;
  if (Object.keys(row).length !== fields.size
      || Object.keys(row).some((field) =>
        !fields.has(field))
      || row.event_type !== 'UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_KEY_CANDIDATE'
      || row.game_version !== profile.replay_version || row.patch !== '16.19'
      || row.build_profile !== profile.id
      || row.replay_sha256 !== prepared.replaySha
      || row.confidence !== 'CANDIDATE'
      || row.semantic_status !== profile.evidence_status
      || row.pair_basis
        !== 'NATIVE_CALLBACK_LOOKUP_KEY_0X24_EXACT_FULL_KEY_IN_CANONICAL_HEROSTATS_ROSTER'
      || row.lookup_resolution_status !== 'UNKNOWN'
      || row.actor_assignment_status !== 'UNKNOWN'
      || row.source_target_role_status !== 'UNKNOWN'
      || row.semantic_effect_status !== 'UNKNOWN'
      || !Number.isSafeInteger(rawParam) || rawParam <= 0
      || rawParam > 0xffffffff
      || !Number.isSafeInteger(key)
      || key < 0x400000ae || key > 0x400000b7
      || decodeUnitApplyDamageLookupKeyFromRaw821(
        row.native_callback_lookup_key_0x24_encoded_bytes_hex, 0x24) !== key
      || row.native_callback_lookup_key_0x24_raw_param_relation !== relation
      || row.hero_raw_param !== key
      || row.hero_stats_participant_id_candidate !== key - 0x400000ae + 1
      || !Array.isArray(row.raw_packet_refs)
      || !isDeepStrictEqual(row.raw_packet_refs, [damageRef, statsRef])
      || !validUnitApplyDamageRosterRef(damageRef, prepared.replaySha,
        prepared.sourcePath, 0x005f, rawParam, row.replay_time_ms)
      || !validUnitApplyDamageRosterRef(statsRef, prepared.replaySha,
        prepared.sourcePath, 0x0089, key)
      || !validDamageAssociationV3F32Row(row, damageRef, profile)) {
    invalid('native lookup full key, roster label, unknown roles or source references differ');
  }
  const payload = Buffer.from(damageRef.raw_payload_hex, 'hex');
  const selector24 = payload[3] & 7;
  const selector0 = payload[0] & 7;
  const selector3 = (payload[0] >>> 3) & 7;
  if (!isObservedUnitApplyDamageShape821(
    payload.length, selector24, selector0, selector3)) {
    invalid('0x005f raw packet shape differs from exact 821 observed catalog');
  }
  if (damageRef.chunk_index < state.previousDamageChunkIndex
      || (damageRef.chunk_index === state.previousDamageChunkIndex
        && damageRef.decompressed_block_offset
          <= state.previousDamageBlockOffset)) {
    invalid('damage packet order differs from Replay walk order');
  }
  state.previousDamageChunkIndex = damageRef.chunk_index;
  state.previousDamageBlockOffset = damageRef.decompressed_block_offset;
  const rosterFrame = `${statsRef.chunk_index}/${statsRef.chunk_id}/` +
    `${statsRef.chunk_file_offset}/${statsRef.replay_time_ms}`;
  if (state.rosterFrame !== null && state.rosterFrame !== rosterFrame) {
    invalid('HeroStats reference is not from the canonical roster keyframe');
  }
  state.rosterFrame = rosterFrame;
  const priorStatsRef = state.rosterRefs.get(key);
  if (priorStatsRef && !isDeepStrictEqual(priorStatsRef, statsRef)) {
    invalid('same full lookup key uses conflicting HeroStats roster references');
  }
  const statsPosition = `${statsRef.chunk_index}/${statsRef.decompressed_block_offset}`;
  const priorKey = state.rosterPositions.get(statsPosition);
  if (priorKey != null && priorKey !== key) {
    invalid('different full lookup keys share one HeroStats packet position');
  }
  state.rosterRefs.set(key, statsRef);
  state.rosterPositions.set(statsPosition, key);
  state.damagePositions.add(`${damageRef.chunk_index}/` +
    `${damageRef.decompressed_block_offset}`);
  state.relationCounts[relation] += 1;
}

function unitApplyDamageLookup2cRosterKeyRow(row, prepared, lineNumber, state) {
  if (prepared.eventKey !== 'unit_apply_damage_lookup2c_roster_key_candidates') return;
  const invalid = (reason) => {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid UnitApplyDamage +0x2c lookup roster key pair at JSONL line ${lineNumber}: ${reason}.`,
      { line_number: lineNumber });
  };
  const profile = damageAssociationProfile(prepared.capabilityResult,
    UNIT_APPLY_DAMAGE_LOOKUP2C_ROSTER_KEY_821_PROFILE,
    UNIT_APPLY_DAMAGE_LOOKUP2C_ROSTER_KEY_PROFILE_V1_821,
    UNIT_APPLY_DAMAGE_LOOKUP2C_ROSTER_KEY_PROFILE_V2_821);
  const damageRef = row.unit_apply_damage_raw_packet_ref;
  const statsRef = row.hero_stats_roster_raw_packet_ref;
  const rawParam = row.raw_param;
  const key24 = row.native_callback_lookup_key_u32_0x24_candidate;
  const key2c = row.native_callback_lookup_key_u32_0x2c_candidate;
  const rawParamRelation = rawParam === key24 ? 'EQUAL'
    : rawParam - key24 === 0x100
      ? 'RAW_PARAM_IS_LOOKUP_PLUS_0X100' : 'OTHER';
  const key24RosterRelation = key24 === key2c ? 'SAME_ROSTER_KEY'
    : key24 >= 0x400000ae && key24 <= 0x400000b7
      ? 'DIFFERENT_ROSTER_KEY' : 'KEY24_NOT_IN_ROSTER';
  const fields = profile.id.endsWith('-v3')
    ? UNIT_APPLY_DAMAGE_LOOKUP2C_ROSTER_V3_ROW_FIELDS_821
    : UNIT_APPLY_DAMAGE_LOOKUP2C_ROSTER_ROW_FIELDS_821;
  if (Object.keys(row).length !== fields.size
      || Object.keys(row).some((field) =>
        !fields.has(field))
      || row.event_type !== 'UNIT_APPLY_DAMAGE_LOOKUP2C_ROSTER_KEY_CANDIDATE'
      || row.game_version !== profile.replay_version || row.patch !== '16.19'
      || row.build_profile !== profile.id
      || row.replay_sha256 !== prepared.replaySha
      || row.confidence !== 'CANDIDATE'
      || row.semantic_status !== profile.evidence_status
      || row.pair_basis
        !== 'NATIVE_CALLBACK_LOOKUP_KEY_0X2C_EXACT_FULL_KEY_IN_CANONICAL_HEROSTATS_ROSTER'
      || row.lookup_resolution_status !== 'UNKNOWN'
      || row.actor_assignment_status !== 'UNKNOWN'
      || row.source_target_role_status !== 'UNKNOWN'
      || row.semantic_effect_status !== 'UNKNOWN'
      || !Number.isSafeInteger(rawParam) || rawParam <= 0
      || rawParam > 0xffffffff
      || !Number.isSafeInteger(key24) || key24 <= 0
      || key24 > 0xffffffff
      || !Number.isSafeInteger(key2c)
      || key2c < 0x400000ae || key2c > 0x400000b7
      || decodeUnitApplyDamageLookupKeyFromRaw821(
        row.native_callback_lookup_key_0x24_encoded_bytes_hex, 0x24)
        !== key24
      || decodeUnitApplyDamageLookupKeyFromRaw821(
        row.native_callback_lookup_key_0x2c_encoded_bytes_hex, 0x2c)
        !== key2c
      || row.native_callback_lookup_key_0x24_raw_param_relation
        !== rawParamRelation
      || row.key24_roster_relation !== key24RosterRelation
      || row.hero_raw_param !== key2c
      || row.hero_stats_participant_id_candidate
        !== key2c - 0x400000ae + 1
      || !Array.isArray(row.raw_packet_refs)
      || !isDeepStrictEqual(row.raw_packet_refs, [damageRef, statsRef])
      || !validUnitApplyDamageRosterRef(damageRef, prepared.replaySha,
        prepared.sourcePath, 0x005f, rawParam, row.replay_time_ms)
      || !validUnitApplyDamageRosterRef(statsRef, prepared.replaySha,
        prepared.sourcePath, 0x0089, key2c)
      || !validDamageAssociationV3F32Row(row, damageRef, profile)) {
    invalid('native lookup full keys, roster label, unknown roles or source references differ');
  }
  const payload = Buffer.from(damageRef.raw_payload_hex, 'hex');
  const selector24 = payload[3] & 7;
  const selector0 = payload[0] & 7;
  const selector3 = (payload[0] >>> 3) & 7;
  if (!isObservedUnitApplyDamageShape821(
    payload.length, selector24, selector0, selector3)) {
    invalid('0x005f raw packet shape differs from exact 821 observed catalog');
  }
  if (damageRef.chunk_index < state.previousDamageChunkIndex
      || (damageRef.chunk_index === state.previousDamageChunkIndex
        && damageRef.decompressed_block_offset
          <= state.previousDamageBlockOffset)) {
    invalid('damage packet order differs from Replay walk order');
  }
  state.previousDamageChunkIndex = damageRef.chunk_index;
  state.previousDamageBlockOffset = damageRef.decompressed_block_offset;
  const rosterFrame = `${statsRef.chunk_index}/${statsRef.chunk_id}/`
    + `${statsRef.chunk_file_offset}/${statsRef.replay_time_ms}`;
  if (state.rosterFrame !== null && state.rosterFrame !== rosterFrame) {
    invalid('HeroStats reference is not from the canonical roster keyframe');
  }
  state.rosterFrame = rosterFrame;
  const priorStatsRef = state.rosterRefs.get(key2c);
  if (priorStatsRef && !isDeepStrictEqual(priorStatsRef, statsRef)) {
    invalid('same +0x2c full key uses conflicting HeroStats roster references');
  }
  const statsPosition = `${statsRef.chunk_index}/${statsRef.decompressed_block_offset}`;
  const priorKey = state.rosterPositions.get(statsPosition);
  if (priorKey != null && priorKey !== key2c) {
    invalid('different +0x2c full keys share one HeroStats packet position');
  }
  state.rosterRefs.set(key2c, statsRef);
  state.rosterPositions.set(statsPosition, key2c);
  state.damagePositions.add(`${damageRef.chunk_index}/`
    + `${damageRef.decompressed_block_offset}`);
  state.key24RosterCounts[key24RosterRelation] += 1;
}

function validHeroDeathDamageLookupDeathRef(ref, prepared, role, packetId,
  payloadLength, replayTime, chunkIndex) {
  return !!ref && typeof ref === 'object' && !Array.isArray(ref)
    && Object.keys(ref).length
      === HERO_DEATH_DAMAGE_LOOKUP_DEATH_REF_FIELDS_821.size
    && Object.keys(ref).every((field) =>
      HERO_DEATH_DAMAGE_LOOKUP_DEATH_REF_FIELDS_821.has(field))
    && ref.role === role
    && ref.source_path === (prepared.sourcePath ?? null)
    && ref.replay_sha256 === prepared.replaySha
    && ref.chunk_stream === 'game_chunk'
    && Number.isSafeInteger(ref.chunk_index) && ref.chunk_index >= 0
    && (chunkIndex === null || ref.chunk_index === chunkIndex)
    && Number.isSafeInteger(ref.chunk_id) && ref.chunk_id >= 0
    && Number.isSafeInteger(ref.chunk_file_offset)
    && ref.chunk_file_offset >= 0
    && Number.isSafeInteger(ref.decompressed_block_offset)
    && ref.decompressed_block_offset >= 0
    && Number.isSafeInteger(ref.decompressed_payload_offset)
    && ref.decompressed_payload_offset > ref.decompressed_block_offset
    && ref.packet_id === packetId
    && ref.replay_time_ms === replayTime
    && Number.isSafeInteger(ref.payload_length)
    && (Array.isArray(payloadLength)
      ? payloadLength.includes(ref.payload_length)
      : payloadLength === null ? ref.payload_length > 5
        : ref.payload_length === payloadLength)
    && Number.isSafeInteger(ref.raw_param) && ref.raw_param >= 0
    && ref.raw_param <= 0xffffffff
    && REPLAY_SHA.test(ref.raw_payload_sha256);
}

function heroDeathDamageLookupKeyCooccurrenceRow(row, prepared, lineNumber,
  state) {
  if (prepared.eventKey
      !== 'hero_death_damage_lookup_key_cooccurrence_candidates') return;
  const invalid = (reason) => {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid hero death/damage lookup cooccurrence at JSONL line ${lineNumber}: ${reason}.`,
      { line_number: lineNumber });
  };
  const profile = damageAssociationProfile(prepared.capabilityResult,
    HERO_DEATH_DAMAGE_LOOKUP_KEY_COOCCURRENCE_821_PROFILE,
    HERO_DEATH_DAMAGE_LOOKUP_KEY_COOCCURRENCE_PROFILE_V1_821,
    HERO_DEATH_DAMAGE_LOOKUP_KEY_COOCCURRENCE_PROFILE_V2_821);
  const deathRefs = row.hero_death_raw_packet_refs;
  const primary = row.hero_death_raw_packet_ref;
  const dieSourceRef = row.hero_death_die_source_raw_packet_ref;
  const rosterRef = row.hero_stats_roster_raw_packet_ref;
  const packets = row.same_time_victim_key24_packet_candidates;
  const victim = row.victim_participant_id_candidate;
  const victimKey = 0x400000ad + victim;
  const dieSource = row.die_source_network_id_candidate;
  if (Object.keys(row).length !== HERO_DEATH_DAMAGE_LOOKUP_ROW_FIELDS_821.size
      || Object.keys(row).some((field) =>
        !HERO_DEATH_DAMAGE_LOOKUP_ROW_FIELDS_821.has(field))
      || row.event_type !== 'HERO_DEATH_DAMAGE_LOOKUP_KEY_COOCCURRENCE_CANDIDATE'
      || row.game_version !== profile.replay_version || row.patch !== '16.19'
      || row.build_profile !== profile.id
      || row.replay_sha256 !== prepared.replaySha
      || row.confidence !== 'CANDIDATE'
      || row.semantic_status !== profile.evidence_status
      || row.pair_basis
        !== 'SAME_CHUNK_SAME_MILLISECOND_EXACT_CANONICAL_VICTIM_KEY24'
      || row.lookup_resolution_status !== 'UNKNOWN'
      || row.actor_assignment_status !== 'UNKNOWN'
      || row.source_target_role_status !== 'UNKNOWN'
      || row.semantic_effect_status !== 'UNKNOWN'
      || !Number.isSafeInteger(victim) || victim < 1 || victim > 10
      || row.victim_lookup_roster_key_u32_candidate !== victimKey
      || ![victimKey, victimKey + 0x100].includes(row.victim_raw_param)
      || (dieSource !== null
        && (!Number.isSafeInteger(dieSource) || dieSource < 0
          || dieSource > 0xffffffff))
      || !Array.isArray(deathRefs) || ![3, 4].includes(deathRefs.length)
      || !isDeepStrictEqual(primary, deathRefs[0])
      || !isDeepStrictEqual(dieSourceRef, deathRefs[1])
      || !Array.isArray(packets)
      || !isCount(row.same_time_victim_key24_packet_candidate_count)
      || row.same_time_victim_key24_packet_candidate_count !== packets.length
      || !isCount(row.same_time_victim_key24_packet_before_primary_count)
      || !isCount(row.same_time_victim_key24_packet_after_primary_count)
      || !validUnitApplyDamageRosterRef(rosterRef, prepared.replaySha,
        prepared.sourcePath, 0x0089, victimKey)
      || !validHeroDeathDamageLookupDeathRef(primary, prepared,
        'candidate_primary', 0x0259, 5, row.replay_time_ms, null)
      || primary.raw_param !== row.victim_raw_param
      || !validHeroDeathDamageLookupDeathRef(dieSourceRef, prepared,
        'candidate_paired', 0x0438, null, row.replay_time_ms,
        primary.chunk_index)
      || dieSourceRef.raw_param !== row.victim_raw_param
      || !validHeroDeathDamageLookupDeathRef(deathRefs[2], prepared,
        'corroborating_core_co_timed', 0x031b, null,
        row.replay_time_ms, primary.chunk_index)
      || (deathRefs.length === 4
        && !validHeroDeathDamageLookupDeathRef(deathRefs[3], prepared,
          'optional_corroborating_co_timed', 0x03d4, [3, 7],
          row.replay_time_ms, primary.chunk_index))) {
    invalid('exact death anchor, canonical roster or candidate boundaries differ');
  }
  const deathPositions = new Set();
  for (const ref of deathRefs) {
    if (ref.chunk_id !== primary.chunk_id
        || ref.chunk_file_offset !== primary.chunk_file_offset) {
      invalid('death route references do not share one game chunk');
    }
    const position = `${ref.chunk_index}/${ref.decompressed_block_offset}`;
    if (deathPositions.has(position) || state.deathRoutePositions.has(position)) {
      invalid('duplicate death route packet reference');
    }
    deathPositions.add(position);
    state.deathRoutePositions.add(position);
  }
  const primaryPosition = `${primary.chunk_index}/${primary.decompressed_block_offset}`;
  if (state.primaryPositions.has(primaryPosition)
      || primary.chunk_index < state.previousPrimaryChunkIndex
      || (primary.chunk_index === state.previousPrimaryChunkIndex
        && primary.decompressed_block_offset
          <= state.previousPrimaryBlockOffset)) {
    invalid('death anchors are duplicated or outside Replay walk order');
  }
  state.primaryPositions.add(primaryPosition);
  state.previousPrimaryChunkIndex = primary.chunk_index;
  state.previousPrimaryBlockOffset = primary.decompressed_block_offset;
  const rosterFrame = `${rosterRef.chunk_index}/${rosterRef.chunk_id}/`
    + `${rosterRef.chunk_file_offset}/${rosterRef.replay_time_ms}`;
  if (state.rosterFrame !== null && state.rosterFrame !== rosterFrame) {
    invalid('HeroStats packet is outside one canonical roster keyframe');
  }
  state.rosterFrame = rosterFrame;
  const priorRosterRef = state.rosterRefs.get(victimKey);
  if (priorRosterRef && !isDeepStrictEqual(priorRosterRef, rosterRef)) {
    invalid('one canonical victim key has conflicting HeroStats refs');
  }
  const rosterPosition = `${rosterRef.chunk_index}/${rosterRef.decompressed_block_offset}`;
  const priorRosterKey = state.rosterPositions.get(rosterPosition);
  if (priorRosterKey !== undefined && priorRosterKey !== victimKey) {
    invalid('different canonical victim keys share one HeroStats packet position');
  }
  state.rosterRefs.set(victimKey, rosterRef);
  state.rosterPositions.set(rosterPosition, victimKey);
  let previousDamageBlockOffset = -1;
  let before = 0;
  let after = 0;
  let dieSourceMatches = 0;
  const damageRefs = [];
  for (const packet of packets) {
    const damageRef = packet?.unit_apply_damage_raw_packet_ref;
    const rawParam = packet?.raw_param;
    const key24 = packet?.native_callback_lookup_key_u32_0x24_candidate;
    const key2c = packet?.native_callback_lookup_key_u32_0x2c_candidate;
    const rawParamRelation = rawParam === key24 ? 'EQUAL'
      : rawParam - key24 === 0x100
        ? 'RAW_PARAM_IS_LOOKUP_PLUS_0X100' : 'OTHER';
    const isBefore = damageRef?.decompressed_block_offset
      < primary.decompressed_block_offset;
    const relative = isBefore ? 'BEFORE_PRIMARY' : 'AFTER_PRIMARY';
    const dieSourceEqual = dieSource === null ? null : key2c === dieSource;
    const packetFields = profile.id.endsWith('-v3')
      ? HERO_DEATH_DAMAGE_LOOKUP_V3_PACKET_FIELDS_821
      : HERO_DEATH_DAMAGE_LOOKUP_PACKET_FIELDS_821;
    if (!packet || typeof packet !== 'object' || Array.isArray(packet)
        || Object.keys(packet).length !== packetFields.size
        || Object.keys(packet).some((field) =>
          !packetFields.has(field))
        || !Number.isSafeInteger(rawParam) || rawParam <= 0
        || rawParam > 0xffffffff
        || key24 !== victimKey
        || !Number.isSafeInteger(key2c) || key2c <= 0
        || key2c > 0xffffffff
        || decodeUnitApplyDamageLookupKeyFromRaw821(
          packet.native_callback_lookup_key_0x24_encoded_bytes_hex, 0x24)
          !== key24
        || decodeUnitApplyDamageLookupKeyFromRaw821(
          packet.native_callback_lookup_key_0x2c_encoded_bytes_hex, 0x2c)
          !== key2c
        || packet.native_callback_lookup_key_0x24_raw_param_relation
          !== rawParamRelation
        || packet.die_source_key2c_equal !== dieSourceEqual
        || packet.relative_to_death_primary !== relative
        || !validUnitApplyDamageRosterRef(damageRef, prepared.replaySha,
          prepared.sourcePath, 0x005f, rawParam, row.replay_time_ms)
        || damageRef.chunk_index !== primary.chunk_index
        || damageRef.chunk_id !== primary.chunk_id
        || damageRef.chunk_file_offset !== primary.chunk_file_offset
        || damageRef.decompressed_block_offset
          === primary.decompressed_block_offset
        || damageRef.decompressed_block_offset <= previousDamageBlockOffset
        || !validDamageAssociationV3F32Row(packet, damageRef, profile)) {
      invalid('nested native keys, packet order, raw bytes or same-time chunk differ');
    }
    const payload = Buffer.from(damageRef.raw_payload_hex, 'hex');
    if (!isObservedUnitApplyDamageShape821(payload.length, payload[3] & 7,
      payload[0] & 7, (payload[0] >>> 3) & 7)) {
      invalid('nested 0x005f packet shape is outside exact 821 catalog');
    }
    const position = `${damageRef.chunk_index}/${damageRef.decompressed_block_offset}`;
    if (deathPositions.has(position) || state.damagePositions.has(position)) {
      invalid('nested damage reference duplicates a route or prior anchor packet');
    }
    state.damagePositions.add(position);
    previousDamageBlockOffset = damageRef.decompressed_block_offset;
    if (isBefore) before += 1;
    else after += 1;
    if (dieSourceEqual) dieSourceMatches += 1;
    damageRefs.push(damageRef);
  }
  const status = dieSource === null ? 'DIE_SOURCE_UNAVAILABLE'
    : dieSourceMatches > 0 ? 'HAS_SAME_TIME_MATCH' : 'NO_SAME_TIME_MATCH';
  if (row.same_time_victim_key24_packet_before_primary_count !== before
      || row.same_time_victim_key24_packet_after_primary_count !== after
      || row.same_time_die_source_key2c_packet_candidate_count
        !== (dieSource === null ? null : dieSourceMatches)
      || row.die_source_key2c_match_status !== status
      || !isDeepStrictEqual(row.raw_packet_refs,
        [...deathRefs, rosterRef, ...damageRefs])) {
    invalid('per-anchor packet counts, absence or ordered raw refs differ');
  }
  state.deathRoutePacketCount += deathRefs.length;
  state.matchedPacketCount += packets.length;
  state.withPacketCount += Number(packets.length > 0);
  state.withoutPacketCount += Number(packets.length === 0);
  state.multiplePacketAnchorCount += Number(packets.length > 1);
  state.maxPacketCount = Math.max(state.maxPacketCount, packets.length);
  state.dieSourceMatchPacketCount += dieSourceMatches;
  state.withDieSourceMatchCount += Number(dieSource !== null
    && dieSourceMatches > 0);
  state.withoutDieSourceMatchCount += Number(dieSource !== null
    && dieSourceMatches === 0);
  state.dieSourceUnavailableCount += Number(dieSource === null);
}

function candidateChildEventId(row, eventKey, lineNumber) {
  const field = eventKey === 'champion_triple_quadra_multi_group_candidates'
    ? 'on_champion_triple_quadra_child_event_id'
    : eventKey === 'champion_double_kill_multi_group_candidates'
      ? 'on_champion_double_kill_child_event_id'
      : ['hq_kill_event_packet_candidates',
        'objective_bounty_claimed_packet_candidates'].includes(eventKey)
        ? 'event_id' : 'child_event_id';
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

const DIE_SOURCE_KEY2C_MATCH_FILTERS_821 = Object.freeze({
  has: 'HAS_SAME_TIME_MATCH',
  none: 'NO_SAME_TIME_MATCH',
  unavailable: 'DIE_SOURCE_UNAVAILABLE',
});

function validateFilters(options) {
  const { fromMs = null, toMs = null, participant = null,
    killerParticipant = null, assistingParticipant = null, rawParam = null,
    itemId = null, previousItemId = null, slot = null,
    opaqueU32 = null, opaquePair = null, opaqueI32 = null,
    castNestedBits = null, damageCallbackF32Available = false,
    damageCallbackF32At18Raw = false,
    damageLookupKey24 = null, damageLookupKey2c = null,
    damageCallbackU32At10 = null,
    dieSourceKey2cMatch = null,
    packetRecordCount = null, showHealthZeroFlag = null, levelAfter = null,
    childEventId = null, limit = null, latestPerParticipant = false,
    endpointReversedPair: endpointReversedPairFilter = false,
    comparisonToEndpoints = null } = options;
  if (typeof latestPerParticipant !== 'boolean') {
    throw new EventQueryError('INVALID_FILTER', 'Invalid latestPerParticipant query filter.');
  }
  if (typeof damageCallbackF32Available !== 'boolean') {
    throw new EventQueryError('INVALID_FILTER',
      'Invalid damageCallbackF32Available query filter.');
  }
  if (typeof damageCallbackF32At18Raw !== 'boolean') {
    throw new EventQueryError('INVALID_FILTER',
      'Invalid damageCallbackF32At18Raw query filter.');
  }
  if (typeof endpointReversedPairFilter !== 'boolean') {
    throw new EventQueryError('INVALID_FILTER', 'Invalid endpointReversedPair query filter.');
  }
  if (comparisonToEndpoints != null
      && !INVENTORY_GAME_COMPARISON_LABELS_821.includes(comparisonToEndpoints)) {
    throw new EventQueryError('INVALID_FILTER',
      'Invalid comparisonToEndpoints query filter.');
  }
  if (dieSourceKey2cMatch != null
      && (typeof dieSourceKey2cMatch !== 'string'
        || !Object.hasOwn(DIE_SOURCE_KEY2C_MATCH_FILTERS_821,
          dieSourceKey2cMatch))) {
    throw new EventQueryError('INVALID_FILTER',
      'Invalid dieSourceKey2cMatch query filter.');
  }
  for (const [name, value, minimum, maximum] of [
    ['fromMs', fromMs, 0, Number.MAX_SAFE_INTEGER],
    ['toMs', toMs, 0, Number.MAX_SAFE_INTEGER],
    ['participant', participant, 1, 10],
    ['killerParticipant', killerParticipant, 1, 10],
    ['assistingParticipant', assistingParticipant, 1, 10],
    ['rawParam', rawParam, 0, 0xffffffff],
    ['damageLookupKey24', damageLookupKey24, 0, 0xffffffff],
    ['damageLookupKey2c', damageLookupKey2c, 0, 0xffffffff],
    ['damageCallbackU32At10', damageCallbackU32At10, 0, 0xffffffff],
    ['itemId', itemId, 0, 0xffffffff],
    ['previousItemId', previousItemId, 0, 0xffffffff],
    ['slot', slot, 0, 9],
    ['opaqueU32', opaqueU32, 0, 0xffffffff],
    ['opaqueI32', opaqueI32, -0x80000000, 0x7fffffff],
    ['castNestedBits', castNestedBits, 0, 0xff],
    ['packetRecordCount', packetRecordCount, 0, 1],
    ['showHealthZeroFlag', showHealthZeroFlag, 0, 1],
    ['levelAfter', levelAfter, 1, 20],
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
    castNestedBits = null, damageCallbackF32Available = false,
    damageCallbackF32At18Raw = false,
    damageLookupKey24 = null, damageLookupKey2c = null,
    damageCallbackU32At10 = null,
    dieSourceKey2cMatch = null,
    packetRecordCount = null, showHealthZeroFlag = null, levelAfter = null,
    childEventId = null, limit = null, latestPerParticipant = false,
    endpointReversedPair: endpointReversedPairFilter = false,
    comparisonToEndpoints = null } = options;
  if (endpointReversedPairFilter
      && (prepared.eventKey !== 'inventory_keyframe_interval_difference_candidates'
        || prepared.replayVersion !== '16.19.821.7343'
        || prepared.capabilityStatus !== 'CANDIDATE')) {
    throw new EventQueryError('UNSUPPORTED_FILTER',
      '--endpoint-reversed-pair requires exact 16.19.821.7343 inventory keyframe interval difference candidates.');
  }
  if (comparisonToEndpoints != null
      && (prepared.eventKey !== 'inventory_game_broadcast_keyframe_bracket_candidates'
        || prepared.replayVersion !== '16.19.821.7343'
        || prepared.capabilityStatus !== 'CANDIDATE')) {
    throw new EventQueryError('UNSUPPORTED_FILTER',
      '--comparison-to-endpoints requires exact 16.19.821.7343 inventory game Broadcast keyframe bracket candidates.');
  }
  if (dieSourceKey2cMatch != null
      && (prepared.eventKey
        !== 'hero_death_damage_lookup_key_cooccurrence_candidates'
        || prepared.replayVersion !== '16.19.821.7343'
        || prepared.capabilityStatus !== 'CANDIDATE')) {
    throw new EventQueryError('UNSUPPORTED_FILTER',
      '--die-source-key2c-match requires exact 16.19.821.7343 hero death/damage lookup cooccurrence candidates.');
  }
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
    'inventory_game_broadcast_keyframe_bracket_candidates',
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
      '--item-id and --slot require an exact-821 inventory packet, ward/inventory pair, keyframe interval difference, or game Broadcast bracket candidate event.');
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
  if (castNestedBits != null) prepareCastSpellAnsNestedBits(prepared);
  const damageLookupKeysRequested = damageLookupKey24 != null
    || damageLookupKey2c != null;
  const damagePacketCheck = damageCallbackF32Available || damageLookupKeysRequested
    || damageCallbackU32At10 != null || damageCallbackF32At18Raw;
  if (damageCallbackF32At18Raw) prepareUnitApplyDamageF32At18Raw(prepared);
  if (damageCallbackU32At10 != null) prepareUnitApplyDamageCallbackU32At10(prepared);
  if (damageLookupKeysRequested) prepareUnitApplyDamageLookupKeys(prepared);
  else if (damageCallbackF32Available) prepareUnitApplyDamageCallbackF32(prepared);
  if (packetRecordCount != null) {
    prepareCircularMovementRestrictionRecordCount(prepared);
  }
  if (showHealthZeroFlag != null) prepareShowHealthBarZeroFlag(prepared);
  if (levelAfter != null && (prepared.eventKey
      !== 'level_experience_keyframe_bracket_candidates'
      || prepared.replayVersion !== '16.19.821.7343')) {
    throw new EventQueryError('UNSUPPORTED_FILTER',
      '--level-after requires exact 16.19.821.7343 level/experience bracket candidates.');
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
  let endpointReversedPairInspectedCount = 0;
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
  let castNestedBitsCheckedCount = 0;
  const castNestedBitsPacketPositions = new Set();
  let damageCallbackF32AvailableCount = 0;
  let damageCallbackF32UnavailableCount = 0;
  const damagePacketPositions = new Set();
  const damageShapeFamilies = new Set();
  const damageNativeFloatSourceCounts = Object.fromEntries(
    UNIT_APPLY_DAMAGE_NATIVE_FLOAT_SOURCES_821.map((source) => [source, 0]));
  const damageNativeLookupRelationCounts = Object.fromEntries(
    UNIT_APPLY_DAMAGE_LOOKUP_RELATIONS_821.map((relation) => [relation, 0]));
  const damageNativeU32SourceCounts = Object.fromEntries(
    UNIT_APPLY_DAMAGE_NATIVE_U32_SOURCES_821.map((source) => [source, 0]));
  const damageNativeF32At18SourceCounts = Object.fromEntries(
    UNIT_APPLY_DAMAGE_NATIVE_F32_0X18_SOURCES_821.map((source) => [source, 0]));
  const damageNativeInputHash = damagePacketCheck
    ? crypto.createHash('sha256') : null;
  const circularPacketPositions = new Set();
  const circularShapeCounts = { empty1: 0, record24: 0 };
  const showHealthState = showHealthZeroFlag == null ? null : {
    positions: new Set(), previousChunkIndex: -1, previousBlockOffset: -1,
    observedPayloadCounts: { '4a': 0, '4b': 0 },
    nativeInputHash: crypto.createHash('sha256'),
  };
  let childEventIdUnavailableCount = 0;
  let childEventIdAvailableCount = 0;
  let tripleGroupCount = 0;
  let quadraGroupCount = 0;
  let observedReturnCount = 0;
  let terminalUnobservedCount = 0;
  const associationKeys = new Set();
  const associationPacketPositions = new Set();
  const firstBloodAssistPacketPositions = prepared.eventKey
    === 'first_blood_assist_event_packet_candidates'
    ? new Set(prepared.capabilityResult.excluded_same_length_foreign_packet_refs
      .map((ref) => `${ref.chunk_index}/${ref.decompressed_block_offset}`)) : null;
  const episodePhysicalRefs = new Map();
  const wardPairFrames = new Map();
  const inventoryIntervalState = { pairs: new Map(), frameTimes: new Map(),
    endpoints: new Map(), changedSlotCount: 0 };
  const inventoryGameState = { seenGamePositions: new Set(),
    distinctIntervals: new Set(), recordComparisonCount: 0,
    comparisonCounts: {
      SAME_AS_BOTH_ENDPOINTS: 0, DIFFERS_FROM_EQUAL_ENDPOINTS: 0,
      SAME_AS_PREVIOUS_ENDPOINT: 0, SAME_AS_NEXT_ENDPOINT: 0,
      DIFFERS_FROM_BOTH_ENDPOINTS: 0,
    } };
  const faceRosterPairState = { frames: new Map(), positions: new Set() };
  const damageRosterPairState = {
    previousDamageChunkIndex: -1, previousDamageBlockOffset: -1,
    damagePositions: new Set(), rosterFrame: null,
    rosterRefs: new Map(), rosterPositions: new Map(),
  };
  const lookupRosterPairState = {
    previousDamageChunkIndex: -1, previousDamageBlockOffset: -1,
    damagePositions: new Set(), rosterFrame: null,
    rosterRefs: new Map(), rosterPositions: new Map(),
    relationCounts: {
      EQUAL: 0, RAW_PARAM_IS_LOOKUP_PLUS_0X100: 0, OTHER: 0,
    },
  };
  const lookup2cRosterPairState = {
    previousDamageChunkIndex: -1, previousDamageBlockOffset: -1,
    damagePositions: new Set(), rosterFrame: null,
    rosterRefs: new Map(), rosterPositions: new Map(),
    key24RosterCounts: {
      SAME_ROSTER_KEY: 0, DIFFERENT_ROSTER_KEY: 0, KEY24_NOT_IN_ROSTER: 0,
    },
  };
  const deathDamageLookupState = {
    previousPrimaryChunkIndex: -1, previousPrimaryBlockOffset: -1,
    primaryPositions: new Set(), deathRoutePositions: new Set(),
    damagePositions: new Set(), rosterFrame: null,
    rosterRefs: new Map(), rosterPositions: new Map(),
    deathRoutePacketCount: 0, matchedPacketCount: 0,
    withPacketCount: 0, withoutPacketCount: 0,
    multiplePacketAnchorCount: 0, maxPacketCount: 0,
    dieSourceMatchPacketCount: 0, withDieSourceMatchCount: 0,
    withoutDieSourceMatchCount: 0, dieSourceUnavailableCount: 0,
  };
  const minionBracketExpected = prepared.associationConfig?.minionBracket
    ? await loadMinionBracketExpectedRows(prepared) : null;
  const experienceIntervalExpected = prepared.associationConfig?.experienceInterval
    ? await loadExperienceIntervalExpectedRows(prepared) : null;
  const levelExperienceBracketExpected =
    prepared.associationConfig?.levelExperienceBracket
      ? await loadLevelExperienceBracketExpectedRows(prepared) : null;
  const objectiveBountyTurretPairSourceRows =
    prepared.associationConfig?.objectiveBountyTurretPair
      ? await loadObjectiveBountyTurretPairSourceRows(prepared) : null;
  const inventoryEndpointSnapshots = endpointReversedPairFilter
    || prepared.associationConfig?.inventoryGameBracket
    ? await loadInventoryIntervalEndpointSnapshots(prepared) : null;
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
      if (firstBloodAssistPacketPositions) {
        firstBloodAssistPacketRow(row, prepared, lineNumber,
          firstBloodAssistPacketPositions);
      }
      objectiveBountyClaimedPacketRow(row, prepared, lineNumber,
        associationPacketPositions);
      incrementMinionKillsPacketRow(row, prepared, lineNumber,
        associationPacketPositions);
      faceDirectionRosterPairRow(row, prepared, lineNumber, faceRosterPairState);
      unitApplyDamageRosterKeyRow(row, prepared, lineNumber,
        damageRosterPairState);
      unitApplyDamageLookupRosterKeyRow(row, prepared, lineNumber,
        lookupRosterPairState);
      unitApplyDamageLookup2cRosterKeyRow(row, prepared, lineNumber,
        lookup2cRosterPairState);
      heroDeathDamageLookupKeyCooccurrenceRow(row, prepared, lineNumber,
        deathDamageLookupState);
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
        inventoryIntervalState, minionBracketExpected, experienceIntervalExpected,
        levelExperienceBracketExpected);
      if (objectiveBountyTurretPairSourceRows) {
        objectiveBountyTurretPairSourceRefs(row,
          objectiveBountyTurretPairSourceRows, lineNumber);
      }
      if (prepared.associationConfig?.inventoryGameBracket) {
        inventoryGameBroadcastBracketRow(row, prepared, lineNumber,
          inventoryEndpointSnapshots, inventoryGameState);
      }
      const reversedPairObserved = endpointReversedPairFilter
        ? endpointReversedPair(row, prepared, lineNumber, inventoryEndpointSnapshots)
        : false;
      if (endpointReversedPairFilter) endpointReversedPairInspectedCount += 1;
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
      const params = rawParam == null ? null
        : prepared.eventKey
            === 'hero_death_damage_lookup_key_cooccurrence_candidates'
          ? row.same_time_victim_key24_packet_candidates.map(
            (packet) => packet.raw_param)
        : ['unit_apply_damage_lookup_roster_key_candidates',
          'unit_apply_damage_lookup2c_roster_key_candidates']
          .includes(prepared.eventKey)
          ? [row.raw_param] : rawPacketParams(row, lineNumber);
      const inventoryRecordRow = prepared.eventKey
        === 'inventory_keyframe_interval_difference_candidates'
        ? { records_candidate: row.changed_slots_candidate.map((change) => ({
          slot_candidate: change.slot_candidate,
          item_id_candidate: change.current_item_id_candidate,
        })), record_count: row.changed_slot_count }
        : prepared.associationConfig?.inventoryGameBracket
          ? { records_candidate: row.record_comparisons_candidate.map((record) => ({
            slot_candidate: record.slot_candidate,
            item_id_candidate: record.game_item_id_candidate,
          })), record_count: row.record_count }
        : prepared.eventKey === 'ward_inventory_keyframe_pair_candidates'
          ? { records_candidate: row.inventory_records_candidate,
            record_count: row.inventory_record_count } : row;
      const items = itemId == null ? null
        : prepared.eventKey === 'hero_inventory_set_item_packet_candidates'
          ? packetScalarItemId(row, lineNumber)
          : packetRecordItemIds(inventoryRecordRow, lineNumber,
            ['hero_inventory_broadcast_packet_candidates',
              'ward_inventory_keyframe_pair_candidates',
              'inventory_keyframe_interval_difference_candidates',
              'inventory_game_broadcast_keyframe_bracket_candidates']
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
      const nestedBits = castNestedBits == null ? null
        : castSpellAnsNestedBits(row, prepared, lineNumber,
          castNestedBitsPacketPositions);
      if (castNestedBits != null) castNestedBitsCheckedCount += 1;
      const damageCallbackF32 = damagePacketCheck
        ? unitApplyDamageCallbackF32(row, prepared, lineNumber,
          damagePacketPositions, damageShapeFamilies, damageNativeInputHash,
          damageNativeFloatSourceCounts, damageNativeLookupRelationCounts,
          damageNativeU32SourceCounts, damageNativeF32At18SourceCounts) : null;
      if (damagePacketCheck) {
        if (damageCallbackF32) damageCallbackF32AvailableCount += 1;
        else damageCallbackF32UnavailableCount += 1;
      }
      const circularRecordCount = packetRecordCount == null ? null
        : circularMovementRestrictionRecordCount(row, prepared, lineNumber,
          circularPacketPositions);
      if (packetRecordCount != null) {
        circularShapeCounts[circularRecordCount === 0 ? 'empty1' : 'record24'] += 1;
      }
      const showHealthFlag = showHealthZeroFlag == null ? null
        : showHealthBarZeroFlag(row, prepared, lineNumber, showHealthState);
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
          || (endpointReversedPairFilter && !reversedPairObserved)
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
          || (prepared.associationConfig?.inventoryGameBracket
            && (comparisonToEndpoints != null || (itemId != null && slot != null))
            && !row.record_comparisons_candidate.some((record) =>
              (comparisonToEndpoints == null
                || record.comparison_to_endpoints === comparisonToEndpoints)
              && (itemId == null || record.game_item_id_candidate === itemId)
              && (slot == null || record.slot_candidate === slot)))
          || (itemId != null && slot != null
            && prepared.eventKey !== 'inventory_keyframe_interval_difference_candidates'
            && !prepared.associationConfig?.inventoryGameBracket
            && (prepared.eventKey === 'hero_inventory_set_item_packet_candidates'
              ? (row.item_id_candidate !== itemId || row.slot_candidate !== slot)
              : !inventoryRecordRow.records_candidate.some((record) =>
                record.item_id_candidate === itemId && record.slot_candidate === slot)))
          || (opaqueU32 != null && !opaqueValues.values.includes(opaqueU32))
          || (opaquePair != null && (!pairValue.available
            || pairValue.u32 !== opaquePair.u32 || pairValue.u8 !== opaquePair.u8))
          || (opaqueI32 != null && opaqueI32Field.value !== opaqueI32)
          || (castNestedBits != null && nestedBits !== castNestedBits)
          || (damageCallbackF32Available && !damageCallbackF32)
          || (damageLookupKey24 != null
            && row.native_callback_lookup_key_u32_0x24_candidate
              !== damageLookupKey24)
          || (damageLookupKey2c != null
            && row.native_callback_lookup_key_u32_0x2c_candidate
              !== damageLookupKey2c)
          || (damageCallbackU32At10 != null
            && row.native_callback_u32_0x10_candidate !== damageCallbackU32At10)
          || (damageCallbackF32At18Raw
            && row.native_callback_f32_0x18_source !== 'RAW_READER')
          || (dieSourceKey2cMatch != null
            && row.die_source_key2c_match_status
              !== DIE_SOURCE_KEY2C_MATCH_FILTERS_821[dieSourceKey2cMatch])
          || (packetRecordCount != null && circularRecordCount !== packetRecordCount)
          || (showHealthZeroFlag != null && showHealthFlag !== showHealthZeroFlag)
          || (levelAfter != null && row.level_after_candidate !== levelAfter)
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
  if (packetRecordCount != null
      && !isDeepStrictEqual(circularShapeCounts,
        prepared.capabilityResult.observed_shape_counts)) {
    throw new EventQueryError('EVENT_COUNT_MISMATCH',
      'Circular movement restriction row shapes differ from capability metadata.',
      { observed_shape_counts: circularShapeCounts });
  }
  if (showHealthZeroFlag != null
      && (!isDeepStrictEqual(showHealthState.observedPayloadCounts,
        prepared.capabilityResult.observed_payload_counts)
        || showHealthState.nativeInputHash.digest('hex')
          !== prepared.capabilityResult.native_input_sha256)) {
    throw new EventQueryError('EVENT_COUNT_MISMATCH',
      'ShowHealthBar raw payload counts or ordered native input digest differ from capability metadata.',
      { observed_payload_counts: showHealthState.observedPayloadCounts });
  }
  if (damagePacketCheck
      && (damageCallbackF32AvailableCount
          !== prepared.capabilityResult.callback_f32_available_count
        || damageCallbackF32UnavailableCount
          !== prepared.capabilityResult.callback_f32_unavailable_count
        || damageShapeFamilies.size
          !== prepared.capabilityResult.observed_shape_family_count
        || (prepared.capabilityResult.profile_id
          !== UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V1_ID_821
          && !isDeepStrictEqual(damageNativeFloatSourceCounts,
            prepared.capabilityResult.native_callback_f32_source_counts))
        || ([UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V3_ID_821,
          UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V4_ID_821,
          UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821.id]
          .includes(prepared.capabilityResult.profile_id)
          && !isDeepStrictEqual(damageNativeLookupRelationCounts,
            prepared.capabilityResult.native_callback_lookup_key_0x24_raw_param_relation_counts))
        || ([UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V4_ID_821,
          UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821.id]
          .includes(prepared.capabilityResult.profile_id)
          && !isDeepStrictEqual(damageNativeU32SourceCounts,
            prepared.capabilityResult.native_callback_u32_0x10_source_counts))
        || (prepared.capabilityResult.profile_id
          === UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821.id
          && !isDeepStrictEqual(damageNativeF32At18SourceCounts,
            prepared.capabilityResult.native_callback_f32_0x18_source_counts))
        || damageNativeInputHash.digest('hex')
          !== prepared.capabilityResult.native_input_sha256)) {
    throw new EventQueryError('EVENT_COUNT_MISMATCH',
      'UnitApplyDamage row shapes, float availability, or ordered native input digest differ from capability metadata.',
      { callback_f32_available_count: damageCallbackF32AvailableCount,
        callback_f32_unavailable_count: damageCallbackF32UnavailableCount,
        observed_shape_family_count: damageShapeFamilies.size });
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
  if (prepared.eventKey === 'unit_apply_damage_roster_key_candidates'
      && (damageRosterPairState.damagePositions.size !== scannedCount
        || damageRosterPairState.rosterRefs.size > 10)) {
    throw new EventQueryError('EVENT_COUNT_MISMATCH',
      'UnitApplyDamage roster pair rows have duplicate packet references or an invalid roster.',
      { scanned_count: scannedCount,
        unique_damage_packet_count: damageRosterPairState.damagePositions.size,
        observed_roster_key_count: damageRosterPairState.rosterRefs.size });
  }
  if (prepared.eventKey === 'unit_apply_damage_lookup_roster_key_candidates'
      && (lookupRosterPairState.damagePositions.size !== scannedCount
        || lookupRosterPairState.rosterRefs.size > 10
        || lookupRosterPairState.relationCounts.EQUAL
          !== prepared.capabilityResult.matched_equal_packet_count
        || lookupRosterPairState.relationCounts.RAW_PARAM_IS_LOOKUP_PLUS_0X100
          !== prepared.capabilityResult.matched_alias_0x100_packet_count
        || lookupRosterPairState.relationCounts.OTHER
          !== prepared.capabilityResult.matched_other_relation_packet_count)) {
    throw new EventQueryError('EVENT_COUNT_MISMATCH',
      'UnitApplyDamage lookup roster rows disagree with packet order, roster or relation counts.',
      { scanned_count: scannedCount,
        unique_damage_packet_count: lookupRosterPairState.damagePositions.size,
        observed_roster_key_count: lookupRosterPairState.rosterRefs.size,
        relation_counts: lookupRosterPairState.relationCounts });
  }
  if (prepared.eventKey === 'unit_apply_damage_lookup2c_roster_key_candidates'
      && (lookup2cRosterPairState.damagePositions.size !== scannedCount
        || lookup2cRosterPairState.rosterRefs.size > 10
        || !isDeepStrictEqual(lookup2cRosterPairState.key24RosterCounts,
          prepared.capabilityResult.matched_key24_roster_counts))) {
    throw new EventQueryError('EVENT_COUNT_MISMATCH',
      'UnitApplyDamage +0x2c lookup roster rows disagree with packet order, roster or key relations.',
      { scanned_count: scannedCount,
        unique_damage_packet_count: lookup2cRosterPairState.damagePositions.size,
        observed_roster_key_count: lookup2cRosterPairState.rosterRefs.size,
        key24_roster_counts: lookup2cRosterPairState.key24RosterCounts });
  }
  if (prepared.eventKey
      === 'hero_death_damage_lookup_key_cooccurrence_candidates') {
    const result = prepared.capabilityResult;
    if (deathDamageLookupState.primaryPositions.size !== scannedCount
        || deathDamageLookupState.deathRoutePacketCount
          !== result.verified_hero_death_route_packet_count
        || deathDamageLookupState.matchedPacketCount
          !== result.matched_victim_key24_packet_count
        || deathDamageLookupState.withPacketCount
          !== result.death_anchor_with_victim_key24_packet_count
        || deathDamageLookupState.withoutPacketCount
          !== result.death_anchor_without_victim_key24_packet_count
        || deathDamageLookupState.multiplePacketAnchorCount
          !== result.multiple_victim_key24_packet_anchor_count
        || deathDamageLookupState.maxPacketCount
          !== result.max_victim_key24_packet_count_per_anchor
        || deathDamageLookupState.dieSourceMatchPacketCount
          !== result.matched_die_source_key2c_packet_count
        || deathDamageLookupState.withDieSourceMatchCount
          !== result.death_anchor_with_die_source_key2c_match_count
        || deathDamageLookupState.withoutDieSourceMatchCount
          !== result.death_anchor_without_die_source_key2c_match_count
        || deathDamageLookupState.dieSourceUnavailableCount
          !== result.death_anchor_die_source_unavailable_count) {
      throw new EventQueryError('EVENT_COUNT_MISMATCH',
        'Hero death/damage lookup rows disagree with death anchors, source refs or packet multiplicity.',
        { scanned_count: scannedCount,
          matched_victim_key24_packet_count:
            deathDamageLookupState.matchedPacketCount,
          matched_die_source_key2c_packet_count:
            deathDamageLookupState.dieSourceMatchPacketCount });
    }
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
  if (prepared.associationConfig?.inventoryGameBracket
      && (inventoryGameState.seenGamePositions.size !== scannedCount
        || inventoryGameState.recordComparisonCount
          !== prepared.capabilityResult.record_comparison_count
        || inventoryGameState.distinctIntervals.size
          !== prepared.capabilityResult.distinct_participant_interval_count
        || !isDeepStrictEqual(inventoryGameState.comparisonCounts,
          prepared.capabilityResult.comparison_counts))) {
    throw new EventQueryError('EVENT_COUNT_MISMATCH',
      'Inventory game Broadcast rows disagree with bracket and record counts.');
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
    ...(endpointReversedPairFilter ? {
      endpoint_reversed_pair_inspected_count: endpointReversedPairInspectedCount,
      endpoint_reversed_pair_unavailable_count: 0,
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
    ...(castNestedBits == null ? {} : {
      cast_nested_bits_checked_count: castNestedBitsCheckedCount,
      cast_nested_bits_unavailable_count: 0,
    }),
    ...(damageCallbackF32Available ? {
      damage_callback_f32_available_count: damageCallbackF32AvailableCount,
      damage_callback_f32_unavailable_count: damageCallbackF32UnavailableCount,
      damage_callback_f32_checked_count: scannedCount,
      native_witness_check: 'PERSISTED_METADATA_AND_RAW_BYTES',
    } : {}),
    ...(damageLookupKeysRequested ? {
      damage_lookup_keys_checked_count: scannedCount,
      native_witness_check: 'PERSISTED_METADATA_AND_RAW_BYTES',
    } : {}),
    ...(damageCallbackU32At10 == null ? {} : {
      damage_callback_u32_0x10_checked_count: scannedCount,
      native_witness_check: 'PERSISTED_METADATA_AND_RAW_BYTES',
    }),
    ...(damageCallbackF32At18Raw ? {
      damage_callback_f32_0x18_checked_count: scannedCount,
      native_witness_check: 'PERSISTED_METADATA_AND_RAW_BYTES',
    } : {}),
    ...(packetRecordCount == null ? {} : {
      packet_record_count_checked_count: scannedCount,
      packet_record_count_unavailable_count: 0,
    }),
    ...(showHealthZeroFlag == null ? {} : {
      show_health_zero_flag_checked_count: scannedCount,
      show_health_zero_flag_unavailable_count: 0,
      native_witness_check: 'PERSISTED_METADATA_AND_RAW_BYTES',
    }),
    ...(levelAfter == null ? {} : {
      level_after_checked_count: scannedCount,
      level_after_unavailable_count: 0,
    }),
    ...(childEventId == null ? {} : { child_event_id_unavailable_count: childEventIdUnavailableCount }),
    filters: { from_ms: fromMs, to_ms: toMs, participant_id: participant, limit,
      ...(latestPerParticipant ? { latest_per_participant: true } : {}),
      ...(endpointReversedPairFilter ? { endpoint_reversed_pair: true } : {}),
      ...(comparisonToEndpoints == null ? {}
        : { comparison_to_endpoints: comparisonToEndpoints }),
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
      ...(castNestedBits == null ? {} : { cast_nested_bits: castNestedBits }),
      ...(damageCallbackF32Available ? { damage_callback_f32_available: true } : {}),
      ...(damageLookupKey24 == null ? {}
        : { damage_lookup_key24: damageLookupKey24 }),
      ...(damageLookupKey2c == null ? {}
        : { damage_lookup_key2c: damageLookupKey2c }),
      ...(damageCallbackU32At10 == null ? {}
        : { damage_callback_u32_0x10: damageCallbackU32At10 }),
      ...(damageCallbackF32At18Raw
        ? { damage_callback_f32_0x18_raw: true } : {}),
      ...(dieSourceKey2cMatch == null ? {}
        : { die_source_key2c_match: dieSourceKey2cMatch }),
      ...(packetRecordCount == null ? {} : { packet_record_count: packetRecordCount }),
      ...(showHealthZeroFlag == null ? {} : {
        show_health_zero_flag: showHealthZeroFlag,
      }),
      ...(levelAfter == null ? {} : { level_after: levelAfter }),
      ...(childEventId == null ? {} : { child_event_id: childEventId }) },
    rows_unmodified: true,
  };
}

async function streamBatchEventQuery(prepared, options, emitLine) {
  validateFilters(options);
  if (options.endpointReversedPair
      && prepared.eventKey !== 'inventory_keyframe_interval_difference_candidates') {
    throw new EventQueryError('UNSUPPORTED_FILTER',
      '--endpoint-reversed-pair requires exact 16.19.821.7343 inventory keyframe interval difference candidates.');
  }
  if (options.comparisonToEndpoints != null
      && (prepared.eventKey !== 'inventory_game_broadcast_keyframe_bracket_candidates'
        || prepared.replays.some((replay) => replay.replayVersion !== '16.19.821.7343'))) {
    throw new EventQueryError('UNSUPPORTED_FILTER',
      '--comparison-to-endpoints requires exact 16.19.821.7343 inventory game Broadcast keyframe bracket candidates.');
  }
  if (options.dieSourceKey2cMatch != null
      && (prepared.eventKey
        !== 'hero_death_damage_lookup_key_cooccurrence_candidates'
        || prepared.replays.some((replay) =>
          replay.replayVersion !== '16.19.821.7343'))) {
    throw new EventQueryError('UNSUPPORTED_FILTER',
      '--die-source-key2c-match requires exact 16.19.821.7343 hero death/damage lookup cooccurrence candidates.');
  }
  if (options.endpointReversedPair
      || prepared.eventKey === 'inventory_game_broadcast_keyframe_bracket_candidates') {
    for (const replay of prepared.replays) {
      if (!replay.prepared) continue;
      const source = prepareInventoryIntervalSource(replay.prepared);
      const relative = `${replay.relative}/${source.eventKey}.jsonl`;
      const expected = prepared.outputHashes?.[relative];
      if (!REPLAY_SHA.test(expected) || sha256File(source.inputPath) !== expected) {
        throw new EventQueryError('ARTIFACT_HASH_MISMATCH',
          `Batch manifest SHA-256 differs for ${relative}.`,
          { filename: source.inputPath, relative });
      }
    }
  }
  let scannedCount = 0;
  let matchedCount = 0;
  let emittedCount = 0;
  let selectedCount = 0;
  let latestParticipantUnavailableCount = 0;
  let castNestedBitsCheckedCount = 0;
  let castNestedBitsUnavailableCount = 0;
  let damageCallbackF32CheckedCount = 0;
  let damageCallbackF32AvailableCount = 0;
  let damageCallbackF32UnavailableCount = 0;
  let damageLookupKeysCheckedCount = 0;
  let damageCallbackU32At10CheckedCount = 0;
  let packetRecordCountCheckedCount = 0;
  let showHealthZeroFlagCheckedCount = 0;
  let levelAfterCheckedCount = 0;
  let endpointReversedPairInspectedCount = 0;
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
            'OPAQUE_I32_UNAVAILABLE', 'CAST_NESTED_BITS_UNAVAILABLE',
            'CHILD_EVENT_ID_UNAVAILABLE'].includes(error.code)) {
        throw error;
      }
      replayResults.push({ ...identity, query_status: 'UNAVAILABLE',
        code: error.code, message: error.message, ...error.details });
      if (error.code === 'CAST_NESTED_BITS_UNAVAILABLE') {
        castNestedBitsUnavailableCount += error.details.cast_nested_bits_unavailable_count;
      }
      continue;
    }
    completedCount += 1;
    filters ??= { ...summary.filters, limit: options.limit ?? null };
    scannedCount += summary.scanned_count;
    if (options.castNestedBits != null) {
      castNestedBitsCheckedCount += summary.cast_nested_bits_checked_count;
    }
    if (options.damageCallbackF32Available) {
      damageCallbackF32CheckedCount += summary.damage_callback_f32_checked_count;
      damageCallbackF32AvailableCount += summary.damage_callback_f32_available_count;
      damageCallbackF32UnavailableCount += summary.damage_callback_f32_unavailable_count;
    }
    if (options.damageLookupKey24 != null || options.damageLookupKey2c != null) {
      damageLookupKeysCheckedCount += summary.damage_lookup_keys_checked_count;
    }
    if (options.damageCallbackU32At10 != null) {
      damageCallbackU32At10CheckedCount +=
        summary.damage_callback_u32_0x10_checked_count;
    }
    if (options.packetRecordCount != null) {
      packetRecordCountCheckedCount += summary.packet_record_count_checked_count;
    }
    if (options.showHealthZeroFlag != null) {
      showHealthZeroFlagCheckedCount += summary.show_health_zero_flag_checked_count;
    }
    if (options.levelAfter != null) {
      levelAfterCheckedCount += summary.level_after_checked_count;
    }
    matchedCount += summary.matched_count;
    if (options.latestPerParticipant) {
      selectedCount += summary.selected_count;
      latestParticipantUnavailableCount += summary.latest_participant_unavailable_count;
    }
    if (options.endpointReversedPair) {
      endpointReversedPairInspectedCount += summary.endpoint_reversed_pair_inspected_count;
    }
    replayResults.push({ ...identity, query_status: 'COMPLETE',
      capability_status: summary.capability_status,
      declared_event_count: summary.declared_event_count,
      scanned_count: summary.scanned_count,
      matched_count: summary.matched_count,
      ...(options.castNestedBits == null ? {} : {
        cast_nested_bits_checked_count: summary.cast_nested_bits_checked_count,
        cast_nested_bits_unavailable_count: 0,
      }),
      ...(options.damageCallbackF32Available ? {
        damage_callback_f32_checked_count: summary.damage_callback_f32_checked_count,
        damage_callback_f32_available_count: summary.damage_callback_f32_available_count,
        damage_callback_f32_unavailable_count: summary.damage_callback_f32_unavailable_count,
        native_witness_check: 'PERSISTED_METADATA_AND_RAW_BYTES',
      } : {}),
      ...(options.damageLookupKey24 == null && options.damageLookupKey2c == null
        ? {} : {
          damage_lookup_keys_checked_count: summary.damage_lookup_keys_checked_count,
          native_witness_check: 'PERSISTED_METADATA_AND_RAW_BYTES',
        }),
      ...(options.damageCallbackU32At10 == null ? {} : {
        damage_callback_u32_0x10_checked_count:
          summary.damage_callback_u32_0x10_checked_count,
        native_witness_check: 'PERSISTED_METADATA_AND_RAW_BYTES',
      }),
      ...(options.packetRecordCount == null ? {} : {
        packet_record_count_checked_count:
          summary.packet_record_count_checked_count,
        packet_record_count_unavailable_count: 0,
      }),
      ...(options.showHealthZeroFlag == null ? {} : {
        show_health_zero_flag_checked_count:
          summary.show_health_zero_flag_checked_count,
        show_health_zero_flag_unavailable_count: 0,
        native_witness_check: 'PERSISTED_METADATA_AND_RAW_BYTES',
      }),
      ...(options.levelAfter == null ? {} : {
        level_after_checked_count: summary.level_after_checked_count,
        level_after_unavailable_count: 0,
      }),
      ...(options.latestPerParticipant ? {
        selected_count: summary.selected_count,
        latest_participant_unavailable_count: summary.latest_participant_unavailable_count,
      } : {}),
      ...(options.endpointReversedPair ? {
        endpoint_reversed_pair_inspected_count:
          summary.endpoint_reversed_pair_inspected_count,
        endpoint_reversed_pair_unavailable_count: 0,
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
    ...(options.castNestedBits == null ? {} : {
      cast_nested_bits_checked_count: castNestedBitsCheckedCount,
      cast_nested_bits_unavailable_count: castNestedBitsUnavailableCount,
      cast_nested_bits_unavailable_replay_count:
        replayResults.filter((replay) =>
          replay.code === 'CAST_NESTED_BITS_UNAVAILABLE').length,
    }),
    ...(options.damageCallbackF32Available ? {
      damage_callback_f32_checked_count: damageCallbackF32CheckedCount,
      damage_callback_f32_available_count: damageCallbackF32AvailableCount,
      damage_callback_f32_unavailable_count: damageCallbackF32UnavailableCount,
      damage_callback_f32_unavailable_replay_count:
        prepared.replays.length - completedCount,
      native_witness_check: 'PERSISTED_METADATA_AND_RAW_BYTES',
    } : {}),
    ...(options.damageLookupKey24 == null && options.damageLookupKey2c == null
      ? {} : {
        damage_lookup_keys_checked_count: damageLookupKeysCheckedCount,
        damage_lookup_keys_unavailable_replay_count:
          prepared.replays.length - completedCount,
        native_witness_check: 'PERSISTED_METADATA_AND_RAW_BYTES',
      }),
    ...(options.damageCallbackU32At10 == null ? {} : {
      damage_callback_u32_0x10_checked_count:
        damageCallbackU32At10CheckedCount,
      damage_callback_u32_0x10_unavailable_replay_count:
        prepared.replays.length - completedCount,
      native_witness_check: 'PERSISTED_METADATA_AND_RAW_BYTES',
    }),
    ...(options.packetRecordCount == null ? {} : {
      packet_record_count_checked_count: packetRecordCountCheckedCount,
      packet_record_count_unavailable_replay_count:
        prepared.replays.length - completedCount,
    }),
    ...(options.showHealthZeroFlag == null ? {} : {
      show_health_zero_flag_checked_count: showHealthZeroFlagCheckedCount,
      show_health_zero_flag_unavailable_replay_count:
        prepared.replays.length - completedCount,
      native_witness_check: 'PERSISTED_METADATA_AND_RAW_BYTES',
    }),
    ...(options.levelAfter == null ? {} : {
      level_after_checked_count: levelAfterCheckedCount,
      level_after_unavailable_replay_count:
        prepared.replays.length - completedCount,
    }),
    ...(options.latestPerParticipant ? {
      selected_count: selectedCount,
      latest_participant_unavailable_count: latestParticipantUnavailableCount,
    } : {}),
    ...(options.endpointReversedPair ? {
      endpoint_reversed_pair_inspected_count: endpointReversedPairInspectedCount,
      endpoint_reversed_pair_unavailable_replay_count:
        prepared.replays.length - completedCount,
    } : {}),
    emitted_count: emittedCount, filters,
    replay_results: replayResults, rows_unmodified: true };
}

module.exports = { EventQueryError, prepareEventQuery, prepareBatchEventQuery,
  streamEventQuery, streamBatchEventQuery };

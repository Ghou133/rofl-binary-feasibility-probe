'use strict';

const { SWEEPER_DECODER_CAPABILITY_PROFILES } = require('../sweeper_capability');
const {
  DEEP_RECOVERY_SEMANTIC_PROFILES,
} = require('../deep_recovery_semantic_profiles_16_16');
const {
  GAMEPLAY_ROUTE_TAIL_PROFILES,
} = require('./gameplay_route_tail_16_16');
const {
  HERO_REINCARNATE_ALIVE_PROFILE,
} = require('./hero_reincarnate_alive_16_16');
const {
  SHIELD_ABSORBED_PROFILE,
  shieldAbsorbedFromFullyConsumedRow,
} = require('./shield_absorbed_16_16');

const REPLAY_VERSION = '16.16.805.0442';
const RUNTIME_IMAGE_SHA256 = '0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55';

const CONTAINER_PROFILE = Object.freeze({
  replay_version: REPLAY_VERSION,
  status: 'VERIFIED_DIRECT',
  header: 'VERIFIED_DIRECT',
  chunks: 'VERIFIED_DIRECT',
  zstd: 'VERIFIED_DIRECT',
  block_framing: 'VERIFIED_DIRECT',
});

const LEVEL_AFTER_BY_FIELD_10 = Object.freeze({
  2: 15,
  18: 16,
  34: 13,
  50: 14,
  66: 11,
  82: 12,
  98: 9,
  114: 10,
  130: 7,
  146: 8,
  162: 5,
  178: 6,
  194: 3,
  197: 19,
  210: 4,
  213: 20,
  229: 17,
  242: 2,
  245: 18,
});

const LEVEL_MAPPING_COUNTS = Object.freeze({
  2: 79,
  18: 59,
  34: 123,
  50: 101,
  66: 153,
  82: 140,
  98: 171,
  114: 166,
  130: 177,
  146: 175,
  162: 178,
  178: 179,
  194: 179,
  197: 5,
  210: 180,
  213: 3,
  229: 33,
  242: 180,
  245: 14,
});

function routeView(profile, replayBlockPacketId, runtimeTypeName) {
  return Object.freeze({
    ...profile,
    replay_block_packet_id: replayBlockPacketId,
    client_opcode: replayBlockPacketId,
    runtime_type_name: runtimeTypeName,
  });
}

function gameplayRouteView(profile) {
  return Object.freeze({
    ...profile,
    capability: profile.event_type,
    status: 'SEMANTIC_VERIFIED_DIRECT',
    structure_status: 'STRUCTURE_VERIFIED',
    semantic_status: 'SEMANTIC_VERIFIED_DIRECT_BOUNDED',
    enabled: true,
    replay_block_packet_id: profile.packet_id,
    client_opcode: profile.packet_id,
  });
}

const DEEP_BUFF_PROFILE = DEEP_RECOVERY_SEMANTIC_PROFILES.buff;
const DEEP_PROTECTION_PROFILE = DEEP_RECOVERY_SEMANTIC_PROFILES.protection;

const SEMANTIC_PROFILE_REGISTRY = Object.freeze({
  shield_absorbed: SHIELD_ABSORBED_PROFILE,
  participant_mapping: Object.freeze({
    id: 'rofl-16.16.805.0442-champion-network-id-v1',
    capability: 'Participant / entity mapping',
    replay_version: REPLAY_VERSION,
    status: 'SEMANTIC_VERIFIED_DIRECT',
    enabled: true,
    champion_network_id_min: 0x400000ae,
    champion_network_id_max: 0x400000b7,
    participant_formula: 'network_id - 0x400000ad',
    validation_artifact: 'artifacts/multi_build_rofl_support_v1/hero_path_validation/hero_path_validation_summary.json',
  }),
  hero_path: Object.freeze({
    id: 'rofl-16.16.805.0442-path-packet-unicorn-v1',
    capability: 'Hero Path',
    replay_version: REPLAY_VERSION,
    status: 'SEMANTIC_VERIFIED_DERIVED',
    structure_status: 'STRUCTURE_VERIFIED',
    semantic_status: 'SEMANTIC_VERIFIED_DERIVED',
    enabled: true,
    replay_block_packet_id: 0x00f6,
    client_opcode: 0x00f6,
    constructor_rva: 0x00ead060,
    opcode_store_rva: 0x00ead06c,
    object_vtable_rva: 0x01b13988,
    vtable_rva: 0x01b13998,
    deserialize_rva: 0x0102a170,
    object_size: 0x2c,
    payload_pointer_offset: 0x18,
    payload_size_offset: 0x20,
    shared_decoder: 'historical-compatible-path-plaintext-v1',
    coordinate_transform: Object.freeze({
      x: 'signed_u16(encoded_x) * 2 + 7358',
      z: 'signed_u16(encoded_y) * 2 + 7412',
      status: 'VERIFIED_CURRENT_CALIBRATION',
    }),
    validation_artifact: 'artifacts/multi_build_rofl_support_v1/hero_path_validation/hero_path_validation_summary.json',
    evidence: 'EXACT_RUNTIME_FULL_CONSUME_PLUS_DETAILS_POSITION_ANCHORS',
  }),
  level_transition: Object.freeze({
    id: 'rofl-16.16.805.0442-level-transition-unicorn-v1',
    capability: 'LevelTransition',
    replay_version: REPLAY_VERSION,
    status: 'SEMANTIC_VERIFIED_DERIVED',
    structure_status: 'STRUCTURE_VERIFIED',
    transition_status: 'SEMANTIC_VERIFIED_DIRECT',
    level_after_status: 'SEMANTIC_VERIFIED_DERIVED_BUILD_BOUND',
    enabled: true,
    replay_block_packet_id: 0x0314,
    client_opcode: 0x0314,
    rejected_candidate_replay_block_packet_id: 0x01e8,
    constructor_rva: 0x00e7de60,
    object_vtable_rva: 0x01b10668,
    vtable_rva: 0x01b10678,
    deserialize_rva: 0x00ef8520,
    object_size: 0x14,
    raw_field_10_offset: 0x10,
    raw_field_11_offset: 0x11,
    level_after_mapping: LEVEL_AFTER_BY_FIELD_10,
    level_mapping_counts: LEVEL_MAPPING_COUNTS,
    validation_artifact: 'artifacts/multi_build_rofl_support_v1/level_transition_validation/level_transition_validation_summary.json',
    evidence: 'EXACT_RUNTIME_FULL_CONSUME_PLUS_DETAILS_LEVEL_UP_ANCHORS',
  }),
  ward_spawn: Object.freeze({
    id: 'rofl-16.16.805.0442-ward-spawn-unicorn-v1',
    capability: 'WardSpawn',
    replay_version: REPLAY_VERSION,
    status: 'SEMANTIC_VERIFIED_DERIVED',
    structure_status: 'STRUCTURE_VERIFIED',
    semantic_status: 'SEMANTIC_VERIFIED_DERIVED',
    lifecycle_status: 'SEMANTIC_PARTIAL_DERIVED',
    enabled: true,
    replay_block_packet_id: 0x049a,
    client_opcode: 0x049a,
    constructor_rva: 0x00eabb20,
    opcode_store_rva: 0x00eabb29,
    factory_rva: 0x00ed97b0,
    factory_jump_table_rva: 0x00eea1bc,
    factory_case_rva: 0x00ee9116,
    factory_constructor_callsite_rva: 0x00ee9128,
    object_vtable_rva: 0x01b14570,
    vtable_rva: 0x01b14570,
    deserialize_rva: 0x01025d50,
    rejected_deserialize_candidate_rva: 0x00fc7770,
    object_size: 0x90,
    codec_singleton_pointer_rva: 0x01ee9d08,
    codec_singleton_enable_offset: 0x70,
    raw_fields: Object.freeze({
      position_x: Object.freeze({ offset: 0x10, type: 'f32', selection: 'last_size_4_write' }),
      position_height: Object.freeze({ offset: 0x14, type: 'f32', selection: 'last_size_4_write' }),
      position_y: Object.freeze({ offset: 0x18, type: 'f32', selection: 'last_size_4_write' }),
      owner_network_id: Object.freeze({ offset: 0x1c, type: 'u32', selection: 'first_size_4_write' }),
      generic_name: Object.freeze({ pointer_offset: 0x48, length_offset: 0x50 }),
      alternate_position: Object.freeze({ x_offset: 0x5c, height_offset: 0x60, y_offset: 0x64 }),
      entity_network_id: Object.freeze({ offset: 0x70, type: 'u32', selection: 'first_size_4_write' }),
      entity_name: Object.freeze({ pointer_offset: 0x78, length_offset: 0x80 }),
    }),
    participant_mapping: 'owner_network_id - 0x400000ad; exact Replay tail team map',
    classification: Object.freeze({
      player_active_ward: 'known direct Ward name + champion owner + plausible direct position',
      special_or_map: 'retained and never promoted to player Ward',
    }),
    validation_artifact: 'artifacts/16_16_ward_semantic_recovery_v1/runtime/ward_validation_summary.json',
    evidence: 'EXACT_FACTORY_VTABLE_RUNTIME_FULL_CONSUME_PLUS_DIRECT_NAMES_OWNER_POSITION',
    field_evidence: Object.freeze({
      spawn_time: 'VERIFIED_DIRECT',
      position: 'VERIFIED_DIRECT',
      owner_entity: 'VERIFIED_DIRECT',
      entity_network_id: 'VERIFIED_DIRECT',
      participant: 'VERIFIED_DERIVED_BUILD_BOUND',
      team: 'VERIFIED_DERIVED_REPLAY_TAIL_PARTICIPANT_MAP',
      ward_type: 'VERIFIED_DERIVED_FROM_DIRECT_NAMES',
      lifecycle_end: 'PARTIAL_DERIVED_FROM_DIRECT_CORPSE_EVENT',
      end_reason: 'UNKNOWN',
    }),
  }),
  hero_damage: Object.freeze({
    id: 'rofl-16.16.805.0442-unit-apply-damage-unicorn-v1',
    capability: 'Hero Damage',
    replay_version: REPLAY_VERSION,
    status: 'SEMANTIC_VERIFIED_DIRECT',
    structure_status: 'STRUCTURE_VERIFIED',
    semantic_status: 'SEMANTIC_VERIFIED_DIRECT',
    enabled: true,
    replay_block_packet_id: 0x017f,
    client_opcode: 0x017f,
    runtime_type_name: 'PKT_UnitApplyDamage_s',
    factory_case_rva: 0x00edf117,
    constructor_rva: 0x00eac750,
    vtable_rva: 0x01b109b8,
    deserialize_rva: 0x00f20f20,
    object_size: 0x34,
    runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    profile_artifact: 'artifacts/hero_combat_state_v2/emulation/profiles/packet_017f.json',
    validation_artifact: 'artifacts/hero_combat_state_v2/damage/damage_16_16_anchor_validation.json',
    full_decode_artifact: 'artifacts/hero_combat_state_v2/emulation/packet_017f_latest_four_summary.json',
    damage_type_by_code: Object.freeze({ 0: 'physical', 1: 'magic', 2: 'true' }),
    field_evidence: Object.freeze({
      source_network_id: 'VERIFIED_DIRECT_FIELD_10',
      target_network_id: 'VERIFIED_DIRECT_FIELD_14',
      amount: 'VERIFIED_DIRECT_FIELD_24_STAGE_UNKNOWN',
      damage_type: 'VERIFIED_DIRECT_FIELD_28',
      pre_mitigation_amount: 'UNAVAILABLE',
      post_mitigation_amount: 'UNAVAILABLE',
      effective_damage: 'UNAVAILABLE',
      spell_item_rune_passive_attribution: 'UNAVAILABLE',
    }),
    evidence: 'EXACT_RTTI_REGISTRATION_FACTORY_VTABLE_DESERIALIZER_FULL_CONSUME_PLUS_DETAILS_ANCHORS',
    known_limits: Object.freeze([
      'The recorded amount field is direct; its pre/post-mitigation/effective-HP-loss stage is unknown.',
      'Unidentified numeric protocol fields are preserved without semantic promotion.',
    ]),
  }),
  hero_death: Object.freeze({
    id: 'rofl-16.16.805.0442-hero-death-unicorn-v2',
    capability: 'Hero Death',
    replay_version: REPLAY_VERSION,
    status: 'SEMANTIC_VERIFIED_DIRECT',
    enabled: true,
    replay_block_packet_id: 0x0112,
    stream_tag: 1,
    stream: 'game_chunk',
    runtime_type_name: 'PKT_NPC_Hero_Die_s',
    runtime_factory: Object.freeze({
      constructor_rva: 0x00e7da60,
      vtable_rva: 0x01b10810,
      deserializer_rva: 0x00ef7800,
      object_size: 0x5c,
    }),
    runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    profile_artifact:
      'artifacts/full_semantic_baseline_v1/runtime_candidates/packet_0112_static_profile.json',
    profile_sha256: 'e8bcf9530d84c0aa4335eb05eb4c77571fa87e4bf3d8d5933c2140979b268935',
    killer_storage_field: Object.freeze({
      object_offset: 0x18,
      decoded_field: 'unknown_u32_0x18',
      helper_rva: 0x00e639c0,
      lookup_table_rva: 0x01b0fc50,
      lookup_table_sha256:
        'ae15d606869d66dc47309b26cb489e01bf841e9dd57d540683e2dc7f5e394588',
      status: 'VERIFIED_DIRECT_AFTER_EXACT_HELPER_INVERSE',
    }),
    participant_formula: '(raw_param & 0xff) - 0xad',
    field_semantics: Object.freeze({
      event_occurrence: 'VERIFIED_DIRECT_ROUTE',
      replay_time_ms: 'VERIFIED_DIRECT_PACKET_TIMESTAMP',
      victim_participant_id: 'VERIFIED_DERIVED_EXACT_BUILD_RAW_PARAM_LOW_BYTE',
      raw_param: 'VERIFIED_DIRECT_UPPER_BYTES_UNKNOWN',
      killer_network_id: 'VERIFIED_DIRECT_AFTER_EXACT_RUNTIME_HELPER_INVERSE',
      killer_participant_id: 'VERIFIED_DERIVED_EXACT_BUILD_NETWORK_ID',
      assists: 'UNAVAILABLE_WITH_EXPLICIT_NEGATIVE_DIFFERENTIAL',
      respawn_inner_fields: 'UNAVAILABLE_OR_UNKNOWN',
    }),
    evidence:
      'EXACT_RTTI_REGISTRATION_FACTORY_VTABLE_DESERIALIZER_301_FULL_CONSUME_PLUS_301_DETAILS_FIELD_DIFFERENTIAL',
    validation_artifact:
      'artifacts/full_semantic_baseline_v1/runtime_candidates/packet_0112_p0_semantic_differential_16_16.json',
    route_validation_artifact:
      'artifacts/hero_combat_state_v2/death/death_16_16_route_anchor_validation.json',
    runtime_artifact:
      'artifacts/full_semantic_baseline_v1/runtime_candidates/buff_spell_item_runtime_candidates_16_16.json',
    known_limits: Object.freeze([
      'The full raw_param is retained because upper-byte variants are observed and not semantically named.',
      'Killer is published only after the exact-build helper inverse; raw storage is retained.',
      'Assists, kill credit, respawn time, and all other inner-payload semantics remain unavailable or unknown.',
      'The assist surface has explicit negative evidence; zero-valued fields must not be treated as an empty assist list.',
      'This is a hero-only route validation and does not establish NPC or objective death semantics.',
    ]),
  }),
  hero_scoreboard_state: Object.freeze({
    id: 'rofl-16.16.805.0442-hero-stats-scoreboard-unicorn-v1',
    capability: 'Hero cumulative scoreboard state',
    replay_version: REPLAY_VERSION,
    status: 'SEMANTIC_VERIFIED_DIRECT',
    structure_status: 'STRUCTURE_VERIFIED',
    semantic_status: 'SEMANTIC_VERIFIED_DIRECT',
    enabled: true,
    replay_block_packet_id: 0x010c,
    client_opcode: 0x010c,
    stream_tag: 2,
    stream: 'keyframe',
    runtime_type_name: 'PKT_S2C_HeroStats_s',
    factory_case_rva: 0x00edd8e7,
    constructor_rva: 0x00e8cf30,
    vtable_rva: 0x01b11128,
    deserialize_rva: 0x00f0a220,
    object_size: 0x28,
    runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    profile_artifact: 'artifacts/hero_combat_state_v2/emulation/profiles/packet_010c.json',
    profile_sha256: 'e00e4766a032a5ebd3c5caa4bd030e2ed1256cf59ff63d8f3e9aeef286e523ef',
    validation_artifact:
      'artifacts/full_semantic_baseline_v1/hero_stats/hero_stats_scoreboard_validation_16_16.json',
    blob_length: 1476,
    blob_fields: Object.freeze({
      experience_points_raw: Object.freeze({
        offset: 0x28,
        type: 'f32',
        status: 'VERIFIED_DIRECT',
        validation_relation: 'Math.floor(raw) === DETAILS participantFrame.xp',
      }),
      total_gold_candidate: Object.freeze({
        offset: 0x38,
        type: 'f32',
        status: 'CANDIDATE',
        validation_relation: 'Math.floor(raw) matched 1389/1390 safe P0 frame anchors',
      }),
      lane_minions_killed: Object.freeze({
        offset: 0x3c,
        type: 'f32',
        status: 'VERIFIED_DIRECT',
        validation_relation: 'raw === DETAILS participantFrame.minionsKilled',
      }),
      jungle_minions_killed_candidate: Object.freeze({
        offset: 0x40,
        type: 'f32',
        status: 'CANDIDATE',
        validation_relation: 'high-correlation only; float-boundary ambiguity retained',
      }),
    }),
    evidence:
      'EXACT_RTTI_REGISTRATION_FACTORY_VTABLE_DESERIALIZER_FULL_CONSUME_PLUS_1390_DETAILS_FRAME_ANCHORS',
    known_limits: Object.freeze([
      'This route is a cumulative scoreboard keyframe, not current combat-state evidence.',
      'Only raw experience points and lane minions killed are semantically published.',
      'Total gold and jungle minions killed remain CANDIDATE and are retained only in protocol evidence.',
      'All unidentified blob bytes remain UNKNOWN and are retained in the decoded row.',
    ]),
  }),
  hero_death_timer: DEEP_RECOVERY_SEMANTIC_PROFILES.hero_death_timer,
  cast_spell: DEEP_RECOVERY_SEMANTIC_PROFILES.cast_spell,
  buff: DEEP_BUFF_PROFILE,
  buff_add: routeView(DEEP_BUFF_PROFILE, 0x0326, 'PKT_NPC_BuffAdd2_s'),
  buff_remove: routeView(DEEP_BUFF_PROFILE, 0x045b, 'PKT_NPC_BuffRemove2_s'),
  buff_update_count: routeView(DEEP_BUFF_PROFILE, 0x0123, 'PKT_NPC_BuffUpdateCount_s'),
  buff_update_counter: routeView(
    DEEP_BUFF_PROFILE, 0x041f, 'PKT_NPC_BuffUpdateNumCounter_s',
  ),
  buff_replace: routeView(DEEP_BUFF_PROFILE, 0x043c, 'PKT_NPC_BuffReplace_s'),
  protection: DEEP_PROTECTION_PROFILE,
  heal_reported: routeView(DEEP_PROTECTION_PROFILE, 0x0371, 'PKT_OnEvent_s'),
  shield_generated: routeView(DEEP_PROTECTION_PROFILE, 0x0371, 'PKT_OnEvent_s'),
  item_state: DEEP_RECOVERY_SEMANTIC_PROFILES.item_state,
  item_state_broadcast: routeView(
    DEEP_RECOVERY_SEMANTIC_PROFILES.item_state,
    0x0311,
    'PKT_S2C_SetInventory_Broadcast_s',
  ),
  item_state_map_view: routeView(
    DEEP_RECOVERY_SEMANTIC_PROFILES.item_state,
    0x02ea,
    'PKT_S2C_SetInventory_MapView_s',
  ),
  item_state_special_slot: routeView(
    DEEP_RECOVERY_SEMANTIC_PROFILES.item_state,
    0x006c,
    'PKT_SetItem_s',
  ),
  item_swap: DEEP_RECOVERY_SEMANTIC_PROFILES.item_swap,
  item_substitution_map: DEEP_RECOVERY_SEMANTIC_PROFILES.item_substitution_map,
  support_quest_item_stage: DEEP_RECOVERY_SEMANTIC_PROFILES.support_quest_item_stage,
  ability_cooldown_broadcast: gameplayRouteView(GAMEPLAY_ROUTE_TAIL_PROFILES['0x00b8']),
  instant_stop_attack: gameplayRouteView(GAMEPLAY_ROUTE_TAIL_PROFILES['0x00e4']),
  face_direction_vector: gameplayRouteView(GAMEPLAY_ROUTE_TAIL_PROFILES['0x01ab']),
  basic_attack_position_minion: gameplayRouteView(GAMEPLAY_ROUTE_TAIL_PROFILES['0x01b5']),
  wall_tracking_component_cache_snapshot:
    gameplayRouteView(GAMEPLAY_ROUTE_TAIL_PROFILES['0x0298']),
  missile_movement_complete_count:
    gameplayRouteView(GAMEPLAY_ROUTE_TAIL_PROFILES['0x03d4']),
  hero_reincarnate_alive: gameplayRouteView(HERO_REINCARNATE_ALIVE_PROFILE),
  ...SWEEPER_DECODER_CAPABILITY_PROFILES,
});

function semanticProfileFor(capability, replayVersion) {
  if (replayVersion !== REPLAY_VERSION) {
    return { status: 'UNSUPPORTED_VERSION', profile: null, candidate: null };
  }
  const candidate = SEMANTIC_PROFILE_REGISTRY[capability] || null;
  if (!candidate) return { status: 'UNAVAILABLE', profile: null, candidate: null };
  return {
    status: candidate.status,
    profile: candidate.enabled ? candidate : null,
    candidate,
  };
}

function participantIdFromChampionNetworkId(networkId) {
  if (!Number.isInteger(networkId)
      || networkId < 0x400000ae || networkId > 0x400000b7) return null;
  return networkId - 0x400000ad;
}

function levelMapping(rawField10, replayVersion) {
  if (replayVersion !== REPLAY_VERSION) {
    return {
      level_before: null,
      level_after: null,
      evidence: 'UNSUPPORTED_VERSION',
    };
  }
  if (!Number.isInteger(rawField10)
      || !Object.hasOwn(LEVEL_AFTER_BY_FIELD_10, rawField10)) {
    return {
      level_before: null,
      level_after: null,
      evidence: 'UNAVAILABLE',
    };
  }
  const levelAfter = LEVEL_AFTER_BY_FIELD_10[rawField10];
  return {
    level_before: levelAfter - 1,
    level_after: levelAfter,
    evidence: 'VERIFIED_DERIVED',
    qualification: `PATCH_BOUND_TO_${REPLAY_VERSION}`,
  };
}

module.exports = {
  REPLAY_VERSION,
  RUNTIME_IMAGE_SHA256,
  CONTAINER_PROFILE,
  LEVEL_AFTER_BY_FIELD_10,
  LEVEL_MAPPING_COUNTS,
  SEMANTIC_PROFILE_REGISTRY,
  participantIdFromChampionNetworkId,
  levelMapping,
  semanticProfileFor,
  shieldAbsorbedFromFullyConsumedRow,
};

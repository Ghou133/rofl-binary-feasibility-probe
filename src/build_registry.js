'use strict';

const fs = require('node:fs');
const path = require('node:path');

const oldDecoder = require('./decoders/rofl_16_15_801_3452');
const newDecoder = require('./decoders/rofl_16_16_805_0442');
const decoder1619 = require('./decoders/rofl_16_19_820_7193');
const decoder1619821 = require('./decoders/rofl_16_19_821_7343');
const heroStatsCandidate1619821 =
  require('./decoders/rofl_16_19_821_hero_stats_candidate');
const levelCandidate1619821 = require('./decoders/rofl_16_19_821_level_candidate');
const respawnCandidate1619821 = require('./decoders/rofl_16_19_821_respawn_candidate');
const deathTimerCandidate1619821 =
  require('./decoders/rofl_16_19_821_death_timer_candidate');
const auxiliaryCountsCandidate1619821 =
  require('./decoders/rofl_16_19_821_aux_counts_candidate');
const floatStatsCandidate1619821 =
  require('./decoders/rofl_16_19_821_float_stats_candidate');
const killStatsCandidate1619821 =
  require('./decoders/rofl_16_19_821_kill_stats_candidate');
const assistCandidate1619821 =
  require('./decoders/rofl_16_19_821_assist_candidate');
const inventoryPacketCandidate1619821 =
  require('./decoders/rofl_16_19_821_inventory_packet_candidate');
const inventoryBroadcastPacketCandidate1619821 =
  require('./decoders/rofl_16_19_821_inventory_broadcast_packet_candidate');
const inventorySetItemPacketCandidate1619821 =
  require('./decoders/rofl_16_19_821_inventory_set_item_packet_candidate');
const paramsHealPacketCandidate1619821 =
  require('./decoders/rofl_16_19_821_params_heal_packet_candidate');
const shieldingParamsPacketPairCandidate1619821 =
  require('./decoders/rofl_16_19_821_shielding_params_packet_pair_candidate');
const stealthEventPacketCandidate1619821 =
  require('./decoders/rofl_16_19_821_stealth_event_packet_candidate');
const championDieEventPacketCandidate1619821 =
  require('./decoders/rofl_16_19_821_champion_die_event_packet_candidate');
const championKillEventPacketCandidate1619821 =
  require('./decoders/rofl_16_19_821_champion_kill_event_packet_candidate');
const championMultipleKillEventPacketCandidate1619821 =
  require('./decoders/rofl_16_19_821_champion_multiple_kill_event_packet_candidate');
const championDoubleKillEventPacketCandidate1619821 =
  require('./decoders/rofl_16_19_821_champion_double_kill_event_packet_candidate');
const championTripleQuadraEventPacketCandidate1619821 =
  require('./decoders/rofl_16_19_821_champion_triple_quadra_event_packet_candidate');
const onShutdownEventPacketCandidate1619821 =
  require('./decoders/rofl_16_19_821_on_shutdown_event_packet_candidate');
const resurrectEventPacketCandidate1619821 =
  require('./decoders/rofl_16_19_821_resurrect_event_packet_candidate');
const turretPlateEventPacketCandidate1619821 =
  require('./decoders/rofl_16_19_821_turret_plate_event_packet_candidate');
const castSpellAnsCandidate1619821 =
  require('./decoders/rofl_16_19_821_cast_spell_ans_packet_candidate');
const buffRemovePacketCandidate1619821 =
  require('./decoders/rofl_16_19_821_buff_remove_packet_candidate');
const buffAddPacketCandidate1619821 =
  require('./decoders/rofl_16_19_821_buff_add_packet_candidate');
const buffUpdateNumCounterPacketCandidate1619821 =
  require('./decoders/rofl_16_19_821_buff_update_num_counter_packet_candidate');
const buffUpdateCountPacketCandidate1619821 =
  require('./decoders/rofl_16_19_821_buff_update_count_packet_candidate');
const buffReplacePacketCandidate1619821 =
  require('./decoders/rofl_16_19_821_buff_replace_packet_candidate');
const setSpellTimerFromBuffPacketCandidate1619821 =
  require('./decoders/rofl_16_19_821_set_spell_timer_from_buff_packet_candidate');
const setSpellLevelPacketCandidate1619821 =
  require('./decoders/rofl_16_19_821_set_spell_level_packet_candidate');
const directInputTurnPacketCandidate1619821 =
  require('./decoders/rofl_16_19_821_direct_input_turn_packet_candidate');
const setMovementDriverPacketCandidate1619821 =
  require('./decoders/rofl_16_19_821_set_movement_driver_packet_candidate');
const damageFloatCandidate1619821 =
  require('./decoders/rofl_16_19_821_damage_float_candidate');
const timeStatsCandidate1619821 =
  require('./decoders/rofl_16_19_821_time_stats_candidate');
const healStatsCandidate1619821 =
  require('./decoders/rofl_16_19_821_heal_stats_candidate');
const epicCcCandidate1619821 =
  require('./decoders/rofl_16_19_821_epic_cc_candidate');
const heroStatsCandidate1619 = require('./decoders/rofl_16_19_hero_stats_candidate');
const buffRemoveCandidate1619 = require('./decoders/rofl_16_19_buff_remove_candidate');
const buffAddCandidate1619 = require('./decoders/rofl_16_19_buff_add_candidate');
const { SWEEPER_CAPABILITY_CONTRACT_ID } = require('./sweeper_capability');
const { PATH_PACKET_PROFILE: OLD_PATH_PROFILE } = require('./path_pipeline_v2');
const { WARD_SPAWN_PROFILE: OLD_WARD_PROFILE } = require('./ward_pipeline_v2');
const { parseReplayFile } = require('./rofl');

const ROLLING_COMPATIBILITY_WINDOW = 3;
const SUPPORT_LEVELS = Object.freeze([
  'BLOCKED',
  'CORE_READY',
  'INFERENCE_READY',
  'VISION_READY',
  'COMBAT_READY',
  'COMBAT_AND_SCOREBOARD_READY',
  'DEEP_SEMANTIC_READY',
  'FULL_PLATFORM_READY',
]);

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

const BUILD_PROFILES = deepFreeze({
  '16.15.801.3452': {
    schema_version: 1,
    game_version: '16.15.801.3452',
    patch: '16.15',
    support_level: 'FULL_PLATFORM_READY',
    release_status: 'SUPPORTED',
    downstream_release_gate: 'SUPPORTED_LEGACY_FULL_PLATFORM',
    format_profile: {
      implementation: 'src/rofl.js',
      status: 'FORMAT_VERIFIED',
    },
    runtime_profile: {
      image_sha256: oldDecoder.DAMAGE_PROFILE.runtime_image_sha256,
      base_packet_vtable_rva: 0x01a239a0,
      base_packet_serialize_rva: 0x01254af0,
      base_packet_decode_rva: 0x012370a0,
    },
    packet_routes: {
      hero_path: OLD_PATH_PROFILE.replay_packet_id,
      level_transition: oldDecoder.LEVEL_UP_PROFILE.replay_block_packet_id,
      ward_spawn: OLD_WARD_PROFILE.replay_packet_id,
      hero_damage: oldDecoder.DAMAGE_PROFILE.replay_block_packet_id,
      hero_death: oldDecoder.PROFILE.replay_block_packet_id,
      cast_spell: oldDecoder.CAST_SPELL_PROFILE.replay_block_packet_id,
      buff_add: oldDecoder.BUFF_PROFILES.add.replay_block_packet_id,
      buff_remove: oldDecoder.BUFF_PROFILES.remove.replay_block_packet_id,
      buff_update_count: oldDecoder.BUFF_PROFILES.update_count.replay_block_packet_id,
      protection: oldDecoder.ON_EVENT_PROFILE.replay_block_packet_id,
      shield_damage: oldDecoder.SHIELD_DAMAGE_PROFILE.replay_block_packet_id,
    },
    decoder_profile: {
      hero_path: OLD_PATH_PROFILE,
      level_transition: oldDecoder.LEVEL_UP_PROFILE,
      ward_spawn: OLD_WARD_PROFILE,
      hero_damage: oldDecoder.DAMAGE_PROFILE,
      hero_death: oldDecoder.PROFILE,
      cast_spell: oldDecoder.CAST_SPELL_PROFILE,
      buff: oldDecoder.BUFF_PROFILES,
      protection: oldDecoder.ON_EVENT_PROFILE,
      shield_damage: oldDecoder.SHIELD_DAMAGE_PROFILE,
    },
    field_semantics: {
      participant_mapping: 'SEMANTIC_VERIFIED_DIRECT',
      hero_path: 'SEMANTIC_VERIFIED_DERIVED',
      level_transition: 'SEMANTIC_VERIFIED_DIRECT',
      level_after: 'SEMANTIC_VERIFIED_DERIVED_BUILD_BOUND',
    },
    semantic_mappings: {
      level_after: 'src/level_transition.js#LEVEL_AFTER_BY_FIELD_10',
      coordinates: OLD_PATH_PROFILE.coordinate_transform,
    },
    verified_capabilities: [
      'participant_mapping', 'hero_path', 'level_transition', 'level_after',
      'ward_spawn', 'hero_damage', 'hero_death', 'cast_spell', 'buff', 'protection',
    ],
    candidate_capabilities: [],
    unsupported_capabilities: [],
    validation_artifacts: [
      'artifacts/semantic_probe/damage_validation_summary.json',
      'artifacts/semantic_probe/death_validation_current/death_validation_summary.json',
      'artifacts/v2_ward_spawn/current_validation_summary.json',
      'artifacts/protection_v4_publication/regression_summary.json',
    ],
    regression_fixture_set: '16.15-frozen-regression-v1',
  },
  '16.16.805.0442': {
    schema_version: 1,
    game_version: '16.16.805.0442',
    patch: '16.16',
    support_level: 'DEEP_SEMANTIC_READY',
    release_status: 'SUPPORTED_VERIFIED_DEEP_SEMANTICS_PARTIAL',
    downstream_release_gate: 'RELEASE_16_16_EXACT_BUILD_DEEP_SEMANTICS',
    supersedes_format_only_gate: (
      'artifacts/new_build_rofl_compatibility_gate_v1/core_compatibility_summary.json'
    ),
    format_profile: {
      implementation: 'src/rofl.js',
      status: 'FORMAT_VERIFIED',
    },
    runtime_profile: {
      image_sha256: newDecoder.RUNTIME_IMAGE_SHA256,
      base_packet_vtable_rva: 0x01a23ab0,
      base_packet_serialize_rva: 0x0124c2e0,
      base_packet_decode_rva: 0x0122e820,
      runtime_alloc_rva: 0x011928c0,
      runtime_memset_leaf_rva: 0x019d9662,
    },
    packet_routes: Object.fromEntries(Object.entries(newDecoder.SEMANTIC_PROFILE_REGISTRY)
      .map(([capability, profile]) => [
        capability,
        profile.replay_block_packet_id ?? profile.candidate_replay_block_packet_id ?? null,
      ])),
    decoder_profile: newDecoder.SEMANTIC_PROFILE_REGISTRY,
    field_semantics: {
      participant_mapping: 'SEMANTIC_VERIFIED_DIRECT',
      hero_path: 'SEMANTIC_VERIFIED_DERIVED',
      level_transition: 'SEMANTIC_VERIFIED_DIRECT',
      level_after: 'SEMANTIC_VERIFIED_DERIVED_BUILD_BOUND',
      ward_spawn: 'SEMANTIC_VERIFIED_DERIVED',
      ward_lifecycle: 'SEMANTIC_PARTIAL_DERIVED',
      hero_damage: 'SEMANTIC_VERIFIED_DIRECT',
      hero_death: 'SEMANTIC_VERIFIED_DIRECT',
      hero_death_timer: 'SEMANTIC_VERIFIED_DIRECT',
      hero_reincarnate_alive: 'SEMANTIC_VERIFIED_DIRECT_BOUNDED',
      hero_scoreboard_state: 'SEMANTIC_VERIFIED_DIRECT',
      experience_points: 'SEMANTIC_VERIFIED_DIRECT',
      lane_minions_killed: 'SEMANTIC_VERIFIED_DIRECT',
      total_gold: 'CANDIDATE',
      jungle_minions_killed: 'CANDIDATE',
      buff: 'SEMANTIC_VERIFIED_DIRECT_PARTIAL',
      cast_spell: 'SEMANTIC_VERIFIED_DIRECT_PARTIAL',
      heal_reported: 'SEMANTIC_VERIFIED_DIRECT',
      shield_generated: 'SEMANTIC_VERIFIED_DIRECT',
      item_state: 'SEMANTIC_VERIFIED_DIRECT_PARTIAL',
      item_swap: 'SEMANTIC_VERIFIED_DIRECT',
      item_substitution_map: 'SEMANTIC_VERIFIED_DIRECT',
      support_quest_item_stage: 'SEMANTIC_VERIFIED_DERIVED',
      ability_cooldown_broadcast: 'SEMANTIC_VERIFIED_DIRECT_BOUNDED',
      instant_stop_attack: 'SEMANTIC_VERIFIED_DIRECT_BOUNDED',
      face_direction_vector: 'SEMANTIC_VERIFIED_DIRECT_BOUNDED',
      basic_attack_position_minion: 'SEMANTIC_VERIFIED_DIRECT_BOUNDED',
      wall_tracking_component_cache_snapshot: 'SEMANTIC_VERIFIED_DIRECT_BOUNDED',
      missile_movement_complete_count: 'SEMANTIC_VERIFIED_DIRECT_BOUNDED',
      trinket_state: 'UNVERIFIED',
      trinket_slot_state: 'UNVERIFIED',
      trinket_swap: 'UNVERIFIED',
      trinket_purchase_or_swap: 'UNVERIFIED',
      sweeper_held: 'UNVERIFIED',
      sweeper_activation: 'UNAVAILABLE',
      sweeper_active_interval: 'UNAVAILABLE',
      sweeper_position: 'UNAVAILABLE',
      sweeper_owner: 'UNAVAILABLE',
    },
    semantic_mappings: {
      level_after: newDecoder.LEVEL_AFTER_BY_FIELD_10,
      coordinates: newDecoder.SEMANTIC_PROFILE_REGISTRY.hero_path.coordinate_transform,
      ward_participant: 'owner_network_id - 0x400000ad',
      ward_team: 'exact Replay tail participant TEAM',
    },
    verified_capabilities: [
      'participant_mapping', 'hero_path', 'level_transition', 'level_after',
      'ward_spawn', 'hero_damage', 'hero_death', 'hero_scoreboard_state',
      'hero_death_timer', 'hero_reincarnate_alive', 'experience_points',
      'lane_minions_killed',
      'heal_reported', 'shield_generated', 'item_swap', 'item_substitution_map',
      'support_quest_item_stage', 'ability_cooldown_broadcast', 'instant_stop_attack',
      'face_direction_vector', 'basic_attack_position_minion',
      'wall_tracking_component_cache_snapshot', 'missile_movement_complete_count',
    ],
    partial_capabilities: ['ward_lifecycle', 'buff', 'cast_spell', 'item_state'],
    candidate_capabilities: ['total_gold', 'jungle_minions_killed'],
    unverified_capabilities: [
      'trinket_state', 'trinket_slot_state', 'trinket_swap', 'trinket_purchase_or_swap',
      'sweeper_held',
    ],
    unsupported_capabilities: [
      'sweeper_activation', 'sweeper_active_interval', 'sweeper_position', 'sweeper_owner',
    ],
    validation_artifacts: [
      'artifacts/multi_build_rofl_support_v1/hero_path_validation/hero_path_validation_summary.json',
      'artifacts/multi_build_rofl_support_v1/level_transition_validation/level_transition_validation_summary.json',
      'artifacts/16_16_ward_semantic_recovery_v1/runtime/ward_validation_summary.json',
      'artifacts/new_build_rofl_compatibility_gate_v1/core_compatibility_summary.json',
      'artifacts/hero_combat_state_v2/damage/damage_16_16_anchor_validation.json',
      'artifacts/hero_combat_state_v2/emulation/packet_017f_latest_four_summary.json',
      'artifacts/hero_combat_state_v2/death/death_16_16_route_anchor_validation.json',
      'artifacts/full_semantic_baseline_v1/runtime_candidates/buff_spell_item_runtime_candidates_16_16.json',
      'artifacts/full_semantic_baseline_v1/runtime_candidates/packet_0112_p0_semantic_differential_16_16.json',
      'artifacts/full_semantic_baseline_v1/hero_stats/hero_stats_scoreboard_validation_16_16.json',
      'artifacts/full_semantic_deep_recovery_v2/hero_state/hero_state_damage_defense_deep_report_16_16.json',
      'artifacts/full_semantic_deep_recovery_v2/buff_spell/PROMOTION_MATRIX.json',
      'artifacts/full_semantic_deep_recovery_v2/entity_item/entity_item_deep_recovery_summary_16_16.json',
      'artifacts/full_semantic_deep_recovery_v2/unknown_mining/route_0064_support_quest_audit.json',
      'artifacts/full_semantic_deep_recovery_v2/unknown_mining/route_0064_runtime_residual_audit.json',
      'artifacts/full_semantic_deep_recovery_v2/gameplay_route_tail/gameplay_route_tail_audit_16_16.json',
      'artifacts/full_semantic_deep_recovery_v2/gameplay_route_tail/gameplay_route_tail_machine_decisions_16_16.json',
      'artifacts/full_semantic_deep_recovery_v2/hero_respawn/hero_reincarnate_alive_audit_16_16.json',
    ],
    capability_contracts: [SWEEPER_CAPABILITY_CONTRACT_ID],
    regression_fixture_set: '16.16-deep-semantic-exact-build-safe-corpus-v2',
  },
  '16.19.820.7193': {
    schema_version: 1,
    game_version: '16.19.820.7193',
    patch: '16.19',
    support_level: 'CORE_READY',
    release_status: 'EXPERIMENTAL_CANDIDATE',
    downstream_release_gate: null,
    format_profile: {
      implementation: 'src/rofl.js',
      status: 'FORMAT_VERIFIED_LOCAL_REPLAYS',
    },
    runtime_profile: {
      status: 'UNPROFILED',
      image_sha256: null,
    },
    packet_routes: {
      hero_death: null,
      hero_death_timer: 0x02d6,
      hero_respawn: 0x0357,
      hero_level_state: 0x02b3,
      hero_minions_killed_snapshot: 0x0276,
      hero_jungle_minions_killed_snapshot: 0x0276,
      hero_experience_snapshot: 0x0276,
      hero_gold_earned_snapshot: 0x0276,
      hero_gold_spent_snapshot: 0x0276,
      hero_champion_kills_snapshot: 0x0276,
      hero_deaths_snapshot: 0x0276,
      hero_assists_snapshot: 0x0276,
      hero_kill_stats_snapshot: 0x0276,
      hero_ward_stats_snapshot: 0x0276,
      hero_damage_totals_snapshot: 0x0276,
      hero_damage_taken_from_champions_snapshot: 0x0276,
      hero_damage_self_mitigated_snapshot: 0x0276,
      hero_longest_living_time_snapshot: 0x0276,
      hero_total_time_spent_dead_snapshot: 0x0276,
      hero_total_heal_snapshot: 0x0276,
      hero_total_units_healed_snapshot: 0x0276,
      hero_vision_score_snapshot: 0x0276,
      hero_epic_monster_damage_snapshot: 0x0276,
      hero_crowd_control_time_snapshot: 0x0276,
      hero_structure_objective_damage_snapshot: 0x0276,
      hero_inventory_mapview: 0x0420,
      hero_inventory_set_item: 0x03b7,
      hero_inventory_broadcast: 0x03ef,
      npc_buff_remove_packet: 0x043c,
      npc_buff_add_packet: 0x03ed,
    },
    decoder_profile: {
      hero_death: {
        id: 'rofl-16.19.820.7193-hero-death-triad-selector-candidate-v1',
        replay_version: decoder1619.REPLAY_VERSION,
        status: 'CANDIDATE',
        enabled: true,
        route_profiles: decoder1619.HERO_DEATH_CANDIDATE_PROFILES,
      },
      hero_death_timer: decoder1619.HERO_DEATH_TIMER_CANDIDATE_PROFILE,
      hero_respawn: decoder1619.HERO_RESPAWN_CANDIDATE_PROFILE,
      hero_level_state: decoder1619.HERO_LEVEL_STATE_CANDIDATE_PROFILE,
      hero_minions_killed_snapshot:
        heroStatsCandidate1619.HERO_MINIONS_KILLED_SNAPSHOT_CANDIDATE_PROFILE,
      hero_jungle_minions_killed_snapshot:
        heroStatsCandidate1619.HERO_JUNGLE_MINIONS_KILLED_SNAPSHOT_CANDIDATE_PROFILE,
      hero_experience_snapshot:
        heroStatsCandidate1619.HERO_EXPERIENCE_SNAPSHOT_CANDIDATE_PROFILE,
      hero_gold_earned_snapshot:
        heroStatsCandidate1619.HERO_GOLD_EARNED_SNAPSHOT_CANDIDATE_PROFILE,
      hero_gold_spent_snapshot:
        heroStatsCandidate1619.HERO_GOLD_SPENT_SNAPSHOT_CANDIDATE_PROFILE,
      hero_champion_kills_snapshot:
        heroStatsCandidate1619.HERO_CHAMPION_KILLS_SNAPSHOT_CANDIDATE_PROFILE,
      hero_deaths_snapshot:
        heroStatsCandidate1619.HERO_DEATHS_SNAPSHOT_CANDIDATE_PROFILE,
      hero_assists_snapshot:
        heroStatsCandidate1619.HERO_ASSISTS_SNAPSHOT_CANDIDATE_PROFILE,
      hero_kill_stats_snapshot:
        heroStatsCandidate1619.HERO_KILL_STATS_SNAPSHOT_CANDIDATE_PROFILE,
      hero_ward_stats_snapshot:
        heroStatsCandidate1619.HERO_WARD_STATS_SNAPSHOT_CANDIDATE_PROFILE,
      hero_damage_totals_snapshot:
        heroStatsCandidate1619.HERO_DAMAGE_TOTALS_SNAPSHOT_CANDIDATE_PROFILE,
      hero_damage_taken_from_champions_snapshot:
        heroStatsCandidate1619.HERO_DAMAGE_TAKEN_FROM_CHAMPIONS_SNAPSHOT_CANDIDATE_PROFILE,
      hero_damage_self_mitigated_snapshot:
        heroStatsCandidate1619.HERO_DAMAGE_SELF_MITIGATED_SNAPSHOT_CANDIDATE_PROFILE,
      hero_longest_living_time_snapshot:
        heroStatsCandidate1619.HERO_LONGEST_LIVING_TIME_SNAPSHOT_CANDIDATE_PROFILE,
      hero_total_time_spent_dead_snapshot:
        heroStatsCandidate1619.HERO_TOTAL_TIME_SPENT_DEAD_SNAPSHOT_CANDIDATE_PROFILE,
      hero_total_heal_snapshot:
        heroStatsCandidate1619.HERO_TOTAL_HEAL_SNAPSHOT_CANDIDATE_PROFILE,
      hero_total_units_healed_snapshot:
        heroStatsCandidate1619.HERO_TOTAL_UNITS_HEALED_SNAPSHOT_CANDIDATE_PROFILE,
      hero_vision_score_snapshot:
        heroStatsCandidate1619.HERO_VISION_SCORE_SNAPSHOT_CANDIDATE_PROFILE,
      hero_epic_monster_damage_snapshot:
        heroStatsCandidate1619.HERO_EPIC_MONSTER_DAMAGE_SNAPSHOT_CANDIDATE_PROFILE,
      hero_crowd_control_time_snapshot:
        heroStatsCandidate1619.HERO_CROWD_CONTROL_TIME_SNAPSHOT_CANDIDATE_PROFILE,
      hero_structure_objective_damage_snapshot:
        heroStatsCandidate1619.HERO_STRUCTURE_OBJECTIVE_DAMAGE_SNAPSHOT_CANDIDATE_PROFILE,
      hero_inventory_mapview: decoder1619.HERO_INVENTORY_MAPVIEW_CANDIDATE_PROFILE,
      hero_inventory_set_item: decoder1619.HERO_INVENTORY_SET_ITEM_CANDIDATE_PROFILE,
      hero_inventory_broadcast: decoder1619.HERO_INVENTORY_BROADCAST_CANDIDATE_PROFILE,
      npc_buff_remove_packet: buffRemoveCandidate1619.NPC_BUFF_REMOVE_PACKET_CANDIDATE_PROFILE,
      npc_buff_add_packet: buffAddCandidate1619.NPC_BUFF_ADD_PACKET_CANDIDATE_PROFILE,
    },
    field_semantics: {
      hero_death: 'CANDIDATE_EXACT_BUILD_ROUTE_FINGERPRINT',
      hero_death_timer: 'CANDIDATE_EXACT_RUNTIME_FLOAT_AND_REPLAY_TIMING',
      hero_respawn: 'CANDIDATE_EXACT_RUNTIME_ROUTE_AND_TIMER_MATCH',
      hero_level_state: 'CANDIDATE_EXACT_RUNTIME_FIELD_WITH_SEQUENCE_GAPS',
      hero_minions_killed_snapshot: 'CANDIDATE_KEYFRAME_MINIONS_KILLED_FIELD',
      hero_jungle_minions_killed_snapshot: 'CANDIDATE_KEYFRAME_THREE_NEUTRAL_MINION_TAIL_CORRELATIONS',
      hero_experience_snapshot: 'CANDIDATE_KEYFRAME_EXPERIENCE_FIELD',
      hero_gold_earned_snapshot: 'CANDIDATE_KEYFRAME_GOLD_EARNED_FIELD',
      hero_gold_spent_snapshot: 'CANDIDATE_KEYFRAME_GOLD_SPENT_FIELD',
      hero_champion_kills_snapshot: 'CANDIDATE_KEYFRAME_MIRRORED_CHAMPION_KILLS_FIELD',
      hero_deaths_snapshot: 'CANDIDATE_KEYFRAME_DEATH_COUNT_FIELD',
      hero_assists_snapshot: 'CANDIDATE_KEYFRAME_ASSIST_COUNT_FIELD',
      hero_kill_stats_snapshot: 'CANDIDATE_KEYFRAME_KILL_STAT_TAIL_CORRELATIONS',
      hero_ward_stats_snapshot: 'CANDIDATE_KEYFRAME_WARD_STAT_TAIL_CORRELATIONS',
      hero_damage_totals_snapshot: 'CANDIDATE_KEYFRAME_THREE_DAMAGE_TAIL_CORRELATIONS',
      hero_damage_taken_from_champions_snapshot:
        'CANDIDATE_KEYFRAME_DAMAGE_TAKEN_FROM_CHAMPIONS_TAIL_CORRELATION',
      hero_damage_self_mitigated_snapshot:
        'CANDIDATE_KEYFRAME_DAMAGE_SELF_MITIGATED_TAIL_CORRELATION',
      hero_longest_living_time_snapshot:
        'CANDIDATE_KEYFRAME_LONGEST_LIVING_TIME_TAIL_CORRELATION',
      hero_total_time_spent_dead_snapshot:
        'CANDIDATE_KEYFRAME_TOTAL_TIME_SPENT_DEAD_TAIL_CORRELATION',
      hero_total_heal_snapshot: 'CANDIDATE_KEYFRAME_TOTAL_HEAL_TAIL_CORRELATION',
      hero_total_units_healed_snapshot: 'CANDIDATE_KEYFRAME_TOTAL_UNITS_HEALED_TAIL_CORRELATION',
      hero_vision_score_snapshot: 'CANDIDATE_KEYFRAME_VISION_SCORE_TAIL_CORRELATION',
      hero_epic_monster_damage_snapshot: 'CANDIDATE_KEYFRAME_EPIC_MONSTER_DAMAGE_TAIL_CORRELATION',
      hero_crowd_control_time_snapshot: 'CANDIDATE_KEYFRAME_CROWD_CONTROL_TIME_TAIL_CORRELATION',
      hero_structure_objective_damage_snapshot: 'CANDIDATE_KEYFRAME_STRUCTURE_OBJECTIVE_DAMAGE_TAIL_CORRELATION',
      hero_inventory_mapview: 'CANDIDATE_EXACT_RUNTIME_MAPVIEW_PACKET_SLOT_RECORDS',
      hero_inventory_set_item: 'CANDIDATE_EXACT_RUNTIME_SET_ITEM_PACKET_FIELDS',
      hero_inventory_broadcast: 'CANDIDATE_EXACT_RUNTIME_BROADCAST_SLOT_RECORDS',
      npc_buff_remove_packet: 'CANDIDATE_EXACT_RUNTIME_BUFF_REMOVE2_PACKET_FIELDS',
      npc_buff_add_packet: 'CANDIDATE_EXACT_RUNTIME_BUFF_ADD2_PACKET_FIELDS',
    },
    semantic_mappings: {
      victim_participant: '(raw_param & 0xff) - 0xad, route-profile bounded',
      death_timer_seconds_candidate: '0x02d6 decoded float; HN route profile only',
      respawn_time_candidate: 'observed 0x0357 time matched to HN death timer; HN route profile only',
      level_after_candidate: '0x02b3 decoded object field; HN route profile only',
      minions_killed_candidate: '0x0276 keyframe HeroStats f32 field; HN route profile only',
      jungle_minions_killed_candidate: '0x0276 keyframe HeroStats f32 offsets 0x40/0x44/0x48; floors correlate with three neutral-minion Replay tails in one HN Replay',
      experience_points_candidate: '0x0276 keyframe HeroStats f32 offset 0x28; HN route profile only',
      gold_earned_candidate: '0x0276 keyframe HeroStats f32 offset 0x38; HN route profile only',
      gold_spent_candidate: '0x0276 keyframe HeroStats f32 offset 0x34; HN route profile only',
      champion_kills_candidate: '0x0276 keyframe HeroStats mirrored u32 offsets 0x4c and 0x33c; HN route profile only',
      deaths_candidate: '0x0276 keyframe HeroStats u32 offset 0x50; HN route profile only',
      assists_candidate: '0x0276 keyframe HeroStats u32 offset 0x54; HN route profile only',
      kill_stats_candidate: '0x0276 keyframe HeroStats u32 offsets 0x58-0x6c; six Replay-tail correlations in one HN Replay',
      ward_stats_candidate: '0x0276 keyframe HeroStats u32 offsets 0x1a4-0x1ac; three Replay-tail correlations in one HN Replay',
      damage_totals_candidate: '0x0276 keyframe HeroStats f32 offsets 0x1d0/0x1e0/0x1f0; floors correlate with three damage Replay tails in one HN Replay',
      damage_taken_from_champions_candidate: '0x0276 keyframe HeroStats f32 offset 0x200; floors correlate with TOTAL_DAMAGE_TAKEN_FROM_CHAMPIONS tails in two HN Replays; no individual damage event',
      damage_self_mitigated_candidate: '0x0276 keyframe HeroStats f32 offset 0x208; floors correlate with TOTAL_DAMAGE_SELF_MITIGATED tails in two HN Replays; no individual damage or mitigation event',
      longest_living_time_candidate: '0x0276 keyframe HeroStats f32 offset 0x244; floors correlate with LONGEST_TIME_SPENT_LIVING tails in three HN Replays, with one post-keyframe tail gap; no individual life-span event',
      total_time_spent_dead_candidate: '0x0276 keyframe HeroStats f32 offset 0x248; floors correlate with TOTAL_TIME_SPENT_DEAD tails in three HN Replays; no individual death-duration event',
      total_heal_candidate: '0x0276 keyframe HeroStats u32 offset 0x234; observed values correlate with TOTAL_HEAL tail in one HN Replay',
      total_units_healed_candidate: '0x0276 keyframe HeroStats u32 offset 0x23c; observed values correlate with TOTAL_UNITS_HEALED tails in three HN Replays; no individual heal event',
      vision_score_candidate: '0x0276 keyframe HeroStats f32 offset 0x1b0; floors correlate with VISION_SCORE tail in one HN Replay',
      epic_monster_damage_candidate: '0x0276 keyframe HeroStats f32 offset 0x21c; floors correlate with TOTAL_DAMAGE_DEALT_TO_EPIC_MONSTERS tail in one HN Replay',
      crowd_control_time_candidate: '0x0276 keyframe HeroStats f32 offset 0x230; floors correlate with TOTAL_TIME_CROWD_CONTROL_DEALT_TO_CHAMPIONS tail in one HN Replay; no individual crowd-control events or targets',
      structure_objective_damage_candidate: '0x0276 keyframe HeroStats f32 offsets 0x210/0x214 and 0x218; floors correlate with BUILDINGS and OBJECTIVES tails in one HN Replay; BUILDINGS/TURRETS identity and objective attribution remain unresolved',
      inventory_mapview_candidate: '0x0420 observed HN packet slot/item-ID records; no continuous inventory state or purchase event',
      inventory_set_item_candidate: '0x03b7 observed HN packet slot/item-ID fields; no item transaction or general participant mapping',
      inventory_broadcast_candidate: '0x03ef exact HN runtime vector and record fields; bounded one-Replay raw-param-to-participant candidate, without transaction inference',
      buff_remove2_candidate: '0x043c exact HN runtime decoded f32/u8/u32 packet fields; no buff owner, type, or successful removal inference',
      buff_add2_candidate: '0x03ed exact HN runtime decoded scalar packet fields across game and keyframe streams; no buff owner, type, or successful application inference',
    },
    verified_capabilities: [],
    candidate_capabilities: [
      'hero_death', 'hero_death_timer', 'hero_respawn', 'hero_level_state',
      'hero_minions_killed_snapshot',
      'hero_jungle_minions_killed_snapshot',
      'hero_experience_snapshot',
      'hero_gold_earned_snapshot',
      'hero_gold_spent_snapshot',
      'hero_champion_kills_snapshot',
      'hero_deaths_snapshot',
      'hero_assists_snapshot',
      'hero_kill_stats_snapshot',
      'hero_ward_stats_snapshot',
      'hero_damage_totals_snapshot',
      'hero_damage_taken_from_champions_snapshot',
      'hero_damage_self_mitigated_snapshot',
      'hero_longest_living_time_snapshot',
      'hero_total_time_spent_dead_snapshot',
      'hero_total_heal_snapshot',
      'hero_total_units_healed_snapshot',
      'hero_vision_score_snapshot',
      'hero_epic_monster_damage_snapshot',
      'hero_crowd_control_time_snapshot',
      'hero_structure_objective_damage_snapshot',
      'hero_inventory_mapview',
      'hero_inventory_set_item',
      'hero_inventory_broadcast',
      'npc_buff_remove_packet',
      'npc_buff_add_packet',
    ],
    unsupported_capabilities: [],
    validation_artifacts: [],
    regression_fixture_set: null,
  },
  '16.19.821.7343': {
    schema_version: 1,
    game_version: '16.19.821.7343',
    patch: '16.19',
    support_level: 'CORE_READY',
    release_status: 'EXPERIMENTAL_CANDIDATE',
    downstream_release_gate: null,
    format_profile: {
      implementation: 'src/rofl.js',
      status: 'FORMAT_VERIFIED_LOCAL_REPLAYS',
    },
    runtime_profile: {
      status: 'CAPTURED_EXACT_IMAGE_NATIVE_ROUTE_KEYFRAME_AND_INVENTORY_RESEARCH',
      image_sha256: levelCandidate1619821.RUNTIME_IMAGE_SHA256,
    },
    packet_routes: {
      hero_death: 0x0259,
      hero_assist: 0x040a,
      hero_death_timer: 0x0259,
      hero_respawn: 0x0048,
      hero_deaths_snapshot: 0x0089,
      hero_champion_kills_snapshot: 0x0089,
      hero_assists_snapshot: 0x0089,
      hero_missions_minions_killed_snapshot: 0x0089,
      hero_ward_stats_snapshot: 0x0089,
      hero_missions_cannon_minions_killed_snapshot: 0x0089,
      hero_minions_killed_snapshot: 0x0089,
      hero_jungle_minions_killed_snapshot: 0x0089,
      hero_kill_stats_snapshot: 0x0089,
      hero_experience_snapshot: 0x0089,
      hero_vision_score_snapshot: 0x0089,
      hero_gold_earned_snapshot: 0x0089,
      hero_gold_spent_snapshot: 0x0089,
      hero_damage_totals_snapshot: 0x0089,
      hero_damage_taken_from_champions_snapshot: 0x0089,
      hero_damage_self_mitigated_snapshot: 0x0089,
      hero_structure_objective_damage_snapshot: 0x0089,
      hero_longest_living_time_snapshot: 0x0089,
      hero_total_time_spent_dead_snapshot: 0x0089,
      hero_total_heal_snapshot: 0x0089,
      hero_total_units_healed_snapshot: 0x0089,
      hero_epic_monster_damage_snapshot: 0x0089,
      hero_crowd_control_time_snapshot: 0x0089,
      hero_level_state: 0x0197,
      hero_inventory_packet: 0x018d,
      hero_inventory_broadcast_packet: 0x0357,
      hero_inventory_set_item_packet: 0x002d,
      params_heal_packet: 0x040a,
      shielding_params_packet_pair: 0x040a,
      stealth_event_packet: 0x040a,
      champion_die_event_packet: 0x040a,
      champion_kill_event_packet: 0x040a,
      champion_multiple_kill_event_packet: 0x040a,
      champion_double_kill_event_packet: 0x040a,
      champion_triple_quadra_event_packet: 0x040a,
      on_shutdown_event_packet: 0x040a,
      resurrect_event_packet: 0x040a,
      turret_plate_event_packet: 0x040a,
      cast_spell_ans_packet: 0x01da,
      npc_buff_remove_packet: 0x047c,
      npc_buff_add_packet: 0x00ae,
      npc_buff_update_num_counter_packet: 0x0194,
      npc_buff_update_count_packet: 0x02d9,
      npc_buff_replace_packet: 0x01ad,
      set_spell_timer_from_buff_packet: 0x00fd,
      set_spell_level_packet: 0x025d,
      direct_input_movement_turn_packet: 0x00ba,
      set_movement_driver_packet: 0x0335,
    },
    decoder_profile: {
      hero_death: decoder1619821.HERO_DEATH_CANDIDATE_PROFILE_821,
      hero_assist: assistCandidate1619821.HERO_ASSIST_CANDIDATE_PROFILE_821,
      hero_death_timer: deathTimerCandidate1619821.HERO_DEATH_TIMER_CANDIDATE_PROFILE_821,
      hero_respawn: respawnCandidate1619821.HERO_RESPAWN_CANDIDATE_PROFILE_821,
      hero_deaths_snapshot:
        heroStatsCandidate1619821.HERO_DEATHS_SNAPSHOT_821_CANDIDATE_PROFILE,
      hero_champion_kills_snapshot:
        heroStatsCandidate1619821.HERO_CHAMPION_KILLS_SNAPSHOT_821_CANDIDATE_PROFILE,
      hero_assists_snapshot:
        heroStatsCandidate1619821.HERO_ASSISTS_SNAPSHOT_821_CANDIDATE_PROFILE,
      hero_missions_minions_killed_snapshot:
        heroStatsCandidate1619821.HERO_MISSIONS_MINIONS_KILLED_SNAPSHOT_821_CANDIDATE_PROFILE,
      hero_ward_stats_snapshot:
        auxiliaryCountsCandidate1619821.HERO_WARD_STATS_SNAPSHOT_821_CANDIDATE_PROFILE,
      hero_missions_cannon_minions_killed_snapshot:
        auxiliaryCountsCandidate1619821.HERO_MISSIONS_CANNON_MINIONS_KILLED_SNAPSHOT_821_CANDIDATE_PROFILE,
      hero_minions_killed_snapshot: floatStatsCandidate1619821.PROFILES.hero_minions_killed_snapshot,
      hero_jungle_minions_killed_snapshot:
        floatStatsCandidate1619821.PROFILES.hero_jungle_minions_killed_snapshot,
      hero_kill_stats_snapshot:
        killStatsCandidate1619821.HERO_KILL_STATS_SNAPSHOT_821_CANDIDATE_PROFILE,
      hero_experience_snapshot: floatStatsCandidate1619821.PROFILES.hero_experience_snapshot,
      hero_vision_score_snapshot: floatStatsCandidate1619821.PROFILES.hero_vision_score_snapshot,
      hero_gold_earned_snapshot: floatStatsCandidate1619821.PROFILES.hero_gold_earned_snapshot,
      hero_gold_spent_snapshot: floatStatsCandidate1619821.PROFILES.hero_gold_spent_snapshot,
      hero_damage_totals_snapshot:
        damageFloatCandidate1619821.PROFILES.hero_damage_totals_snapshot,
      hero_damage_taken_from_champions_snapshot:
        damageFloatCandidate1619821.PROFILES.hero_damage_taken_from_champions_snapshot,
      hero_damage_self_mitigated_snapshot:
        damageFloatCandidate1619821.PROFILES.hero_damage_self_mitigated_snapshot,
      hero_structure_objective_damage_snapshot:
        damageFloatCandidate1619821.PROFILES.hero_structure_objective_damage_snapshot,
      hero_longest_living_time_snapshot:
        timeStatsCandidate1619821.PROFILES.hero_longest_living_time_snapshot,
      hero_total_time_spent_dead_snapshot:
        timeStatsCandidate1619821.PROFILES.hero_total_time_spent_dead_snapshot,
      hero_total_heal_snapshot: healStatsCandidate1619821.PROFILES.hero_total_heal_snapshot,
      hero_total_units_healed_snapshot:
        healStatsCandidate1619821.PROFILES.hero_total_units_healed_snapshot,
      hero_epic_monster_damage_snapshot:
        epicCcCandidate1619821.PROFILES.hero_epic_monster_damage_snapshot,
      hero_crowd_control_time_snapshot:
        epicCcCandidate1619821.PROFILES.hero_crowd_control_time_snapshot,
      hero_level_state: levelCandidate1619821.HERO_LEVEL_CANDIDATE_PROFILE_821,
      hero_inventory_packet:
        inventoryPacketCandidate1619821.HERO_INVENTORY_PACKET_CANDIDATE_PROFILE_821,
      hero_inventory_broadcast_packet:
        inventoryBroadcastPacketCandidate1619821.HERO_INVENTORY_BROADCAST_PACKET_CANDIDATE_PROFILE_821,
      hero_inventory_set_item_packet:
        inventorySetItemPacketCandidate1619821.HERO_INVENTORY_SET_ITEM_PACKET_CANDIDATE_PROFILE_821,
      params_heal_packet:
        paramsHealPacketCandidate1619821.PARAMS_HEAL_PACKET_CANDIDATE_PROFILE_821,
      shielding_params_packet_pair:
        shieldingParamsPacketPairCandidate1619821.SHIELDING_PARAMS_PACKET_PAIR_821_PROFILE,
      stealth_event_packet:
        stealthEventPacketCandidate1619821.STEALTH_EVENT_PACKET_CANDIDATE_PROFILE_821,
      champion_die_event_packet:
        championDieEventPacketCandidate1619821.CHAMPION_DIE_EVENT_PACKET_821_PROFILE,
      champion_kill_event_packet:
        championKillEventPacketCandidate1619821.CHAMPION_KILL_EVENT_PACKET_CANDIDATE_PROFILE_821,
      champion_multiple_kill_event_packet:
        championMultipleKillEventPacketCandidate1619821.CHAMPION_MULTIPLE_KILL_EVENT_PACKET_821_PROFILE,
      champion_double_kill_event_packet:
        championDoubleKillEventPacketCandidate1619821.CHAMPION_DOUBLE_KILL_EVENT_PACKET_821_PROFILE,
      champion_triple_quadra_event_packet:
        championTripleQuadraEventPacketCandidate1619821.CHAMPION_TRIPLE_QUADRA_EVENT_PACKET_821_PROFILE,
      on_shutdown_event_packet:
        onShutdownEventPacketCandidate1619821.ON_SHUTDOWN_EVENT_PACKET_821_PROFILE,
      resurrect_event_packet:
        resurrectEventPacketCandidate1619821.RESURRECT_EVENT_PACKET_821_PROFILE,
      turret_plate_event_packet:
        turretPlateEventPacketCandidate1619821.TURRET_PLATE_EVENT_PACKET_821_PROFILE,
      cast_spell_ans_packet:
        castSpellAnsCandidate1619821.CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_821,
      npc_buff_remove_packet:
        buffRemovePacketCandidate1619821.NPC_BUFF_REMOVE_PACKET_CANDIDATE_PROFILE_821,
      npc_buff_add_packet:
        buffAddPacketCandidate1619821.NPC_BUFF_ADD_PACKET_CANDIDATE_PROFILE_821,
      npc_buff_update_num_counter_packet:
        buffUpdateNumCounterPacketCandidate1619821.NPC_BUFF_UPDATE_NUM_COUNTER_PACKET_CANDIDATE_PROFILE_821,
      npc_buff_update_count_packet:
        buffUpdateCountPacketCandidate1619821.NPC_BUFF_UPDATE_COUNT_PACKET_CANDIDATE_PROFILE_821,
      npc_buff_replace_packet:
        buffReplacePacketCandidate1619821.NPC_BUFF_REPLACE_PACKET_CANDIDATE_PROFILE_821,
      set_spell_timer_from_buff_packet:
        setSpellTimerFromBuffPacketCandidate1619821.SET_SPELL_TIMER_FROM_BUFF_PACKET_CANDIDATE_PROFILE_821,
      set_spell_level_packet:
        setSpellLevelPacketCandidate1619821.SET_SPELL_LEVEL_PACKET_CANDIDATE_PROFILE_821,
      direct_input_movement_turn_packet:
        directInputTurnPacketCandidate1619821.DIRECT_INPUT_MOVEMENT_TURN_PACKET_CANDIDATE_PROFILE_821,
      set_movement_driver_packet:
        setMovementDriverPacketCandidate1619821.SET_MOVEMENT_DRIVER_PACKET_CANDIDATE_PROFILE_821,
    },
    evidence_grades: {
      hero_death: 'CANDIDATE_821_REPLAY_TAIL_ROUTE_AND_RUNTIME_DIE_SOURCE',
      hero_assist: 'CANDIDATE_821_PAIRED_ROUTE_DEATH_KILLER_AND_ASSISTS_TAIL',
      hero_death_timer: 'CANDIDATE_821_RUNTIME_FLOAT_AND_DEATH_ROUTE_CORRELATION',
      hero_respawn: 'CANDIDATE_821_RUNTIME_RETURN_FIELDS_AND_DEAD_TIME_CORRELATION',
      hero_deaths_snapshot: 'CANDIDATE_821_RUNTIME_COUNT_BYTE_KEYFRAME_TAIL_CORRELATION',
      hero_champion_kills_snapshot: 'CANDIDATE_821_RUNTIME_COUNT_BYTE_MIRRORED_KEYFRAME_TAIL_CORRELATION',
      hero_assists_snapshot: 'CANDIDATE_821_RUNTIME_COUNT_BYTE_KEYFRAME_TAIL_CORRELATION',
      hero_missions_minions_killed_snapshot:
        'CANDIDATE_821_RUNTIME_TWO_BYTE_MISSIONS_TAIL_CORRELATION',
      hero_ward_stats_snapshot: 'CANDIDATE_821_RUNTIME_WARD_COUNT_BYTES_AND_TAILS',
      hero_missions_cannon_minions_killed_snapshot:
        'CANDIDATE_821_RUNTIME_CANNON_COUNT_BYTE_AND_MISSIONS_TAIL',
      hero_minions_killed_snapshot: 'CANDIDATE_821_NATIVE_F32_STANDARD_MINIONS_KILLED_TAIL',
      hero_jungle_minions_killed_snapshot:
        'CANDIDATE_821_NATIVE_F32_NEUTRAL_MINIONS_THREE_TAILS',
      hero_kill_stats_snapshot: 'CANDIDATE_821_NATIVE_U32_KILL_STATS_SIX_TAILS',
      hero_experience_snapshot: 'CANDIDATE_821_RUNTIME_F32_KEYFRAME_EXP_TAIL',
      hero_vision_score_snapshot: 'CANDIDATE_821_RUNTIME_F32_KEYFRAME_VISION_TAIL',
      hero_gold_earned_snapshot: 'CANDIDATE_821_RUNTIME_F32_KEYFRAME_EARNED_TAIL',
      hero_gold_spent_snapshot: 'CANDIDATE_821_RUNTIME_F32_KEYFRAME_SPENT_TAIL',
      hero_damage_totals_snapshot: 'CANDIDATE_821_NATIVE_F32_DAMAGE_TOTALS_TAILS',
      hero_damage_taken_from_champions_snapshot:
        'CANDIDATE_821_NATIVE_F32_DAMAGE_TAKEN_FROM_CHAMPIONS_TAIL',
      hero_damage_self_mitigated_snapshot:
        'CANDIDATE_821_NATIVE_F32_SELF_MITIGATED_TAIL',
      hero_structure_objective_damage_snapshot:
        'CANDIDATE_821_NATIVE_F32_STRUCTURE_MIRROR_OBJECTIVE_TAILS',
      hero_longest_living_time_snapshot: 'CANDIDATE_821_NATIVE_F32_LONGEST_LIVING_TAIL',
      hero_total_time_spent_dead_snapshot: 'CANDIDATE_821_NATIVE_F32_TOTAL_DEAD_TIME_TAIL',
      hero_total_heal_snapshot: 'CANDIDATE_821_NATIVE_U32_TOTAL_HEAL_TAIL',
      hero_total_units_healed_snapshot: 'CANDIDATE_821_NATIVE_U32_UNITS_HEALED_TAIL',
      hero_epic_monster_damage_snapshot: 'CANDIDATE_821_NATIVE_F32_EPIC_DAMAGE_TAIL',
      hero_crowd_control_time_snapshot: 'CANDIDATE_821_NATIVE_F32_CROWD_CONTROL_TAIL',
      hero_level_state: 'CANDIDATE_821_RUNTIME_LEVEL_BYTE_AND_REPLAY_TAIL',
      hero_inventory_packet: 'CANDIDATE_821_NATIVE_MAPVIEW_SLOT_ITEM_RECORDS',
      hero_inventory_broadcast_packet:
        'CANDIDATE_821_NATIVE_BROADCAST_SLOT_ITEM_RECORDS',
      hero_inventory_set_item_packet:
        'CANDIDATE_821_NATIVE_SET_ITEM_SLOT_ITEM_PACKET_FIELDS',
      params_heal_packet:
        'CANDIDATE_821_NATIVE_ON_EVENT_PARAMS_HEAL_REPORTED_FLOAT',
      shielding_params_packet_pair:
        'CANDIDATE_821_NATIVE_ON_EVENT_SHIELDING_PARAMS_PAIRED_REPORTS',
      stealth_event_packet:
        'CANDIDATE_821_NATIVE_ON_EVENT_STEALTH_NAMED_PACKET_FIELDS',
      champion_die_event_packet:
        'CANDIDATE_821_NATIVE_ON_CHAMPION_DIE_NAMED_PACKET_FIELD',
      champion_kill_event_packet:
        'CANDIDATE_821_NATIVE_ON_CHAMPION_KILL_NAMED_PACKET_FIELDS',
      champion_multiple_kill_event_packet:
        'CANDIDATE_821_NATIVE_ON_CHAMPION_MULTIPLE_KILL_NAMED_PACKET_FIELDS',
      champion_double_kill_event_packet:
        'CANDIDATE_821_NATIVE_ON_CHAMPION_DOUBLE_KILL_NAMED_PACKET_MARKER',
      champion_triple_quadra_event_packet:
        'CANDIDATE_821_NATIVE_ON_CHAMPION_TRIPLE_QUADRA_NAMED_PACKET_MARKERS',
      on_shutdown_event_packet:
        'CANDIDATE_821_NATIVE_ON_SHUTDOWN_NAMED_PACKET_FIELDS',
      resurrect_event_packet:
        'CANDIDATE_821_NATIVE_ON_RESURRECT_NAMED_PACKET_FIELDS',
      turret_plate_event_packet:
        'CANDIDATE_821_NATIVE_ON_TURRET_PLATE_NAMED_PACKET_FIELD',
      cast_spell_ans_packet: 'CANDIDATE_821_NATIVE_CAST_SPELL_ANS_OPAQUE_PACKET_FIELDS',
      npc_buff_remove_packet: 'CANDIDATE_821_NATIVE_BUFF_REMOVE2_OPAQUE_PACKET_FIELDS',
      npc_buff_add_packet: 'CANDIDATE_821_NATIVE_BUFF_ADD2_OPAQUE_PACKET_FIELDS',
      npc_buff_update_num_counter_packet:
        'CANDIDATE_821_NATIVE_BUFF_UPDATE_NUM_COUNTER_OPAQUE_PACKET_FIELDS',
      npc_buff_update_count_packet:
        'CANDIDATE_821_NATIVE_BUFF_UPDATE_COUNT_OPAQUE_PACKET_FIELDS',
      npc_buff_replace_packet:
        'CANDIDATE_821_NATIVE_BUFF_REPLACE_OPAQUE_PACKET_FIELDS',
      set_spell_timer_from_buff_packet:
        'CANDIDATE_821_NATIVE_SET_SPELL_TIMER_FROM_BUFF_OPAQUE_PACKET_FIELDS',
      set_spell_level_packet:
        'CANDIDATE_821_NATIVE_SET_SPELL_LEVEL_OPAQUE_PACKET_FIELDS',
      direct_input_movement_turn_packet:
        'CANDIDATE_821_NATIVE_DIRECT_INPUT_TURN_OPAQUE_PACKET_FIELDS',
      set_movement_driver_packet:
        'CANDIDATE_821_NATIVE_SET_MOVEMENT_DRIVER_OPAQUE_DISPATCH_FIELD',
    },
    semantic_mappings: {
      victim_participant: '(raw_param & 0xff) - 0xad, 821 route-profile bounded',
      assisting_participant_ids_candidate: 'paired 0x040a/44 shapes at a validated death core and all ten ASSISTS tails; per-death attribution candidate only',
      die_source_network_id_candidate: 'exact 821 0x0438 terminal two-byte source field, 655/655 runtime match; killer participant requires all ten CHAMPIONS_KILLED tails',
      death_timer_seconds_candidate: 'exact 821 0x0259 deserializer f32; matched death core only, not a respawn prediction',
      observed_return_time: 'exact 821 0x0048 ReincarnateAlive route/f32 decode paired with death core and dead-time tail; co-timed 0x018d is inventory MapView fingerprint only',
      keyframe_deaths_snapshot:
        'exact 821 native 0x0089 carrier and vector byte transform at raw byte 1182; death-count semantic label candidate only',
      keyframe_champion_kills_snapshot:
        'exact 821 native 0x0089 carrier and vector byte transform at mirrored raw bytes 434/1186; kill-count semantic label candidate only',
      keyframe_assists_snapshot:
        'exact 821 native 0x0089 carrier and vector byte transform at raw byte 1178; assist-count semantic label candidate only',
      keyframe_missions_minions_killed_snapshot:
        'exact 821 runtime byte transform at 0x0089 raw bytes 374/373; Missions_MinionsKilled tail correlation only, distinct from MINIONS_KILLED',
      keyframe_ward_stats_snapshot:
        'exact 821 native 0x0089 carrier and vector bytes at raw offsets 834/838/842; three ward-tail semantic labels candidate only',
      keyframe_missions_cannon_minions_killed_snapshot:
        'exact 821 native 0x0089 carrier and vector byte at raw offset 450; Missions_CannonMinionsKilled semantic label candidate only',
      keyframe_minions_killed_snapshot:
        'exact 821 native 0x0089 vector f32LE at offset 0x3c; standard MINIONS_KILLED tail correlation only, distinct from Missions_MinionsKilled at 0x378',
      keyframe_jungle_minions_killed_snapshot:
        'exact 821 native 0x0089 vector f32LE at offsets 0x40/0x44/0x48; three neutral-minion Replay-tail correlations only, with raw fractional values and retained floor gaps',
      keyframe_kill_stats_snapshot:
        'exact 821 native 0x0089 vector aligned values at offsets 0x58..0x6c; six kill-stat Replay-tail correlations only, with sparse QUADRA_KILLS evidence',
      keyframe_float_snapshots:
        'exact 821 native 0x0089 carrier and reversed vector at offsets 0x28/0x1b0/0x38/0x34; EXP/VISION_SCORE/GOLD_EARNED/GOLD_SPENT semantic labels candidate only',
      keyframe_damage_float_snapshots:
        'exact 821 native 0x0089 carrier and reversed vector at offsets 0x1d0/0x1e0/0x1f0/0x200/0x208/0x210/0x214/0x218; damage-tail labels candidate only, with 0x210/0x214 mirror and building/turret ambiguity',
      keyframe_time_heal_epic_cc_snapshots:
        'exact 821 native 0x0089 carrier and reversed vector at offsets 0x244/0x248/0x234/0x23c/0x21c/0x230; Replay-tail labels candidate only',
      level_state: 'exact 821 PKT_NPC_LevelUp_s route and +0x11 byte transform; participant alignment and event interpretation candidate only',
      inventory_packet: 'exact 821 native 0x018d MapView record vector and slot/item transforms; exact-image callback resets slots 0–9 then applies records to a packet-local candidate slot snapshot; raw-param participant mapping candidate, with no between-packet state or transaction inference',
      inventory_broadcast_packet: 'exact 821 native 0x0357 SetInventory_Broadcast record vector and slot/item transforms; shared exact-image callback resets slots 0–9 then applies packet records; raw zero item values and omitted slots remain distinct, with no between-packet state or transaction inference',
      inventory_set_item_packet: 'exact 821 native 0x002d SetItem nested slot/item transform; observed slot 8 only and six item-definition keys; no purchase, sale, replacement, or between-packet state inference',
      params_heal_packet: 'exact 821 native 0x040a OnEvent packet and registered child 0x004b ParamsHeal; handler reads reported f32 at child +0x18; two u32 fields remain anonymous, with no effective-heal, caster, or target inference',
      shielding_params_packet_pair: 'exact 821 native 0x040a OnEvent child 0x00ef/0x00f0 registration and one-to-one packet-local blob pairing; callback reads anonymous fields, while raw f32 at child +0x10 is opaque; no shield generation, absorption, actor, or target inference',
      stealth_event_packet: 'exact 821 native 0x040a OnEvent child 0x0101/0x0102 registrations and event-name table; callback reads anonymous child +0x04 u32; no participant, visibility, or transition lifecycle inference',
      champion_die_event_packet: 'exact 821 native 0x040a OnEvent child 0x0004 ParamsDie registration and OnChampionDie name table; callback reads anonymous child +0x04 u32; no effective death, actor, or state transition inference',
      champion_kill_event_packet: 'exact 821 native 0x040a OnEvent child 0x0007 ParamsChampionKill registration and OnChampionKill name table; callback reads anonymous child +0x04/+0x58/+0x5c u32; no effective kill, actor, or state transition inference',
      champion_multiple_kill_event_packet: 'exact 821 native 0x040a OnEvent child 0x0009 ParamsKillingSpree registration and OnChampionMultipleKill name table; callback reads anonymous child +0x04/+0x08/+0x0c u32; no effective multikill, actor, or state transition inference',
      champion_double_kill_event_packet: 'exact 821 native 0x040a OnEvent child 0x000b and OnChampionDoubleKill name table; packet marker only, no callback-backed field, effective double kill, actor, or state transition inference',
      champion_triple_quadra_event_packet: 'exact 821 native 0x040a OnEvent children 0x000c/0x000d and OnChampionTripleKill/OnChampionQuadraKill name table; packet markers only, no effective kill streak, actor, or state transition inference',
      on_shutdown_event_packet: 'exact 821 native 0x040a OnEvent child 0x00e8 registration and OnShutdown name table; callback reads anonymous child +0x04/+0x58/+0x5c u32; no gameplay shutdown effect, actor, or state transition inference',
      resurrect_event_packet: 'exact 821 native 0x040a OnEvent child 0x002d registration and OnResurrect name table; native child +0x04/+0x08 u32 remain anonymous; no resurrection, actor, or state transition inference',
      turret_plate_event_packet: 'exact 821 native 0x040a OnEvent child 0x0107 and OnTurretPlateDestroyed name table; native child +0x04 u32 remains anonymous; no callback-field, structure, or game-state transition inference',
      cast_spell_ans_packet: 'exact 821 native 0x01da packet constructor/deserializer, callback transforms for opaque object offsets 0x148/0x14c, nested protected float at +0xe0 and byte at +0x140; no successful-cast, owner, target, spell, slot or field-meaning inference',
      npc_buff_remove_packet: 'exact 821 native 0x047c BuffRemove2 constructor/deserializer and callback transforms for opaque object offsets 0x10/0x14/0x18; no owner, buff identity, target or lifecycle inference',
      npc_buff_add_packet: 'exact 821 native 0x00ae BuffAdd2 constructor/deserializer and callback transforms for opaque object offsets 0x10/0x14; no owner, buff identity, target or lifecycle inference',
      npc_buff_update_num_counter_packet: 'exact 821 native 0x0194 BuffUpdateNumCounter constructor/deserializer and callback transforms for anonymous object offsets 0x10/0x14/0x18/0x1c; no owner, buff identity, target, counter meaning, or lifecycle inference',
      npc_buff_update_count_packet: 'exact 821 native 0x02d9 BuffUpdateCount constructor/deserializer and callback transforms for anonymous object offsets 0x10/0x11/0x14/0x18/0x1c; no owner, buff identity, target, counter meaning, or lifecycle inference',
      npc_buff_replace_packet: 'exact 821 native 0x01ad BuffReplace constructor/deserializer and callback transforms for anonymous object offsets 0x10/0x14/0x18/0x1c; no owner, buff identity, target, replacement effect, or lifecycle inference',
      set_spell_timer_from_buff_packet: 'exact 821 native 0x00fd SetSpellTimerFromBuff constructor/deserializer and callback transforms for anonymous object offsets 0x10/0x11/0x14/0x18/0x1c/0x20; no owner, buff identity, spell identity, timer effect, or lifecycle inference',
      set_spell_level_packet: 'exact 821 native 0x025d SetSpellLevel constructor/deserializer and callback transforms for anonymous object offsets 0x10/0x14; no owner, spell identity, level change, or lifecycle inference',
      direct_input_movement_turn_packet: 'exact 821 native 0x00ba DirectInputMovementDriverServerTurnData constructor/deserializer and callback transform for three opaque f32 fields at object offsets 0x10/0x14/0x18; no world-position, hero-path or participant inference',
      set_movement_driver_packet: 'exact 821 native 0x0335 SetMovementDriver constructor/deserializer and callback transform for opaque byte at object offset 0x2a; no driver-state transition, position, path or participant inference',
    },
    verified_capabilities: [],
    candidate_capabilities: [
      'hero_death', 'hero_assist', 'hero_death_timer', 'hero_respawn', 'hero_deaths_snapshot',
      'hero_champion_kills_snapshot', 'hero_assists_snapshot',
      'hero_missions_minions_killed_snapshot',
      'hero_ward_stats_snapshot', 'hero_missions_cannon_minions_killed_snapshot',
      'hero_minions_killed_snapshot',
      'hero_jungle_minions_killed_snapshot',
      'hero_kill_stats_snapshot',
      'hero_experience_snapshot', 'hero_vision_score_snapshot',
      'hero_gold_earned_snapshot', 'hero_gold_spent_snapshot',
      'hero_damage_totals_snapshot', 'hero_damage_taken_from_champions_snapshot',
      'hero_damage_self_mitigated_snapshot',
      'hero_structure_objective_damage_snapshot',
      'hero_longest_living_time_snapshot', 'hero_total_time_spent_dead_snapshot',
      'hero_total_heal_snapshot', 'hero_total_units_healed_snapshot',
      'hero_epic_monster_damage_snapshot', 'hero_crowd_control_time_snapshot',
      'hero_level_state', 'hero_inventory_packet',
      'hero_inventory_broadcast_packet',
      'hero_inventory_set_item_packet',
      'params_heal_packet',
      'shielding_params_packet_pair',
      'stealth_event_packet',
      'champion_die_event_packet',
      'champion_kill_event_packet',
      'champion_multiple_kill_event_packet',
      'champion_double_kill_event_packet',
      'champion_triple_quadra_event_packet',
      'on_shutdown_event_packet',
      'resurrect_event_packet',
      'turret_plate_event_packet',
      'cast_spell_ans_packet', 'npc_buff_remove_packet', 'npc_buff_add_packet',
      'npc_buff_update_num_counter_packet',
      'npc_buff_update_count_packet',
      'npc_buff_replace_packet',
      'set_spell_timer_from_buff_packet',
      'set_spell_level_packet',
      'direct_input_movement_turn_packet',
      'set_movement_driver_packet',
    ],
    unsupported_capabilities: [],
    validation_artifacts: [],
    regression_fixture_set: null,
  },
});

function versionFromInput(input) {
  if (typeof input === 'string') {
    if (Object.hasOwn(BUILD_PROFILES, input)) return input;
    if (fs.existsSync(input)) return parseReplayFile(path.resolve(input)).header.version;
    return input;
  }
  return input?.header?.version ?? input?.game_version ?? input?.replay_version ?? null;
}

function resolveBuildProfile(input) {
  const gameVersion = versionFromInput(input);
  const profile = BUILD_PROFILES[gameVersion] ?? null;
  if (!profile) {
    return {
      status: 'UNSUPPORTED_VERSION',
      game_version: gameVersion,
      profile: null,
    };
  }
  return {
    status: 'SUPPORTED',
    game_version: gameVersion,
    profile,
  };
}

function resolveCapability(input, capability) {
  const resolved = resolveBuildProfile(input);
  if (!resolved.profile) return { ...resolved, capability, capability_profile: null };
  const capabilityProfile = resolved.profile.decoder_profile[capability] ?? null;
  if (!capabilityProfile) {
    return {
      ...resolved,
      status: 'UNAVAILABLE',
      capability,
      capability_profile: null,
    };
  }
  return {
    ...resolved,
    status: capabilityProfile.enabled === false
      ? capabilityProfile.status
      : capabilityProfile.status ?? 'SEMANTIC_VERIFIED_DIRECT',
    capability,
    capability_profile: capabilityProfile,
  };
}

function rollingCompatibilityWindow(size = ROLLING_COMPATIBILITY_WINDOW) {
  if (!Number.isInteger(size) || size < 1) throw new TypeError('window size must be positive');
  return Object.values(BUILD_PROFILES)
    .sort((left, right) => right.game_version.localeCompare(left.game_version, undefined, {
      numeric: true,
    }))
    .slice(0, size)
    .map((profile, index) => ({
      position: index === 0 ? 'CURRENT' : `CURRENT-${index}`,
      game_version: profile.game_version,
      support_level: profile.support_level,
      release_status: profile.release_status,
    }));
}

module.exports = {
  BUILD_PROFILES,
  ROLLING_COMPATIBILITY_WINDOW,
  SUPPORT_LEVELS,
  resolveBuildProfile,
  resolveCapability,
  rollingCompatibilityWindow,
  versionFromInput,
};

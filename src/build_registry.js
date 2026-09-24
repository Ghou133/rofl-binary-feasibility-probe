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
      status: 'UNPROFILED',
      image_sha256: null,
    },
    packet_routes: {
      hero_death: 0x0259,
      hero_respawn: 0x0048,
      hero_deaths_snapshot: 0x0089,
      hero_champion_kills_snapshot: 0x0089,
      hero_level_state: 0x0197,
    },
    decoder_profile: {
      hero_death: decoder1619821.HERO_DEATH_CANDIDATE_PROFILE_821,
      hero_respawn: respawnCandidate1619821.HERO_RESPAWN_CANDIDATE_PROFILE_821,
      hero_deaths_snapshot:
        heroStatsCandidate1619821.HERO_DEATHS_SNAPSHOT_821_CANDIDATE_PROFILE,
      hero_champion_kills_snapshot:
        heroStatsCandidate1619821.HERO_CHAMPION_KILLS_SNAPSHOT_821_CANDIDATE_PROFILE,
      hero_level_state: levelCandidate1619821.HERO_LEVEL_CANDIDATE_PROFILE_821,
    },
    evidence_grades: {
      hero_death: 'CANDIDATE_821_REPLAY_TAIL_ROUTE_CORRELATION',
      hero_respawn: 'CANDIDATE_821_REPLAY_TAIL_DEAD_TIME_CORRELATION',
      hero_deaths_snapshot: 'CANDIDATE_821_RAW_BYTE_KEYFRAME_TAIL_CORRELATION',
      hero_champion_kills_snapshot: 'CANDIDATE_821_MIRRORED_RAW_BYTE_KEYFRAME_TAIL_CORRELATION',
      hero_level_state: 'CANDIDATE_821_LEVEL_ROUTE_TAIL_CODEBOOK',
    },
    semantic_mappings: {
      victim_participant: '(raw_param & 0xff) - 0xad, 821 route-profile bounded',
      observed_return_time: '0x0048 route uniquely paired with a matched death core and 0x018d support; candidate only',
      keyframe_deaths_snapshot:
        'exact 0x0089 raw byte 1182 finite codebook, 821 KR keyframe candidate only',
      keyframe_champion_kills_snapshot:
        'exact 0x0089 mirrored raw bytes 434/1186 finite codebook, 821 KR keyframe candidate only',
      level_state: 'exact 0x0197 full-param families and finite payload codebook, candidate only',
    },
    verified_capabilities: [],
    candidate_capabilities: [
      'hero_death', 'hero_respawn', 'hero_deaths_snapshot',
      'hero_champion_kills_snapshot', 'hero_level_state',
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

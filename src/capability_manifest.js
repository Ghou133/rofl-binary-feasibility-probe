'use strict';

const fs = require('node:fs');
const path = require('node:path');

const { BUILD_PROFILES, resolveBuildProfile } = require('./build_registry');

const CAPABILITY_MANIFEST_SCHEMA_VERSION = 'ROFL_CAPABILITY_MANIFEST_V2';
const SEMANTIC_COMPATIBILITY_MATRIX_SCHEMA_VERSION = 'ROFL_SEMANTIC_COMPATIBILITY_MATRIX_V2';
const CANONICAL_SEMANTIC_SCHEMA_VERSION = 'ROFL_SEMANTIC_SCHEMA_V2';
const MANIFEST_GENERATED_AT = '2026-08-20';
const EVIDENCE_GRADES = Object.freeze([
  'VERIFIED_DIRECT',
  'VERIFIED_DERIVED',
  'INFERRED',
  'CANDIDATE',
  'UNAVAILABLE',
  'UNVERIFIED',
]);
const VALIDATION_STATUSES = Object.freeze([
  'PASS', 'PARTIAL', 'CANDIDATE_ONLY', 'UNAVAILABLE', 'UNVERIFIED',
]);
const COMPATIBILITY_STATUSES = Object.freeze([
  'YES', 'NO', 'NOT_COMPARABLE', 'UNVERIFIED',
]);

const CAPABILITY_VOCABULARY = Object.freeze([
  'ROFL_CONTAINER', 'PACKET_FRAMING', 'PARTICIPANT_MAPPING',
  'HERO_PATH', 'HERO_DEATH', 'HERO_DEATH_TIMER', 'HERO_RESPAWN',
  'HERO_KILL_CREDIT', 'HERO_ASSIST',
  'LEVEL_TRANSITION',
  'WARD_SPAWN', 'WARD_LIFECYCLE', 'SWEEPER',
  'CAST_SPELL', 'MISSILE', 'ABILITY_COOLDOWN_BROADCAST',
  'MISSILE_SYNC_MOVEMENT_COMPLETE_COUNT',
  'DAMAGE', 'DAMAGE_TYPE', 'DAMAGE_SOURCE_ATTRIBUTION',
  'CURRENT_HP', 'MAX_HP', 'ARMOR', 'MAGIC_RESIST', 'ATTACK_DAMAGE',
  'ABILITY_POWER', 'MOVE_SPEED', 'ATTACK_SPEED', 'MANA', 'CURRENT_MANA',
  'MAX_MANA', 'TEMPORARY_HP', 'TEMPORARY_STATS', 'MOVEMENT_SPECIAL',
  'FACE_DIRECTION_VECTOR', 'INSTANT_STOP_ATTACK', 'BASIC_ATTACK_POSITION_MINION',
  'WALL_TRACKING_COMPONENT_CACHE_SNAPSHOT',
  'DAMAGE_STAGE', 'DAMAGE_MITIGATION',
  'BUFF', 'DEBUFF',
  'SHIELD_GENERATED', 'SHIELD_ABSORBED', 'SHIELD_REMAINING', 'SHIELD_LIFECYCLE',
  'HEAL_REPORTED', 'HEAL_EFFECTIVE', 'OVERHEAL',
  'ITEM_BUY', 'ITEM_SELL', 'ITEM_UNDO', 'ITEM_TRANSFORM', 'ITEM_DESTROY', 'ITEM_STATE',
  'ITEM_SWAP', 'ITEM_SUBSTITUTION_MAP', 'SUPPORT_QUEST_ITEM_STAGE',
  'SUMMONER_SPELL_STATE', 'SUMMONER_CAST', 'RUNE_STATE', 'RUNE_PROC',
  'PASSIVE_STATE', 'PASSIVE_PROC', 'VISIBILITY_STATE',
  'XP', 'GOLD', 'CS',
  'NPC_SPAWN', 'NPC_DEATH', 'NPC_DESPAWN', 'NPC_CLASSIFICATION',
  'LANE_MINION_LIFECYCLE', 'JUNGLE_MONSTER_LIFECYCLE', 'CAMP_CLEAR', 'CAMP_STATE',
  'OBJECTIVE', 'STRUCTURE', 'MAP_MECHANIC',
]);

const BUILD_16_15 = '16.15.801.3452';
const BUILD_16_16 = '16.16.805.0442';
const SEMANTIC_COMPATIBILITY_DECLARATIONS = Object.freeze({
  HERO_PATH: Object.freeze({
    status: 'YES',
    evidence: ['docs/PROTOCOL_VERSION_MATRIX.md', 'docs/semantic_compatibility.md'],
    rationale: 'Both exact-build decoders emit the canonical HeroPath semantic; routes and decoder profiles differ.',
  }),
  HERO_DEATH: Object.freeze({
    status: 'YES',
    evidence: [
      'artifacts/semantic_probe/death_validation_current/death_validation_summary.json',
      'artifacts/hero_combat_state_v2/death/death_16_16_route_anchor_validation.json',
    ],
    rationale: 'Both exact-build decoders emit the common hero-death occurrence, packet time, and victim participant subset; 16.16 additionally verifies killer, while routes and raw entity encoding details differ.',
  }),
  SHIELD_ABSORBED: Object.freeze({
    status: 'YES',
    evidence: [
      '.omo/evidence/quant_combat_closure/shield_absorbed_semantic_fingerprint.json',
      '.omo/evidence/quant_combat_closure/shield_absorbed_migration_oracle_decision.json',
      '.omo/evidence/quant_combat_closure/packet_01e1_shield_absorbed_direct.jsonl',
    ],
    rationale: 'Both exact-build decoders emit the same direct target-total absorbed-shield amount and target semantic; the route and callback inverse bindings differ, while source, instance and remaining state remain unavailable in both builds.',
  }),
  LEVEL_TRANSITION: Object.freeze({
    status: 'YES',
    evidence: ['docs/PROTOCOL_VERSION_MATRIX.md', 'docs/semantic_compatibility.md'],
    rationale: 'Both exact-build decoders emit canonical transition fields; LevelAfter remains separately build-bound.',
  }),
  WARD_SPAWN: Object.freeze({
    status: 'YES',
    evidence: ['docs/ROFL_CAPABILITY_MATRIX.md', 'docs/semantic_compatibility.md'],
    rationale: 'Both exact-build decoders emit the canonical WardSpawn semantic with documented direct/derived fields.',
  }),
  WARD_LIFECYCLE: Object.freeze({
    status: 'YES',
    evidence: ['docs/ROFL_CAPABILITY_MATRIX.md', 'docs/semantic_compatibility.md'],
    rationale: 'Both records are limited to conservative observed-end lifecycle semantics; neither declares an end reason.',
  }),
});

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function unavailable(capability, build, knownLimits = 'No exact-build verified Replay semantic has been recovered.') {
  return {
    semantic_capability: capability,
    build,
    protocol_route: null,
    packet_registration_route: null,
    decoder_version: null,
    field_mapping: {},
    evidence_grade: 'UNAVAILABLE',
    validation_status: 'UNAVAILABLE',
    sample_count: { replay_count: null, event_count: null, scope: 'NOT_MEASURED' },
    positive_examples: [],
    negative_examples: [],
    known_limits: [knownLimits, 'UNAVAILABLE does not assert protocol nonexistence.'],
    introduced_at: null,
    last_verified_at: null,
    canonical_schema_version: CANONICAL_SEMANTIC_SCHEMA_VERSION,
  };
}

function unverified(capability, build, knownLimits) {
  return {
    ...unavailable(capability, build, knownLimits),
    evidence_grade: 'UNVERIFIED',
    validation_status: 'UNVERIFIED',
    known_limits: [knownLimits, 'UNVERIFIED is not a zero-observation claim.'],
  };
}

function record(capability, build, values) {
  return {
    ...unavailable(capability, build),
    ...values,
    semantic_capability: capability,
    build,
    canonical_schema_version: CANONICAL_SEMANTIC_SCHEMA_VERSION,
  };
}

function probedCombatStateUnavailable(capability, knownLimit) {
  return record(capability, BUILD_16_15, {
    protocol_route: null,
    packet_registration_route: null,
    decoder_version: null,
    field_mapping: {},
    evidence_grade: 'UNAVAILABLE',
    validation_status: 'UNAVAILABLE',
    sample_count: {
      replay_count: 4,
      event_count: 6222445,
      scope: 'strict packet rows screened by the first-round exact-build combat-state candidate probe',
    },
    positive_examples: [],
    negative_examples: ['artifacts/semantic_coverage_v1/combat_candidate_report.json'],
    known_limits: [
      knownLimit,
      'Structural candidate routes do not identify a field and cannot populate the canonical value.',
      'UNAVAILABLE does not assert protocol nonexistence.',
    ],
    introduced_at: null,
    last_verified_at: '2026-08-20',
  });
}

const BUILD_RECORD_OVERRIDES = Object.freeze({
  [BUILD_16_15]: Object.freeze({
    ROFL_CONTAINER: record('ROFL_CONTAINER', BUILD_16_15, {
      decoder_version: 'src/rofl.js', evidence_grade: 'VERIFIED_DIRECT', validation_status: 'PASS',
      field_mapping: { header: 'direct', chunks: 'direct', zstd: 'direct' },
      sample_count: { replay_count: null, event_count: null, scope: 'REGISTERED_FORMAT' },
      positive_examples: ['artifacts/semantic_probe/damage_validation_summary.json'],
      known_limits: ['Container validation does not establish semantic-route compatibility.'],
      introduced_at: null, last_verified_at: null,
    }),
    PACKET_FRAMING: record('PACKET_FRAMING', BUILD_16_15, {
      decoder_version: 'src/rofl.js', evidence_grade: 'VERIFIED_DIRECT', validation_status: 'PASS',
      field_mapping: { packet_id: 'direct', timestamp_ms: 'direct', payload: 'direct' },
      sample_count: { replay_count: null, event_count: null, scope: 'REGISTERED_FORMAT' },
      positive_examples: ['src/rofl.js'], known_limits: ['Framing alone never authorizes semantic decoding.'],
      introduced_at: null, last_verified_at: null,
    }),
    PARTICIPANT_MAPPING: record('PARTICIPANT_MAPPING', BUILD_16_15, {
      protocol_route: 'metadata + exact champion network-id rule', decoder_version: 'rofl-16.15 participant mapping',
      field_mapping: { participant_id: 'low_byte(network_id) - 0xad', champion: 'Replay tail SKIN', team: 'Replay tail TEAM' },
      evidence_grade: 'VERIFIED_DIRECT', validation_status: 'PASS',
      sample_count: { replay_count: 4, event_count: 40, scope: 'damage validation participant-source and target coverage' },
      positive_examples: ['artifacts/semantic_probe/damage_validation_summary.json'],
      known_limits: ['Only the exact champion network-id range is promoted to a participant.'],
      introduced_at: null, last_verified_at: null,
    }),
    HERO_PATH: record('HERO_PATH', BUILD_16_15, {
      protocol_route: '0x02d1', packet_registration_route: '0x02d1', decoder_version: 'path_pipeline_v2',
      field_mapping: { entity: 'direct', speed: 'direct', encoded_waypoints: 'direct', game_coordinates: 'derived calibration' },
      evidence_grade: 'VERIFIED_DERIVED', validation_status: 'PASS',
      sample_count: { replay_count: null, event_count: null, scope: 'legacy frozen regression' },
      positive_examples: ['docs/ROFL_CAPABILITY_MATRIX.md'],
      known_limits: ['Coordinates/interpolation are derived; packet paths are not map or strategic labels.'],
      introduced_at: null, last_verified_at: null,
    }),
    HERO_DEATH: record('HERO_DEATH', BUILD_16_15, {
      protocol_route: '0x0160', packet_registration_route: '0x0160', decoder_version: 'rofl-16.15.801.3452-hero-death-v1',
      field_mapping: { replay_time_ms: 'direct', victim_network_id: 'direct', victim_participant: 'derived from exact id rule' },
      evidence_grade: 'VERIFIED_DIRECT', validation_status: 'PASS',
      sample_count: { replay_count: 4, event_count: 245, scope: 'exact death anchors' },
      positive_examples: ['artifacts/semantic_probe/death_validation_current/death_validation_summary.json'],
      negative_examples: ['No ordinary-monster death semantics are promoted.'],
      known_limits: ['Hero-only route; no killer or combat reconstruction fields.'],
      introduced_at: null, last_verified_at: null,
    }),
    LEVEL_TRANSITION: record('LEVEL_TRANSITION', BUILD_16_15, {
      protocol_route: '0x025a', packet_registration_route: '0x025a', decoder_version: 'rofl-16.15.801.3452-npc-level-up-unicorn-v1',
      field_mapping: { occurrence: 'direct', entity: 'direct', timestamp: 'direct', level_after: 'derived build-bound field_10 mapping' },
      evidence_grade: 'VERIFIED_DERIVED', validation_status: 'PASS',
      sample_count: { replay_count: null, event_count: null, scope: 'legacy exact-build profile' },
      positive_examples: ['docs/ROFL_CAPABILITY_MATRIX.md'],
      known_limits: ['Level-after mapping is build-bound; timestamp-zero initialization has level_after=null.'],
      introduced_at: null, last_verified_at: null,
    }),
    WARD_SPAWN: record('WARD_SPAWN', BUILD_16_15, {
      protocol_route: '0x0353', packet_registration_route: '0x0353', decoder_version: 'ward_pipeline_v2',
      field_mapping: { spawn_time: 'direct', owner: 'direct', position: 'direct', participant_team_type: 'derived' },
      evidence_grade: 'VERIFIED_DERIVED', validation_status: 'PASS',
      sample_count: { replay_count: null, event_count: 1357, scope: 'current Ward validation evidence' },
      positive_examples: ['artifacts/protection_v4_publication/regression_summary.json'],
      known_limits: ['Strategic location is outside Parser ownership.'], introduced_at: null, last_verified_at: null,
    }),
    WARD_LIFECYCLE: record('WARD_LIFECYCLE', BUILD_16_15, {
      decoder_version: 'ward_pipeline_v2', evidence_grade: 'VERIFIED_DERIVED', validation_status: 'PARTIAL',
      field_mapping: { observed_end: 'conservative corpse-derived match', end_reason: null },
      sample_count: { replay_count: null, event_count: null, scope: 'legacy conservative lifecycle' },
      positive_examples: ['docs/ROFL_CAPABILITY_MATRIX.md'],
      known_limits: ['Lifecycle is partial; end reason remains unknown.'], introduced_at: null, last_verified_at: null,
    }),
    CAST_SPELL: record('CAST_SPELL', BUILD_16_15, {
      protocol_route: '0x0459', packet_registration_route: '0x0459', decoder_version: 'rofl-16.15.801.3452-cast-spell-unicorn-v1',
      field_mapping: { caster: 'direct', spell_key: 'direct', targets: 'direct', spell_identifier_slot: 'derived dictionary' },
      evidence_grade: 'VERIFIED_DIRECT', validation_status: 'PASS',
      sample_count: { replay_count: null, event_count: null, scope: 'exact-build decoder profile' },
      positive_examples: ['src/decoders/rofl_16_15_801_3452.js'],
      known_limits: ['Spell attribution cannot be inferred from temporal proximity.'], introduced_at: null, last_verified_at: null,
    }),
    DAMAGE: record('DAMAGE', BUILD_16_15, {
      protocol_route: '0x028a', packet_registration_route: '0x028a', decoder_version: 'rofl-16.15.801.3452-unit-apply-damage-unicorn-v1',
      field_mapping: {
        replay_time_ms: 'direct', source_network_id: 'direct', target_network_id: 'direct',
        amount: 'direct recorded amount; pre/post-mitigation meaning unresolved',
        damage_type: 'direct field_21 mapping', spell_key: 'direct field_1c',
        critical_true: 'derived only when field_20 == 3',
      },
      evidence_grade: 'VERIFIED_DIRECT', validation_status: 'PASS',
      sample_count: { replay_count: 4, event_count: 220244, scope: 'fully consumed exact-build UnitApplyDamage packets' },
      positive_examples: [
        'artifacts/semantic_probe/damage_validation_summary.json',
        'research-v3/docs/COMBAT_RESEARCH_STATUS.md',
      ],
      known_limits: [
        'Recorded amount is not proven pre-mitigation, post-mitigation, or effective HP loss.',
        'Human-readable spell/basic-attack/item/rune/passive attribution remains unavailable in the base semantic API.',
      ],
      introduced_at: null, last_verified_at: null,
    }),
    DAMAGE_TYPE: record('DAMAGE_TYPE', BUILD_16_15, {
      protocol_route: '0x028a', packet_registration_route: '0x028a',
      decoder_version: 'rofl-16.15.801.3452-unit-apply-damage-unicorn-v1',
      field_mapping: { field_21_0: 'physical', field_21_1: 'magic', field_21_2: 'true' },
      evidence_grade: 'VERIFIED_DIRECT', validation_status: 'PASS',
      sample_count: {
        replay_count: 10,
        event_count: 27625,
        scope: 'champion-to-champion exact-build rows; 11423 physical, 12799 magic, 3403 true',
      },
      positive_examples: [
        'research-v3/docs/COMBAT_RESEARCH_STATUS.md',
        'research-v3/tests/test_combat_attribution.py',
      ],
      negative_examples: ['Unknown field_21 values remain null/UNAVAILABLE.'],
      known_limits: ['Mapping is exact-build only and does not authorize any 16.16 route.'],
      introduced_at: '2026-08-20', last_verified_at: '2026-08-20',
    }),
    DAMAGE_SOURCE_ATTRIBUTION: record('DAMAGE_SOURCE_ATTRIBUTION', BUILD_16_15, {
      protocol_route: '0x028a', decoder_version: 'rofl-16.15.801.3452-unit-apply-damage-unicorn-v1',
      field_mapping: {
        source_entity: 'direct', source_participant: 'derived when champion',
        spell_key: 'direct field_1c without human-readable identity',
        critical_true: 'derived only when field_20 == 3',
        source_type: null, spell_item_rune_passive: null,
      },
      evidence_grade: 'VERIFIED_DIRECT', validation_status: 'PARTIAL',
      sample_count: { replay_count: 4, event_count: 220244, scope: 'source entity only; attribution dimensions unverified' },
      positive_examples: [
        'artifacts/semantic_probe/damage_validation_summary.json',
        'research-v3/docs/COMBAT_RESEARCH_STATUS.md',
      ],
      known_limits: [
        'A direct source entity or script key is not a verified spell/basic/item/rune/passive classification.',
        'Human-readable spell and true-only basic-attack enrichment remain separate partial research.',
      ], introduced_at: null, last_verified_at: '2026-08-20',
    }),
    CURRENT_HP: probedCombatStateUnavailable(
      'CURRENT_HP',
      'No exact-build current-HP field was decoded; 0x03da and 0x00e7 remain structural live-family candidates only.',
    ),
    MAX_HP: probedCombatStateUnavailable(
      'MAX_HP',
      'No exact-build max-HP field was decoded; champion-bound keyframe families remain structural candidates only.',
    ),
    ARMOR: probedCombatStateUnavailable(
      'ARMOR',
      'No exact-build armor field was decoded; HeroStats/StatFormulaOutputs are name-only candidates.',
    ),
    MAGIC_RESIST: probedCombatStateUnavailable(
      'MAGIC_RESIST',
      'No exact-build magic-resist field was decoded; HeroStats/StatFormulaOutputs are name-only candidates.',
    ),
    BUFF: record('BUFF', BUILD_16_15, {
      protocol_route: '0x0406 / 0x0031 / 0x0256', packet_registration_route: '0x0406,0x0031,0x0256', decoder_version: 'rofl-16.15.801.3452-npc-buff-*-unicorn-v1',
      field_mapping: { operation: 'direct', target: 'direct', source: 'direct except remove', name_hash: 'direct for add/remove', stack_count: 'direct when present' },
      evidence_grade: 'VERIFIED_DIRECT', validation_status: 'PASS',
      sample_count: { replay_count: null, event_count: null, scope: 'exact-build decoder profile' },
      positive_examples: ['src/decoders/rofl_16_15_801_3452.js'],
      known_limits: ['Buff semantic category/name resolution and hidden/package fields remain unverified.'], introduced_at: null, last_verified_at: null,
    }),
    SHIELD_GENERATED: record('SHIELD_GENERATED', BUILD_16_15, {
      protocol_route: '0x009e / event 0x00ed', packet_registration_route: 'PKT_OnEvent_s', decoder_version: 'rofl-16.15.801.3452-on-event-protection-v4',
      field_mapping: { source_network_id: '+0x08 u32', target_network_id: '+0x0c u32', generated_amount: '+0x10 f32' },
      evidence_grade: 'VERIFIED_DIRECT', validation_status: 'PASS',
      sample_count: { replay_count: 14, event_count: null, scope: 'Protection V4 exact route corpus' },
      positive_examples: ['artifacts/protection_v4_probe/protection_v4_field_contract.json'],
      known_limits: ['Shield instance and remaining amount are unavailable.'], introduced_at: null, last_verified_at: null,
    }),
    SHIELD_ABSORBED: record('SHIELD_ABSORBED', BUILD_16_15, {
      protocol_route: '0x0017', packet_registration_route: 'PKT_UnitApplyShieldDamage_s', decoder_version: 'rofl-16.15.801.3452-unit-apply-shield-damage-v4',
      field_mapping: { target_network_id: '+0x14/+0x1c u32', absorbed_amount: '+0x18 f32', source_or_instance: null },
      evidence_grade: 'VERIFIED_DIRECT', validation_status: 'PASS',
      sample_count: { replay_count: 14, event_count: 2, scope: 'fully consumed target-total absorption rows' },
      positive_examples: ['artifacts/protection_v4_probe/protection_v4_field_contract.json'],
      known_limits: ['Direct target-total only; source and shield-instance attribution are unavailable.'], introduced_at: null, last_verified_at: null,
    }),
    HEAL_REPORTED: record('HEAL_REPORTED', BUILD_16_15, {
      protocol_route: '0x009e / event 0x004b', packet_registration_route: 'PKT_OnEvent_s', decoder_version: 'rofl-16.15.801.3452-on-event-protection-v4',
      field_mapping: { target_network_id: '+0x04 u32', source_network_id: '+0x14 u32', reported_amount: '+0x18 f32' },
      evidence_grade: 'VERIFIED_DIRECT', validation_status: 'PASS',
      sample_count: { replay_count: 14, event_count: 81652, scope: 'raw reported-heal occurrences' },
      positive_examples: ['docs/PROTECTION_V4_CAPABILITY_MATRIX.md'],
      known_limits: ['Reported amount is not proven raw/effective healing; rows are preserved without silent deduplication.'], introduced_at: null, last_verified_at: null,
    }),
  }),
  [BUILD_16_16]: Object.freeze({
    ROFL_CONTAINER: record('ROFL_CONTAINER', BUILD_16_16, {
      decoder_version: 'src/rofl.js', evidence_grade: 'VERIFIED_DIRECT', validation_status: 'PASS',
      field_mapping: { header: 'direct', chunks: 'direct', zstd: 'direct' },
      sample_count: { replay_count: 40, event_count: 55552224, scope: 'strict framed blocks' },
      positive_examples: ['artifacts/new_build_rofl_compatibility_gate_v1/core_compatibility_summary.json'],
      known_limits: ['Container validation does not establish semantic-route compatibility.'], introduced_at: null, last_verified_at: null,
    }),
    PACKET_FRAMING: record('PACKET_FRAMING', BUILD_16_16, {
      decoder_version: 'src/rofl.js', evidence_grade: 'VERIFIED_DIRECT', validation_status: 'PASS',
      field_mapping: { packet_id: 'direct', timestamp_ms: 'direct', payload: 'direct' },
      sample_count: { replay_count: 40, event_count: 55552224, scope: 'strict framed blocks; zero framing errors' },
      positive_examples: ['artifacts/new_build_rofl_compatibility_gate_v1/core_compatibility_summary.json'],
      known_limits: ['Framing alone never authorizes semantic decoding.'], introduced_at: null, last_verified_at: null,
    }),
    PARTICIPANT_MAPPING: record('PARTICIPANT_MAPPING', BUILD_16_16, {
      protocol_route: 'Replay tail + network_id - 0x400000ad', decoder_version: 'rofl-16.16.805.0442-champion-network-id-v1',
      field_mapping: { participant_id: 'network_id - 0x400000ad', champion: 'Replay tail SKIN', team: 'Replay tail TEAM' },
      evidence_grade: 'VERIFIED_DIRECT', validation_status: 'PASS',
      sample_count: { replay_count: 8, event_count: 80, scope: 'all ten participants in eight HeroPath replays' },
      positive_examples: ['artifacts/multi_build_rofl_support_v1/hero_path_validation/hero_path_validation_summary.json'],
      known_limits: ['Exact champion range only.'], introduced_at: null, last_verified_at: null,
    }),
    HERO_PATH: record('HERO_PATH', BUILD_16_16, {
      protocol_route: '0x00f6', packet_registration_route: '0x00f6', decoder_version: 'rofl-16.16.805.0442-path-packet-unicorn-v1',
      field_mapping: { entity: 'direct', speed: 'runtime decoded', encoded_waypoints: 'runtime decoded', game_coordinates: 'derived calibration' },
      evidence_grade: 'VERIFIED_DERIVED', validation_status: 'PASS',
      sample_count: { replay_count: 8, event_count: 18001, scope: 'fully consumed exact-route packets' },
      positive_examples: ['artifacts/multi_build_rofl_support_v1/hero_path_validation/hero_path_validation_summary.json'],
      negative_examples: ['0x02d1 observed zero times in 40-replay 16.16 strict scan.'],
      known_limits: ['Coordinates are derived and build-bound; path is not a strategic-region label.'], introduced_at: null, last_verified_at: null,
    }),
    HERO_DEATH: record('HERO_DEATH', BUILD_16_16, {
      protocol_route: '0x0112',
      packet_registration_route: '0x0112 PKT_NPC_Hero_Die_s',
      decoder_version: 'rofl-16.16.805.0442-hero-death-unicorn-v2',
      field_mapping: {
        occurrence: 'direct exact route',
        replay_time_ms: 'direct packet timestamp',
        raw_victim_entity_param: 'direct raw_param with upper bytes retained as unknown',
        victim_participant: 'derived exact-build (raw_param & 0xff) - 0xad',
        killer_storage_field: 'direct runtime-decoded object +0x18',
        killer_network_id: 'direct after exact helper 0x00e639c0 inverse',
        killer_participant: 'derived exact-build killer_network_id - 0x400000ad',
      },
      evidence_grade: 'VERIFIED_DIRECT',
      validation_status: 'PASS',
      sample_count: {
        replay_count: 4,
        event_count: 301,
        scope: '301/301 exact runtime full-consume packets matched DETAILS victim and killer across all ten participants at 0-1ms',
      },
      positive_examples: [
        'artifacts/hero_combat_state_v2/death/death_16_16_route_anchor_validation.json',
        'artifacts/full_semantic_baseline_v1/runtime_candidates/packet_0112_p0_semantic_differential_16_16.json',
        'artifacts/full_semantic_baseline_v1/runtime_candidates/buff_spell_item_runtime_candidates_16_16.json',
      ],
      negative_examples: [
        'No NPC, minion, monster, structure, or objective death semantic is promoted.',
      ],
      known_limits: [
        'raw_param upper-byte variants are preserved and not semantically named.',
        'Killer is verified only through the exact-build helper inverse; raw storage is retained.',
        'Assists, kill-credit semantics, and all other inner payload fields remain unavailable or unknown; exact respawn occurrence is published separately from route 0x0265.',
        '242 nonempty-assist counterexamples reject zero/scalar/bitmask/fixed-triplet assist interpretations.',
        'Hero-only validation does not establish any non-hero entity lifecycle.',
      ],
      introduced_at: '2026-08-20',
      last_verified_at: '2026-08-20',
    }),
    HERO_DEATH_TIMER: record('HERO_DEATH_TIMER', BUILD_16_16, {
      protocol_route: '0x0074',
      packet_registration_route: '0x0074 PKT_S2C_UpdateDeathTimer_s',
      decoder_version: 'rofl-16.16.805.0442-hero-death-timer-v1',
      field_mapping: {
        subject_entity_id: 'direct raw packet parameter',
        replay_time_ms: 'direct packet timestamp',
        death_timer_seconds: 'direct f32 after exact receive-side byte inverse',
        respawn_timestamp_ms: null,
      },
      evidence_grade: 'VERIFIED_DIRECT',
      validation_status: 'PASS',
      sample_count: {
        replay_count: 8,
        event_count: 608,
        scope: '608/608 exact runtime full-consume rows; finite inverse values; P0 Talon death anchor at +1ms with 12 seconds',
      },
      positive_examples: [
        'artifacts/full_semantic_deep_recovery_v2/hero_state/hero_state_damage_defense_deep_report_16_16.json',
        'artifacts/full_semantic_deep_recovery_v2/hero_state/packet_0074_death_timer_events.jsonl',
      ],
      negative_examples: [
        'Timer values are not converted into exact respawn timestamps.',
      ],
      known_limits: [
        'The published value is a death-timer update, not an exact respawn event or timestamp.',
        'Non-champion routing rows retain UNKNOWN entity classification.',
      ],
      introduced_at: '2026-08-20',
      last_verified_at: '2026-08-20',
    }),
    HERO_RESPAWN: record('HERO_RESPAWN', BUILD_16_16, {
      protocol_route: '0x0265',
      packet_registration_route: '0x0265 PKT_HeroReincarnateAlive_s / AIHeroClient',
      decoder_version: 'rofl-16.16.805.0442-hero-reincarnate-alive-v1',
      field_mapping: {
        occurrence: 'direct exact HeroReincarnateAlive callback route',
        replay_time_ms: 'direct packet timestamp and exact respawn occurrence time',
        raw_subject_entity_param: 'direct full raw_param retained',
        participant_id: 'derived exact-build (raw_param & 0xff) - 0xad',
        position_xz: 'direct after exact callback protected-field byte inverse',
        position_y: 'derived callback constant zero',
        reincarnate_scalar: 'direct float with UNKNOWN resource-like semantic role',
      },
      evidence_grade: 'VERIFIED_DIRECT',
      validation_status: 'PASS',
      sample_count: {
        replay_count: 4,
        event_count: 282,
        scope: '282/282 exact native full-consume rows; each uniquely follows one of 301 safe P0 deaths, while all 19 deaths without a row are participant-final terminal deaths',
      },
      positive_examples: [
        'artifacts/full_semantic_deep_recovery_v2/hero_respawn/hero_reincarnate_alive_audit_16_16.json',
        'artifacts/full_semantic_deep_recovery_v2/hero_respawn/hero_reincarnate_alive_events_16_16.jsonl',
      ],
      negative_examples: [
        'The third float is not promoted to current/max/seed resource: Yone and level/item boundary rows reject a universal powerMax interpretation.',
      ],
      known_limits: [
        'Exact-build only; the full raw entity parameter is retained beside the participant derivation.',
        'Coordinates are protocol values and do not carry map-region, base, or strategic semantics.',
        'Reincarnate scalar current/max/seed resource role remains CANDIDATE.',
      ],
      introduced_at: '2026-08-20',
      last_verified_at: '2026-08-20',
    }),
    LEVEL_TRANSITION: record('LEVEL_TRANSITION', BUILD_16_16, {
      protocol_route: '0x0314', packet_registration_route: '0x0314', decoder_version: 'rofl-16.16.805.0442-level-transition-unicorn-v1',
      field_mapping: { occurrence: 'direct', entity: 'direct', timestamp: 'direct', level_after: 'derived build-bound raw_field_10 mapping' },
      evidence_grade: 'VERIFIED_DERIVED', validation_status: 'PASS',
      sample_count: { replay_count: 20, event_count: 2325, scope: 'fully consumed champion-param packets' },
      positive_examples: ['artifacts/multi_build_rofl_support_v1/level_transition_validation/level_transition_validation_summary.json'],
      negative_examples: ['0x01e8 explicitly rejected.'],
      known_limits: ['Level-after is build-bound; unmapped initialization is null/UNAVAILABLE.'], introduced_at: null, last_verified_at: null,
    }),
    WARD_SPAWN: record('WARD_SPAWN', BUILD_16_16, {
      protocol_route: '0x049a', packet_registration_route: '0x049a broad entity route', decoder_version: 'rofl-16.16.805.0442-ward-spawn-unicorn-v1',
      field_mapping: { spawn_time: 'direct', position: 'direct', owner_entity: 'direct', entity_network_id: 'direct', participant_team_type: 'derived' },
      evidence_grade: 'VERIFIED_DERIVED', validation_status: 'PASS',
      sample_count: { replay_count: 20, event_count: 2252, scope: 'confirmed player-active wards; 31862 fully consumed entity rows' },
      positive_examples: ['artifacts/16_16_ward_semantic_recovery_v1/runtime/ward_validation_summary.json'],
      negative_examples: ['0x0353 observed zero times in 40-replay 16.16 strict scan.'],
      known_limits: ['Special/map/unknown entities remain retained and must not be promoted to player Wards.'], introduced_at: null, last_verified_at: null,
    }),
    WARD_LIFECYCLE: record('WARD_LIFECYCLE', BUILD_16_16, {
      protocol_route: '0x049a corpse subset', decoder_version: 'rofl-16.16.805.0442-ward-spawn-unicorn-v1',
      field_mapping: { observed_end: 'partial derived match to direct corpse signal', end_reason: null },
      evidence_grade: 'VERIFIED_DERIVED', validation_status: 'PARTIAL',
      sample_count: { replay_count: 20, event_count: 1128, scope: 'conservative observed lifecycle ends' },
      positive_examples: ['artifacts/16_16_ward_semantic_recovery_v1/runtime/ward_validation_summary.json'],
      known_limits: ['End reason is UNKNOWN; estimated ends are never emitted.'], introduced_at: null, last_verified_at: null,
    }),
    SWEEPER: unverified('SWEEPER', BUILD_16_16, 'Held/trinket state lacks a verified route; activation, interval, owner and position are unavailable.'),
    DAMAGE: record('DAMAGE', BUILD_16_16, {
      protocol_route: '0x017f', packet_registration_route: '0x017f PKT_UnitApplyDamage_s',
      decoder_version: 'rofl-16.16.805.0442-unit-apply-damage-unicorn-v1',
      field_mapping: {
        replay_time_ms: 'direct packet timestamp',
        source_network_id: 'direct decoded object +0x10',
        target_network_id: 'direct decoded object +0x14',
        amount: 'direct decoded object +0x24; semantic stage unknown',
        damage_type: 'direct decoded object +0x28 mapping',
      },
      evidence_grade: 'VERIFIED_DIRECT', validation_status: 'PASS',
      sample_count: {
        replay_count: 4,
        event_count: 266332,
        scope: 'all observed 0x017f rows in latest-four exact-build Replays; 266332/266332 exact runtime full consume',
      },
      positive_examples: [
        'artifacts/hero_combat_state_v2/runtime/hero_combat_state_runtime_trace_16_16.json',
        'artifacts/hero_combat_state_v2/emulation/packet_017f_latest_four_summary.json',
        'artifacts/hero_combat_state_v2/damage/damage_16_16_anchor_validation.json',
      ],
      known_limits: [
        'Recorded amount is not proven pre-mitigation, post-mitigation, or effective HP loss.',
        'Numeric protocol identifiers are retained but not promoted to spell/basic/item/rune/passive attribution.',
      ], introduced_at: '2026-08-20', last_verified_at: '2026-08-20',
    }),
    DAMAGE_TYPE: record('DAMAGE_TYPE', BUILD_16_16, {
      protocol_route: '0x017f', packet_registration_route: '0x017f PKT_UnitApplyDamage_s',
      decoder_version: 'rofl-16.16.805.0442-unit-apply-damage-unicorn-v1',
      field_mapping: { field_28_0: 'physical', field_28_1: 'magic', field_28_2: 'true' },
      evidence_grade: 'VERIFIED_DIRECT', validation_status: 'PASS',
      sample_count: {
        replay_count: 1,
        event_count: 6,
        scope: 'one-to-one DETAILS anchor matches selected without using type code; 2 physical, 2 magic, 2 true, zero mismatches',
      },
      positive_examples: ['artifacts/hero_combat_state_v2/damage/damage_16_16_anchor_validation.json'],
      negative_examples: ['Unknown field_28 values remain null/UNKNOWN.'],
      known_limits: ['Mapping is exact-build only; it does not classify damage source kind.'],
      introduced_at: '2026-08-20', last_verified_at: '2026-08-20',
    }),
    DAMAGE_SOURCE_ATTRIBUTION: record('DAMAGE_SOURCE_ATTRIBUTION', BUILD_16_16, {
      protocol_route: '0x017f', packet_registration_route: '0x017f PKT_UnitApplyDamage_s',
      decoder_version: 'rofl-16.16.805.0442-unit-apply-damage-unicorn-v1',
      field_mapping: {
        source_entity: 'direct object +0x10',
        source_participant: 'derived only for exact champion network-id range',
        numeric_protocol_identifiers: 'direct retained fields +0x1c/+0x30 with semantics unknown',
        spell_item_rune_passive: null,
      },
      evidence_grade: 'VERIFIED_DIRECT', validation_status: 'PARTIAL',
      sample_count: {
        replay_count: 4,
        event_count: 266332,
        scope: 'direct source entity retained for every exact full-consume row; participant only when champion',
      },
      positive_examples: [
        'artifacts/hero_combat_state_v2/emulation/packet_017f_latest_four_summary.json',
        'artifacts/hero_combat_state_v2/damage/damage_16_16_anchor_validation.json',
      ],
      known_limits: [
        'A source entity and unidentified numeric fields do not prove spell/basic/item/rune/passive classification.',
        'Non-champion entities remain UNKNOWN_ENTITY until independently classified.',
      ], introduced_at: '2026-08-20', last_verified_at: '2026-08-20',
    }),
    BUFF: record('BUFF', BUILD_16_16, {
      protocol_route: '0x0326 / 0x0123 / 0x041f / 0x043c / 0x045b',
      packet_registration_route: 'BuffManagerClient exact callback family',
      decoder_version: 'rofl-16.16.805.0442-buff-manager-deep-v1',
      field_mapping: {
        operation: 'direct exact route: add/update-count/update-counter/replace/remove',
        routing_entity_id: 'direct callback routing entity; not renamed gameplay target',
        slot_or_index: 'direct callback argument',
        numeric_buff_identifier: 'direct cross-operation stable field where present',
        source_entity_id: null,
        stack_count: null,
        duration_seconds: null,
      },
      evidence_grade: 'VERIFIED_DIRECT',
      validation_status: 'PARTIAL',
      sample_count: {
        replay_count: 4,
        event_count: 354854,
        scope: '354854/354854 native full-consume rows across five operation routes',
      },
      positive_examples: [
        'artifacts/full_semantic_deep_recovery_v2/buff_spell/PROMOTION_MATRIX.json',
        'artifacts/full_semantic_deep_recovery_v2/buff_spell/buff_spell_damage_deep_analysis_latest_four.json',
      ],
      negative_examples: [
        '1861 first-update counterexamples reject add+0x02 as a universal gameplay stack field.',
        'Keyframe and persistent rows reject universal duration/expiry roles.',
      ],
      known_limits: [
        'Routing entity is retained separately from gameplay subject/target semantics.',
        'Human-readable buff identity, source causality, universal stack, duration and expiry remain unavailable.',
      ],
      introduced_at: '2026-08-20', last_verified_at: '2026-08-20',
    }),
    CAST_SPELL: record('CAST_SPELL', BUILD_16_16, {
      protocol_route: '0x01cf',
      packet_registration_route: '0x01cf PKT_NPC_CastSpellAns_s / SpellbookClient',
      decoder_version: 'rofl-16.16.805.0442-cast-occurrence-translator-v1',
      field_mapping: {
        occurrence: 'direct exact route',
        numeric_spell_key: 'direct exact translator field',
        caster_name: 'direct exact translator string',
        caster_entity_id: 'derived only when exact replay participant name cross-check passes',
        target_entity_id: null,
        damage_causality: null,
      },
      evidence_grade: 'VERIFIED_DIRECT',
      validation_status: 'PARTIAL',
      sample_count: {
        replay_count: 4,
        event_count: 21013,
        scope: '21013/21013 exact full-consume cast occurrence rows; 16439 participant name matches and 192 retained mismatches',
      },
      positive_examples: [
        'artifacts/full_semantic_deep_recovery_v2/buff_spell/PROMOTION_MATRIX.json',
      ],
      negative_examples: [
        'Only 31.05% of casts have an exact-key caster-or-chain-owner Damage row within two seconds.',
        'Near-time Missile neighborhoods are overwhelmingly ambiguous.',
      ],
      known_limits: [
        'The numeric spell key is not a human-readable ability identity.',
        'Target, channel/recast, cast result, missile ownership and damage causality remain unavailable.',
      ],
      introduced_at: '2026-08-20', last_verified_at: '2026-08-20',
    }),
    HEAL_REPORTED: record('HEAL_REPORTED', BUILD_16_16, {
      protocol_route: '0x0371',
      packet_registration_route: 'PKT_OnEvent_s / OnCastHeal / ParamsHeal',
      decoder_version: 'rofl-16.16.805.0442-on-event-protection-v1',
      field_mapping: {
        source_entity_id: 'direct exact parameter layout',
        target_entity_id: 'direct exact parameter layout',
        event_selector: 'direct exact event id 0x004b inside PKT_OnEvent_s',
        reported_amount: 'direct reported-or-gross f32 amount',
        effective_amount: null,
        overheal_amount: null,
      },
      evidence_grade: 'VERIFIED_DIRECT',
      validation_status: 'PASS',
      sample_count: {
        replay_count: 4,
        event_count: 28404,
        scope: '28404 exact schema/size rows; 37/40 participant source totals within 10% and 40/40 within 25% of SUMMARY totalHeal',
      },
      positive_examples: ['artifacts/full_semantic_deep_recovery_v2/buff_spell/PROMOTION_MATRIX.json'],
      negative_examples: ['No effective-heal or overheal ground truth is present in the exact Replay corpus.'],
      known_limits: [
        'Amount is reported or gross healing, never effective post-overheal healing.',
        'Effective heal and overheal remain unavailable.',
      ],
      introduced_at: '2026-08-20', last_verified_at: '2026-08-20',
    }),
    SHIELD_GENERATED: record('SHIELD_GENERATED', BUILD_16_16, {
      protocol_route: '0x0371',
      packet_registration_route: 'PKT_OnEvent_s / OnReceiveShield + OnGrantShield',
      decoder_version: 'rofl-16.16.805.0442-on-event-protection-v1',
      field_mapping: {
        source_entity_id: 'direct exact parameter layout',
        target_entity_id: 'direct exact parameter layout',
        event_selector: 'direct 0x00ed; exact duplicate 0x00ee is suppressed canonically',
        generated_or_application_amount: 'direct f32 amount',
        shield_absorbed: null,
        shield_remaining: null,
      },
      evidence_grade: 'VERIFIED_DIRECT',
      validation_status: 'PASS',
      sample_count: {
        replay_count: 4,
        event_count: 1107,
        scope: '1107 receive/application rows paired one-to-one with 1107 byte-identical grant duplicates',
      },
      positive_examples: ['artifacts/full_semantic_deep_recovery_v2/buff_spell/PROMOTION_MATRIX.json'],
      negative_examples: [
        'Twenty participant sources have positive raw amounts with zero independent absorbed-shield anchors.',
      ],
      known_limits: [
        'Amount is application/generated shield, not absorbed or remaining shield.',
        '0x00ee is suppressed only under the exact duplicate-pair gate; unpaired rows fail closed.',
      ],
      introduced_at: '2026-08-20', last_verified_at: '2026-08-20',
    }),
    SHIELD_ABSORBED: record('SHIELD_ABSORBED', BUILD_16_16, {
      protocol_route: '0x01e1',
      packet_registration_route: 'PKT_UnitApplyShieldDamage_s / AIBaseClient',
      decoder_version: 'rofl-16.16.805.0442-unit-apply-shield-damage-callback-inverse-v1',
      field_mapping: {
        target_network_id: 'direct duplicate callback-inverse object +0x18/+0x1c u32',
        absorbed_amount: 'direct callback-inverse object +0x10 f32',
        source_or_instance: null,
      },
      evidence_grade: 'VERIFIED_DIRECT', validation_status: 'PASS',
      sample_count: {
        replay_count: 4, event_count: 12,
        scope: '12/12 exact runtime full-consume rows; duplicate target fields agree and match canonical raw target; amounts finite positive',
      },
      positive_examples: [
        '.omo/evidence/quant_combat_closure/packet_01e1_shield_absorbed_direct.jsonl',
        '.omo/evidence/quant_combat_closure/shield_route_migration_scan.json',
      ],
      known_limits: [
        'Direct target-total only; source and shield-instance attribution are unavailable.',
        'This event does not expose shield remaining or application/expiry/replacement state.',
      ],
      introduced_at: '2026-08-21', last_verified_at: '2026-08-21',
    }),
    ITEM_BUY: record('ITEM_BUY', BUILD_16_16, {
      protocol_route: '0x0137 candidate subset',
      packet_registration_route: '0x0137 PKT_BuyItemAns_s / HeroInventoryClient',
      decoder_version: null,
      field_mapping: {
        item_id: 'bounded per-packet outer +0x24 u32 field; route semantic remains candidate',
        participant_candidate: 'exact-build derived (raw_param & 0xff) - 0xad; full raw_param retained',
      },
      evidence_grade: 'CANDIDATE',
      validation_status: 'CANDIDATE_ONLY',
      sample_count: {
        replay_count: 4,
        event_count: 1601,
        scope: '1601/1601 exact runtime full-consume; 1154/1168 DETAILS purchases matched at 0-2ms, with 447 route extras and 14 DETAILS misses',
      },
      positive_examples: [
        'artifacts/full_semantic_baseline_v1/runtime_candidates/packet_0137_04b3_item_route_differential_16_16.json',
      ],
      negative_examples: [
        '447 unmatched 0x0137 rows and 14 unmatched DETAILS purchases forbid route-level ITEM_BUY publication.',
        'Boolean fields have both matched-false and unmatched-true counterexamples.',
      ],
      known_limits: [
        'The bounded item_id field does not classify the whole route as a purchase event.',
        'No canonical ItemEvent is emitted from this candidate.',
      ],
      introduced_at: null,
      last_verified_at: '2026-08-20',
    }),
    ITEM_SELL: record('ITEM_SELL', BUILD_16_16, {
      protocol_route: '0x04b3 candidate subset',
      packet_registration_route: '0x04b3 PKT_RemoveItemAns_s / HeroInventoryClient',
      decoder_version: null,
      field_mapping: {
        participant_candidate: 'exact-build derived (raw_param & 0xff) - 0xad; full raw_param retained',
        item_id: null,
      },
      evidence_grade: 'CANDIDATE',
      validation_status: 'CANDIDATE_ONLY',
      sample_count: {
        replay_count: 4,
        event_count: 1013,
        scope: '1013/1013 exact runtime full-consume; all 60 DETAILS sales align at 0-1ms, but 953 route rows are non-sale',
      },
      positive_examples: [
        'artifacts/full_semantic_baseline_v1/runtime_candidates/packet_0137_04b3_item_route_differential_16_16.json',
      ],
      negative_examples: [
        '953 non-sale rows and 219 true-flag non-sale rows forbid route/flag ITEM_SELL naming.',
        'The packet carries no direct item ID.',
      ],
      known_limits: [
        'ITEM_SOLD is an aligned subset of a generic removal route, not the route semantic.',
        'No canonical ItemEvent is emitted from this candidate.',
      ],
      introduced_at: null,
      last_verified_at: '2026-08-20',
    }),
    ITEM_UNDO: record('ITEM_UNDO', BUILD_16_16, {
      protocol_route: null,
      packet_registration_route: null,
      decoder_version: null,
      field_mapping: {},
      evidence_grade: 'UNAVAILABLE',
      validation_status: 'UNAVAILABLE',
      sample_count: {
        replay_count: 4,
        event_count: 52,
        scope: '52 safe DETAILS ITEM_UNDO anchors; zero direct 0x0137/0x04b3 matches within the bounded window',
      },
      positive_examples: [],
      negative_examples: [
        'artifacts/full_semantic_baseline_v1/runtime_candidates/packet_0137_04b3_item_route_differential_16_16.json',
      ],
      known_limits: [
        'Negative evidence is limited to 0x0137 and 0x04b3 and does not prove protocol nonexistence.',
        'A dedicated undo callback/route remains to be recovered.',
      ],
      introduced_at: null,
      last_verified_at: '2026-08-20',
    }),
    ITEM_TRANSFORM: record('ITEM_TRANSFORM', BUILD_16_16, {
      protocol_route: null,
      packet_registration_route: null,
      decoder_version: null,
      field_mapping: {},
      evidence_grade: 'UNAVAILABLE',
      validation_status: 'UNAVAILABLE',
      sample_count: {
        replay_count: 4,
        event_count: 684,
        scope: 'purchase-coincident generic removals retained as component-consumption candidates only',
      },
      positive_examples: [],
      negative_examples: [
        'artifacts/full_semantic_baseline_v1/runtime_candidates/packet_0137_04b3_item_route_differential_16_16.json',
      ],
      known_limits: [
        'No transform or recipe semantic is published without an independent exact-build item recipe graph.',
        'UNAVAILABLE does not assert protocol nonexistence.',
      ],
      introduced_at: null,
      last_verified_at: '2026-08-20',
    }),
    ITEM_STATE: record('ITEM_STATE', BUILD_16_16, {
      protocol_route: '0x0311 / 0x02ea snapshots; 0x006c special-slot set',
      packet_registration_route: 'PKT_S2C_SetInventory_Broadcast_s / PKT_S2C_SetInventory_MapView_s / PKT_SetItem_s',
      decoder_version: 'rofl-16.16.805.0442-inventory-snapshot-layout-v1',
      field_mapping: {
        subject_entity_id: 'direct raw packet parameter',
        operation: 'direct exact snapshot/set route',
        item_id: 'direct after exact runtime inverse',
        slot_index: 'direct after exact runtime inverse',
        stack_count: 'direct after exact runtime inverse',
      },
      evidence_grade: 'VERIFIED_DIRECT',
      validation_status: 'PARTIAL',
      sample_count: {
        replay_count: 4,
        event_count: 1777,
        scope: '1271/1425 broadcast snapshots, 299/299 map-view snapshots, and 53/53 special-slot set rows full-consumed; 154 broadcast failures conserved',
      },
      positive_examples: [
        'artifacts/full_semantic_deep_recovery_v2/entity_item/entity_item_deep_recovery_summary_16_16.json',
      ],
      negative_examples: [
        '154 0x0311 rows retain explicit native-emulation failures and are never silently discarded.',
        'Keyframe snapshots can lag live game-stream mutations and are not injected as mutation commands.',
      ],
      known_limits: [
        'Only successful exact rows publish snapshot fields; failed rows remain raw/count-conserved.',
        'Snapshot/set operations do not identify buy, sell, undo, transform, or use causes.',
        'The neutral 0x0310 storage value is not universally named charges.',
      ],
      introduced_at: '2026-08-20',
      last_verified_at: '2026-08-20',
    }),
    ITEM_SWAP: record('ITEM_SWAP', BUILD_16_16, {
      protocol_route: '0x01e8',
      packet_registration_route: '0x01e8 PKT_SwapItemAns_s / HeroInventoryClient',
      decoder_version: 'rofl-16.16.805.0442-inventory-swap-v1',
      field_mapping: {
        subject_entity_id: 'direct raw packet parameter',
        first_slot_index: 'direct after exact runtime inverse',
        second_slot_index: 'direct after exact runtime inverse',
      },
      evidence_grade: 'VERIFIED_DIRECT', validation_status: 'PASS',
      sample_count: {
        replay_count: 4, event_count: 258,
        scope: '258/258 exact native full-consume rows; both selectors constrained to inventory slots 0..5',
      },
      positive_examples: [
        'artifacts/full_semantic_deep_recovery_v2/entity_item/entity_item_deep_recovery_summary_16_16.json',
      ],
      known_limits: ['The route does not carry item identity; no item identity is inferred from prior state.'],
      introduced_at: '2026-08-20', last_verified_at: '2026-08-20',
    }),
    ITEM_SUBSTITUTION_MAP: record('ITEM_SUBSTITUTION_MAP', BUILD_16_16, {
      protocol_route: '0x005a',
      packet_registration_route: 'PKT_S2C_ShopItemSubstitutionSet_Broadcast_s / HeroInventoryClient',
      decoder_version: 'rofl-16.16.805.0442-shop-item-substitution-map-v1',
      field_mapping: {
        source_item_id: 'direct after exact runtime inverse',
        target_item_id: 'direct after exact runtime inverse',
      },
      evidence_grade: 'VERIFIED_DIRECT', validation_status: 'PASS',
      sample_count: {
        replay_count: 4, event_count: 8,
        scope: '8/8 exact native full-consume rows; observed mappings 1001->2422 and 2420->2421',
      },
      positive_examples: [
        'artifacts/full_semantic_deep_recovery_v2/entity_item/entity_item_deep_recovery_summary_16_16.json',
      ],
      negative_examples: ['The exact two-pair map does not explain the retained 3363/3340 undo residual.'],
      known_limits: ['A map update is not itself proof of an inventory transform event.'],
      introduced_at: '2026-08-20', last_verified_at: '2026-08-20',
    }),
    SUPPORT_QUEST_ITEM_STAGE: record('SUPPORT_QUEST_ITEM_STAGE', BUILD_16_16, {
      protocol_route: '0x0064 canonical ten-row group / utility participant subset',
      packet_registration_route: 'numeric factory route 0x0064; symbolic runtime type unavailable',
      decoder_version: 'rofl-16.16.805.0442-support-quest-stage-snapshot-v1',
      field_mapping: {
        stage_code_f32: 'direct exact codec field_10',
        participant_entity_routing_key: 'direct exact codec field_14',
        participant_id: 'derived canonical walk ordinal and exact champion routing key',
        stage: 'derived exact-build map 1.17->0, 1.27->1, 1.47->2',
      },
      evidence_grade: 'VERIFIED_DERIVED', validation_status: 'PASS',
      sample_count: {
        replay_count: 8, event_count: 169654,
        scope: '169654/169654 exact full-consume; 15071 canonical groups; 16/16 safe-P0 stage transitions aligned; 18944 residual rows retained unclassified',
      },
      positive_examples: [
        'artifacts/full_semantic_deep_recovery_v2/unknown_mining/route_0064_support_quest_audit.json',
        'artifacts/full_semantic_deep_recovery_v2/unknown_mining/route_0064_runtime_residual_audit.json',
        'artifacts/full_semantic_deep_recovery_v2/entity_item/entity_item_deep_recovery_summary_16_16.json',
      ],
      negative_examples: [
        'Nonutility rows are stable controls and reject general HP/defense/resource interpretations.',
      ],
      known_limits: [
        'Only canonical ten-row groups and utility participants 5 and 10 are published.',
        'Three-byte and noncanonical rows remain structured residuals without gameplay names.',
        'The exact numeric route identity has no recovered symbolic runtime type name.',
      ],
      introduced_at: '2026-08-20', last_verified_at: '2026-08-20',
    }),
    FACE_DIRECTION_VECTOR: record('FACE_DIRECTION_VECTOR', BUILD_16_16, {
      protocol_route: '0x01ab',
      packet_registration_route: '0x01ab PKT_S2C_FaceDirection_s / AIBaseClient',
      decoder_version: 'rofl-16.16.805.0442-face-direction-vector-research-v1',
      field_mapping: {
        subject_entity_id: 'direct raw packet parameter',
        replay_time_ms: 'direct packet timestamp',
        direction_xyz: 'direct exact receive-side inverse at object +0x14..+0x1f',
        flag_10: null,
        scalar_20: null,
      },
      evidence_grade: 'VERIFIED_DIRECT', validation_status: 'PASS',
      sample_count: {
        replay_count: 4, event_count: 105124,
        scope: '105124 full-corpus rows profiled; 192 stratified native rows full-consumed and unit-vector checked',
      },
      positive_examples: [
        'artifacts/full_semantic_deep_recovery_v2/gameplay_route_tail/gameplay_route_tail_audit_16_16.json',
      ],
      negative_examples: ['The vector is not a world position or path.'],
      known_limits: ['The flag and optional scalar retain UNKNOWN neutral protocol roles.'],
      introduced_at: '2026-08-20', last_verified_at: '2026-08-20',
    }),
    INSTANT_STOP_ATTACK: record('INSTANT_STOP_ATTACK', BUILD_16_16, {
      protocol_route: '0x00e4',
      packet_registration_route: '0x00e4 PKT_NPC_InstantStop_Attack_s / AIBaseClient',
      decoder_version: 'rofl-16.16.805.0442-instant-stop-attack-research-v1',
      field_mapping: {
        subject_entity_id: 'direct raw packet parameter',
        replay_time_ms: 'direct packet timestamp',
        occurrence: 'direct exact runtime route',
        attack_sequence: 'direct consumer comparison value at +0x14',
        target_entity_id: null,
      },
      evidence_grade: 'VERIFIED_DIRECT', validation_status: 'PASS',
      sample_count: {
        replay_count: 4, event_count: 96782,
        scope: '96782 full-corpus rows profiled; 549 stratified native rows full-consumed',
      },
      positive_examples: [
        'artifacts/full_semantic_deep_recovery_v2/gameplay_route_tail/gameplay_route_tail_audit_16_16.json',
      ],
      negative_examples: ['Many rows have no Damage within 10 ms; occurrence is not a damage or hit carrier.'],
      known_limits: ['Nullable +0x1c remains a target candidate; flags retain neutral names.'],
      introduced_at: '2026-08-20', last_verified_at: '2026-08-20',
    }),
    BASIC_ATTACK_POSITION_MINION: record('BASIC_ATTACK_POSITION_MINION', BUILD_16_16, {
      protocol_route: '0x01b5',
      packet_registration_route: '0x01b5 PKT_Basic_Attack_Pos_Minion_s / AIBaseClient',
      decoder_version: 'rofl-16.16.805.0442-basic-attack-position-minion-research-v1',
      field_mapping: {
        subject_entity_id: 'direct raw packet parameter',
        replay_time_ms: 'direct packet timestamp',
        target_entity_id: 'direct exact consumer lookup key',
        position_xz: 'direct exact two-component position vector',
      },
      evidence_grade: 'VERIFIED_DIRECT', validation_status: 'PASS',
      sample_count: {
        replay_count: 4, event_count: 52986,
        scope: '52986 full-corpus rows profiled; 571 stratified native rows full-consumed',
      },
      positive_examples: [
        'artifacts/full_semantic_deep_recovery_v2/gameplay_route_tail/gameplay_route_tail_audit_16_16.json',
      ],
      negative_examples: ['Most sampled rows are not within 10 ms of Damage.'],
      known_limits: ['The inline attack subobject stays structural; no hit or damage application is claimed.'],
      introduced_at: '2026-08-20', last_verified_at: '2026-08-20',
    }),
    ABILITY_COOLDOWN_BROADCAST: record('ABILITY_COOLDOWN_BROADCAST', BUILD_16_16, {
      protocol_route: '0x00b8',
      packet_registration_route: '0x00b8 PKT_CHAR_SetCooldown_Broadcast_s / SpellbookClient',
      decoder_version: 'rofl-16.16.805.0442-ability-cooldown-broadcast-research-v1',
      field_mapping: {
        subject_entity_id: 'direct raw packet parameter',
        replay_time_ms: 'direct packet timestamp',
        spell_slot_key: 'direct exact consumer lookup key',
        numeric_fields: 'direct decoded values with UNKNOWN neutral roles',
        cooldown_start_end_duration: null,
      },
      evidence_grade: 'VERIFIED_DIRECT', validation_status: 'PARTIAL',
      sample_count: {
        replay_count: 4, event_count: 62000,
        scope: '62000 full-corpus rows profiled; 683 stratified native rows full-consumed',
      },
      positive_examples: [
        'artifacts/full_semantic_deep_recovery_v2/gameplay_route_tail/gameplay_route_tail_audit_16_16.json',
      ],
      negative_examples: ['Short branches default omitted values; zero is not necessarily transmitted zero.'],
      known_limits: ['Four f32 fields are not named start, end, duration, or current cooldown.'],
      introduced_at: '2026-08-20', last_verified_at: '2026-08-20',
    }),
    MISSILE_SYNC_MOVEMENT_COMPLETE_COUNT: record(
      'MISSILE_SYNC_MOVEMENT_COMPLETE_COUNT', BUILD_16_16, {
        protocol_route: '0x03d4',
        packet_registration_route: '0x03d4 PKT_S2C_SyncMovementCompleteCount_s / MissileClient',
        decoder_version: 'rofl-16.16.805.0442-missile-movement-complete-research-v1',
        field_mapping: {
          missile_entity_id: 'direct raw packet parameter on MissileClient callback',
          replay_time_ms: 'direct packet timestamp',
          movement_complete_count: 'direct exact receive-side inverse at object +0x10',
        },
        evidence_grade: 'VERIFIED_DIRECT', validation_status: 'PASS',
        sample_count: {
          replay_count: 4, event_count: 85503,
          scope: '85503 full-corpus constant-count rows; 96 stratified native rows full-consumed',
        },
        positive_examples: [
          'artifacts/full_semantic_deep_recovery_v2/gameplay_route_tail/gameplay_route_tail_audit_16_16.json',
        ],
        negative_examples: ['Subjects are MissileClient-scoped and overwhelmingly outside hero network IDs.'],
        known_limits: ['The current corpus observes only count=1; larger values require a new governed replay.'],
        introduced_at: '2026-08-20', last_verified_at: '2026-08-20',
      },
    ),
    WALL_TRACKING_COMPONENT_CACHE_SNAPSHOT: record(
      'WALL_TRACKING_COMPONENT_CACHE_SNAPSHOT', BUILD_16_16, {
        protocol_route: '0x0298 keyframe only',
        packet_registration_route: '0x0298 PKT_S2C_WallTrackingComponentCacheData_s',
        decoder_version: 'rofl-16.16.805.0442-wall-tracking-cache-snapshot-research-v1',
        field_mapping: {
          subject_entity_id: 'direct raw packet parameter',
          replay_time_ms: 'direct packet timestamp',
          cache_selector: 'direct exact consumer selector',
          coordinate_xz: 'direct exact cache coordinate pair',
          neutral_cache_fields: 'direct decoded values with UNKNOWN roles',
        },
        evidence_grade: 'VERIFIED_DIRECT', validation_status: 'PASS',
        sample_count: {
          replay_count: 4, event_count: 77706,
          scope: '77706/77706 rows are keyframe-only; 768 stratified native rows full-consumed',
        },
        positive_examples: [
          'artifacts/full_semantic_deep_recovery_v2/gameplay_route_tail/gameplay_route_tail_audit_16_16.json',
        ],
        negative_examples: ['Keyframe-only behavior rejects a live wall-collision event interpretation.'],
        known_limits: ['This parser-owned cache snapshot does not establish map truth or strategic labels.'],
        introduced_at: '2026-08-20', last_verified_at: '2026-08-20',
      },
    ),
    XP: record('XP', BUILD_16_16, {
      protocol_route: '0x010c keyframe',
      packet_registration_route: '0x010c PKT_S2C_HeroStats_s',
      decoder_version: 'rofl-16.16.805.0442-hero-stats-scoreboard-unicorn-v1',
      field_mapping: {
        experience_points_raw: 'direct f32 at decoded scoreboard blob +0x28',
        details_integer_projection: 'verified derived Math.floor(experience_points_raw)',
      },
      evidence_grade: 'VERIFIED_DIRECT',
      validation_status: 'PASS',
      sample_count: {
        replay_count: 4,
        event_count: 1390,
        scope: '1390/1390 exact runtime full-consume keyframes; floor(raw XP) matched independent DETAILS frames 1390/1390',
      },
      positive_examples: [
        'artifacts/full_semantic_baseline_v1/hero_stats/hero_stats_scoreboard_validation_16_16.json',
      ],
      negative_examples: [
        '0x010c is a cumulative scoreboard keyframe, not a current combat-state route.',
      ],
      known_limits: [
        'The public Replay semantic is the raw cumulative XP float; the integer projection is separately VERIFIED_DERIVED.',
        'Approximately 60-second keyframe cadence does not provide exact XP event timing.',
      ],
      introduced_at: '2026-08-20', last_verified_at: '2026-08-20',
    }),
    GOLD: record('GOLD', BUILD_16_16, {
      protocol_route: '0x010c keyframe candidate',
      packet_registration_route: '0x010c PKT_S2C_HeroStats_s',
      decoder_version: null,
      field_mapping: { total_gold_candidate: 'candidate f32 at decoded scoreboard blob +0x38; not published' },
      evidence_grade: 'CANDIDATE',
      validation_status: 'CANDIDATE_ONLY',
      sample_count: {
        replay_count: 4,
        event_count: 1390,
        scope: 'floor(candidate) matched DETAILS totalGold 1389/1390; one retained mismatch forbids promotion',
      },
      positive_examples: [
        'artifacts/full_semantic_baseline_v1/hero_stats/hero_stats_scoreboard_validation_16_16.json',
      ],
      negative_examples: [
        'Game 11191336852 participant 4 at 2220711ms: raw 20593.97265625 vs DETAILS 20591.',
      ],
      known_limits: [
        'High correlation is not a verified semantic relation; public total_gold remains null/CANDIDATE.',
        'Current gold, spend, passive income, and transaction deltas are unavailable.',
      ],
      introduced_at: null, last_verified_at: '2026-08-20',
    }),
    CS: record('CS', BUILD_16_16, {
      protocol_route: '0x010c keyframe',
      packet_registration_route: '0x010c PKT_S2C_HeroStats_s',
      decoder_version: 'rofl-16.16.805.0442-hero-stats-scoreboard-unicorn-v1',
      field_mapping: {
        lane_minions_killed: 'direct f32 at decoded scoreboard blob +0x3c; integer-valued 1390/1390',
        jungle_minions_killed: null,
      },
      evidence_grade: 'VERIFIED_DIRECT',
      validation_status: 'PARTIAL',
      sample_count: {
        replay_count: 4,
        event_count: 1390,
        scope: 'lane minionsKilled direct field matched independent DETAILS exactly 1390/1390',
      },
      positive_examples: [
        'artifacts/full_semantic_baseline_v1/hero_stats/hero_stats_scoreboard_validation_16_16.json',
      ],
      negative_examples: [
        'Jungle score candidate at blob +0x40 has only 1375/1390 floor matches and remains unpromoted.',
      ],
      known_limits: [
        'Only cumulative lane minions killed is verified; jungle CS and combined CS are unavailable/candidate.',
        'Approximately 60-second keyframe cadence does not provide exact minion-kill event timing.',
      ],
      introduced_at: '2026-08-20', last_verified_at: '2026-08-20',
    }),
  }),
});

function buildRecords(build) {
  const overrides = BUILD_RECORD_OVERRIDES[build] || {};
  return CAPABILITY_VOCABULARY.map((capability) => clone(overrides[capability]
    || unavailable(capability, build)));
}

function publishedBuilds() {
  // This canonical artifact is the frozen published baseline. Experimental
  // build profiles remain visible through build_registry and semantic_api.
  return Object.keys(BUILD_PROFILES).filter((build) =>
    BUILD_PROFILES[build].release_status !== 'EXPERIMENTAL_CANDIDATE');
}

function createCapabilityManifest() {
  return {
    schema: CAPABILITY_MANIFEST_SCHEMA_VERSION,
    schema_version: 1,
    canonical_semantic_schema_version: CANONICAL_SEMANTIC_SCHEMA_VERSION,
    generated_at: MANIFEST_GENERATED_AT,
    exact_build_only: true,
    nearest_build_fallback: 'FORBIDDEN',
    evidence_grade_vocabulary: [...EVIDENCE_GRADES],
    validation_status_vocabulary: [...VALIDATION_STATUSES],
    capability_vocabulary: [...CAPABILITY_VOCABULARY],
    build_profiles: Object.fromEntries(publishedBuilds().map((build) => [build, {
      patch: BUILD_PROFILES[build].patch,
      decoder_profile: `rofl-${build}`,
      release_status: BUILD_PROFILES[build].release_status,
      records: buildRecords(build),
    }])),
  };
}

function validateCapabilityManifest(manifest) {
  const errors = [];
  if (!manifest || typeof manifest !== 'object') return ['manifest must be an object'];
  if (manifest.schema !== CAPABILITY_MANIFEST_SCHEMA_VERSION) errors.push('invalid schema');
  if (manifest.schema_version !== 1) errors.push('invalid schema_version');
  if (manifest.canonical_semantic_schema_version !== CANONICAL_SEMANTIC_SCHEMA_VERSION) errors.push('invalid canonical schema');
  if (manifest.exact_build_only !== true || manifest.nearest_build_fallback !== 'FORBIDDEN') errors.push('exact-build fallback policy missing');
  for (const build of publishedBuilds()) {
    const profile = manifest.build_profiles?.[build];
    if (!profile) { errors.push(`missing build ${build}`); continue; }
    const seen = new Set();
    for (const item of profile.records || []) {
      if (!CAPABILITY_VOCABULARY.includes(item.semantic_capability)) errors.push(`unknown capability ${item.semantic_capability}`);
      if (item.build !== build) errors.push(`record build mismatch for ${item.semantic_capability}`);
      if (seen.has(item.semantic_capability)) errors.push(`duplicate ${build}/${item.semantic_capability}`);
      seen.add(item.semantic_capability);
      for (const field of ['protocol_route', 'packet_registration_route', 'decoder_version', 'field_mapping', 'evidence_grade', 'validation_status', 'sample_count', 'positive_examples', 'negative_examples', 'known_limits', 'introduced_at', 'last_verified_at', 'canonical_schema_version']) {
        if (!Object.hasOwn(item, field)) errors.push(`missing ${field} for ${build}/${item.semantic_capability}`);
      }
      if (!EVIDENCE_GRADES.includes(item.evidence_grade)) errors.push(`invalid evidence grade for ${build}/${item.semantic_capability}`);
      if (!VALIDATION_STATUSES.includes(item.validation_status)) errors.push(`invalid validation status for ${build}/${item.semantic_capability}`);
      if (item.canonical_schema_version !== CANONICAL_SEMANTIC_SCHEMA_VERSION) errors.push(`schema mismatch for ${build}/${item.semantic_capability}`);
      if (!item.sample_count || typeof item.sample_count !== 'object'
          || typeof item.sample_count.scope !== 'string' || !item.sample_count.scope) {
        errors.push(`invalid sample_count for ${build}/${item.semantic_capability}`);
      }
      for (const key of ['replay_count', 'event_count']) {
        const value = item.sample_count?.[key];
        if (value !== null && (!Number.isInteger(value) || value < 0)) {
          errors.push(`invalid sample_count.${key} for ${build}/${item.semantic_capability}`);
        }
      }
      for (const dateField of ['introduced_at', 'last_verified_at']) {
        const value = item[dateField];
        if (value !== null && (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value))) {
          errors.push(`invalid ${dateField} for ${build}/${item.semantic_capability}`);
        }
      }
      if (item.introduced_at && item.last_verified_at && item.introduced_at > item.last_verified_at) {
        errors.push(`date order invalid for ${build}/${item.semantic_capability}`);
      }
      if (['VERIFIED_DIRECT', 'VERIFIED_DERIVED'].includes(item.evidence_grade)
          && (!['PASS', 'PARTIAL'].includes(item.validation_status)
            || !Array.isArray(item.positive_examples) || item.positive_examples.length === 0
            || !item.field_mapping || Object.keys(item.field_mapping).length === 0)) {
        errors.push(`verified evidence consistency failure for ${build}/${item.semantic_capability}`);
      }
      if (item.evidence_grade === 'CANDIDATE' && item.validation_status !== 'CANDIDATE_ONLY') {
        errors.push(`candidate status inconsistency for ${build}/${item.semantic_capability}`);
      }
      if (item.evidence_grade === 'UNAVAILABLE' && item.validation_status !== 'UNAVAILABLE') {
        errors.push(`unavailable status inconsistency for ${build}/${item.semantic_capability}`);
      }
      if (item.evidence_grade === 'UNVERIFIED' && item.validation_status !== 'UNVERIFIED') {
        errors.push(`unverified status inconsistency for ${build}/${item.semantic_capability}`);
      }
    }
    for (const capability of CAPABILITY_VOCABULARY) if (!seen.has(capability)) errors.push(`missing ${build}/${capability}`);
  }
  return errors;
}

function queryCapability(manifest, { build, capability } = {}) {
  const resolved = resolveBuildProfile(build);
  if (!resolved.profile) return { status: 'UNSUPPORTED_BUILD', build: resolved.game_version, record: null };
  if (!CAPABILITY_VOCABULARY.includes(capability)) return { status: 'UNAVAILABLE', build, record: null };
  const record = manifest.build_profiles?.[build]?.records
    ?.find((item) => item.semantic_capability === capability) ?? null;
  return { status: record?.validation_status ?? 'UNAVAILABLE', build, record: record && clone(record) };
}

function writeCapabilityManifest(outputPath, manifest = createCapabilityManifest()) {
  const errors = validateCapabilityManifest(manifest);
  if (errors.length) throw new Error(`invalid capability manifest: ${errors.join('; ')}`);
  const target = path.resolve(outputPath);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, `${JSON.stringify(manifest, null, 2)}\n`);
  return target;
}

function readCapabilityManifest(inputPath) {
  const manifest = JSON.parse(fs.readFileSync(inputPath, 'utf8'));
  const errors = validateCapabilityManifest(manifest);
  if (errors.length) throw new Error(`invalid capability manifest: ${errors.join('; ')}`);
  return manifest;
}

function semanticCompatibilityFor(capability, record15, record16) {
  const declaration = SEMANTIC_COMPATIBILITY_DECLARATIONS[capability] ?? null;
  const bothEvidenceBacked = ['VERIFIED_DIRECT', 'VERIFIED_DERIVED'].includes(record15.evidence_grade)
    && ['VERIFIED_DIRECT', 'VERIFIED_DERIVED'].includes(record16.evidence_grade);
  if (declaration && bothEvidenceBacked) return { status: 'YES', declaration };
  if (!bothEvidenceBacked) {
    return {
      status: 'NOT_COMPARABLE',
      declaration: {
        status: 'NOT_COMPARABLE', evidence: [],
        rationale: 'One or both exact builds lack an evidence-backed semantic record.',
      },
    };
  }
  return {
    status: 'UNVERIFIED',
    declaration: {
      status: 'UNVERIFIED', evidence: [],
      rationale: 'No explicit pairwise semantic-equivalence declaration is registered.',
    },
  };
}

function compatibilityFor(capability, record15, record16) {
  const routesKnown = record15.protocol_route !== null && record16.protocol_route !== null;
  const sameRoute = routesKnown && record15.protocol_route === record16.protocol_route;
  const semantic = semanticCompatibilityFor(capability, record15, record16);
  const canonicalSchema = record15.canonical_schema_version === record16.canonical_schema_version;
  return {
    binary_compatible: !routesKnown ? 'UNVERIFIED' : sameRoute ? 'YES' : 'NO',
    decoder_compatible: !routesKnown || !record15.decoder_version || !record16.decoder_version
      ? 'UNVERIFIED'
      : sameRoute && record15.decoder_version === record16.decoder_version ? 'YES' : 'NO',
    semantic_compatible: semantic.status,
    semantic_compatibility_declaration: semantic.declaration,
    schema_compatible: canonicalSchema ? 'YES' : 'NO',
  };
}

function createSemanticCompatibilityMatrix(manifest = createCapabilityManifest()) {
  const errors = validateCapabilityManifest(manifest);
  if (errors.length) throw new Error(`invalid capability manifest: ${errors.join('; ')}`);
  return {
    schema: SEMANTIC_COMPATIBILITY_MATRIX_SCHEMA_VERSION,
    schema_version: 1,
    generated_at: MANIFEST_GENERATED_AT,
    exact_build_only: true,
    nearest_build_fallback: 'FORBIDDEN',
    compared_builds: [BUILD_16_15, BUILD_16_16],
    compatibility_status_vocabulary: [...COMPATIBILITY_STATUSES],
    rows: CAPABILITY_VOCABULARY.map((capability) => {
      const oldRecord = queryCapability(manifest, { build: BUILD_16_15, capability }).record;
      const newRecord = queryCapability(manifest, { build: BUILD_16_16, capability }).record;
      return {
        semantic_capability: capability,
        builds: {
          [BUILD_16_15]: { evidence_grade: oldRecord.evidence_grade, validation_status: oldRecord.validation_status, protocol_route: oldRecord.protocol_route },
          [BUILD_16_16]: { evidence_grade: newRecord.evidence_grade, validation_status: newRecord.validation_status, protocol_route: newRecord.protocol_route },
        },
        ...compatibilityFor(capability, oldRecord, newRecord),
        canonical_schema_version: CANONICAL_SEMANTIC_SCHEMA_VERSION,
        known_limits: [
          'Binary route, decoder profile, semantic equivalence, and schema compatibility are independent declarations.',
          'NOT_COMPARABLE is not a negative protocol claim and never permits a fallback decoder.',
        ],
      };
    }),
  };
}

function validateSemanticCompatibilityMatrix(matrix) {
  const errors = [];
  if (!matrix || typeof matrix !== 'object') return ['matrix must be an object'];
  if (matrix.schema !== SEMANTIC_COMPATIBILITY_MATRIX_SCHEMA_VERSION) errors.push('invalid matrix schema');
  if (matrix.schema_version !== 1) errors.push('invalid matrix schema_version');
  if (matrix.exact_build_only !== true || matrix.nearest_build_fallback !== 'FORBIDDEN') errors.push('matrix fallback policy missing');
  const seen = new Set();
  for (const row of matrix.rows || []) {
    if (!CAPABILITY_VOCABULARY.includes(row.semantic_capability)) errors.push(`unknown matrix capability ${row.semantic_capability}`);
    if (seen.has(row.semantic_capability)) errors.push(`duplicate matrix row ${row.semantic_capability}`);
    seen.add(row.semantic_capability);
    for (const field of ['binary_compatible', 'decoder_compatible', 'semantic_compatible', 'schema_compatible']) {
      if (!COMPATIBILITY_STATUSES.includes(row[field])) errors.push(`invalid ${field} for ${row.semantic_capability}`);
    }
    const declaration = row.semantic_compatibility_declaration;
    if (!declaration || declaration.status !== row.semantic_compatible
        || !Array.isArray(declaration.evidence) || typeof declaration.rationale !== 'string') {
      errors.push(`invalid semantic declaration for ${row.semantic_capability}`);
    }
    if (row.semantic_compatible === 'YES') {
      const expected = SEMANTIC_COMPATIBILITY_DECLARATIONS[row.semantic_capability];
      if (!expected || declaration.rationale !== expected.rationale
          || JSON.stringify(declaration.evidence) !== JSON.stringify(expected.evidence)) {
        errors.push(`unregistered semantic equivalence for ${row.semantic_capability}`);
      }
    }
    for (const build of [BUILD_16_15, BUILD_16_16]) if (!row.builds?.[build]) errors.push(`missing matrix build ${build}/${row.semantic_capability}`);
  }
  for (const capability of CAPABILITY_VOCABULARY) if (!seen.has(capability)) errors.push(`missing matrix row ${capability}`);
  return errors;
}

function querySemanticCompatibility(matrix, capability) {
  if (!CAPABILITY_VOCABULARY.includes(capability)) return null;
  const row = matrix.rows?.find((item) => item.semantic_capability === capability) ?? null;
  return row && clone(row);
}

function writeSemanticCompatibilityMatrix(outputPath, matrix = createSemanticCompatibilityMatrix()) {
  const errors = validateSemanticCompatibilityMatrix(matrix);
  if (errors.length) throw new Error(`invalid semantic compatibility matrix: ${errors.join('; ')}`);
  const target = path.resolve(outputPath);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, `${JSON.stringify(matrix, null, 2)}\n`);
  return target;
}

module.exports = {
  BUILD_16_15,
  BUILD_16_16,
  CANONICAL_SEMANTIC_SCHEMA_VERSION,
  CAPABILITY_MANIFEST_SCHEMA_VERSION,
  CAPABILITY_VOCABULARY,
  COMPATIBILITY_STATUSES,
  EVIDENCE_GRADES,
  SEMANTIC_COMPATIBILITY_DECLARATIONS,
  SEMANTIC_COMPATIBILITY_MATRIX_SCHEMA_VERSION,
  createCapabilityManifest,
  createSemanticCompatibilityMatrix,
  queryCapability,
  querySemanticCompatibility,
  readCapabilityManifest,
  validateCapabilityManifest,
  validateSemanticCompatibilityMatrix,
  writeCapabilityManifest,
  writeSemanticCompatibilityMatrix,
};

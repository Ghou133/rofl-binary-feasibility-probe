'use strict';

const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { resolveBuildProfile } = require('./build_registry');
const {
  collectCandidateRoutes,
  collectCandidateRoutesAndHeroStats,
  decodeHeroDeathCandidates,
  decodeHeroDeathTimerCandidates,
  decodeHeroRespawnCandidates,
  decodeHeroLevelStateCandidates,
  decodeHeroInventoryMapViewCandidates,
  decodeHeroInventorySetItemCandidates,
  decodeHeroInventoryBroadcastCandidates,
} = require('./decoders/rofl_16_19_820_7193');
const { decodeHeroDeathCandidates821 } = require('./decoders/rofl_16_19_821_7343');
const { decodeHeroDeathTimerCandidates821 } =
  require('./decoders/rofl_16_19_821_death_timer_candidate');
const { decodeHeroRespawnCandidates821 } =
  require('./decoders/rofl_16_19_821_respawn_candidate');
const {
  decodeHeroDeathsSnapshotCandidates821,
  decodeHeroChampionKillsSnapshotCandidates821,
  decodeHeroAssistsSnapshotCandidates821,
  decodeHeroMissionsMinionsKilledSnapshotCandidates821,
} =
  require('./decoders/rofl_16_19_821_hero_stats_candidate');
const { decodeHeroLevelCandidates821 } =
  require('./decoders/rofl_16_19_821_level_candidate');
const {
  decodeHeroWardStatsSnapshotCandidates821,
  decodeHeroMissionsCannonMinionsKilledSnapshotCandidates821,
} = require('./decoders/rofl_16_19_821_aux_counts_candidate');
const { decodeHeroFloatSnapshotCandidates821 } =
  require('./decoders/rofl_16_19_821_float_stats_candidate');
const { decodeHeroKillStatsSnapshotCandidates821 } =
  require('./decoders/rofl_16_19_821_kill_stats_candidate');
const { decodeHeroAssistCandidates821 } =
  require('./decoders/rofl_16_19_821_assist_candidate');
const { decodeHeroInventoryPacketCandidates821 } =
  require('./decoders/rofl_16_19_821_inventory_packet_candidate');
const { decodeCastSpellAnsPacketCandidates821 } =
  require('./decoders/rofl_16_19_821_cast_spell_ans_packet_candidate');
const { decodeNpcBuffRemovePacketCandidates821 } =
  require('./decoders/rofl_16_19_821_buff_remove_packet_candidate');
const { decodeNpcBuffAddPacketCandidates821 } =
  require('./decoders/rofl_16_19_821_buff_add_packet_candidate');
const { decodeDirectInputMovementTurnPacketCandidates821 } =
  require('./decoders/rofl_16_19_821_direct_input_turn_packet_candidate');
const { decodeSetMovementDriverPacketCandidates821 } =
  require('./decoders/rofl_16_19_821_set_movement_driver_packet_candidate');
const { decodeHeroDamageSnapshotCandidates821 } =
  require('./decoders/rofl_16_19_821_damage_float_candidate');
const { decodeHeroTimeSnapshotCandidates821 } =
  require('./decoders/rofl_16_19_821_time_stats_candidate');
const { decodeHeroHealSnapshotCandidates821 } =
  require('./decoders/rofl_16_19_821_heal_stats_candidate');
const { decodeHeroEpicCcSnapshotCandidates821 } =
  require('./decoders/rofl_16_19_821_epic_cc_candidate');
const { collect821Routes } = require('./decoders/rofl_16_19_821_scan');
const { decodeNpcBuffRemovePacketCandidates } =
  require('./decoders/rofl_16_19_buff_remove_candidate');
const { decodeNpcBuffAddPacketCandidates } =
  require('./decoders/rofl_16_19_buff_add_candidate');
const { analyzeBuffPacketKeyCompatibility } =
  require('./decoders/rofl_16_19_buff_key_compatibility');
const { analyzeBuffPacketKeyCompatibility821 } =
  require('./decoders/rofl_16_19_821_buff_key_compatibility');
const {
  HERO_STATS_SNAPSHOT_CAPABILITIES,
  decodeHeroStatsSnapshotCandidateSet,
} = require('./decoders/rofl_16_19_hero_stats_candidate');
const {
  createSweeperCapabilityExport,
  emptySweeperEvents,
} = require('./sweeper_capability');
const { levelTransitionEvent } = require('./events');
const { levelMapping } = require('./level_transition');
const { parseReplayFile, walkBlocks } = require('./rofl');
const {
  DAMAGE_PROFILE: DAMAGE_PROFILE_16_16,
  damageEventFromDecodedRow: damageEventFromDecodedRow16,
  participantMetadata: damageParticipantMetadata16,
} = require('./decoders/damage_16_16');
const {
  DEATH_PROFILE: DEATH_PROFILE_16_16,
  decodeHeroDeathDecodedRow: decodeHeroDeathDecodedRow16,
  decodeHeroDeaths: decodeHeroDeathRoutes16,
  participantMetadata: deathParticipantMetadata16,
} = require('./decoders/death_16_16');
const {
  HERO_STATS_PROFILE: HERO_STATS_PROFILE_16_16,
  heroScoreboardStateFromDecodedRow: heroScoreboardStateFromDecodedRow16,
  participantMetadata: heroStatsParticipantMetadata16,
} = require('./decoders/hero_stats_16_16');
const {
  SemanticStateEngine,
  stateUpdateFromGroundTruthFrame,
} = require('./semantic_state_engine');
const {
  buffEventFromDecodedRow,
  canonicalProtectionEventsFromDecodedRows,
  deathTimerEventFromDecodedRow,
  inventorySnapshotEvent,
  inventorySwapEvent,
  itemSubstitutionMapEvent,
  spellCastEventFromDecodedRow,
  supportQuestStageEventsFromRows,
} = require('./decoders/deep_recovery_events_16_16');
const {
  GAMEPLAY_ROUTE_TAIL_PROFILES,
  gameplayRouteTailEventFromDecodedRow,
} = require('./decoders/gameplay_route_tail_16_16');
const {
  HERO_REINCARNATE_ALIVE_PROFILE,
  heroReincarnateAliveEventFromDecodedRow,
} = require('./decoders/hero_reincarnate_alive_16_16');
const {
  CANONICAL_EVENT_TYPES,
  EVIDENCE_STATUS_VOCABULARY,
  EVENT_FIELD_DEFINITIONS,
  assertNoConsumerAdapterLeak,
  blankFields,
  canonicalSchemaDocument,
  createCanonicalRecord,
  validateCanonicalRecord,
} = require('./canonical_semantic_schema');
const semanticCalibration = require('./semantic_calibration_api');

const REPOSITORY_ROOT = path.resolve(__dirname, '..');
const DEFAULT_16_16_RUNTIME_IMAGE = path.join(
  REPOSITORY_ROOT,
  'artifacts',
  'new_build_rofl_compatibility_gate_v1',
  'runtime',
  'league_16.16.805.0442.memory.bin',
);
const DEFAULT_16_16_DAMAGE_PROFILE = path.join(
  REPOSITORY_ROOT,
  'artifacts',
  'hero_combat_state_v2',
  'emulation',
  'profiles',
  'packet_017f.json',
);
const DEFAULT_16_16_DEATH_PROFILE = path.join(
  REPOSITORY_ROOT,
  'artifacts',
  'full_semantic_baseline_v1',
  'runtime_candidates',
  'packet_0112_static_profile.json',
);
const DEFAULT_16_16_HERO_STATS_PROFILE = path.join(
  REPOSITORY_ROOT,
  'artifacts',
  'hero_combat_state_v2',
  'emulation',
  'profiles',
  'packet_010c.json',
);
const DEFAULT_16_16_DEATH_TIMER_PROFILE = path.join(
  REPOSITORY_ROOT,
  'artifacts',
  'full_semantic_deep_recovery_v2',
  'hero_state',
  'profiles',
  'packet_0074.json',
);
const DEFAULT_16_16_HERO_REINCARNATE_ALIVE_PROFILE = path.join(
  REPOSITORY_ROOT,
  'artifacts',
  'full_semantic_deep_recovery_v2',
  'hero_respawn',
  'packet_0265_profile.json',
);

const CANONICAL_EVENT_FIELD_ALIASES = Object.freeze({
  HeroState: Object.freeze({
    entity_id: ['entity_id', 'entity_network_id', 'network_id'],
    participant_id: ['participant_id'], champion: ['champion'], current_hp: ['current_hp'],
    max_hp: ['max_hp'], armor: ['armor'], magic_resist: ['magic_resist'],
    attack_damage: ['attack_damage'], ability_power: ['ability_power'], attack_speed: ['attack_speed'],
    move_speed: ['move_speed'], mana: ['mana'], max_mana: ['max_mana'],
    experience_points: ['experience_points', 'xp'], total_gold: ['total_gold'],
    lane_minions_killed: ['lane_minions_killed', 'minions_killed', 'lane_cs'],
    jungle_minions_killed: ['jungle_minions_killed', 'jungle_cs'],
    level: ['level', 'level_after'],
    alive: ['alive'], position: ['position'],
  }),
  DamageEvent: Object.freeze({
    source_entity_id: ['source_entity_id', 'source_network_id'],
    target_entity_id: ['target_entity_id', 'target_network_id'],
    source_participant_id: ['source_participant_id'], target_participant_id: ['target_participant_id'],
    amount: ['amount'], amount_semantic_stage: ['amount_semantic_stage'], damage_type: ['damage_type'],
    spell_identifier: ['spell_identifier', 'spell'], is_critical: ['is_critical'],
  }),
  BuffEvent: Object.freeze({
    subject_entity_id: ['subject_entity_id', 'target_entity_id', 'entity_network_id'],
    routing_entity_id: ['routing_entity_id', 'target_network_id_candidate'],
    source_entity_id: ['source_entity_id', 'source_network_id'], operation: ['operation', 'buff_operation'],
    buff_identifier: ['buff_identifier', 'buff_name_hash'], stack_count: ['stack_count'],
    slot_index: ['slot_index', 'slot_candidate'],
    duration_seconds: ['duration_seconds'], remaining_seconds: ['remaining_seconds', 'running_time_seconds'],
  }),
  SpellCast: Object.freeze({
    caster_entity_id: ['caster_entity_id', 'caster_network_id', 'source_network_id'],
    caster_name: ['caster_name', 'caster_name_exact_translator'],
    chain_owner_entity_id: ['chain_owner_entity_id', 'chain_owner_network_id'],
    target_entity_id: ['target_entity_id', 'target_network_id'],
    spell_identifier: ['spell_identifier', 'spell'], spell_slot: ['spell_slot'],
    numeric_spell_key: ['numeric_spell_key', 'spell_key_candidate'],
    target_position: ['target_position', 'position'], cast_result: ['cast_result'],
    cast_time_seconds: ['cast_time_seconds', 'time_seconds_candidate'],
  }),
  EntityLifecycle: Object.freeze({
    entity_id: ['entity_id', 'entity_network_id', 'network_id', 'victim_network_id', 'target_network_id'],
    participant_id: ['participant_id', 'victim_participant_id', 'target_participant_id'],
    entity_type: ['entity_type', 'victim_entity_type', 'target_entity_type'],
    entity_subtype: ['entity_subtype'], lifecycle_operation: ['lifecycle_operation', 'event_type'],
    owner_entity_id: ['owner_entity_id', 'owner_network_id'],
    killer_entity_id: ['killer_entity_id', 'killer_network_id'],
    killer_participant_id: ['killer_participant_id'],
    assisting_entity_ids: ['assisting_entity_ids', 'assists'],
    death_timer_seconds: ['death_timer_seconds'],
    respawn_timestamp_ms: ['respawn_timestamp_ms'], position: ['position'],
  }),
  WardEvent: Object.freeze({
    ward_entity_id: ['ward_entity_id', 'ward_network_id', 'entity_network_id'],
    owner_entity_id: ['owner_entity_id', 'owner_network_id', 'ward_owner_network_id'],
    ward_type: ['ward_type'], operation: ['operation', 'event_type'], position: ['position'],
  }),
  ItemEvent: Object.freeze({
    subject_entity_id: ['subject_entity_id', 'entity_network_id', 'network_id'], operation: ['operation', 'event_type'],
    item_identifier: ['item_identifier', 'item'], quantity: ['quantity', 'stack_count'], gold_delta: ['gold_delta'],
    source_item_identifier: ['source_item_identifier', 'source_item_id'],
    target_item_identifier: ['target_item_identifier', 'target_item_id'],
    slot_index: ['slot_index', 'slot'], source_slot_index: ['source_slot_index', 'first_slot_index'],
    target_slot_index: ['target_slot_index', 'second_slot_index'],
    inventory_entries: ['inventory_entries', 'snapshot_items'], stage: ['stage'],
    stage_code: ['stage_code', 'stage_code_f32'], snapshot_scope: ['snapshot_scope'],
  }),
  ObjectiveEvent: Object.freeze({
    objective_entity_id: ['objective_entity_id', 'entity_network_id', 'entity_id'], operation: ['operation', 'event_type'],
    killer_entity_id: ['killer_entity_id', 'killer_network_id'], objective_type: ['objective_type'],
  }),
  PositionEvent: Object.freeze({
    entity_id: ['entity_id', 'entity_network_id', 'network_id', 'subject_network_id'], position: ['position'],
    direction: ['direction'], operation: ['operation', 'event_type'],
    resolution_ms: ['resolution_ms'], interpolation: ['interpolation'],
  }),
  MissileEvent: Object.freeze({
    missile_entity_id: ['missile_entity_id', 'entity_network_id', 'subject_network_id'],
    source_entity_id: ['source_entity_id', 'source_network_id'], target_entity_id: ['target_entity_id', 'target_network_id'],
    operation: ['operation', 'event_type'], position: ['position'],
    movement_complete_count: ['movement_complete_count', 'movement_complete_count_u8'],
  }),
  AttackEvent: Object.freeze({
    subject_entity_id: ['subject_entity_id', 'subject_network_id', 'entity_network_id'],
    target_entity_id: ['target_entity_id', 'target_network_id', 'target_network_id_u32'],
    operation: ['operation', 'event_type'], attack_sequence: ['attack_sequence', 'attack_sequence_14_u32'],
    position: ['position'],
  }),
  SpellState: Object.freeze({
    subject_entity_id: ['subject_entity_id', 'subject_network_id', 'entity_network_id'],
    operation: ['operation', 'event_type'], spell_slot_key: ['spell_slot_key', 'spell_slot_key_1c_u8'],
    protocol_numeric_values: ['protocol_numeric_values'],
  }),
  EntityComponentState: Object.freeze({
    subject_entity_id: ['subject_entity_id', 'subject_network_id', 'entity_network_id'],
    component: ['component'], operation: ['operation', 'event_type'],
    selector: ['selector', 'cache_selector_10_u16'], position: ['position'],
    protocol_numeric_values: ['protocol_numeric_values'],
  }),
  ProtectionEvent: Object.freeze({
    subject_entity_id: ['subject_entity_id', 'target_network_id'], source_entity_id: ['source_entity_id', 'source_network_id'],
    protection_type: ['protection_type', 'shield_type'], reported_amount: ['reported_amount', 'generated_amount', 'raw_heal_amount'],
    effective_amount: ['effective_amount', 'effective_heal_amount'],
    amount_stage: ['amount_stage'], duplicate_suppressed: ['duplicate_suppressed'],
  }),
  LevelTransition: Object.freeze({
    entity_id: ['entity_id', 'entity_network_id'], participant_id: ['participant_id'],
    level_before: ['level_before'], level_after: ['level_after'], is_initialization: ['is_initialization'],
  }),
});

function firstDefined(source, names) {
  for (const name of names) {
    if (Object.prototype.hasOwnProperty.call(source, name)) return { name, value: source[name] };
  }
  return { name: null, value: null };
}

function normalizeCanonicalEvidenceStatus(value, fallback) {
  const candidate = value ?? fallback;
  if (EVIDENCE_STATUS_VOCABULARY.includes(candidate)) return candidate;
  if (candidate === 'VERIFIED') return 'VERIFIED_DIRECT';
  if (candidate === 'DERIVED' || candidate === 'DETAILS_DERIVED') return 'VERIFIED_DERIVED';
  if (candidate === 'DETAILS_DIRECT' || candidate === 'GROUND_TRUTH_FRAME_SNAPSHOT') return 'VERIFIED_DIRECT';
  if (/^(?:SEMANTIC_)?VERIFIED_DIRECT/.test(String(candidate))) return 'VERIFIED_DIRECT';
  if (/^(?:SEMANTIC_)?VERIFIED_DERIVED/.test(String(candidate))) return 'VERIFIED_DERIVED';
  if (/CANDIDATE/.test(String(candidate))) return 'CANDIDATE';
  if (candidate === 'UNVERIFIED' || candidate === 'PARTIAL' || candidate === 'UNSUPPORTED_VERSION') return 'UNKNOWN';
  return fallback;
}

function exactBuildFromPublicEvent(event, options) {
  const exactBuild = event.exact_build ?? event.game_version ?? event.replay_version ?? options.exactBuild ?? null;
  if (typeof exactBuild !== 'string' || !/^\d+\.\d+\.\d+\.\d+$/.test(exactBuild)) {
    throw new Error('canonicalization requires an explicit exact four-component build; no nearest-build fallback exists');
  }
  return exactBuild;
}

function canonicalizeSemanticEvent(semanticType, event, options = {}) {
  if (!CANONICAL_EVENT_TYPES.includes(semanticType)) throw new Error(`unsupported canonical semantic type: ${semanticType}`);
  if (!event || typeof event !== 'object' || Array.isArray(event)) throw new TypeError('semantic event must be an object');
  const aliases = CANONICAL_EVENT_FIELD_ALIASES[semanticType];
  const blank = blankFields(semanticType);
  for (const fieldName of Object.keys(EVENT_FIELD_DEFINITIONS[semanticType])) {
    const selected = firstDefined(event, aliases[fieldName] ?? [fieldName]);
    blank.fields[fieldName] = selected.value;
    const sourceStatus = selected.name === null ? null
      : event.field_confidence?.[selected.name]
        ?? event[`${selected.name}_status`]
        ?? event.field_confidence?.[fieldName]
        ?? event[`${fieldName}_status`];
    blank.field_evidence[fieldName] = normalizeCanonicalEvidenceStatus(
      sourceStatus,
      selected.value === null ? 'UNKNOWN' : normalizeCanonicalEvidenceStatus(
        event.semantic_status ?? event.confidence,
        'CANDIDATE',
      ),
    );
  }
  const exactBuild = exactBuildFromPublicEvent(event, options);
  const aggregateEvidence = normalizeCanonicalEvidenceStatus(event.semantic_status ?? event.confidence, 'UNKNOWN');
  const result = createCanonicalRecord(semanticType, {
    event_id: event.event_id ?? null,
    replay_sha256: event.replay_sha256 ?? event.raw_packet_ref?.replay_sha256 ?? null,
    exact_build: exactBuild,
    replay_time_ms: event.replay_time_ms ?? event.timestamp_ms ?? null,
    fields: blank.fields,
    field_evidence: blank.field_evidence,
    evidence: {
      status: aggregateEvidence,
      limitations: Array.isArray(event.known_limits) ? [...event.known_limits] : [],
    },
    provenance: {
      source_kind: 'ROFL',
      source_artifact_sha256: event.raw_payload_sha256 ?? event.raw_packet_ref?.payload_sha256 ?? null,
      parser_version: event.build_profile ?? null,
      exact_build_adapter_id: event.decoder_profile ?? event.build_profile ?? null,
    },
  });
  assertNoConsumerAdapterLeak(result);
  return result;
}

function canonicalGameplayRouteTailEvent(event) {
  const common = {
    ...event,
    subject_entity_id: event.subject_network_id,
  };
  if (event.event_type === 'FACE_DIRECTION_VECTOR') {
    return canonicalizeSemanticEvent('PositionEvent', {
      ...common,
      operation: 'FACE_DIRECTION',
      direction: {
        x: event.direction_x_f32,
        y: event.direction_y_f32,
        z: event.direction_z_f32,
      },
      field_confidence: {
        ...event.field_confidence,
        subject_entity_id: 'VERIFIED_DIRECT',
        operation: 'VERIFIED_DIRECT',
        direction: 'VERIFIED_DIRECT',
      },
    });
  }
  if (event.event_type === 'INSTANT_STOP_ATTACK') {
    const target = event.target_network_id_candidate_1c_u32 || null;
    return canonicalizeSemanticEvent('AttackEvent', {
      ...common,
      operation: 'INSTANT_STOP_ATTACK',
      target_entity_id: target,
      attack_sequence: event.attack_sequence_14_u32,
      field_confidence: {
        ...event.field_confidence,
        subject_entity_id: 'VERIFIED_DIRECT',
        operation: 'VERIFIED_DIRECT',
        target_entity_id: target === null ? 'UNKNOWN' : 'CANDIDATE',
        attack_sequence: 'VERIFIED_DIRECT',
      },
    });
  }
  if (event.event_type === 'BASIC_ATTACK_POSITION_MINION') {
    return canonicalizeSemanticEvent('AttackEvent', {
      ...common,
      operation: 'BASIC_ATTACK_POSITION_MINION',
      target_entity_id: event.target_network_id_u32,
      position: { x: event.position_x_f32, z: event.position_z_f32 },
      field_confidence: {
        ...event.field_confidence,
        subject_entity_id: 'VERIFIED_DIRECT',
        operation: 'VERIFIED_DIRECT',
        target_entity_id: 'VERIFIED_DIRECT',
        position: 'VERIFIED_DIRECT',
      },
    });
  }
  if (event.event_type === 'ABILITY_COOLDOWN_BROADCAST') {
    return canonicalizeSemanticEvent('SpellState', {
      ...common,
      operation: 'ABILITY_COOLDOWN_BROADCAST',
      spell_slot_key: event.spell_slot_key_1c_u8,
      protocol_numeric_values: {
        numeric_10_f32: event.numeric_10_f32,
        numeric_18_f32: event.numeric_18_f32,
        numeric_20_f32: event.numeric_20_f32,
        numeric_24_f32: event.numeric_24_f32,
        flag_14_u8: event.flag_14_u8,
        roles: 'UNKNOWN',
      },
      field_confidence: {
        ...event.field_confidence,
        subject_entity_id: 'VERIFIED_DIRECT',
        operation: 'VERIFIED_DIRECT',
        spell_slot_key: 'VERIFIED_DIRECT',
        protocol_numeric_values: 'UNKNOWN',
      },
    });
  }
  if (event.event_type === 'WALL_TRACKING_CACHE_SNAPSHOT') {
    return canonicalizeSemanticEvent('EntityComponentState', {
      ...common,
      component: 'WallTrackingComponentCacheData',
      operation: 'KEYFRAME_CACHE_SNAPSHOT',
      selector: event.cache_selector_10_u16,
      position: { x: event.coordinate_x_18_f32, z: event.coordinate_z_1c_f32 },
      protocol_numeric_values: {
        numeric_14_f32: event.numeric_14_f32,
        field_20_u8: event.field_20_u8,
        field_21_u8: event.field_21_u8,
        field_22_u8: event.field_22_u8,
        roles: 'UNKNOWN',
      },
      field_confidence: {
        ...event.field_confidence,
        subject_entity_id: 'VERIFIED_DIRECT',
        component: 'VERIFIED_DIRECT',
        operation: 'VERIFIED_DIRECT',
        selector: 'VERIFIED_DIRECT',
        position: 'VERIFIED_DIRECT',
        protocol_numeric_values: 'UNKNOWN',
      },
    });
  }
  if (event.event_type === 'MISSILE_MOVEMENT_COMPLETE') {
    return canonicalizeSemanticEvent('MissileEvent', {
      ...common,
      missile_entity_id: event.subject_network_id,
      operation: 'MOVEMENT_COMPLETE_COUNT_UPDATE',
      movement_complete_count: event.movement_complete_count_u8,
      field_confidence: {
        ...event.field_confidence,
        missile_entity_id: 'VERIFIED_DIRECT',
        operation: 'VERIFIED_DIRECT',
        movement_complete_count: 'VERIFIED_DIRECT',
      },
    });
  }
  throw new Error(`unsupported gameplay route tail event ${event.event_type}`);
}

function canonicalHeroReincarnateAliveEvent(event) {
  return canonicalizeSemanticEvent('EntityLifecycle', {
    ...event,
    entity_id: event.subject_network_id,
    entity_type: 'Champion',
    lifecycle_operation: 'REINCARNATE_ALIVE',
    respawn_timestamp_ms: event.respawn_timestamp_ms,
    position: event.position,
    field_confidence: {
      ...event.field_confidence,
      entity_id: 'VERIFIED_DIRECT',
      entity_type: 'VERIFIED_DIRECT',
      lifecycle_operation: 'VERIFIED_DIRECT',
      respawn_timestamp_ms: 'VERIFIED_DIRECT',
      position: 'VERIFIED_DIRECT',
    },
  });
}

function getCanonicalSemanticSchema() {
  return canonicalSchemaDocument();
}

function loadReplay(input) {
  if (typeof input === 'string') return parseReplayFile(path.resolve(input));
  if (!input?.header?.version) throw new TypeError('expected a Replay path or parsed Replay');
  return input;
}

function profileResolution(input) {
  const replay = loadReplay(input);
  return { replay, ...resolveBuildProfile(replay) };
}

function withBuildMetadata(event, buildProfile) {
  if (!event || typeof event !== 'object') return event;
  return {
    ...event,
    game_version: event.game_version ?? buildProfile.game_version,
    patch: event.patch ?? buildProfile.patch,
    build_profile: event.build_profile
      ?? buildProfile.decoder_profile[event.event_type]?.id
      ?? `rofl-${buildProfile.game_version}`,
  };
}

function decorateResultEvents(result, buildProfile) {
  if (!result?.events) return result;
  const events = Object.fromEntries(Object.entries(result.events).map(([key, rows]) => [
    key,
    Array.isArray(rows) ? rows.map((row) => withBuildMetadata(row, buildProfile)) : rows,
  ]));
  return { ...result, events };
}

function rawPacketRow(replay, chunk, block, occurrenceIndex) {
  return {
    schema_version: 1,
    replay_path: replay.source_path,
    replay_sha256: replay.source_sha256,
    replay_version: replay.header.version,
    replay_label: path.basename(replay.source_path, path.extname(replay.source_path)),
    chunk_index: chunk.index,
    chunk_stream: chunk.stream,
    decompressed_block_offset: block.offset,
    replay_time_ms: block.timestamp_ms,
    occurrence_index: occurrenceIndex,
    packet_id: block.packet_id,
    packet_type: block.packet_type,
    payload_length: block.payload_length,
    raw_param: block.param >>> 0,
    raw_payload_hex: block.payload.toString('hex'),
    raw_payload_sha256: crypto.createHash('sha256').update(block.payload).digest('hex'),
  };
}

function sha256File(filePath) {
  const digest = crypto.createHash('sha256');
  digest.update(fs.readFileSync(filePath));
  return digest.digest('hex');
}

function exportPackets(
  replay,
  outputPath,
  packetId,
  predicate = () => true,
  includeStreams = [1],
) {
  const output = fs.openSync(outputPath, 'w');
  let count = 0;
  let walked = null;
  try {
    walked = walkBlocks(replay, (block, chunk) => {
      if (!includeStreams.includes(chunk.stream_tag)
          || block.packet_id !== packetId || !predicate(block)) return;
      fs.writeSync(output, `${JSON.stringify(rawPacketRow(replay, chunk, block, count))}\n`);
      count += 1;
    }, { includeStreams, strict: true });
    if (walked.errors.length) throw new Error(`strict Replay walk returned ${walked.errors.length} errors`);
  } finally {
    fs.closeSync(output);
  }
  const manifest = {
    schema_version: 1,
    target_replay_version: replay.header.version,
    output: outputPath,
    packet_ids: [packetId],
    selected_packet_count: count,
    packet_counts: { [packetId]: count },
    replay_count: 1,
    replays: [{
      path: replay.source_path,
      sha256: replay.source_sha256,
      version: replay.header.version,
      selected_packet_count: count,
      parser_error_count: walked.errors.length,
    }],
    included_stream_tags: [...includeStreams],
    export_scope: 'STRICT_SINGLE_REPLAY_PUBLIC_API',
  };
  fs.writeFileSync(`${outputPath}.manifest.json`, `${JSON.stringify(manifest, null, 2)}\n`);
  return count;
}

function exportPacketSet(replay, outputPath, packetIds, includeStreams = [1]) {
  const selected = new Set(packetIds);
  const output = fs.openSync(outputPath, 'w');
  const packetCounts = Object.fromEntries([...selected].map((packetId) => [packetId, 0]));
  let count = 0;
  let walked = null;
  try {
    walked = walkBlocks(replay, (block, chunk) => {
      if (!includeStreams.includes(chunk.stream_tag) || !selected.has(block.packet_id)) return;
      fs.writeSync(output, `${JSON.stringify(rawPacketRow(replay, chunk, block, count))}\n`);
      packetCounts[block.packet_id] += 1;
      count += 1;
    }, { includeStreams, strict: true });
    if (walked.errors.length) throw new Error(`strict Replay walk returned ${walked.errors.length} errors`);
  } finally {
    fs.closeSync(output);
  }
  fs.writeFileSync(`${outputPath}.manifest.json`, `${JSON.stringify({
    schema_version: 1,
    target_replay_version: replay.header.version,
    output: outputPath,
    packet_ids: [...selected].sort((left, right) => left - right),
    selected_packet_count: count,
    packet_counts: packetCounts,
    replay_count: 1,
    replays: [{
      path: replay.source_path,
      sha256: replay.source_sha256,
      version: replay.header.version,
      selected_packet_count: count,
      parser_error_count: walked.errors.length,
    }],
    included_stream_tags: [...includeStreams],
    export_scope: 'STRICT_SINGLE_REPLAY_PUBLIC_DEEP_RECOVERY_API',
  }, null, 2)}\n`);
  return { total: count, packet_counts: packetCounts };
}

function runDeepRecoveryPython(scriptName, runtimeImage, packets, output, summary, options) {
  const python = options.pythonExecutable || process.env.PYTHON || 'python';
  const script = path.join(REPOSITORY_ROOT, 'scripts', scriptName);
  const run = childProcess.spawnSync(python, [
    '-B', script,
    '--image', runtimeImage,
    '--events', packets,
    '--output', output,
    '--summary', summary,
    '--progress-every', '0',
  ], {
    cwd: REPOSITORY_ROOT,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  });
  if (run.error || run.status !== 0) {
    const detail = run.error?.message || run.stderr || run.stdout || `exit ${run.status}`;
    throw new Error(`16.16 deep-recovery decoder ${scriptName} failed: ${detail}`);
  }
  return JSON.parse(fs.readFileSync(summary, 'utf8'));
}

function runGameplayRouteTailPython(runtimeImage, packets, output, summary, options) {
  const python = options.pythonExecutable || process.env.PYTHON || 'python';
  const script = path.join(REPOSITORY_ROOT, 'scripts', 'decode_gameplay_route_tail_16_16.py');
  const profileArgs = Object.values(GAMEPLAY_ROUTE_TAIL_PROFILES)
    .flatMap((profile) => [
      '--profile-json', path.resolve(REPOSITORY_ROOT, profile.runtime_decoder_profile),
    ]);
  const run = childProcess.spawnSync(python, [
    '-B', script,
    '--image', runtimeImage,
    '--events', packets,
    ...profileArgs,
    '--runtime-profile', '16.16.805.0442',
    '--output', output,
    '--summary', summary,
    '--progress-every', '0',
  ], {
    cwd: REPOSITORY_ROOT,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  });
  if (run.error || run.status !== 0) {
    const detail = run.error?.message || run.stderr || run.stdout || `exit ${run.status}`;
    throw new Error(`16.16 gameplay-route-tail runtime decoder failed: ${detail}`);
  }
  return JSON.parse(run.stdout);
}

function runRuntimeDecoder(capability, runtimeImage, packets, output, options, extraArgs = []) {
  const python = options.pythonExecutable || process.env.PYTHON || 'python';
  const script = path.join(REPOSITORY_ROOT, 'scripts', 'validate_multi_build_runtime.py');
  const run = childProcess.spawnSync(python, [
    '-B', script,
    '--capability', capability,
    '--runtime-image', runtimeImage,
    '--packets', packets,
    '--output', output,
    '--decode-only',
    ...extraArgs,
  ], {
    cwd: REPOSITORY_ROOT,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  });
  if (run.error || run.status !== 0) {
    const detail = run.error?.message || run.stderr || run.stdout || `exit ${run.status}`;
    throw new Error(`16.16 ${capability} runtime decoder failed: ${detail}`);
  }
  return JSON.parse(run.stdout);
}

function runWardRuntimeDecoder(runtimeImage, packets, participants, output, options) {
  const python = options.pythonExecutable || process.env.PYTHON || 'python';
  const script = path.join(REPOSITORY_ROOT, 'scripts', 'decode_ward_spawn_16_16.py');
  const run = childProcess.spawnSync(python, [
    '-B', script,
    '--runtime-image', runtimeImage,
    '--packets', packets,
    '--participants', participants,
    '--output', output,
    '--progress-every', '0',
    '--validation-scope', 'SINGLE_REPLAY_DECODE',
  ], {
    cwd: REPOSITORY_ROOT,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  });
  if (run.error || run.status !== 0) {
    const detail = run.error?.message || run.stderr || run.stdout || `exit ${run.status}`;
    throw new Error(`16.16 ward_spawn runtime decoder failed: ${detail}`);
  }
  return JSON.parse(run.stdout);
}

function runPacketProfileRuntimeDecoder(
  runtimeImage,
  packets,
  profileJson,
  output,
  summary,
  options,
) {
  const python = options.pythonExecutable || process.env.PYTHON || 'python';
  const script = path.join(REPOSITORY_ROOT, 'scripts', 'emulate_packet_profile_json.py');
  const run = childProcess.spawnSync(python, [
    '-B', script,
    '--image', runtimeImage,
    '--events', packets,
    '--profile-json', profileJson,
    '--runtime-profile', '16.16.805.0442',
    '--output', output,
    '--summary', summary,
    '--progress-every', '0',
  ], {
    cwd: REPOSITORY_ROOT,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  });
  if (run.error || run.status !== 0) {
    const detail = run.error?.message || run.stderr || run.stdout || `exit ${run.status}`;
    throw new Error(`16.16 packet-profile runtime decoder failed: ${detail}`);
  }
  return JSON.parse(run.stdout);
}

function readJsonl(filePath) {
  const source = fs.readFileSync(filePath, 'utf8').trim();
  if (!source) return [];
  return source.split(/\r?\n/).map((line) => JSON.parse(line));
}

function emptyRuntimeDecode(capability, outputDirectory, runtimeImageSha256) {
  fs.mkdirSync(outputDirectory, { recursive: true });
  const outputNames = capability === 'hero_path'
    ? ['hero_path_events.jsonl']
    : capability === 'damage'
      ? ['damage_decoded.jsonl']
    : capability === 'hero_death'
      ? ['death_decoded.jsonl']
    : capability === 'hero_scoreboard_state'
      ? ['hero_stats_decoded.jsonl']
    : capability === 'hero_death_timer'
      ? ['death_timer_decoded.jsonl']
    : capability === 'ward_spawn'
      ? [
        'vision_entity_events_16_16.jsonl',
        'ward_spawn_events_16_16.jsonl',
        'ward_lifecycles_16_16.jsonl',
      ]
      : ['level_transition_decoded.jsonl'];
  for (const outputName of outputNames) fs.writeFileSync(path.join(outputDirectory, outputName), '');
  return {
    schema_version: 1,
    status: 'NO_MATCHING_PACKETS_IN_REPLAY',
    game_version: '16.16.805.0442',
    runtime_image_sha256: runtimeImageSha256,
    packet_rows_selected: 0,
    decoded_rows: 0,
    fully_consumed_success_rows: 0,
    infrastructure_failure_count: 0,
    empty_verified_by_strict_replay_scan: true,
  };
}

function levelTransitionFromRuntimeRow(row, buildProfile) {
  const mapped = levelMapping(row.raw_field_10, buildProfile.game_version);
  const hasLevelMapping = mapped.evidence === 'VERIFIED_DERIVED';
  return levelTransitionEvent({
    game_version: buildProfile.game_version,
    patch: buildProfile.patch,
    build_profile: row.build_profile,
    confidence: hasLevelMapping ? 'VERIFIED_DERIVED' : 'PARTIAL',
    semantic_status: hasLevelMapping
      ? 'SEMANTIC_VERIFIED_DERIVED_BUILD_BOUND'
      : 'SEMANTIC_PARTIAL_DIRECT_TRANSITION_UNMAPPED_LEVEL',
    replay_sha256: row.replay_sha256,
    replay_time_ms: row.replay_time_ms,
    timestamp_ms: row.replay_time_ms,
    source_network_id: row.entity_network_id,
    entity_network_id: row.entity_network_id,
    participant_id: row.participant_id,
    source_participant_id: row.participant_id,
    raw_field_10: row.raw_field_10,
    raw_field_11: row.raw_field_11,
    level_before: mapped.level_before,
    level_after: mapped.level_after,
    transition_evidence: 'VERIFIED_DIRECT',
    level_mapping_evidence: mapped.evidence,
    field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT',
      entity_network_id: 'VERIFIED_DIRECT',
      participant_id: 'VERIFIED_DIRECT',
      raw_field_10: 'VERIFIED_DIRECT',
      raw_field_11: 'VERIFIED_DIRECT',
      level_transition: 'VERIFIED_DIRECT',
      level_before: hasLevelMapping ? 'VERIFIED_DERIVED_BUILD_BOUND' : 'UNAVAILABLE',
      level_after: hasLevelMapping ? 'VERIFIED_DERIVED_BUILD_BOUND' : 'UNAVAILABLE',
    },
    is_initialization: row.replay_time_ms === 0 && !hasLevelMapping,
    raw_packet_ref: {
      replay_sha256: row.replay_sha256,
      packet_id: row.packet_id,
      chunk_index: row.chunk_index,
      decompressed_block_offset: row.decompressed_block_offset,
      payload_length: row.payload_length,
      raw_param: row.raw_param,
      raw_payload_sha256: row.raw_payload_sha256,
      packet_timestamp_ms: row.replay_time_ms,
    },
  });
}

function participantMetadataForReplay(
  replay,
  outputPath,
  validationScope = 'SINGLE_REPLAY_DECODE',
) {
  if (!['CORPUS_RELEASE_GATE', 'SINGLE_REPLAY_DECODE'].includes(validationScope)) {
    throw new RangeError(`unsupported 16.16 Ward validation scope: ${validationScope}`);
  }
  const stats = replay.tail?.stats;
  const minimumParticipantRows = validationScope === 'CORPUS_RELEASE_GATE' ? 10 : 1;
  if (
    !Array.isArray(stats)
    || stats.length < minimumParticipantRows
    || stats.length > 10
    || replay.tail?.stats_parse_error
  ) {
    throw new Error(
      validationScope === 'CORPUS_RELEASE_GATE'
        ? '16.16 Ward corpus release requires ten valid Replay tail participant rows'
        : '16.16 Ward single-Replay decode requires one to ten valid Replay tail participant rows',
    );
  }
  const replayLabel = path.basename(replay.source_path, path.extname(replay.source_path));
  const participants = stats.map((stat, index) => {
    const participantId = index + 1;
    if (!stat || typeof stat !== 'object' || Array.isArray(stat)) {
      throw new Error(`invalid Replay tail participant row for participant ${participantId}`);
    }
    const teamId = Number(stat.TEAM);
    if (!Number.isInteger(teamId) || ![100, 200].includes(teamId)) {
      throw new Error(`invalid Replay tail TEAM for participant ${participantId}: ${stat.TEAM}`);
    }
    return {
      participant_id: participantId,
      owner_network_id: 0x400000ad + participantId,
      owner_network_id_hex: `0x${(0x400000ad + participantId).toString(16).padStart(8, '0')}`,
      team_id: teamId,
      champion: stat.SKIN || null,
      ward_placed: Number(stat.WARD_PLACED || 0),
      detector_wards_placed: Number(stat.WARD_PLACED_DETECTOR || 0),
      vision_wards_bought: Number(stat.VISION_WARDS_BOUGHT_IN_GAME || 0),
      sight_wards_bought: Number(stat.SIGHT_WARDS_BOUGHT_IN_GAME || 0),
    };
  });
  const presentParticipantIds = participants.map((participant) => participant.participant_id);
  const missingParticipantIds = Array.from({ length: 10 }, (_ignored, index) => index + 1)
    .filter((participantId) => !presentParticipantIds.includes(participantId));
  const roster = {
    expected_participant_count: 10,
    available_participant_count: participants.length,
    completeness: participants.length === 10 ? 'COMPLETE' : 'PARTIAL',
    present_participant_ids: presentParticipantIds,
    missing_participant_ids: missingParticipantIds,
    missing_owner_mappings_fabricated: false,
  };
  const document = {
    schema_version: 1,
    target_replay_version: replay.header.version,
    validation_scope: validationScope,
    participant_network_id_formula: '0x400000ad + participant_id',
    source: 'Replay tail participant stats; exact Replay SHA-256 bound',
    replay_count: 1,
    replays: [{
      replay_label: replayLabel,
      replay_path: replay.source_path,
      replay_sha256: replay.source_sha256,
      replay_version: replay.header.version,
      roster,
      participants,
    }],
  };
  fs.writeFileSync(outputPath, `${JSON.stringify(document, null, 2)}\n`);
  return document;
}

function decode1616(replay, buildProfile, options = {}) {
  const sweeperCapability = createSweeperCapabilityExport(buildProfile.game_version);
  const runtimeImage = path.resolve(options.runtimeImagePath || DEFAULT_16_16_RUNTIME_IMAGE);
  if (!fs.existsSync(runtimeImage)) {
    return {
      status: 'BLOCKED',
      release_level: 'BLOCKED',
      profile: buildProfile,
      events: null,
      sweeper_capability: sweeperCapability,
      decoded_packet_count: 0,
      note: `Exact runtime image is required: ${runtimeImage}`,
    };
  }
  const runtimeImageSha256 = sha256File(runtimeImage);
  if (runtimeImageSha256 !== buildProfile.runtime_profile.image_sha256) {
    throw new Error(
      `wrong 16.16 runtime image SHA-256: ${runtimeImageSha256}`,
    );
  }
  if (!replay.source_path) {
    throw new TypeError('16.16 semantic decoding requires a parsed Replay with source_path');
  }

  const temporaryRoot = path.resolve(os.tmpdir());
  const temporaryDirectory = fs.mkdtempSync(path.join(temporaryRoot, 'rofl-16-16-'));
  try {
    const pathPackets = path.join(temporaryDirectory, 'path_packets.jsonl');
    const levelPackets = path.join(temporaryDirectory, 'level_packets.jsonl');
    const pathOutput = path.join(temporaryDirectory, 'path');
    const levelOutput = path.join(temporaryDirectory, 'level');
    const wardPackets = path.join(temporaryDirectory, 'ward_packets.jsonl');
    const wardParticipants = path.join(temporaryDirectory, 'ward_participants.json');
    const wardOutput = path.join(temporaryDirectory, 'ward');
    const damagePackets = path.join(temporaryDirectory, 'damage_packets.jsonl');
    const damageOutput = path.join(temporaryDirectory, 'damage');
    const damageDecoded = path.join(damageOutput, 'damage_decoded.jsonl');
    const damageSummaryPath = path.join(damageOutput, 'damage_decode_summary.json');
    const deathPackets = path.join(temporaryDirectory, 'death_packets.jsonl');
    const deathOutput = path.join(temporaryDirectory, 'death');
    const deathDecoded = path.join(deathOutput, 'death_decoded.jsonl');
    const deathSummaryPath = path.join(deathOutput, 'death_decode_summary.json');
    const heroStatsPackets = path.join(temporaryDirectory, 'hero_stats_packets.jsonl');
    const heroStatsOutput = path.join(temporaryDirectory, 'hero_scoreboard_state');
    const heroStatsDecoded = path.join(heroStatsOutput, 'hero_stats_decoded.jsonl');
    const heroStatsSummaryPath = path.join(heroStatsOutput, 'hero_stats_decode_summary.json');
    const deathTimerPackets = path.join(temporaryDirectory, 'death_timer_packets.jsonl');
    const deathTimerOutput = path.join(temporaryDirectory, 'death_timer');
    const deathTimerDecoded = path.join(deathTimerOutput, 'death_timer_decoded.jsonl');
    const deathTimerSummaryPath = path.join(deathTimerOutput, 'death_timer_decode_summary.json');
    const reincarnatePackets = path.join(temporaryDirectory, 'reincarnate_packets.jsonl');
    const reincarnateOutput = path.join(temporaryDirectory, 'hero_reincarnate_alive');
    const reincarnateDecoded = path.join(reincarnateOutput, 'reincarnate_decoded.jsonl');
    const reincarnateSummaryPath = path.join(
      reincarnateOutput, 'reincarnate_decode_summary.json',
    );
    const buffSpellPackets = path.join(temporaryDirectory, 'buff_spell_packets.jsonl');
    const buffSpellDecoded = path.join(temporaryDirectory, 'buff_spell_decoded.jsonl');
    const buffSpellSummaryPath = path.join(temporaryDirectory, 'buff_spell_decode_summary.json');
    const protectionPackets = path.join(temporaryDirectory, 'protection_packets.jsonl');
    const protectionDecoded = path.join(temporaryDirectory, 'protection_decoded.jsonl');
    const protectionSummaryPath = path.join(temporaryDirectory, 'protection_decode_summary.json');
    const itemPackets = path.join(temporaryDirectory, 'item_packets.jsonl');
    const gameplayTailPackets = path.join(temporaryDirectory, 'gameplay_tail_packets.jsonl');
    const gameplayTailDecoded = path.join(temporaryDirectory, 'gameplay_tail_decoded.jsonl');
    const gameplayTailSummaryPath = path.join(
      temporaryDirectory, 'gameplay_tail_decode_summary.json',
    );
    const damageProfile = path.resolve(
      options.damageProfilePath || DEFAULT_16_16_DAMAGE_PROFILE,
    );
    const deathProfile = path.resolve(
      options.deathProfilePath || DEFAULT_16_16_DEATH_PROFILE,
    );
    const heroStatsProfile = path.resolve(
      options.heroStatsProfilePath || DEFAULT_16_16_HERO_STATS_PROFILE,
    );
    const deathTimerProfile = path.resolve(
      options.deathTimerProfilePath || DEFAULT_16_16_DEATH_TIMER_PROFILE,
    );
    const reincarnateProfile = path.resolve(
      options.heroReincarnateAliveProfilePath
        || DEFAULT_16_16_HERO_REINCARNATE_ALIVE_PROFILE,
    );
    const pathPacketCount = exportPackets(replay, pathPackets, 0x00f6);
    const levelPacketCount = exportPackets(
      replay,
      levelPackets,
      0x0314,
      (block) => block.param >= 0x400000ae && block.param <= 0x400000b7,
    );
    const wardPacketCount = exportPackets(replay, wardPackets, 0x049a);
    const damagePacketCount = exportPackets(
      replay,
      damagePackets,
      DAMAGE_PROFILE_16_16.replay_block_packet_id,
    );
    const deathPacketCount = exportPackets(
      replay,
      deathPackets,
      DEATH_PROFILE_16_16.replay_block_packet_id,
    );
    const heroStatsPacketCount = exportPackets(
      replay,
      heroStatsPackets,
      HERO_STATS_PROFILE_16_16.replay_block_packet_id,
      () => true,
      [HERO_STATS_PROFILE_16_16.stream_tag],
    );
    const deathTimerPacketCount = exportPackets(replay, deathTimerPackets, 0x0074);
    const reincarnatePacketCount = exportPackets(
      replay,
      reincarnatePackets,
      HERO_REINCARNATE_ALIVE_PROFILE.packet_id,
    );
    const buffSpellExport = exportPacketSet(
      replay,
      buffSpellPackets,
      [0x0123, 0x01cf, 0x0326, 0x041f, 0x043c, 0x045b],
      [1, 2, 3],
    );
    const protectionExport = exportPacketSet(replay, protectionPackets, [0x0371], [1, 2, 3]);
    const itemExport = exportPacketSet(
      replay,
      itemPackets,
      [0x005a, 0x0064, 0x006c, 0x01e8, 0x02ea, 0x0310, 0x0311],
      [1, 2, 3],
    );
    const gameplayTailExport = exportPacketSet(
      replay,
      gameplayTailPackets,
      Object.values(GAMEPLAY_ROUTE_TAIL_PROFILES).map((profile) => profile.packet_id),
      [1, 2, 3],
    );
    const pathSummary = pathPacketCount > 0
      ? runRuntimeDecoder('hero_path', runtimeImage, pathPackets, pathOutput, options)
      : emptyRuntimeDecode('hero_path', pathOutput, runtimeImageSha256);
    const levelSummary = levelPacketCount > 0
      ? runRuntimeDecoder('level_transition', runtimeImage, levelPackets, levelOutput, options)
      : emptyRuntimeDecode('level_transition', levelOutput, runtimeImageSha256);
    participantMetadataForReplay(replay, wardParticipants, 'SINGLE_REPLAY_DECODE');
    const wardSummary = wardPacketCount > 0
      ? runWardRuntimeDecoder(runtimeImage, wardPackets, wardParticipants, wardOutput, options)
      : emptyRuntimeDecode('ward_spawn', wardOutput, runtimeImageSha256);
    const damageSummary = damagePacketCount > 0
      ? runPacketProfileRuntimeDecoder(
        runtimeImage,
        damagePackets,
        damageProfile,
        damageDecoded,
        damageSummaryPath,
        options,
      )
      : emptyRuntimeDecode('damage', damageOutput, runtimeImageSha256);
    const deathSummary = deathPacketCount > 0
      ? runPacketProfileRuntimeDecoder(
        runtimeImage,
        deathPackets,
        deathProfile,
        deathDecoded,
        deathSummaryPath,
        options,
      )
      : emptyRuntimeDecode('hero_death', deathOutput, runtimeImageSha256);
    const heroStatsSummary = heroStatsPacketCount > 0
      ? runPacketProfileRuntimeDecoder(
        runtimeImage,
        heroStatsPackets,
        heroStatsProfile,
        heroStatsDecoded,
        heroStatsSummaryPath,
        options,
      )
      : emptyRuntimeDecode(
        'hero_scoreboard_state',
        heroStatsOutput,
        runtimeImageSha256,
      );
    const deathTimerSummary = deathTimerPacketCount > 0
      ? runPacketProfileRuntimeDecoder(
        runtimeImage,
        deathTimerPackets,
        deathTimerProfile,
        deathTimerDecoded,
        deathTimerSummaryPath,
        options,
      )
      : emptyRuntimeDecode('hero_death_timer', deathTimerOutput, runtimeImageSha256);
    const reincarnateSummary = reincarnatePacketCount > 0
      ? runPacketProfileRuntimeDecoder(
        runtimeImage,
        reincarnatePackets,
        reincarnateProfile,
        reincarnateDecoded,
        reincarnateSummaryPath,
        options,
      )
      : emptyRuntimeDecode(
        'hero_reincarnate_alive',
        reincarnateOutput,
        runtimeImageSha256,
      );
    const buffSpellSummary = buffSpellExport.total > 0
      ? runDeepRecoveryPython(
        'decode_buff_spell_callbacks_16_16_deep.py',
        runtimeImage,
        buffSpellPackets,
        buffSpellDecoded,
        buffSpellSummaryPath,
        options,
      )
      : null;
    const protectionSummary = protectionExport.total > 0
      ? runDeepRecoveryPython(
        'decode_on_event_16_16_deep.py',
        runtimeImage,
        protectionPackets,
        protectionDecoded,
        protectionSummaryPath,
        options,
      )
      : null;
    const gameplayTailSummary = gameplayTailExport.total > 0
      ? runGameplayRouteTailPython(
        runtimeImage,
        gameplayTailPackets,
        gameplayTailDecoded,
        gameplayTailSummaryPath,
        options,
      )
      : null;
    const heroPaths = readJsonl(path.join(pathOutput, 'hero_path_events.jsonl'))
      .map((event) => ({
        ...event,
        confidence: 'VERIFIED_DERIVED',
        semantic_status: 'SEMANTIC_VERIFIED_DERIVED',
        field_confidence: {
          replay_time_ms: 'VERIFIED_DIRECT',
          entity_network_id: 'VERIFIED_DIRECT',
          participant_id: 'VERIFIED_DIRECT',
          speed: 'VERIFIED_DERIVED_RUNTIME_DECODE',
          encoded_waypoints: 'VERIFIED_DERIVED_RUNTIME_DECODE',
          waypoints_xz: 'VERIFIED_DERIVED_CURRENT_CALIBRATION',
        },
      }));
    const levelTransitionKeys = new Set();
    const levelTransitions = readJsonl(
      path.join(levelOutput, 'level_transition_decoded.jsonl'),
    ).map((row) => levelTransitionFromRuntimeRow(row, buildProfile)).filter((event) => {
      const key = [
        event.replay_sha256,
        event.replay_time_ms,
        event.participant_id,
        event.raw_field_10,
        event.raw_field_11,
      ].join(':');
      if (levelTransitionKeys.has(key)) return false;
      levelTransitionKeys.add(key);
      return true;
    });
    const visionEntityEvents = readJsonl(path.join(wardOutput, 'vision_entity_events_16_16.jsonl'));
    const wardSpawns = readJsonl(path.join(wardOutput, 'ward_spawn_events_16_16.jsonl'));
    const wardLifecycles = readJsonl(path.join(wardOutput, 'ward_lifecycles_16_16.jsonl'));
    const confirmedWardSpawns = wardSpawns.filter(
      (event) => event.vision_entity_class === 'PLAYER_ACTIVE_WARD_CONFIRMED',
    );
    const damageParticipants = damageParticipantMetadata16(replay);
    const damageEvents = readJsonl(damageDecoded)
      .map((row) => damageEventFromDecodedRow16(replay, row, damageParticipants));
    const damageReplayDecodeVerified = damagePacketCount === 0
      ? damageSummary.status === 'NO_MATCHING_PACKETS_IN_REPLAY'
        && damageSummary.runtime_image_sha256 === runtimeImageSha256
        && damageSummary.empty_verified_by_strict_replay_scan === true
      : damageSummary.image_sha256 === runtimeImageSha256
        && damageSummary.decoder_profile === DAMAGE_PROFILE_16_16.id
        && damageSummary.event_count === damagePacketCount
        && damageSummary.successful_full_consume_count === damagePacketCount
        && (damageSummary.emulation_error_count ?? 0) === 0
        && damageEvents.length === damagePacketCount
        && damageEvents.every((event) => event !== null);
    if (!damageReplayDecodeVerified) {
      throw new Error('16.16 Damage replay decode did not satisfy the exact-build structural gate');
    }
    const deathRouteDecode = decodeHeroDeathRoutes16(replay, { strict: true });
    const deathParticipants = deathParticipantMetadata16(replay);
    const deathEvents = readJsonl(deathDecoded)
      .map((row) => decodeHeroDeathDecodedRow16(replay, row, deathParticipants));
    const deathReplayDecodeVerified = deathPacketCount === 0
      ? deathSummary.status === 'NO_MATCHING_PACKETS_IN_REPLAY'
        && deathSummary.runtime_image_sha256 === runtimeImageSha256
        && deathSummary.empty_verified_by_strict_replay_scan === true
        && deathRouteDecode.signature_count === 0
      : deathSummary.image_sha256 === runtimeImageSha256
        && deathSummary.decoder_profile === 'runtime_candidate_16_16_0112'
        && deathSummary.profile_sha256 === DEATH_PROFILE_16_16.profile_sha256
        && deathSummary.event_count === deathPacketCount
        && deathSummary.successful_full_consume_count === deathPacketCount
        && Object.keys(deathSummary.emulation_errors ?? {}).length === 0
        && deathRouteDecode.walk.errors.length === 0
        && deathRouteDecode.rejected_signature_count === 0
        && deathRouteDecode.signature_count === deathPacketCount
        && deathEvents.length === deathPacketCount
        && deathEvents.every((event) => event !== null);
    if (!deathReplayDecodeVerified) {
      throw new Error('16.16 HeroDeath replay decode did not satisfy the exact-build payload gate');
    }
    const heroStatsParticipants = heroStatsParticipantMetadata16(replay);
    const heroScoreboardStates = readJsonl(heroStatsDecoded)
      .map((row) => heroScoreboardStateFromDecodedRow16(replay, row, heroStatsParticipants));
    const heroStatsReplayDecodeVerified = heroStatsPacketCount === 0
      ? heroStatsSummary.status === 'NO_MATCHING_PACKETS_IN_REPLAY'
        && heroStatsSummary.runtime_image_sha256 === runtimeImageSha256
        && heroStatsSummary.empty_verified_by_strict_replay_scan === true
      : heroStatsSummary.image_sha256 === runtimeImageSha256
        && heroStatsSummary.profile_sha256 === HERO_STATS_PROFILE_16_16.profile_sha256
        && heroStatsSummary.event_count === heroStatsPacketCount
        && heroStatsSummary.successful_full_consume_count === heroStatsPacketCount
        && Object.keys(heroStatsSummary.emulation_errors ?? {}).length === 0
        && heroScoreboardStates.length === heroStatsPacketCount
        && heroScoreboardStates.every((event) => event !== null);
    if (!heroStatsReplayDecodeVerified) {
      throw new Error('16.16 HeroStats replay decode did not satisfy the exact-build scoreboard gate');
    }
    const deathTimerRows = readJsonl(deathTimerDecoded);
    const deathTimerEvents = deathTimerRows
      .map((row) => deathTimerEventFromDecodedRow(replay, row));
    const deathTimerReplayDecodeVerified = deathTimerPacketCount === 0
      ? deathTimerSummary.status === 'NO_MATCHING_PACKETS_IN_REPLAY'
        && deathTimerSummary.runtime_image_sha256 === runtimeImageSha256
        && deathTimerSummary.empty_verified_by_strict_replay_scan === true
      : deathTimerSummary.image_sha256 === runtimeImageSha256
        && deathTimerSummary.profile_sha256
          === buildProfile.decoder_profile.hero_death_timer.runtime_decoder_profile_sha256
        && deathTimerSummary.event_count === deathTimerPacketCount
        && deathTimerSummary.successful_full_consume_count === deathTimerPacketCount
        && Object.keys(deathTimerSummary.emulation_errors ?? {}).length === 0
        && deathTimerEvents.length === deathTimerPacketCount;
    if (!deathTimerReplayDecodeVerified) {
      throw new Error('16.16 death-timer replay decode did not satisfy the exact-build gate');
    }
    const reincarnateRows = readJsonl(reincarnateDecoded);
    const reincarnateEvents = reincarnateRows
      .map((row) => heroReincarnateAliveEventFromDecodedRow(replay, row));
    const canonicalReincarnateEvents = reincarnateEvents
      .map(canonicalHeroReincarnateAliveEvent);
    const reincarnateReplayDecodeVerified = reincarnatePacketCount === 0
      ? reincarnateSummary.status === 'NO_MATCHING_PACKETS_IN_REPLAY'
        && reincarnateSummary.runtime_image_sha256 === runtimeImageSha256
        && reincarnateSummary.empty_verified_by_strict_replay_scan === true
      : reincarnateSummary.image_sha256 === runtimeImageSha256
        && reincarnateSummary.profile_sha256
          === HERO_REINCARNATE_ALIVE_PROFILE.runtime_decoder_profile_sha256
        && reincarnateSummary.decoder_profile
          === HERO_REINCARNATE_ALIVE_PROFILE.runtime_decoder_profile_id
        && reincarnateSummary.event_count === reincarnatePacketCount
        && reincarnateSummary.successful_full_consume_count === reincarnatePacketCount
        && Object.keys(reincarnateSummary.emulation_errors ?? {}).length === 0
        && reincarnateEvents.length === reincarnatePacketCount
        && canonicalReincarnateEvents.every((event) => validateCanonicalRecord(event));
    if (!reincarnateReplayDecodeVerified) {
      throw new Error(
        '16.16 HeroReincarnateAlive replay decode did not satisfy the exact-build gate',
      );
    }
    const buffSpellRows = buffSpellExport.total > 0 ? readJsonl(buffSpellDecoded) : [];
    const buffEvents = buffSpellRows.filter((row) => row.packet_id !== 0x01cf)
      .map((row) => buffEventFromDecodedRow(replay, row));
    const spellEvents = buffSpellRows.filter((row) => row.packet_id === 0x01cf)
      .map((row) => spellCastEventFromDecodedRow(replay, row));
    const buffSpellReplayDecodeVerified = buffSpellExport.total === 0
      ? true
      : buffSpellSummary?.status === 'PASS'
        && buffSpellSummary.runtime_image?.sha256 === runtimeImageSha256
        && buffSpellSummary.selected_route_rows === buffSpellExport.total
        && buffSpellSummary.deserialize_success_rows === buffSpellExport.total
        && buffSpellSummary.fully_consumed_rows === buffSpellExport.total
        && buffEvents.length + spellEvents.length === buffSpellExport.total;
    if (!buffSpellReplayDecodeVerified) {
      throw new Error('16.16 Buff/Spell replay decode did not satisfy the exact-build gate');
    }
    const protectionRows = protectionExport.total > 0 ? readJsonl(protectionDecoded)
      .filter((row) => [0x004b, 0x00ed, 0x00ee].includes(row.event_id)) : [];
    const protectionEvents = protectionRows.length > 0
      ? canonicalProtectionEventsFromDecodedRows(replay, protectionRows) : [];
    const protectionReplayDecodeVerified = protectionExport.total === 0
      ? true
      : protectionSummary?.status === 'PASS'
        && protectionSummary.runtime_image?.sha256 === runtimeImageSha256
        && protectionSummary.input_route_rows === protectionExport.total
        && protectionSummary.deserialize_success_rows === protectionExport.total
        && protectionSummary.fully_consumed_rows === protectionExport.total;
    if (!protectionReplayDecodeVerified) {
      throw new Error('16.16 Protection replay decode did not satisfy the exact-build gate');
    }
    const gameplayTailRows = gameplayTailExport.total > 0
      ? readJsonl(gameplayTailDecoded) : [];
    const gameplayTailRuntimeImage = gameplayTailExport.total > 0
      ? fs.readFileSync(runtimeImage) : null;
    const gameplayTailEvents = gameplayTailRows.map((row) =>
      gameplayRouteTailEventFromDecodedRow(replay, row, gameplayTailRuntimeImage));
    const canonicalGameplayTailEvents = gameplayTailEvents.map(canonicalGameplayRouteTailEvent);
    const gameplayTailReplayDecodeVerified = gameplayTailExport.total === 0
      ? true
      : gameplayTailSummary?.status === 'PASS'
        && gameplayTailSummary.exact_build === buildProfile.game_version
        && gameplayTailSummary.image_sha256 === runtimeImageSha256
        && gameplayTailSummary.input_event_count === gameplayTailExport.total
        && gameplayTailSummary.output_row_count === gameplayTailExport.total
        && gameplayTailSummary.successful_full_consume_count === gameplayTailExport.total
        && gameplayTailSummary.emulation_error_count === 0
        && gameplayTailSummary.input_conserved === true
        && gameplayTailEvents.length === gameplayTailExport.total
        && Object.values(GAMEPLAY_ROUTE_TAIL_PROFILES).every((profile) => {
          const route = `0x${profile.packet_id.toString(16).padStart(4, '0')}`;
          const summary = gameplayTailSummary.routes?.[route];
          return summary?.profile_sha256 === profile.runtime_decoder_profile_sha256
            && summary?.decoder_profile === profile.runtime_decoder_profile_id
            && summary?.input_event_count === gameplayTailExport.packet_counts[profile.packet_id]
            && summary?.successful_full_consume_count
              === gameplayTailExport.packet_counts[profile.packet_id];
        });
    if (!gameplayTailReplayDecodeVerified) {
      throw new Error('16.16 gameplay-route-tail decode did not satisfy the exact-build gate');
    }
    const itemRawRows = itemExport.total > 0 ? readJsonl(itemPackets) : [];
    const supportQuestRows = itemRawRows.filter((row) => row.packet_id === 0x0064);
    let supportQuestDecode = {
      events: [], residuals: [...supportQuestRows], input_row_count: supportQuestRows.length,
      canonical_event_count: 0, residual_row_count: supportQuestRows.length,
      input_conserved: true, status: 'NO_MATCHING_PACKETS_IN_REPLAY',
    };
    if (supportQuestRows.length > 0) {
      const utilityParticipants = (replay.tail?.stats ?? []).map((row, index) => ({
        participant_id: index + 1,
        team_position: row.TEAM_POSITION ?? null,
      })).filter((row) => row.team_position === 'UTILITY')
        .map((row) => row.participant_id);
      supportQuestDecode = JSON.stringify(utilityParticipants.sort((a, b) => a - b))
        === JSON.stringify([5, 10])
        ? { ...supportQuestStageEventsFromRows(replay, supportQuestRows), status: 'PASS' }
        : {
          ...supportQuestDecode,
          status: 'ROSTER_UTILITY_METADATA_UNAVAILABLE',
          residuals: supportQuestRows.map((row) => ({
            ...row, residual_reason: 'ROSTER_UTILITY_METADATA_UNAVAILABLE',
          })),
        };
    }
    if (supportQuestDecode.input_conserved !== true) {
      throw new Error('16.16 support-quest item-stage adapter failed packet conservation');
    }
    const itemEvents = [...supportQuestDecode.events];
    const wardProfile = buildProfile.decoder_profile.ward_spawn;
    const wardReplayDecodeVerified = wardPacketCount === 0
      ? wardSummary.status === 'NO_MATCHING_PACKETS_IN_REPLAY'
        && wardSummary.runtime_image_sha256 === runtimeImageSha256
        && wardSummary.empty_verified_by_strict_replay_scan === true
      : wardSummary.status === 'PASS'
        && wardSummary.runtime_image_sha256_verified === true
        && wardSummary.counts?.valid_input_rows === wardPacketCount
        && wardSummary.counts?.fully_consumed === wardPacketCount
        && wardSummary.counts?.input_provenance_failures === 0
        && wardSummary.counts?.infrastructure_failures === 0;
    if (!wardReplayDecodeVerified) {
      throw new Error('16.16 Ward replay decode did not satisfy the exact-build structural gate');
    }
    const result = {
      status: buildProfile.support_level,
      release_level: buildProfile.support_level,
      downstream_gate: buildProfile.downstream_release_gate,
      status_basis: 'EXACT_BUILD_PROFILE_PLUS_CURRENT_REPLAY_DECODE_ATTESTATION',
      event_observation_status: pathPacketCount + levelPacketCount + wardPacketCount
        + damagePacketCount + deathPacketCount + heroStatsPacketCount
        + deathTimerPacketCount + reincarnatePacketCount
        + buffSpellExport.total + protectionExport.total
        + itemExport.total + gameplayTailExport.total > 0
        ? 'VERIFIED_EVENTS_OBSERVED'
        : 'NO_VERIFIED_EVENTS_OBSERVED',
      profile: buildProfile,
      events: {
        hero_path_events: heroPaths,
        position_events: gameplayTailEvents.filter(
          (event) => event.event_type === 'FACE_DIRECTION_VECTOR',
        ),
        level_transition_events: levelTransitions,
        ward_events: confirmedWardSpawns,
        vision_entity_events: visionEntityEvents,
        ward_spawn_events: wardSpawns,
        ward_lifecycle_events: wardLifecycles,
        damage_events: damageEvents,
        death_events: deathEvents,
        death_timer_events: deathTimerEvents,
        reincarnate_alive_events: reincarnateEvents,
        respawn_events: reincarnateEvents,
        canonical_respawn_events: canonicalReincarnateEvents,
        canonical_entity_lifecycle_events: canonicalReincarnateEvents,
        hero_state_events: heroScoreboardStates,
        state_update_events: heroScoreboardStates,
        spell_events: spellEvents,
        buff_events: buffEvents,
        shield_events: protectionEvents.filter((event) => event.protection_type === 'SHIELD_APPLICATION'),
        heal_events: protectionEvents.filter((event) => event.protection_type === 'HEAL_REPORTED'),
        protection_events: protectionEvents,
        item_events: itemEvents,
        gameplay_route_tail_events: gameplayTailEvents,
        canonical_gameplay_route_tail_events: canonicalGameplayTailEvents,
        canonical_attack_events: canonicalGameplayTailEvents.filter(
          (event) => event.semantic_type === 'AttackEvent',
        ),
        canonical_spell_state_events: canonicalGameplayTailEvents.filter(
          (event) => event.semantic_type === 'SpellState',
        ),
        canonical_position_events: canonicalGameplayTailEvents.filter(
          (event) => event.semantic_type === 'PositionEvent',
        ),
        canonical_missile_events: canonicalGameplayTailEvents.filter(
          (event) => event.semantic_type === 'MissileEvent',
        ),
        canonical_entity_component_state_events: canonicalGameplayTailEvents.filter(
          (event) => event.semantic_type === 'EntityComponentState',
        ),
        attack_events: gameplayTailEvents.filter((event) => [
          'INSTANT_STOP_ATTACK', 'BASIC_ATTACK_POSITION_MINION',
        ].includes(event.event_type)),
        spell_state_events: gameplayTailEvents.filter(
          (event) => event.event_type === 'ABILITY_COOLDOWN_BROADCAST',
        ),
        missile_events: gameplayTailEvents.filter(
          (event) => event.event_type === 'MISSILE_MOVEMENT_COMPLETE',
        ),
        entity_component_state_events: gameplayTailEvents.filter(
          (event) => event.event_type === 'WALL_TRACKING_CACHE_SNAPSHOT',
        ),
        ...emptySweeperEvents(),
      },
      capabilities: {
        participant_mapping: buildProfile.field_semantics.participant_mapping,
        hero_path: buildProfile.field_semantics.hero_path,
        level_transition: buildProfile.field_semantics.level_transition,
        level_after: buildProfile.field_semantics.level_after,
        ward_spawn: wardProfile.semantic_status,
        ward_lifecycle: wardProfile.lifecycle_status,
        hero_damage: buildProfile.field_semantics.hero_damage,
        hero_death: buildProfile.field_semantics.hero_death,
        hero_death_timer: buildProfile.field_semantics.hero_death_timer,
        hero_reincarnate_alive:
          buildProfile.field_semantics.hero_reincarnate_alive,
        hero_scoreboard_state: buildProfile.field_semantics.hero_scoreboard_state
          ?? HERO_STATS_PROFILE_16_16.semantic_status,
        experience_points: buildProfile.field_semantics.experience_points
          ?? 'SEMANTIC_VERIFIED_DIRECT',
        lane_minions_killed: buildProfile.field_semantics.lane_minions_killed
          ?? 'SEMANTIC_VERIFIED_DIRECT',
        total_gold: 'CANDIDATE_NOT_PUBLISHED',
        jungle_minions_killed: 'CANDIDATE_NOT_PUBLISHED',
        buff: buildProfile.field_semantics.buff,
        cast_spell: buildProfile.field_semantics.cast_spell,
        heal_reported: buildProfile.field_semantics.heal_reported,
        shield_generated: buildProfile.field_semantics.shield_generated,
        item_state: buildProfile.field_semantics.item_state,
        item_swap: buildProfile.field_semantics.item_swap,
        item_substitution_map: buildProfile.field_semantics.item_substitution_map,
        support_quest_item_stage: buildProfile.field_semantics.support_quest_item_stage,
        face_direction_vector: buildProfile.field_semantics.face_direction_vector,
        instant_stop_attack: buildProfile.field_semantics.instant_stop_attack,
        basic_attack_position_minion: buildProfile.field_semantics.basic_attack_position_minion,
        ability_cooldown_broadcast: buildProfile.field_semantics.ability_cooldown_broadcast,
        missile_movement_complete_count:
          buildProfile.field_semantics.missile_movement_complete_count,
        wall_tracking_component_cache_snapshot:
          buildProfile.field_semantics.wall_tracking_component_cache_snapshot,
        trinket_state: sweeperCapability.capabilities.TRINKET_STATE.status,
        trinket_slot_state: sweeperCapability.capabilities.TRINKET_SLOT_STATE.status,
        trinket_swap: sweeperCapability.capabilities.TRINKET_SWAP.status,
        trinket_purchase_or_swap: sweeperCapability.capabilities.TRINKET_PURCHASE_OR_SWAP.status,
        sweeper_held: sweeperCapability.capabilities.SWEEPER_HELD.status,
        sweeper_activation: sweeperCapability.capabilities.SWEEPER_ACTIVATION.status,
        sweeper_active_interval: sweeperCapability.capabilities.SWEEPER_ACTIVE_INTERVAL.status,
        sweeper_position: sweeperCapability.capabilities.SWEEPER_POSITION.status,
        sweeper_owner: sweeperCapability.capabilities.SWEEPER_OWNER.status,
      },
      sweeper_capability: sweeperCapability,
      release_attestation: {
        source: 'EXACT_BUILD_PROFILE_CORPUS_RELEASE',
        capability_profile: wardProfile.id,
        capability_validation_artifact: wardProfile.validation_artifact,
        profile_support_level: buildProfile.support_level,
        profile_capability_status: wardProfile.semantic_status,
        current_replay_validation_scope: wardSummary.validation_scope
          ?? 'STRICT_REPLAY_SCAN_NO_MATCHING_PACKETS',
        current_replay_decode_status: wardSummary.status,
        current_replay_decode_verified: wardReplayDecodeVerified,
        corpus_release_revalidated_on_current_replay: false,
      },
      damage_release_attestation: {
        source: 'EXACT_BUILD_STATIC_RUNTIME_PLUS_DETAILS_ANCHOR_RELEASE',
        capability_profile: DAMAGE_PROFILE_16_16.id,
        capability_validation_artifact:
          damageSummary.profile_source?.validation_artifact
          ?? 'artifacts/hero_combat_state_v2/damage/damage_16_16_anchor_validation.json',
        profile_support_level: buildProfile.support_level,
        profile_capability_status: buildProfile.field_semantics.hero_damage,
        current_replay_validation_scope: 'STRICT_SINGLE_REPLAY_EXACT_PROFILE_DECODE',
        current_replay_decode_status: damagePacketCount > 0
          ? 'PASS'
          : 'NO_MATCHING_PACKETS_IN_REPLAY',
        current_replay_decode_verified: damageReplayDecodeVerified,
        amount_stage_semantics: 'UNKNOWN',
        corpus_release_revalidated_on_current_replay: false,
      },
      death_release_attestation: {
        source: 'EXACT_BUILD_STATIC_RUNTIME_PLUS_DETAILS_FIELD_DIFFERENTIAL',
        capability_profile: DEATH_PROFILE_16_16.id,
        capability_validation_artifact: DEATH_PROFILE_16_16.validation_artifact,
        profile_support_level: buildProfile.support_level,
        profile_capability_status: buildProfile.field_semantics.hero_death,
        current_replay_validation_scope: 'STRICT_SINGLE_REPLAY_EXACT_PROFILE_DECODE',
        current_replay_decode_status: deathPacketCount > 0
          ? 'PASS'
          : 'NO_MATCHING_PACKETS_IN_REPLAY',
        current_replay_decode_verified: deathReplayDecodeVerified,
        killer_network_id: 'VERIFIED_DIRECT_EXACT_HELPER_INVERSE',
        killer_participant_id: 'VERIFIED_DERIVED_EXACT_BUILD',
        assists: 'UNAVAILABLE_WITH_EXPLICIT_NEGATIVE_DIFFERENTIAL',
        respawn_and_other_inner_fields: 'UNAVAILABLE_OR_UNKNOWN',
        corpus_release_revalidated_on_current_replay: false,
      },
      hero_scoreboard_release_attestation: {
        source: 'EXACT_BUILD_STATIC_RUNTIME_PLUS_DETAILS_FRAME_FIELD_DIFFERENTIAL',
        capability_profile: HERO_STATS_PROFILE_16_16.id,
        capability_validation_artifact: HERO_STATS_PROFILE_16_16.validation_artifact,
        profile_support_level: buildProfile.support_level,
        profile_capability_status: HERO_STATS_PROFILE_16_16.semantic_status,
        current_replay_validation_scope: 'STRICT_SINGLE_REPLAY_EXACT_PROFILE_KEYFRAME_DECODE',
        current_replay_decode_status: heroStatsPacketCount > 0
          ? 'PASS'
          : 'NO_MATCHING_PACKETS_IN_REPLAY',
        current_replay_decode_verified: heroStatsReplayDecodeVerified,
        verified_fields: ['experience_points', 'lane_minions_killed'],
        candidate_not_published_fields: ['total_gold', 'jungle_minions_killed'],
        corpus_release_revalidated_on_current_replay: false,
      },
      deep_recovery_release_attestation: {
        source: 'EXACT_BUILD_RUNTIME_DECODERS_PLUS_SAFE_CORPUS_DIFFERENTIALS',
        exact_build: buildProfile.game_version,
        nearest_build_fallback: 'FORBIDDEN',
        death_timer: {
          capability_profile: buildProfile.decoder_profile.hero_death_timer.id,
          capability_validation_artifact:
            buildProfile.decoder_profile.hero_death_timer.validation_artifact,
          raw_packet_count: deathTimerPacketCount,
          canonical_event_count: deathTimerEvents.length,
          current_replay_decode_verified: deathTimerReplayDecodeVerified,
          respawn_timestamp_semantics: 'NOT_PUBLISHED',
        },
        hero_reincarnate_alive: {
          capability_profile: HERO_REINCARNATE_ALIVE_PROFILE.id,
          capability_validation_artifact:
            HERO_REINCARNATE_ALIVE_PROFILE.validation_artifact,
          raw_packet_count: reincarnatePacketCount,
          canonical_event_count: reincarnateEvents.length,
          current_replay_decode_verified: reincarnateReplayDecodeVerified,
          respawn_timestamp_semantics: 'VERIFIED_DIRECT_EXACT_PACKET_OCCURRENCE',
          position_semantics: 'VERIFIED_DIRECT_PROTOCOL_COORDINATE',
          reincarnate_scalar_semantics: 'UNKNOWN_RESOURCE_LIKE_CANDIDATE',
        },
        buff_spell: {
          capability_profiles: {
            buff: buildProfile.decoder_profile.buff.id,
            cast_spell: buildProfile.decoder_profile.cast_spell.id,
          },
          raw_packet_count: buffSpellExport.total,
          raw_packet_counts_by_route: Object.fromEntries(
            Object.entries(buffSpellExport.packet_counts)
              .map(([packetId, count]) => [`0x${Number(packetId).toString(16).padStart(4, '0')}`, count]),
          ),
          canonical_buff_event_count: buffEvents.length,
          canonical_spell_event_count: spellEvents.length,
          current_replay_decode_verified: buffSpellReplayDecodeVerified,
          causal_damage_attribution: 'NOT_PUBLISHED',
          buff_gameplay_stack_and_duration: 'NOT_PUBLISHED',
        },
        protection: {
          capability_profiles: {
            heal_reported: buildProfile.decoder_profile.heal_reported.id,
            shield_generated: buildProfile.decoder_profile.shield_generated.id,
          },
          raw_route_packet_count: protectionExport.total,
          selected_candidate_row_count: protectionRows.length,
          canonical_event_count: protectionEvents.length,
          exact_duplicate_rows_suppressed: protectionRows.length - protectionEvents.length,
          unclassified_route_row_count: protectionExport.total - protectionRows.length,
          current_replay_decode_verified: protectionReplayDecodeVerified,
          effective_heal_shield_absorbed_or_remaining: 'NOT_PUBLISHED',
        },
        item: {
          capability_profiles: {
            item_state: buildProfile.decoder_profile.item_state.id,
            item_swap: buildProfile.decoder_profile.item_swap.id,
            item_substitution_map: buildProfile.decoder_profile.item_substitution_map.id,
            support_quest_item_stage: buildProfile.decoder_profile.support_quest_item_stage.id,
          },
          raw_packet_count: itemExport.total,
          raw_packet_counts_by_route: Object.fromEntries(
            Object.entries(itemExport.packet_counts)
              .map(([packetId, count]) => [`0x${Number(packetId).toString(16).padStart(4, '0')}`, count]),
          ),
          support_quest_route_row_count: supportQuestRows.length,
          support_quest_canonical_event_count: itemEvents.length,
          support_quest_residual_row_count: supportQuestDecode.residual_row_count,
          support_quest_input_conserved: supportQuestDecode.input_conserved,
          other_exact_rows_requiring_route_specific_materializer:
            itemExport.total - supportQuestRows.length,
          other_exact_rows_status: 'RETAINED_RAW_NOT_SILENTLY_DISCARDED',
          buy_sell_undo_cause_semantics: 'NOT_PUBLISHED',
        },
        gameplay_route_tail: {
          capability_profiles: Object.fromEntries(Object.values(
            GAMEPLAY_ROUTE_TAIL_PROFILES,
          ).map((profile) => [profile.event_type, profile.id])),
          raw_packet_count: gameplayTailExport.total,
          raw_packet_counts_by_route: Object.fromEntries(Object.entries(
            gameplayTailExport.packet_counts,
          ).map(([packetId, count]) => [
            `0x${Number(packetId).toString(16).padStart(4, '0')}`, count,
          ])),
          canonical_research_event_count: gameplayTailEvents.length,
          current_replay_decode_verified: gameplayTailReplayDecodeVerified,
          neutral_field_roles: 'UNKNOWN_RETAINED_DECODED',
          damage_map_truth_or_cooldown_duration_inference: 'NOT_PUBLISHED',
        },
      },
      replay_event_observation: {
        hero_path: pathPacketCount > 0 ? 'EVENTS_OBSERVED' : 'NO_MATCHING_PACKETS',
        level_transition: levelPacketCount > 0 ? 'EVENTS_OBSERVED' : 'NO_MATCHING_PACKETS',
        ward_spawn: wardPacketCount > 0 ? 'EVENTS_OBSERVED' : 'NO_MATCHING_PACKETS',
        damage: damagePacketCount > 0 ? 'EVENTS_OBSERVED' : 'NO_MATCHING_PACKETS',
        hero_death: deathPacketCount > 0
          ? 'EVENTS_OBSERVED'
          : 'NO_MATCHING_PACKETS',
        hero_scoreboard_state: heroStatsPacketCount > 0
          ? 'EVENTS_OBSERVED'
          : 'NO_MATCHING_PACKETS',
        hero_death_timer: deathTimerPacketCount > 0
          ? 'EVENTS_OBSERVED'
          : 'NO_MATCHING_PACKETS',
        hero_reincarnate_alive: reincarnatePacketCount > 0
          ? 'EVENTS_OBSERVED'
          : 'NO_MATCHING_PACKETS',
        buff: buffEvents.length > 0 ? 'EVENTS_OBSERVED' : 'NO_MATCHING_PACKETS',
        cast_spell: spellEvents.length > 0 ? 'EVENTS_OBSERVED' : 'NO_MATCHING_PACKETS',
        protection: protectionEvents.length > 0
          ? 'EVENTS_OBSERVED'
          : protectionExport.total > 0
            ? 'ROUTE_ROWS_OBSERVED_NO_PUBLISHED_EVENT'
            : 'NO_MATCHING_PACKETS',
        item: itemEvents.length > 0
          ? 'EVENTS_OBSERVED_WITH_RETAINED_RAW_RESIDUALS'
          : itemExport.total > 0
            ? 'ROUTE_ROWS_RETAINED_NO_PUBLISHED_EVENT'
            : 'NO_MATCHING_PACKETS',
        gameplay_route_tail: gameplayTailEvents.length > 0
          ? 'EVENTS_OBSERVED'
          : 'NO_MATCHING_PACKETS',
        sweeper: sweeperCapability.observation_status,
      },
      decoded_packet_count: heroPaths.length + levelTransitions.length + wardSpawns.length
        + damageEvents.length + deathEvents.length + heroScoreboardStates.length
        + deathTimerEvents.length + reincarnateEvents.length
        + buffEvents.length + spellEvents.length
        + protectionEvents.length + itemEvents.length + gameplayTailEvents.length,
      path_decode: { ...pathSummary, exported_packet_count: pathPacketCount },
      level_transition_decode: { ...levelSummary, exported_packet_count: levelPacketCount },
      ward_spawn_decode: { ...wardSummary, exported_packet_count: wardPacketCount },
      damage_decode: { ...damageSummary, exported_packet_count: damagePacketCount },
      death_decode: {
        ...deathSummary,
        profile: DEATH_PROFILE_16_16,
        signature_count: deathRouteDecode.signature_count,
        decoded_event_count: deathEvents.length,
        rejected_signature_count: deathRouteDecode.rejected_signature_count,
        walk_error_count: deathRouteDecode.walk.errors.length,
        exported_packet_count: deathPacketCount,
        current_replay_decode_verified: deathReplayDecodeVerified,
      },
      hero_scoreboard_decode: {
        ...heroStatsSummary,
        profile: HERO_STATS_PROFILE_16_16,
        decoded_event_count: heroScoreboardStates.length,
        exported_packet_count: heroStatsPacketCount,
        current_replay_decode_verified: heroStatsReplayDecodeVerified,
      },
      death_timer_decode: {
        ...deathTimerSummary,
        profile: buildProfile.decoder_profile.hero_death_timer,
        decoded_event_count: deathTimerEvents.length,
        exported_packet_count: deathTimerPacketCount,
        current_replay_decode_verified: deathTimerReplayDecodeVerified,
      },
      hero_reincarnate_alive_decode: {
        ...reincarnateSummary,
        profile: HERO_REINCARNATE_ALIVE_PROFILE,
        decoded_event_count: reincarnateEvents.length,
        canonical_event_count: canonicalReincarnateEvents.length,
        exported_packet_count: reincarnatePacketCount,
        current_replay_decode_verified: reincarnateReplayDecodeVerified,
      },
      buff_spell_decode: {
        ...(buffSpellSummary ?? {
          status: 'NO_MATCHING_PACKETS_IN_REPLAY',
          selected_route_rows: 0,
          deserialize_success_rows: 0,
          fully_consumed_rows: 0,
        }),
        exported_packet_count: buffSpellExport.total,
        canonical_buff_event_count: buffEvents.length,
        canonical_spell_event_count: spellEvents.length,
        current_replay_decode_verified: buffSpellReplayDecodeVerified,
      },
      protection_decode: {
        ...(protectionSummary ?? {
          status: 'NO_MATCHING_PACKETS_IN_REPLAY',
          input_route_rows: 0,
          deserialize_success_rows: 0,
          fully_consumed_rows: 0,
        }),
        exported_packet_count: protectionExport.total,
        selected_candidate_row_count: protectionRows.length,
        canonical_event_count: protectionEvents.length,
        exact_duplicate_rows_suppressed: protectionRows.length - protectionEvents.length,
        unclassified_route_row_count: protectionExport.total - protectionRows.length,
        current_replay_decode_verified: protectionReplayDecodeVerified,
      },
      item_decode: {
        status: itemExport.total > 0 ? 'PARTIAL_CANONICALIZATION_WITH_RAW_CONSERVATION'
          : 'NO_MATCHING_PACKETS_IN_REPLAY',
        exported_packet_count: itemExport.total,
        packet_counts: itemExport.packet_counts,
        support_quest_item_stage: supportQuestDecode,
        route_specific_materializer_pending_row_count: itemExport.total - supportQuestRows.length,
        route_specific_materializer_pending_status: 'RETAINED_RAW_NOT_SILENTLY_DISCARDED',
        input_conserved: supportQuestRows.length
          + (itemExport.total - supportQuestRows.length) === itemExport.total,
      },
      gameplay_route_tail_decode: {
        ...(gameplayTailSummary ?? {
          status: 'NO_MATCHING_PACKETS_IN_REPLAY',
          input_event_count: 0,
          output_row_count: 0,
          successful_full_consume_count: 0,
          emulation_error_count: 0,
          routes: {},
        }),
        exported_packet_count: gameplayTailExport.total,
        packet_counts: gameplayTailExport.packet_counts,
        canonical_research_event_count: gameplayTailEvents.length,
        current_replay_decode_verified: gameplayTailReplayDecodeVerified,
      },
    };
    if (options.outputDirectory) {
      fs.mkdirSync(options.outputDirectory, { recursive: true });
      fs.cpSync(pathOutput, path.join(options.outputDirectory, 'hero_path'), { recursive: true });
      fs.cpSync(levelOutput, path.join(options.outputDirectory, 'level_transition'), {
        recursive: true,
      });
      fs.cpSync(wardOutput, path.join(options.outputDirectory, 'ward_spawn'), { recursive: true });
      fs.cpSync(damageOutput, path.join(options.outputDirectory, 'damage'), { recursive: true });
      fs.cpSync(deathOutput, path.join(options.outputDirectory, 'hero_death'), { recursive: true });
      fs.cpSync(heroStatsOutput, path.join(options.outputDirectory, 'hero_scoreboard_state'), {
        recursive: true,
      });
      fs.cpSync(deathTimerOutput, path.join(options.outputDirectory, 'hero_death_timer'), {
        recursive: true,
      });
      const deepOutput = path.join(options.outputDirectory, 'deep_recovery_exact_rows');
      fs.mkdirSync(deepOutput, { recursive: true });
      for (const source of [
        buffSpellPackets, `${buffSpellPackets}.manifest.json`, buffSpellDecoded,
        buffSpellSummaryPath, protectionPackets, `${protectionPackets}.manifest.json`,
        protectionDecoded, protectionSummaryPath, itemPackets, `${itemPackets}.manifest.json`,
        gameplayTailPackets, `${gameplayTailPackets}.manifest.json`, gameplayTailDecoded,
        gameplayTailSummaryPath,
      ]) {
        if (fs.existsSync(source)) fs.copyFileSync(source, path.join(deepOutput, path.basename(source)));
      }
    }
    return result;
  } finally {
    if (options.keepTemporaryOutputs !== true) {
      const resolved = path.resolve(temporaryDirectory);
      if (!resolved.startsWith(`${temporaryRoot}${path.sep}`)) {
        throw new Error(`refusing to remove non-temporary path: ${resolved}`);
      }
      fs.rmSync(resolved, { recursive: true, force: true });
    }
  }
}

function decode1619(replay, profile, options = {}) {
  const requested = options.capabilities ?? [];
  if (!Array.isArray(requested)
      || requested.some((capability) => typeof capability !== 'string' || !capability)) {
    throw new TypeError('16.19 capabilities must be an array of nonempty names');
  }
  const capabilities = [...new Set(requested)];
  const capabilityResults = {};
  const events = {};
  const decoders = {
    hero_death: decodeHeroDeathCandidates,
    hero_death_timer: decodeHeroDeathTimerCandidates,
    hero_respawn: decodeHeroRespawnCandidates,
    hero_level_state: decodeHeroLevelStateCandidates,
    hero_inventory_mapview: decodeHeroInventoryMapViewCandidates,
    hero_inventory_set_item: decodeHeroInventorySetItemCandidates,
    hero_inventory_broadcast: decodeHeroInventoryBroadcastCandidates,
    npc_buff_remove_packet: decodeNpcBuffRemovePacketCandidates,
    npc_buff_add_packet: decodeNpcBuffAddPacketCandidates,
    hero_minions_killed_snapshot: decodeHeroStatsSnapshotCandidateSet,
    hero_jungle_minions_killed_snapshot: decodeHeroStatsSnapshotCandidateSet,
    hero_experience_snapshot: decodeHeroStatsSnapshotCandidateSet,
    hero_gold_earned_snapshot: decodeHeroStatsSnapshotCandidateSet,
    hero_gold_spent_snapshot: decodeHeroStatsSnapshotCandidateSet,
    hero_champion_kills_snapshot: decodeHeroStatsSnapshotCandidateSet,
    hero_deaths_snapshot: decodeHeroStatsSnapshotCandidateSet,
    hero_assists_snapshot: decodeHeroStatsSnapshotCandidateSet,
    hero_kill_stats_snapshot: decodeHeroStatsSnapshotCandidateSet,
    hero_ward_stats_snapshot: decodeHeroStatsSnapshotCandidateSet,
    hero_damage_totals_snapshot: decodeHeroStatsSnapshotCandidateSet,
    hero_damage_taken_from_champions_snapshot: decodeHeroStatsSnapshotCandidateSet,
    hero_damage_self_mitigated_snapshot: decodeHeroStatsSnapshotCandidateSet,
    hero_longest_living_time_snapshot: decodeHeroStatsSnapshotCandidateSet,
    hero_total_time_spent_dead_snapshot: decodeHeroStatsSnapshotCandidateSet,
    hero_total_heal_snapshot: decodeHeroStatsSnapshotCandidateSet,
    hero_total_units_healed_snapshot: decodeHeroStatsSnapshotCandidateSet,
    hero_vision_score_snapshot: decodeHeroStatsSnapshotCandidateSet,
    hero_epic_monster_damage_snapshot: decodeHeroStatsSnapshotCandidateSet,
    hero_crowd_control_time_snapshot: decodeHeroStatsSnapshotCandidateSet,
    hero_structure_objective_damage_snapshot: decodeHeroStatsSnapshotCandidateSet,
  };
  const outputKeys = {
    hero_death: 'hero_death_candidates',
    hero_death_timer: 'hero_death_timer_candidates',
    hero_respawn: 'hero_respawn_candidates',
    hero_level_state: 'hero_level_state_candidates',
    hero_inventory_mapview: 'hero_inventory_mapview_candidates',
    hero_inventory_set_item: 'hero_inventory_set_item_candidates',
    hero_inventory_broadcast: 'hero_inventory_broadcast_candidates',
    npc_buff_remove_packet: 'npc_buff_remove_packet_candidates',
    npc_buff_add_packet: 'npc_buff_add_packet_candidates',
    hero_minions_killed_snapshot: 'hero_minions_killed_snapshot_candidates',
    hero_jungle_minions_killed_snapshot: 'hero_jungle_minions_killed_snapshot_candidates',
    hero_experience_snapshot: 'hero_experience_snapshot_candidates',
    hero_gold_earned_snapshot: 'hero_gold_earned_snapshot_candidates',
    hero_gold_spent_snapshot: 'hero_gold_spent_snapshot_candidates',
    hero_champion_kills_snapshot: 'hero_champion_kills_snapshot_candidates',
    hero_deaths_snapshot: 'hero_deaths_snapshot_candidates',
    hero_assists_snapshot: 'hero_assists_snapshot_candidates',
    hero_kill_stats_snapshot: 'hero_kill_stats_snapshot_candidates',
    hero_ward_stats_snapshot: 'hero_ward_stats_snapshot_candidates',
    hero_damage_totals_snapshot: 'hero_damage_totals_snapshot_candidates',
    hero_damage_taken_from_champions_snapshot:
      'hero_damage_taken_from_champions_snapshot_candidates',
    hero_damage_self_mitigated_snapshot:
      'hero_damage_self_mitigated_snapshot_candidates',
    hero_longest_living_time_snapshot:
      'hero_longest_living_time_snapshot_candidates',
    hero_total_time_spent_dead_snapshot:
      'hero_total_time_spent_dead_snapshot_candidates',
    hero_total_heal_snapshot: 'hero_total_heal_snapshot_candidates',
    hero_total_units_healed_snapshot: 'hero_total_units_healed_snapshot_candidates',
    hero_vision_score_snapshot: 'hero_vision_score_snapshot_candidates',
    hero_epic_monster_damage_snapshot: 'hero_epic_monster_damage_snapshot_candidates',
    hero_crowd_control_time_snapshot: 'hero_crowd_control_time_snapshot_candidates',
    hero_structure_objective_damage_snapshot: 'hero_structure_objective_damage_snapshot_candidates',
  };
  const gameRouteCapabilities = new Set([
    'hero_death', 'hero_death_timer', 'hero_respawn', 'hero_level_state',
    'hero_inventory_mapview', 'hero_inventory_set_item', 'hero_inventory_broadcast',
  ]);
  const heroStatsCapabilities = new Set(HERO_STATS_SNAPSHOT_CAPABILITIES);
  const selectsGameRoutes = capabilities.some((capability) => gameRouteCapabilities.has(capability));
  const selectsHeroStats = capabilities.some((capability) => heroStatsCapabilities.has(capability));
  const selectsBuffAdd = capabilities.includes('npc_buff_add_packet');
  const selectsBuffRemove = capabilities.includes('npc_buff_remove_packet');
  const routeOptions = { includeBuffAdd: selectsBuffAdd, includeBuffRemove: selectsBuffRemove };
  // Single Buff requests retain their original narrow walks. Share the route
  // scan when both Buffs or another selected capability can use it.
  const selectsRouteScan = selectsGameRoutes
    || (selectsBuffAdd && selectsBuffRemove)
    || ((selectsBuffAdd || selectsBuffRemove) && selectsHeroStats);
  const sharedScans = selectsRouteScan && selectsHeroStats
    && options.candidateRouteScan == null && options.heroStatsScan == null
    ? collectCandidateRoutesAndHeroStats(replay, routeOptions) : null;
  const collected = options.candidateRouteScan != null ? options.candidateRouteScan
    : sharedScans !== null ? sharedScans.candidateRouteScan
      : selectsRouteScan ? collectCandidateRoutes(replay, routeOptions) : null;
  const heroStatsScan = options.heroStatsScan ?? sharedScans?.heroStatsScan ?? undefined;
  let timerOutcome = null;
  let heroStatsOutcomes = null;
  for (const capability of capabilities) {
    if (!Object.hasOwn(decoders, capability)) {
      capabilityResults[capability] = {
        status: 'UNSUPPORTED', event_count: null, input_count: null,
        error: `16.19.820.7193 has no decoder for ${capability}`,
      };
      continue;
    }
    let outcome;
    try {
      if (capability === 'hero_death_timer' || capability === 'hero_respawn') {
        timerOutcome ??= decodeHeroDeathTimerCandidates(replay, collected);
        outcome = capability === 'hero_respawn'
          ? decodeHeroRespawnCandidates(replay, collected, timerOutcome) : timerOutcome;
      } else if (heroStatsCapabilities.has(capability)) {
        heroStatsOutcomes ??= decodeHeroStatsSnapshotCandidateSet(replay,
          capabilities.filter((name) => heroStatsCapabilities.has(name)),
          heroStatsScan);
        outcome = heroStatsOutcomes[capability];
      } else if (capability === 'hero_inventory_mapview'
          || capability === 'hero_inventory_set_item'
          || capability === 'hero_inventory_broadcast'
          || capability === 'npc_buff_remove_packet'
          || capability === 'npc_buff_add_packet') {
        // A stream-2 framing error invalidates the shared route token, but a
        // game-stream-only BuffRemove candidate may still decode independently.
        const packetScan = capability === 'npc_buff_remove_packet' && collected?.error
          ? null : collected;
        outcome = decoders[capability](replay, packetScan, options);
      } else {
        outcome = decoders[capability](replay, collected);
      }
    } catch (error) {
      outcome = { status: 'DECODE_FAILED', input_count: null, event_count: null,
        events: null, error: error.message || String(error) };
    }
    const { events: candidateEvents, ...result } = outcome;
    result.runtime_image_status ??= options.runtimeImagePath
      ? 'PROVIDED_NOT_USED' : 'NOT_REQUIRED';
    result.runtime_image_used ??= false;
    capabilityResults[capability] = result;
    if (result.status === 'CANDIDATE') {
      events[outputKeys[capability]] = candidateEvents;
    }
  }
  const results = Object.values(capabilityResults);
  const usable = results.filter((result) => result.status === 'CANDIDATE' || result.status === 'PASS');
  const failed = results.filter((result) => result.status !== 'CANDIDATE' && result.status !== 'PASS');
  const status = results.length === 0 ? 'PROFILE_RESOLVED'
    : failed.length > 0 ? (usable.length > 0 ? 'PARTIAL' : failed[0].status)
      : 'EXPERIMENTAL_CANDIDATE';
  const uniqueDecodedInputCounts = new Map();
  for (const result of usable) {
    const packetId = result.input_packet_id;
    uniqueDecodedInputCounts.set(packetId,
      Math.max(uniqueDecodedInputCounts.get(packetId) ?? 0, result.input_count));
  }
  const candidateAssociations = {};
  if (selectsBuffAdd && selectsBuffRemove) {
    const addRows = events.npc_buff_add_packet_candidates;
    const removeRows = events.npc_buff_remove_packet_candidates;
    if (Array.isArray(addRows) && Array.isArray(removeRows)) {
      try {
        candidateAssociations.npc_buff_add_remove_opaque_key =
          analyzeBuffPacketKeyCompatibility(addRows, removeRows,
            replay.source_sha256);
      } catch (error) {
        candidateAssociations.npc_buff_add_remove_opaque_key = {
          status: 'DECODE_FAILED',
          error: error.message || String(error),
        };
      }
    } else {
      candidateAssociations.npc_buff_add_remove_opaque_key = {
        status: 'UNAVAILABLE',
        required_capabilities: ['npc_buff_add_packet', 'npc_buff_remove_packet'],
        dependency_statuses: {
          npc_buff_add_packet: capabilityResults.npc_buff_add_packet?.status ?? 'UNEXECUTED',
          npc_buff_remove_packet: capabilityResults.npc_buff_remove_packet?.status ?? 'UNEXECUTED',
        },
      };
    }
  }
  return {
    status,
    game_version: profile.game_version,
    profile,
    events: usable.length > 0 ? events : null,
    capability_results: capabilityResults,
    candidate_associations: candidateAssociations,
    decoded_packet_count: [...uniqueDecodedInputCounts.values()]
      .reduce((sum, count) => sum + count, 0),
    runtime_image_used: results.some((result) => result.runtime_image_used === true),
    runtime_image_sha256: results.find((result) => result.runtime_image_used === true)
      ?.runtime_image_sha256 ?? null,
    sweeper_capability: createSweeperCapabilityExport(profile.game_version),
  };
}

function decode1619821(replay, profile, options = {}) {
  const requested = options.capabilities ?? [];
  if (!Array.isArray(requested)
      || requested.some((capability) => typeof capability !== 'string' || !capability)) {
    throw new TypeError('16.19 capabilities must be an array of nonempty names');
  }
  const capabilities = [...new Set(requested)];
  const decoders = {
    hero_death: decodeHeroDeathCandidates821,
    hero_assist: decodeHeroAssistCandidates821,
    hero_death_timer: decodeHeroDeathTimerCandidates821,
    hero_respawn: decodeHeroRespawnCandidates821,
    hero_deaths_snapshot: decodeHeroDeathsSnapshotCandidates821,
    hero_champion_kills_snapshot: decodeHeroChampionKillsSnapshotCandidates821,
    hero_assists_snapshot: decodeHeroAssistsSnapshotCandidates821,
    hero_missions_minions_killed_snapshot: decodeHeroMissionsMinionsKilledSnapshotCandidates821,
    hero_ward_stats_snapshot: decodeHeroWardStatsSnapshotCandidates821,
    hero_missions_cannon_minions_killed_snapshot:
      decodeHeroMissionsCannonMinionsKilledSnapshotCandidates821,
    hero_minions_killed_snapshot: (input, collected) =>
      decodeHeroFloatSnapshotCandidates821(input, 'hero_minions_killed_snapshot', collected),
    hero_jungle_minions_killed_snapshot: (input, collected) =>
      decodeHeroFloatSnapshotCandidates821(input,
        'hero_jungle_minions_killed_snapshot', collected),
    hero_kill_stats_snapshot: decodeHeroKillStatsSnapshotCandidates821,
    hero_experience_snapshot: (input, collected) =>
      decodeHeroFloatSnapshotCandidates821(input, 'hero_experience_snapshot', collected),
    hero_vision_score_snapshot: (input, collected) =>
      decodeHeroFloatSnapshotCandidates821(input, 'hero_vision_score_snapshot', collected),
    hero_gold_earned_snapshot: (input, collected) =>
      decodeHeroFloatSnapshotCandidates821(input, 'hero_gold_earned_snapshot', collected),
    hero_gold_spent_snapshot: (input, collected) =>
      decodeHeroFloatSnapshotCandidates821(input, 'hero_gold_spent_snapshot', collected),
    hero_damage_totals_snapshot: (input, collected) =>
      decodeHeroDamageSnapshotCandidates821(input, 'hero_damage_totals_snapshot', collected),
    hero_damage_taken_from_champions_snapshot: (input, collected) =>
      decodeHeroDamageSnapshotCandidates821(input,
        'hero_damage_taken_from_champions_snapshot', collected),
    hero_damage_self_mitigated_snapshot: (input, collected) =>
      decodeHeroDamageSnapshotCandidates821(input,
        'hero_damage_self_mitigated_snapshot', collected),
    hero_structure_objective_damage_snapshot: (input, collected) =>
      decodeHeroDamageSnapshotCandidates821(input,
        'hero_structure_objective_damage_snapshot', collected),
    hero_longest_living_time_snapshot: (input, collected) =>
      decodeHeroTimeSnapshotCandidates821(input,
        'hero_longest_living_time_snapshot', collected),
    hero_total_time_spent_dead_snapshot: (input, collected) =>
      decodeHeroTimeSnapshotCandidates821(input,
        'hero_total_time_spent_dead_snapshot', collected),
    hero_total_heal_snapshot: (input, collected) =>
      decodeHeroHealSnapshotCandidates821(input, 'hero_total_heal_snapshot', collected),
    hero_total_units_healed_snapshot: (input, collected) =>
      decodeHeroHealSnapshotCandidates821(input,
        'hero_total_units_healed_snapshot', collected),
    hero_epic_monster_damage_snapshot: (input, collected) =>
      decodeHeroEpicCcSnapshotCandidates821(input,
        'hero_epic_monster_damage_snapshot', collected),
    hero_crowd_control_time_snapshot: (input, collected) =>
      decodeHeroEpicCcSnapshotCandidates821(input,
        'hero_crowd_control_time_snapshot', collected),
    hero_level_state: decodeHeroLevelCandidates821,
    hero_inventory_packet: (input, collected) =>
      decodeHeroInventoryPacketCandidates821(input, {
        runtimeImagePath: options.runtimeImagePath,
        pythonExecutable: options.pythonExecutable,
        precollected: collected,
      }),
    cast_spell_ans_packet: (input, collected) =>
      decodeCastSpellAnsPacketCandidates821(input, {
        runtimeImagePath: options.runtimeImagePath,
        pythonExecutable: options.pythonExecutable,
        precollected: collected,
      }),
    npc_buff_remove_packet: (input, collected) =>
      decodeNpcBuffRemovePacketCandidates821(input, {
        runtimeImagePath: options.runtimeImagePath,
        pythonExecutable: options.pythonExecutable,
        precollected: collected,
      }),
    npc_buff_add_packet: (input, collected) =>
      decodeNpcBuffAddPacketCandidates821(input, {
        runtimeImagePath: options.runtimeImagePath,
        pythonExecutable: options.pythonExecutable,
        precollected: collected,
      }),
    direct_input_movement_turn_packet: (input, collected) =>
      decodeDirectInputMovementTurnPacketCandidates821(input, {
        runtimeImagePath: options.runtimeImagePath,
        pythonExecutable: options.pythonExecutable,
        precollected: collected,
      }),
    set_movement_driver_packet: (input, collected) =>
      decodeSetMovementDriverPacketCandidates821(input, {
        runtimeImagePath: options.runtimeImagePath,
        pythonExecutable: options.pythonExecutable,
        precollected: collected,
      }),
  };
  const outputKeys = {
    hero_death: 'hero_death_candidates',
    hero_assist: 'hero_assist_candidates',
    hero_death_timer: 'hero_death_timer_candidates',
    hero_respawn: 'hero_respawn_candidates',
    hero_deaths_snapshot: 'hero_deaths_snapshot_candidates',
    hero_champion_kills_snapshot: 'hero_champion_kills_snapshot_candidates',
    hero_assists_snapshot: 'hero_assists_snapshot_candidates',
    hero_missions_minions_killed_snapshot: 'hero_missions_minions_killed_snapshot_candidates',
    hero_ward_stats_snapshot: 'hero_ward_stats_snapshot_candidates',
    hero_missions_cannon_minions_killed_snapshot:
      'hero_missions_cannon_minions_killed_snapshot_candidates',
    hero_minions_killed_snapshot: 'hero_minions_killed_snapshot_candidates',
    hero_jungle_minions_killed_snapshot: 'hero_jungle_minions_killed_snapshot_candidates',
    hero_kill_stats_snapshot: 'hero_kill_stats_snapshot_candidates',
    hero_experience_snapshot: 'hero_experience_snapshot_candidates',
    hero_vision_score_snapshot: 'hero_vision_score_snapshot_candidates',
    hero_gold_earned_snapshot: 'hero_gold_earned_snapshot_candidates',
    hero_gold_spent_snapshot: 'hero_gold_spent_snapshot_candidates',
    hero_damage_totals_snapshot: 'hero_damage_totals_snapshot_candidates',
    hero_damage_taken_from_champions_snapshot:
      'hero_damage_taken_from_champions_snapshot_candidates',
    hero_damage_self_mitigated_snapshot:
      'hero_damage_self_mitigated_snapshot_candidates',
    hero_structure_objective_damage_snapshot:
      'hero_structure_objective_damage_snapshot_candidates',
    hero_longest_living_time_snapshot: 'hero_longest_living_time_snapshot_candidates',
    hero_total_time_spent_dead_snapshot: 'hero_total_time_spent_dead_snapshot_candidates',
    hero_total_heal_snapshot: 'hero_total_heal_snapshot_candidates',
    hero_total_units_healed_snapshot: 'hero_total_units_healed_snapshot_candidates',
    hero_epic_monster_damage_snapshot: 'hero_epic_monster_damage_snapshot_candidates',
    hero_crowd_control_time_snapshot: 'hero_crowd_control_time_snapshot_candidates',
    hero_level_state: 'hero_level_state_candidates',
    hero_inventory_packet: 'hero_inventory_packet_candidates',
    cast_spell_ans_packet: 'cast_spell_ans_packet_candidates',
    npc_buff_remove_packet: 'npc_buff_remove_packet_candidates',
    npc_buff_add_packet: 'npc_buff_add_packet_candidates',
    direct_input_movement_turn_packet: 'direct_input_movement_turn_packet_candidates',
    set_movement_driver_packet: 'set_movement_driver_packet_candidates',
  };
  const capabilityResults = {};
  const events = {};
  const sharedScanCapabilities = new Set([
    'hero_death', 'hero_assist', 'hero_death_timer', 'hero_deaths_snapshot', 'hero_champion_kills_snapshot',
    'hero_assists_snapshot', 'hero_level_state', 'hero_respawn',
    'hero_missions_minions_killed_snapshot',
    'hero_ward_stats_snapshot', 'hero_missions_cannon_minions_killed_snapshot',
    'hero_minions_killed_snapshot', 'hero_jungle_minions_killed_snapshot',
    'hero_kill_stats_snapshot',
    'hero_experience_snapshot', 'hero_vision_score_snapshot',
    'hero_gold_earned_snapshot', 'hero_gold_spent_snapshot',
    'hero_damage_totals_snapshot', 'hero_damage_taken_from_champions_snapshot',
    'hero_damage_self_mitigated_snapshot',
    'hero_structure_objective_damage_snapshot',
    'hero_longest_living_time_snapshot', 'hero_total_time_spent_dead_snapshot',
    'hero_total_heal_snapshot', 'hero_total_units_healed_snapshot',
    'hero_epic_monster_damage_snapshot', 'hero_crowd_control_time_snapshot',
    'hero_inventory_packet',
    'cast_spell_ans_packet',
    'npc_buff_remove_packet',
    'npc_buff_add_packet',
    'direct_input_movement_turn_packet',
    'set_movement_driver_packet',
  ]);
  const supported = capabilities.filter((capability) => sharedScanCapabilities.has(capability));
  let candidate821Scan = options.candidate821Scan ?? null;
  if (candidate821Scan === null
      && (supported.length > 1 || supported.includes('hero_respawn'))) {
    try {
      candidate821Scan = collect821Routes(replay, supported);
    } catch {
      // Keep the original independent error boundary when one stream fails:
      // a sound keyframe scan can still return snapshots after a game-stream
      // framing failure. Each decoder's strict walk reports its own outcome.
      candidate821Scan = null;
    }
  }
  for (const capability of capabilities) {
    let outcome;
    if (!decoders[capability]) {
      outcome = { status: 'UNSUPPORTED', input_count: null, event_count: null,
        error: `16.19.821.7343 has no decoder for ${capability}`, events: null };
    } else {
      try {
        outcome = decoders[capability](replay, candidate821Scan);
      } catch (error) {
        outcome = { status: 'DECODE_FAILED', input_count: null, event_count: null,
          error: error.message || String(error), events: null };
      }
    }
    const { events: candidateEvents, ...result } = outcome;
    if (capability === 'hero_inventory_packet' || capability === 'cast_spell_ans_packet'
        || capability === 'npc_buff_remove_packet' || capability === 'npc_buff_add_packet'
        || capability === 'direct_input_movement_turn_packet'
        || capability === 'set_movement_driver_packet') {
      result.runtime_image_status ??= options.runtimeImagePath
        ? 'PROVIDED_NOT_USED' : 'NOT_REQUIRED';
      result.runtime_image_used ??= false;
    } else {
      result.runtime_image_status = options.runtimeImagePath
        ? 'PROVIDED_NOT_USED' : result.runtime_image_status ?? 'NOT_REQUIRED';
      result.runtime_image_used = false;
    }
    capabilityResults[capability] = result;
    if (result.status === 'CANDIDATE') {
      events[outputKeys[capability]] = candidateEvents;
    }
  }
  const results = Object.values(capabilityResults);
  const usable = results.filter((result) => result.status === 'CANDIDATE');
  const failed = results.filter((result) => result.status !== 'CANDIDATE');
  const uniqueDecodedInputCounts = new Map();
  for (const result of usable) {
    const packetId = result.input_packet_id;
    uniqueDecodedInputCounts.set(packetId,
      Math.max(uniqueDecodedInputCounts.get(packetId) ?? 0, result.input_count));
  }
  const candidateAssociations = {};
  if (capabilities.includes('npc_buff_add_packet')
      && capabilities.includes('npc_buff_remove_packet')) {
    const addRows = events.npc_buff_add_packet_candidates;
    const removeRows = events.npc_buff_remove_packet_candidates;
    if (Array.isArray(addRows) && Array.isArray(removeRows)) {
      try {
        candidateAssociations.npc_buff_add_remove_opaque_key =
          analyzeBuffPacketKeyCompatibility821(addRows, removeRows,
            replay.source_sha256);
      } catch (error) {
        candidateAssociations.npc_buff_add_remove_opaque_key = {
          status: 'DECODE_FAILED',
          error: error.message || String(error),
        };
      }
    } else {
      candidateAssociations.npc_buff_add_remove_opaque_key = {
        status: 'UNAVAILABLE',
        required_capabilities: ['npc_buff_add_packet', 'npc_buff_remove_packet'],
        dependency_statuses: {
          npc_buff_add_packet: capabilityResults.npc_buff_add_packet?.status ?? 'UNEXECUTED',
          npc_buff_remove_packet: capabilityResults.npc_buff_remove_packet?.status ?? 'UNEXECUTED',
        },
      };
    }
  }
  return {
    status: results.length === 0 ? 'PROFILE_RESOLVED'
      : failed.length > 0 ? (usable.length > 0 ? 'PARTIAL' : failed[0].status)
        : 'EXPERIMENTAL_CANDIDATE',
    game_version: profile.game_version,
    profile,
    events: usable.length > 0 ? events : null,
    capability_results: capabilityResults,
    candidate_associations: candidateAssociations,
    decoded_packet_count: [...uniqueDecodedInputCounts.values()]
      .reduce((sum, count) => sum + count, 0),
    runtime_image_used: results.some((result) => result.runtime_image_used === true),
    runtime_image_sha256: results.find((result) => result.runtime_image_used === true)
      ?.runtime_image_sha256 ?? null,
    sweeper_capability: createSweeperCapabilityExport(profile.game_version),
  };
}

function decodeSemanticReplay(input, options = {}) {
  const { replay, status, profile, game_version: gameVersion } = profileResolution(input);
  if (!profile) {
    return {
      status,
      game_version: gameVersion,
      profile: null,
      events: null,
      capability_results: {},
      decoded_packet_count: 0,
      sweeper_capability: createSweeperCapabilityExport(gameVersion),
    };
  }
  if (options.profileResolutionOnly === true) {
    return {
      status: 'PROFILE_RESOLVED',
      game_version: gameVersion,
      profile,
      events: null,
      capability_results: {},
      decoded_packet_count: 0,
      sweeper_capability: createSweeperCapabilityExport(gameVersion),
    };
  }
  if (gameVersion === '16.19.820.7193') return decode1619(replay, profile, options);
  if (gameVersion === '16.19.821.7343') return decode1619821(replay, profile, options);
  if (gameVersion === '16.16.805.0442') return decode1616(replay, profile, options);
  const legacy = require('./semantic_pipeline').decodeSemanticReplay(replay, options);
  return {
    ...decorateResultEvents(legacy, profile),
    sweeper_capability: createSweeperCapabilityExport(gameVersion),
  };
}

function getHeroPaths(decoded) {
  return decoded?.events?.hero_path_events ?? decoded?.events?.position_events ?? [];
}

function getLevelTransitions(decoded) {
  return decoded?.events?.level_transition_events ?? [];
}

function getWardSpawns(decoded) {
  return decoded?.events?.ward_events ?? decoded?.events?.ward_spawn_events ?? [];
}

function wardRows(decoded, keys) {
  if (Array.isArray(decoded)) return decoded;
  for (const key of keys) {
    if (Array.isArray(decoded?.events?.[key])) return decoded.events[key];
  }
  return [];
}

function filterWardRows(rows, options = {}) {
  const fromMs = options.from_ms ?? options.start_ms ?? -Infinity;
  const toMs = options.to_ms ?? options.end_ms ?? Infinity;
  return rows.filter((row) => {
    const timestamp = row.timestamp_ms ?? row.replay_time_ms ?? row.spawn_time_ms
      ?? row.ward_spawn_time_ms;
    const participant = row.owner_participant ?? row.ward_owner_participant;
    const team = row.owner_team ?? row.ward_team;
    const wardId = row.ward_network_id ?? row.entity_network_id;
    return (timestamp == null || (timestamp >= fromMs && timestamp <= toMs))
      && (options.participant_id == null || participant === options.participant_id)
      && (options.team_id == null || team === options.team_id)
      && (options.ward_network_id == null || wardId === options.ward_network_id)
      && (options.ward_type == null || row.ward_type === options.ward_type)
      && (options.vision_entity_class == null
        || row.vision_entity_class === options.vision_entity_class)
      && (options.player_active_only !== true || row.player_active_ward_confirmed === true);
  });
}

function queryWardEvents(decoded, options = {}) {
  return filterWardRows(
    wardRows(decoded, ['vision_entity_events', 'ward_spawn_events', 'ward_events']),
    options,
  );
}

function queryWardSpawns(decoded, options = {}) {
  return filterWardRows(wardRows(decoded, ['ward_spawn_events', 'ward_events']), options);
}

function queryWardLifecycles(decoded, options = {}) {
  return filterWardRows(wardRows(decoded, ['ward_lifecycle_events', 'ward_lifecycles']), options);
}

function getHeroDamage(decoded) {
  return decoded?.events?.damage_events ?? [];
}

function getHeroDeaths(decoded) {
  return decoded?.events?.death_events ?? [];
}

function getHeroDeathCandidates(decoded) {
  return decoded?.events?.hero_death_candidates ?? null;
}

function getHeroDeathTimerCandidates(decoded) {
  return decoded?.events?.hero_death_timer_candidates ?? null;
}

function getHeroRespawnCandidates(decoded) {
  return decoded?.events?.hero_respawn_candidates ?? null;
}

function getHeroLevelStateCandidates(decoded) {
  return decoded?.events?.hero_level_state_candidates ?? null;
}

function getHeroInventoryMapViewCandidates(decoded) {
  return decoded?.events?.hero_inventory_mapview_candidates ?? null;
}

function getHeroInventorySetItemCandidates(decoded) {
  return decoded?.events?.hero_inventory_set_item_candidates ?? null;
}

function getHeroInventoryBroadcastCandidates(decoded) {
  return decoded?.events?.hero_inventory_broadcast_candidates ?? null;
}

function getNpcBuffRemovePacketCandidates(decoded) {
  return decoded?.events?.npc_buff_remove_packet_candidates ?? null;
}

function getNpcBuffAddPacketCandidates(decoded) {
  return decoded?.events?.npc_buff_add_packet_candidates ?? null;
}

function getDirectInputMovementTurnPacketCandidates(decoded) {
  return decoded?.events?.direct_input_movement_turn_packet_candidates ?? null;
}

function getSetMovementDriverPacketCandidates(decoded) {
  return decoded?.events?.set_movement_driver_packet_candidates ?? null;
}

function getHeroMinionsKilledSnapshotCandidates(decoded) {
  return decoded?.events?.hero_minions_killed_snapshot_candidates ?? null;
}

function getHeroJungleMinionsKilledSnapshotCandidates(decoded) {
  return decoded?.events?.hero_jungle_minions_killed_snapshot_candidates ?? null;
}

function getHeroExperienceSnapshotCandidates(decoded) {
  return decoded?.events?.hero_experience_snapshot_candidates ?? null;
}

function getHeroGoldEarnedSnapshotCandidates(decoded) {
  return decoded?.events?.hero_gold_earned_snapshot_candidates ?? null;
}

function getHeroGoldSpentSnapshotCandidates(decoded) {
  return decoded?.events?.hero_gold_spent_snapshot_candidates ?? null;
}

function getHeroChampionKillsSnapshotCandidates(decoded) {
  return decoded?.events?.hero_champion_kills_snapshot_candidates ?? null;
}

function getHeroDeathsSnapshotCandidates(decoded) {
  return decoded?.events?.hero_deaths_snapshot_candidates ?? null;
}

function getHeroAssistsSnapshotCandidates(decoded) {
  return decoded?.events?.hero_assists_snapshot_candidates ?? null;
}

function getHeroKillStatsSnapshotCandidates(decoded) {
  return decoded?.events?.hero_kill_stats_snapshot_candidates ?? null;
}

function getHeroWardStatsSnapshotCandidates(decoded) {
  return decoded?.events?.hero_ward_stats_snapshot_candidates ?? null;
}

function getHeroDamageTotalsSnapshotCandidates(decoded) {
  return decoded?.events?.hero_damage_totals_snapshot_candidates ?? null;
}

function getHeroDamageTakenFromChampionsSnapshotCandidates(decoded) {
  return decoded?.events?.hero_damage_taken_from_champions_snapshot_candidates ?? null;
}

function getHeroDamageSelfMitigatedSnapshotCandidates(decoded) {
  return decoded?.events?.hero_damage_self_mitigated_snapshot_candidates ?? null;
}

function getHeroLongestLivingTimeSnapshotCandidates(decoded) {
  return decoded?.events?.hero_longest_living_time_snapshot_candidates ?? null;
}

function getHeroTotalTimeSpentDeadSnapshotCandidates(decoded) {
  return decoded?.events?.hero_total_time_spent_dead_snapshot_candidates ?? null;
}

function getHeroTotalHealSnapshotCandidates(decoded) {
  return decoded?.events?.hero_total_heal_snapshot_candidates ?? null;
}

function getHeroTotalUnitsHealedSnapshotCandidates(decoded) {
  return decoded?.events?.hero_total_units_healed_snapshot_candidates ?? null;
}

function getHeroVisionScoreSnapshotCandidates(decoded) {
  return decoded?.events?.hero_vision_score_snapshot_candidates ?? null;
}

function getHeroEpicMonsterDamageSnapshotCandidates(decoded) {
  return decoded?.events?.hero_epic_monster_damage_snapshot_candidates ?? null;
}

function getHeroCrowdControlTimeSnapshotCandidates(decoded) {
  return decoded?.events?.hero_crowd_control_time_snapshot_candidates ?? null;
}

function getHeroStructureObjectiveDamageSnapshotCandidates(decoded) {
  return decoded?.events?.hero_structure_objective_damage_snapshot_candidates ?? null;
}

function getCastSpellAnsPacketCandidates(decoded) {
  return decoded?.events?.cast_spell_ans_packet_candidates ?? null;
}

function getHeroStates(decoded) {
  return decoded?.events?.hero_state_events ?? decoded?.events?.state_update_events ?? [];
}

function getDeathTimerEvents(decoded) {
  return decoded?.events?.death_timer_events ?? [];
}

function getHeroRespawns(decoded) {
  return decoded?.events?.respawn_events
    ?? decoded?.events?.reincarnate_alive_events ?? [];
}

function getBuffEvents(decoded) {
  return decoded?.events?.buff_events ?? [];
}

function getSpellEvents(decoded) {
  return decoded?.events?.spell_events ?? [];
}

function getProtectionEvents(decoded) {
  return decoded?.events?.protection_events ?? [];
}

function getItemEvents(decoded) {
  return decoded?.events?.item_events ?? [];
}

function getGameplayRouteTailEvents(decoded) {
  return decoded?.events?.gameplay_route_tail_events ?? [];
}

function getAttackEvents(decoded) {
  return decoded?.events?.canonical_attack_events ?? decoded?.events?.attack_events ?? [];
}

function getSpellStateEvents(decoded) {
  return decoded?.events?.canonical_spell_state_events ?? decoded?.events?.spell_state_events ?? [];
}

function getFaceDirectionEvents(decoded) {
  return (decoded?.events?.gameplay_route_tail_events ?? [])
    .filter((event) => event.event_type === 'FACE_DIRECTION_VECTOR');
}

function getMissileEvents(decoded) {
  return decoded?.events?.canonical_missile_events ?? decoded?.events?.missile_events ?? [];
}

function getEntityComponentStateEvents(decoded) {
  return decoded?.events?.canonical_entity_component_state_events
    ?? decoded?.events?.entity_component_state_events ?? [];
}

function getSweeperCapability(decoded) {
  return decoded?.sweeper_capability ?? createSweeperCapabilityExport(decoded?.profile?.game_version);
}

function statsAt(hero, gameTime, inputs = {}, options = {}) {
  return require('./stat_combat_semantic_layer').statsAt(hero, gameTime, inputs, options);
}

function baseStatAtLevel(options = {}) {
  return require('./champion_base_stat_engine').baseStatAtLevel(options);
}

function effectiveDefenseForDamageEvent(input) {
  return require('./dynamic_defense_semantic_layer').effectiveDefenseForDamageEvent(input);
}

function createSemanticAcquisitionPlan(request) {
  return require('./semantic_acquisition_router').createSemanticAcquisitionPlan(request);
}

function inventoryStateIndex(events, options = {}) {
  return require('./inventory_state_at').inventoryStateIndex(events, options);
}

function inventoryStateAt(index, entityId, replayTimeMs, options = {}) {
  return require('./inventory_state_at').inventory_state_at(
    index, entityId, replayTimeMs, options,
  );
}

module.exports = {
  DEFAULT_16_16_RUNTIME_IMAGE,
  DEFAULT_16_16_DAMAGE_PROFILE,
  DEFAULT_16_16_DEATH_PROFILE,
  DEFAULT_16_16_DEATH_TIMER_PROFILE,
  DEFAULT_16_16_HERO_STATS_PROFILE,
  DEFAULT_16_16_HERO_REINCARNATE_ALIVE_PROFILE,
  SemanticStateEngine,
  buffEventFromDecodedRow,
  canonicalProtectionEventsFromDecodedRows,
  canonicalizeSemanticEvent,
  decodeSemanticReplay,
  deathTimerEventFromDecodedRow,
  getBuffEvents,
  getAttackEvents,
  getCanonicalSemanticSchema,
  getDeathTimerEvents,
  getEntityComponentStateEvents,
  getFaceDirectionEvents,
  getGameplayRouteTailEvents,
  getHeroDamage,
  getHeroDeaths,
  getHeroDeathCandidates,
  getHeroDeathTimerCandidates,
  getHeroRespawnCandidates,
  getHeroLevelStateCandidates,
  getHeroInventoryMapViewCandidates,
  getHeroInventorySetItemCandidates,
  getHeroInventoryBroadcastCandidates,
  getNpcBuffRemovePacketCandidates,
  getNpcBuffAddPacketCandidates,
  getDirectInputMovementTurnPacketCandidates,
  getSetMovementDriverPacketCandidates,
  getHeroMinionsKilledSnapshotCandidates,
  getHeroJungleMinionsKilledSnapshotCandidates,
  getHeroExperienceSnapshotCandidates,
  getHeroGoldEarnedSnapshotCandidates,
  getHeroGoldSpentSnapshotCandidates,
  getHeroChampionKillsSnapshotCandidates,
  getHeroDeathsSnapshotCandidates,
  getHeroAssistsSnapshotCandidates,
  getHeroKillStatsSnapshotCandidates,
  getHeroWardStatsSnapshotCandidates,
  getHeroDamageTotalsSnapshotCandidates,
  getHeroDamageTakenFromChampionsSnapshotCandidates,
  getHeroDamageSelfMitigatedSnapshotCandidates,
  getHeroLongestLivingTimeSnapshotCandidates,
  getHeroTotalTimeSpentDeadSnapshotCandidates,
  getHeroTotalHealSnapshotCandidates,
  getHeroTotalUnitsHealedSnapshotCandidates,
  getHeroVisionScoreSnapshotCandidates,
  getHeroEpicMonsterDamageSnapshotCandidates,
  getHeroCrowdControlTimeSnapshotCandidates,
  getHeroStructureObjectiveDamageSnapshotCandidates,
  getCastSpellAnsPacketCandidates,
  getHeroPaths,
  getHeroRespawns,
  getHeroStates,
  getItemEvents,
  getLevelTransitions,
  getProtectionEvents,
  getMissileEvents,
  getSpellStateEvents,
  getSpellEvents,
  getSweeperCapability,
  getWardSpawns,
  inventorySnapshotEvent,
  inventoryStateAt,
  inventoryStateIndex,
  inventorySwapEvent,
  itemSubstitutionMapEvent,
  levelTransitionFromRuntimeRow,
  profileResolution,
  participantMetadataForReplay,
  queryWardEvents,
  queryWardLifecycles,
  queryWardSpawns,
  stateUpdateFromGroundTruthFrame,
  spellCastEventFromDecodedRow,
  canonicalGameplayRouteTailEvent,
  canonicalHeroReincarnateAliveEvent,
  heroReincarnateAliveEventFromDecodedRow,
  supportQuestStageEventsFromRows,
  statsAt,
  stats_at: statsAt,
  baseStatAtLevel,
  base_stat_at_level: baseStatAtLevel,
  effectiveDefenseForDamageEvent,
  effective_defense_for_damage_event: effectiveDefenseForDamageEvent,
  createSemanticAcquisitionPlan,
  create_semantic_acquisition_plan: createSemanticAcquisitionPlan,
  inventory_state_at: inventoryStateAt,
  validateCanonicalRecord,
  withBuildMetadata,
  semanticCalibration,
};

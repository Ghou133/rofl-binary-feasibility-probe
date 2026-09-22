'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const CANONICAL_SEMANTIC_SCHEMA_VERSION = 'ROFL_CANONICAL_SEMANTIC_SCHEMA_V2';
const ENTITY_TYPE_REGISTRY_VERSION = 'ROFL_ENTITY_TYPE_REGISTRY_V1';
const EXACT_BUILD_ADAPTER_SCHEMA_VERSION = 'ROFL_EXACT_BUILD_ADAPTER_METADATA_V2';
const DEFAULT_EXACT_BUILD = '16.16.805.0442';

const EVIDENCE_STATUS_VOCABULARY = Object.freeze([
  'VERIFIED_DIRECT',
  'VERIFIED_DERIVED',
  'INFERRED',
  'CANDIDATE',
  'UNKNOWN',
  'UNAVAILABLE',
  'NOT_GAMEPLAY_RELEVANT',
]);

const ENTITY_TYPE_VOCABULARY = Object.freeze([
  'CHAMPION',
  'MINION',
  'MONSTER',
  'WARD',
  'MISSILE',
  'STRUCTURE',
  'OBJECTIVE',
  'MAP_MECHANIC',
  'UNKNOWN_ENTITY',
]);

const CANONICAL_EVENT_TYPES = Object.freeze([
  'HeroState',
  'DamageEvent',
  'BuffEvent',
  'SpellCast',
  'EntityLifecycle',
  'WardEvent',
  'ItemEvent',
  'ObjectiveEvent',
  'PositionEvent',
  'MissileEvent',
  'AttackEvent',
  'SpellState',
  'EntityComponentState',
  'ProtectionEvent',
  'LevelTransition',
]);

const CONSUMER_FORBIDDEN_KEYS = new Set([
  'packet_id', 'packetId', 'opcode', 'decoded_opcode', 'protocol_route',
  'packet_registration_route', 'raw_param', 'raw_payload_hex', 'decoder_profile',
  'deserializer_rva', 'factory_case_rva', 'callback_receive_target_rva',
]);

const FIELD_TYPES = Object.freeze({
  ENTITY_ID: 'ENTITY_ID', PARTICIPANT_ID: 'PARTICIPANT_ID', STRING: 'STRING',
  NUMBER: 'NUMBER', INTEGER: 'INTEGER', BOOLEAN: 'BOOLEAN', POSITION: 'POSITION',
  ENTITY_TYPE: 'ENTITY_TYPE', ARRAY: 'ARRAY', OBJECT: 'OBJECT', ENUM: 'ENUM',
});

function field(type, description, options = {}) {
  return Object.freeze({
    type,
    nullable: options.nullable !== false,
    description,
    missing_value_policy: 'EXPLICIT_NULL_WITH_FIELD_EVIDENCE_STATUS',
    no_implicit_zero: true,
  });
}

const EVENT_FIELD_DEFINITIONS = Object.freeze({
  HeroState: Object.freeze({
    entity_id: field(FIELD_TYPES.ENTITY_ID, 'Protocol-observed entity identity.'),
    participant_id: field(FIELD_TYPES.PARTICIPANT_ID, 'Build-bound participant association.'),
    champion: field(FIELD_TYPES.STRING, 'Champion identity when directly supplied or derived.'),
    current_hp: field(FIELD_TYPES.NUMBER, 'Observed health; null is not zero health.'),
    max_hp: field(FIELD_TYPES.NUMBER, 'Observed maximum health.'),
    armor: field(FIELD_TYPES.NUMBER, 'Observed armor.'),
    magic_resist: field(FIELD_TYPES.NUMBER, 'Observed magic resistance.'),
    attack_damage: field(FIELD_TYPES.NUMBER, 'Observed attack damage.'),
    ability_power: field(FIELD_TYPES.NUMBER, 'Observed ability power.'),
    attack_speed: field(FIELD_TYPES.NUMBER, 'Observed attack speed.'),
    move_speed: field(FIELD_TYPES.NUMBER, 'Observed movement speed.'),
    mana: field(FIELD_TYPES.NUMBER, 'Observed resource amount.'),
    max_mana: field(FIELD_TYPES.NUMBER, 'Observed resource maximum.'),
    temporary_hp: field(FIELD_TYPES.NUMBER, 'Observed temporary health; never inferred from shield amount.'),
    temporary_stats: field(FIELD_TYPES.OBJECT, 'Observed temporary stat values with per-field evidence.'),
    experience_points: field(FIELD_TYPES.NUMBER, 'Observed cumulative raw champion experience points.'),
    total_gold: field(FIELD_TYPES.NUMBER, 'Observed cumulative gold; remains null until independently verified.'),
    lane_minions_killed: field(FIELD_TYPES.INTEGER, 'Observed cumulative lane-minion kill count.'),
    jungle_minions_killed: field(FIELD_TYPES.NUMBER, 'Observed cumulative jungle score; remains null until independently verified.'),
    level: field(FIELD_TYPES.INTEGER, 'Observed or build-bound derived level.'),
    alive: field(FIELD_TYPES.BOOLEAN, 'Observed lifecycle state; null is not alive.'),
    position: field(FIELD_TYPES.POSITION, 'Protocol-observed or derived coordinates, never a map label.'),
  }),
  DamageEvent: Object.freeze({
    source_entity_id: field(FIELD_TYPES.ENTITY_ID, 'Raw source entity identity.'),
    target_entity_id: field(FIELD_TYPES.ENTITY_ID, 'Raw target entity identity.'),
    source_participant_id: field(FIELD_TYPES.PARTICIPANT_ID, 'Build-bound source participant association.'),
    target_participant_id: field(FIELD_TYPES.PARTICIPANT_ID, 'Build-bound target participant association.'),
    amount: field(FIELD_TYPES.NUMBER, 'Recorded amount; stage is separately qualified.'),
    amount_semantic_stage: field(FIELD_TYPES.ENUM, 'Never assume pre/post-mitigation or effective HP loss.'),
    damage_type: field(FIELD_TYPES.ENUM, 'Exact-build damage type where validated.'),
    spell_identifier: field(FIELD_TYPES.STRING, 'Protocol spell identifier, if verified.'),
    is_critical: field(FIELD_TYPES.BOOLEAN, 'Critical classification only when validated.'),
  }),
  BuffEvent: Object.freeze({
    subject_entity_id: field(FIELD_TYPES.ENTITY_ID, 'Entity carrying the buff.'),
    routing_entity_id: field(FIELD_TYPES.ENTITY_ID, 'Protocol routing entity; not implicitly a gameplay target.'),
    source_entity_id: field(FIELD_TYPES.ENTITY_ID, 'Source entity when known.'),
    operation: field(FIELD_TYPES.ENUM, 'Add, update, remove, or unknown protocol operation.'),
    buff_identifier: field(FIELD_TYPES.STRING, 'Build-bound buff identifier or hash.'),
    slot_index: field(FIELD_TYPES.INTEGER, 'Protocol buff slot or index.'),
    stack_count: field(FIELD_TYPES.INTEGER, 'Observed stack count.'),
    duration_seconds: field(FIELD_TYPES.NUMBER, 'Reported duration.'),
    remaining_seconds: field(FIELD_TYPES.NUMBER, 'Reported remaining duration.'),
  }),
  SpellCast: Object.freeze({
    caster_entity_id: field(FIELD_TYPES.ENTITY_ID, 'Caster entity identity.'),
    caster_name: field(FIELD_TYPES.STRING, 'Exact translator caster name when observed.'),
    chain_owner_entity_id: field(FIELD_TYPES.ENTITY_ID, 'Structural chain-owner identity when independently verified.'),
    target_entity_id: field(FIELD_TYPES.ENTITY_ID, 'Target entity identity.'),
    spell_identifier: field(FIELD_TYPES.STRING, 'Build-bound spell identifier.'),
    numeric_spell_key: field(FIELD_TYPES.INTEGER, 'Exact build-bound numeric spell key; not a human-readable ability identity.'),
    spell_slot: field(FIELD_TYPES.ENUM, 'Spell slot if exactly decoded.'),
    target_position: field(FIELD_TYPES.POSITION, 'Protocol coordinate, not strategic location.'),
    cast_result: field(FIELD_TYPES.ENUM, 'Observed cast outcome.'),
    cast_time_seconds: field(FIELD_TYPES.NUMBER, 'Protocol cast-time field only when independently qualified.'),
  }),
  EntityLifecycle: Object.freeze({
    entity_id: field(FIELD_TYPES.ENTITY_ID, 'Entity identity.'),
    participant_id: field(FIELD_TYPES.PARTICIPANT_ID, 'Build-bound participant association for the subject entity.'),
    entity_type: field(FIELD_TYPES.ENTITY_TYPE, 'Registry-backed type; unknown entities remain UNKNOWN_ENTITY.'),
    entity_subtype: field(FIELD_TYPES.STRING, 'Subtype only when independently verified.'),
    lifecycle_operation: field(FIELD_TYPES.ENUM, 'Spawn, update, death, reincarnate-alive/respawn, destroy, despawn, or unknown.'),
    owner_entity_id: field(FIELD_TYPES.ENTITY_ID, 'Owner identity when known.'),
    killer_entity_id: field(FIELD_TYPES.ENTITY_ID, 'Killer entity identity when exactly decoded.'),
    killer_participant_id: field(FIELD_TYPES.PARTICIPANT_ID, 'Build-bound killer participant association.'),
    assisting_entity_ids: field(FIELD_TYPES.ARRAY, 'Assisting entity identities only when exactly decoded.'),
    death_timer_seconds: field(FIELD_TYPES.NUMBER, 'Exact death-timer update value; not an exact respawn timestamp.'),
    respawn_timestamp_ms: field(FIELD_TYPES.INTEGER, 'Exact respawn time only when independently verified.'),
    position: field(FIELD_TYPES.POSITION, 'Protocol coordinate.'),
  }),
  WardEvent: Object.freeze({
    ward_entity_id: field(FIELD_TYPES.ENTITY_ID, 'Ward entity identity.'),
    owner_entity_id: field(FIELD_TYPES.ENTITY_ID, 'Ward owner identity.'),
    ward_type: field(FIELD_TYPES.ENUM, 'Validated ward type; special entities are not promoted.'),
    operation: field(FIELD_TYPES.ENUM, 'Spawn, update, despawn, or unknown.'),
    position: field(FIELD_TYPES.POSITION, 'Protocol coordinate, never strategic location.'),
  }),
  ItemEvent: Object.freeze({
    subject_entity_id: field(FIELD_TYPES.ENTITY_ID, 'Entity affected by the item event.'),
    operation: field(FIELD_TYPES.ENUM, 'Buy, sell, undo, transform, snapshot, swap, substitution-map update, or unknown.'),
    item_identifier: field(FIELD_TYPES.STRING, 'Exact-build item identifier.'),
    source_item_identifier: field(FIELD_TYPES.STRING, 'Source item in an exact substitution-map update.'),
    target_item_identifier: field(FIELD_TYPES.STRING, 'Target item in an exact substitution-map update.'),
    slot_index: field(FIELD_TYPES.INTEGER, 'Exact inventory slot when observed.'),
    source_slot_index: field(FIELD_TYPES.INTEGER, 'First slot in an exact swap operation.'),
    target_slot_index: field(FIELD_TYPES.INTEGER, 'Second slot in an exact swap operation.'),
    inventory_entries: field(FIELD_TYPES.ARRAY, 'Exact decoded snapshot entries; failed rows are not silently omitted.'),
    stage: field(FIELD_TYPES.INTEGER, 'Bounded exact-build support-quest item stage.'),
    stage_code: field(FIELD_TYPES.NUMBER, 'Direct exact-build stage-family code.'),
    snapshot_scope: field(FIELD_TYPES.ENUM, 'Snapshot scope such as live game stream, keyframe, or bounded utility stage.'),
    quantity: field(FIELD_TYPES.INTEGER, 'Reported count.'),
    gold_delta: field(FIELD_TYPES.NUMBER, 'Reported gold delta, not inferred economy state.'),
  }),
  ObjectiveEvent: Object.freeze({
    objective_entity_id: field(FIELD_TYPES.ENTITY_ID, 'Objective entity identity.'),
    operation: field(FIELD_TYPES.ENUM, 'Spawn, death, despawn, state update, or unknown.'),
    killer_entity_id: field(FIELD_TYPES.ENTITY_ID, 'Killer identity when exactly observed.'),
    objective_type: field(FIELD_TYPES.ENUM, 'Objective type only when exactly verified.'),
  }),
  PositionEvent: Object.freeze({
    entity_id: field(FIELD_TYPES.ENTITY_ID, 'Entity identity.'),
    position: field(FIELD_TYPES.POSITION, 'Observed or calibrated coordinate.'),
    direction: field(FIELD_TYPES.POSITION, 'Direct facing vector; never interpreted as a world position.'),
    operation: field(FIELD_TYPES.ENUM, 'Position or facing operation.'),
    resolution_ms: field(FIELD_TYPES.INTEGER, 'Sampling resolution.'),
    interpolation: field(FIELD_TYPES.ENUM, 'Interpolation status.'),
  }),
  MissileEvent: Object.freeze({
    missile_entity_id: field(FIELD_TYPES.ENTITY_ID, 'Missile entity identity.'),
    source_entity_id: field(FIELD_TYPES.ENTITY_ID, 'Source identity.'),
    target_entity_id: field(FIELD_TYPES.ENTITY_ID, 'Target identity.'),
    operation: field(FIELD_TYPES.ENUM, 'Create, update, destroy, or unknown.'),
    position: field(FIELD_TYPES.POSITION, 'Protocol coordinate.'),
    movement_complete_count: field(FIELD_TYPES.INTEGER, 'Direct movement-completion counter when observed.'),
  }),
  AttackEvent: Object.freeze({
    subject_entity_id: field(FIELD_TYPES.ENTITY_ID, 'Entity carrying the attack-state event.'),
    target_entity_id: field(FIELD_TYPES.ENTITY_ID, 'Direct target identity when verified.'),
    operation: field(FIELD_TYPES.ENUM, 'Attack-state operation such as instant-stop or basic-attack-position.'),
    attack_sequence: field(FIELD_TYPES.INTEGER, 'Direct protocol sequence value with bounded neutral semantics.'),
    position: field(FIELD_TYPES.POSITION, 'Direct attack-position X/Z coordinate when present.'),
  }),
  SpellState: Object.freeze({
    subject_entity_id: field(FIELD_TYPES.ENTITY_ID, 'Entity carrying the spell-state update.'),
    operation: field(FIELD_TYPES.ENUM, 'Spell-state operation.'),
    spell_slot_key: field(FIELD_TYPES.INTEGER, 'Direct exact-build spell-slot lookup key.'),
    protocol_numeric_values: field(FIELD_TYPES.OBJECT, 'Direct numeric values whose gameplay roles remain explicitly unknown.'),
  }),
  EntityComponentState: Object.freeze({
    subject_entity_id: field(FIELD_TYPES.ENTITY_ID, 'Entity carrying the component state.'),
    component: field(FIELD_TYPES.STRING, 'Verified runtime component identity.'),
    operation: field(FIELD_TYPES.ENUM, 'Component-state operation such as keyframe cache snapshot.'),
    selector: field(FIELD_TYPES.INTEGER, 'Direct component selector.'),
    position: field(FIELD_TYPES.POSITION, 'Direct component cache coordinate; not map truth.'),
    protocol_numeric_values: field(FIELD_TYPES.OBJECT, 'Direct neutral component values with unresolved business roles.'),
  }),
  ProtectionEvent: Object.freeze({
    subject_entity_id: field(FIELD_TYPES.ENTITY_ID, 'Protected entity.'),
    source_entity_id: field(FIELD_TYPES.ENTITY_ID, 'Protection source.'),
    protection_type: field(FIELD_TYPES.ENUM, 'Shield, heal, temporary HP, or unknown.'),
    reported_amount: field(FIELD_TYPES.NUMBER, 'Reported amount; effective value stays null until validated.'),
    effective_amount: field(FIELD_TYPES.NUMBER, 'Validated effective amount only.'),
    amount_stage: field(FIELD_TYPES.ENUM, 'Reported/gross, application/generated, effective, absorbed, remaining, or unknown.'),
    duplicate_suppressed: field(FIELD_TYPES.BOOLEAN, 'Whether an exact duplicate protocol row was suppressed.'),
  }),
  LevelTransition: Object.freeze({
    entity_id: field(FIELD_TYPES.ENTITY_ID, 'Entity identity.'),
    participant_id: field(FIELD_TYPES.PARTICIPANT_ID, 'Build-bound participant association.'),
    level_before: field(FIELD_TYPES.INTEGER, 'Known prior level.'),
    level_after: field(FIELD_TYPES.INTEGER, 'Exact-build derived level after transition.'),
    is_initialization: field(FIELD_TYPES.BOOLEAN, 'Whether this is an initialization event.'),
  }),
});

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function sha256Buffer(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function assertAllowedInputPath(filePath) {
  invariant(typeof filePath === 'string' && filePath.length > 0, 'input path must be non-empty');
  if (/holdout/i.test(filePath)) throw new Error('Holdout paths are forbidden before read, enumeration, or hashing');
}

function assertNoConsumerAdapterLeak(value, pathLabel = '$') {
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoConsumerAdapterLeak(item, `${pathLabel}[${index}]`));
    return;
  }
  if (!isPlainObject(value)) return;
  for (const [key, item] of Object.entries(value)) {
    if (CONSUMER_FORBIDDEN_KEYS.has(key)) {
      throw new Error(`canonical consumer record leaks exact-build adapter key: ${pathLabel}.${key}`);
    }
    assertNoConsumerAdapterLeak(item, `${pathLabel}.${key}`);
  }
}

function schemaFor(semanticType) {
  const fields = EVENT_FIELD_DEFINITIONS[semanticType];
  if (!fields) throw new Error(`unsupported canonical semantic type: ${semanticType}`);
  return fields;
}

function assertExactKeys(value, expected, label) {
  invariant(isPlainObject(value), `${label} must be an object`);
  const actual = Object.keys(value).sort();
  const required = [...expected].sort();
  invariant(JSON.stringify(actual) === JSON.stringify(required),
    `${label} must contain exactly the declared canonical fields`);
}

function validateCanonicalRecord(record) {
  invariant(isPlainObject(record), 'canonical semantic record must be an object');
  assertNoConsumerAdapterLeak(record);
  invariant(record.schema_version === CANONICAL_SEMANTIC_SCHEMA_VERSION,
    'canonical semantic schema version mismatch');
  invariant(CANONICAL_EVENT_TYPES.includes(record.semantic_type), 'unsupported canonical semantic type');
  const fields = schemaFor(record.semantic_type);
  const envelope = ['schema_version', 'semantic_type', 'event_id', 'replay_sha256', 'exact_build',
    'replay_time_ms', 'fields', 'field_evidence', 'evidence', 'provenance'];
  assertExactKeys(record, envelope, 'canonical semantic record');
  assertExactKeys(record.fields, Object.keys(fields), 'canonical fields');
  assertExactKeys(record.field_evidence, Object.keys(fields), 'canonical field evidence');
  invariant(isPlainObject(record.evidence), 'canonical evidence must be an object');
  invariant(EVIDENCE_STATUS_VOCABULARY.includes(record.evidence.status), 'invalid aggregate evidence status');
  invariant(isPlainObject(record.provenance), 'canonical provenance must be an object');
  for (const name of Object.keys(fields)) {
    const value = record.fields[name];
    const status = record.field_evidence[name];
    invariant(value !== undefined, `canonical field ${name} must be explicit (null is allowed)`);
    invariant(EVIDENCE_STATUS_VOCABULARY.includes(status), `invalid evidence status for ${name}`);
    if (value === null) {
      invariant(!['VERIFIED_DIRECT', 'VERIFIED_DERIVED', 'INFERRED'].includes(status),
        `null canonical field ${name} cannot claim a populated evidence grade`);
    } else {
      invariant(status !== 'UNAVAILABLE', `non-null canonical field ${name} cannot be UNAVAILABLE`);
    }
  }
  return structuredClone(record);
}

function blankFields(semanticType, evidenceStatus = 'UNKNOWN') {
  schemaFor(semanticType);
  invariant(EVIDENCE_STATUS_VOCABULARY.includes(evidenceStatus), 'invalid blank field evidence status');
  return {
    fields: Object.fromEntries(Object.keys(EVENT_FIELD_DEFINITIONS[semanticType]).map((name) => [name, null])),
    field_evidence: Object.fromEntries(Object.keys(EVENT_FIELD_DEFINITIONS[semanticType])
      .map((name) => [name, evidenceStatus])),
  };
}

function createCanonicalRecord(semanticType, record) {
  invariant(isPlainObject(record), 'canonical record payload must be an object');
  schemaFor(semanticType);
  invariant(isPlainObject(record.fields) && isPlainObject(record.field_evidence),
    'canonical fields and field_evidence must be explicit; use blankFields() to request explicit unknown/null values');
  const merged = {
    schema_version: CANONICAL_SEMANTIC_SCHEMA_VERSION,
    semantic_type: semanticType,
    event_id: null,
    replay_sha256: null,
    exact_build: null,
    replay_time_ms: null,
    fields: record.fields,
    field_evidence: record.field_evidence,
    evidence: { status: 'UNKNOWN', limitations: [] },
    provenance: { source_kind: 'ROFL', source_artifact_sha256: null, parser_version: null, exact_build_adapter_id: null },
    ...record,
  };
  return validateCanonicalRecord(merged);
}

function canonicalSchemaDocument() {
  return {
    schema: 'ROFL_CANONICAL_SEMANTIC_SCHEMA_DOCUMENT_V1',
    schema_version: CANONICAL_SEMANTIC_SCHEMA_VERSION,
    consumer_contract: {
      exact_build_bound: true,
      nearest_build_fallback: 'FORBIDDEN',
      null_policy: 'NULL_MEANS_MISSING_OR_NOT_COMPUTABLE_AND_NEVER_NUMERIC_ZERO',
      unknown_policy: 'UNKNOWN_ENTITY_AND_UNKNOWN_EVIDENCE_ARE_PRESERVED',
      evidence_policy: 'EVERY_DECLARED_FIELD_HAS_AN_EXPLICIT_EVIDENCE_STATUS',
      adapter_boundary: 'Packet route, opcode, and decoder internals exist only in exact-build adapter metadata, never in consumer records.',
      forbidden_consumer_keys: [...CONSUMER_FORBIDDEN_KEYS].sort(),
    },
    evidence_status_vocabulary: EVIDENCE_STATUS_VOCABULARY,
    entity_type_vocabulary: ENTITY_TYPE_VOCABULARY,
    canonical_event_types: CANONICAL_EVENT_TYPES.map((semanticType) => ({
      semantic_type: semanticType,
      fields: EVENT_FIELD_DEFINITIONS[semanticType],
    })),
  };
}

function profileRecords(capabilityManifest, exactBuild) {
  invariant(capabilityManifest?.exact_build_only === true, 'capability manifest must be exact-build only');
  invariant(capabilityManifest?.nearest_build_fallback === 'FORBIDDEN', 'capability manifest must forbid fallback');
  const profile = capabilityManifest?.build_profiles?.[exactBuild];
  invariant(profile && Array.isArray(profile.records), `capability manifest has no exact profile for ${exactBuild}`);
  return profile.records;
}

function verifiedRecord(records, capability) {
  return records.find((row) => row.semantic_capability === capability
    && ['PASS', 'PARTIAL'].includes(row.validation_status)
    && ['VERIFIED_DIRECT', 'VERIFIED_DERIVED'].includes(row.evidence_grade)) ?? null;
}

const ADAPTER_CAPABILITY_BINDINGS = Object.freeze({
  HeroState: [
    'CURRENT_HP', 'MAX_HP', 'ARMOR', 'MAGIC_RESIST', 'LEVEL_TRANSITION',
    'ATTACK_DAMAGE', 'ABILITY_POWER', 'ATTACK_SPEED', 'MOVE_SPEED',
    'MANA', 'CURRENT_MANA', 'MAX_MANA', 'TEMPORARY_HP', 'TEMPORARY_STATS',
    'XP', 'GOLD', 'CS',
  ],
  DamageEvent: [
    'DAMAGE', 'DAMAGE_TYPE', 'DAMAGE_SOURCE_ATTRIBUTION', 'DAMAGE_STAGE',
    'DAMAGE_MITIGATION', 'HERO_KILL_CREDIT', 'HERO_ASSIST',
  ],
  BuffEvent: ['BUFF', 'DEBUFF', 'RUNE_PROC', 'PASSIVE_PROC'],
  SpellCast: ['CAST_SPELL', 'SUMMONER_CAST'],
  EntityLifecycle: [
    'HERO_DEATH', 'HERO_DEATH_TIMER', 'HERO_RESPAWN', 'NPC_SPAWN', 'NPC_DEATH', 'NPC_DESPAWN',
    'NPC_CLASSIFICATION', 'LANE_MINION_LIFECYCLE', 'JUNGLE_MONSTER_LIFECYCLE',
    'STRUCTURE',
  ],
  WardEvent: ['WARD_SPAWN', 'WARD_LIFECYCLE', 'VISIBILITY_STATE'],
  ItemEvent: [
    'ITEM_BUY', 'ITEM_SELL', 'ITEM_UNDO', 'ITEM_TRANSFORM', 'ITEM_DESTROY', 'ITEM_STATE',
    'ITEM_SWAP', 'ITEM_SUBSTITUTION_MAP', 'SUPPORT_QUEST_ITEM_STAGE',
  ],
  ObjectiveEvent: ['OBJECTIVE', 'CAMP_CLEAR', 'CAMP_STATE', 'MAP_MECHANIC'],
  PositionEvent: ['HERO_PATH', 'MOVEMENT_SPECIAL', 'FACE_DIRECTION_VECTOR'],
  MissileEvent: ['MISSILE', 'MISSILE_SYNC_MOVEMENT_COMPLETE_COUNT'],
  AttackEvent: ['INSTANT_STOP_ATTACK', 'BASIC_ATTACK_POSITION_MINION'],
  SpellState: ['ABILITY_COOLDOWN_BROADCAST'],
  EntityComponentState: ['WALL_TRACKING_COMPONENT_CACHE_SNAPSHOT'],
  ProtectionEvent: [
    'SHIELD_GENERATED', 'SHIELD_ABSORBED', 'SHIELD_REMAINING', 'SHIELD_LIFECYCLE',
    'HEAL_REPORTED', 'HEAL_EFFECTIVE', 'OVERHEAL',
  ],
  LevelTransition: ['LEVEL_TRANSITION'],
});

function buildExactBuildAdapterMetadata(capabilityManifest, exactBuild = DEFAULT_EXACT_BUILD) {
  const records = profileRecords(capabilityManifest, exactBuild);
  const bindings = [];
  for (const semanticType of CANONICAL_EVENT_TYPES) {
    for (const capability of ADAPTER_CAPABILITY_BINDINGS[semanticType] ?? []) {
      const row = records.find((candidate) => candidate.semantic_capability === capability) ?? null;
      if (!row) continue;
      bindings.push({
        canonical_semantic_type: semanticType,
        semantic_capability: capability,
        adapter_id: row.decoder_version ?? null,
        exact_build: exactBuild,
        protocol_route: row.protocol_route ?? null,
        packet_registration_route: row.packet_registration_route ?? null,
        field_mapping: row.field_mapping ?? {},
        evidence_grade: row.evidence_grade,
        validation_status: row.validation_status,
        known_limits: row.known_limits ?? [],
      });
    }
  }
  return {
    schema: EXACT_BUILD_ADAPTER_SCHEMA_VERSION,
    exact_build: exactBuild,
    exact_build_only: true,
    nearest_build_fallback: 'FORBIDDEN',
    scope: 'Adapter-only metadata. It must not be copied into canonical consumer records.',
    bindings: bindings.sort((left, right) => left.canonical_semantic_type.localeCompare(right.canonical_semantic_type)
      || left.semantic_capability.localeCompare(right.semantic_capability)),
  };
}

function evidenceBinding(row, capability, exactBuild) {
  return row ? {
    semantic_capability: capability,
    exact_build: exactBuild,
    evidence_grade: row.evidence_grade,
    validation_status: row.validation_status,
    evidence_status: row.evidence_grade,
  } : {
    semantic_capability: capability,
    exact_build: exactBuild,
    evidence_grade: 'UNAVAILABLE',
    validation_status: 'UNAVAILABLE',
    evidence_status: 'UNAVAILABLE',
  };
}

function buildEntityTypeRegistry(capabilityManifest, exactBuild = DEFAULT_EXACT_BUILD) {
  const records = profileRecords(capabilityManifest, exactBuild);
  const champion = verifiedRecord(records, 'PARTICIPANT_MAPPING');
  const ward = verifiedRecord(records, 'WARD_SPAWN');
  invariant(champion, 'exact-build participant mapping evidence is required for CHAMPION registry status');
  invariant(ward, 'exact-build WardSpawn evidence is required for WARD registry status');
  const unavailable = (entityType, description) => ({
    entity_type: entityType,
    aliases: [],
    status: 'UNAVAILABLE',
    evidence_status: 'UNAVAILABLE',
    subtype_status: 'UNAVAILABLE',
    verified_subtypes: [],
    description,
    evidence_bindings: [],
    limitation: 'No exact-build verified entity-type or subtype mapping is currently published.',
  });
  const entries = [
    {
      entity_type: 'CHAMPION', aliases: ['HERO'], status: 'VERIFIED_DERIVED',
      evidence_status: 'VERIFIED_DERIVED', subtype_status: 'UNAVAILABLE', verified_subtypes: [],
      description: 'Participant-backed champion entity recognized through the exact-build participant mapping.',
      evidence_bindings: [evidenceBinding(champion, 'PARTICIPANT_MAPPING', exactBuild)],
      limitation: 'Champion identity is build-bound; subclass taxonomy is not established here.',
    },
    unavailable('MINION', 'Lane or summoned minion entity.'),
    unavailable('MONSTER', 'Neutral or ordinary monster entity.'),
    {
      entity_type: 'WARD', aliases: [], status: 'VERIFIED_DERIVED',
      evidence_status: 'VERIFIED_DERIVED', subtype_status: 'UNAVAILABLE', verified_subtypes: [],
      description: 'Confirmed player-active ward entity from the exact-build WardSpawn capability.',
      evidence_bindings: [evidenceBinding(ward, 'WARD_SPAWN', exactBuild)],
      limitation: 'Special/map/unknown entities are retained and are not promoted to WARD; ward subtype remains unverified.',
    },
    unavailable('MISSILE', 'Projectile or missile entity.'),
    unavailable('STRUCTURE', 'Structure entity.'),
    unavailable('OBJECTIVE', 'Objective entity.'),
    unavailable('MAP_MECHANIC', 'Protocol-observed map mechanic entity; this is not map truth.'),
    {
      entity_type: 'UNKNOWN_ENTITY', aliases: [], status: 'VERIFIED_DIRECT',
      evidence_status: 'VERIFIED_DIRECT', subtype_status: 'NOT_GAMEPLAY_RELEVANT', verified_subtypes: [],
      description: 'Required preservation classification for an observed entity that lacks an exact verified type mapping.',
      evidence_bindings: [{ semantic_capability: 'RAW_ENTITY_REFERENCE_PRESERVATION', exact_build: exactBuild,
        evidence_grade: 'VERIFIED_DIRECT', validation_status: 'PASS', evidence_status: 'VERIFIED_DIRECT' }],
      limitation: 'UNKNOWN_ENTITY is not a claim that an entity is irrelevant or absent; it prevents silent type invention.',
    },
  ];
  invariant(entries.length === ENTITY_TYPE_VOCABULARY.length, 'entity type registry must be exhaustive');
  return {
    schema: ENTITY_TYPE_REGISTRY_VERSION,
    exact_build: exactBuild,
    exact_build_only: true,
    nearest_build_fallback: 'FORBIDDEN',
    unknown_entity_policy: 'Observed unclassified entities are emitted as UNKNOWN_ENTITY with raw identity/provenance retained.',
    entries,
  };
}

function readJsonSource(filePath, root = process.cwd()) {
  assertAllowedInputPath(filePath);
  const resolved = path.resolve(root, filePath);
  const bytes = fs.readFileSync(resolved);
  return {
    path: path.relative(root, resolved).split(path.sep).join('/'),
    sha256: sha256Buffer(bytes),
    byte_count: bytes.length,
    document: JSON.parse(bytes.toString('utf8')),
  };
}

function writeJson(filePath, document) {
  const text = `${JSON.stringify(document, null, 2)}\n`;
  fs.writeFileSync(filePath, text, 'utf8');
  return { file: path.basename(filePath), sha256: sha256Buffer(Buffer.from(text)), byte_count: Buffer.byteLength(text), schema: document.schema };
}

function buildCanonicalSemanticSchemaArtifacts({ root = process.cwd(), capabilityManifestPath = 'artifacts/semantic_coverage_v1/capability_manifest.json', outputDirectory = 'artifacts/full_semantic_baseline_v1/schema', exactBuild = DEFAULT_EXACT_BUILD } = {}) {
  const manifest = readJsonSource(capabilityManifestPath, root);
  const target = path.resolve(root, outputDirectory);
  assertAllowedInputPath(target);
  const canonicalSchema = canonicalSchemaDocument();
  const entityRegistry = buildEntityTypeRegistry(manifest.document, exactBuild);
  const adapterMetadata = buildExactBuildAdapterMetadata(manifest.document, exactBuild);
  fs.mkdirSync(target, { recursive: true });
  const files = [
    writeJson(path.join(target, 'canonical_semantic_schema.json'), canonicalSchema),
    writeJson(path.join(target, 'entity_type_registry.json'), entityRegistry),
    writeJson(path.join(target, 'exact_build_adapter_metadata.json'), adapterMetadata),
  ];
  const artifactManifest = {
    schema: 'ROFL_CANONICAL_SEMANTIC_SCHEMA_ARTIFACT_MANIFEST_V1',
    exact_build: exactBuild,
    exact_build_only: true,
    nearest_build_fallback: 'FORBIDDEN',
    input_sources: [{ label: 'capability_manifest', path: manifest.path, sha256: manifest.sha256, byte_count: manifest.byte_count }],
    self_hash_excluded: true,
    files,
  };
  files.push(writeJson(path.join(target, 'artifact_manifest.json'), artifactManifest));
  return { output_directory: target, files, schema_version: CANONICAL_SEMANTIC_SCHEMA_VERSION };
}

module.exports = {
  ADAPTER_CAPABILITY_BINDINGS,
  CANONICAL_EVENT_TYPES,
  CANONICAL_SEMANTIC_SCHEMA_VERSION,
  CONSUMER_FORBIDDEN_KEYS,
  DEFAULT_EXACT_BUILD,
  ENTITY_TYPE_REGISTRY_VERSION,
  ENTITY_TYPE_VOCABULARY,
  EVENT_FIELD_DEFINITIONS,
  EVIDENCE_STATUS_VOCABULARY,
  EXACT_BUILD_ADAPTER_SCHEMA_VERSION,
  assertAllowedInputPath,
  assertNoConsumerAdapterLeak,
  blankFields,
  buildCanonicalSemanticSchemaArtifacts,
  buildEntityTypeRegistry,
  buildExactBuildAdapterMetadata,
  canonicalSchemaDocument,
  createCanonicalRecord,
  sha256Buffer,
  stableStringify,
  validateCanonicalRecord,
};

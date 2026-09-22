'use strict';

const crypto = require('node:crypto');

const STATE_ENGINE_SCHEMA = 'SEMANTIC_STATE_ENGINE_V1';
const STATE_SNAPSHOT_SCHEMA = 'SEMANTIC_STATE_SNAPSHOT_V1';
const STATE_UPDATE = 'STATE_UPDATE';
const VERIFIED_DERIVED_STATE = 'VERIFIED_DERIVED_STATE';
const STATE_EVENT_TYPES = Object.freeze([STATE_UPDATE, VERIFIED_DERIVED_STATE]);

const DIRECT_STATE_EVIDENCE = new Set([
  'VERIFIED_DIRECT',
  'DETAILS_DIRECT',
  'GROUND_TRUTH_FRAME_SNAPSHOT',
]);

const KNOWN_EVENT_TYPES = new Set([
  'DAMAGE',
  'SPELL_CAST',
  'DEATH',
  'CHAMPION_KILL',
  'RESPAWN',
  'POSITION',
  'ITEM_PURCHASE',
  'ITEM_SOLD',
  'ITEM_UNDO',
  'ITEM_TRANSFORM',
  'BUFF',
  'SHIELD',
  'HEAL',
  'PROTECTION',
  'LEVEL_TRANSITION',
  'ENTITY_SPAWN',
  'ENTITY_UPDATE',
  'ENTITY_DEATH',
  'ENTITY_DESTROY',
  'ENTITY_DESPAWN',
  'WARD_SPAWN',
  'WARD_LIFECYCLE',
]);

const COMBAT_EVENT_TYPES = new Set([
  'DAMAGE',
  'SPELL_CAST',
  'DEATH',
  'CHAMPION_KILL',
  'RESPAWN',
  'BUFF',
  'SHIELD',
  'HEAL',
  'PROTECTION',
]);

const EVENT_TYPE_ALIASES = Object.freeze({
  HERO_REINCARNATE_ALIVE: 'RESPAWN',
  REINCARNATE_ALIVE: 'RESPAWN',
});

const COMBAT_STATE_FIELDS = new Set([
  'current_hp',
  'max_hp',
  'armor',
  'magic_resist',
  'attack_damage',
  'ability_power',
  'attack_speed',
  'move_speed',
  'mana',
  'max_mana',
  'shield',
  'shield_remaining',
  'level',
  'alive',
  'death_state',
]);

const TIMESTAMP_FIELDS = Object.freeze([
  'replay_time_ms',
  'timestamp_ms',
  'spawn_time_ms',
  'ward_spawn_time_ms',
  'death_time_ms',
  'apply_time_ms',
  'protection_start_ms',
  'destroy_time_ms',
  'despawn_time_ms',
  'ward_disappear_time_ms',
]);

const FORBIDDEN_FIELD_NAMES = new Set(['__proto__', 'prototype', 'constructor']);

function hasOwn(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key);
}

function assertPlainObject(value, name) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${name} must be an object`);
  }
}

function assertJsonValue(value, path = '$', seen = new Set()) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError(`${path} must not contain a non-finite number`);
    return;
  }
  if (typeof value !== 'object') throw new TypeError(`${path} must contain JSON-compatible values`);
  if (seen.has(value)) throw new TypeError(`${path} must not contain a cycle`);
  seen.add(value);
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertJsonValue(item, `${path}[${index}]`, seen));
  } else {
    for (const [key, item] of Object.entries(value)) assertJsonValue(item, `${path}.${key}`, seen);
  }
  seen.delete(value);
}

function clone(value) {
  if (value === undefined) return undefined;
  return structuredClone(value);
}

function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => (
      `${JSON.stringify(key)}:${stableStringify(value[key])}`
    )).join(',')}}`;
  }
  return JSON.stringify(value);
}

function requireReplaySha256(value, name = 'replay_sha256') {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/i.test(value)) {
    throw new Error(`${name} must be an exact 64-character Replay SHA-256`);
  }
  return value.toLowerCase();
}

function requireExactBuild(value, name = 'exact_build') {
  if (typeof value !== 'string' || !/^\d+\.\d+\.\d+\.\d+$/.test(value)) {
    throw new Error(`${name} must be an exact four-component Replay build`);
  }
  return value;
}

function valuesAtPaths(record, paths) {
  const values = [];
  for (const path of paths) {
    let current = record;
    for (const key of path) {
      if (!current || typeof current !== 'object' || !hasOwn(current, key)) {
        current = undefined;
        break;
      }
      current = current[key];
    }
    if (current !== null && current !== undefined) values.push(current);
  }
  return values;
}

function uniqueScopeValue(values, normalizer, name) {
  const normalized = values.map((value) => normalizer(value, name));
  const unique = [...new Set(normalized)];
  if (unique.length === 0) throw new Error(`record is missing exact ${name}`);
  if (unique.length !== 1) throw new Error(`record has conflicting ${name} values`);
  return unique[0];
}

function exactScopeFromRecord(record) {
  assertPlainObject(record, 'record');
  const shaValues = valuesAtPaths(record, [
    ['replay_sha256'],
    ['scope', 'replay_sha256'],
    ['raw_packet_ref', 'replay_sha256'],
    ['source', 'replay_sha256'],
  ]);
  if (Array.isArray(record.raw_packet_refs)) {
    for (const reference of record.raw_packet_refs) {
      if (reference && reference.replay_sha256 !== null && reference.replay_sha256 !== undefined) {
        shaValues.push(reference.replay_sha256);
      }
    }
  }
  const buildValues = valuesAtPaths(record, [
    ['exact_build'],
    ['replay_build'],
    ['game_version'],
    ['replay_version'],
    ['scope', 'exact_build'],
    ['raw_packet_ref', 'exact_build'],
    ['raw_packet_ref', 'game_version'],
    ['raw_packet_ref', 'replay_version'],
    ['source', 'exact_build'],
  ]);
  if (Array.isArray(record.raw_packet_refs)) {
    for (const reference of record.raw_packet_refs) {
      if (!reference || typeof reference !== 'object') continue;
      for (const field of ['exact_build', 'game_version', 'replay_version']) {
        if (reference[field] !== null && reference[field] !== undefined) buildValues.push(reference[field]);
      }
    }
  }
  return {
    replay_sha256: uniqueScopeValue(shaValues, requireReplaySha256, 'replay_sha256'),
    exact_build: uniqueScopeValue(buildValues, requireExactBuild, 'exact_build'),
  };
}

function timestampFromRecord(record, required = false) {
  for (const field of TIMESTAMP_FIELDS) {
    if (!hasOwn(record, field) || record[field] === null || record[field] === undefined) continue;
    if (!Number.isFinite(record[field]) || record[field] < 0) {
      throw new Error(`${field} must be a non-negative finite number`);
    }
    return { replay_time_ms: record[field], timestamp_source_field: field };
  }
  if (required) throw new Error('state update requires an observed Replay timestamp');
  return { replay_time_ms: null, timestamp_source_field: null };
}

function explicitEvidenceGrade(record) {
  if (hasOwn(record, 'evidence_grade')) return record.evidence_grade;
  if (hasOwn(record, 'confidence')) return record.confidence;
  return 'UNVERIFIED';
}

function stateEventType(record, explicitType = null) {
  const candidate = explicitType ?? record.state_event_type ?? record.canonical_event_type
    ?? record.event_type ?? null;
  if (candidate === null || candidate === undefined) return null;
  const normalized = String(candidate).toUpperCase();
  return STATE_EVENT_TYPES.includes(normalized) ? normalized : null;
}

function canonicalEventType(record) {
  const canonicalLifecycleOperation = record.semantic_type === 'EntityLifecycle'
    ? record.fields?.lifecycle_operation ?? null : null;
  const source = record.canonical_event_type ?? record.event_type ?? record.source_event_type
    ?? canonicalLifecycleOperation ?? null;
  if (source === null || source === undefined || String(source).trim() === '') return 'UNKNOWN';
  const normalized = String(source).trim().toUpperCase().replace(/[ -]+/g, '_');
  const aliased = EVENT_TYPE_ALIASES[normalized] ?? normalized;
  return KNOWN_EVENT_TYPES.has(aliased) ? aliased : 'UNKNOWN';
}

function rawReferences(record) {
  return {
    raw_packet_ref: hasOwn(record, 'raw_packet_ref') ? clone(record.raw_packet_ref) : null,
    raw_packet_refs: hasOwn(record, 'raw_packet_refs') ? clone(record.raw_packet_refs) : null,
  };
}

function entityDescriptorFromRecord(record) {
  const nested = record.entity && typeof record.entity === 'object' && !Array.isArray(record.entity)
    ? record.entity : null;
  const explicitKey = record.entity_key ?? nested?.entity_key ?? null;
  if (explicitKey !== null && (typeof explicitKey !== 'string' || explicitKey.trim() === '')) {
    throw new Error('entity_key must be a non-empty string when supplied');
  }
  const candidates = [
    ['entity_id', record.entity_id ?? nested?.entity_id ?? record.fields?.entity_id],
    ['participant_id', record.participant_id ?? record.target_participant_id
      ?? nested?.participant_id ?? record.fields?.participant_id],
    ['entity_network_id', record.entity_network_id ?? nested?.entity_network_id],
    ['network_id', record.network_id ?? nested?.network_id],
    ['target_network_id', record.target_network_id],
  ];
  if ((typeof record.entity === 'string' || typeof record.entity === 'number')
      && record.entity !== '') candidates.unshift(['entity_id', record.entity]);
  if (nested && nested.id !== null && nested.id !== undefined) {
    candidates.unshift([nested.id_kind ?? 'entity_id', nested.id]);
  }
  if (explicitKey !== null) candidates.push(['entity_key', explicitKey]);
  const chosen = candidates.find(([, value]) => value !== null && value !== undefined && value !== '');
  if (!chosen) throw new Error('state update requires an entity or participant identifier');
  const [idKind, id] = chosen;
  const keyKind = String(idKind).toLowerCase().includes('participant') ? 'participant' : 'entity';
  return {
    entity_key: explicitKey ?? `${keyKind}:${String(id)}`,
    id_kind: idKind,
    id,
    participant_id: record.participant_id ?? record.target_participant_id
      ?? nested?.participant_id ?? null,
    entity_network_id: record.entity_network_id ?? record.network_id
      ?? nested?.entity_network_id ?? nested?.network_id ?? record.target_network_id ?? null,
    champion: record.champion ?? nested?.champion ?? null,
    team_id: record.team_id ?? nested?.team_id ?? null,
    source_entity: nested ? clone(nested) : null,
  };
}

function pushEntityReference(references, role, idKind, id) {
  if (id === null || id === undefined || id === '') return;
  const reference = { role, id_kind: idKind, id };
  const key = stableStringify(reference);
  if (!references.some((item) => stableStringify(item) === key)) references.push(reference);
}

function entityReferencesFromRecord(record, stateEntity = null) {
  const references = [];
  const fields = [
    ['entity', 'entity_id', record.entity_id],
    ['entity', 'entity_network_id', record.entity_network_id],
    ['entity', 'network_id', record.network_id],
    ['participant', 'participant_id', record.participant_id],
    ['source', 'network_id', record.source_network_id],
    ['source_participant', 'participant_id', record.source_participant_id],
    ['target', 'network_id', record.target_network_id],
    ['target_participant', 'participant_id', record.target_participant_id],
    ['victim', 'network_id', record.victim_network_id],
    ['killer', 'network_id', record.killer_network_id],
    ['caster', 'network_id', record.caster_network_id],
    ['owner', 'network_id', record.owner_network_id],
  ];
  for (const [role, kind, id] of fields) pushEntityReference(references, role, kind, id);
  if (record.fields && typeof record.fields === 'object' && !Array.isArray(record.fields)) {
    pushEntityReference(references, 'entity', 'entity_id', record.fields.entity_id);
    pushEntityReference(references, 'participant', 'participant_id', record.fields.participant_id);
    pushEntityReference(references, 'source', 'entity_id', record.fields.source_entity_id);
    pushEntityReference(references, 'target', 'entity_id', record.fields.target_entity_id);
    pushEntityReference(references, 'killer', 'entity_id', record.fields.killer_entity_id);
    pushEntityReference(
      references, 'killer_participant', 'participant_id', record.fields.killer_participant_id,
    );
  }
  if (record.entity && typeof record.entity === 'object' && !Array.isArray(record.entity)) {
    const nested = record.entity;
    pushEntityReference(references, 'entity', 'entity_id', nested.id ?? nested.entity_id);
    pushEntityReference(references, 'entity', 'entity_network_id', nested.entity_network_id ?? nested.network_id);
    pushEntityReference(references, 'participant', 'participant_id', nested.participant_id);
  }
  if (stateEntity) {
    pushEntityReference(references, 'state_entity', stateEntity.id_kind, stateEntity.id);
    pushEntityReference(references, 'participant', 'participant_id', stateEntity.participant_id);
    pushEntityReference(references, 'entity', 'entity_network_id', stateEntity.entity_network_id);
  }
  return references;
}

function statePayload(record) {
  for (const field of ['state', 'state_fields', 'updates']) {
    if (hasOwn(record, field)) {
      assertPlainObject(record[field], field);
      return record[field];
    }
  }
  throw new Error('state update requires an explicit state, state_fields, or updates object');
}

function normalizeEvidenceObject(value, name) {
  if (value === null || value === undefined) return null;
  if (typeof value === 'string') return { evidence_grade: value };
  assertPlainObject(value, name);
  return clone(value);
}

function evidenceGradeFromField(record, descriptor, fieldName, fallback) {
  if (descriptor && hasOwn(descriptor, 'evidence_grade')) return descriptor.evidence_grade;
  if (descriptor && hasOwn(descriptor, 'confidence')) return descriptor.confidence;
  const evidence = record.field_evidence?.[fieldName];
  if (typeof evidence === 'string') return evidence;
  if (evidence && hasOwn(evidence, 'evidence_grade')) return evidence.evidence_grade;
  if (evidence && hasOwn(evidence, 'confidence')) return evidence.confidence;
  const confidence = record.field_confidence?.[fieldName];
  if (typeof confidence === 'string') return confidence;
  return fallback;
}

function validateStateEvidence(kind, grade, fieldName = null) {
  const prefix = fieldName === null ? 'state update' : `state field ${fieldName}`;
  if (kind === VERIFIED_DERIVED_STATE && grade !== 'VERIFIED_DERIVED') {
    throw new Error(`${prefix} in VERIFIED_DERIVED_STATE requires VERIFIED_DERIVED evidence`);
  }
  if (kind === STATE_UPDATE && !DIRECT_STATE_EVIDENCE.has(grade)) {
    throw new Error(`${prefix} in STATE_UPDATE requires explicit direct evidence`);
  }
}

function normalizeStateFields(record, kind, recordGrade) {
  const payload = statePayload(record);
  const entries = Object.entries(payload).sort(([left], [right]) => left.localeCompare(right));
  if (entries.length === 0) throw new Error('state update must observe at least one field');
  const fields = {};
  for (const [fieldName, supplied] of entries) {
    if (fieldName === '' || FORBIDDEN_FIELD_NAMES.has(fieldName)) {
      throw new Error(`invalid state field name: ${fieldName}`);
    }
    const descriptor = supplied && typeof supplied === 'object' && !Array.isArray(supplied)
      && hasOwn(supplied, 'value') ? supplied : null;
    const value = descriptor ? descriptor.value : supplied;
    if (value === undefined) throw new Error(`state field ${fieldName} must not be undefined`);
    assertJsonValue(value, `state.${fieldName}`);
    const evidenceGrade = evidenceGradeFromField(record, descriptor, fieldName, recordGrade);
    validateStateEvidence(kind, evidenceGrade, fieldName);
    fields[fieldName] = {
      value: clone(value),
      evidence_grade: evidenceGrade,
      field_evidence: normalizeEvidenceObject(
        descriptor?.field_evidence ?? record.field_evidence?.[fieldName] ?? null,
        `field_evidence.${fieldName}`,
      ),
      field_confidence: descriptor?.field_confidence
        ?? record.field_confidence?.[fieldName] ?? null,
      field_provenance: clone(
        descriptor?.provenance ?? record.field_provenance?.[fieldName] ?? null,
      ),
    };
  }
  return fields;
}

function recordEvidence(record, grade) {
  return {
    evidence_grade: grade,
    confidence: hasOwn(record, 'confidence') ? record.confidence : null,
    semantic_status: hasOwn(record, 'semantic_status') ? record.semantic_status : null,
    field_confidence: hasOwn(record, 'field_confidence') ? clone(record.field_confidence) : null,
    source: hasOwn(record, 'source') ? clone(record.source) : null,
    ...rawReferences(record),
  };
}

function sourceEventType(record) {
  const value = record.event_type ?? record.source_event_type ?? record.canonical_event_type ?? null;
  return value === undefined ? null : value;
}

function recordId(record) {
  for (const field of [
    'source_record_id', 'event_id', 'anchor_id', 'state_update_id', 'record_id', 'id',
  ]) {
    if (record[field] !== null && record[field] !== undefined) return record[field];
  }
  return null;
}

function timelineId(entry) {
  return `semantic-timeline:${crypto.createHash('sha256').update(stableStringify({
    replay_sha256: entry.replay_sha256,
    exact_build: entry.exact_build,
    sequence: entry.sequence,
    record_kind: entry.record_kind,
    canonical_event_type: entry.canonical_event_type,
    replay_time_ms: entry.replay_time_ms,
    original_record: entry.original_record,
  })).digest('hex').slice(0, 24)}`;
}

function compareTimeline(left, right) {
  const leftTime = left.replay_time_ms === null ? Number.POSITIVE_INFINITY : left.replay_time_ms;
  const rightTime = right.replay_time_ms === null ? Number.POSITIVE_INFINITY : right.replay_time_ms;
  return leftTime - rightTime || left.sequence - right.sequence || left.timeline_id.localeCompare(right.timeline_id);
}

function assertQueryTime(value, name) {
  if (!Number.isFinite(value) || value < 0) throw new Error(`${name} must be a non-negative finite number`);
  return value;
}

function normalizedFilterValues(value) {
  const values = Array.isArray(value) ? value : [value];
  return new Set(values.map((item) => String(item).trim().toUpperCase().replace(/[ -]+/g, '_')));
}

function matchesEntitySelector(entry, options) {
  const selectors = [
    ['entity_id', options.entity_id],
    ['entity_network_id', options.entity_network_id ?? options.network_id],
    ['participant_id', options.participant_id],
  ].filter(([, value]) => value !== null && value !== undefined);
  if (options.entity_key !== null && options.entity_key !== undefined) {
    if (entry.state_entity?.entity_key !== options.entity_key) return false;
  }
  if (selectors.length === 0) return true;
  return selectors.every(([kind, id]) => entry.entity_references.some((reference) => (
    String(reference.id) === String(id)
      && (kind === 'entity_id'
        || String(reference.id_kind).toLowerCase().includes(kind.replace('entity_', '')))
  )));
}

function isCombatEntry(entry) {
  if (COMBAT_EVENT_TYPES.has(entry.canonical_event_type)) return true;
  if (STATE_EVENT_TYPES.includes(entry.record_kind)) {
    return Object.keys(entry.state_fields).some((field) => COMBAT_STATE_FIELDS.has(field));
  }
  const domain = entry.original_record.semantic_domain ?? entry.original_record.domain ?? null;
  const domains = Array.isArray(entry.original_record.semantic_domains)
    ? entry.original_record.semantic_domains : [];
  return String(domain ?? '').toLowerCase() === 'combat'
    || domains.some((value) => String(value).toLowerCase() === 'combat');
}

class SemanticStateEngine {
  constructor(scope) {
    assertPlainObject(scope, 'scope');
    this.schema_version = 1;
    this.engine_schema = STATE_ENGINE_SCHEMA;
    this.scope = {
      replay_sha256: requireReplaySha256(scope.replay_sha256),
      exact_build: requireExactBuild(scope.exact_build ?? scope.replay_build ?? scope.game_version),
    };
    this.timeline = [];
    this.nextSequence = 0;
  }

  assertRecordScope(record) {
    const scope = exactScopeFromRecord(record);
    if (scope.replay_sha256 !== this.scope.replay_sha256) {
      throw new Error('record Replay SHA-256 does not match engine scope');
    }
    if (scope.exact_build !== this.scope.exact_build) {
      throw new Error('record exact build does not match engine scope');
    }
    return scope;
  }

  assertQueryScope(options) {
    for (const [field, expected] of [
      ['replay_sha256', this.scope.replay_sha256],
      ['exact_build', this.scope.exact_build],
      ['replay_build', this.scope.exact_build],
      ['game_version', this.scope.exact_build],
    ]) {
      if (options[field] !== null && options[field] !== undefined
          && String(options[field]).toLowerCase() !== String(expected).toLowerCase()) {
        throw new Error(`query ${field} does not match engine scope`);
      }
    }
  }

  ingest(record, explicitType = null) {
    if (stateEventType(record, explicitType) !== null) return this.ingestStateUpdate(record, explicitType);
    return this.ingestEvent(record);
  }

  ingestEvent(record) {
    assertPlainObject(record, 'event');
    assertJsonValue(record, '$event');
    this.assertRecordScope(record);
    const time = timestampFromRecord(record, false);
    const grade = explicitEvidenceGrade(record);
    const entry = {
      schema_version: 1,
      record_kind: 'EVENT',
      canonical_event_type: canonicalEventType(record),
      source_event_type: sourceEventType(record),
      source_record_id: recordId(record),
      replay_sha256: this.scope.replay_sha256,
      exact_build: this.scope.exact_build,
      replay_time_ms: time.replay_time_ms,
      timestamp_source_field: time.timestamp_source_field,
      state_entity: null,
      entity_references: entityReferencesFromRecord(record),
      state_fields: {},
      evidence: recordEvidence(record, grade),
      original_record: clone(record),
      sequence: this.nextSequence,
      timeline_id: null,
    };
    this.nextSequence += 1;
    entry.timeline_id = timelineId(entry);
    this.timeline.push(entry);
    return clone(entry);
  }

  ingestStateUpdate(record, explicitType = null) {
    assertPlainObject(record, 'state update');
    assertJsonValue(record, '$state_update');
    this.assertRecordScope(record);
    const kind = stateEventType(record, explicitType);
    if (kind === null) throw new Error('state update type must be STATE_UPDATE or VERIFIED_DERIVED_STATE');
    const grade = explicitEvidenceGrade(record);
    validateStateEvidence(kind, grade);
    const time = timestampFromRecord(record, true);
    const entity = entityDescriptorFromRecord(record);
    const fields = normalizeStateFields(record, kind, grade);
    const entry = {
      schema_version: 1,
      record_kind: kind,
      canonical_event_type: kind,
      source_event_type: sourceEventType(record),
      source_record_id: recordId(record),
      replay_sha256: this.scope.replay_sha256,
      exact_build: this.scope.exact_build,
      replay_time_ms: time.replay_time_ms,
      timestamp_source_field: time.timestamp_source_field,
      state_entity: entity,
      entity_references: entityReferencesFromRecord(record, entity),
      state_fields: fields,
      evidence: recordEvidence(record, grade),
      original_record: clone(record),
      sequence: this.nextSequence,
      timeline_id: null,
    };
    this.nextSequence += 1;
    entry.timeline_id = timelineId(entry);
    this.timeline.push(entry);
    return clone(entry);
  }

  ingestMany(records) {
    if (!Array.isArray(records)) throw new TypeError('records must be an array');
    return records.map((record) => this.ingest(record));
  }

  queryTimeline(options = {}) {
    assertPlainObject(options, 'query options');
    this.assertQueryScope(options);
    const hasFrom = options.from_ms !== null && options.from_ms !== undefined;
    const hasTo = options.to_ms !== null && options.to_ms !== undefined;
    const from = hasFrom ? assertQueryTime(options.from_ms, 'from_ms') : Number.NEGATIVE_INFINITY;
    const to = hasTo ? assertQueryTime(options.to_ms, 'to_ms') : Number.POSITIVE_INFINITY;
    if (from > to) throw new Error('from_ms must not exceed to_ms');
    const typeFilter = options.event_types !== undefined || options.event_type !== undefined
      ? normalizedFilterValues(options.event_types ?? options.event_type) : null;
    const kindFilter = options.record_kinds !== undefined || options.record_kind !== undefined
      ? normalizedFilterValues(options.record_kinds ?? options.record_kind) : null;
    return this.timeline
      .filter((entry) => {
        if (entry.replay_time_ms === null) {
          if (hasFrom || hasTo || options.include_untimed === false) return false;
        } else if (entry.replay_time_ms < from || entry.replay_time_ms > to) return false;
        if (typeFilter && !typeFilter.has(entry.canonical_event_type)
            && !typeFilter.has(String(entry.source_event_type ?? '').toUpperCase())) return false;
        if (kindFilter && !kindFilter.has(entry.record_kind)) return false;
        return matchesEntitySelector(entry, options);
      })
      .sort(compareTimeline)
      .map(clone);
  }

  queryCombatTimeline(options = {}) {
    const rows = this.queryTimeline(options).filter(isCombatEntry);
    return options.include_state_updates === false
      ? rows.filter((entry) => !STATE_EVENT_TYPES.includes(entry.record_kind))
      : rows;
  }

  stateAt(replayTimeMs, options = {}) {
    const atMs = assertQueryTime(replayTimeMs, 'replayTimeMs');
    assertPlainObject(options, 'state options');
    this.assertQueryScope(options);
    const states = new Map();
    const updates = this.timeline
      .filter((entry) => STATE_EVENT_TYPES.includes(entry.record_kind)
        && entry.replay_time_ms !== null && entry.replay_time_ms <= atMs
        && matchesEntitySelector(entry, options))
      .sort(compareTimeline);
    for (const update of updates) {
      const key = update.state_entity.entity_key;
      if (!states.has(key)) {
        states.set(key, {
          entity_key: key,
          entity: clone(update.state_entity),
          fields: {},
          last_observed_at_ms: null,
        });
      }
      const state = states.get(key);
      for (const [name, value] of Object.entries(update.state_entity)) {
        if (value !== null && value !== undefined) state.entity[name] = clone(value);
      }
      state.last_observed_at_ms = update.replay_time_ms;
      for (const [fieldName, field] of Object.entries(update.state_fields)) {
        state.fields[fieldName] = {
          value: clone(field.value),
          observed_at_ms: update.replay_time_ms,
          state_event_type: update.record_kind,
          evidence_grade: field.evidence_grade,
          source_timeline_id: update.timeline_id,
          provenance: {
            replay_sha256: update.replay_sha256,
            exact_build: update.exact_build,
            source_record_id: update.source_record_id,
            timestamp_source_field: update.timestamp_source_field,
            record_evidence: clone(update.evidence),
            field_evidence: clone(field.field_evidence),
            field_confidence: clone(field.field_confidence),
            field_provenance: clone(field.field_provenance),
          },
        };
      }
    }
    const entities = [...states.values()]
      .sort((left, right) => left.entity_key.localeCompare(right.entity_key))
      .map((state) => {
        const fields = Object.fromEntries(Object.entries(state.fields)
          .sort(([left], [right]) => left.localeCompare(right)));
        return {
          ...state,
          observed_fields: Object.keys(fields),
          values: Object.fromEntries(Object.entries(fields).map(([name, field]) => [name, clone(field.value)])),
          fields,
        };
      });
    return {
      schema: STATE_SNAPSHOT_SCHEMA,
      schema_version: 1,
      replay_sha256: this.scope.replay_sha256,
      exact_build: this.scope.exact_build,
      at_ms: atMs,
      entity_count: entities.length,
      entities,
    };
  }

  toJSON() {
    return {
      schema: STATE_ENGINE_SCHEMA,
      schema_version: this.schema_version,
      replay_sha256: this.scope.replay_sha256,
      exact_build: this.scope.exact_build,
      timeline_event_count: this.timeline.length,
      state_update_count: this.timeline.filter((entry) => STATE_EVENT_TYPES.includes(entry.record_kind)).length,
      unknown_event_count: this.timeline.filter((entry) => entry.canonical_event_type === 'UNKNOWN').length,
      timeline: this.queryTimeline(),
    };
  }
}

function stateUpdateFromGroundTruthFrame(anchor) {
  assertPlainObject(anchor, 'ground-truth frame');
  if (anchor.anchor_type !== 'GROUND_TRUTH_FRAME_SNAPSHOT') {
    throw new Error('ground-truth frame requires GROUND_TRUTH_FRAME_SNAPSHOT anchor_type');
  }
  const state = {};
  const fieldEvidence = {};
  for (const field of ['level', 'current_hp', 'max_hp', 'armor', 'magic_resist']) {
    if (!hasOwn(anchor, field)) continue;
    state[field] = clone(anchor[field]);
    fieldEvidence[field] = {
      evidence_grade: 'GROUND_TRUTH_FRAME_SNAPSHOT',
      json_path: anchor.source?.field_json_paths?.[field] ?? null,
      source_key: anchor.source?.field_keys?.[field] ?? field,
    };
  }
  if (Object.keys(state).length === 0) throw new Error('ground-truth frame has no observed P0 state fields');
  return {
    event_type: STATE_UPDATE,
    replay_sha256: anchor.replay_sha256,
    exact_build: anchor.replay_build ?? anchor.exact_build,
    replay_time_ms: anchor.timestamp_ms,
    entity: clone(anchor.entity),
    participant_id: anchor.participant_id ?? anchor.entity?.participant_id ?? null,
    champion: anchor.champion ?? anchor.entity?.champion ?? null,
    team_id: anchor.entity?.team_id ?? null,
    state,
    evidence_grade: 'GROUND_TRUTH_FRAME_SNAPSHOT',
    field_evidence: fieldEvidence,
    source_record_id: anchor.anchor_id ?? null,
    source: clone(anchor.source ?? null),
    upstream_anchor: {
      schema_version: anchor.schema_version ?? null,
      anchor_type: anchor.anchor_type,
      anchor_id: anchor.anchor_id ?? null,
      semantic_scope: anchor.semantic_scope ?? null,
      health_state: anchor.health_state ?? null,
      frame_boundary_evidence: clone(anchor.frame_boundary_evidence ?? null),
    },
  };
}

module.exports = {
  COMBAT_EVENT_TYPES,
  COMBAT_STATE_FIELDS,
  EVENT_TYPE_ALIASES,
  STATE_ENGINE_SCHEMA,
  STATE_EVENT_TYPES,
  STATE_SNAPSHOT_SCHEMA,
  STATE_UPDATE,
  VERIFIED_DERIVED_STATE,
  SemanticStateEngine,
  exactScopeFromRecord,
  stateUpdateFromGroundTruthFrame,
};

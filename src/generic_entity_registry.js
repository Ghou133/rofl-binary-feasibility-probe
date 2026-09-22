'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const ENTITY_EVENT_TYPES = Object.freeze([
  'ENTITY_SPAWN',
  'ENTITY_UPDATE',
  'ENTITY_DEATH',
  'ENTITY_DESTROY',
  'ENTITY_DESPAWN',
]);

const SOURCE_EVENT_TYPE_MAP = Object.freeze({
  entity_spawn: 'ENTITY_SPAWN',
  route_entity_spawn: 'ENTITY_SPAWN',
  ward_spawn: 'ENTITY_SPAWN',
  entity_update: 'ENTITY_UPDATE',
  entity_death: 'ENTITY_DEATH',
  death: 'ENTITY_DEATH',
  entity_destroy: 'ENTITY_DESTROY',
  entity_despawn: 'ENTITY_DESPAWN',
  ward_despawn: 'ENTITY_DESPAWN',
  ward_lifecycle_end: 'ENTITY_DESPAWN',
});

const ENTITY_ID_FIELDS = Object.freeze([
  'entity_id',
  'entity_network_id',
  'network_id',
  'ward_network_id',
  'victim_network_id',
  'target_network_id',
]);

function valueOrNull(value) {
  return value === undefined ? null : value;
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

function compareIds(left, right) {
  const leftNumber = Number(left);
  const rightNumber = Number(right);
  if (Number.isSafeInteger(leftNumber) && Number.isSafeInteger(rightNumber) && leftNumber !== rightNumber) {
    return leftNumber - rightNumber;
  }
  return String(left).localeCompare(String(right));
}

function uniqueSorted(values) {
  return [...new Set(values.filter((value) => value !== null && value !== undefined))]
    .sort(compareIds);
}

function eventTime(record) {
  const value = record.replay_time_ms ?? record.timestamp_ms ?? record.spawn_time_ms
    ?? record.ward_spawn_time_ms ?? record.death_time_ms ?? record.destroy_time_ms
    ?? record.despawn_time_ms ?? record.ward_disappear_time_ms ?? null;
  return Number.isFinite(value) ? value : null;
}

function canonicalEventType(record, explicitType) {
  const candidate = explicitType ?? record.canonical_event_type ?? record.event_type;
  if (ENTITY_EVENT_TYPES.includes(candidate)) return candidate;
  const mapped = SOURCE_EVENT_TYPE_MAP[String(candidate || '').toLowerCase()];
  if (mapped) return mapped;
  throw new Error(`Unsupported entity lifecycle event type: ${candidate}`);
}

function entityIds(record) {
  const aliases = [
    ...ENTITY_ID_FIELDS.map((field) => record[field]),
    ...(Array.isArray(record.network_ids) ? record.network_ids : []),
    ...(Array.isArray(record.aliases) ? record.aliases : []),
  ];
  return uniqueSorted(aliases);
}

function entityIdFromRecord(record) {
  for (const field of ENTITY_ID_FIELDS) {
    if (record[field] !== null && record[field] !== undefined) return record[field];
  }
  const ids = entityIds(record);
  return ids[0] ?? null;
}

function positionFromRecord(record) {
  const position = record.position;
  if (position && typeof position === 'object') {
    const x = valueOrNull(position.x);
    const y = valueOrNull(position.y);
    const z = valueOrNull(position.z);
    const height = valueOrNull(position.height);
    if ([x, y, z, height].some((value) => value !== null)) return { x, y, z, height };
  }
  const x = valueOrNull(record.x ?? record.ward_exact_x);
  const y = valueOrNull(record.y ?? record.ward_exact_y);
  const z = valueOrNull(record.z);
  const height = valueOrNull(record.height ?? record.ward_height);
  return [x, y, z, height].some((value) => value !== null) ? { x, y, z, height } : null;
}

function nameValues(record) {
  return uniqueSorted([
    record.name,
    record.entity_name,
    record.ward_entity_name,
    record.generic_name,
    record.template,
    record.archetype,
    record.name_hash,
  ]);
}

function fieldEvidence(record) {
  return {
    confidence: record.confidence ?? 'UNVERIFIED',
    semantic_status: valueOrNull(record.semantic_status),
    field_confidence: record.field_confidence ?? null,
    raw_packet_ref: record.raw_packet_ref ?? null,
    raw_packet_refs: record.raw_packet_refs ?? null,
  };
}

function firstSharedValue(values) {
  const unique = [...new Set(values.filter((value) => value !== null && value !== undefined))];
  return unique.length === 1 ? unique[0] : null;
}

function replayShaFromRecord(record) {
  return firstSharedValue([
    record.replay_sha256,
    record.raw_packet_ref?.replay_sha256,
    ...(Array.isArray(record.raw_packet_refs)
      ? record.raw_packet_refs.map((reference) => reference?.replay_sha256)
      : []),
  ]);
}

function exactBuildFromRecord(record) {
  return record.game_version ?? record.replay_version ?? record.build_profile ?? record.decoder_profile ?? null;
}

function entityScopeFromRecord(record) {
  const replaySha256 = replayShaFromRecord(record);
  const exactBuild = exactBuildFromRecord(record);
  if (replaySha256 !== null && exactBuild !== null) {
    return {
      key: `replay:${replaySha256}|build:${exactBuild}`,
      replay_sha256: replaySha256,
      exact_build: exactBuild,
      provenance_status: 'EXACT_REPLAY_AND_BUILD',
    };
  }
  // Missing identity must never merge entities merely because numeric network IDs match.
  const fallback = crypto.createHash('sha256').update(stableStringify(record)).digest('hex').slice(0, 24);
  return {
    key: `unscoped:${fallback}`,
    replay_sha256: replaySha256,
    exact_build: exactBuild,
    provenance_status: 'UNVERIFIED_PROVENANCE_ISOLATED',
  };
}

function entityScopeFromQuery(options) {
  const replaySha256 = replayShaFromRecord(options);
  const exactBuild = exactBuildFromRecord(options);
  if (replaySha256 === null || exactBuild === null) return null;
  return `replay:${replaySha256}|build:${exactBuild}`;
}

function hasProvenanceSelector(options) {
  return replayShaFromRecord(options) !== null || exactBuildFromRecord(options) !== null;
}

function recordFingerprint(event) {
  return crypto.createHash('sha256').update(stableStringify({
    canonical_event_type: event.event_type,
    entity_id: event.entity_id,
    entity_scope: event.entity_scope,
    network_ids: event.network_ids,
    replay_time_ms: event.replay_time_ms,
    position: event.position,
    source_event_type: event.source_event_type,
    raw_packet_ref: event.evidence.raw_packet_ref,
  })).digest('hex').slice(0, 24);
}

function newEntity(entityId, scope) {
  return {
    entity_id: entityId,
    entity_network_id: entityId,
    entity_scope: scope.key,
    replay_sha256: scope.replay_sha256,
    exact_build: scope.exact_build,
    provenance_status: scope.provenance_status,
    network_ids: [entityId],
    entity_type: 'UNKNOWN_ENTITY',
    entity_subtype: null,
    owner_network_id: null,
    owner_entity_id: null,
    team_id: null,
    spawn_time_ms: null,
    last_update_time_ms: null,
    death_time_ms: null,
    destroy_time_ms: null,
    despawn_time_ms: null,
    positions: [],
    names: [],
    builds: [],
    evidence: [],
  };
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

class GenericEntityRegistry {
  constructor(options = {}) {
    this.schema_version = 1;
    this.registry_version = options.registry_version ?? 'GENERIC_ENTITY_REGISTRY_V1';
    this.entities = new Map();
    this.aliases = new Map();
    this.aliasKeys = new Map();
    this.events = [];
  }

  resolveEntityKey(id, scopeKey = null) {
    if (id === null || id === undefined) return null;
    if (scopeKey !== null) return this.aliases.get(`${scopeKey}|${String(id)}`) ?? null;
    const matches = this.aliasKeys.get(String(id));
    return matches?.size === 1 ? [...matches][0] : null;
  }

  validateRecord(record, explicitType) {
    if (!record || typeof record !== 'object' || Array.isArray(record)) {
      throw new TypeError('entity record must be an object');
    }
    const entityId = entityIdFromRecord(record);
    if (entityId === null || entityId === undefined) {
      throw new Error('entity record requires entity_id, entity_network_id, network_id, ward_network_id, victim_network_id, or target_network_id');
    }
    return { entity_id: entityId, event_type: canonicalEventType(record, explicitType) };
  }

  ingest(record, explicitType) {
    const validated = this.validateRecord(record, explicitType);
    const scope = entityScopeFromRecord(record);
    const aliases = entityIds(record);
    const entityKey = aliases.map((id) => this.resolveEntityKey(id, scope.key)).find(Boolean)
      ?? `${scope.key}|entity:${String(validated.entity_id)}`;
    let entity = this.entities.get(entityKey);
    if (!entity) {
      entity = newEntity(validated.entity_id, scope);
      this.entities.set(entityKey, entity);
    }

    const allAliases = uniqueSorted([...entity.network_ids, ...aliases, entity.entity_id]);
    entity.network_ids = allAliases;
    for (const alias of allAliases) {
      this.aliases.set(`${scope.key}|${String(alias)}`, entityKey);
      if (!this.aliasKeys.has(String(alias))) this.aliasKeys.set(String(alias), new Set());
      this.aliasKeys.get(String(alias)).add(entityKey);
    }

    // Types are only accepted when the supplied semantic record names them directly.
    if (record.entity_type !== null && record.entity_type !== undefined) entity.entity_type = record.entity_type;
    if (record.entity_subtype !== null && record.entity_subtype !== undefined) {
      entity.entity_subtype = record.entity_subtype;
    }
    const owner = record.owner_network_id ?? record.owner_entity ?? record.owner_entity_id ?? null;
    if (owner !== null) {
      entity.owner_network_id = owner;
      entity.owner_entity_id = owner;
    }
    const team = record.team_id ?? record.owner_team ?? record.team ?? null;
    if (team !== null) entity.team_id = team;

    const time = eventTime(record);
    if (validated.event_type === 'ENTITY_SPAWN' && entity.spawn_time_ms === null) entity.spawn_time_ms = time;
    if (validated.event_type === 'ENTITY_UPDATE') entity.last_update_time_ms = time;
    if (validated.event_type === 'ENTITY_DEATH') entity.death_time_ms = time;
    if (validated.event_type === 'ENTITY_DESTROY') entity.destroy_time_ms = time;
    if (validated.event_type === 'ENTITY_DESPAWN') entity.despawn_time_ms = time;

    const position = positionFromRecord(record);
    if (position) {
      const observation = { replay_time_ms: time, ...position };
      const key = stableStringify(observation);
      if (!entity.positions.some((item) => stableStringify(item) === key)) entity.positions.push(observation);
      entity.positions.sort((left, right) => (left.replay_time_ms ?? -1) - (right.replay_time_ms ?? -1)
        || stableStringify(left).localeCompare(stableStringify(right)));
    }
    entity.names = uniqueSorted([...entity.names, ...nameValues(record)]);
    const build = {
      game_version: record.game_version ?? record.replay_version ?? null,
      patch: record.patch ?? null,
      build_profile: record.build_profile ?? record.decoder_profile ?? null,
    };
    if (Object.values(build).some((value) => value !== null)) {
      if (!entity.builds.some((item) => stableStringify(item) === stableStringify(build))) entity.builds.push(build);
      entity.builds.sort((left, right) => stableStringify(left).localeCompare(stableStringify(right)));
    }
    const evidence = fieldEvidence(record);
    if (!entity.evidence.some((item) => stableStringify(item) === stableStringify(evidence))) {
      entity.evidence.push(evidence);
      entity.evidence.sort((left, right) => stableStringify(left).localeCompare(stableStringify(right)));
    }

    const event = {
      schema_version: 1,
      event_type: validated.event_type,
      source_event_type: record.event_type ?? null,
      entity_id: entity.entity_id,
      entity_network_id: entity.entity_id,
      entity_scope: scope.key,
      replay_sha256: scope.replay_sha256,
      exact_build: scope.exact_build,
      provenance_status: scope.provenance_status,
      network_ids: allAliases,
      replay_time_ms: time,
      position,
      evidence,
      event_id: null,
    };
    event.event_id = `entity-event:${recordFingerprint(event)}`;
    this.events.push(event);
    return clone(event);
  }

  ingestMany(records, explicitType) {
    if (!Array.isArray(records)) throw new TypeError('records must be an array');
    return records.map((record) => this.ingest(record, explicitType));
  }

  ingestLifecycle(record) {
    if (!record || typeof record !== 'object') throw new TypeError('lifecycle record must be an object');
    const start = { ...record, event_type: 'ENTITY_SPAWN', replay_time_ms: record.spawn_time_ms ?? record.ward_spawn_time_ms };
    const events = [this.ingest(start, 'ENTITY_SPAWN')];
    const endTime = record.despawn_time_ms ?? record.ward_disappear_time_ms ?? record.destroy_time_ms
      ?? record.death_time_ms ?? null;
    if (endTime !== null && endTime !== undefined) {
      events.push(this.ingest({ ...record, event_type: 'ENTITY_DESPAWN', replay_time_ms: endTime }, 'ENTITY_DESPAWN'));
    }
    return events;
  }

  get(entityId, options = {}) {
    const scopeKey = entityScopeFromQuery(options);
    if (scopeKey === null && hasProvenanceSelector(options)) return null;
    const entity = this.entities.get(this.resolveEntityKey(entityId, scopeKey));
    return entity ? clone(entity) : null;
  }

  query(options = {}) {
    const entityId = options.entity_id ?? options.entity_network_id ?? options.network_id;
    const scopeKey = entityScopeFromQuery(options);
    if (scopeKey === null && hasProvenanceSelector(options)) return [];
    const entityKey = entityId === undefined ? null : this.resolveEntityKey(entityId, scopeKey);
    const selectedEntity = entityKey === null ? null : this.entities.get(entityKey);
    const from = options.from_ms ?? options.start_ms ?? -Infinity;
    const to = options.to_ms ?? options.end_ms ?? Infinity;
    const eventType = options.event_type ?? null;
    return this.events
      .filter((event) => (scopeKey === null || event.entity_scope === scopeKey)
        && (entityId === undefined || (selectedEntity !== null
          && event.entity_scope === selectedEntity.entity_scope
          && event.entity_id === selectedEntity.entity_id))
        && (eventType === null || event.event_type === eventType)
        && (event.replay_time_ms === null || (event.replay_time_ms >= from && event.replay_time_ms <= to)))
        .sort((left, right) => left.entity_scope.localeCompare(right.entity_scope)
          || (left.replay_time_ms ?? -1) - (right.replay_time_ms ?? -1)
        || left.event_type.localeCompare(right.event_type)
        || compareIds(left.entity_id, right.entity_id)
        || left.event_id.localeCompare(right.event_id))
      .map(clone);
  }

  toJSON() {
    return {
      schema_version: this.schema_version,
      registry_version: this.registry_version,
      entity_count: this.entities.size,
      event_count: this.events.length,
      entities: [...this.entities.values()]
        .sort((left, right) => left.entity_scope.localeCompare(right.entity_scope)
          || compareIds(left.entity_id, right.entity_id))
        .map(clone),
      events: this.query(),
    };
  }
}

function writeEntityRegistry(outputPath, registry) {
  if (!(registry instanceof GenericEntityRegistry)) {
    throw new TypeError('registry must be a GenericEntityRegistry');
  }
  const resolved = path.resolve(outputPath);
  fs.mkdirSync(path.dirname(resolved), { recursive: true });
  fs.writeFileSync(resolved, `${JSON.stringify(registry.toJSON(), null, 2)}\n`);
  return resolved;
}

module.exports = {
  ENTITY_EVENT_TYPES,
  GenericEntityRegistry,
  SOURCE_EVENT_TYPE_MAP,
  canonicalEventType,
  entityScopeFromRecord,
  stableStringify,
  writeEntityRegistry,
};

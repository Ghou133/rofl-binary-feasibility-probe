'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { BUILD_PROFILES, resolveBuildProfile } = require('./build_registry');
const { formatOpcode, parseReplayFile, walkBlocks } = require('./rofl');

const INVENTORY_SCHEMA_VERSION = 'PACKET_COVERAGE_INVENTORY_V1';
const ANALYZER_VERSION = 'packet-coverage-inventory-v1';

function strictCompare(left, right) {
  const a = String(left);
  const b = String(right);
  return a < b ? -1 : a > b ? 1 : 0;
}

const CAPABILITY_CATEGORIES = Object.freeze({
  hero_path: 'MOVEMENT',
  level_transition: 'ENTITY_STATE',
  ward_spawn: 'VISION',
  hero_damage: 'COMBAT',
  hero_death: 'COMBAT',
  cast_spell: 'SPELL',
  buff_add: 'BUFF',
  buff_remove: 'BUFF',
  buff_update_count: 'BUFF',
  protection: 'COMBAT',
  shield_damage: 'COMBAT',
  ability_cooldown_broadcast: 'SPELL',
  instant_stop_attack: 'COMBAT',
  face_direction_vector: 'ENTITY_STATE',
  basic_attack_position_minion: 'COMBAT',
  hero_reincarnate_alive: 'ENTITY_STATE',
  wall_tracking_component_cache_snapshot: 'ENTITY_STATE',
  missile_movement_complete_count: 'MISSILE',
});

function numericPacketId(value) {
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= 0xffff) {
    return value;
  }
  if (typeof value === 'string' && /^(?:0x)?[0-9a-f]+$/i.test(value)) {
    const parsed = Number.parseInt(value, 16);
    if (Number.isSafeInteger(parsed) && parsed >= 0 && parsed <= 0xffff) return parsed;
  }
  throw new TypeError(`packet_id must be an unsigned 16-bit integer; got ${String(value)}`);
}

function optionalNonNegativeInteger(value, name) {
  if (value === null || value === undefined || value === '') return null;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new TypeError(`${name} must be a non-negative integer when supplied`);
  }
  return parsed;
}

function optionalTimestamp(value) {
  if (value === null || value === undefined || value === '') return null;
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) throw new TypeError('replay_time_ms must be finite when supplied');
  return Math.round(parsed);
}

function canonicalRecord(record, provenance = {}) {
  if (!record || typeof record !== 'object') throw new TypeError('packet record must be an object');
  const gameVersion = record.game_version ?? record.replay_version ?? record.build;
  if (typeof gameVersion !== 'string' || gameVersion.length === 0) {
    throw new TypeError('packet record requires exact game_version, replay_version, or build');
  }
  const packetId = numericPacketId(record.packet_id ?? record.packet_discriminator);
  const recordSource = record.source && typeof record.source === 'object' ? record.source : {};
  return {
    game_version: gameVersion,
    packet_id: packetId,
    payload_length: optionalNonNegativeInteger(record.payload_length ?? record.packet_length, 'payload_length'),
    raw_param: optionalNonNegativeInteger(record.raw_param ?? record.param, 'raw_param'),
    replay_time_ms: optionalTimestamp(record.replay_time_ms ?? record.timestamp_ms),
    chunk_stream: record.chunk_stream ?? record.stream ?? null,
    source: {
      source_kind: provenance.source_kind ?? record.source_kind ?? recordSource.source_kind
        ?? 'EXPORTED_PACKET_RECORD',
      source_path: provenance.source_path ?? record.replay_path ?? record.source_path
        ?? recordSource.source_path ?? null,
      replay_sha256: provenance.replay_sha256 ?? record.replay_sha256 ?? recordSource.replay_sha256 ?? null,
      record_source_sha256: provenance.record_source_sha256 ?? record.record_source_sha256
        ?? recordSource.record_source_sha256 ?? null,
    },
  };
}

function recordsFromReplayFile(replayPath, options = {}) {
  const replay = parseReplayFile(replayPath);
  const includeStreams = new Set(options.includeStreams ?? [1, 2, 3]);
  const records = [];
  const walk = walkBlocks(replay, (block, chunk) => {
    records.push(canonicalRecord({
      game_version: replay.header.version,
      packet_id: block.packet_id,
      payload_length: block.payload_length,
      raw_param: block.param,
      replay_time_ms: block.timestamp_ms,
      chunk_stream: chunk.stream,
    }, {
      source_kind: 'RAW_ROFL',
      source_path: replay.source_path,
      replay_sha256: replay.source_sha256,
    }));
  }, { includeStreams: [...includeStreams], strict: options.strict !== false });
  if (walk.errors.length > 0) {
    throw new Error(`Replay walk failed for ${replay.source_path}: ${walk.errors.length} framing error(s)`);
  }
  return records;
}

function recordsFromExport(records, provenance = {}) {
  if (!Array.isArray(records)) throw new TypeError('exported packet records must be an array');
  return records.map((record) => canonicalRecord(record, {
    source_kind: provenance.source_kind,
    source_path: provenance.source_path,
    record_source_sha256: provenance.record_source_sha256,
  }));
}

function routeStatus(buildProfile, capability) {
  const semantic = buildProfile?.field_semantics?.[capability] ?? null;
  if (semantic === 'CANDIDATE') return 'CANDIDATE';
  if (semantic === 'UNAVAILABLE' || semantic === 'UNVERIFIED') return semantic;
  if (buildProfile?.candidate_capabilities?.includes(capability)) return 'CANDIDATE';
  if (buildProfile?.unverified_capabilities?.includes(capability)) return 'UNVERIFIED';
  if (buildProfile?.unsupported_capabilities?.includes(capability)) return 'UNAVAILABLE';
  return semantic ?? 'REGISTERED_ROUTE_STATUS_UNSPECIFIED';
}

function registeredDecoders(gameVersion, packetId) {
  const resolved = resolveBuildProfile(gameVersion);
  if (!resolved.profile) return [{
    capability: null,
    status: 'UNSUPPORTED_BUILD_RAW_ONLY',
    possible_category: 'UNKNOWN',
  }];
  return Object.entries(resolved.profile.packet_routes)
    .filter(([, route]) => route === packetId)
    .map(([capability]) => ({
      capability,
      status: routeStatus(resolved.profile, capability),
      possible_category: CAPABILITY_CATEGORIES[capability] ?? 'UNKNOWN',
    }))
    .sort((left, right) => strictCompare(left.capability, right.capability));
}

function candidatePriority(observedCount) {
  if (observedCount >= 10000) return 'P0_HIGH_FREQUENCY_UNKNOWN_PACKET_CANDIDATE';
  if (observedCount >= 100) return 'P1_RECURRING_UNKNOWN_PACKET_CANDIDATE';
  return 'P2_LOW_FREQUENCY_UNKNOWN_PACKET_CANDIDATE';
}

function categoryAndConfidence(gameVersion, packetId, observedCount = 0) {
  const decodedAs = registeredDecoders(gameVersion, packetId);
  const known = decodedAs.filter((entry) => entry.capability !== null);
  if (known.length === 0) {
    return {
      currently_decoded_as_status: decodedAs[0]?.status ?? 'UNREGISTERED_EXACT_BUILD_RAW_ONLY',
      decoded_as: decodedAs.length > 0 ? decodedAs : [{
        capability: null,
        status: 'UNREGISTERED_EXACT_BUILD_RAW_ONLY',
        possible_category: 'UNKNOWN',
      }],
      possible_category: 'UNKNOWN',
      confidence: 'CANDIDATE',
      research_priority: candidatePriority(observedCount),
    };
  }
  const statuses = known.map((entry) => entry.status);
  const hasCandidate = statuses.includes('CANDIDATE');
  const hasUnavailable = statuses.includes('UNAVAILABLE') || statuses.includes('UNVERIFIED');
  const categories = [...new Set(known.map((entry) => entry.possible_category))].sort();
  return {
    currently_decoded_as_status: hasCandidate
      ? 'CANDIDATE_ROUTE_REGISTERED'
      : hasUnavailable ? 'REGISTERED_BUT_NOT_AVAILABLE' : 'EXACT_BUILD_ROUTE_REGISTERED',
    decoded_as: known,
    possible_category: categories.length === 1 ? categories[0] : 'MULTIPLE_REGISTERED_CATEGORIES',
    confidence: hasCandidate ? 'CANDIDATE' : hasUnavailable ? 'UNVERIFIED' : 'VERIFIED_DIRECT',
    research_priority: hasCandidate ? 'P0_VALIDATE_CANDIDATE_ROUTE' : 'P3_REGRESSION_MONITOR',
  };
}

function entityCandidate(params) {
  const observed = [...params].sort((left, right) => left - right);
  if (observed.length === 0) return {
    status: 'UNKNOWN',
    kind: 'RAW_PARAM_NOT_AVAILABLE',
    observed_distinct_raw_params: 0,
  };
  const nonzero = observed.filter((value) => value !== 0);
  if (nonzero.length === 0) return {
    status: 'UNKNOWN',
    kind: 'RAW_PARAM_ZERO_ONLY',
    observed_distinct_raw_params: observed.length,
  };
  const championRange = nonzero.every((value) => value >= 0x400000ae && value <= 0x400000b7);
  return {
    status: 'CANDIDATE',
    kind: championRange
      ? 'CHAMPION_NETWORK_ID_RANGE_CANDIDATE'
      : 'RAW_PARAM_MAY_BE_ENTITY_OR_EVENT_KEY',
    observed_distinct_raw_params: observed.length,
    observed_nonzero_raw_params: nonzero.length,
  };
}

function temporalBehavior(times, count) {
  if (times.length === 0) return {
    status: 'UNKNOWN',
    pattern: 'REPLAY_TIME_NOT_AVAILABLE',
    first_observed_time_ms: null,
    last_observed_time_ms: null,
  };
  const sorted = [...times].sort((left, right) => left - right);
  const first = sorted[0];
  const last = sorted.at(-1);
  return {
    status: 'CANDIDATE',
    pattern: last <= 5000
      ? 'STARTUP_CONCENTRATED_CANDIDATE'
      : count === 1 ? 'SINGLE_OCCURRENCE_CANDIDATE' : 'RECURRING_CANDIDATE',
    first_observed_time_ms: first,
    last_observed_time_ms: last,
  };
}

function payloadSizeDistribution(sizes) {
  const counts = new Map();
  for (const size of sizes) counts.set(size, (counts.get(size) ?? 0) + 1);
  return [...counts.entries()]
    .map(([payload_length, count]) => ({ payload_length, count }))
    .sort((left, right) => left.payload_length - right.payload_length);
}

function uniqueProvenance(records) {
  const seen = new Map();
  for (const record of records) {
    const value = record.source;
    const key = JSON.stringify(value);
    seen.set(key, value);
  }
  return [...seen.values()].sort((left, right) => (
    strictCompare(left.source_path ?? '', right.source_path ?? '')
    || strictCompare(left.replay_sha256 ?? '', right.replay_sha256 ?? '')
    || strictCompare(left.record_source_sha256 ?? '', right.record_source_sha256 ?? '')
  ));
}

function buildPacketCoverageInventory(input, options = {}) {
  const records = Array.isArray(input)
    ? recordsFromExport(input, options.recordProvenance)
    : input?.records
      ? recordsFromExport(input.records, input.provenance)
      : (() => { throw new TypeError('input must be packet records or { records, provenance }'); })();
  const groups = new Map();
  for (const record of records) {
    const key = `${record.game_version}:${record.packet_id}`;
    let group = groups.get(key);
    if (!group) {
      group = { game_version: record.game_version, packet_id: record.packet_id, records: [] };
      groups.set(key, group);
    }
    group.records.push(record);
  }
  const packets = [...groups.values()].map((group) => {
    const sizes = group.records.map((record) => record.payload_length).filter((value) => value !== null);
    const params = new Set(group.records.map((record) => record.raw_param).filter((value) => value !== null));
    const times = group.records.map((record) => record.replay_time_ms).filter((value) => value !== null);
    const semantic = categoryAndConfidence(group.game_version, group.packet_id, group.records.length);
    return {
      build: group.game_version,
      packet_id: group.packet_id,
      packet_discriminator: formatOpcode(group.packet_id),
      count: group.records.length,
      payload_size_distribution: payloadSizeDistribution(sizes),
      payload_size_observation_status: sizes.length === group.records.length
        ? 'OBSERVED_FOR_ALL_PACKETS' : 'PARTIAL_RAW_RECORDS',
      currently_decoded_as_status: semantic.currently_decoded_as_status,
      decoded_as: semantic.decoded_as,
      entity_candidate: entityCandidate(params),
      temporal_behavior: temporalBehavior(times, group.records.length),
      possible_category: semantic.possible_category,
      confidence: semantic.confidence,
      research_priority: semantic.research_priority,
      provenance: uniqueProvenance(group.records),
    };
  }).sort((left, right) => strictCompare(left.build, right.build)
    || left.packet_id - right.packet_id);
  const builds = [...new Set(records.map((record) => record.game_version))]
    .sort(strictCompare)
    .map((gameVersion) => ({
      game_version: gameVersion,
      build_profile_status: resolveBuildProfile(gameVersion).status,
      packet_type_count: packets.filter((packet) => packet.build === gameVersion).length,
      packet_count: packets.filter((packet) => packet.build === gameVersion)
        .reduce((sum, packet) => sum + packet.count, 0),
    }));
  return {
    schema_version: INVENTORY_SCHEMA_VERSION,
    analyzer_version: ANALYZER_VERSION,
    exact_build_policy: 'RAW_PACKET_ROWS_ARE_NEVER_MERGED_ACROSS_EXACT_GAME_VERSION',
    semantic_policy: 'REGISTERED_DECODERS_ARE_REPORTED_FROM_EXACT_BUILD_PROFILES_ONLY; UNREGISTERED_SEMANTICS_REMAIN_UNKNOWN_CANDIDATE',
    input_record_count: records.length,
    builds,
    packets,
  };
}

function inventoryFromReplayFiles(replayPaths, options = {}) {
  if (!Array.isArray(replayPaths) || replayPaths.length === 0) {
    throw new TypeError('at least one .rofl path is required');
  }
  const records = [...replayPaths]
    .map((filePath) => path.resolve(filePath))
    .sort(strictCompare)
    .flatMap((filePath) => recordsFromReplayFile(filePath, options));
  return buildPacketCoverageInventory(records);
}

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function knownBuildProfiles() {
  return Object.keys(BUILD_PROFILES).sort(strictCompare);
}

module.exports = {
  ANALYZER_VERSION,
  CAPABILITY_CATEGORIES,
  INVENTORY_SCHEMA_VERSION,
  buildPacketCoverageInventory,
  candidatePriority,
  canonicalRecord,
  entityCandidate,
  inventoryFromReplayFiles,
  knownBuildProfiles,
  numericPacketId,
  payloadSizeDistribution,
  recordsFromExport,
  recordsFromReplayFile,
  registeredDecoders,
  sha256File,
  strictCompare,
  temporalBehavior,
};

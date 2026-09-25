'use strict';

const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');
const { isDeepStrictEqual } = require('node:util');
const { CHAMPION_DIE_HERO_DEATH_PAIR_821_PROFILE } =
  require('./decoders/rofl_16_19_821_champion_die_hero_death_pair_candidate');
const { CHAMPION_KILL_DIE_HERO_DEATH_PAIR_821_PROFILE } =
  require('./decoders/rofl_16_19_821_champion_kill_die_hero_death_pair_candidate');
const { CHAMPION_MULTIPLE_KILL_DIE_HERO_DEATH_PAIR_821_PROFILE } =
  require('./decoders/rofl_16_19_821_champion_multiple_kill_die_hero_death_pair_candidate');
const { CHAMPION_DIE_EVENT_PACKET_821_PROFILE } =
  require('./decoders/rofl_16_19_821_champion_die_event_packet_candidate');
const { CHAMPION_KILL_EVENT_PACKET_CANDIDATE_PROFILE_821 } =
  require('./decoders/rofl_16_19_821_champion_kill_event_packet_candidate');
const { CHAMPION_MULTIPLE_KILL_EVENT_PACKET_821_PROFILE } =
  require('./decoders/rofl_16_19_821_champion_multiple_kill_event_packet_candidate');
const { HERO_DEATH_CANDIDATE_PROFILE_821 } =
  require('./decoders/rofl_16_19_821_7343');

const EVENT_KEY = /^[a-z][a-z0-9_]*_candidates$/;
const REPLAY_SHA = /^[a-f0-9]{64}$/;
const SUBJECT_PARTICIPANT_FIELDS = [
  'participant_id_candidate', 'participant_id',
  'victim_participant_id_candidate', 'victim_participant_id',
  'owner_participant_id_candidate', 'owner_participant_id',
  'target_participant_id',
];
const OPAQUE_U32_FIELDS_821 = Object.freeze({
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
  champion_die_hero_death_pair_candidates: Object.freeze([
    'on_champion_die_event_u32_0x04',
  ]),
  champion_kill_die_hero_death_pair_candidates: Object.freeze([
    'on_champion_kill_event_u32_0x04', 'on_champion_die_event_u32_0x04',
  ]),
  champion_multiple_kill_die_hero_death_pair_candidates: Object.freeze([
    'on_champion_multiple_kill_event_u32_0x04', 'on_champion_die_event_u32_0x04',
  ]),
});
const ASSOCIATION_EVENTS_821 = Object.freeze({
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

function isCount(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function prepareAssociation(semantic, analysis, eventKey, associationConfig) {
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

function prepareEventQuery(directory, eventKey) {
  if (typeof eventKey !== 'string' || !EVENT_KEY.test(eventKey)) {
    throw new EventQueryError('INVALID_EVENT_KEY',
      'The event key must be an exact lowercase *_candidates name.');
  }
  const artifactDirectory = path.resolve(directory);
  const semantic = readArtifactJson(artifactDirectory, 'semantic_run.json');
  const analysis = readArtifactJson(artifactDirectory, 'replay_analysis.json');
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
  const capability = eventKey.slice(0, -'_candidates'.length);
  const capabilityResult = associationConfig
    ? prepareAssociation(semantic, analysis, eventKey, associationConfig)
    : semantic.capability_results?.[capability];
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
  return {
    artifactDirectory, inputPath, eventKey, eventStorage, capability, capabilityStatus,
    capabilityResult, declaredCount, replaySha, associationConfig,
    replayVersion: semantic.replay_version, semanticRunStatus: semantic.status,
    semanticApiStatus: semantic.api_status ?? null,
  };
}

function subjectParticipant(row, lineNumber) {
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

function associationRow(row, prepared, lineNumber, seenKeys, seenPacketPositions) {
  const { associationConfig, capabilityResult, replaySha, replayVersion } = prepared;
  if (!associationConfig) return;
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

function stealthChildEventId(row, lineNumber) {
  const value = row.child_event_id;
  if (value == null) return { value: null, available: false };
  if (!Number.isSafeInteger(value) || ![0x0101, 0x0102].includes(value)) {
    throw new EventQueryError('INVALID_EVENT_ROW',
      `Invalid child_event_id at JSONL line ${lineNumber}.`, { line_number: lineNumber });
  }
  return { value, available: true };
}

function validateFilters(options) {
  const { fromMs = null, toMs = null, participant = null, rawParam = null,
    itemId = null, opaqueU32 = null, childEventId = null, limit = null } = options;
  for (const [name, value, minimum, maximum] of [
    ['fromMs', fromMs, 0, Number.MAX_SAFE_INTEGER],
    ['toMs', toMs, 0, Number.MAX_SAFE_INTEGER],
    ['participant', participant, 1, 10],
    ['rawParam', rawParam, 0, 0xffffffff],
    ['itemId', itemId, 0, 0xffffffff],
    ['opaqueU32', opaqueU32, 0, 0xffffffff],
    ['childEventId', childEventId, 0, 0xffffffff],
    ['limit', limit, 1, Number.MAX_SAFE_INTEGER],
  ]) {
    if (value != null && (!Number.isSafeInteger(value) || value < minimum || value > maximum)) {
      throw new EventQueryError('INVALID_FILTER', `Invalid ${name} query filter.`);
    }
  }
  if (fromMs != null && toMs != null && fromMs > toMs) {
    throw new EventQueryError('INVALID_FILTER', 'fromMs must not exceed toMs.');
  }
  if (childEventId != null && ![0x0101, 0x0102].includes(childEventId)) {
    throw new EventQueryError('INVALID_FILTER',
      'childEventId must be 0x0101 (OnEnterStealth) or 0x0102 (OnExitStealth).');
  }
}

async function streamEventQuery(prepared, options, emitLine) {
  validateFilters(options);
  const { fromMs = null, toMs = null, participant = null, rawParam = null,
    itemId = null, opaqueU32 = null, childEventId = null, limit = null } = options;
  const inventoryPacketEvent = [
    'hero_inventory_packet_candidates',
    'hero_inventory_broadcast_packet_candidates',
    'hero_inventory_set_item_packet_candidates',
  ].includes(prepared.eventKey);
  if (itemId != null && (!inventoryPacketEvent
      || prepared.replayVersion !== '16.19.821.7343')) {
    throw new EventQueryError('UNSUPPORTED_FILTER',
      '--item-id requires a 16.19.821.7343 inventory packet candidate event.');
  }
  const opaqueU32Fields = OPAQUE_U32_FIELDS_821[prepared.eventKey] ?? null;
  if (opaqueU32 != null && (!opaqueU32Fields
      || prepared.replayVersion !== '16.19.821.7343')) {
    throw new EventQueryError('UNSUPPORTED_FILTER',
      '--opaque-u32 requires an 821 ParamsHeal, ShieldingParams, stealth, OnChampionDie, OnChampionKill, OnChampionMultipleKill, or supported packet association candidate event.');
  }
  if (childEventId != null && (prepared.eventKey !== 'stealth_event_packet_candidates'
      || prepared.replayVersion !== '16.19.821.7343')) {
    throw new EventQueryError('UNSUPPORTED_FILTER',
      '--child-event-id requires a 16.19.821.7343 stealth packet candidate event.');
  }
  let scannedCount = 0;
  let matchedCount = 0;
  let emittedCount = 0;
  let participantUnavailableCount = 0;
  let rawParamUnavailableCount = 0;
  let itemIdUnavailableCount = 0;
  let itemIdAvailableCount = 0;
  let opaqueU32UnavailableCount = 0;
  let opaqueU32AvailableCount = 0;
  let childEventIdUnavailableCount = 0;
  let childEventIdAvailableCount = 0;
  const associationKeys = new Set();
  const associationPacketPositions = new Set();
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
      const subject = subjectParticipant(row, lineNumber);
      if (row.replay_sha256 !== prepared.replaySha
          || (row.raw_packet_ref != null
            && row.raw_packet_ref.replay_sha256 !== prepared.replaySha)
          || (row.raw_packet_refs != null && (!Array.isArray(row.raw_packet_refs)
            || row.raw_packet_refs.some((ref) => ref?.replay_sha256 !== prepared.replaySha)))) {
        throw new EventQueryError('ARTIFACT_IDENTITY_MISMATCH',
          `Event JSONL line ${lineNumber} has a different Replay SHA-256.`,
          { line_number: lineNumber });
      }
      associationRow(row, prepared, lineNumber, associationKeys,
        associationPacketPositions);
      const params = rawParam == null ? null : rawPacketParams(row, lineNumber);
      const items = itemId == null ? null
        : prepared.eventKey === 'hero_inventory_set_item_packet_candidates'
          ? packetScalarItemId(row, lineNumber)
          : packetRecordItemIds(row, lineNumber,
            prepared.eventKey === 'hero_inventory_broadcast_packet_candidates');
      const opaqueValues = opaqueU32 == null ? null
        : opaqueU32Values(row, lineNumber, opaqueU32Fields);
      const childId = childEventId == null ? null
        : stealthChildEventId(row, lineNumber);
      if (participant != null && subject.value == null) participantUnavailableCount += 1;
      if (rawParam != null && params.length === 0) rawParamUnavailableCount += 1;
      if (itemId != null && items.unavailable) itemIdUnavailableCount += 1;
      if (itemId != null && items.available) itemIdAvailableCount += 1;
      if (opaqueU32 != null && opaqueValues.unavailable) opaqueU32UnavailableCount += 1;
      if (opaqueU32 != null && opaqueValues.available) opaqueU32AvailableCount += 1;
      if (childEventId != null && !childId.available) childEventIdUnavailableCount += 1;
      if (childEventId != null && childId.available) childEventIdAvailableCount += 1;
      if ((fromMs != null && replayTime < fromMs)
          || (toMs != null && replayTime > toMs)
          || (participant != null && subject.value !== participant)
          || (rawParam != null && !params.includes(rawParam))
          || (itemId != null && !items.values.includes(itemId))
          || (opaqueU32 != null && !opaqueValues.values.includes(opaqueU32))
          || (childEventId != null && childId.value !== childEventId)) continue;
      matchedCount += 1;
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
  if (participant != null && scannedCount > 0 && participantUnavailableCount === scannedCount) {
    throw new EventQueryError('PARTICIPANT_UNAVAILABLE',
      'This event stream has no resolved subject participant for filtering.',
      { scanned_count: scannedCount, participant_unavailable_count: participantUnavailableCount,
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
  if (opaqueU32 != null && scannedCount > 0 && opaqueU32AvailableCount === 0) {
    throw new EventQueryError('OPAQUE_U32_UNAVAILABLE',
      'This event stream has no decoded anonymous u32 field for filtering.',
      { scanned_count: scannedCount,
        opaque_u32_unavailable_count: opaqueU32UnavailableCount,
        capability_status: prepared.capabilityStatus });
  }
  if (childEventId != null && scannedCount > 0 && childEventIdAvailableCount === 0) {
    throw new EventQueryError('CHILD_EVENT_ID_UNAVAILABLE',
      'This event stream has no decoded stealth child event ID for filtering.',
      { scanned_count: scannedCount,
        child_event_id_unavailable_count: childEventIdUnavailableCount,
        capability_status: prepared.capabilityStatus });
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
    participant_unavailable_count: participantUnavailableCount,
    ...(rawParam == null ? {} : { raw_param_unavailable_count: rawParamUnavailableCount }),
    ...(itemId == null ? {} : { item_id_unavailable_count: itemIdUnavailableCount }),
    ...(opaqueU32 == null ? {} : { opaque_u32_unavailable_count: opaqueU32UnavailableCount }),
    ...(childEventId == null ? {} : { child_event_id_unavailable_count: childEventIdUnavailableCount }),
    filters: { from_ms: fromMs, to_ms: toMs, participant_id: participant, limit,
      ...(rawParam == null ? {} : { raw_param: rawParam }),
      ...(itemId == null ? {} : { item_id: itemId }),
      ...(opaqueU32 == null ? {} : { opaque_u32: opaqueU32 }),
      ...(childEventId == null ? {} : { child_event_id: childEventId }) },
    rows_unmodified: true,
  };
}

module.exports = { EventQueryError, prepareEventQuery, streamEventQuery };

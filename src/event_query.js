'use strict';

const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');

const EVENT_KEY = /^[a-z][a-z0-9_]*_candidates$/;
const REPLAY_SHA = /^[a-f0-9]{64}$/;
const SUBJECT_PARTICIPANT_FIELDS = [
  'participant_id_candidate', 'participant_id',
  'victim_participant_id_candidate', 'victim_participant_id',
  'owner_participant_id_candidate', 'owner_participant_id',
  'target_participant_id',
];

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
  const capability = eventKey.slice(0, -'_candidates'.length);
  const capabilityResult = semantic.capability_results?.[capability];
  const capabilityStatus = capabilityResult?.status ?? null;
  if (capabilityStatus && !['CANDIDATE', 'PASS'].includes(capabilityStatus)) {
    throw new EventQueryError('CAPABILITY_UNAVAILABLE',
      `${capability} was ${capabilityStatus}; no candidate rows may be queried.`,
      { capability, capability_status: capabilityStatus,
        missing_input: capabilityResult?.missing_input ?? null,
        error: capabilityResult?.error ?? null,
        semantic_run_status: semantic.status });
  }
  if (!capabilityResult || !Array.isArray(semantic.requested_capabilities)
      || !semantic.requested_capabilities.includes(capability)) {
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
    capabilityResult, declaredCount, replaySha,
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

function validateFilters(options) {
  const { fromMs = null, toMs = null, participant = null, rawParam = null,
    itemId = null, limit = null } = options;
  for (const [name, value, minimum, maximum] of [
    ['fromMs', fromMs, 0, Number.MAX_SAFE_INTEGER],
    ['toMs', toMs, 0, Number.MAX_SAFE_INTEGER],
    ['participant', participant, 1, 10],
    ['rawParam', rawParam, 0, 0xffffffff],
    ['itemId', itemId, 0, 0xffffffff],
    ['limit', limit, 1, Number.MAX_SAFE_INTEGER],
  ]) {
    if (value != null && (!Number.isSafeInteger(value) || value < minimum || value > maximum)) {
      throw new EventQueryError('INVALID_FILTER', `Invalid ${name} query filter.`);
    }
  }
  if (fromMs != null && toMs != null && fromMs > toMs) {
    throw new EventQueryError('INVALID_FILTER', 'fromMs must not exceed toMs.');
  }
}

async function streamEventQuery(prepared, options, emitLine) {
  validateFilters(options);
  const { fromMs = null, toMs = null, participant = null, rawParam = null,
    itemId = null, limit = null } = options;
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
  let scannedCount = 0;
  let matchedCount = 0;
  let emittedCount = 0;
  let participantUnavailableCount = 0;
  let rawParamUnavailableCount = 0;
  let itemIdUnavailableCount = 0;
  let itemIdAvailableCount = 0;
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
      const params = rawParam == null ? null : rawPacketParams(row, lineNumber);
      const items = itemId == null ? null
        : prepared.eventKey === 'hero_inventory_set_item_packet_candidates'
          ? packetScalarItemId(row, lineNumber)
          : packetRecordItemIds(row, lineNumber,
            prepared.eventKey === 'hero_inventory_broadcast_packet_candidates');
      if (participant != null && subject.value == null) participantUnavailableCount += 1;
      if (rawParam != null && params.length === 0) rawParamUnavailableCount += 1;
      if (itemId != null && items.unavailable) itemIdUnavailableCount += 1;
      if (itemId != null && items.available) itemIdAvailableCount += 1;
      if ((fromMs != null && replayTime < fromMs)
          || (toMs != null && replayTime > toMs)
          || (participant != null && subject.value !== participant)
          || (rawParam != null && !params.includes(rawParam))
          || (itemId != null && !items.values.includes(itemId))) continue;
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
    filters: { from_ms: fromMs, to_ms: toMs, participant_id: participant, limit,
      ...(rawParam == null ? {} : { raw_param: rawParam }),
      ...(itemId == null ? {} : { item_id: itemId }) },
    rows_unmodified: true,
  };
}

module.exports = { EventQueryError, prepareEventQuery, streamEventQuery };

'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const GROUND_TRUTH_ORACLE_SCHEMA_VERSION = 'GROUND_TRUTH_ORACLE_V1';
const CONTROLLED_CALIBRATION_BATCH_SCHEMA_VERSION = 'CONTROLLED_CALIBRATION_BATCH_V1';
const GROUND_TRUTH_ALIGNMENT_SCHEMA_VERSION = 'GROUND_TRUTH_ALIGNMENT_V1';
const MANUAL_GROUND_TRUTH_TASKS_SCHEMA_VERSION = 'MANUAL_GROUND_TRUTH_TASKS_V2';

const P0_SEMANTICS = Object.freeze(['CURRENT_HP', 'MAX_HP', 'ARMOR', 'MAGIC_RESIST']);
const MANUAL_OR_MACHINE = new Set(['MANUAL', 'MACHINE']);
const BEFORE_AFTER_VALUES = new Set(['SNAPSHOT', 'BEFORE', 'AFTER', 'BEFORE_AFTER']);
const MANUAL_EVENT_RELATIONS = new Set([
  'LAST_STABLE_VISIBLE_BEFORE_EVENT',
  'FIRST_STABLE_VISIBLE_AFTER_EVENT',
]);
const FORBIDDEN_MANUAL_MILLISECOND_KEYS = new Set([
  'before_timestamp', 'before_timestamp_ms', 'after_timestamp', 'after_timestamp_ms',
  'human_pause_ms', 'human_pause_timestamp_ms', 'human_timestamp_ms',
  'human_time_tolerance_ms', 'timestamp_tolerance_ms', 'allowed_time_deviation_ms',
  'actual_pause_before_ms', 'actual_pause_after_ms', 'actual_pause_intermediate_ms',
  'allowed_window_ms', 'fixed_tolerance_ms', 'target_ms',
]);
const FORBIDDEN_TRUTH_KEYS = new Set([
  'packet', 'packet_id', 'packet_route', 'protocol_route', 'route', 'offset',
  'field_offset', 'payload', 'discriminator', 'raw_packet_ref',
]);

const CONTROLLED_REPLAY_REQUEST_SPECS = Object.freeze({
  CALIBRATION_SET_A_HP_DEFENSE_V1: Object.freeze({
    schema_version: 'CONTROLLED_REPLAY_REQUEST_SPEC_V1',
    request_id: 'CALIBRATION_SET_A_HP_DEFENSE_V1',
    priority: 'P0',
    recommended_replay_count: '1-3',
    required_exact_build: true,
    principles: Object.freeze([
      'ONE_CHAMPION_AND_ONE_CHANGED_VARIABLE_PER_STEP',
      'AVOID_COMPLEX_MULTI_PLAYER_FIGHTS',
      'RECORD_EVENT_RELATIVE_STABLE_VISIBLE_STATES',
      'HUMAN_GAME_CLOCK_INTEGER_SECONDS_ONLY',
    ]),
    actions: Object.freeze([
      'TAKE_ISOLATED_DAMAGE', 'NATURAL_REGEN', 'HEAL', 'SHIELD', 'DEATH', 'RESPAWN',
      'LEVEL_UP', 'BUY_HP_ITEM', 'SELL_HP_ITEM', 'UNDO_HP_ITEM',
      'BUY_ARMOR_ITEM', 'SELL_ARMOR_ITEM', 'UNDO_ARMOR_ITEM',
      'BUY_MAGIC_RESIST_ITEM', 'SELL_MAGIC_RESIST_ITEM', 'UNDO_MAGIC_RESIST_ITEM',
    ]),
    expected_truth_fields: Object.freeze(P0_SEMANTICS),
    prohibited_interpretations: Object.freeze([
      'PACKET_ROUTE_OR_OFFSET_IS_NOT_GROUND_TRUTH',
      'TIMESTAMP_PROXIMITY_DOES_NOT_PROVE_CAUSALITY',
      'NATURAL_REGEN_IS_NOT_A_POINT_EVENT_OR_RAW_HP_DELTA_ATTRIBUTION',
    ]),
  }),
});

function fail(message) {
  throw new Error(`controlled calibration: ${message}`);
}

function isObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function requiredString(value, label) {
  if (typeof value !== 'string' || value.trim() === '') fail(`${label} must be a non-empty string`);
  return value.trim();
}

function requiredFinite(value, label) {
  const number = Number(value);
  if (!Number.isFinite(number)) fail(`${label} must be finite`);
  return number;
}

function requiredExactBuild(value, label) {
  const build = requiredString(value, label);
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(build)) {
    fail(`${label} must be an exact build in N.N.N.N form`);
  }
  return build;
}

function assertJsonSafe(value, label) {
  const ancestors = new Set();
  function visit(candidate, location) {
    if (candidate === null || typeof candidate === 'string' || typeof candidate === 'boolean') return;
    if (typeof candidate === 'number') {
      if (!Number.isFinite(candidate)) fail(`${location} must be JSON-safe finite data`);
      return;
    }
    if (typeof candidate === 'undefined' || typeof candidate === 'bigint'
      || typeof candidate === 'function' || typeof candidate === 'symbol') {
      fail(`${location} must be JSON-safe data`);
    }
    if (typeof candidate !== 'object') fail(`${location} must be JSON-safe data`);
    if (ancestors.has(candidate)) fail(`${location} cannot be circular`);
    ancestors.add(candidate);
    for (const [key, child] of Object.entries(candidate)) visit(child, `${location}.${key}`);
    ancestors.delete(candidate);
  }
  visit(value, label);
  return value;
}

function requiredSha256(value, label) {
  const sha = requiredString(value, label).toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(sha)) fail(`${label} must be a SHA-256 hex digest`);
  return sha;
}

function requiredSource(value, label) {
  if (typeof value === 'string') return requiredString(value, label);
  if (!isObject(value) || Object.keys(value).length === 0) fail(`${label} must be non-empty provenance`);
  assertJsonSafe(value, label);
  return value;
}

function assertNoHumanMillisecondInstruction(value, label = 'manual validation input') {
  const seen = new Set();
  function isForbiddenTimingFieldName(valueToCheck) {
    const normalized = String(valueToCheck).trim().toLowerCase().replace(/[-\s]+/g, '_');
    return FORBIDDEN_MANUAL_MILLISECOND_KEYS.has(normalized)
      || normalized.includes('timestamp')
      || normalized.includes('millisecond')
      || /(^|_)ms($|_)/.test(normalized)
      || normalized.includes('pause')
      || normalized.includes('tolerance')
      || normalized.includes('window')
      || normalized.includes('deviation')
      || normalized.includes('target_time')
      || normalized.includes('time_target');
  }
  function visit(candidate, location) {
    if (candidate === null || candidate === undefined || typeof candidate !== 'object') return;
    if (seen.has(candidate)) return;
    seen.add(candidate);
    for (const [key, child] of Object.entries(candidate)) {
      const normalizedKey = key.toLowerCase();
      const normalizedStringValue = typeof child === 'string' ? child.trim().toLowerCase() : null;
      const isDecoderMachineTimestamp = normalizedKey === 'decoder_event_timestamp_ms'
        && /\.decoder_events\.\d+$/.test(location);
      const stringNamesTimingField = normalizedStringValue !== null
        && /^[a-z0-9_-]+$/.test(normalizedStringValue)
        && isForbiddenTimingFieldName(normalizedStringValue);
      if ((!isDecoderMachineTimestamp && isForbiddenTimingFieldName(normalizedKey)) || stringNamesTimingField) {
        fail(`${location}.${key} requires human millisecond timing and is forbidden`);
      }
      visit(child, `${location}.${key}`);
    }
  }
  visit(value, label);
}

function normalizedBeforeAfter(value, label) {
  const normalized = requiredString(value ?? 'SNAPSHOT', label).toUpperCase();
  if (!BEFORE_AFTER_VALUES.has(normalized)) {
    fail(`${label} must be one of ${[...BEFORE_AFTER_VALUES].join(', ')}`);
  }
  return normalized;
}

function valueAtPath(value, key) {
  if (!isObject(value)) return undefined;
  return value[key];
}

function replaySha(record) {
  return valueAtPath(record, 'replay_sha') ?? valueAtPath(record, 'replay_sha256');
}

function timestamp(record) {
  return valueAtPath(record, 'timestamp') ?? valueAtPath(record, 'timestamp_ms')
    ?? valueAtPath(record, 'replay_time_ms');
}

function entityKey(entity) {
  if (!isObject(entity)) return null;
  const id = entity.id ?? entity.entity_id ?? entity.network_id ?? entity.participant_id ?? null;
  const champion = entity.champion ?? null;
  if (id === null && champion === null) return null;
  return `${id ?? ''}|${champion ?? ''}`;
}

function entityFrom(record) {
  if (isObject(record.entity)) return record.entity;
  if (typeof record.champion === 'string' && record.champion.trim()) return { champion: record.champion.trim() };
  return null;
}

function assertNoProtectedReference(value, label = 'input') {
  const seen = new Set();
  function visit(candidate, location) {
    if (candidate === null || candidate === undefined) return;
    if (typeof candidate === 'string') {
      if (/jungle[_ -]?objective[_ -]?holdout|protected[_ -]?holdout|holdout/i.test(candidate)) {
        fail(`${location} references protected Holdout`);
      }
      return;
    }
    if (typeof candidate !== 'object' || seen.has(candidate)) return;
    seen.add(candidate);
    for (const [key, child] of Object.entries(candidate)) visit(child, `${location}.${key}`);
  }
  visit(value, label);
}

function assertTruthIsSemanticOnly(value, label = 'truth') {
  const seen = new Set();
  function visit(candidate, location) {
    if (candidate === null || candidate === undefined || typeof candidate !== 'object') return;
    if (seen.has(candidate)) return;
    seen.add(candidate);
    for (const [key, child] of Object.entries(candidate)) {
      if (FORBIDDEN_TRUTH_KEYS.has(key.toLowerCase())) {
        fail(`${location}.${key} is decoder route/offset data and cannot be ground truth`);
      }
      visit(child, `${location}.${key}`);
    }
  }
  visit(value, label);
}

function normalizedOracleRecord(record, index = 0) {
  if (!isObject(record)) fail(`oracle record ${index} must be an object`);
  assertNoProtectedReference(record, `oracle record ${index}`);
  assertTruthIsSemanticOnly(record, `oracle record ${index}`);
  assertJsonSafe(record, `oracle record ${index}`);
  const entity = entityFrom(record);
  if (!entityKey(entity)) fail(`oracle record ${index} requires entity or champion`);
  const source = requiredSource(record.source, `oracle record ${index}.source`);
  const mode = requiredString(record.manual_or_machine, `oracle record ${index}.manual_or_machine`).toUpperCase();
  if (!MANUAL_OR_MACHINE.has(mode)) fail(`oracle record ${index}.manual_or_machine must be MANUAL or MACHINE`);
  if (!Object.hasOwn(record, 'observed_value')) fail(`oracle record ${index}.observed_value is required`);
  return {
    schema_version: GROUND_TRUTH_ORACLE_SCHEMA_VERSION,
    case_id: requiredString(record.case_id, `oracle record ${index}.case_id`),
    replay_sha: requiredSha256(replaySha(record), `oracle record ${index}.replay_sha`),
    exact_build: requiredExactBuild(record.exact_build, `oracle record ${index}.exact_build`),
    timestamp: requiredFinite(timestamp(record), `oracle record ${index}.timestamp`),
    entity,
    semantic: requiredString(record.semantic, `oracle record ${index}.semantic`).toUpperCase(),
    observed_value: assertJsonSafe(record.observed_value, `oracle record ${index}.observed_value`),
    before_after: normalizedBeforeAfter(record.before_after, `oracle record ${index}.before_after`),
    source,
    manual_or_machine: mode,
    confidence: record.confidence ?? 'UNSPECIFIED',
    notes: typeof record.notes === 'string' ? record.notes : JSON.stringify(record.notes ?? ''),
    ...(record.frame_boundary_evidence === undefined ? {} : {
      frame_boundary_evidence: assertJsonSafe(
        record.frame_boundary_evidence,
        `oracle record ${index}.frame_boundary_evidence`,
      ),
    }),
  };
}

function createGroundTruthOracle(records, options = {}) {
  if (!Array.isArray(records) || records.length === 0) fail('oracle requires at least one explicit record');
  assertNoProtectedReference(records, 'oracle records');
  const normalized = records.map(normalizedOracleRecord);
  const caseIds = new Set();
  for (const row of normalized) {
    if (caseIds.has(row.case_id)) fail(`duplicate oracle case_id ${row.case_id}`);
    caseIds.add(row.case_id);
  }
  normalized.sort((a, b) => a.case_id.localeCompare(b.case_id));
  return {
    schema_version: GROUND_TRUTH_ORACLE_SCHEMA_VERSION,
    exact_build_only: true,
    decoder_routes_or_offsets_in_truth: 'FORBIDDEN',
    generated_at_omitted_for_reproducibility: true,
    source_provenance: options.source_provenance ?? 'EXPLICIT_SUPPLIED_INPUTS_ONLY',
    records: normalized,
  };
}

function oracleRecordsFromDetailsP0(anchors, options = {}) {
  if (!Array.isArray(anchors) || anchors.length === 0) fail('DETAILS P0 conversion requires explicit anchors');
  assertNoProtectedReference(anchors, 'DETAILS P0 anchors');
  const records = [];
  for (const anchor of anchors) {
    if (!isObject(anchor)) fail('DETAILS P0 anchor must be an object');
    const values = {
      CURRENT_HP: anchor.current_hp,
      MAX_HP: anchor.max_hp,
      ARMOR: anchor.armor,
      MAGIC_RESIST: anchor.magic_resist,
    };
    for (const semantic of P0_SEMANTICS) {
      if (!Object.hasOwn(values, semantic) || values[semantic] === undefined) {
        fail(`DETAILS P0 anchor ${anchor.anchor_id ?? 'unknown'} lacks ${semantic}`);
      }
      records.push({
        case_id: `${requiredString(anchor.anchor_id, 'DETAILS P0 anchor.anchor_id')}:${semantic}`,
        replay_sha: anchor.replay_sha ?? anchor.replay_sha256,
        exact_build: anchor.exact_build ?? anchor.replay_build,
        timestamp: anchor.timestamp ?? anchor.timestamp_ms,
        entity: anchor.entity ?? { participant_id: anchor.participant_id, champion: anchor.champion },
        semantic,
        observed_value: values[semantic],
        before_after: 'SNAPSHOT',
        ...(anchor.frame_boundary_evidence === undefined ? {} : {
          frame_boundary_evidence: anchor.frame_boundary_evidence,
        }),
        source: anchor.source ?? { fact_source: 'DETAILS_P0_GROUND_TRUTH_V1' },
        manual_or_machine: 'MACHINE',
        confidence: 'DETAILS_DIRECT',
        notes: options.notes ?? 'Converted from DETAILS_P0_GROUND_TRUTH_V1 anchor; no decoder route or offset retained.',
      });
    }
  }
  return createGroundTruthOracle(records, { source_provenance: 'DETAILS_P0_GROUND_TRUTH_V1_EXPLICIT_ANCHORS' });
}

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function importControlledCalibrationBatch(input) {
  if (!isObject(input)) fail('batch input must be an object');
  assertNoProtectedReference(input, 'controlled calibration batch');
  const files = input.files ?? [];
  const objects = input.objects ?? [];
  if (!Array.isArray(files) || !Array.isArray(objects) || files.length + objects.length === 0) {
    fail('batch requires explicit files and/or objects');
  }
  const entries = [];
  for (const [index, item] of files.entries()) {
    if (!isObject(item)) fail(`file ${index} must be an object`);
    const suppliedPath = requiredString(item.path, `file ${index}.path`);
    const resolved = path.resolve(suppliedPath);
    let stat;
    try {
      stat = fs.statSync(resolved);
    } catch (error) {
      fail(`file ${index} path is not readable: ${resolved}`);
    }
    if (!stat.isFile()) fail(`file ${index} path is not a regular file: ${resolved}`);
    const shouldHash = item.hash === true || item.verify_sha256 === true || item.expected_sha256 !== undefined;
    const actualSha = shouldHash ? sha256File(resolved) : null;
    if (item.expected_sha256 !== undefined && actualSha !== requiredSha256(item.expected_sha256, `file ${index}.expected_sha256`)) {
      fail(`file ${index} SHA-256 mismatch`);
    }
    entries.push({
      id: requiredString(item.id ?? `file-${index}`, `file ${index}.id`),
      input_kind: requiredString(item.kind ?? 'FILE', `file ${index}.kind`),
      path: resolved,
      exact_build: requiredExactBuild(item.exact_build, `file ${index}.exact_build`),
      source: requiredSource(item.source, `file ${index}.source`),
      byte_size: stat.size,
      sha256: actualSha,
      replay_sha: String(item.kind ?? '').toUpperCase() === 'REPLAY' ? actualSha : null,
      hash_requested: shouldHash,
      explicitly_supplied: true,
    });
  }
  for (const [index, item] of objects.entries()) {
    if (!isObject(item) || !isObject(item.object)) fail(`object ${index} requires an explicit object property`);
    entries.push({
      id: requiredString(item.id ?? `object-${index}`, `object ${index}.id`),
      input_kind: requiredString(item.kind ?? 'OBJECT', `object ${index}.kind`),
      exact_build: requiredExactBuild(item.exact_build, `object ${index}.exact_build`),
      source: requiredSource(item.source, `object ${index}.source`),
      object: assertJsonSafe(item.object, `object ${index}.object`),
      sha256: item.hash === true ? crypto.createHash('sha256').update(JSON.stringify(item.object)).digest('hex') : null,
      hash_requested: item.hash === true,
      explicitly_supplied: true,
    });
  }
  const ids = new Set();
  for (const entry of entries) {
    if (ids.has(entry.id)) fail(`duplicate controlled calibration input id ${entry.id}`);
    ids.add(entry.id);
  }
  entries.sort((a, b) => a.id.localeCompare(b.id));
  return {
    schema_version: CONTROLLED_CALIBRATION_BATCH_SCHEMA_VERSION,
    directory_discovery: 'FORBIDDEN',
    protected_holdout: { read: false, enumerate: false, hash: false, decode: false, consume: false },
    inputs: entries,
  };
}

function candidateValue(row) {
  return row.observed_value ?? row.value ?? row.decoded_value ?? null;
}

function alignGroundTruthOracle(oracle, semanticRows, options = {}) {
  if (!isObject(oracle) || oracle.schema_version !== GROUND_TRUTH_ORACLE_SCHEMA_VERSION) {
    fail('alignment requires a versioned GroundTruthOracle');
  }
  if (!Array.isArray(semanticRows)) fail('alignment semanticRows must be an array');
  assertNoProtectedReference([oracle, semanticRows], 'alignment inputs');
  const toleranceMs = requiredFinite(options.timestamp_tolerance_ms ?? 0, 'timestamp_tolerance_ms');
  if (toleranceMs < 0) fail('timestamp_tolerance_ms cannot be negative');
  const results = oracle.records.map((truth) => {
    const matches = semanticRows.filter((row) => isObject(row)
      && replaySha(row) === truth.replay_sha
      && row.exact_build === truth.exact_build
      && String(row.semantic ?? '').toUpperCase() === truth.semantic
      && entityKey(entityFrom(row)) === entityKey(truth.entity)
      && Math.abs(requiredFinite(timestamp(row), 'semantic row timestamp') - truth.timestamp) <= toleranceMs);
    const base = {
      case_id: truth.case_id,
      oracle: truth,
      candidate_count: matches.length,
      automatic_semantic_promotion: 'FORBIDDEN',
    };
    if (matches.length !== 1) return {
      ...base,
      status: matches.length === 0 ? 'UNMATCHED' : 'AMBIGUOUS',
      candidates: matches,
      residual: null,
    };
    const candidate = matches[0];
    const actual = candidateValue(candidate);
    const residual = typeof truth.observed_value === 'number' && typeof actual === 'number'
      ? actual - truth.observed_value : null;
    return {
      ...base,
      status: 'MATCHED',
      candidate,
      residual,
      candidate_semantic_status_preserved: candidate.semantic_status ?? candidate.confidence ?? 'UNKNOWN',
    };
  });
  return {
    schema_version: GROUND_TRUTH_ALIGNMENT_SCHEMA_VERSION,
    exact_build_only: true,
    timestamp_tolerance_ms: toleranceMs,
    results,
    counts: {
      matched: results.filter((row) => row.status === 'MATCHED').length,
      unmatched: results.filter((row) => row.status === 'UNMATCHED').length,
      ambiguous: results.filter((row) => row.status === 'AMBIGUOUS').length,
    },
  };
}

function generateManualValidationCases(unresolvedHypotheses, options = {}) {
  if (!Array.isArray(unresolvedHypotheses)) fail('unresolved hypotheses must be an array');
  assertNoProtectedReference(unresolvedHypotheses, 'unresolved hypotheses');
  assertNoHumanMillisecondInstruction(unresolvedHypotheses, 'unresolved hypotheses');
  const limit = Math.min(Number(options.max_cases ?? 20), 20);
  if (!Number.isInteger(limit) || limit < 1) fail('max_cases must be an integer from 1 to 20');
  const cases = unresolvedHypotheses.map((row, index) => {
    if (!isObject(row)) fail(`hypothesis ${index} must be an object`);
    const entity = entityFrom(row);
    if (!entityKey(entity)) fail(`hypothesis ${index} requires champion or entity`);
    const competing = row.competing_hypotheses;
    if (!Array.isArray(competing) || competing.length < 2) fail(`hypothesis ${index} needs at least two competing hypotheses`);
    const fields = row.expected_observation_fields;
    if (!Array.isArray(fields) || fields.length === 0) fail(`hypothesis ${index} needs expected observation fields`);
    if (!Array.isArray(row.decoder_events) || row.decoder_events.length === 0) {
      fail(`hypothesis ${index} needs decoder_events machine provenance`);
    }
    const eventIds = new Set();
    const decoderEvents = row.decoder_events.map((event, eventIndex) => {
      if (!isObject(event)) fail(`hypothesis ${index}.decoder_events ${eventIndex} must be an object`);
      const eventId = requiredString(event.event_id, `hypothesis ${index}.decoder_events ${eventIndex}.event_id`);
      if (eventIds.has(eventId)) fail(`hypothesis ${index} has duplicate decoder event_id ${eventId}`);
      eventIds.add(eventId);
      return {
        event_id: eventId,
        semantic: requiredString(event.semantic, `hypothesis ${index}.decoder_events ${eventIndex}.semantic`).toUpperCase(),
        decoder_event_timestamp_ms: requiredFinite(
          event.decoder_event_timestamp_ms,
          `hypothesis ${index}.decoder_events ${eventIndex}.decoder_event_timestamp_ms`,
        ),
      };
    });
    if (!Array.isArray(row.observation_steps) || row.observation_steps.length < 2) {
      fail(`hypothesis ${index} needs at least two event-relative observation_steps`);
    }
    const observationIds = new Set();
    const observationSteps = row.observation_steps.map((step, stepIndex) => {
      if (!isObject(step)) fail(`hypothesis ${index}.observation_steps ${stepIndex} must be an object`);
      const observationId = requiredString(
        step.observation_id,
        `hypothesis ${index}.observation_steps ${stepIndex}.observation_id`,
      );
      if (observationIds.has(observationId)) fail(`hypothesis ${index} has duplicate observation_id ${observationId}`);
      observationIds.add(observationId);
      const eventId = requiredString(step.event_id, `hypothesis ${index}.observation_steps ${stepIndex}.event_id`);
      if (!eventIds.has(eventId)) fail(`hypothesis ${index}.observation_steps ${stepIndex} references unknown event_id ${eventId}`);
      const relation = requiredString(
        step.relation,
        `hypothesis ${index}.observation_steps ${stepIndex}.relation`,
      ).toUpperCase();
      if (!MANUAL_EVENT_RELATIONS.has(relation)) {
        fail(`hypothesis ${index}.observation_steps ${stepIndex}.relation must be one of ${[...MANUAL_EVENT_RELATIONS].join(', ')}`);
      }
      if (!Array.isArray(step.hud_fields) || step.hud_fields.length === 0) {
        fail(`hypothesis ${index}.observation_steps ${stepIndex}.hud_fields must be non-empty`);
      }
      let answerFields;
      if (step.answer_fields !== undefined) {
        if (!Array.isArray(step.answer_fields) || step.answer_fields.length === 0) {
          fail(`hypothesis ${index}.observation_steps ${stepIndex}.answer_fields must be a non-empty array when provided`);
        }
        answerFields = step.answer_fields.map((field, fieldIndex) => requiredString(
          field,
          `hypothesis ${index}.observation_steps ${stepIndex}.answer_fields ${fieldIndex}`,
        ));
        for (const answerField of answerFields) {
          if (!fields.includes(answerField)) {
            fail(`hypothesis ${index}.observation_steps ${stepIndex}.answer_fields ${answerField} must belong to expected_observation_fields`);
          }
        }
      }
      return {
        observation_id: observationId,
        relation,
        event_id: eventId,
        hud_fields: step.hud_fields.map((field, fieldIndex) => requiredString(
          field,
          `hypothesis ${index}.observation_steps ${stepIndex}.hud_fields ${fieldIndex}`,
        ).toUpperCase()),
        ...(answerFields === undefined ? {} : { answer_fields: answerFields }),
        ...(step.indicator_fields === undefined ? {} : {
          indicator_fields: step.indicator_fields.map((field, fieldIndex) => requiredString(
            field,
            `hypothesis ${index}.observation_steps ${stepIndex}.indicator_fields ${fieldIndex}`,
          ).toUpperCase()),
        }),
        ...(step.purpose === undefined ? {} : {
          purpose: requiredString(step.purpose, `hypothesis ${index}.observation_steps ${stepIndex}.purpose`),
        }),
      };
    });
    const isIntervalHpChange = String(row.semantic ?? row.variable ?? '').toUpperCase() === 'HP_CHANGE_OVER_INTERVAL';
    let intervalDefinition;
    let competingHpSourceReview;
    if (isIntervalHpChange) {
      if (!isObject(row.interval_definition)) fail(`hypothesis ${index} HP_CHANGE_OVER_INTERVAL requires interval_definition`);
      const startEventId = requiredString(row.interval_definition.start_event_id, `hypothesis ${index}.interval_definition.start_event_id`);
      const endEventId = requiredString(row.interval_definition.end_event_id, `hypothesis ${index}.interval_definition.end_event_id`);
      if (!eventIds.has(startEventId) || !eventIds.has(endEventId)) fail(`hypothesis ${index}.interval_definition must reference decoder events`);
      const startRelation = requiredString(row.interval_definition.start_relation, `hypothesis ${index}.interval_definition.start_relation`).toUpperCase();
      const endRelation = requiredString(row.interval_definition.end_relation, `hypothesis ${index}.interval_definition.end_relation`).toUpperCase();
      if (!MANUAL_EVENT_RELATIONS.has(startRelation) || !MANUAL_EVENT_RELATIONS.has(endRelation)) {
        fail(`hypothesis ${index}.interval_definition relations must be event-relative`);
      }
      if (!isObject(row.competing_hp_source_review) || Object.keys(row.competing_hp_source_review).length === 0) {
        fail(`hypothesis ${index} HP_CHANGE_OVER_INTERVAL requires competing_hp_source_review`);
      }
      intervalDefinition = {
        start_event_id: startEventId,
        start_relation: startRelation,
        end_event_id: endEventId,
        end_relation: endRelation,
        ...(row.interval_definition.description === undefined ? {} : {
          description: requiredString(row.interval_definition.description, `hypothesis ${index}.interval_definition.description`),
        }),
      };
      competingHpSourceReview = assertJsonSafe(
        row.competing_hp_source_review,
        `hypothesis ${index}.competing_hp_source_review`,
      );
    }
    return {
      case_id: requiredString(row.case_id, `hypothesis ${index}.case_id`),
      replay: requiredString(row.replay ?? row.replay_label, `hypothesis ${index}.replay`),
      replay_sha: row.replay_sha ? requiredSha256(row.replay_sha, `hypothesis ${index}.replay_sha`) : null,
      build: requiredExactBuild(row.exact_build, `hypothesis ${index}.exact_build`),
      champion: entity.champion ?? String(entity.id ?? entity.participant_id),
      variable: requiredString(row.semantic ?? row.variable, `hypothesis ${index}.semantic`),
      decoder_events: decoderEvents,
      observation_steps: observationSteps,
      human_time_precision: 'GAME_CLOCK_INTEGER_SECOND',
      human_millisecond_input: 'FORBIDDEN',
      evidence_requirements: Object.freeze([
        'VISIBLE_GAME_CLOCK_INTEGER_SECOND',
        'SCREENSHOT_OR_FRAME_REFERENCE_PER_OBSERVATION',
        'HUD_VALUES_PER_OBSERVATION',
      ]),
      competing_hypotheses: [...competing],
      expected_observation_fields: [...fields],
      why_this_case_matters: requiredString(row.why_this_case_matters ?? row.rationale ?? 'Distinguishes the remaining semantic candidates.', `hypothesis ${index}.why_this_case_matters`),
      information_gain: requiredFinite(row.information_gain ?? 0, `hypothesis ${index}.information_gain`),
      ...(isIntervalHpChange ? {
        interval_definition: intervalDefinition,
        competing_hp_source_review: competingHpSourceReview,
        natural_regen_attribution: 'NOT_ASSERTED_BY_MANUAL_REVIEW',
      } : {}),
    };
  }).sort((a, b) => b.information_gain - a.information_gain || a.case_id.localeCompare(b.case_id));
  const selected = cases.slice(0, limit);
  return {
    schema_version: MANUAL_GROUND_TRUTH_TASKS_SCHEMA_VERSION,
    manual_validation_default: 'FORBIDDEN_UNLESS_AUTOMATIC_EVIDENCE_IS_UNRESOLVED',
    requested_case_limit: limit,
    task_count: selected.length,
    tasks: selected,
  };
}

function formatManualGroundTruthTasks(batch) {
  if (!isObject(batch) || batch.schema_version !== MANUAL_GROUND_TRUTH_TASKS_SCHEMA_VERSION) {
    fail('formatting requires ManualValidationCaseGenerator output');
  }
  return batch.tasks.map((task) => {
    const expected = task.expected_observation_fields.map((field) => `${field} = ?`).join('\n');
    const hypotheses = task.competing_hypotheses.map((item, index) => `${String.fromCharCode(65 + index)}. ${item}`).join('\n');
    const observations = task.observation_steps.map((step) => [
      `OBSERVATION_ID: ${step.observation_id}`,
      `Fixed relation: ${step.relation} (${step.event_id})`,
      `HUD values to copy: ${step.hud_fields.join(', ')}`,
      ...(step.indicator_fields ? [`Indicators to record: ${step.indicator_fields.join(', ')}`] : []),
      'Record the visible game-clock integer second and a screenshot or frame reference.',
      ...(step.answer_fields ? ['Answers:', ...step.answer_fields.map((field) => `${field} = ?`)] : []),
    ].join('\n')).join('\n\n');
    return [
      `CASE_ID: ${task.case_id}`,
      `Replay: ${task.replay}`,
      `Build: ${task.build}`,
      `Champion: ${task.champion}`,
      `Variable: ${task.variable}`,
      '',
      'Use the listed fixed event-relative observations. Do not provide or estimate milliseconds.',
      observations,
      '',
      'Expected observation format:',
      expected,
      ...(task.interval_definition ? [
        '',
        'Continuous HP interval only:',
        `${task.interval_definition.start_relation} (${task.interval_definition.start_event_id}) through ${task.interval_definition.end_relation} (${task.interval_definition.end_event_id})`,
        'Record competing HP source review. Do not label any HP change as natural regen.',
      ] : []),
      '',
      'Why this case matters:',
      task.why_this_case_matters,
      '',
      'Competing hypotheses:',
      hypotheses,
    ].join('\n');
  }).join('\n\n');
}

function groundTruthOracleSchemaDocument() {
  return {
    schema_document_version: 'GROUND_TRUTH_ORACLE_SCHEMA_DOCUMENT_V1',
    schema_version: GROUND_TRUTH_ORACLE_SCHEMA_VERSION,
    exact_build_pattern: '^\\d+\\.\\d+\\.\\d+\\.\\d+$',
    before_after_enum: [...BEFORE_AFTER_VALUES],
    record_required_fields: [
      'case_id', 'replay_sha', 'exact_build', 'timestamp', 'entity', 'semantic',
      'observed_value', 'before_after', 'source', 'manual_or_machine', 'confidence', 'notes',
    ],
    truth_forbidden_fields: [...FORBIDDEN_TRUTH_KEYS].sort(),
    semantic_route_separation: 'REQUIRED',
  };
}

function controlledCalibrationBatchSchemaDocument() {
  return {
    schema_document_version: 'CONTROLLED_CALIBRATION_BATCH_SCHEMA_DOCUMENT_V1',
    schema_version: CONTROLLED_CALIBRATION_BATCH_SCHEMA_VERSION,
    exact_build_pattern: '^\\d+\\.\\d+\\.\\d+\\.\\d+$',
    input_required_fields: ['id', 'kind', 'exact_build', 'source'],
    explicit_files_or_objects_only: true,
    directory_discovery: 'FORBIDDEN',
    protected_holdout: { read: false, enumerate: false, hash: false, decode: false, consume: false },
  };
}

function groundTruthAlignmentSchemaDocument() {
  return {
    schema_document_version: 'GROUND_TRUTH_ALIGNMENT_SCHEMA_DOCUMENT_V1',
    schema_version: GROUND_TRUTH_ALIGNMENT_SCHEMA_VERSION,
    required_match_keys: ['replay_sha', 'exact_build', 'semantic', 'entity', 'bounded_timestamp'],
    preserved_nonmatches: ['UNMATCHED', 'AMBIGUOUS'],
    automatic_semantic_promotion: 'FORBIDDEN',
    numeric_residual: 'candidate_value_minus_observed_value_when_both_numeric',
  };
}

function manualValidationTasksSchemaDocument() {
  return {
    schema_document_version: 'MANUAL_GROUND_TRUTH_TASKS_SCHEMA_DOCUMENT_V2',
    schema_version: MANUAL_GROUND_TRUTH_TASKS_SCHEMA_VERSION,
    task_required_fields: [
      'case_id', 'replay', 'build', 'champion', 'variable', 'decoder_events',
      'observation_steps', 'human_time_precision', 'human_millisecond_input',
      'evidence_requirements', 'competing_hypotheses', 'expected_observation_fields',
      'why_this_case_matters', 'information_gain',
    ],
    decoder_event_timestamp_ms: 'MACHINE_PROVENANCE_ONLY',
    human_time_precision: 'GAME_CLOCK_INTEGER_SECOND',
    human_millisecond_input: 'FORBIDDEN',
    observation_relation_enum: [...MANUAL_EVENT_RELATIONS],
    observation_step_answer_fields: 'OPTIONAL_NON_EMPTY_SUBSET_OF_TASK_EXPECTED_OBSERVATION_FIELDS',
    required_evidence_per_observation: ['VISIBLE_GAME_CLOCK_INTEGER_SECOND', 'SCREENSHOT_OR_FRAME_REFERENCE', 'HUD_VALUES'],
    continuous_hp_interval_contract: {
      semantic: 'HP_CHANGE_OVER_INTERVAL',
      requires: ['interval_definition', 'competing_hp_source_review'],
      natural_regen_attribution: 'NOT_ASSERTED_BY_MANUAL_REVIEW',
    },
    max_cases: 20,
    manual_validation_default: 'FORBIDDEN_UNLESS_AUTOMATIC_EVIDENCE_IS_UNRESOLVED',
  };
}

module.exports = {
  CONTROLLED_CALIBRATION_BATCH_SCHEMA_VERSION,
  CONTROLLED_REPLAY_REQUEST_SPECS,
  BEFORE_AFTER_VALUES,
  FORBIDDEN_TRUTH_KEYS,
  GROUND_TRUTH_ALIGNMENT_SCHEMA_VERSION,
  GROUND_TRUTH_ORACLE_SCHEMA_VERSION,
  MANUAL_GROUND_TRUTH_TASKS_SCHEMA_VERSION,
  MANUAL_EVENT_RELATIONS,
  P0_SEMANTICS,
  alignGroundTruthOracle,
  assertNoProtectedReference,
  assertJsonSafe,
  assertTruthIsSemanticOnly,
  createGroundTruthOracle,
  controlledCalibrationBatchSchemaDocument,
  formatManualGroundTruthTasks,
  groundTruthAlignmentSchemaDocument,
  groundTruthOracleSchemaDocument,
  generateManualValidationCases,
  importControlledCalibrationBatch,
  manualValidationTasksSchemaDocument,
  oracleRecordsFromDetailsP0,
};

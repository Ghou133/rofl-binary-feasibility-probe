'use strict';

// This importer deliberately consumes only completed human-visible observations plus
// the already-published canonical task document.  It does not inspect a replay or
// derive protocol facts.
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const {
  MANUAL_GROUND_TRUTH_TASKS_SCHEMA_VERSION,
  MANUAL_EVENT_RELATIONS,
  assertNoProtectedReference,
  createGroundTruthOracle,
} = require('./controlled_calibration');

const OPERATOR_SCHEMA = 'MANUAL_GROUND_TRUTH_OPERATOR_CHECKLIST_ZH_V2_EVENT_RELATIVE';
const COMPLETED_SCHEMA = 'COMPLETED_MANUAL_GROUND_TRUTH_V1';
const IMPORT_REPORT_SCHEMA = 'MANUAL_GROUND_TRUTH_IMPORT_REPORT_V1';
const IMPORT_MANIFEST_SCHEMA = 'MANUAL_GROUND_TRUTH_IMPORT_ARTIFACT_MANIFEST_V1';
const EXPECTED_CASE_IDS = Object.freeze([
  'P0-HP-01-DAMAGE-REGEN',
  'P0-HP-02-HEAL',
  'P0-HP-03-SHIELD-DAMAGE',
  'P0-HP-04-DEATH',
  'P0-HP-05-RESPAWN',
  'P0-STATS-06-LEVEL-UP',
  'P0-ITEM-07-RUBY-BUY-UNDO',
  'P0-ITEM-08-RUBY-BUY-SELL',
  'P0-ITEM-09-CLOTH-BUY-UNDO',
  'P0-ITEM-10-CLOTH-BUY-SELL',
  'P0-ITEM-11-MR-BUY-UNDO',
  'P0-ITEM-12-MR-BUY-SELL',
]);
const HUD_VALUE_ENUMS = new Set(['NOT_VISIBLE', 'UNCLEAR']);
const INDICATOR_ENUMS = new Set(['PRESENT', 'ABSENT', 'NOT_VISIBLE', 'UNCLEAR']);
const YES_NO_UNCLEAR = new Set(['YES', 'NO', 'UNCLEAR']);
const COMPETING_HP_SOURCE_VALUES = new Set([
  'NO_OTHER_VISIBLE_HP_SOURCE', 'OTHER_HP_SOURCE_VISIBLE', 'UNCLEAR',
]);

function fail(message) {
  throw new Error(`manual ground-truth import: ${message}`);
}

function isObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function requiredString(value, label) {
  if (typeof value !== 'string' || value.trim() === '') fail(`${label} must be a non-empty string`);
  return value.trim();
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function sha256File(filePath) {
  return sha256(fs.readFileSync(filePath));
}

function readJson(filePath, label) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (error) {
    fail(`${label} is not valid JSON: ${error.message}`);
  }
}

function strictExactBuild(value, label) {
  const build = requiredString(value, label);
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(build)) fail(`${label} must be an exact N.N.N.N build`);
  return build;
}

function strictSha(value, label) {
  const result = requiredString(value, label).toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(result)) fail(`${label} must be SHA-256 hex`);
  return result;
}

function sameStrings(actual, expected, label) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(`${label} does not match the required canonical order and values`);
  }
}

function containsForbiddenHumanTimingKey(key) {
  const normalized = String(key).trim().toLowerCase().replace(/[-\s]+/g, '_');
  return normalized.includes('timestamp') || normalized.includes('millisecond')
    || /(^|_)ms($|_)/.test(normalized) || normalized.includes('pause')
    || normalized.includes('tolerance') || normalized.includes('window')
    || normalized.includes('deviation') || normalized.includes('target_time');
}

function assertNoHumanTimingFields(value, label, allowDecoderTimestamp = false) {
  if (!isObject(value) && !Array.isArray(value)) return;
  for (const [key, child] of Object.entries(value)) {
    const allowedDecoderTimestamp = allowDecoderTimestamp && key === 'decoder_event_timestamp_ms';
    if (!allowedDecoderTimestamp && containsForbiddenHumanTimingKey(key)) {
      fail(`${label}.${key} is human millisecond/timing input and is forbidden`);
    }
    assertNoHumanTimingFields(child, `${label}.${key}`, allowDecoderTimestamp);
  }
}

function stripKnownInlineFillHint(value) {
  // The operator checklist uses these exact, human-facing suffix forms.  Do not
  // remove any other parenthetical content: it may be a real note or frame name.
  return value.trim().replace(/\s*(?:（(?:只填|填写|填入|可填)[^（）]*）|\((?:只填|填写|填入|可填)[^()]*\))\s*$/u, '').trim();
}

function parseCompletedChecklistText(text) {
  if (typeof text !== 'string' || text.trim() === '') fail('filled text must be non-empty');
  assertNoProtectedReference(text, 'filled text');
  const cases = new Map();
  let currentCaseId = null;
  for (const [index, rawLine] of text.split(/\r?\n/).entries()) {
    const line = rawLine.trim();
    const caseMatch = /^CASE_ID\s*:\s*(\S+)\s*$/i.exec(line);
    if (caseMatch) {
      currentCaseId = caseMatch[1];
      if (cases.has(currentCaseId)) fail(`duplicate CASE_ID ${currentCaseId} at line ${index + 1}`);
      cases.set(currentCaseId, new Map());
      continue;
    }
    const answerMatch = /^([A-Za-z][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/.exec(line);
    if (!answerMatch) continue;
    if (!currentCaseId) fail(`answer ${answerMatch[1]} appears before CASE_ID at line ${index + 1}`);
    const [unused, key, rawValue] = answerMatch;
    if (containsForbiddenHumanTimingKey(key)) {
      fail(`filled text field ${key} is human millisecond/timing input and is forbidden`);
    }
    const answers = cases.get(currentCaseId);
    if (answers.has(key)) fail(`duplicate answer ${currentCaseId}.${key} at line ${index + 1}`);
    answers.set(key, stripKnownInlineFillHint(rawValue));
  }
  if (cases.size === 0) fail('filled text contains no CASE_ID section');
  return cases;
}

function validateTaskPairing(operator, canonical) {
  if (!isObject(operator) || operator.schema_version !== OPERATOR_SCHEMA) {
    fail(`operator template must use ${OPERATOR_SCHEMA}`);
  }
  if (!isObject(canonical) || canonical.schema_version !== MANUAL_GROUND_TRUTH_TASKS_SCHEMA_VERSION) {
    fail(`canonical tasks must use ${MANUAL_GROUND_TRUTH_TASKS_SCHEMA_VERSION}`);
  }
  if (operator.source_schema_version !== MANUAL_GROUND_TRUTH_TASKS_SCHEMA_VERSION) {
    fail('operator template source_schema_version does not match canonical task schema');
  }
  if (operator.task_count !== 12 || canonical.task_count !== 12
    || !Array.isArray(operator.tasks) || !Array.isArray(canonical.tasks)
    || operator.tasks.length !== 12 || canonical.tasks.length !== 12) {
    fail('operator template and canonical tasks must each contain exactly 12 tasks');
  }
  const canonicalIds = canonical.tasks.map((task) => task.case_id);
  const operatorIds = operator.tasks.map((task) => task.case_id);
  sameStrings(canonicalIds, EXPECTED_CASE_IDS, 'canonical task case IDs');
  sameStrings(operatorIds, EXPECTED_CASE_IDS, 'operator task case IDs');
  strictExactBuild(operator.build, 'operator.build');
  strictSha(operator.replay_sha, 'operator.replay_sha');
  const result = [];
  for (let i = 0; i < canonical.tasks.length; i += 1) {
    const task = canonical.tasks[i];
    const operatorTask = operator.tasks[i];
    if (!isObject(task) || !isObject(operatorTask) || task.case_id !== operatorTask.case_id) {
      fail(`task pairing failed at index ${i}`);
    }
    const build = strictExactBuild(task.build, `${task.case_id}.build`);
    const replaySha = strictSha(task.replay_sha, `${task.case_id}.replay_sha`);
    if (build !== operator.build || replaySha !== operator.replay_sha) {
      fail(`${task.case_id} build or replay SHA does not match operator template`);
    }
    if (!Array.isArray(task.decoder_events) || task.decoder_events.length === 0
      || !Array.isArray(task.observation_steps) || task.observation_steps.length < 2) {
      fail(`${task.case_id} lacks canonical decoder events or observation steps`);
    }
    if (task.human_millisecond_input !== 'FORBIDDEN'
      || task.human_time_precision !== 'GAME_CLOCK_INTEGER_SECOND') {
      fail(`${task.case_id} does not enforce the event-relative human timing contract`);
    }
    assertNoHumanTimingFields(operatorTask.answer_template, `${task.case_id}.operator.answer_template`);
    const eventMap = new Map();
    for (const event of task.decoder_events) {
      if (!isObject(event) || typeof event.event_id !== 'string'
        || !Number.isInteger(event.decoder_event_timestamp_ms) || event.decoder_event_timestamp_ms < 0) {
        fail(`${task.case_id} has invalid decoder event provenance`);
      }
      if (eventMap.has(event.event_id)) fail(`${task.case_id} has duplicate decoder event ${event.event_id}`);
      eventMap.set(event.event_id, event);
    }
    const expectedFields = Array.isArray(task.expected_observation_fields) ? task.expected_observation_fields : [];
    if (expectedFields.length === 0) fail(`${task.case_id} lacks expected observation fields`);
    const operatorFields = Object.keys(operatorTask.answer_template ?? {});
    sameStrings(operatorFields, expectedFields, `${task.case_id} operator answer template fields`);
    const observedFields = [];
    for (const step of task.observation_steps) {
      if (!isObject(step) || !MANUAL_EVENT_RELATIONS.has(step.relation) || !eventMap.has(step.event_id)
        || !Array.isArray(step.hud_fields) || step.hud_fields.length === 0
        || !Array.isArray(step.answer_fields) || step.answer_fields.length === 0) {
        fail(`${task.case_id} has invalid event-relative observation step`);
      }
      observedFields.push(...step.answer_fields);
    }
    const caseFields = expectedFields.filter((field) => !observedFields.includes(field));
    if (!caseFields.every((field) => Array.isArray(operatorTask.case_level_answer_fields)
      && operatorTask.case_level_answer_fields.includes(field))) {
      fail(`${task.case_id} operator case-level fields are incomplete`);
    }
    result.push({ task, operatorTask, eventMap, expectedFields, caseFields });
  }
  return result;
}

function parseClock(value, label) {
  const match = /^(\d{2}):(\d{2})$/.exec(requiredString(value, label));
  if (!match || Number(match[2]) > 59) fail(`${label} must be MM:SS with an integer visible game second`);
  return { display: value.trim(), second: Number(match[1]) * 60 + Number(match[2]) };
}

function parseHudValue(value, label) {
  const normalized = requiredString(value, label).toUpperCase();
  if (HUD_VALUE_ENUMS.has(normalized)) return normalized;
  if (!/^\d+$/.test(normalized)) fail(`${label} must be a non-negative integer HUD value, NOT_VISIBLE, or UNCLEAR`);
  return Number(normalized);
}

function enumValue(value, label, allowed) {
  const normalized = requiredString(value, label).toUpperCase();
  if (!allowed.has(normalized)) fail(`${label} has an unsupported value ${normalized}`);
  return normalized;
}

function normalizedAnswer(value, field, label) {
  if (field.startsWith('game_clock_second_')) return parseClock(value, label);
  if (/^(CURRENT_HP|MAX_HP|ARMOR|MAGIC_RESIST)_.*_numeric$/.test(field)) return parseHudValue(value, label);
  if (field.startsWith('screenshot_or_frame_ref_') || field === 'interval_frame_evidence_refs') {
    return requiredString(value, label);
  }
  if (field.startsWith('shield_indicator_')) return enumValue(value, label, INDICATOR_ENUMS);
  if (field === 'continuous_hp_change_observed' || field === 'shield_and_damage_states_separable') {
    return enumValue(value, label, YES_NO_UNCLEAR);
  }
  if (field === 'competing_hp_source_review') return enumValue(value, label, COMPETING_HP_SOURCE_VALUES);
  if (field === 'frame_boundary_notes') return value.trim() === '' ? null : value.trim();
  fail(`${label} is not a recognized canonical answer field`);
}

function answerForStep(step, answers, caseId) {
  const values = {};
  for (const field of step.answer_fields) {
    if (!answers.has(field)) fail(`${caseId}.${field} is required`);
    values[field] = normalizedAnswer(answers.get(field), field, `${caseId}.${field}`);
  }
  const clockField = step.answer_fields.find((field) => field.startsWith('game_clock_second_'));
  const frameField = step.answer_fields.find((field) => field.startsWith('screenshot_or_frame_ref_'));
  if (!clockField || !frameField) fail(`${caseId}.${step.observation_id} lacks required clock/frame fields`);
  const hudValues = {};
  const indicatorValues = {};
  for (const field of step.answer_fields) {
    const hud = /^(CURRENT_HP|MAX_HP|ARMOR|MAGIC_RESIST)_.*_numeric$/.exec(field);
    if (hud) hudValues[hud[1]] = values[field];
    if (field.startsWith('shield_indicator_')) indicatorValues.SHIELD_INDICATOR = values[field];
  }
  for (const semantic of step.hud_fields) {
    if (!Object.hasOwn(hudValues, semantic)) fail(`${caseId}.${step.observation_id} lacks HUD answer for ${semantic}`);
  }
  return {
    observation_id: step.observation_id,
    relation: step.relation,
    event_id: step.event_id,
    game_clock: values[clockField],
    screenshot_or_frame_ref: values[frameField],
    hud_values: hudValues,
    indicator_values: indicatorValues,
    answer_values: values,
  };
}

function deriveIntervalSummary(task, observations, caseAnswers) {
  if (task.variable !== 'HP_CHANGE_OVER_INTERVAL') return null;
  const definition = task.interval_definition;
  if (!isObject(definition)) fail(`${task.case_id} lacks interval definition`);
  function resolveBoundary(prefix) {
    const idKey = `${prefix}_observation_id`;
    const eventKey = `${prefix}_event_id`;
    const relationKey = `${prefix}_relation`;
    const byId = definition[idKey] === undefined ? []
      : observations.filter((row) => row.observation_id === definition[idKey]);
    const hasEventSelector = definition[eventKey] !== undefined || definition[relationKey] !== undefined;
    if (hasEventSelector && (typeof definition[eventKey] !== 'string'
      || !MANUAL_EVENT_RELATIONS.has(definition[relationKey]))) {
      fail(`${task.case_id} interval ${prefix} boundary must supply canonical event_id and relation`);
    }
    const byEventRelation = !hasEventSelector ? [] : observations.filter((row) => row.event_id === definition[eventKey]
      && row.relation === definition[relationKey]);
    if (byId.length > 1 || byEventRelation.length > 1) {
      fail(`${task.case_id} interval ${prefix} boundary is ambiguous`);
    }
    if (byId.length === 0 && byEventRelation.length === 0) {
      fail(`${task.case_id} interval ${prefix} boundary does not resolve to an observation`);
    }
    if (byId.length === 1 && byEventRelation.length === 1 && byId[0].observation_id !== byEventRelation[0].observation_id) {
      fail(`${task.case_id} interval ${prefix} boundary selectors conflict`);
    }
    return byId[0] ?? byEventRelation[0];
  }
  const start = resolveBoundary('start');
  const end = resolveBoundary('end');
  const startHp = start.hud_values.CURRENT_HP;
  const endHp = end.hud_values.CURRENT_HP;
  const numericDelta = Number.isInteger(startHp) && Number.isInteger(endHp) ? endHp - startHp : null;
  return {
    manual_case_id: task.case_id,
    interval_start_observation_id: start.observation_id,
    interval_end_observation_id: end.observation_id,
    current_hp_start: startHp,
    current_hp_end: endHp,
    current_hp_delta: numericDelta,
    continuous_hp_change_observed: caseAnswers.continuous_hp_change_observed,
    interval_frame_evidence_refs: caseAnswers.interval_frame_evidence_refs,
    competing_hp_source_review: caseAnswers.competing_hp_source_review,
    natural_regen_attribution: 'NOT_ASSERTED_BY_MANUAL_REVIEW',
    causal_interpretation: 'NO_NATURAL_REGEN_OR_OTHER_HP_CAUSE_INFERRED',
  };
}

function normalizeHoldCases(value) {
  if (value === undefined || value === null) return new Map();
  const entries = Array.isArray(value)
    ? value
    : isObject(value) ? Object.entries(value).map(([case_id, reason]) => ({ case_id, reason }))
      : fail('hold_cases must be an array or a case_id-to-reason object');
  const result = new Map();
  for (const entry of entries) {
    const row = typeof entry === 'string'
      ? { case_id: entry.slice(0, entry.indexOf(':')), reason: entry.slice(entry.indexOf(':') + 1) }
      : entry;
    if (!isObject(row) || typeof row.case_id !== 'string' || typeof row.reason !== 'string'
      || row.case_id.trim() === '' || row.reason.trim() === '') {
      fail('each held case requires CASE_ID and a non-empty explicit reason');
    }
    const caseId = row.case_id.trim();
    if (!EXPECTED_CASE_IDS.includes(caseId)) fail(`hold case ${caseId} is not one of the required case IDs`);
    if (result.has(caseId)) fail(`duplicate hold disposition for ${caseId}`);
    result.set(caseId, row.reason.trim());
  }
  return result;
}

function buildCompletedData(parsedCases, pairedTasks, inputHashes, holdCases) {
  const completedCases = [];
  const oracleRecords = [];
  const intervalSummaries = [];
  for (const pair of pairedTasks) {
    const { task, expectedFields, caseFields, eventMap } = pair;
    const answers = parsedCases.get(task.case_id);
    if (!answers) fail(`missing CASE_ID ${task.case_id}`);
    const suppliedFields = [...answers.keys()];
    const unknown = suppliedFields.filter((field) => !expectedFields.includes(field));
    if (unknown.length) fail(`${task.case_id} includes unknown answer field(s): ${unknown.join(', ')}`);
    const missing = expectedFields.filter((field) => !answers.has(field));
    if (missing.length) fail(`${task.case_id} misses required answer field(s): ${missing.join(', ')}`);
    const observations = task.observation_steps.map((step) => ({
      ...answerForStep(step, answers, task.case_id),
      decoder_event: {
        event_id: eventMap.get(step.event_id).event_id,
        semantic: eventMap.get(step.event_id).semantic,
        decoder_event_timestamp_ms: eventMap.get(step.event_id).decoder_event_timestamp_ms,
      },
    }));
    const caseAnswers = Object.fromEntries(caseFields.map((field) => [
      field,
      normalizedAnswer(answers.get(field), field, `${task.case_id}.${field}`),
    ]));
    const interval = deriveIntervalSummary(task, observations, caseAnswers);
    if (interval) intervalSummaries.push(interval);
    const holdReason = holdCases.get(task.case_id) ?? null;
    for (const observation of observations) {
      if (holdReason) continue;
      const event = eventMap.get(observation.event_id);
      for (const [semantic, observedValue] of Object.entries(observation.hud_values)) {
        oracleRecords.push({
          case_id: `MANUAL:${task.case_id}:${observation.observation_id}:${semantic}`,
          replay_sha: task.replay_sha,
          exact_build: task.build,
          timestamp: event.decoder_event_timestamp_ms,
          entity: { champion: task.champion },
          semantic,
          observed_value: observedValue,
          before_after: observation.relation === 'LAST_STABLE_VISIBLE_BEFORE_EVENT' ? 'BEFORE' : 'AFTER',
          source: {
            fact_source: 'MANUAL_EVENT_RELATIVE_HUD_OBSERVATION_V2',
            manual_case_id: task.case_id,
            observation_id: observation.observation_id,
            relation: observation.relation,
            game_clock_second: observation.game_clock.second,
            game_clock_display: observation.game_clock.display,
            screenshot_or_frame_ref: observation.screenshot_or_frame_ref,
            frame_boundary_notes: caseAnswers.frame_boundary_notes ?? null,
            checklist_sha256: inputHashes.filled_text_sha256,
          },
          manual_or_machine: 'MANUAL',
          confidence: 'MANUAL',
          notes: 'Visible HUD observation only; no item, shield-absorption, or causal attribution inferred.',
          frame_boundary_evidence: {
            screenshot_or_frame_ref: observation.screenshot_or_frame_ref,
            game_clock_display: observation.game_clock.display,
            relation: observation.relation,
            frame_boundary_notes: caseAnswers.frame_boundary_notes ?? null,
          },
        });
      }
    }
    completedCases.push({
      case_id: task.case_id,
      variable: task.variable,
      exact_build: task.build,
      replay_sha: task.replay_sha,
      champion: task.champion,
      decoder_events: task.decoder_events.map((event) => ({
        event_id: event.event_id,
        semantic: event.semantic,
        decoder_event_timestamp_ms: event.decoder_event_timestamp_ms,
      })),
      observations,
      case_level_answers: caseAnswers,
      non_scalar_answers: Object.fromEntries(Object.entries(caseAnswers)
        .filter(([, value]) => !Number.isInteger(value))),
      import_disposition: holdReason ? 'HELD_NO_ORACLE_RECORDS' : 'IMPORTED_TO_MANUAL_ORACLE',
      ...(holdReason ? { hold_reason: holdReason } : {}),
      ...(interval ? { hp_interval_summary: interval } : {}),
    });
  }
  const suppliedIds = [...parsedCases.keys()].sort();
  const expectedIds = [...EXPECTED_CASE_IDS].sort();
  if (JSON.stringify(suppliedIds) !== JSON.stringify(expectedIds)) {
    fail('filled text CASE_ID set does not exactly match the required 12 case IDs');
  }
  const oracleSourceProvenance = {
    kind: 'COMPLETED_EVENT_RELATIVE_MANUAL_CHECKLIST_V2',
    filled_text_sha256: inputHashes.filled_text_sha256,
    operator_template_sha256: inputHashes.operator_template_sha256,
    canonical_tasks_sha256: inputHashes.canonical_tasks_sha256,
    held_cases: [...holdCases.entries()].map(([case_id, reason]) => ({ case_id, reason })),
    automatic_promotion: 'FORBIDDEN',
  };
  const oracle = oracleRecords.length > 0 ? createGroundTruthOracle(oracleRecords, {
    source_provenance: oracleSourceProvenance,
  }) : {
    schema_version: 'GROUND_TRUTH_ORACLE_V1',
    exact_build_only: true,
    decoder_routes_or_offsets_in_truth: 'FORBIDDEN',
    generated_at_omitted_for_reproducibility: true,
    source_provenance: oracleSourceProvenance,
    records: [],
  };
  return {
    completed: {
      schema_version: COMPLETED_SCHEMA,
      exact_build: completedCases[0].exact_build,
      replay_sha: completedCases[0].replay_sha,
      case_count: completedCases.length,
      human_timing_contract: 'EVENT_RELATIVE_VISIBLE_GAME_CLOCK_INTEGER_SECOND_ONLY',
      decoder_timestamp_provenance: 'CANONICAL_DECODER_EVENTS_ONLY',
      automatic_promotion: 'FORBIDDEN',
      held_cases: [...holdCases.entries()].map(([case_id, reason]) => ({ case_id, reason })),
      input_sha256: inputHashes,
      cases: completedCases,
      hp_interval_summaries: intervalSummaries,
    },
    oracle: {
      ...oracle,
      automatic_promotion: 'FORBIDDEN',
      manual_confidence_only: true,
      interval_hp_causal_inference: 'FORBIDDEN',
      shield_absorption_inference: 'FORBIDDEN',
      item_cause_inference: 'FORBIDDEN',
    },
  };
}

function atomicWriteJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const temporary = `${filePath}.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`;
  try {
    fs.writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
    fs.renameSync(temporary, filePath);
  } finally {
    if (fs.existsSync(temporary)) fs.unlinkSync(temporary);
  }
}

function outputManifest(outputDirectory, outputPaths, inputHashes) {
  return {
    schema_version: IMPORT_MANIFEST_SCHEMA,
    generated_at_omitted_for_reproducibility: true,
    input_sha256: inputHashes,
    output_count: outputPaths.length,
    outputs: outputPaths.map((filePath) => ({
      path: path.relative(outputDirectory, filePath).replaceAll('\\', '/'),
      sha256: sha256File(filePath),
      byte_size: fs.statSync(filePath).size,
    })).sort((a, b) => a.path.localeCompare(b.path)),
    manifest_self_hash: 'OMITTED_TO_AVOID_SELF_REFERENCE',
    protected_boundary: {
      enumerated: false, read: false, hashed: false, decoded: false, tested: false, consumed: false,
    },
  };
}

function importCompletedManualGroundTruth(options = {}) {
  const requiredOptions = ['filled_text_path', 'operator_template_path', 'canonical_tasks_path', 'output_directory'];
  for (const key of requiredOptions) requiredString(options[key], key);
  const paths = Object.fromEntries(requiredOptions.map((key) => [key, path.resolve(options[key])]));
  for (const [key, filePath] of Object.entries(paths)) assertNoProtectedReference(filePath, key);
  for (const key of ['filled_text_path', 'operator_template_path', 'canonical_tasks_path']) {
    if (!fs.existsSync(paths[key]) || !fs.statSync(paths[key]).isFile()) fail(`${key} must be a readable file`);
  }
  const filledText = fs.readFileSync(paths.filled_text_path, 'utf8');
  const operator = readJson(paths.operator_template_path, 'operator template');
  const canonical = readJson(paths.canonical_tasks_path, 'canonical tasks');
  assertNoProtectedReference(operator, 'operator template');
  assertNoProtectedReference(canonical, 'canonical tasks');
  const inputHashes = {
    filled_text_sha256: sha256(Buffer.from(filledText, 'utf8')),
    operator_template_sha256: sha256File(paths.operator_template_path),
    canonical_tasks_sha256: sha256File(paths.canonical_tasks_path),
  };
  const pairedTasks = validateTaskPairing(operator, canonical);
  const parsed = parseCompletedChecklistText(filledText);
  const holdCases = normalizeHoldCases(options.hold_cases);
  const { completed, oracle } = buildCompletedData(parsed, pairedTasks, inputHashes, holdCases);
  const report = {
    schema_version: IMPORT_REPORT_SCHEMA,
    status: 'PASS',
    exact_build: completed.exact_build,
    replay_sha: completed.replay_sha,
    expected_case_count: 12,
    completed_case_count: completed.case_count,
    imported_case_count: completed.case_count - completed.held_cases.length,
    oracle_record_count: oracle.records.length,
    hp_interval_summary_count: completed.hp_interval_summaries.length,
    held_case_count: completed.held_cases.length,
    held_cases: completed.held_cases,
    input_sha256: inputHashes,
    validation: {
      exact_case_id_set: 'PASS',
      build_and_replay_sha_pairing: 'PASS',
      event_relative_human_timing_only: 'PASS',
      decoder_timestamps_from_canonical_only: 'PASS',
      required_hud_clock_and_frame_answers: 'PASS',
      automatic_promotion: 'FORBIDDEN',
      natural_regen_attribution: 'NOT_ASSERTED_BY_MANUAL_REVIEW',
      shield_absorption_inference: 'FORBIDDEN',
      item_cause_inference: 'FORBIDDEN',
      explicit_hold_dispositions: completed.held_cases.length ? 'APPLIED' : 'NONE',
    },
  };
  const outputDirectory = paths.output_directory;
  const completedPath = path.join(outputDirectory, 'completed_manual_ground_truth.json');
  const oraclePath = path.join(outputDirectory, 'manual_ground_truth_oracle.json');
  const reportPath = path.join(outputDirectory, 'manual_ground_truth_import_report.json');
  atomicWriteJson(completedPath, completed);
  atomicWriteJson(oraclePath, oracle);
  atomicWriteJson(reportPath, report);
  const manifestPath = path.join(outputDirectory, 'artifact_manifest.json');
  atomicWriteJson(manifestPath, outputManifest(outputDirectory, [completedPath, oraclePath, reportPath], inputHashes));
  return {
    status: 'PASS',
    output_directory: outputDirectory,
    completed_manual_ground_truth: completedPath,
    manual_ground_truth_oracle: oraclePath,
    manual_ground_truth_import_report: reportPath,
    artifact_manifest: manifestPath,
    oracle_record_count: oracle.records.length,
  };
}

module.exports = {
  COMPLETED_SCHEMA,
  EXPECTED_CASE_IDS,
  IMPORT_MANIFEST_SCHEMA,
  IMPORT_REPORT_SCHEMA,
  OPERATOR_SCHEMA,
  importCompletedManualGroundTruth,
  normalizeHoldCases,
  parseCompletedChecklistText,
  stripKnownInlineFillHint,
  validateTaskPairing,
};

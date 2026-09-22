'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  CONTROLLED_REPLAY_REQUEST_SPECS,
  GROUND_TRUTH_ORACLE_SCHEMA_VERSION,
  alignGroundTruthOracle,
  createGroundTruthOracle,
  controlledCalibrationBatchSchemaDocument,
  formatManualGroundTruthTasks,
  generateManualValidationCases,
  groundTruthAlignmentSchemaDocument,
  groundTruthOracleSchemaDocument,
  importControlledCalibrationBatch,
  manualValidationTasksSchemaDocument,
  oracleRecordsFromDetailsP0,
} = require('../src/controlled_calibration');

const SHA = 'a'.repeat(64);

function oracleRecord(overrides = {}) {
  return {
    case_id: 'case-1', replay_sha: SHA, exact_build: '16.16.805.0442', timestamp: 1000,
    entity: { participant_id: 1, champion: 'Ahri' }, semantic: 'CURRENT_HP', observed_value: 731,
    before_after: 'AFTER', source: { kind: 'REPLAY_UI' }, manual_or_machine: 'MANUAL',
    confidence: 'HIGH', notes: 'UI ground truth', ...overrides,
  };
}

test('GroundTruthOracle is versioned, complete, deterministic, and excludes decoder layout', () => {
  const oracle = createGroundTruthOracle([oracleRecord({ case_id: 'z' }), oracleRecord({ case_id: 'a' })]);
  assert.equal(oracle.schema_version, GROUND_TRUTH_ORACLE_SCHEMA_VERSION);
  assert.deepEqual(oracle.records.map((row) => row.case_id), ['a', 'z']);
  assert.equal(oracle.decoder_routes_or_offsets_in_truth, 'FORBIDDEN');
  assert.throws(() => createGroundTruthOracle([oracleRecord({ packet_route: '0x0123' })]), /cannot be ground truth/);
  assert.throws(() => createGroundTruthOracle([oracleRecord({ semantic: 'ARMOR', entity: null, champion: '' })]), /entity or champion/);
  assert.throws(() => createGroundTruthOracle([oracleRecord({ exact_build: '16.16' })]), /N.N.N.N/);
  assert.throws(() => createGroundTruthOracle([oracleRecord({ observed_value: Number.NaN })]), /JSON-safe/);
  assert.throws(() => createGroundTruthOracle([oracleRecord({ before_after: 'FRAME' })]), /before_after must be one of/);
});

test('DETAILS P0 anchors convert to four semantic-only oracle records', () => {
  const oracle = oracleRecordsFromDetailsP0([{
    anchor_id: '42:60000:1:p0', replay_sha256: SHA, replay_build: '16.16.805.0442', timestamp_ms: 60000,
    entity: { participant_id: 1, champion: 'Ahri' }, current_hp: 100, max_hp: 200, armor: 50,
    magic_resist: 30, frame_boundary_evidence: { health_transition: 'POSITIVE_TO_POSITIVE' },
    source: { fact_source: 'DETAILS_P0_GROUND_TRUTH_V1' },
  }]);
  assert.deepEqual(oracle.records.map((row) => row.semantic), ['ARMOR', 'CURRENT_HP', 'MAGIC_RESIST', 'MAX_HP']);
  assert.equal(oracle.records.find((row) => row.semantic === 'MAX_HP').observed_value, 200);
  const hp = oracle.records.find((row) => row.semantic === 'CURRENT_HP');
  assert.equal(hp.before_after, 'SNAPSHOT');
  assert.deepEqual(hp.frame_boundary_evidence, { health_transition: 'POSITIVE_TO_POSITIVE' });
});

test('controlled batch only reads explicit regular files, hashes on request, and blocks holdout before I/O', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'controlled-calibration-'));
  try {
    const fixture = path.join(directory, 'fixture.rofl');
    fs.writeFileSync(fixture, 'fixture');
    const batch = importControlledCalibrationBatch({ files: [{
      id: 'r1', kind: 'REPLAY', path: fixture, exact_build: '16.16.805.0442', source: 'USER_SUPPLIED', hash: true,
    }] });
    assert.equal(batch.directory_discovery, 'FORBIDDEN');
    assert.equal(batch.inputs[0].sha256, crypto.createHash('sha256').update('fixture').digest('hex'));
    assert.equal(batch.protected_holdout.hash, false);
    assert.throws(() => importControlledCalibrationBatch({ files: [{
      id: 'bad-build', path: fixture, exact_build: '16.16', source: 'USER_SUPPLIED',
    }] }), /N.N.N.N/);
    assert.throws(() => importControlledCalibrationBatch({ files: [{
      id: 'blocked', path: path.join(directory, 'JUNGLE_OBJECTIVE_HOLDOUT_V1.rofl'), exact_build: '16.16.805.0442', source: 'USER_SUPPLIED', hash: true,
    }] }), /protected Holdout/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('alignment is exact replay/build/semantic/entity plus bounded timestamp and preserves ambiguity', () => {
  const oracle = createGroundTruthOracle([oracleRecord()]);
  const row = { replay_sha: SHA, exact_build: '16.16.805.0442', timestamp: 1004,
    entity: { participant_id: 1, champion: 'Ahri' }, semantic: 'CURRENT_HP', value: 700, confidence: 'CANDIDATE' };
  const matched = alignGroundTruthOracle(oracle, [row], { timestamp_tolerance_ms: 5 });
  assert.equal(matched.results[0].status, 'MATCHED');
  assert.equal(matched.results[0].residual, -31);
  assert.equal(matched.results[0].candidate_semantic_status_preserved, 'CANDIDATE');
  const ambiguous = alignGroundTruthOracle(oracle, [row, { ...row, value: 699 }], { timestamp_tolerance_ms: 5 });
  assert.equal(ambiguous.results[0].status, 'AMBIGUOUS');
  const unmatched = alignGroundTruthOracle(oracle, [{ ...row, exact_build: '16.17.000.0001' }]);
  assert.equal(unmatched.results[0].status, 'UNMATCHED');
});

test('manual tasks use event-relative integer-second observations, cap at twenty, and render no human millisecond request', () => {
  const hypotheses = Array.from({ length: 22 }, (_, index) => ({
    case_id: `case-${String(index).padStart(2, '0')}`, replay: `replay-${index}.rofl`, replay_sha: SHA,
    exact_build: '16.16.805.0442', champion: 'Ahri', semantic: 'CURRENT_HP', information_gain: index,
    decoder_events: [{ event_id: 'damage', semantic: 'DAMAGE', decoder_event_timestamp_ms: 1000 + index }],
    observation_steps: [
      { observation_id: 'before', relation: 'LAST_STABLE_VISIBLE_BEFORE_EVENT', event_id: 'damage', hud_fields: ['CURRENT_HP', 'MAX_HP'], answer_fields: ['CURRENT_HP_BEFORE'] },
      { observation_id: 'after', relation: 'FIRST_STABLE_VISIBLE_AFTER_EVENT', event_id: 'damage', hud_fields: ['CURRENT_HP', 'MAX_HP'], answer_fields: ['CURRENT_HP_AFTER'] },
    ],
    competing_hypotheses: ['candidate A is CURRENT_HP', 'candidate B is display HP'],
    expected_observation_fields: ['CURRENT_HP_BEFORE', 'CURRENT_HP_AFTER'], rationale: 'The before/after delta distinguishes candidates.',
  }));
  const batch = generateManualValidationCases(hypotheses);
  assert.equal(batch.task_count, 20);
  assert.equal(batch.tasks[0].case_id, 'case-21');
  assert.equal(batch.tasks[0].decoder_events[0].decoder_event_timestamp_ms, 1021);
  assert.equal(batch.tasks[0].human_time_precision, 'GAME_CLOCK_INTEGER_SECOND');
  assert.equal(batch.tasks[0].human_millisecond_input, 'FORBIDDEN');
  const rendered = formatManualGroundTruthTasks(batch);
  assert.match(rendered, /CASE_ID: case-21/);
  assert.match(rendered, /Expected observation format:\nCURRENT_HP_BEFORE = \?/);
  assert.match(rendered, /Fixed relation: LAST_STABLE_VISIBLE_BEFORE_EVENT \(damage\)/);
  assert.match(rendered, /Answers:\nCURRENT_HP_BEFORE = \?/);
  assert.doesNotMatch(rendered, /Timestamp:|millisecond timestamp|Before timestamp|After timestamp/);
  assert.match(rendered, /Competing hypotheses:\nA\./);
  assert.equal(generateManualValidationCases(hypotheses.slice(0, 1)).task_count, 1);
  for (const forbiddenField of [
    'before_timestamp_ms', 'actual_pause_before_ms', 'actual_pause_after_ms',
    'actual_pause_intermediate_ms', 'allowed_window_ms', 'fixed_tolerance_ms', 'target_ms',
    'pause_ms', 'manual_pause_timestamp_ms', 'tolerance_seconds', 'target_time_seconds',
    'selection_window_seconds', 'event_deviation_seconds', 'target-time-seconds',
  ]) {
    assert.throws(
      () => generateManualValidationCases([{ ...hypotheses[0], [forbiddenField]: 900 }]),
      /human millisecond timing/,
    );
    assert.throws(
      () => generateManualValidationCases([{ ...hypotheses[0], expected_observation_fields: [forbiddenField] }]),
      /human millisecond timing/,
    );
  }
  assert.throws(() => generateManualValidationCases([{
    ...hypotheses[0],
    observation_steps: [{ ...hypotheses[0].observation_steps[0], timestamp_ms: 999 }, hypotheses[0].observation_steps[1]],
  }]), /human millisecond timing/);
  assert.throws(() => generateManualValidationCases([{
    ...hypotheses[0],
    decoder_events: [{ event_id: 'damage', semantic: 'DAMAGE', timestamp_ms: 1000 }],
  }]), /human millisecond timing/);
  assert.throws(() => generateManualValidationCases([{ ...hypotheses[0], observation_steps: [{
    observation_id: 'bad', relation: 'BEFORE', event_id: 'damage', hud_fields: ['CURRENT_HP'],
  }, hypotheses[0].observation_steps[1] ] }]), /relation must be one of/);
  assert.throws(() => generateManualValidationCases([{ ...hypotheses[0], observation_steps: [{
    ...hypotheses[0].observation_steps[0], answer_fields: ['NOT_IN_EXPECTED_FIELDS'],
  }, hypotheses[0].observation_steps[1] ] }]), /must belong to expected_observation_fields/);
  assert.throws(() => generateManualValidationCases([{ ...hypotheses[0], observation_steps: [{
    ...hypotheses[0].observation_steps[0], answer_fields: [],
  }, hypotheses[0].observation_steps[1] ] }]), /must be a non-empty array when provided/);
  assert.ok(CONTROLLED_REPLAY_REQUEST_SPECS.CALIBRATION_SET_A_HP_DEFENSE_V1.actions.includes('BUY_ARMOR_ITEM'));
  assert.ok(CONTROLLED_REPLAY_REQUEST_SPECS.CALIBRATION_SET_A_HP_DEFENSE_V1.principles.includes('RECORD_EVENT_RELATIVE_STABLE_VISIBLE_STATES'));
  assert.ok(CONTROLLED_REPLAY_REQUEST_SPECS.CALIBRATION_SET_A_HP_DEFENSE_V1.prohibited_interpretations.includes('NATURAL_REGEN_IS_NOT_A_POINT_EVENT_OR_RAW_HP_DELTA_ATTRIBUTION'));
});

test('continuous HP interval cases require event-relative boundaries and prohibit natural-regen attribution', () => {
  const common = {
    case_id: 'hp-interval', replay: 'replay.rofl', replay_sha: SHA, exact_build: '16.16.805.0442',
    champion: 'Kayn', semantic: 'HP_CHANGE_OVER_INTERVAL', information_gain: 9,
    decoder_events: [
      { event_id: 'damage', semantic: 'DAMAGE', decoder_event_timestamp_ms: 21667 },
      { event_id: 'heal', semantic: 'HEAL_REPORTED', decoder_event_timestamp_ms: 45212 },
    ],
    observation_steps: [
      { observation_id: 'start', relation: 'FIRST_STABLE_VISIBLE_AFTER_EVENT', event_id: 'damage', hud_fields: ['CURRENT_HP', 'MAX_HP'] },
      { observation_id: 'end', relation: 'LAST_STABLE_VISIBLE_BEFORE_EVENT', event_id: 'heal', hud_fields: ['CURRENT_HP', 'MAX_HP'] },
    ],
    expected_observation_fields: ['CURRENT_HP_INTERVAL_START', 'CURRENT_HP_INTERVAL_END'],
    competing_hypotheses: ['unattributed HP change over interval', 'another visible HP source'],
    rationale: 'Records an interval without assigning its cause.',
  };
  const batch = generateManualValidationCases([{ ...common,
    interval_definition: {
      start_event_id: 'damage', start_relation: 'FIRST_STABLE_VISIBLE_AFTER_EVENT',
      end_event_id: 'heal', end_relation: 'LAST_STABLE_VISIBLE_BEFORE_EVENT',
    },
    competing_hp_source_review: { heal_cast_seen: false, consumable_seen: false, fountain_seen: false },
  }]);
  const task = batch.tasks[0];
  assert.equal(task.variable, 'HP_CHANGE_OVER_INTERVAL');
  assert.equal(task.natural_regen_attribution, 'NOT_ASSERTED_BY_MANUAL_REVIEW');
  assert.match(formatManualGroundTruthTasks(batch), /Do not label any HP change as natural regen/);
  assert.throws(() => generateManualValidationCases([common]), /requires interval_definition/);
  assert.throws(() => generateManualValidationCases([{ ...common, interval_definition: {
    start_event_id: 'damage', start_relation: 'FIRST_STABLE_VISIBLE_AFTER_EVENT',
    end_event_id: 'heal', end_relation: 'LAST_STABLE_VISIBLE_BEFORE_EVENT',
  } }]), /requires competing_hp_source_review/);
});

test('versioned schema-document factories describe all controlled-calibration contracts', () => {
  const oracle = groundTruthOracleSchemaDocument();
  assert.equal(oracle.schema_version, GROUND_TRUTH_ORACLE_SCHEMA_VERSION);
  assert.ok(oracle.before_after_enum.includes('SNAPSHOT'));
  assert.equal(controlledCalibrationBatchSchemaDocument().directory_discovery, 'FORBIDDEN');
  assert.deepEqual(groundTruthAlignmentSchemaDocument().preserved_nonmatches, ['UNMATCHED', 'AMBIGUOUS']);
  const manual = manualValidationTasksSchemaDocument();
  assert.equal(manual.max_cases, 20);
  assert.equal(manual.human_millisecond_input, 'FORBIDDEN');
  assert.equal(manual.decoder_event_timestamp_ms, 'MACHINE_PROVENANCE_ONLY');
  assert.ok(manual.observation_relation_enum.includes('FIRST_STABLE_VISIBLE_AFTER_EVENT'));
});

'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const {
  EXPECTED_CASE_IDS,
  importCompletedManualGroundTruth,
} = require('../src/manual_ground_truth_import');

const BUILD = '16.16.805.0442';
const REPLAY_SHA = '1fb1321e802103ce8e20e670b981b8b59d43a1fbbdc911f79ba249257ed672ff';

function writeJson(filePath, value) {
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function basicTask(caseId, index) {
  const semantic = index >= 8 ? 'MAGIC_RESIST' : index >= 6 ? 'ARMOR' : 'MAX_HP';
  const before = {
    observation_id: 'before_action',
    relation: 'LAST_STABLE_VISIBLE_BEFORE_EVENT',
    event_id: 'action',
    hud_fields: [semantic],
    answer_fields: [`game_clock_second_before_action`, `${semantic}_before_action_numeric`, 'screenshot_or_frame_ref_before_action'],
  };
  const after = {
    observation_id: 'after_action',
    relation: 'FIRST_STABLE_VISIBLE_AFTER_EVENT',
    event_id: 'action',
    hud_fields: [semantic],
    answer_fields: ['game_clock_second_after_action', `${semantic}_after_action_numeric`, 'screenshot_or_frame_ref_after_action'],
  };
  return {
    case_id: caseId,
    replay: 'C:/controlled/HN1.rofl',
    replay_sha: REPLAY_SHA,
    build: BUILD,
    champion: 'Kayn',
    variable: semantic,
    decoder_events: [{ event_id: 'action', semantic: 'CONTROLLED_ACTION', decoder_event_timestamp_ms: 1000 + index }],
    observation_steps: [before, after],
    human_time_precision: 'GAME_CLOCK_INTEGER_SECOND',
    human_millisecond_input: 'FORBIDDEN',
    expected_observation_fields: [...before.answer_fields, ...after.answer_fields, 'frame_boundary_notes'],
  };
}

function fixtureDocuments() {
  const tasks = EXPECTED_CASE_IDS.map(basicTask);
  const interval = tasks[0];
  interval.variable = 'HP_CHANGE_OVER_INTERVAL';
  interval.decoder_events = [
    { event_id: 'damage', semantic: 'DAMAGE', decoder_event_timestamp_ms: 21000 },
    { event_id: 'heal_interval_boundary', semantic: 'HEAL', decoder_event_timestamp_ms: 45000 },
  ];
  interval.observation_steps = [
    {
      observation_id: 'interval_start_after_damage', relation: 'FIRST_STABLE_VISIBLE_AFTER_EVENT', event_id: 'damage',
      hud_fields: ['CURRENT_HP', 'MAX_HP'],
      answer_fields: ['game_clock_second_interval_start', 'CURRENT_HP_interval_start_numeric', 'MAX_HP_interval_start_numeric', 'screenshot_or_frame_ref_interval_start'],
    },
    {
      observation_id: 'interval_end_before_heal', relation: 'LAST_STABLE_VISIBLE_BEFORE_EVENT', event_id: 'heal_interval_boundary',
      hud_fields: ['CURRENT_HP', 'MAX_HP'],
      answer_fields: ['game_clock_second_interval_end', 'CURRENT_HP_interval_end_numeric', 'MAX_HP_interval_end_numeric', 'screenshot_or_frame_ref_interval_end'],
    },
  ];
  interval.interval_definition = {
    start_event_id: 'damage', start_relation: 'FIRST_STABLE_VISIBLE_AFTER_EVENT',
    end_event_id: 'heal_interval_boundary', end_relation: 'LAST_STABLE_VISIBLE_BEFORE_EVENT',
  };
  interval.expected_observation_fields = [
    ...interval.observation_steps.flatMap((step) => step.answer_fields),
    'continuous_hp_change_observed', 'interval_frame_evidence_refs', 'competing_hp_source_review', 'frame_boundary_notes',
  ];
  const shield = tasks[2];
  shield.observation_steps[0].answer_fields.splice(2, 0, 'shield_indicator_before_action');
  shield.observation_steps[1].answer_fields.splice(2, 0, 'shield_indicator_after_action');
  shield.expected_observation_fields = [
    ...shield.observation_steps.flatMap((step) => step.answer_fields),
    'shield_and_damage_states_separable', 'frame_boundary_notes',
  ];
  const canonical = {
    schema_version: 'MANUAL_GROUND_TRUTH_TASKS_V2', task_count: 12, tasks,
  };
  const operator = {
    schema_version: 'MANUAL_GROUND_TRUTH_OPERATOR_CHECKLIST_ZH_V2_EVENT_RELATIVE',
    source_schema_version: 'MANUAL_GROUND_TRUTH_TASKS_V2',
    build: BUILD, replay_sha: REPLAY_SHA, task_count: 12,
    tasks: tasks.map((task) => ({
      case_id: task.case_id,
      answer_template: Object.fromEntries(task.expected_observation_fields.map((field) => [field, null])),
      case_level_answer_fields: task.expected_observation_fields.filter((field) => !task.observation_steps.some((step) => step.answer_fields.includes(field))),
    })),
  };
  return { canonical, operator };
}

function answerForField(field, counter) {
  if (field.startsWith('game_clock_second_')) return '00:21';
  if (/^(CURRENT_HP|MAX_HP|ARMOR|MAGIC_RESIST)_.*_numeric$/.test(field)) return String(500 + counter);
  if (field.startsWith('screenshot_or_frame_ref_')) return `frame-${counter}.png`;
  if (field.startsWith('shield_indicator_')) return 'PRESENT';
  if (field === 'continuous_hp_change_observed' || field === 'shield_and_damage_states_separable') return 'YES （只填 YES / NO / UNCLEAR）';
  if (field === 'interval_frame_evidence_refs') return 'frame-interval-a.png/frame-interval-b.png';
  if (field === 'competing_hp_source_review') return 'NO_OTHER_VISIBLE_HP_SOURCE（只填 NO_OTHER_VISIBLE_HP_SOURCE / OTHER_HP_SOURCE_VISIBLE / UNCLEAR）';
  if (field === 'frame_boundary_notes') return '';
  throw new Error(`missing fixture answer for ${field}`);
}

function fixtureText(operator) {
  let counter = 0;
  return operator.tasks.map((task) => {
    const lines = [`CASE_ID: ${task.case_id}`];
    for (const field of Object.keys(task.answer_template)) lines.push(`${field} = ${answerForField(field, counter += 1)}`);
    return lines.join('\n');
  }).join('\n\n---\n\n');
}

function createFixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'manual-ground-truth-import-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const { canonical, operator } = fixtureDocuments();
  const canonicalPath = path.join(directory, 'canonical.json');
  const operatorPath = path.join(directory, 'operator.json');
  const textPath = path.join(directory, 'filled.txt');
  writeJson(canonicalPath, canonical);
  writeJson(operatorPath, operator);
  fs.writeFileSync(textPath, fixtureText(operator));
  return { directory, canonical, operator, canonicalPath, operatorPath, textPath };
}

function runFixture(fixture, extra = {}) {
  return importCompletedManualGroundTruth({
    filled_text_path: fixture.textPath,
    operator_template_path: fixture.operatorPath,
    canonical_tasks_path: fixture.canonicalPath,
    output_directory: path.join(fixture.directory, 'out'),
    ...extra,
  });
}

test('imports actual-like event-relative text deterministically with interval non-attribution', (t) => {
  const fixture = createFixture(t);
  const first = runFixture(fixture, {
    hold_cases: { 'P0-STATS-06-LEVEL-UP': 'HUD stat updates have separate visible boundaries.' },
  });
  const outputA = fs.readFileSync(first.completed_manual_ground_truth);
  const oracleA = fs.readFileSync(first.manual_ground_truth_oracle);
  const second = runFixture(fixture, {
    hold_cases: [{ case_id: 'P0-STATS-06-LEVEL-UP', reason: 'HUD stat updates have separate visible boundaries.' }],
  });
  assert.equal(fs.readFileSync(second.completed_manual_ground_truth).toString(), outputA.toString());
  assert.equal(fs.readFileSync(second.manual_ground_truth_oracle).toString(), oracleA.toString());
  const completed = JSON.parse(outputA);
  const oracle = JSON.parse(oracleA);
  assert.equal(completed.case_count, 12);
  assert.equal(completed.held_cases.length, 1);
  assert.equal(completed.hp_interval_summaries[0].current_hp_delta, 4);
  assert.equal(completed.hp_interval_summaries[0].natural_regen_attribution, 'NOT_ASSERTED_BY_MANUAL_REVIEW');
  assert.equal(completed.hp_interval_summaries[0].causal_interpretation, 'NO_NATURAL_REGEN_OR_OTHER_HP_CAUSE_INFERRED');
  assert.equal(oracle.records.some((row) => row.source.manual_case_id === 'P0-STATS-06-LEVEL-UP'), false);
  assert.ok(oracle.records.every((row) => row.manual_or_machine === 'MANUAL' && row.confidence === 'MANUAL'));
  assert.ok(oracle.records.every((row) => row.source.checklist_sha256 === crypto.createHash('sha256').update(fs.readFileSync(fixture.textPath)).digest('hex')));
  assert.equal(oracle.automatic_promotion, 'FORBIDDEN');
  assert.equal(JSON.parse(fs.readFileSync(first.manual_ground_truth_import_report, 'utf8')).imported_case_count, 11);
});

test('rejects malformed, missing, duplicate, wrong-ID, and human-millisecond manual values', (t) => {
  const fixture = createFixture(t);
  const text = fs.readFileSync(fixture.textPath, 'utf8');
  fs.writeFileSync(fixture.textPath, text.replace(/(CURRENT_HP_interval_start_numeric = )\d+/, '$1no-number'));
  assert.throws(() => runFixture(fixture), /non-negative integer HUD value/);
  fs.writeFileSync(fixture.textPath, text.replace(/MAX_HP_interval_start_numeric = \d+\n/, ''));
  assert.throws(() => runFixture(fixture), /misses required answer field/);
  fs.writeFileSync(fixture.textPath, text.replace(/(CURRENT_HP_interval_start_numeric = \d+\n)/, '$1$1'));
  assert.throws(() => runFixture(fixture), /duplicate answer/);
  fs.writeFileSync(fixture.textPath, text.replace('CASE_ID: P0-HP-02-HEAL', 'CASE_ID: WRONG-CASE'));
  assert.throws(() => runFixture(fixture), /missing CASE_ID|CASE_ID set/);
  fs.writeFileSync(fixture.textPath, `${text}\nhuman_pause_ms = 9\n`);
  assert.throws(() => runFixture(fixture), /human millisecond/);
});

test('rejects wrong canonical build/SHA and invalid hold dispositions', (t) => {
  const fixture = createFixture(t);
  fixture.operator.build = '16.16.805.0443';
  writeJson(fixture.operatorPath, fixture.operator);
  assert.throws(() => runFixture(fixture), /build or replay SHA/);
  fixture.operator.build = BUILD;
  fixture.operator.replay_sha = '0'.repeat(64);
  writeJson(fixture.operatorPath, fixture.operator);
  assert.throws(() => runFixture(fixture), /build or replay SHA/);
  fixture.operator.replay_sha = REPLAY_SHA;
  writeJson(fixture.operatorPath, fixture.operator);
  assert.throws(() => runFixture(fixture, { hold_cases: { 'WRONG-CASE': 'wrong' } }), /not one of the required/);
});

test('rejects missing or ambiguous canonical interval boundaries', (t) => {
  const fixture = createFixture(t);
  fixture.canonical.tasks[0].interval_definition.start_event_id = 'missing-event';
  writeJson(fixture.canonicalPath, fixture.canonical);
  assert.throws(() => runFixture(fixture), /start boundary does not resolve/);
  fixture.canonical.tasks[0].interval_definition.start_event_id = 'damage';
  fixture.canonical.tasks[0].observation_steps.push({
    ...fixture.canonical.tasks[0].observation_steps[0],
    observation_id: 'duplicate_interval_start_after_damage',
  });
  writeJson(fixture.canonicalPath, fixture.canonical);
  assert.throws(() => runFixture(fixture), /start boundary is ambiguous/);
});

test('CLI requires explicit paths and applies repeatable hold dispositions', (t) => {
  const fixture = createFixture(t);
  const script = path.join(__dirname, '..', 'scripts', 'import_completed_manual_ground_truth.js');
  const missing = spawnSync(process.execPath, [script], { encoding: 'utf8' });
  assert.notEqual(missing.status, 0);
  assert.match(missing.stderr, /Usage:/);
  const output = path.join(fixture.directory, 'cli-output');
  const invoked = spawnSync(process.execPath, [
    script,
    '--filled-text', fixture.textPath,
    '--operator-template', fixture.operatorPath,
    '--canonical-tasks', fixture.canonicalPath,
    '--output-directory', output,
    '--hold-case', 'P0-STATS-06-LEVEL-UP:separate visible stat boundaries',
  ], { encoding: 'utf8' });
  assert.equal(invoked.status, 0, invoked.stderr);
  assert.equal(JSON.parse(invoked.stdout).status, 'PASS');
  const report = JSON.parse(fs.readFileSync(path.join(output, 'manual_ground_truth_import_report.json'), 'utf8'));
  assert.deepEqual(report.held_cases, [{ case_id: 'P0-STATS-06-LEVEL-UP', reason: 'separate visible stat boundaries' }]);
  assert.equal(report.completed_case_count, 12);
  assert.equal(report.imported_case_count, 11);
  const protectedPath = spawnSync(process.execPath, [
    script,
    '--filled-text', fixture.textPath,
    '--operator-template', fixture.operatorPath,
    '--canonical-tasks', fixture.canonicalPath,
    '--output-directory', output,
    '--hold-cases-json', 'protected-holdout.json',
  ], { encoding: 'utf8' });
  assert.notEqual(protectedPath.status, 0);
  assert.match(protectedPath.stderr, /protected Holdout/);
});

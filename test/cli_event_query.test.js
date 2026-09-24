'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const CLI = path.resolve(__dirname, '../src/cli.js');
const SHA = 'a'.repeat(64);
const VERSION = '16.19.820.7193';
const EVENT = 'hero_level_state_candidates';
const CAPABILITY = 'hero_level_state';

function artifact(t, rows = [
  { replay_sha256: SHA, replay_time_ms: 0, participant_id_candidate: 1,
    confidence: 'CANDIDATE', field_confidence: { level: 'CANDIDATE' } },
  { replay_sha256: SHA, replay_time_ms: 1000, participant_id_candidate: null,
    confidence: 'CANDIDATE', raw_packet_ref: { replay_sha256: SHA } },
  { replay_sha256: SHA, replay_time_ms: 2000, participant_id_candidate: 1,
    confidence: 'CANDIDATE', raw_packet_ref: { replay_sha256: SHA } },
  { replay_sha256: SHA, replay_time_ms: 2000, participant_id_candidate: 2,
    confidence: 'CANDIDATE', raw_packet_ref: { replay_sha256: SHA } },
], compact = true) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-event-query-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const replayDirectory = path.join(root, 'replays', 'synthetic');
  fs.mkdirSync(replayDirectory, { recursive: true });
  const semantic = {
    replay_version: VERSION, replay_sha256: SHA, container_status: 'PASS',
    status: 'PARTIAL', api_status: 'PARTIAL',
    requested_capabilities: [CAPABILITY, 'hero_path'],
    capability_results: {
      [CAPABILITY]: { status: 'CANDIDATE', input_count: rows.length,
        event_count: rows.length, evidence_status: 'CANDIDATE_SYNTHETIC' },
      hero_path: { status: 'MISSING_INPUT', input_count: null, event_count: null,
        missing_input: 'exact runtime image' },
    },
  };
  const analysis = {
    patch: '16.19', replay_version: VERSION, replay_sha256: SHA,
    event_counts: { [EVENT]: rows.length },
    ...(compact ? { event_storage: 'JSONL_ONLY',
      event_jsonl_files: { [EVENT]: `${EVENT}.jsonl` }, events: null }
      : { events: { [EVENT]: rows } }),
  };
  fs.writeFileSync(path.join(replayDirectory, 'semantic_run.json'), JSON.stringify(semantic));
  fs.writeFileSync(path.join(replayDirectory, 'replay_analysis.json'), JSON.stringify(analysis));
  const lines = rows.map((row) => JSON.stringify(row));
  fs.writeFileSync(path.join(replayDirectory, `${EVENT}.jsonl`),
    lines.length ? `${lines.join('\n')}\n` : '');
  return { root, replayDirectory, semantic, analysis, lines };
}

function run(...args) {
  return spawnSync(process.execPath, [CLI, 'query-events', ...args],
    { encoding: 'utf8', cwd: path.dirname(CLI) });
}

test('query-events streams filtered unmodified JSONL and reports full counts and original status', (t) => {
  const fixture = artifact(t);
  const output = path.join(fixture.root, 'selected.jsonl');
  const result = run(fixture.replayDirectory, '--event', EVENT,
    '--from-ms', '0', '--to-ms', '2000', '--participant', '1', '--limit', '1',
    '--output', output);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, '');
  const summary = JSON.parse(result.stdout);
  assert.equal(summary.query_status, 'COMPLETE');
  assert.equal(summary.capability_status, 'CANDIDATE');
  assert.equal(summary.semantic_run_status, 'PARTIAL');
  assert.equal(summary.replay_sha256, SHA);
  assert.equal(summary.declared_event_count, 4);
  assert.equal(summary.scanned_count, 4);
  assert.equal(summary.matched_count, 2);
  assert.equal(summary.emitted_count, 1);
  assert.equal(summary.participant_unavailable_count, 1);
  assert.deepEqual(summary.filters,
    { from_ms: 0, to_ms: 2000, participant_id: 1, limit: 1 });
  assert.equal(fs.readFileSync(output, 'utf8'), `${fixture.lines[0]}\n`);
  assert.equal(fs.readFileSync(path.join(fixture.replayDirectory, `${EVENT}.jsonl`), 'utf8'),
    `${fixture.lines.join('\n')}\n`);
});

test('query-events keeps stdout as JSONL and puts its query summary on stderr', (t) => {
  const fixture = artifact(t);
  const result = run(fixture.replayDirectory, '--event', EVENT, '--from-ms=1000',
    '--to-ms=2000', '--participant=2');
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, `${fixture.lines[3]}\n`);
  const summary = JSON.parse(result.stderr);
  assert.equal(summary.matched_count, 1);
  assert.equal(summary.emitted_count, 1);
  assert.equal(summary.output, '-');
});

test('query-events filters recorded raw packet parameters without resolving participants', (t) => {
  const rows = [
    { replay_sha256: SHA, replay_time_ms: 10, confidence: 'CANDIDATE',
      raw_param: 0x400000ae, raw_packet_ref: { replay_sha256: SHA, raw_param: 0x400000ae } },
    { replay_sha256: SHA, replay_time_ms: 20, confidence: 'CANDIDATE',
      raw_packet_refs: [{ replay_sha256: SHA, raw_param: 0x400000af }] },
    { replay_sha256: SHA, replay_time_ms: 30, confidence: 'CANDIDATE' },
  ];
  const fixture = artifact(t, rows);
  const result = run(fixture.replayDirectory, '--event', EVENT,
    '--raw-param', '0x400000af', '--limit', '1');
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, `${fixture.lines[1]}\n`);
  const summary = JSON.parse(result.stderr);
  assert.equal(summary.scanned_count, 3);
  assert.equal(summary.matched_count, 1);
  assert.equal(summary.emitted_count, 1);
  assert.equal(summary.raw_param_unavailable_count, 1);
  assert.equal(summary.filters.raw_param, 0x400000af);
  assert.equal(summary.filters.participant_id, null);

  const decimal = run(fixture.replayDirectory, '--event', EVENT,
    '--raw-param', String(0x400000ae));
  assert.equal(decimal.status, 0, decimal.stderr);
  assert.equal(decimal.stdout, `${fixture.lines[0]}\n`);
});

test('query-events distinguishes absent raw parameters from zero matches', (t) => {
  const fixture = artifact(t);
  const output = path.join(fixture.root, 'missing-raw-param.jsonl');
  const unavailable = run(fixture.replayDirectory, '--event', EVENT,
    '--raw-param', '0', '--output', output);
  assert.equal(unavailable.status, 2);
  assert.equal(JSON.parse(unavailable.stderr).code, 'RAW_PARAM_UNAVAILABLE');
  assert.equal(fs.existsSync(output), false);

  const rows = [{ replay_sha256: SHA, replay_time_ms: 10,
    raw_param: 0, raw_packet_ref: { replay_sha256: SHA, raw_param: 0 } }];
  const withParam = artifact(t, rows);
  const zeroMatch = run(withParam.replayDirectory, '--event', EVENT,
    '--raw-param', '1');
  assert.equal(zeroMatch.status, 0, zeroMatch.stderr);
  assert.equal(zeroMatch.stdout, '');
  assert.equal(JSON.parse(zeroMatch.stderr).matched_count, 0);
});

test('query-events rejects invalid recorded raw parameters and removes partial output', (t) => {
  const fixture = artifact(t, [
    { replay_sha256: SHA, replay_time_ms: 1, raw_param: 7 },
    { replay_sha256: SHA, replay_time_ms: 2, raw_param: -1 },
  ]);
  const output = path.join(fixture.root, 'invalid-raw-param.jsonl');
  const result = run(fixture.replayDirectory, '--event', EVENT,
    '--raw-param', '7', '--output', output);
  assert.equal(result.status, 2);
  assert.equal(JSON.parse(result.stderr).code, 'INVALID_EVENT_ROW');
  assert.equal(fs.existsSync(output), false);
});

test('query-events reads default 16.19 artifacts with embedded arrays and existing JSONL', (t) => {
  const fixture = artifact(t, undefined, false);
  const result = run(fixture.replayDirectory, '--event', EVENT,
    '--participant', '1', '--from-ms', '2000');
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, `${fixture.lines[2]}\n`);
  const summary = JSON.parse(result.stderr);
  assert.equal(summary.event_storage, 'EMBEDDED_AND_JSONL');
  assert.equal(summary.scanned_count, 4);
  assert.equal(summary.capability_status, 'CANDIDATE');
});

test('query-events reports missing capability without inventing zero events', (t) => {
  const fixture = artifact(t);
  const result = run(fixture.replayDirectory, '--event', 'hero_path_candidates');
  assert.equal(result.status, 2);
  assert.equal(result.stdout, '');
  const error = JSON.parse(result.stderr);
  assert.equal(error.code, 'CAPABILITY_UNAVAILABLE');
  assert.equal(error.capability_status, 'MISSING_INPUT');
  assert.equal(error.missing_input, 'exact runtime image');
});

test('query-events rejects unsafe keys, mismatched identity, count corruption, and output replacement', (t) => {
  const fixture = artifact(t);
  const unsafe = run(fixture.replayDirectory, '--event', '../semantic_run');
  assert.equal(unsafe.status, 2);
  assert.equal(JSON.parse(unsafe.stderr).code, 'INVALID_EVENT_KEY');

  const alias = run(fixture.replayDirectory, '--event', EVENT,
    '--output', path.join(fixture.replayDirectory, `${EVENT}.jsonl`));
  assert.equal(alias.status, 2);
  assert.equal(JSON.parse(alias.stderr).code, 'UNSAFE_OUTPUT');

  const analysisPath = path.join(fixture.replayDirectory, 'replay_analysis.json');
  const analysis = JSON.parse(fs.readFileSync(analysisPath));
  analysis.replay_sha256 = 'b'.repeat(64);
  fs.writeFileSync(analysisPath, JSON.stringify(analysis));
  const mismatch = run(fixture.replayDirectory, '--event', EVENT);
  assert.equal(mismatch.status, 2);
  assert.equal(JSON.parse(mismatch.stderr).code, 'ARTIFACT_IDENTITY_MISMATCH');

  analysis.replay_sha256 = SHA;
  fs.writeFileSync(analysisPath, JSON.stringify(analysis));
  fs.appendFileSync(path.join(fixture.replayDirectory, `${EVENT}.jsonl`), `${fixture.lines[0]}\n`);
  const badOutput = path.join(fixture.root, 'bad-output.jsonl');
  const corrupted = run(fixture.replayDirectory, '--event', EVENT, '--output', badOutput);
  assert.equal(corrupted.status, 2);
  assert.equal(JSON.parse(corrupted.stderr).code, 'EVENT_COUNT_MISMATCH');
  assert.equal(fs.existsSync(badOutput), false);
});

test('query-events distinguishes zero candidates from an unresolved participant filter', (t) => {
  const fixture = artifact(t, []);
  const zero = run(fixture.replayDirectory, '--event', EVENT);
  assert.equal(zero.status, 0, zero.stderr);
  assert.equal(zero.stdout, '');
  const summary = JSON.parse(zero.stderr);
  assert.equal(summary.scanned_count, 0);
  assert.equal(summary.capability_status, 'CANDIDATE');

  const row = { replay_sha256: SHA, replay_time_ms: 10, confidence: 'CANDIDATE' };
  const analysisPath = path.join(fixture.replayDirectory, 'replay_analysis.json');
  const semanticPath = path.join(fixture.replayDirectory, 'semantic_run.json');
  const analysis = JSON.parse(fs.readFileSync(analysisPath));
  const semantic = JSON.parse(fs.readFileSync(semanticPath));
  analysis.event_counts[EVENT] = 1;
  semantic.capability_results[CAPABILITY].event_count = 1;
  fs.writeFileSync(analysisPath, JSON.stringify(analysis));
  fs.writeFileSync(semanticPath, JSON.stringify(semantic));
  fs.writeFileSync(path.join(fixture.replayDirectory, `${EVENT}.jsonl`), `${JSON.stringify(row)}\n`);
  const unknown = run(fixture.replayDirectory, '--event', EVENT, '--participant', '1');
  assert.equal(unknown.status, 2);
  assert.equal(JSON.parse(unknown.stderr).code, 'PARTICIPANT_UNAVAILABLE');
});

test('query-events rejects malformed numeric filters before scanning', (t) => {
  const fixture = artifact(t);
  for (const args of [
    ['--from-ms', '-1'], ['--to-ms', '2.5'], ['--participant', '11'],
    ['--participant', '0'], ['--limit', '0'], ['--from-ms', '2', '--to-ms', '1'],
    ['--raw-param', '-1'], ['--raw-param', '0x100000000'],
    ['--raw-param', '4294967296'], ['--raw-param', '0xgg'],
  ]) {
    const result = run(fixture.replayDirectory, '--event', EVENT, ...args);
    assert.equal(result.status, 1, args.join(' '));
    assert.equal(result.stdout, '');
  }
});

test('query-events refuses metadata path traversal and invalid timestamp or participant rows', (t) => {
  const fixture = artifact(t);
  const analysisPath = path.join(fixture.replayDirectory, 'replay_analysis.json');
  const eventPath = path.join(fixture.replayDirectory, `${EVENT}.jsonl`);
  const analysis = JSON.parse(fs.readFileSync(analysisPath));
  analysis.event_jsonl_files[EVENT] = '../outside.jsonl';
  fs.writeFileSync(analysisPath, JSON.stringify(analysis));
  const unsafe = run(fixture.replayDirectory, '--event', EVENT);
  assert.equal(unsafe.status, 2);
  assert.equal(JSON.parse(unsafe.stderr).code, 'UNSAFE_ARTIFACT');

  analysis.event_jsonl_files[EVENT] = `${EVENT}.jsonl`;
  fs.writeFileSync(analysisPath, JSON.stringify(analysis));
  const original = fs.readFileSync(eventPath, 'utf8');
  for (const corrupt of [
    { replay_sha256: SHA, replay_time_ms: -1, participant_id_candidate: 1 },
    { replay_sha256: SHA, replay_time_ms: 1, participant_id_candidate: 11 },
    { replay_time_ms: 1, participant_id_candidate: 1 },
    { replay_sha256: SHA, replay_time_ms: 1, participant_id_candidate: 1,
      raw_packet_ref: {} },
    { replay_sha256: SHA, replay_time_ms: 1, participant_id_candidate: 1,
      raw_packet_refs: [{ replay_sha256: 'b'.repeat(64) }] },
  ]) {
    fs.writeFileSync(eventPath, `${JSON.stringify(corrupt)}\n${fixture.lines.slice(1).join('\n')}\n`);
    const result = run(fixture.replayDirectory, '--event', EVENT,
      '--output', path.join(fixture.root, 'rejected.jsonl'));
    assert.equal(result.status, 2);
    assert.equal(fs.existsSync(path.join(fixture.root, 'rejected.jsonl')), false);
    assert.ok(['INVALID_EVENT_ROW', 'ARTIFACT_IDENTITY_MISMATCH']
      .includes(JSON.parse(result.stderr).code));
  }
  fs.writeFileSync(eventPath, original);
});

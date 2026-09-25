'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const CLI = path.resolve(__dirname, '../src/cli.js');
const BUILD = '16.19.821.7343';
const INVENTORY_EVENT = 'hero_inventory_packet_candidates';
const SHA_A = 'a'.repeat(64);
const SHA_B = 'b'.repeat(64);

function replayArtifact(root, name, rows, sha = SHA_A, eventKey = INVENTORY_EVENT) {
  const directory = path.join(root, 'replays', name);
  fs.mkdirSync(directory, { recursive: true });
  const capability = eventKey.slice(0, -'_candidates'.length);
  const actualRows = rows.map((row) => ({ replay_sha256: sha, ...row }));
  const lines = actualRows.map((row) => JSON.stringify(row));
  const semantic = {
    replay_version: BUILD, replay_sha256: sha, container_status: 'PASS',
    status: 'CANDIDATE', api_status: 'EXPERIMENTAL_CANDIDATE',
    requested_capabilities: [capability],
    capability_results: {
      [capability]: { status: 'CANDIDATE', input_count: rows.length,
        event_count: rows.length, evidence_status: 'CANDIDATE_SYNTHETIC' },
    },
  };
  const analysis = {
    patch: '16.19', replay_version: BUILD, replay_sha256: sha,
    event_counts: { [eventKey]: rows.length },
    event_storage: 'JSONL_ONLY',
    event_jsonl_files: { [eventKey]: `${eventKey}.jsonl` },
    events: null,
  };
  fs.writeFileSync(path.join(directory, 'semantic_run.json'), JSON.stringify(semantic));
  fs.writeFileSync(path.join(directory, 'replay_analysis.json'), JSON.stringify(analysis));
  fs.writeFileSync(path.join(directory, `${eventKey}.jsonl`), `${lines.join('\n')}\n`);
  return { directory, lines, rows: actualRows, name, sha, eventKey };
}

function fixture(t, rows, eventKey = INVENTORY_EVENT) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-latest-query-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, ...replayArtifact(root, 'first', rows, SHA_A, eventKey) };
}

function batchFixture(t, firstRows, secondRows) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-latest-batch-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const first = replayArtifact(root, 'first', firstRows, SHA_A);
  const second = replayArtifact(root, 'second', secondRows, SHA_B);
  const replayInputs = [first, second].map((entry) => ({
    sha256: entry.sha, version: BUILD,
    artifact_directory: `replays/${entry.name}`,
  }));
  const hashes = {};
  for (const entry of replayInputs) {
    for (const name of ['semantic_run.json', 'replay_analysis.json',
      `${INVENTORY_EVENT}.jsonl`]) {
      const relative = `${entry.artifact_directory}/${name}`;
      hashes[relative] = crypto.createHash('sha256')
        .update(fs.readFileSync(path.join(root, relative))).digest('hex');
    }
  }
  fs.writeFileSync(path.join(root, 'manifest.json'), JSON.stringify({
    command_args: ['batch', 'synthetic-input'], replay_inputs: replayInputs,
    output_hashes_excluding_manifest: hashes,
  }));
  return { root, first, second };
}

function run(directory, ...options) {
  return spawnSync(process.execPath,
    [CLI, 'query-events', directory, ...options],
    { encoding: 'utf8', cwd: path.dirname(CLI) });
}

function outputLines(result) {
  return result.stdout.trimEnd().split('\n').filter(Boolean);
}

function rewriteJson(filename, edit) {
  const document = JSON.parse(fs.readFileSync(filename, 'utf8'));
  edit(document);
  fs.writeFileSync(filename, JSON.stringify(document));
}

test('latest-per-participant uses an inclusive cutoff and later source line on a tie', (t) => {
  const fixtureRows = [
    { replay_time_ms: 100, participant_id_candidate: 1, marker: 'p1-old' },
    { replay_time_ms: 130, participant_id_candidate: null, marker: 'unknown' },
    { replay_time_ms: 180, participant_id_candidate: 2, marker: 'p2-cutoff' },
    { replay_time_ms: 200, participant_id_candidate: 1, marker: 'p1-tie-earlier' },
    { replay_time_ms: 200, participant_id_candidate: 1, marker: 'p1-tie-later' },
    { replay_time_ms: 300, participant_id_candidate: 2, marker: 'p2-after-cutoff' },
  ];
  const input = fixture(t, fixtureRows);
  const cutoff = run(input.directory, '--event', INVENTORY_EVENT,
    '--latest-per-participant', '--to-ms', '200');
  assert.equal(cutoff.status, 0, cutoff.stderr);
  assert.deepEqual(outputLines(cutoff), [input.lines[4], input.lines[2]]);
  const summary = JSON.parse(cutoff.stderr);
  assert.equal(summary.scanned_count, fixtureRows.length);
  assert.equal(summary.matched_count, 5);
  assert.equal(summary.selected_count, 2);
  assert.equal(summary.emitted_count, 2);
  assert.equal(summary.latest_participant_unavailable_count, 1);
  assert.equal(summary.filters.latest_per_participant, true);
  assert.equal(summary.rows_unmodified, true);

  const throughEnd = run(input.directory, '--event', INVENTORY_EVENT,
    '--latest-per-participant');
  assert.equal(throughEnd.status, 0, throughEnd.stderr);
  assert.deepEqual(outputLines(throughEnd), [input.lines[4], input.lines[5]]);
  assert.equal(JSON.parse(throughEnd.stderr).matched_count, 6);
  assert.equal(JSON.parse(throughEnd.stderr).emitted_count, 2);
});

test('latest-per-participant applies item and slot to the same record before choosing', (t) => {
  const input = fixture(t, [
    { replay_time_ms: 10, participant_id_candidate: 1, record_count: 1,
      records_candidate: [{ slot_candidate: 6, item_id_candidate: 3340 }] },
    { replay_time_ms: 20, participant_id_candidate: 1, record_count: 2,
      records_candidate: [{ slot_candidate: 0, item_id_candidate: 3340 },
        { slot_candidate: 6, item_id_candidate: 1001 }] },
    { replay_time_ms: 25, participant_id_candidate: 2, record_count: 1,
      records_candidate: [{ slot_candidate: 6, item_id_candidate: 3340 }] },
    { replay_time_ms: 30, participant_id_candidate: 1, record_count: 1,
      records_candidate: [{ slot_candidate: 6, item_id_candidate: 3340 }] },
    { replay_time_ms: 40, participant_id_candidate: 1, record_count: 0,
      records_candidate: [] },
  ]);
  const selected = run(input.directory, '--event', INVENTORY_EVENT,
    '--latest-per-participant', '--item-id', '3340', '--slot', '6');
  assert.equal(selected.status, 0, selected.stderr);
  assert.deepEqual(outputLines(selected), [input.lines[3], input.lines[2]]);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.matched_count, 3);
  assert.equal(summary.selected_count, 2);
  assert.equal(summary.emitted_count, 2);
  assert.equal(summary.rows_unmodified, true);
});

test('latest-per-participant selects within each Replay before a global batch limit', (t) => {
  const batch = batchFixture(t, [
    { replay_time_ms: 10, participant_id_candidate: 1, marker: 'first-old' },
    { replay_time_ms: 20, participant_id_candidate: 1, marker: 'first-latest' },
  ], [
    { replay_time_ms: 15, participant_id_candidate: 1, marker: 'second-old' },
    { replay_time_ms: 25, participant_id_candidate: 1, marker: 'second-latest' },
  ]);
  const all = run(batch.root, '--event', INVENTORY_EVENT,
    '--latest-per-participant');
  assert.equal(all.status, 0, all.stderr);
  assert.deepEqual(outputLines(all), [batch.first.lines[1], batch.second.lines[1]]);
  const allSummary = JSON.parse(all.stderr);
  assert.equal(allSummary.completed_replay_count, 2);
  assert.equal(allSummary.matched_count, 4);
  assert.equal(allSummary.selected_count, 2);
  assert.equal(allSummary.emitted_count, 2);

  const limited = run(batch.root, '--event', INVENTORY_EVENT,
    '--latest-per-participant', '--limit', '1');
  assert.equal(limited.status, 0, limited.stderr);
  assert.deepEqual(outputLines(limited), [batch.first.lines[1]]);
  const summary = JSON.parse(limited.stderr);
  assert.equal(summary.completed_replay_count, 2);
  assert.equal(summary.matched_count, 4);
  assert.equal(summary.selected_count, 2);
  assert.equal(summary.emitted_count, 1);
  assert.deepEqual(summary.replay_results.map((row) => row.emitted_count), [1, 0]);
});

test('latest-per-participant rejects unsupported or ambiguous streams and later corruption', (t) => {
  const unsupported = fixture(t, [
    { replay_time_ms: 10, participant_id_candidate: 1 },
  ], 'params_heal_packet_candidates');
  const rejected = run(unsupported.directory, '--event', unsupported.eventKey,
    '--latest-per-participant');
  assert.equal(rejected.status, 2);
  assert.equal(JSON.parse(rejected.stderr).code, 'UNSUPPORTED_FILTER');

  const wrongBuild = fixture(t, [
    { replay_time_ms: 10, participant_id_candidate: 1 },
  ]);
  for (const name of ['semantic_run.json', 'replay_analysis.json']) {
    rewriteJson(path.join(wrongBuild.directory, name), (document) => {
      document.replay_version = '16.19.820.7193';
    });
  }
  const old = run(wrongBuild.directory, '--event', INVENTORY_EVENT,
    '--latest-per-participant');
  assert.equal(old.status, 2);
  assert.equal(JSON.parse(old.stderr).code, 'UNSUPPORTED_FILTER');

  const ambiguous = fixture(t, [
    { replay_time_ms: 10, participant_id_candidate: 1,
      victim_participant_id_candidate: 2 },
  ]);
  const invalid = run(ambiguous.directory, '--event', INVENTORY_EVENT,
    '--latest-per-participant');
  assert.equal(invalid.status, 2);
  assert.equal(JSON.parse(invalid.stderr).code, 'INVALID_EVENT_ROW');

  const corrupt = fixture(t, [
    { replay_time_ms: 10, participant_id_candidate: 1 },
    { replay_time_ms: 30, participant_id_candidate: 11 },
  ]);
  const output = path.join(corrupt.root, 'corrupt-latest.jsonl');
  const later = run(corrupt.directory, '--event', INVENTORY_EVENT,
    '--latest-per-participant', '--to-ms', '20', '--output', output);
  assert.equal(later.status, 2);
  assert.equal(JSON.parse(later.stderr).code, 'INVALID_EVENT_ROW');
  assert.equal(fs.existsSync(output), false);
});

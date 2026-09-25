'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { parseReplayFile } = require('../src/rofl');
const { decodeSemanticReplay } = require('../src/semantic_api');

const CAPABILITY = 'hero_experience_snapshot';
const ASSOCIATION = 'experience_keyframe_interval_difference';
const INTERVAL_EVENTS = 'experience_keyframe_interval_difference_candidates';
const SOURCE_EVENTS = 'hero_experience_snapshot_candidates';
const CLI = path.resolve(__dirname, '..', 'src', 'cli.js');
const REPLAY = path.resolve(__dirname, '..', '..', 'kr-rofl-batch-collector',
  'data', 'KR', '16.19', 'builds', '16.19.821.7343', 'rofl',
  'KR_8392938200.rofl');

test('one original KR replay exposes sampled experience intervals through API and CLI', (t) => {
  if (!fs.existsSync(REPLAY)) {
    t.skip('supplied KR 16.19.821.7343 replay absent');
    return;
  }
  const decoded = decodeSemanticReplay(parseReplayFile(REPLAY), {
    capabilities: [CAPABILITY],
  });
  assert.equal(decoded.capability_results[CAPABILITY].status, 'CANDIDATE');
  const summary = decoded.candidate_associations[ASSOCIATION];
  assert.equal(summary.status, 'CANDIDATE', summary.error);
  assert.equal(summary.keyframe_count, 33);
  assert.equal(summary.observed_interval_count, 320);
  assert.equal(summary.changed_interval_count, 290);
  assert.equal(summary.unchanged_interval_count, 30);
  assert.equal(summary.event_count, decoded.events[INTERVAL_EVENTS].length);
  assert.equal(decoded.events[SOURCE_EVENTS].length, 330);
  assert.ok(decoded.events[INTERVAL_EVENTS].every((row) =>
    row.confidence === 'CANDIDATE'
      && row.previous_observation_time_ms < row.current_observation_time_ms
      && row.previous_raw_packet_ref
      && row.current_raw_packet_ref));

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-experience-interval-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const output = path.join(directory, 'output');
  const run = spawnSync(process.execPath, [CLI, 'decode', REPLAY,
    '--events', CAPABILITY, '--event-jsonl-only', '--out-dir', output], {
    encoding: 'utf8', timeout: 120000,
  });
  assert.equal(run.status, 0, run.stderr || run.stdout);
  const acceptance = JSON.parse(fs.readFileSync(path.join(output,
    'acceptance_summary.json'), 'utf8'));
  const replayDirectory = path.join(output,
    acceptance.replay_artifacts[0].artifact_directory);
  const semantic = JSON.parse(fs.readFileSync(path.join(replayDirectory,
    'semantic_run.json'), 'utf8'));
  const intervalRows = fs.readFileSync(path.join(replayDirectory,
    `${INTERVAL_EVENTS}.jsonl`), 'utf8').trim().split(/\r?\n/).map(JSON.parse);
  const sourceRows = fs.readFileSync(path.join(replayDirectory,
    `${SOURCE_EVENTS}.jsonl`), 'utf8').trim().split(/\r?\n/).map(JSON.parse);
  assert.deepEqual(semantic.candidate_associations[ASSOCIATION], summary);
  assert.deepEqual(intervalRows, decoded.events[INTERVAL_EVENTS]);
  assert.equal(sourceRows.length, decoded.events[SOURCE_EVENTS].length);
});

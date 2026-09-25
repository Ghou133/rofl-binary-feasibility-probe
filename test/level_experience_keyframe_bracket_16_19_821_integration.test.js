'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { parseReplayFile } = require('../src/rofl');
const { decodeSemanticReplay } = require('../src/semantic_api');

const BUILD = '16.19.821.7343';
const LEVEL = 'hero_level_state';
const EXPERIENCE = 'hero_experience_snapshot';
const ASSOCIATION = 'level_experience_keyframe_bracket';
const EVENTS = 'level_experience_keyframe_bracket_candidates';
const CLI = path.resolve(__dirname, '..', 'src', 'cli.js');
const REPLAY = path.resolve(__dirname, '..', '..', 'kr-rofl-batch-collector',
  'data', 'KR', '16.19', 'builds', BUILD, 'rofl', 'KR_8392938200.rofl');

test('821 level and experience sources associate only when both are selected', (t) => {
  if (!fs.existsSync(REPLAY)) {
    t.skip('supplied KR 16.19.821.7343 replay absent');
    return;
  }
  const replay = parseReplayFile(REPLAY);
  for (const capability of [LEVEL, EXPERIENCE]) {
    const decoded = decodeSemanticReplay(replay, { capabilities: [capability] });
    assert.equal(decoded.capability_results[capability].status, 'CANDIDATE');
    assert.equal(decoded.candidate_associations[ASSOCIATION], undefined);
    assert.equal(decoded.events[EVENTS], undefined);
  }
  const decoded = decodeSemanticReplay(replay, { capabilities: [LEVEL, EXPERIENCE] });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.capability_results[LEVEL].status, 'CANDIDATE');
  assert.equal(decoded.capability_results[EXPERIENCE].status, 'CANDIDATE');
  const summary = decoded.candidate_associations[ASSOCIATION];
  assert.equal(summary.status, 'CANDIDATE', summary.error);
  assert.ok(summary.event_count > 0);
  assert.equal(summary.event_count, decoded.events[EVENTS].length);
  assert.ok(decoded.events[EVENTS].every((row) =>
    row.event_type === 'LEVEL_EXPERIENCE_KEYFRAME_BRACKET_CANDIDATE'
      && row.game_version === BUILD
      && row.confidence === 'CANDIDATE'
      && row.previous_observation_time_ms < row.replay_time_ms
      && row.replay_time_ms < row.current_observation_time_ms
      && row.level_raw_packet_ref?.packet_id === 0x0197
      && row.previous_experience_raw_packet_ref?.packet_id === 0x0089
      && row.current_experience_raw_packet_ref?.packet_id === 0x0089));
});

test('821 CLI persists the same level/experience bracket as API', (t) => {
  if (!fs.existsSync(REPLAY)) {
    t.skip('supplied KR 16.19.821.7343 replay absent');
    return;
  }
  const decoded = decodeSemanticReplay(parseReplayFile(REPLAY), {
    capabilities: [LEVEL, EXPERIENCE],
  });
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-level-experience-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const output = path.join(directory, 'output');
  const run = spawnSync(process.execPath, [CLI, 'decode', REPLAY,
    '--events', `${LEVEL},${EXPERIENCE}`, '--event-jsonl-only', '--out-dir', output], {
    encoding: 'utf8', timeout: 120000,
  });
  assert.equal(run.status, 0, run.stderr || run.stdout);
  const acceptance = JSON.parse(fs.readFileSync(path.join(output,
    'acceptance_summary.json'), 'utf8'));
  const replayDirectory = path.join(output,
    acceptance.replay_artifacts[0].artifact_directory);
  const semantic = JSON.parse(fs.readFileSync(path.join(replayDirectory,
    'semantic_run.json'), 'utf8'));
  const rows = fs.readFileSync(path.join(replayDirectory,
    `${EVENTS}.jsonl`), 'utf8').trim().split(/\r?\n/).map(JSON.parse);
  assert.deepEqual(semantic.candidate_associations[ASSOCIATION],
    decoded.candidate_associations[ASSOCIATION]);
  assert.deepEqual(rows, decoded.events[EVENTS]);
});

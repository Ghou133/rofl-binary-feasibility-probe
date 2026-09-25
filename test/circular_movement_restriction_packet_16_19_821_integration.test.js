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
const CAPABILITY = 'circular_movement_restriction_packet';
const EVENTS = 'circular_movement_restriction_packet_candidates';
const CLI = path.resolve(__dirname, '..', 'src', 'cli.js');
const IMAGE = path.resolve(__dirname, '..', 'artifacts', '16_19_development',
  'kr_821_runtime_capture', 'LeagueOfLegends_16.19.821.7343.memory.bin');
const REPLAY = path.resolve(__dirname, '..', '..', 'kr-rofl-batch-collector',
  'data', 'KR', '16.19', 'builds', BUILD, 'rofl', 'KR_8392938200.rofl');

test('exact 821 0x0464 candidate reaches API and CLI with unchanged packet rows', (t) => {
  if (!fs.existsSync(REPLAY) || !fs.existsSync(IMAGE)) {
    t.skip('supplied KR 821 replay or matching local runtime image absent');
    return;
  }
  const decoded = decodeSemanticReplay(parseReplayFile(REPLAY), {
    capabilities: [CAPABILITY], runtimeImagePath: IMAGE,
  });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  const result = decoded.capability_results[CAPABILITY];
  assert.equal(result.status, 'CANDIDATE', result.error);
  assert.equal(result.runtime_image_status, 'MATCHED_USED');
  assert.equal(result.runtime_image_used, true);
  assert.equal(result.event_count, decoded.events[EVENTS].length);
  assert.ok(result.event_count > 0);
  assert.ok(decoded.events[EVENTS].every((row) =>
    row.event_type === 'CIRCULAR_MOVEMENT_RESTRICTION_PACKET_CANDIDATE'
      && row.game_version === BUILD && row.confidence === 'CANDIDATE'
      && row.semantic_effect_status === 'UNKNOWN'
      && row.raw_packet_ref.packet_id === 0x0464
      && row.packet_record_count_candidate >= 0
      && row.packet_record_count_candidate <= 1));

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-circular-packet-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const output = path.join(directory, 'output');
  const run = spawnSync(process.execPath, [CLI, 'decode', REPLAY,
    '--events', CAPABILITY, '--runtime-image', IMAGE,
    '--event-jsonl-only', '--out-dir', output], {
    encoding: 'utf8', timeout: 120000,
  });
  assert.equal(run.status, 0, run.stderr || run.stdout);
  const acceptance = JSON.parse(fs.readFileSync(path.join(output,
    'acceptance_summary.json'), 'utf8'));
  const replayDirectory = path.join(output,
    acceptance.replay_artifacts[0].artifact_directory);
  const semantic = JSON.parse(fs.readFileSync(path.join(replayDirectory,
    'semantic_run.json'), 'utf8'));
  const rows = fs.readFileSync(path.join(replayDirectory, `${EVENTS}.jsonl`), 'utf8')
    .trim().split(/\r?\n/).map(JSON.parse);
  assert.deepEqual(semantic.capability_results[CAPABILITY], result);
  assert.deepEqual(rows, decoded.events[EVENTS]);
});

'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { parseReplayFile } = require('../src/rofl');
const { decodeSemanticReplay } = require('../src/semantic_api');

const BUILD = '16.19.821.7343';
const CAPABILITY = 'show_health_bar_packet';
const EVENTS = 'show_health_bar_packet_candidates';
const CLI = path.resolve(__dirname, '..', 'src', 'cli.js');
const IMAGE = path.resolve(__dirname, '..', 'artifacts', '16_19_development',
  'kr_821_runtime_capture', 'LeagueOfLegends_16.19.821.7343.memory.bin');
const REPLAY = path.resolve(__dirname, '..', '..', 'kr-rofl-batch-collector',
  'data', 'KR', '16.19', 'builds', BUILD, 'rofl', 'KR_8392938200.rofl');

test('exact 821 ShowHealthBar candidate reaches API and CLI with identical source rows', async (t) => {
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
  assert.equal(result.native_full_success_count, result.event_count);
  assert.equal(result.event_count, decoded.events[EVENTS].length);
  assert.ok(result.event_count > 0);
  assert.equal(result.observed_payload_counts['4a']
    + result.observed_payload_counts['4b'], result.event_count);
  assert.ok(decoded.events[EVENTS].every((row) =>
    row.event_type === 'SHOW_HEALTH_BAR_PACKET_CANDIDATE'
      && row.game_version === BUILD && row.confidence === 'CANDIDATE'
      && row.semantic_effect_status === 'UNKNOWN'
      && row.raw_packet_ref.packet_id === 0x0165
      && ['4a', '4b'].includes(row.raw_packet_ref.raw_payload_hex)
      && row.callback_zero_flag_candidate === Number(row.callback_byte_candidate === 0)));

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-show-bar-'));
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
  assert.deepEqual(semantic.capability_results[CAPABILITY], result);
  const expectedHash = crypto.createHash('sha256');
  for (const row of decoded.events[EVENTS]) expectedHash.update(`${JSON.stringify(row)}\n`);
  const actualHash = crypto.createHash('sha256');
  for await (const chunk of fs.createReadStream(path.join(replayDirectory, `${EVENTS}.jsonl`))) {
    actualHash.update(chunk);
  }
  assert.equal(actualHash.digest('hex'), expectedHash.digest('hex'));
});

test('missing exact image does not erase an independent 821 level result', (t) => {
  if (!fs.existsSync(REPLAY)) {
    t.skip('supplied KR 821 replay absent');
    return;
  }
  const decoded = decodeSemanticReplay(parseReplayFile(REPLAY), {
    capabilities: [CAPABILITY, 'hero_level_state'],
  });
  assert.equal(decoded.status, 'PARTIAL');
  assert.equal(decoded.capability_results[CAPABILITY].status, 'MISSING_INPUT');
  assert.equal(decoded.events[EVENTS], undefined);
  assert.equal(decoded.capability_results.hero_level_state.status, 'CANDIDATE');
  assert.ok(decoded.events.hero_level_state_candidates.length > 0);
});

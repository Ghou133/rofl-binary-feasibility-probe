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
const CAPABILITY = 'unit_apply_damage_packet';
const EVENTS = 'unit_apply_damage_packet_candidates';
const CLI = path.resolve(__dirname, '..', 'src', 'cli.js');
const IMAGE = path.resolve(__dirname, '..', 'artifacts', '16_19_development',
  'kr_821_runtime_capture', 'LeagueOfLegends_16.19.821.7343.memory.bin');
const REPLAY = path.resolve(__dirname, '..', '..', 'kr-rofl-batch-collector',
  'data', 'KR', '16.19', 'builds', BUILD, 'rofl', 'KR_8392938200.rofl');

test('821 UnitApplyDamage candidate reaches API and CLI without losing raw rows', async (t) => {
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
  assert.equal(result.event_count, 64824);
  assert.equal(result.callback_f32_available_count, 684);
  assert.equal(result.callback_f32_unavailable_count, result.event_count - 684);
  assert.ok(decoded.events[EVENTS].every((row) =>
    row.event_type === 'UNIT_APPLY_DAMAGE_PACKET_CANDIDATE'
      && row.game_version === BUILD
      && row.confidence === 'CANDIDATE'
      && row.semantic_effect_status === 'UNKNOWN'
      && row.raw_packet_ref.packet_id === 0x005f
      && (row.callback_f32_0x20_status === 'NATIVE_MATCHED_SHAPE'
        || row.callback_f32_0x20_status === 'UNAVAILABLE_SHAPE')));

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-unit-damage-'));
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

test('missing exact image leaves independent 821 level output available', (t) => {
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

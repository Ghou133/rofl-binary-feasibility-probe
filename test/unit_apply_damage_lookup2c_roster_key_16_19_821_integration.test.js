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
const CAPABILITY = 'unit_apply_damage_lookup2c_roster_key_pair';
const EVENT = 'unit_apply_damage_lookup2c_roster_key_candidates';
const CLI = path.resolve(__dirname, '..', 'src', 'cli.js');
const IMAGE = path.resolve(__dirname, '..', 'artifacts', '16_19_development',
  'kr_821_runtime_capture', 'LeagueOfLegends_16.19.821.7343.memory.bin');
const REPLAY = path.resolve(__dirname, '..', '..', 'kr-rofl-batch-collector',
  'data', 'KR', '16.19', 'builds', BUILD, 'rofl', 'KR_8392938200.rofl');

test('exact 821 native +0x2c lookup key reaches API and CLI with source-bound rows',
  async (t) => {
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
    assert.ok(result.event_count > 0);
    assert.equal(result.matched_lookup_key_packet_count, result.event_count);
    assert.equal(result.unmatched_packet_count + result.event_count,
      result.damage_packet_count);
    assert.equal(Object.values(result.matched_key24_roster_counts)
      .reduce((sum, count) => sum + count, 0), result.event_count);
    const rows = decoded.events[EVENT];
    assert.equal(rows.length, result.event_count);
    assert.ok(rows.every((row) =>
      row.event_type === 'UNIT_APPLY_DAMAGE_LOOKUP2C_ROSTER_KEY_CANDIDATE'
        && row.game_version === BUILD
        && row.hero_raw_param === row.native_callback_lookup_key_u32_0x2c_candidate
        && row.hero_stats_participant_id_candidate === row.hero_raw_param
          - 0x400000ae + 1
        && Number.isSafeInteger(row.native_callback_lookup_key_u32_0x24_candidate)
        && typeof row.key24_roster_relation === 'string'
        && row.lookup_resolution_status === 'UNKNOWN'
        && row.actor_assignment_status === 'UNKNOWN'
        && row.source_target_role_status === 'UNKNOWN'
        && row.semantic_effect_status === 'UNKNOWN'
        && row.unit_apply_damage_raw_packet_ref.packet_id === 0x005f
        && row.hero_stats_roster_raw_packet_ref.packet_id === 0x0089
        && row.unit_apply_damage_raw_packet_ref.raw_param === row.raw_param
        && row.hero_stats_roster_raw_packet_ref.raw_param === row.hero_raw_param));

    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-damage-lookup2c-roster-'));
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
    for (const row of rows) expectedHash.update(`${JSON.stringify(row)}\n`);
    const actualHash = crypto.createHash('sha256');
    for await (const chunk of fs.createReadStream(path.join(replayDirectory,
      `${EVENT}.jsonl`))) actualHash.update(chunk);
    assert.equal(actualHash.digest('hex'), expectedHash.digest('hex'));
  });

test('missing image leaves independent level candidate but +0x2c association unavailable',
  (t) => {
    if (!fs.existsSync(REPLAY)) {
      t.skip('supplied KR 821 replay absent');
      return;
    }
    const decoded = decodeSemanticReplay(parseReplayFile(REPLAY), {
      capabilities: [CAPABILITY, 'hero_level_state'],
    });
    assert.equal(decoded.status, 'PARTIAL');
    assert.equal(decoded.capability_results[CAPABILITY].status, 'MISSING_INPUT');
    assert.equal(decoded.events[EVENT], undefined);
    assert.equal(decoded.capability_results.hero_level_state.status, 'CANDIDATE');
    assert.ok(decoded.events.hero_level_state_candidates.length > 0);
  });

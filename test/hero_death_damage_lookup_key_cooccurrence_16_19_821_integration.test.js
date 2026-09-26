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
const CAPABILITY = 'hero_death_damage_lookup_key_cooccurrence';
const EVENT = 'hero_death_damage_lookup_key_cooccurrence_candidates';
const CLI = path.resolve(__dirname, '..', 'src', 'cli.js');
const IMAGE = path.resolve(__dirname, '..', 'artifacts', '16_19_development',
  'kr_821_runtime_capture', 'LeagueOfLegends_16.19.821.7343.memory.bin');
const REPLAY = path.resolve(__dirname, '..', '..', 'kr-rofl-batch-collector',
  'data', 'KR', '16.19', 'builds', BUILD, 'rofl', 'KR_8392938200.rofl');

test('exact 821 death/damage key co-occurrence reaches API and CLI with all packets',
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
    assert.match(result.profile_id, /-v3$/);
    assert.equal(result.native_callback_f32_0x18_full_write_count,
      result.damage_packet_count);
    assert.equal(Object.values(result.native_callback_f32_0x18_source_counts)
      .reduce((sum, count) => sum + count, 0), result.damage_packet_count);
    assert.ok(result.event_count > 0);
    assert.equal(result.event_count, result.death_anchor_count);
    assert.equal(result.canonical_roster_key_count, 10);
    const rows = decoded.events[EVENT];
    assert.equal(rows.length, result.event_count);
    assert.equal(rows.reduce((sum, row) => sum
      + row.same_time_victim_key24_packet_candidates.length, 0),
    result.matched_victim_key24_packet_count);
    assert.ok(rows.every((row) =>
      row.event_type === 'HERO_DEATH_DAMAGE_LOOKUP_KEY_COOCCURRENCE_CANDIDATE'
        && row.game_version === BUILD
        && row.victim_lookup_roster_key_u32_candidate
          === 0x400000ad + row.victim_participant_id_candidate
        && row.same_time_victim_key24_packet_candidate_count
          === row.same_time_victim_key24_packet_candidates.length
        && row.actor_assignment_status === 'UNKNOWN'
        && row.source_target_role_status === 'UNKNOWN'
        && row.semantic_effect_status === 'UNKNOWN'
        && row.hero_death_raw_packet_ref.packet_id === 0x0259
        && row.hero_stats_roster_raw_packet_ref.packet_id === 0x0089
        && row.same_time_victim_key24_packet_candidates.every((packet) =>
          packet.native_callback_lookup_key_u32_0x24_candidate
            === row.victim_lookup_roster_key_u32_candidate
          && Number.isFinite(packet.native_callback_f32_0x18_candidate)
          && ['RAW_READER', 'CONSTANT_0'].includes(
            packet.native_callback_f32_0x18_source)
          && packet.die_source_key2c_equal
            === (row.die_source_network_id_candidate === null ? null
              : packet.native_callback_lookup_key_u32_0x2c_candidate
                === row.die_source_network_id_candidate)
          && packet.unit_apply_damage_raw_packet_ref.packet_id === 0x005f
          && packet.unit_apply_damage_raw_packet_ref.chunk_index
            === row.hero_death_raw_packet_ref.chunk_index
          && packet.unit_apply_damage_raw_packet_ref.replay_time_ms
            === row.replay_time_ms)));

    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-death-damage-key-'));
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
    const queried = spawnSync(process.execPath, [CLI, 'query-events',
      replayDirectory, '--event', EVENT, '--limit', '1'], {
      encoding: 'utf8', timeout: 120000,
    });
    assert.equal(queried.status, 0, queried.stderr || queried.stdout);
    assert.equal(JSON.parse(queried.stderr).scanned_count, result.event_count);
  });

test('missing image leaves death candidate available and association unavailable',
  (t) => {
    if (!fs.existsSync(REPLAY)) {
      t.skip('supplied KR 821 replay absent');
      return;
    }
    const decoded = decodeSemanticReplay(parseReplayFile(REPLAY), {
      capabilities: [CAPABILITY, 'hero_death'],
    });
    assert.equal(decoded.status, 'PARTIAL');
    assert.equal(decoded.capability_results[CAPABILITY].status, 'MISSING_INPUT');
    assert.equal(decoded.events[EVENT], undefined);
    assert.equal(decoded.capability_results.hero_death.status, 'CANDIDATE');
    assert.ok(decoded.events.hero_death_candidates.length > 0);
  });

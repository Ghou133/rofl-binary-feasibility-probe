'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { execFileSync } = require('node:child_process');
const { semanticProfileFor } = require('../src/decoders/rofl_16_16_805_0442');

const ROOT = path.resolve(__dirname, '..');
const SUMMARY = path.join(
  ROOT, 'artifacts', '16_16_ward_semantic_recovery_v1', 'runtime',
  'ward_validation_summary.json',
);

test('16.16 Ward release evidence is exact-build, nonempty, and conflict free', () => {
  const summary = JSON.parse(fs.readFileSync(SUMMARY, 'utf8'));
  assert.equal(summary.status, 'PASS');
  assert.equal(summary.game_version, '16.16.805.0442');
  assert.equal(summary.profile.client_opcode, 0x049a);
  assert.equal(summary.profile.deserialize_rva, 0x01025d50);
  assert.equal(summary.profile.rejected_deserialize_candidate_rva, 0x00fc7770);
  assert.equal(summary.counts.valid_input_rows, 31862);
  assert.equal(summary.counts.fully_consumed, 31862);
  assert.equal(summary.counts.infrastructure_failures, 0);
  assert.equal(summary.counts.player_active_ward_confirmed, 2252);
  assert.equal(summary.owner_mapping.coverage_rate, 1);
  assert.equal(summary.owner_mapping.conflict_count, 0);
  assert.ok(summary.owner_mapping.tail_ward_placed_exact_match_rate >= 0.95);
  assert.equal(summary.release.VISION_SPAWN_READY, true);
  assert.equal(summary.release.VISION_LIFECYCLE_READY, false);
  assert.equal(summary.lifecycle.end_reason, 'UNKNOWN');
});

test('16.16 lifecycle evidence never accepts identity without spatial corroboration', () => {
  const lifecycle = fs.readFileSync(path.join(
    ROOT, 'artifacts', '16_16_ward_semantic_recovery_v1',
    'ward_lifecycle_validation.csv',
  ), 'utf8').trim().split(/\r?\n/);
  const header = lifecycle[0].split(',');
  const ruleIndex = header.indexOf('match_rule');
  const coordinateIndex = header.indexOf('coordinate_error');
  for (const line of lifecycle.slice(1)) {
    const columns = line.split(',');
    if (!columns[ruleIndex]) continue;
    assert.ok(Number(columns[coordinateIndex]) <= 5);
    assert.notEqual(columns[ruleIndex], 'SAME_NETWORK_ID');
  }
});

test('16.16 Ward runtime decoder rejects a manifest from another route', () => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-ward-manifest-'));
  try {
    const packets = path.join(temporary, 'packets.jsonl');
    const participants = path.join(temporary, 'participants.json');
    const output = path.join(temporary, 'output');
    fs.writeFileSync(packets, '');
    fs.writeFileSync(`${packets}.manifest.json`, `${JSON.stringify({
      schema_version: 1,
      target_replay_version: '16.16.805.0442',
      output: packets,
      packet_ids: [0x0314],
      selected_packet_count: 0,
      packet_counts: { [0x0314]: 0 },
      replay_count: 1,
      replays: [{ path: 'fixture.rofl', sha256: 'a'.repeat(64),
        version: '16.16.805.0442', selected_packet_count: 0, parser_error_count: 0 }],
    })}\n`);
    fs.writeFileSync(participants, '{}');
    assert.throws(() => execFileSync('python', [
      '-B', path.join(ROOT, 'scripts', 'decode_ward_spawn_16_16.py'),
      '--runtime-image', path.join(ROOT, 'artifacts', 'new_build_rofl_compatibility_gate_v1',
        'runtime', 'league_16.16.805.0442.memory.bin'),
      '--packets', packets,
      '--participants', participants,
      '--output', output,
    ], { cwd: ROOT, stdio: 'pipe' }));
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
});

test('16.16 Ward profile never resolves for 16.15', () => {
  assert.equal(semanticProfileFor('ward_spawn', '16.16.805.0442').profile.replay_block_packet_id,
    0x049a);
  assert.equal(semanticProfileFor('ward_spawn', '16.15.801.3452').status,
    'UNSUPPORTED_VERSION');
});

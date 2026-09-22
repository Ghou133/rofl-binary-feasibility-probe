'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  GAMEPLAY_ROUTE_TAIL_PROFILES,
  gameplayRouteTailEventFromDecodedRow,
} = require('../src/decoders/gameplay_route_tail_16_16');

const ROOT = path.resolve(__dirname, '..');
const PYTHON = process.env.PYTHON || 'python';
const SCRIPT = path.join(ROOT, 'scripts', 'decode_gameplay_route_tail_16_16.py');
const IMAGE_PATH = path.join(
  ROOT, 'artifacts', 'new_build_rofl_compatibility_gate_v1', 'runtime',
  'league_16.16.805.0442.memory.bin',
);
const IMAGE = fs.readFileSync(IMAGE_PATH);

function firstBalancedRow(route) {
  const filePath = path.join(
    ROOT, 'artifacts', 'full_semantic_deep_recovery_v2', 'gameplay_route_tail',
    'emulation', `route_${route.slice(2)}_balanced_decoded.jsonl`,
  );
  return JSON.parse(fs.readFileSync(filePath, 'utf8').split(/\r?\n/, 1)[0]);
}

test('one-pass gameplay-tail decoder conserves and fully consumes all six exact profiles', () => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-gameplay-tail-test-'));
  try {
    const events = path.join(temporary, 'events.jsonl');
    const output = path.join(temporary, 'decoded.jsonl');
    const summaryPath = path.join(temporary, 'summary.json');
    const routes = Object.keys(GAMEPLAY_ROUTE_TAIL_PROFILES);
    const rows = routes.map(firstBalancedRow);
    fs.writeFileSync(events, `${rows.map((row) => JSON.stringify(row)).join('\n')}\n`);
    const profileArgs = Object.values(GAMEPLAY_ROUTE_TAIL_PROFILES).flatMap((profile) => [
      '--profile-json', path.join(ROOT, profile.runtime_decoder_profile),
    ]);
    const run = childProcess.spawnSync(PYTHON, [
      '-B', SCRIPT, '--image', IMAGE_PATH, '--events', events,
      ...profileArgs, '--runtime-profile', '16.16.805.0442',
      '--output', output, '--summary', summaryPath, '--progress-every', '0',
    ], { cwd: ROOT, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
    assert.equal(run.status, 0, run.stderr || run.stdout);
    const summary = JSON.parse(fs.readFileSync(summaryPath, 'utf8'));
    assert.equal(summary.status, 'PASS');
    assert.equal(summary.input_event_count, 6);
    assert.equal(summary.output_row_count, 6);
    assert.equal(summary.successful_full_consume_count, 6);
    assert.equal(summary.emulation_error_count, 0);
    assert.equal(summary.input_conserved, true);
    const decoded = fs.readFileSync(output, 'utf8').trim().split(/\r?\n/).map(JSON.parse);
    assert.equal(decoded.length, 6);
    for (const row of decoded) {
      const event = gameplayRouteTailEventFromDecodedRow({
        source_sha256: row.replay_sha256,
        source_path: 'explicit-safe-public-fixture.rofl',
        header: { version: row.replay_version },
      }, row, IMAGE);
      assert.equal(event.replay_sha256, row.replay_sha256);
    }
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
});

test('one-pass decoder rejects protected paths before opening input', () => {
  const run = childProcess.spawnSync(PYTHON, [
    '-B', SCRIPT, '--image', IMAGE_PATH,
    '--events', path.join(ROOT, 'Jungle Objective Holdout', 'forbidden.jsonl'),
    '--profile-json', path.join(
      ROOT, GAMEPLAY_ROUTE_TAIL_PROFILES['0x00b8'].runtime_decoder_profile,
    ),
    '--output', path.join(os.tmpdir(), 'unused-gameplay-tail-output.jsonl'),
    '--summary', path.join(os.tmpdir(), 'unused-gameplay-tail-summary.json'),
  ], { cwd: ROOT, encoding: 'utf8' });
  assert.notEqual(run.status, 0);
  assert.match(run.stderr, /protected Holdout path is forbidden/);
});

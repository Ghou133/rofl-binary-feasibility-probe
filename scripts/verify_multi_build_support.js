#!/usr/bin/env node
'use strict';

const childProcess = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const { writeJson } = require('../src/io');

const ROOT = path.resolve(__dirname, '..');
const OUTPUT = path.join(ROOT, 'artifacts', 'multi_build_rofl_support_v1');
const PYTHON = process.env.PYTHON || 'python';
const DETAILS_ROOT = process.env.ROFL_DETAILS_ROOT || path.join(ROOT, 'artifacts', 'private_details');
const RUNTIME = path.join(
  ROOT, 'artifacts', 'new_build_rofl_compatibility_gate_v1', 'runtime',
  'league_16.16.805.0442.memory.bin',
);
const API_SMOKE_REPLAY = process.env.ROFL_MULTI_BUILD_SMOKE_REPLAY
  || path.join(ROOT, 'replay', '11190983438.rofl');
const API_NO_LEVEL_SMOKE_REPLAY = process.env.ROFL_MULTI_BUILD_NO_LEVEL_SMOKE_REPLAY
  || path.join(ROOT, 'replay', '11190984064.rofl');

function nodeTests(files) {
  return {
    label: `node --test (${files.length} files)`,
    command: process.execPath,
    args: ['--test', ...files],
  };
}

function commands() {
  const testFiles = fs.readdirSync(path.join(ROOT, 'test'))
    .filter((name) => name.endsWith('.test.js'))
    .sort()
    .map((name) => path.join('test', name));
  return [
    nodeTests(testFiles),
    {
      label: 'multi-build runtime validator unit tests',
      command: PYTHON,
      args: [
        '-B', '-m', 'unittest', 'discover', '-s', 'test',
        '-p', 'test_multi_build_runtime_validator.py', '-v',
      ],
    },
    nodeTests([
      'test/path_v2.test.js',
      'test/ward_v2.test.js',
      'test/ward_analysis_v2.test.js',
      'test/package_portability.test.js',
    ]),
    {
      label: '16.16 HeroPath exact runtime validation',
      command: PYTHON,
      args: [
        '-B', 'scripts/validate_multi_build_runtime.py', '--capability', 'hero_path',
        '--runtime-image', RUNTIME,
        '--packets', path.join(OUTPUT, 'runtime', 'path_00f6_packets.jsonl'),
        '--details-root', DETAILS_ROOT,
        '--output', path.join(OUTPUT, 'hero_path_validation'),
      ],
    },
    {
      label: '16.16 LevelTransition exact runtime validation',
      command: PYTHON,
      args: [
        '-B', 'scripts/validate_multi_build_runtime.py', '--capability', 'level_transition',
        '--runtime-image', RUNTIME,
        '--packets', path.join(OUTPUT, 'runtime', 'level_0314_packets.jsonl'),
        '--details-root', DETAILS_ROOT,
        '--output', path.join(OUTPUT, 'level_transition_validation'),
      ],
    },
    {
      label: 'automatic 16.16 profile resolution and public API smoke',
      command: process.execPath,
      args: [
        'scripts/smoke_multi_build_api.js',
        '--replay', API_SMOKE_REPLAY,
        '--runtime-image', RUNTIME,
        '--output', path.join(OUTPUT, 'auto_profile_resolution_smoke.json'),
      ],
    },
    {
      label: 'automatic 16.16 API no-LevelTransition observation smoke',
      command: process.execPath,
      args: [
        'scripts/smoke_multi_build_api.js',
        '--replay', API_NO_LEVEL_SMOKE_REPLAY,
        '--runtime-image', RUNTIME,
        '--output', path.join(OUTPUT, 'auto_profile_resolution_no_level_smoke.json'),
        '--expect-no-level',
      ],
    },
    {
      label: '16.15 LevelTransition frozen corpus',
      command: process.execPath,
      args: ['scripts/validate_level_transition_corpus.js'],
    },
    {
      label: '16.15 Damage frozen corpus',
      command: process.execPath,
      args: [
        'scripts/validate_damage_events.js',
        '--events', 'artifacts/semantic_probe/damage_events_hero.jsonl',
        '--event-manifest', 'artifacts/semantic_probe/damage_events_hero_manifest.json',
        '--anchors', 'artifacts/semantic_probe/known_event_anchors.json',
        '--decode-summary', 'artifacts/runtime_probe/packet_0650_wrapped_decode_all_summary.json',
        '--runtime-validation', 'artifacts/runtime_probe/unit_apply_damage_runtime_vs_offline_validation_summary.json',
        '--output-dir', 'artifacts/multi_build_rofl_support_v1/regression_16_15/damage',
      ],
    },
    {
      label: '16.15 Death frozen corpus',
      command: process.execPath,
      args: [
        'scripts/validate_death_events.js',
        '--events', 'artifacts/semantic_probe/death_events.jsonl',
        '--anchors', 'artifacts/semantic_probe/known_event_anchors.json',
        '--output-dir', 'artifacts/multi_build_rofl_support_v1/regression_16_15/death',
      ],
    },
    {
      label: '16.15 CastSpell frozen corpus',
      command: process.execPath,
      args: [
        'scripts/validate_spell_events.js',
        '--events', 'artifacts/semantic_probe/spell_events.jsonl',
        '--event-manifest', 'artifacts/semantic_probe/spell_events_manifest.json',
        '--decode-summary', 'artifacts/runtime_probe/packet_1113_decoded_all_summary.json',
        '--replay-dir', 'replay',
        '--output-dir', 'artifacts/multi_build_rofl_support_v1/regression_16_15/spell',
        '--label', 'multi-build-regression',
      ],
    },
    {
      label: '16.15 WardSpawn frozen corpus',
      command: process.execPath,
      args: ['scripts/validate_ward_spawn_16_15.js'],
    },
    {
      label: 'V2 saved-evidence regression',
      command: process.execPath,
      args: ['scripts/verify_v2_regression.js'],
    },
    {
      label: 'research-v3 unit tests',
      command: PYTHON,
      args: ['-B', '-m', 'unittest', 'discover', '-s', 'research-v3/tests', '-v'],
    },
    {
      label: 'research-v4 unit tests',
      command: PYTHON,
      args: ['-B', '-m', 'unittest', 'discover', '-s', 'research-v4/tests', '-v'],
    },
  ];
}

function tail(text, lineCount = 30) {
  return (text || '').trim().split(/\r?\n/).slice(-lineCount).join('\n');
}

function runCommand(specification) {
  const started = process.hrtime.bigint();
  const result = childProcess.spawnSync(specification.command, specification.args, {
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    timeout: 10 * 60 * 1000,
  });
  const seconds = Number(process.hrtime.bigint() - started) / 1e9;
  return {
    label: specification.label,
    command: [specification.command, ...specification.args].join(' '),
    status: !result.error && result.status === 0 ? 'PASS' : 'FAIL',
    exit_code: result.status,
    signal: result.signal,
    wall_seconds: seconds,
    stdout_tail: tail(result.stdout),
    stderr_tail: tail(result.stderr),
    error: result.error?.message ?? null,
  };
}

function markdown(report) {
  const lines = [
    '# Multi-build regression',
    '',
    `Status: \`${report.status}\``,
    '',
    `Wall time: ${report.wall_seconds.toFixed(3)} seconds`,
    '',
    '| Check | Status | Exit | Seconds |',
    '| --- | --- | ---: | ---: |',
    ...report.commands.map((row) => (
      `| ${row.label} | \`${row.status}\` | ${row.exit_code ?? ''} | ${row.wall_seconds.toFixed(3)} |`
    )),
    '',
  ];
  for (const row of report.commands) {
    lines.push(`## ${row.label}`, '', '```text');
    if (row.stdout_tail) lines.push(row.stdout_tail);
    if (row.stderr_tail) lines.push(row.stderr_tail);
    if (row.error) lines.push(row.error);
    lines.push('```', '');
  }
  return `${lines.join('\n')}\n`;
}

function main() {
  const startedAt = new Date();
  const started = process.hrtime.bigint();
  const results = commands().map(runCommand);
  const report = {
    schema_version: 1,
    status: results.every((row) => row.status === 'PASS') ? 'PASS' : 'FAIL',
    started_at_utc: startedAt.toISOString(),
    finished_at_utc: new Date().toISOString(),
    wall_seconds: Number(process.hrtime.bigint() - started) / 1e9,
    commands: results,
  };
  fs.mkdirSync(OUTPUT, { recursive: true });
  writeJson(path.join(OUTPUT, 'multi_build_regression.json'), report);
  fs.writeFileSync(path.join(OUTPUT, 'multi_build_regression.md'), markdown(report), 'utf8');
  process.stdout.write(`${JSON.stringify({
    status: report.status,
    wall_seconds: report.wall_seconds,
    commands: report.commands.map((row) => ({
      label: row.label,
      status: row.status,
      exit_code: row.exit_code,
      wall_seconds: row.wall_seconds,
    })),
  }, null, 2)}\n`);
  if (report.status !== 'PASS') process.exitCode = 1;
}

if (require.main === module) main();

module.exports = { commands, runCommand };

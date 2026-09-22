#!/usr/bin/env node
'use strict';

const path = require('node:path');

const {
  TARGET_BUILD,
  createCombatStateCandidateReport,
  writeCombatStateCandidateReport,
} = require('../src/combat_state_candidate_probe');

function parseArgs(argv) {
  const options = {
    output: path.resolve('artifacts', 'semantic_coverage_v1', 'combat_candidate_report.json'),
    replayPaths: [],
    runtimeImagePath: null,
    targetBuild: TARGET_BUILD,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === '--output') options.output = path.resolve(argv[++index]);
    else if (value === '--replay') options.replayPaths.push(path.resolve(argv[++index]));
    else if (value === '--runtime-image') options.runtimeImagePath = path.resolve(argv[++index]);
    else if (value === '--build') options.targetBuild = argv[++index];
    else if (value === '--help' || value === '-h') options.help = true;
    else if (value.startsWith('-')) throw new Error(`unknown option: ${value}`);
    else if (value.toLowerCase().endsWith('.rofl')) options.replayPaths.push(path.resolve(value));
    else throw new Error(`expected a .rofl path; got ${value}`);
  }
  if (!options.help && options.replayPaths.length === 0) {
    throw new Error('supply at least one exact-build .rofl input');
  }
  return options;
}

function usage() {
  return [
    'Usage: node scripts/probe_combat_state_candidates.js [options] replay.rofl ...',
    '  --output FILE          Deterministic JSON report path',
    '  --runtime-image FILE   Optional exact runtime image for name-only evidence',
    `  --build BUILD          Exact build to require (default ${TARGET_BUILD})`,
  ].join('\n');
}

function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.help) {
    process.stdout.write(`${usage()}\n`);
    return null;
  }
  const report = createCombatStateCandidateReport(options);
  const output = writeCombatStateCandidateReport(options.output, report);
  process.stdout.write(`${JSON.stringify({
    output,
    target_build: report.target_build,
    replay_count: report.input.replay_count,
    framed_block_count: report.input.framed_block_count,
    packet_type_count: report.input.packet_type_count,
    probe_status: report.probe_status,
    semantic_result: report.semantic_result,
  }, null, 2)}\n`);
  return report;
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { main, parseArgs, usage };

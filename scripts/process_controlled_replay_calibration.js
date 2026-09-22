#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const { processControlledReplayCalibration } = require('../src/controlled_replay_calibration');

function usage() {
  return [
    'Process one explicitly supplied controlled Replay and structured action log.',
    '',
    'Usage:',
    '  node scripts/process_controlled_replay_calibration.js --spec SPEC.json',
    '',
    'The spec must name replay.path, replay.expected_sha256, replay.exact_build,',
    'replay.champion, action_log, and output_directory. Directory discovery and',
    'nearest-build fallback are forbidden.',
  ].join('\n');
}

function parseArguments(argv) {
  if (argv.length === 1 && (argv[0] === '--help' || argv[0] === '-h')) return { help: true };
  if (argv.length !== 2 || argv[0] !== '--spec') throw new Error('exactly --spec SPEC.json is required');
  const specPath = path.resolve(argv[1]);
  if (/jungle[_ -]?objective[_ -]?holdout|protected[_ -]?holdout|holdout/i.test(specPath)) {
    throw new Error('spec path references protected Holdout');
  }
  return { spec_path: specPath };
}

function main(argv = process.argv.slice(2)) {
  const options = parseArguments(argv);
  if (options.help) {
    process.stdout.write(`${usage()}\n`);
    return null;
  }
  const spec = JSON.parse(fs.readFileSync(options.spec_path, 'utf8'));
  const result = processControlledReplayCalibration(spec);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  return result;
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { main, parseArguments, usage };

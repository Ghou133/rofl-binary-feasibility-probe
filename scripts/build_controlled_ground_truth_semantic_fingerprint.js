#!/usr/bin/env node
'use strict';

const path = require('node:path');

const {
  DEFAULT_OUTPUT_DIRECTORY,
  buildControlledGroundTruthStage,
} = require('../src/controlled_ground_truth_stage');

function parseArguments(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--output') {
      if (!argv[index + 1]) throw new Error('--output requires a directory');
      options.output_directory = argv[index + 1];
      index += 1;
    } else if (argument === '--repository-root') {
      if (!argv[index + 1]) throw new Error('--repository-root requires a directory');
      options.repository_root = argv[index + 1];
      index += 1;
    } else if (argument === '--help' || argument === '-h') {
      return { help: true };
    } else {
      throw new Error(`unknown argument: ${argument}`);
    }
  }
  return options;
}

function usage() {
  return [
    'Build controlled ground-truth, semantic fingerprint, and migration-oracle artifacts.',
    '',
    'Usage:',
    '  node scripts/build_controlled_ground_truth_semantic_fingerprint.js [--output DIRECTORY]',
    '',
    `Default output: ${DEFAULT_OUTPUT_DIRECTORY}`,
    '',
    'Only the frozen explicit safe input allowlist is consumed; input directory discovery is forbidden.',
  ].join('\n');
}

function main(argv = process.argv.slice(2)) {
  const options = parseArguments(argv);
  if (options.help) {
    process.stdout.write(`${usage()}\n`);
    return null;
  }
  const repositoryRoot = path.resolve(options.repository_root ?? path.resolve(__dirname, '..'));
  const result = buildControlledGroundTruthStage({ ...options, repository_root: repositoryRoot });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  return result;
}

if (require.main === module) main();

module.exports = { main, parseArguments, usage };

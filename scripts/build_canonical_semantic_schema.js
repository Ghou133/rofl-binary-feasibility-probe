#!/usr/bin/env node
'use strict';

const path = require('node:path');
const {
  DEFAULT_EXACT_BUILD,
  buildCanonicalSemanticSchemaArtifacts,
} = require('../src/canonical_semantic_schema');

function requireValue(argv, index, option) {
  if (index >= argv.length || argv[index].startsWith('--')) throw new Error(`${option} requires a value`);
  return argv[index];
}

function parseArgs(argv) {
  const options = {
    root: process.cwd(),
    capabilityManifestPath: 'artifacts/semantic_coverage_v1/capability_manifest.json',
    outputDirectory: 'artifacts/full_semantic_baseline_v1/schema',
    exactBuild: DEFAULT_EXACT_BUILD,
    help: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    if (option === '--help' || option === '-h') options.help = true;
    else if (option === '--root') options.root = requireValue(argv, ++index, option);
    else if (option === '--manifest') options.capabilityManifestPath = requireValue(argv, ++index, option);
    else if (option === '--output-dir') options.outputDirectory = requireValue(argv, ++index, option);
    else if (option === '--build') options.exactBuild = requireValue(argv, ++index, option);
    else throw new Error(`unknown option: ${option}`);
  }
  return options;
}

function usage() {
  return [
    'Usage: node scripts/build_canonical_semantic_schema.js [options]',
    '',
    `  --build BUILD       Exact build only (default ${DEFAULT_EXACT_BUILD})`,
    '  --manifest FILE     Exact-build capability manifest',
    '  --output-dir DIR    Schema artifact directory',
    '  --root DIR          Input/output resolution root',
    '  --help              Show help',
    '',
    'Holdout paths are rejected before read, enumeration, or hashing.',
  ].join('\n');
}

function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.help) {
    process.stdout.write(`${usage()}\n`);
    return null;
  }
  const result = buildCanonicalSemanticSchemaArtifacts({
    root: path.resolve(options.root),
    capabilityManifestPath: options.capabilityManifestPath,
    outputDirectory: options.outputDirectory,
    exactBuild: options.exactBuild,
  });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  return result;
}

if (require.main === module) {
  try { main(); } catch (error) { process.stderr.write(`${error.stack ?? error.message}\n`); process.exitCode = 1; }
}

module.exports = { main, parseArgs, usage };

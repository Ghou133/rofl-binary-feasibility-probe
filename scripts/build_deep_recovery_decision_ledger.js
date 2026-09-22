#!/usr/bin/env node
'use strict';

const path = require('node:path');
const {
  buildDecisionLedger,
  loadSafeSources,
  writeDecisionLedgerArtifacts,
} = require('../src/deep_recovery_decision_ledger');

function parseArgs(argv) {
  const options = {
    root: process.cwd(),
    output: 'artifacts/full_semantic_deep_recovery_v2/decision_ledger',
    generatedAt: '2026-08-20',
  };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === '--root') options.root = argv[++index];
    else if (value === '--output') options.output = argv[++index];
    else if (value === '--generated-at') options.generatedAt = argv[++index];
    else if (value === '--help' || value === '-h') options.help = true;
    else throw new Error(`unknown argument ${value}`);
  }
  return options;
}

function usage() {
  return [
    'Usage: node scripts/build_deep_recovery_decision_ledger.js [options]',
    '',
    'Options:',
    '  --root <directory>        Project root (default: current directory)',
    '  --output <directory>      Output directory relative to root',
    '  --generated-at <date>     Deterministic ledger date (default: 2026-08-20)',
    '  --help                    Show this help',
  ].join('\n');
}

function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.help) {
    process.stdout.write(`${usage()}\n`);
    return null;
  }
  const root = path.resolve(options.root);
  const sources = loadSafeSources(root);
  const ledger = buildDecisionLedger({ sources, generatedAt: options.generatedAt });
  const outputDirectory = path.resolve(root, options.output);
  const written = writeDecisionLedgerArtifacts(outputDirectory, ledger);
  const summary = {
    status: 'PASS',
    exact_build: ledger.exact_build,
    output_directory: written.output_directory,
    route_decision_count: ledger.summary.route_decision_count,
    capability_decision_count: ledger.summary.capability_decision_count,
    domain_decision_count: ledger.summary.domain_decision_count,
    input_source_count: ledger.summary.input_source_count,
    ledger_sha256: written.ledger.sha256,
    manifest_sha256: written.manifest.sha256,
  };
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
  return summary;
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.stack ?? error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { main, parseArgs, usage };

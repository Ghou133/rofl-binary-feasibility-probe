#!/usr/bin/env node
'use strict';

const path = require('node:path');

const {
  DEEP_RECOVERY_BUILD,
  buildDeepRecoveryPriority,
  loadDeepRecoveryInputs,
  writeDeepRecoveryArtifacts,
} = require('../src/semantic_research_priority');

function valueAfter(argv, index, option) {
  if (index + 1 >= argv.length || argv[index + 1].startsWith('--')) {
    throw new Error(`${option} requires a value`);
  }
  return argv[index + 1];
}

function parseArgs(argv) {
  const options = {
    root: process.cwd(),
    exactBuild: DEEP_RECOVERY_BUILD,
    observedRegistryPath: 'artifacts/full_semantic_baseline_v1/observed_route_registry.json',
    capabilityManifestPath: 'artifacts/semantic_coverage_v1/capability_manifest.json',
    negativeEvidencePath: 'artifacts/full_semantic_baseline_v1/negative_evidence_registry.json',
    regressionAttestationPath: 'artifacts/full_semantic_baseline_v1/regression/regression_attestation_16_16.json',
    decisionPaths: [],
    outputDirectory: 'artifacts/full_semantic_deep_recovery_v2',
    generatedAt: '2026-08-20',
    help: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    if (option === '--help' || option === '-h') options.help = true;
    else if (option === '--root') options.root = valueAfter(argv, index++, option);
    else if (option === '--build') options.exactBuild = valueAfter(argv, index++, option);
    else if (option === '--observed-registry') options.observedRegistryPath = valueAfter(argv, index++, option);
    else if (option === '--capability-manifest') options.capabilityManifestPath = valueAfter(argv, index++, option);
    else if (option === '--negative-evidence') options.negativeEvidencePath = valueAfter(argv, index++, option);
    else if (option === '--regression-attestation') options.regressionAttestationPath = valueAfter(argv, index++, option);
    else if (option === '--decision') options.decisionPaths.push(valueAfter(argv, index++, option));
    else if (option === '--output-dir') options.outputDirectory = valueAfter(argv, index++, option);
    else if (option === '--generated-at') options.generatedAt = valueAfter(argv, index++, option);
    else throw new Error(`unknown option: ${option}`);
  }
  if (options.decisionPaths.length > 1) {
    throw new Error('exactly one validated final decision ledger may be supplied');
  }
  return options;
}

function usage() {
  return [
    'Usage: node scripts/build_semantic_deep_recovery.js [options]',
    '',
    `  --build BUILD                  Exact build only (default ${DEEP_RECOVERY_BUILD})`,
    '  --observed-registry FILE       V1 observed route registry',
    '  --capability-manifest FILE     Exact-build capability manifest',
    '  --negative-evidence FILE       V1 negative evidence registry',
    '  --regression-attestation FILE  Passing exact-build regression attestation',
    '  --decision FILE                One validated final decision ledger',
    '  --output-dir DIRECTORY         Output directory',
    '  --root DIRECTORY               Resolve paths from this root',
    '  --generated-at VALUE           Deterministic generated_at value',
    '',
    'Protected Holdout paths are rejected before reads or hashing.',
  ].join('\n');
}

function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.help) {
    process.stdout.write(`${usage()}\n`);
    return null;
  }
  const root = path.resolve(options.root);
  const inputs = loadDeepRecoveryInputs({
    root,
    observedRegistryPath: options.observedRegistryPath,
    capabilityManifestPath: options.capabilityManifestPath,
    negativeEvidencePath: options.negativeEvidencePath,
    regressionAttestationPath: options.regressionAttestationPath,
    decisionPaths: options.decisionPaths,
  });
  const result = buildDeepRecoveryPriority({
    exactBuild: options.exactBuild,
    ...inputs,
    generatedAt: options.generatedAt,
  });
  const written = writeDeepRecoveryArtifacts(path.resolve(root, options.outputDirectory), result);
  const summary = {
    exact_build: result.queue.exact_build,
    queue: result.queue.summary,
    saturation: {
      status: result.saturation.status,
      saturated: result.saturation.saturated,
      checks: result.saturation.saturation_checks,
    },
    files: written.files,
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

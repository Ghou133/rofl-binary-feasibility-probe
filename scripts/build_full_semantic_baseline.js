#!/usr/bin/env node
'use strict';

const path = require('node:path');

const {
  DEFAULT_EXACT_BUILD,
  DEFAULT_INPUT_PATHS,
  buildFullSemanticBaselineFromPaths,
  writeFullSemanticBaselineArtifacts,
} = require('../src/full_semantic_baseline');

function requireValue(argv, index, option) {
  if (index >= argv.length || argv[index].startsWith('--')) {
    throw new Error(`${option} requires a value`);
  }
  return argv[index];
}

function parseArgs(argv) {
  const options = {
    root: process.cwd(),
    outputDirectory: 'artifacts/full_semantic_baseline_v1',
    targetBuild: DEFAULT_EXACT_BUILD,
    inventoryPath: DEFAULT_INPUT_PATHS.inventory,
    callbackMapPath: DEFAULT_INPUT_PATHS.callbackMap,
    capabilityManifestPath: DEFAULT_INPUT_PATHS.capabilityManifest,
    profilerCoveragePath: DEFAULT_INPUT_PATHS.profilerCoverage,
    profilerProfilePaths: null,
    negativeAuditPaths: null,
    supplementalEvidencePaths: null,
    generatedAt: undefined,
    help: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    if (option === '--help' || option === '-h') options.help = true;
    else if (option === '--root') options.root = requireValue(argv, ++index, option);
    else if (option === '--output-dir') options.outputDirectory = requireValue(argv, ++index, option);
    else if (option === '--build') options.targetBuild = requireValue(argv, ++index, option);
    else if (option === '--inventory') options.inventoryPath = requireValue(argv, ++index, option);
    else if (option === '--callback-map') options.callbackMapPath = requireValue(argv, ++index, option);
    else if (option === '--capability-manifest') {
      options.capabilityManifestPath = requireValue(argv, ++index, option);
    } else if (option === '--profiler-coverage') {
      options.profilerCoveragePath = requireValue(argv, ++index, option);
    } else if (option === '--profiler-profile') {
      if (options.profilerProfilePaths === null) options.profilerProfilePaths = [];
      options.profilerProfilePaths.push(requireValue(argv, ++index, option));
    } else if (option === '--negative-audit') {
      if (options.negativeAuditPaths === null) options.negativeAuditPaths = [];
      options.negativeAuditPaths.push(requireValue(argv, ++index, option));
    } else if (option === '--supplemental-evidence') {
      if (options.supplementalEvidencePaths === null) options.supplementalEvidencePaths = [];
      options.supplementalEvidencePaths.push(requireValue(argv, ++index, option));
    } else if (option === '--generated-at') options.generatedAt = requireValue(argv, ++index, option);
    else throw new Error(`unknown option: ${option}`);
  }
  return options;
}

function usage() {
  return [
    'Usage: node scripts/build_full_semantic_baseline.js [options]',
    '',
    `  --build BUILD                 Exact build only (default ${DEFAULT_EXACT_BUILD})`,
    '  --inventory FILE              Exact-build observed packet inventory',
    '  --callback-map FILE           Observed callback/factory route sidecar',
    '  --capability-manifest FILE    Existing exact-build capability manifest',
    '  --profiler-coverage FILE      Field-profiler coverage matrix',
    '  --profiler-profile FILE       Profiler negative-control profile; repeatable',
    '  --negative-audit FILE         Independent negative audit; repeatable',
    '  --supplemental-evidence FILE  Provenance-only runtime/schema/validation/regression JSON; repeatable',
    '  --output-dir DIRECTORY        Output directory',
    '  --root DIRECTORY              Resolve input/output paths from this root',
    '  --generated-at VALUE          Deterministic generated_at override',
    '  --help                        Show this help',
    '',
    'Holdout paths are rejected before any read or hash operation.',
  ].join('\n');
}

function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.help) {
    process.stdout.write(`${usage()}\n`);
    return null;
  }
  const root = path.resolve(options.root);
  const result = buildFullSemanticBaselineFromPaths({
    root,
    targetBuild: options.targetBuild,
    inventoryPath: options.inventoryPath,
    callbackMapPath: options.callbackMapPath,
    capabilityManifestPath: options.capabilityManifestPath,
    profilerCoveragePath: options.profilerCoveragePath,
    profilerProfilePaths: options.profilerProfilePaths ?? undefined,
    negativeAuditPaths: options.negativeAuditPaths ?? undefined,
    supplementalEvidencePaths: options.supplementalEvidencePaths ?? undefined,
    generatedAt: options.generatedAt,
  });
  const outputDirectory = path.resolve(root, options.outputDirectory);
  const written = writeFullSemanticBaselineArtifacts(outputDirectory, result);
  const summary = {
    schema: result.baseline.schema,
    analyzer_version: result.baseline.analyzer_version,
    exact_build: result.baseline.exact_build,
    metrics: result.baseline.metrics,
    conservation: result.baseline.conservation,
    completeness_gate: {
      ready: result.completenessGate.ready,
      status: result.completenessGate.status,
      blocker_count: result.completenessGate.blockers.length,
    },
    output_directory: written.output_directory,
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

module.exports = {
  main,
  parseArgs,
  usage,
};

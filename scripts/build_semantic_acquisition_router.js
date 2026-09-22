#!/usr/bin/env node
'use strict';

const path = require('node:path');
const { writeSemanticAcquisitionArtifacts } = require('../src/semantic_acquisition_router');

function option(name, fallback) {
  const index = process.argv.indexOf(name);
  return index >= 0 && process.argv[index + 1] ? process.argv[index + 1] : fallback;
}

function values(name) {
  return process.argv.flatMap((value, index) => value === name && process.argv[index + 1]
    ? [process.argv[index + 1]] : []);
}

function main() {
  const rootDir = path.resolve(__dirname, '..');
  const semanticNames = values('--semantic');
  const requests = (semanticNames.length ? semanticNames : [
    'BASE_STAT_AT_LEVEL', 'ITEM_STAT_CONTRIBUTION', 'ARMOR',
    'EFFECTIVE_DEFENSE_FOR_DAMAGE_EVENT', 'DAMAGE_STAGE', 'MITIGATION_CLOSURE',
    'SHIELD_LIFECYCLE', 'HEAL_EFFECTIVE_OVERHEAL', 'CURRENT_HP', 'ABILITY_HASTE',
  ]).map((semantic_name) => ({ semantic_name, desired_precision: 'EXACT_BUILD_SEMANTIC' }));
  const result = writeSemanticAcquisitionArtifacts({
    outputDir: path.resolve(option('--output-dir', path.join(rootDir, '.omo', 'evidence', 'semantic_acquisition_router'))),
    requests,
  });
  process.stdout.write(`${JSON.stringify({
    status: result.manifest.status,
    plan_count: result.plans.length,
    manifest_path: result.manifest_path,
    protected_holdout: result.manifest.protected_holdout,
  }, null, 2)}\n`);
}

try {
  main();
} catch (error) {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
}

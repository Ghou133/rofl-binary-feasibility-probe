#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {
  writeDynamicDefensePhaseArtifacts,
} = require('../src/dynamic_defense_semantic_layer');
const {
  canonicalizeExistingSafePath,
  canonicalizeProspectiveSafePath,
} = require('../src/mechanics_build_importer');

function usage() {
  return 'usage: node scripts/build_dynamic_defense_semantic_layer.js --evidence <json> --output <dir>';
}

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!['--evidence', '--output'].includes(key) || !value) throw new Error(usage());
    options[key.slice(2)] = value;
  }
  if (!options.evidence || !options.output) throw new Error(usage());
  return options;
}

function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  const evidenceFile = canonicalizeExistingSafePath(options.evidence, 'dynamic defense evidence input');
  const evidence = JSON.parse(fs.readFileSync(evidenceFile, 'utf8').replace(/^\uFEFF/u, ''));
  const outputDir = canonicalizeProspectiveSafePath(options.output, 'dynamic defense output directory');
  const result = writeDynamicDefensePhaseArtifacts({ outputDir, evidence });
  process.stdout.write(`${JSON.stringify({ status: result.report.status,
    output_dir: path.dirname(result.paths['artifact_manifest.json']), paths: result.paths }, null, 2)}\n`);
  return result;
}

if (require.main === module) main();

module.exports = { main, parseArgs };

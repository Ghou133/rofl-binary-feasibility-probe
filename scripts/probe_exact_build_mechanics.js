'use strict';

const path = require('node:path');
const { writeProbeArtifacts } = require('../src/exact_build_mechanics_probe');

const rootDir = path.resolve(__dirname, '..');
const outputDir = process.argv[2]
  ? path.resolve(process.argv[2])
  : path.join(rootDir, '.omo', 'evidence', 'stat_semantic_mapping_v1', 'exact_mechanics');

const result = writeProbeArtifacts({ rootDir, outputDir });
process.stdout.write(`${JSON.stringify({
  status: result.exact_build_mechanics_data.status,
  decision: result.exact_build_mechanics_data.decision,
  mechanics_path: result.paths.mechanics,
  exception_registry_path: result.paths.exceptions,
  manifest_path: result.paths.manifest,
}, null, 2)}\n`);

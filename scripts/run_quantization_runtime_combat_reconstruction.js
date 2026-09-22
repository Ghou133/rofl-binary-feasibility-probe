#!/usr/bin/env node
'use strict';

const path = require('node:path');
const { runIntegratedReconstruction } = require('../src/quantization_runtime_combat_reconstruction');

const rootDir = path.resolve(__dirname, '..');
let outputDir = path.join(rootDir, '.omo', 'evidence', 'quantization_runtime_combat_reconstruction_v1');
for (let index = 2; index < process.argv.length; index += 1) {
  if (process.argv[index] === '--output-dir') outputDir = path.resolve(process.argv[++index]);
  else throw new Error(`unknown argument: ${process.argv[index]}`);
}

try {
  const { report, paths } = runIntegratedReconstruction({ rootDir, outputDir });
  process.stdout.write(`${JSON.stringify({
    status: report.status,
    stop_condition: report.stop_condition,
    p0_candidate_counts: report.p0_candidate_counts,
    paths,
  }, null, 2)}\n`);
} catch (error) {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
}

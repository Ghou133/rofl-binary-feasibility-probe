#!/usr/bin/env node
'use strict';

const path = require('node:path');
const { runQuantizationAwareP0Recovery } = require('../src/quantization_aware_p0_recovery');

function valueAfter(args, name) {
  const index = args.indexOf(name);
  return index < 0 ? undefined : args[index + 1];
}

const args = process.argv.slice(2);
const result = runQuantizationAwareP0Recovery({
  repository_root: path.resolve(__dirname, '..'),
  output_directory: valueAfter(args, '--output-dir'),
  replay_path: valueAfter(args, '--replay'),
  oracle_path: valueAfter(args, '--oracle'),
  prior_report_path: valueAfter(args, '--prior-report'),
});
process.stdout.write(`${JSON.stringify({
  status: result.status,
  output_directory: result.output_directory,
  report_path: result.report_path,
  artifact_manifest: result.artifact_manifest,
  p0_candidate_counts: result.report.p0_candidate_counts,
}, null, 2)}\n`);

#!/usr/bin/env node
'use strict';

const path = require('node:path');
const { finalizeEvidenceManifest, runStatModifierDependencyAudit } = require('../src/stat_modifier_dependency');

const rootDir = path.resolve(__dirname, '..');
let outputDir = path.join(rootDir, '.omo', 'evidence', 'stat_semantic_mapping_v1',
  'modifier_dependency');
let finalize = false;
let testResultsPath = null;
for (let index = 2; index < process.argv.length; index += 1) {
  if (process.argv[index] === '--output-dir') outputDir = path.resolve(process.argv[++index]);
  else if (process.argv[index] === '--finalize') finalize = true;
  else if (process.argv[index] === '--test-results') testResultsPath = path.resolve(process.argv[++index]);
  else throw new Error(`unknown argument: ${process.argv[index]}`);
}

if (finalize) {
  if (!testResultsPath) throw new Error('--finalize requires --test-results');
  const result = finalizeEvidenceManifest({ outputDir, testResultsPath });
  process.stdout.write(`${JSON.stringify({ status: 'EVIDENCE_FINALIZED', ...result }, null, 2)}\n`);
  process.exit(0);
}

runStatModifierDependencyAudit({ rootDir, outputDir }).then(({ report, paths }) => {
  process.stdout.write(`${JSON.stringify({
    status: report.status,
    exact_build: report.exact_build,
    adjustment_record_count: report.adjustment_observations.record_count,
    formula_row_count: report.formula_observations.row_count,
    same_entity_temporal_pairs: report.dependency_analysis.same_replay_entity_formula_series_count,
    promoted_dependency_edges: report.semantic_decision.formula_dependency.promoted_edges.length,
    selector_status: report.semantic_decision.selector.status,
    operation_status: report.semantic_decision.operation.status,
    evidence_finalized: false,
    paths,
  }, null, 2)}\n`);
}).catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});

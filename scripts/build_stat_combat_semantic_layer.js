#!/usr/bin/env node
'use strict';

const path = require('node:path');

const { writeBaselineArtifacts } = require('../src/stat_combat_semantic_layer');

function option(name, fallback) {
  const index = process.argv.indexOf(name);
  return index >= 0 && process.argv[index + 1] ? process.argv[index + 1] : fallback;
}

function main() {
  const rootDir = path.resolve(__dirname, '..');
  const outputDir = path.resolve(option('--output-dir', path.join(
    rootDir, '.omo', 'evidence', 'stat_semantic_mapping_v1', 'integration',
  )));
  const { report, paths } = writeBaselineArtifacts({ rootDir, outputDir });
  process.stdout.write(`${JSON.stringify({
    status: report.status,
    stop_condition: report.stop_condition,
    verified_stat_mapping_count: report.stat_selector_summary.verified_mapping_count,
    promoted_modifier_dependency_edge_count:
      report.stat_modifier_summary.promoted_dependency_edge_count,
    public_semantic_change_count: report.public_semantic_changes_this_stage.length,
    capability_count: report.derivable_capability_audit_v2.capability_count,
    paths,
  }, null, 2)}\n`);
}

try {
  main();
} catch (error) {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
}

'use strict';

const path = require('node:path');
const {
  canonicalizeExistingSafePath,
  canonicalizeProspectiveSafePath,
  writeExactBuildChampionComponentArtifacts,
} = require('../src/exact_build_champion_component');

const [reportPath, expectedSha256, outputArgument] = process.argv.slice(2);
if (!reportPath || !expectedSha256) {
  throw new Error('usage: node scripts/build_exact_build_champion_component.js <champion-stats-report.json> <expected-sha256> [output-dir]');
}
const canonicalReport = canonicalizeExistingSafePath(reportPath, 'champion extraction report');
const outputDir = outputArgument
  ? canonicalizeProspectiveSafePath(outputArgument, 'output directory')
  : path.join(__dirname, '..', '.omo', 'evidence', 'dynamic_defense_v1', 'champion_component');
const result = writeExactBuildChampionComponentArtifacts({
  reportPath: canonicalReport,
  expectedSha256,
  outputDir,
});
process.stdout.write(`${JSON.stringify({
  status: result.component.status,
  exact_build: result.component.exact_build,
  consumer_permission: result.component.consumer_permission,
  component_path: result.paths.component,
  descriptor_path: result.paths.descriptor,
  validation_path: result.paths.validation,
  validation_evidence_sha256: result.semanticScope.validation_evidence_sha256,
  mapped_root_character_records: result.component.coverage.mapped_root_character_records,
}, null, 2)}\n`);

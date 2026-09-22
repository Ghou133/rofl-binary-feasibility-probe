#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const { assertSafePath, probeExactCombatDataflow } = require('../src/exact_combat_dataflow_probe');

function digest(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function main() {
  const rootDir = path.resolve(__dirname, '..');
  const outputDir = assertSafePath(process.argv[2] || path.join(rootDir, '.omo', 'evidence',
    'stat_semantic_mapping_v1', 'combat_dataflow'), { mustExist: false });
  fs.mkdirSync(outputDir, { recursive: true });
  const report = probeExactCombatDataflow({ rootDir });
  const reportPath = path.join(outputDir, 'exact_combat_dataflow_report.json');
  fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
  const reportBuffer = fs.readFileSync(reportPath);
  const testResult = childProcess.spawnSync(process.execPath, [
    '--test', '--test-reporter', 'tap', path.join(rootDir, 'test', 'exact_combat_dataflow_probe.test.js'),
  ], { cwd: rootDir, encoding: 'utf8', windowsHide: true });
  const testLog = `${testResult.stdout || ''}${testResult.stderr || ''}`
    .replace(/duration_ms: [0-9.]+/g, 'duration_ms: NORMALIZED')
    .replace(/# duration_ms [0-9.]+/g, '# duration_ms NORMALIZED');
  if (testResult.status !== 0) throw new Error(`combat dataflow tests failed:\n${testLog}`);
  const testPath = path.join(outputDir, 'exact_combat_dataflow_test.tap');
  fs.writeFileSync(testPath, testLog);
  const testBuffer = fs.readFileSync(testPath);
  const manifest = {
    schema: 'ROFL_EXACT_COMBAT_DATAFLOW_EVIDENCE_MANIFEST_V1',
    exact_build: report.exact_build,
    runtime_image_sha256: report.image.sha256,
    status: report.status,
    artifacts: [
      { path: path.basename(reportPath), bytes: reportBuffer.length, sha256: digest(reportBuffer) },
      { path: path.basename(testPath), bytes: testBuffer.length, sha256: digest(testBuffer) },
    ],
    protected_holdout_accessed_enumerated_hashed_or_consumed: false,
  };
  const manifestPath = path.join(outputDir, 'artifact_manifest.json');
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify({ report: reportPath, manifest: manifestPath, status: report.status })}\n`);
}

main();

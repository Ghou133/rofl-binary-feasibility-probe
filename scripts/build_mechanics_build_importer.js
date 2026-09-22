'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {
  canonicalizeExistingSafePath,
  canonicalizeProspectiveSafePath,
  writeMechanicsBuildArtifacts,
} = require('../src/mechanics_build_importer');

const rootDir = path.resolve(__dirname, '..');
const descriptorPath = process.argv[2];
if (!descriptorPath) throw new Error('usage: node scripts/build_mechanics_build_importer.js <source-descriptors.json> [output-dir] [previous-manifest.json]');

const descriptorFile = canonicalizeExistingSafePath(descriptorPath, 'source descriptor file');
const descriptorDocument = JSON.parse(fs.readFileSync(descriptorFile, 'utf8'));
const outputDir = process.argv[3]
  ? canonicalizeProspectiveSafePath(process.argv[3], 'output directory')
  : path.join(rootDir, '.omo', 'evidence', 'mechanics_build_importer');
let previousManifest = null;
if (process.argv[4]) {
  const previousFile = canonicalizeExistingSafePath(process.argv[4], 'previous mechanics manifest');
  previousManifest = JSON.parse(fs.readFileSync(previousFile, 'utf8'));
}
const result = writeMechanicsBuildArtifacts({
  outputDir,
  requestedBuild: descriptorDocument.requested_build,
  sources: descriptorDocument.sources,
  previousManifest,
});
process.stdout.write(`${JSON.stringify({
  status: result.mechanics.status,
  exact_build: result.mechanics.exact_build,
  consumer_permission: result.mechanics.consumer_permission,
  mechanics_path: result.paths.mechanics,
  closure_path: result.paths.closure,
  closure_sha256: result.artifacts.find((row) => row.name === 'artifact_closure').sha256,
}, null, 2)}\n`);

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {
  canonicalizeExistingSafePath,
  canonicalizeProspectiveSafePath,
  writeExactClientItemStatInventoryArtifacts,
} = require('../src/exact_client_item_stat_inventory');

const rootDir = path.resolve(__dirname, '..');
const [itemsPath, expectedSha256, bindingPath, requestedOutputDir] = process.argv.slice(2);
if (!itemsPath || !expectedSha256 || !bindingPath) {
  throw new Error('usage: node scripts/build_exact_client_item_stat_inventory.js <items.json> <expected-sha256> <exact-build-binding.json> [output-dir]');
}
const bindingFile = canonicalizeExistingSafePath(bindingPath, 'exact build binding');
const outputDir = requestedOutputDir
  ? canonicalizeProspectiveSafePath(requestedOutputDir, 'output directory')
  : path.join(rootDir, '.omo', 'evidence', 'exact_client_item_stat_inventory');
const result = writeExactClientItemStatInventoryArtifacts({
  outputDir,
  itemsPath,
  expectedSha256,
  exactBuildBinding: JSON.parse(fs.readFileSync(bindingFile, 'utf8')),
});
process.stdout.write(`${JSON.stringify({
  status: result.inventory.status,
  exact_build: result.inventory.exact_build,
  mechanics_consumer_eligible: result.inventory.mechanics_consumer_eligible,
  inventory_path: result.paths.inventory,
  closure_path: result.paths.closure,
  inventory_sha256: result.artifacts[0].sha256,
}, null, 2)}\n`);

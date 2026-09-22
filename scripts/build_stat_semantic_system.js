#!/usr/bin/env node
'use strict';

const path = require('node:path');

const { writeRegistryArtifacts } = require('../src/stat_semantic_system');

function argument(name, fallback) {
  const index = process.argv.indexOf(name);
  return index >= 0 && process.argv[index + 1] ? process.argv[index + 1] : fallback;
}

async function main() {
  const rootDir = path.resolve(__dirname, '..');
  const outputDir = path.resolve(argument('--output-dir', path.join(
    rootDir, '.omo', 'evidence', 'stat_semantic_mapping_v1', 'registry',
  )));
  const { registry, paths } = await writeRegistryArtifacts({ rootDir, outputDir });
  process.stdout.write(`${JSON.stringify({
    status: registry.status,
    accepted_unique_packet_count: registry.corpus_scope.accepted_unique_packet_count,
    observed_selector_ids: registry.corpus_scope.observed_selector_ids,
    output_paths: paths,
  }, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});

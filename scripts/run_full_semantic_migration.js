#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const { resolveBuildProfile } = require('../src/build_registry');
const { assertAllowedInputPath } = require('../src/full_semantic_baseline');
const {
  inventoryFromReplayFiles,
  sha256File,
} = require('../src/packet_coverage_inventory');
const { buildFullSemanticMigration } = require('../src/full_semantic_migration');
const { parseReplayFile } = require('../src/rofl');

function parseArgs(argv) {
  const options = { replay: [] };
  const repeatable = new Set(['replay']);
  const pathKeys = new Set([
    'runtime', 'replay', 'previous_inventory', 'current_inventory',
    'capability_manifest', 'previous_registration_map', 'current_registration_map', 'output',
  ]);
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith('--')) throw new Error(`unexpected positional argument: ${token}`);
    const key = token.slice(2).replaceAll('-', '_');
    const value = argv[++index];
    if (!value || value.startsWith('--')) throw new Error(`${token} requires a value`);
    const parsedValue = pathKeys.has(key) ? path.resolve(value) : value;
    if (repeatable.has(key)) options[key].push(parsedValue);
    else if (Object.hasOwn(options, key)) throw new Error(`${token} may only be provided once`);
    else options[key] = parsedValue;
  }
  for (const required of [
    'runtime', 'previous_build', 'previous_inventory', 'capability_manifest', 'output',
  ]) {
    if (!options[required]) throw new Error(`--${required.replaceAll('_', '-')} is required`);
  }
  if (options.replay.length === 0) throw new Error('at least one explicit --replay is required');
  return options;
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function replayAttestations(replayPaths) {
  return [...replayPaths].sort().map((replayPath) => {
    const replay = parseReplayFile(replayPath);
    return {
      path: replayPath,
      sha256: replay.source_sha256,
      build: replay.header.version,
      container_status: 'STRICT_PARSE_PASS',
    };
  });
}

function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  for (const filePath of [
    options.runtime,
    ...options.replay,
    options.previous_inventory,
    options.current_inventory,
    options.capability_manifest,
    options.previous_registration_map,
    options.current_registration_map,
    options.output,
  ].filter(Boolean)) assertAllowedInputPath(filePath);
  const samples = replayAttestations(options.replay);
  const builds = new Set(samples.map((sample) => sample.build));
  if (builds.size !== 1) throw new Error('explicit Replay samples span multiple exact builds');
  const currentBuild = [...builds][0];
  const resolved = resolveBuildProfile(currentBuild);
  const runtimeSha256 = sha256File(options.runtime);
  const expectedRuntimeSha256 = resolved.profile?.runtime_profile?.image_sha256 ?? null;
  if (expectedRuntimeSha256 && runtimeSha256 !== expectedRuntimeSha256) {
    throw new Error(`runtime SHA-256 does not match exact build ${currentBuild}`);
  }
  const runtimeAttestation = {
    path: options.runtime,
    sha256: runtimeSha256,
    build: currentBuild,
    expected_sha256: expectedRuntimeSha256,
    status: expectedRuntimeSha256 ? 'VERIFIED_EXACT_BUILD' : 'NEEDS_REVALIDATION_UNKNOWN_BUILD',
  };
  const currentInventory = options.current_inventory
    ? readJson(options.current_inventory)
    : inventoryFromReplayFiles(options.replay);
  const previousInventory = readJson(options.previous_inventory);
  const capabilityManifest = readJson(options.capability_manifest);
  const previousRegistrationMap = options.previous_registration_map
    ? readJson(options.previous_registration_map) : null;
  const currentRegistrationMap = options.current_registration_map
    ? readJson(options.current_registration_map) : null;
  const report = buildFullSemanticMigration({
    previous_build: options.previous_build,
    current_build: currentBuild,
    previous_inventory: previousInventory,
    current_inventory: currentInventory,
    capability_manifest: capabilityManifest,
    previous_registration_map: previousRegistrationMap,
    current_registration_map: currentRegistrationMap,
    runtime_attestation: runtimeAttestation,
    replay_samples: samples,
  });
  report.inputs = {
    previous_inventory: { path: options.previous_inventory, sha256: sha256File(options.previous_inventory) },
    current_inventory: options.current_inventory
      ? { path: options.current_inventory, sha256: sha256File(options.current_inventory) }
      : { path: null, sha256: null, source: 'BUILT_FROM_EXPLICIT_REPLAY_SAMPLES' },
    capability_manifest: {
      path: options.capability_manifest,
      sha256: sha256File(options.capability_manifest),
    },
    previous_registration_map: options.previous_registration_map
      ? { path: options.previous_registration_map, sha256: sha256File(options.previous_registration_map) }
      : null,
    current_registration_map: options.current_registration_map
      ? { path: options.current_registration_map, sha256: sha256File(options.current_registration_map) }
      : null,
  };
  fs.mkdirSync(path.dirname(options.output), { recursive: true });
  fs.writeFileSync(options.output, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  process.stdout.write(`${JSON.stringify({
    status: report.status,
    previous_build: report.previous_build,
    current_build: report.current_build,
    packet_status_counts: report.packet_inventory_diff.status_counts,
    capability_status_counts: report.capability_migration.status_counts,
    research_queue_count: report.research_queue.length,
    output: options.output,
    output_sha256: sha256File(options.output),
  }, null, 2)}\n`);
  return report;
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { main, parseArgs, replayAttestations };

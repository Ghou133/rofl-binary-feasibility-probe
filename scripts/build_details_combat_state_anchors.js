#!/usr/bin/env node
'use strict';

const path = require('node:path');

const {
  REQUIRED_KEY_GAME_IDS,
  TARGET_REPLAY_BUILD,
  TARGET_SUMMARY_BUILD,
  buildDetailsCombatStateArtifacts,
  normalizeGameId,
} = require('../src/details_combat_state_anchors');

function usage() {
  return [
    'Usage: node scripts/build_details_combat_state_anchors.js [options]',
    '  --sample GAME_ID|REPLAY.rofl|DETAILS.json|SUMMARY.json   Repeat for each explicit paired sample',
    '  --output-jsonl FILE      Default artifacts/hero_combat_state_v2/anchors/details_p0_ground_truth.jsonl',
    '  --output-manifest FILE   Default artifacts/hero_combat_state_v2/anchors/details_p0_manifest.json',
    '  --help',
    '',
    `Exact Replay build: ${TARGET_REPLAY_BUILD}`,
    `Exact SUMMARY build: ${TARGET_SUMMARY_BUILD}`,
    `Required key games: ${REQUIRED_KEY_GAME_IDS.join(', ')}`,
    '',
    'Inputs are explicit by design: this command never discovers, enumerates, or reads a holdout directory.',
  ].join('\n');
}

function requireValue(argv, index, option) {
  const value = argv[index + 1];
  if (value === undefined || value.startsWith('--')) throw new Error(`${option} requires a value`);
  return value;
}

function parseSampleSpec(value) {
  const parts = String(value).split('|');
  if (parts.length !== 4 || parts.some((part) => part.trim().length === 0)) {
    throw new Error('--sample requires GAME_ID|REPLAY.rofl|DETAILS.json|SUMMARY.json');
  }
  return {
    gameId: normalizeGameId(parts[0]),
    replayPath: path.resolve(parts[1]),
    detailsPath: path.resolve(parts[2]),
    summaryPath: path.resolve(parts[3]),
  };
}

function parseArgs(argv) {
  const options = {
    samples: [],
    jsonlPath: path.resolve(
      'artifacts',
      'hero_combat_state_v2',
      'anchors',
      'details_p0_ground_truth.jsonl',
    ),
    manifestPath: path.resolve(
      'artifacts',
      'hero_combat_state_v2',
      'anchors',
      'details_p0_manifest.json',
    ),
    help: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    if (option === '--sample') options.samples.push(parseSampleSpec(requireValue(argv, index++, option)));
    else if (option === '--output-jsonl') options.jsonlPath = path.resolve(requireValue(argv, index++, option));
    else if (option === '--output-manifest') options.manifestPath = path.resolve(requireValue(argv, index++, option));
    else if (option === '--help' || option === '-h') options.help = true;
    else throw new Error(`unknown option: ${option}\n${usage()}`);
  }
  if (!options.help && options.samples.length === 0) throw new Error(`at least one --sample is required\n${usage()}`);
  return options;
}

function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.help) {
    process.stdout.write(`${usage()}\n`);
    return null;
  }
  const result = buildDetailsCombatStateArtifacts(options.samples, {
    jsonlPath: options.jsonlPath,
    manifestPath: options.manifestPath,
    requireKeySamples: true,
  });
  const report = {
    jsonl: result.jsonlPath,
    manifest: result.manifestPath,
    replay_count: result.manifest.replay_count,
    record_count: result.manifest.record_count,
    zero_health_record_count: result.manifest.zero_health_record_count,
    positive_to_zero_transition_count: result.manifest.positive_to_zero_transition_count,
    zero_to_positive_transition_count: result.manifest.zero_to_positive_transition_count,
    jsonl_sha256: result.manifest.jsonl.sha256,
  };
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
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

module.exports = {
  main,
  parseArgs,
  parseSampleSpec,
  usage,
};

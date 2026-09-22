#!/usr/bin/env node

const fs = require('node:fs');
const path = require('node:path');

const { writeJson } = require('../src/io');
const { parseReplayFile } = require('../src/rofl');
const { extractDetailsAnchors } = require('../src/validation/details');

function parseArgs(argv) {
  const options = { replay: null, details: null, output: null };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === '--replay') options.replay = path.resolve(argv[++index]);
    else if (value === '--details') options.details = path.resolve(argv[++index]);
    else if (value === '--output') options.output = path.resolve(argv[++index]);
    else throw new Error(`unknown argument: ${value}`);
  }
  if (!options.replay) throw new Error('--replay is required');
  if (!options.details) throw new Error('--details is required');
  if (!options.output) throw new Error('--output is required');
  return options;
}

function gameIdFromReplayPath(filePath) {
  const match = /(?:^|[-_])([0-9]+)\.rofl$/i.exec(path.basename(filePath));
  if (!match) throw new Error(`cannot infer gameId from ${filePath}`);
  return match[1];
}

function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  const replay = parseReplayFile(options.replay);
  const details = JSON.parse(fs.readFileSync(options.details, 'utf8'));
  const anchorSet = extractDetailsAnchors(gameIdFromReplayPath(options.replay), replay, details);
  const bundle = {
    schema_version: 1,
    generated_at: new Date().toISOString(),
    target_replay_version: replay.header.version,
    oracle: {
      name: 'LCU SGP Match Details',
      role: 'VALIDATION_ONLY',
      replay_packet_is_fact_source: true,
    },
    replay_count: 1,
    death_count: anchorSet.death_count,
    replays: [anchorSet],
  };
  writeJson(options.output, bundle);
  process.stdout.write(`${JSON.stringify({
    output: options.output,
    game_id: anchorSet.game_id,
    replay_sha256: anchorSet.replay_sha256,
    participant_count: anchorSet.participant_count,
    death_count: anchorSet.death_count,
  }, null, 2)}\n`);
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { gameIdFromReplayPath, main, parseArgs };

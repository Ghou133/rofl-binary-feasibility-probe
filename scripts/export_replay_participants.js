#!/usr/bin/env node

'use strict';

const fs = require('node:fs');
const path = require('node:path');

const { parseReplayFile } = require('../src/rofl');

const REPLAY_VERSION = '16.16.805.0442';

function parseArgs(argv) {
  const options = { output: null, replayFiles: [] };
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === '--output') options.output = path.resolve(argv[++index]);
    else options.replayFiles.push(path.resolve(argv[index]));
  }
  if (!options.output) throw new Error('--output is required');
  if (!options.replayFiles.length) throw new Error('at least one Replay path is required');
  return options;
}

function participantRow(stat, participantId) {
  const teamId = Number(stat.TEAM);
  if (!Number.isInteger(teamId) || ![100, 200].includes(teamId)) {
    throw new Error(`participant ${participantId} has invalid TEAM=${stat.TEAM}`);
  }
  return {
    participant_id: participantId,
    owner_network_id: 0x400000ad + participantId,
    owner_network_id_hex: `0x${(0x400000ad + participantId).toString(16).padStart(8, '0')}`,
    team_id: teamId,
    champion: stat.SKIN || null,
    ward_placed: Number(stat.WARD_PLACED || 0),
    detector_wards_placed: Number(stat.WARD_PLACED_DETECTOR || 0),
    vision_wards_bought: Number(stat.VISION_WARDS_BOUGHT_IN_GAME || 0),
    sight_wards_bought: Number(stat.SIGHT_WARDS_BOUGHT_IN_GAME || 0),
  };
}

function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  const replays = options.replayFiles.map((replayPath) => {
    const replay = parseReplayFile(replayPath);
    if (replay.header.version !== REPLAY_VERSION) {
      throw new Error(`${replayPath} has unsupported version ${replay.header.version}`);
    }
    if (replay.tail.stats_parse_error || !Array.isArray(replay.tail.stats)
        || replay.tail.stats.length !== 10) {
      throw new Error(`${replayPath} does not contain ten valid participant stat rows`);
    }
    return {
      replay_label: path.basename(replay.source_path, path.extname(replay.source_path)),
      replay_path: replay.source_path,
      replay_sha256: replay.source_sha256,
      replay_version: replay.header.version,
      participants: replay.tail.stats.map((stat, index) => participantRow(stat, index + 1)),
    };
  });
  const document = {
    schema_version: 1,
    target_replay_version: REPLAY_VERSION,
    participant_network_id_formula: '0x400000ad + participant_id',
    source: 'Replay tail participant stats; exact Replay SHA-256 bound',
    replay_count: replays.length,
    replays,
  };
  fs.mkdirSync(path.dirname(options.output), { recursive: true });
  fs.writeFileSync(options.output, `${JSON.stringify(document, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify({
    output: options.output,
    replay_count: replays.length,
    participant_count: replays.length * 10,
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

module.exports = { main, parseArgs, participantRow };

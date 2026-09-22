#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { parseReplayFile, walkBlocks } = require('../src/rofl');
const {
  EXACT_BUILD,
  PACKET_ID,
  analyzeRoute0474,
  participantFromRawParam,
} = require('../src/route_0474_champion_specific_audit');

function requireValue(argv, index, option) {
  if (index >= argv.length || argv[index].startsWith('--')) throw new Error(`${option} requires a value`);
  return argv[index];
}

function rejectHoldout(value) {
  const resolved = path.resolve(value);
  if (resolved.toLowerCase().includes('holdout')) throw new Error(`protected Holdout path is forbidden: ${resolved}`);
  return resolved;
}

function parseArgs(argv) {
  const options = {
    build: EXACT_BUILD,
    replayFiles: [],
    registryPath: 'artifacts/full_semantic_baseline_v1/observed_route_registry.json',
    outputPath: 'artifacts/full_semantic_deep_recovery_v2/unknown_mining/route_0474_champion_specific_audit.json',
  };
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    if (option === '--build') options.build = requireValue(argv, ++index, option);
    else if (option === '--replay') options.replayFiles.push(rejectHoldout(requireValue(argv, ++index, option)));
    else if (option === '--registry') options.registryPath = rejectHoldout(requireValue(argv, ++index, option));
    else if (option === '--output') options.outputPath = rejectHoldout(requireValue(argv, ++index, option));
    else throw new Error(`unknown option: ${option}`);
  }
  if (options.build !== EXACT_BUILD) throw new Error(`exact build ${EXACT_BUILD} is required`);
  if (!options.replayFiles.length) throw new Error('at least one explicit --replay is required');
  return options;
}

function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  const registryBytes = fs.readFileSync(options.registryPath);
  const registry = JSON.parse(registryBytes);
  if (registry.exact_build !== EXACT_BUILD) throw new Error('registry exact-build mismatch');
  const route = registry.routes.find((row) => row.packet_id === PACKET_ID);
  if (!route) throw new Error('registry is missing 0x0474');
  const events = [];
  const replays = [];
  for (const replayPath of options.replayFiles) {
    const replay = parseReplayFile(replayPath);
    if (replay.header.version !== EXACT_BUILD) throw new Error(`${replayPath} has build ${replay.header.version}`);
    const roster = replay.tail.stats.map((row, index) => ({
      participant_id: index + 1,
      champion: row.SKIN ?? null,
      team: row.TEAM === undefined ? null : Number(row.TEAM),
    }));
    const championByParticipant = new Map(roster.map((row) => [row.participant_id, row.champion]));
    const before = events.length;
    const walk = walkBlocks(replay, (block, chunk) => {
      if (block.packet_id !== PACKET_ID) return;
      const participantId = participantFromRawParam(block.param >>> 0);
      events.push({
        replay_version: replay.header.version,
        replay_sha256: replay.source_sha256,
        replay_label: path.basename(replay.source_path, path.extname(replay.source_path)),
        replay_time_ms: block.timestamp_ms,
        occurrence_index: events.length,
        packet_id: block.packet_id,
        raw_param: block.param >>> 0,
        chunk_stream: chunk.stream,
        payload_length: block.payload_length,
        raw_payload_hex: block.payload.toString('hex'),
        participant_id: participantId,
        champion: participantId === null ? null : championByParticipant.get(participantId) ?? null,
      });
    }, { includeStreams: [1, 2, 3], strict: true });
    if (walk.errors.length) throw new Error(`${replayPath} parser errors: ${walk.errors.length}`);
    replays.push({
      path: replay.source_path,
      replay_label: path.basename(replay.source_path, path.extname(replay.source_path)),
      replay_sha256: replay.source_sha256,
      selected_count: events.length - before,
      roster,
    });
  }
  const report = analyzeRoute0474(events, route.observed.count, replays);
  report.input = {
    replay_count: replays.length,
    replays: replays.map(({ roster, ...row }) => row),
    registry_path: path.resolve(options.registryPath),
    registry_sha256: crypto.createHash('sha256').update(registryBytes).digest('hex'),
  };
  fs.mkdirSync(path.dirname(options.outputPath), { recursive: true });
  const text = `${JSON.stringify(report, null, 2)}\n`;
  fs.writeFileSync(options.outputPath, text, 'utf8');
  const summary = {
    output: path.resolve(options.outputPath),
    sha256: crypto.createHash('sha256').update(text).digest('hex'),
    counts: report.counts,
    dominant_behavior: report.dominant_behavior,
    validations: report.validations,
    decision: report.route_decisions[0],
  };
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
  return summary;
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.stack ?? error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { main, parseArgs };

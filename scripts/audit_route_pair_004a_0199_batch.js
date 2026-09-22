#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { parseReplayFile, walkBlocks } = require('../src/rofl');
const {
  EXACT_BUILD,
  FIXED_CLUSTER_PACKET_ID,
  VARIABLE_BATCH_PACKET_ID,
  analyzeBatchPair,
} = require('../src/route_pair_004a_0199_batch_audit');

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
    outputPath: 'artifacts/full_semantic_deep_recovery_v2/unknown_mining/route_pair_004a_0199_batch_audit.json',
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
  const expectedCounts = {};
  for (const packetId of [VARIABLE_BATCH_PACKET_ID, FIXED_CLUSTER_PACKET_ID]) {
    const route = registry.routes.find((row) => row.packet_id === packetId);
    if (!route) throw new Error(`registry is missing 0x${packetId.toString(16).padStart(4, '0')}`);
    expectedCounts[packetId] = route.observed.count;
  }
  const events = [];
  const replays = [];
  for (const replayPath of options.replayFiles) {
    const replay = parseReplayFile(replayPath);
    if (replay.header.version !== EXACT_BUILD) throw new Error(`${replayPath} has build ${replay.header.version}`);
    const before = events.length;
    const walk = walkBlocks(replay, (block, chunk) => {
      if (![VARIABLE_BATCH_PACKET_ID, FIXED_CLUSTER_PACKET_ID].includes(block.packet_id)) return;
      events.push({
        replay_version: replay.header.version,
        replay_sha256: replay.source_sha256,
        replay_label: path.basename(replay.source_path, path.extname(replay.source_path)),
        replay_time_ms: block.timestamp_ms,
        occurrence_index: events.length,
        packet_id: block.packet_id,
        raw_param: block.param >>> 0,
        chunk_index: chunk.index,
        chunk_stream: chunk.stream,
        decompressed_block_offset: block.offset,
        payload_length: block.payload_length,
        raw_payload_hex: block.payload.toString('hex'),
      });
    }, { includeStreams: [1, 2, 3], strict: true });
    if (walk.errors.length) throw new Error(`${replayPath} parser errors: ${walk.errors.length}`);
    replays.push({
      path: replay.source_path,
      replay_label: path.basename(replay.source_path, path.extname(replay.source_path)),
      replay_sha256: replay.source_sha256,
      selected_count: events.length - before,
    });
  }
  const report = analyzeBatchPair(events, expectedCounts);
  report.input = {
    replay_count: replays.length,
    replays,
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
    relationship: report.relationship,
    validations: report.validations,
    route_decisions: report.route_decisions,
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

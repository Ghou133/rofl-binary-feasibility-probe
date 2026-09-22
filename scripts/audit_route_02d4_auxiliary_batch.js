#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { parseReplayFile, walkBlocks } = require('../src/rofl');
const {
  EXACT_BUILD,
  PACKET_ID,
  analyzeRoute02d4,
} = require('../src/route_02d4_auxiliary_batch_audit');

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

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
    miningPath: 'artifacts/full_semantic_deep_recovery_v2/unknown_mining/high_frequency_unknown_deep_mining.json',
    outputPath: 'artifacts/full_semantic_deep_recovery_v2/unknown_mining/route_02d4_auxiliary_batch_audit.json',
  };
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    if (option === '--build') options.build = requireValue(argv, ++index, option);
    else if (option === '--replay') options.replayFiles.push(rejectHoldout(requireValue(argv, ++index, option)));
    else if (option === '--registry') options.registryPath = rejectHoldout(requireValue(argv, ++index, option));
    else if (option === '--mining') options.miningPath = rejectHoldout(requireValue(argv, ++index, option));
    else if (option === '--output') options.outputPath = rejectHoldout(requireValue(argv, ++index, option));
    else throw new Error(`unknown option: ${option}`);
  }
  if (options.build !== EXACT_BUILD) throw new Error(`exact build ${EXACT_BUILD} is required`);
  if (!options.replayFiles.length) throw new Error('at least one explicit --replay is required');
  return options;
}

function packetHex(packetId) {
  return `0x${packetId.toString(16).padStart(4, '0')}`;
}

function extractReplay(replayPath) {
  const replay = parseReplayFile(replayPath);
  if (replay.header.version !== EXACT_BUILD) throw new Error(`${replayPath} has build ${replay.header.version}`);
  const routeEvents = [];
  let previous = null;
  let pendingRoute = null;
  let occurrenceIndex = 0;
  const firstWalk = walkBlocks(replay, (block, chunk) => {
    if (pendingRoute) {
      pendingRoute.next_packet_hex = packetHex(block.packet_id);
      pendingRoute.next_same_timestamp_hex = block.timestamp_ms === pendingRoute.replay_time_ms
        ? packetHex(block.packet_id) : null;
      pendingRoute = null;
    }
    if (block.packet_id === PACKET_ID) {
      const event = {
        replay_version: replay.header.version,
        replay_sha256: replay.source_sha256,
        replay_label: path.basename(replay.source_path, path.extname(replay.source_path)),
        replay_time_ms: block.timestamp_ms,
        occurrence_index: occurrenceIndex,
        packet_id: block.packet_id,
        raw_param: block.param >>> 0,
        chunk_stream: chunk.stream,
        payload_length: block.payload_length,
        raw_payload_hex: block.payload.toString('hex'),
        previous_packet_hex: previous ? packetHex(previous.packet_id) : 'START',
        previous_same_timestamp_hex: previous && previous.timestamp_ms === block.timestamp_ms
          ? packetHex(previous.packet_id) : null,
        next_packet_hex: 'END',
        next_same_timestamp_hex: null,
      };
      routeEvents.push(event);
      pendingRoute = event;
    }
    previous = { packet_id: block.packet_id, timestamp_ms: block.timestamp_ms };
    occurrenceIndex += 1;
  }, { includeStreams: [1, 2, 3], strict: true });
  if (firstWalk.errors.length) throw new Error(`${replayPath} parser errors: ${firstWalk.errors.length}`);
  const routeTimes = new Set(routeEvents.map((event) => event.replay_time_ms));
  const timeContextMaps = new Map([...routeTimes].map((timestamp) => [timestamp, new Map()]));
  const secondWalk = walkBlocks(replay, (block) => {
    const counts = timeContextMaps.get(block.timestamp_ms);
    if (!counts) return;
    const key = packetHex(block.packet_id);
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }, { includeStreams: [1, 2, 3], strict: true });
  if (secondWalk.errors.length) throw new Error(`${replayPath} second-pass parser errors: ${secondWalk.errors.length}`);
  return {
    replay_path: replay.source_path,
    replay_label: path.basename(replay.source_path, path.extname(replay.source_path)),
    replay_sha256: replay.source_sha256,
    route_events: routeEvents,
    time_context: new Map([...timeContextMaps].map(([timestamp, counts]) =>
      [timestamp, Object.fromEntries(counts)])),
  };
}

function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  const registryBytes = fs.readFileSync(options.registryPath);
  const registry = JSON.parse(registryBytes);
  if (registry.exact_build !== EXACT_BUILD) throw new Error('route registry exact-build mismatch');
  const route = registry.routes.find((row) => row.packet_id === PACKET_ID);
  if (!route) throw new Error('route registry is missing 0x02d4');
  const miningBytes = fs.readFileSync(options.miningPath);
  const mining = JSON.parse(miningBytes);
  const sampledSemanticEvidence = mining.routes?.find((row) => row.packet_id === PACKET_ID)
    ?? mining.route_analyses?.find((row) => row.packet_id === PACKET_ID)
    ?? null;
  if (!sampledSemanticEvidence) throw new Error('mining artifact is missing 0x02d4');
  const records = options.replayFiles.map(extractReplay);
  const report = analyzeRoute02d4(records, route.observed.count, sampledSemanticEvidence);
  report.input = {
    replays: records.map((record) => ({
      path: record.replay_path,
      replay_sha256: record.replay_sha256,
      selected_packet_count: record.route_events.length,
    })),
    registry_path: path.resolve(options.registryPath),
    registry_sha256: sha256(registryBytes),
    sampled_mining_path: path.resolve(options.miningPath),
    sampled_mining_sha256: sha256(miningBytes),
  };
  fs.mkdirSync(path.dirname(options.outputPath), { recursive: true });
  const text = `${JSON.stringify(report, null, 2)}\n`;
  fs.writeFileSync(options.outputPath, text, 'utf8');
  const summary = {
    output: path.resolve(options.outputPath),
    sha256: sha256(text),
    counts: report.counts,
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

module.exports = { extractReplay, main, parseArgs };

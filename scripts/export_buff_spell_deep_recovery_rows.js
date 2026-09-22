#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { parseReplayFile, walkBlocks, normalizePlayers } = require('../src/rofl');

const TARGET_VERSION = '16.16.805.0442';
const DEFAULT_PACKET_IDS = Object.freeze([
  0x008a, // runtime name only: ForceCreateMissile
  0x00b8, // runtime name only: cooldown broadcast
  0x0123, // BuffManagerClient candidate
  0x0135, // MissileClient candidate
  0x0199, // high-frequency negative-control candidate
  0x01cf, // SpellbookClient CastSpellAns candidate
  0x01e1, // exact runtime shield-damage route; bounded absence is material
  0x02e0, // MissileClient candidate
  0x02e1, // MissileClient candidate
  0x0326, // BuffManagerClient candidate
  0x0371, // exact runtime PKT_OnEvent_s route
  0x041f, // BuffManagerClient candidate
  0x043c, // BuffManagerClient candidate
  0x045b, // BuffManagerClient candidate
  0x0465, // MissileClient candidate
  0x017f, // verified Damage anchor; raw row retained for local joins
]);

function rejectHoldout(value, label) {
  const resolved = path.resolve(value);
  if (resolved.toLowerCase().includes('holdout')) {
    throw new Error(`${label} must not reference protected Holdout content: ${resolved}`);
  }
  return resolved;
}

function parsePacketId(value) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > 0xffff) {
    throw new Error(`invalid packet ID: ${value}`);
  }
  return parsed;
}

function parseArgs(argv) {
  const options = {
    output: null,
    packetIds: new Set(DEFAULT_PACKET_IDS),
    replayFiles: [],
  };
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === '--output') options.output = rejectHoldout(argv[++index], '--output');
    else if (token === '--packet-id') {
      options.packetIds.clear();
      for (const value of argv[++index].split(',')) options.packetIds.add(parsePacketId(value));
    } else options.replayFiles.push(rejectHoldout(token, 'Replay input'));
  }
  if (!options.output) throw new Error('--output is required');
  if (options.packetIds.size === 0) throw new Error('at least one packet ID is required');
  if (options.replayFiles.length === 0) throw new Error('at least one Replay is required');
  return options;
}

function increment(object, key) {
  object[key] = (object[key] ?? 0) + 1;
}

function sortedNumericObject(object) {
  return Object.fromEntries(Object.entries(object)
    .sort(([left], [right]) => Number(left) - Number(right)));
}

function sha256File(filename) {
  return crypto.createHash('sha256').update(fs.readFileSync(filename)).digest('hex');
}

function payloadSha256(payload) {
  return crypto.createHash('sha256').update(payload).digest('hex');
}

function rowFor(replay, chunk, block, occurrenceIndex) {
  return {
    schema_version: 1,
    replay_path: replay.source_path,
    replay_sha256: replay.source_sha256,
    replay_version: replay.header.version,
    replay_label: path.basename(replay.source_path, path.extname(replay.source_path)),
    chunk_index: chunk.index,
    chunk_id: chunk.chunk_id,
    chunk_stream: chunk.stream,
    chunk_stream_tag: chunk.stream_tag,
    chunk_file_offset: chunk.offset,
    compressed_body_offset: chunk.body_offset,
    decompressed_block_offset: block.offset,
    decompressed_payload_offset: block.payload_offset,
    replay_time_ms: block.timestamp_ms,
    occurrence_index: occurrenceIndex,
    packet_id: block.packet_id,
    packet_type: `0x${block.packet_id.toString(16).padStart(4, '0')}`,
    payload_length: block.payload_length,
    raw_param: block.param >>> 0,
    raw_param_hex: `0x${(block.param >>> 0).toString(16).padStart(8, '0')}`,
    raw_payload_hex: block.payload.toString('hex'),
    raw_payload_sha256: payloadSha256(block.payload),
  };
}

function playerSummary(replay) {
  return normalizePlayers(replay).map((player, index) => ({
    participant_id: index + 1,
    champion_network_id: 0x400000ad + index + 1,
    champion: player.champion,
    team_id: player.team_id,
    aggregate_stats: player.aggregate_stats,
  }));
}

function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  fs.mkdirSync(path.dirname(options.output), { recursive: true });
  const destination = fs.openSync(options.output, 'w');
  const packetCounts = {};
  const streamCountsByPacket = {};
  const payloadCountsByPacket = {};
  const firstTimeByPacket = {};
  const lastTimeByPacket = {};
  const replays = [];
  let selectedCount = 0;

  for (const packetId of [...options.packetIds].sort((left, right) => left - right)) {
    packetCounts[packetId] = 0;
    streamCountsByPacket[packetId] = {};
    payloadCountsByPacket[packetId] = {};
  }

  try {
    for (const replayFile of options.replayFiles) {
      const replay = parseReplayFile(replayFile);
      if (replay.header.version !== TARGET_VERSION) {
        throw new Error(`${replayFile} has ${replay.header.version}; expected ${TARGET_VERSION}`);
      }
      const replayPacketCounts = {};
      for (const packetId of options.packetIds) replayPacketCounts[packetId] = 0;
      const walk = walkBlocks(replay, (block, chunk) => {
        if (!options.packetIds.has(block.packet_id)) return;
        const packetKey = String(block.packet_id);
        const streamKey = String(chunk.stream_tag);
        const payloadKey = String(block.payload_length);
        packetCounts[packetKey] += 1;
        replayPacketCounts[packetKey] += 1;
        increment(streamCountsByPacket[packetKey], streamKey);
        increment(payloadCountsByPacket[packetKey], payloadKey);
        firstTimeByPacket[packetKey] = Math.min(
          firstTimeByPacket[packetKey] ?? block.timestamp_ms,
          block.timestamp_ms,
        );
        lastTimeByPacket[packetKey] = Math.max(
          lastTimeByPacket[packetKey] ?? block.timestamp_ms,
          block.timestamp_ms,
        );
        fs.writeSync(destination, `${JSON.stringify(rowFor(replay, chunk, block, selectedCount))}\n`);
        selectedCount += 1;
      }, { includeStreams: [1, 2, 3], strict: true });
      replays.push({
        path: replay.source_path,
        sha256: replay.source_sha256,
        version: replay.header.version,
        packet_counts: sortedNumericObject(replayPacketCounts),
        parser_error_count: walk.errors.length,
        players: playerSummary(replay),
      });
    }
  } finally {
    fs.closeSync(destination);
  }

  const manifest = {
    schema_version: 1,
    analyzer: 'buff-spell-deep-recovery-row-export-v1',
    target_replay_version: TARGET_VERSION,
    output: options.output,
    output_sha256: sha256File(options.output),
    packet_ids: [...options.packetIds].sort((left, right) => left - right),
    selected_packet_count: selectedCount,
    packet_counts: sortedNumericObject(packetCounts),
    stream_counts_by_packet: Object.fromEntries(Object.entries(streamCountsByPacket)
      .sort(([left], [right]) => Number(left) - Number(right))
      .map(([packetId, counts]) => [packetId, sortedNumericObject(counts)])),
    payload_counts_by_packet: Object.fromEntries(Object.entries(payloadCountsByPacket)
      .sort(([left], [right]) => Number(left) - Number(right))
      .map(([packetId, counts]) => [packetId, sortedNumericObject(counts)])),
    first_time_ms_by_packet: sortedNumericObject(firstTimeByPacket),
    last_time_ms_by_packet: sortedNumericObject(lastTimeByPacket),
    replay_count: replays.length,
    replays,
    holdout_boundary: {
      path_guard: "reject every explicit input/output path containing case-insensitive 'holdout'",
      read: false,
      enumerate: false,
      hash: false,
      decode: false,
      test: false,
      consume: false,
    },
    semantic_boundary: (
      'This export is exact raw protocol evidence. Runtime route names and temporal '
      + 'neighbourhoods do not assign gameplay semantics.'
    ),
  };
  const manifestPath = `${options.output}.manifest.json`;
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify({ ...manifest, manifest: manifestPath }, null, 2)}\n`);
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
  DEFAULT_PACKET_IDS,
  main,
  parseArgs,
  parsePacketId,
  rejectHoldout,
  rowFor,
};


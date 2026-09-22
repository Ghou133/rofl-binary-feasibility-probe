#!/usr/bin/env node

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { parseReplayFile, walkBlocks } = require('../src/rofl');

const TARGET_VERSION = '16.16.805.0442';
const DEFAULT_PACKET_IDS = [0x0112, 0x0123, 0x01cf, 0x0310, 0x0326, 0x0405, 0x041f, 0x045b];

function parsePacketId(value) {
  const result = Number(value);
  if (!Number.isSafeInteger(result) || result < 0 || result > 0xffff) {
    throw new Error(`invalid packet ID: ${value}`);
  }
  return result;
}

function parseArgs(argv) {
  const options = {
    output: null,
    samplesPerShapePerReplay: 2,
    packetIds: new Set(DEFAULT_PACKET_IDS),
    streamTags: new Set([1, 2, 3]),
    replayFiles: [],
  };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === '--output') options.output = path.resolve(argv[++index]);
    else if (value === '--samples-per-shape-per-replay') {
      options.samplesPerShapePerReplay = Number(argv[++index]);
    } else if (value === '--packet-id') {
      options.packetIds.clear();
      for (const item of argv[++index].split(',')) options.packetIds.add(parsePacketId(item));
    } else if (value === '--stream-tag') {
      options.streamTags.clear();
      for (const item of argv[++index].split(',')) {
        const streamTag = Number(item);
        if (!Number.isSafeInteger(streamTag) || streamTag < 1 || streamTag > 3) {
          throw new Error(`invalid stream tag: ${item}`);
        }
        options.streamTags.add(streamTag);
      }
    } else options.replayFiles.push(path.resolve(value));
  }
  if (!options.output) throw new Error('--output is required');
  if (!Number.isSafeInteger(options.samplesPerShapePerReplay)
      || options.samplesPerShapePerReplay < 1) {
    throw new Error('--samples-per-shape-per-replay must be a positive integer');
  }
  if (options.packetIds.size === 0) throw new Error('at least one packet ID is required');
  if (options.replayFiles.length === 0) throw new Error('at least one Replay path is required');
  return options;
}

function increment(object, key) {
  object[key] = (object[key] ?? 0) + 1;
}

function sortedNumericObject(object) {
  return Object.fromEntries(Object.entries(object)
    .sort(([left], [right]) => Number(left) - Number(right)));
}

function payloadSha256(payload) {
  return crypto.createHash('sha256').update(payload).digest('hex');
}

function sampleRow(replay, chunk, block, occurrenceIndex) {
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
    packet_type: block.packet_type,
    payload_length: block.payload_length,
    raw_param: block.param >>> 0,
    raw_param_hex: `0x${(block.param >>> 0).toString(16).padStart(8, '0')}`,
    raw_payload_hex: block.payload.toString('hex'),
    raw_payload_sha256: payloadSha256(block.payload),
  };
}

function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  fs.mkdirSync(path.dirname(options.output), { recursive: true });
  const output = fs.openSync(options.output, 'w');
  const packetCounts = {};
  const streamCountsByPacket = {};
  const payloadCountsByPacket = {};
  const selectedPacketCounts = {};
  const shapeSeenCounts = new Map();
  const replays = [];
  let observedCount = 0;
  let selectedCount = 0;

  for (const packetId of [...options.packetIds].sort((a, b) => a - b)) {
    packetCounts[packetId] = 0;
    streamCountsByPacket[packetId] = {};
    payloadCountsByPacket[packetId] = {};
    selectedPacketCounts[packetId] = 0;
  }

  try {
    for (const replayFile of options.replayFiles) {
      const replay = parseReplayFile(replayFile);
      if (replay.header.version !== TARGET_VERSION) {
        throw new Error(`${replayFile} has unsupported version ${replay.header.version}`);
      }
      const replayPacketCounts = {};
      const replaySelectedPacketCounts = {};
      for (const packetId of options.packetIds) {
        replayPacketCounts[packetId] = 0;
        replaySelectedPacketCounts[packetId] = 0;
      }
      const walk = walkBlocks(replay, (block, chunk) => {
        if (!options.streamTags.has(chunk.stream_tag) || !options.packetIds.has(block.packet_id)) {
          return;
        }
        const packetKey = String(block.packet_id);
        const streamKey = String(chunk.stream_tag);
        const payloadKey = String(block.payload_length);
        observedCount += 1;
        packetCounts[packetKey] += 1;
        replayPacketCounts[packetKey] += 1;
        increment(streamCountsByPacket[packetKey], streamKey);
        increment(payloadCountsByPacket[packetKey], payloadKey);

        const shapeKey = [
          replay.source_sha256,
          block.packet_id,
          chunk.stream_tag,
          block.payload_length,
        ].join('/');
        const seen = shapeSeenCounts.get(shapeKey) ?? 0;
        shapeSeenCounts.set(shapeKey, seen + 1);
        if (seen >= options.samplesPerShapePerReplay) return;

        const row = sampleRow(replay, chunk, block, selectedCount);
        fs.writeSync(output, `${JSON.stringify(row)}\n`);
        selectedCount += 1;
        selectedPacketCounts[packetKey] += 1;
        replaySelectedPacketCounts[packetKey] += 1;
      }, { includeStreams: [...options.streamTags], strict: true });
      replays.push({
        path: replay.source_path,
        sha256: replay.source_sha256,
        version: replay.header.version,
        packet_counts: sortedNumericObject(replayPacketCounts),
        selected_packet_counts: sortedNumericObject(replaySelectedPacketCounts),
        parser_error_count: walk.errors.length,
      });
    }
  } finally {
    fs.closeSync(output);
  }

  const manifest = {
    schema_version: 1,
    target_replay_version: TARGET_VERSION,
    sample_policy: 'first N rows per (Replay SHA-256, packet ID, stream tag, payload length)',
    samples_per_shape_per_replay: options.samplesPerShapePerReplay,
    output: options.output,
    packet_ids: [...options.packetIds].sort((a, b) => a - b),
    stream_tags: [...options.streamTags].sort((a, b) => a - b),
    observed_packet_count: observedCount,
    selected_packet_count: selectedCount,
    packet_counts: sortedNumericObject(packetCounts),
    selected_packet_counts: sortedNumericObject(selectedPacketCounts),
    stream_counts_by_packet: Object.fromEntries(Object.entries(streamCountsByPacket)
      .sort(([left], [right]) => Number(left) - Number(right))
      .map(([packetId, counts]) => [packetId, sortedNumericObject(counts)])),
    payload_counts_by_packet: Object.fromEntries(Object.entries(payloadCountsByPacket)
      .sort(([left], [right]) => Number(left) - Number(right))
      .map(([packetId, counts]) => [packetId, sortedNumericObject(counts)])),
    replay_count: replays.length,
    replays,
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

module.exports = { main, parseArgs, parsePacketId, sampleRow };

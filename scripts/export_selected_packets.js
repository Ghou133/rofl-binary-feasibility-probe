#!/usr/bin/env node

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { parseReplayFile, walkBlocks } = require('../src/rofl');

const DEFAULT_TARGET_VERSION = '16.15.801.3452';

function parsePacketId(value) {
  const packetId = Number(value);
  if (!Number.isSafeInteger(packetId) || packetId < 0 || packetId > 0xffff) {
    throw new Error(`invalid packet ID: ${value}`);
  }
  return packetId;
}

function parseArgs(argv) {
  const options = {
    output: null,
    packetIds: new Set(),
    streamTags: new Set([1]),
    replayFiles: [],
    replayVersion: DEFAULT_TARGET_VERSION,
    maxTimeMs: null,
    maxPerPacketPerReplay: null,
    sampleEvery: 1,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === '--output') options.output = path.resolve(argv[++index]);
    else if (value === '--replay-version') options.replayVersion = argv[++index];
    else if (value === '--stream-tag') {
      options.streamTags.clear();
      for (const item of argv[++index].split(',')) {
        const streamTag = Number(item);
        if (!Number.isSafeInteger(streamTag) || streamTag < 1 || streamTag > 3) {
          throw new Error(`invalid stream tag: ${item}`);
        }
        options.streamTags.add(streamTag);
      }
    }
    else if (value === '--max-time-ms') {
      options.maxTimeMs = Number(argv[++index]);
      if (!Number.isFinite(options.maxTimeMs) || options.maxTimeMs < 0) {
        throw new Error('--max-time-ms must be a non-negative number');
      }
    }
    else if (value === '--max-per-packet-per-replay') {
      options.maxPerPacketPerReplay = Number(argv[++index]);
      if (!Number.isSafeInteger(options.maxPerPacketPerReplay)
          || options.maxPerPacketPerReplay < 1) {
        throw new Error('--max-per-packet-per-replay must be a positive integer');
      }
    }
    else if (value === '--sample-every') {
      options.sampleEvery = Number(argv[++index]);
      if (!Number.isSafeInteger(options.sampleEvery) || options.sampleEvery < 1) {
        throw new Error('--sample-every must be a positive integer');
      }
    }
    else if (value === '--packet-id') {
      for (const item of argv[++index].split(',')) options.packetIds.add(parsePacketId(item));
    } else options.replayFiles.push(path.resolve(value));
  }
  if (!options.output) throw new Error('--output is required');
  if (options.packetIds.size === 0) throw new Error('--packet-id is required');
  if (options.replayFiles.length === 0) throw new Error('at least one Replay path is required');
  return options;
}

function payloadSha256(payload) {
  return crypto.createHash('sha256').update(payload).digest('hex');
}

function selectedBlock(replay, chunk, block, occurrenceIndex) {
  return {
    schema_version: 1,
    replay_path: replay.source_path,
    replay_sha256: replay.source_sha256,
    replay_version: replay.header.version,
    replay_label: path.basename(replay.source_path, path.extname(replay.source_path)),
    chunk_index: chunk.index,
    chunk_id: chunk.chunk_id,
    chunk_stream: chunk.stream,
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
  const packetCounts = Object.fromEntries([...options.packetIds].sort((a, b) => a - b).map((id) => [id, 0]));
  const replays = [];
  let selectedCount = 0;

  try {
    for (const replayFile of options.replayFiles) {
      const replay = parseReplayFile(replayFile);
      if (replay.header.version !== options.replayVersion) {
        throw new Error(`${replayFile} has unsupported version ${replay.header.version}`);
      }
      let replaySelectedCount = 0;
      const replayPacketCounts = new Map();
      const replayPacketSeenCounts = new Map();
      const walk = walkBlocks(replay, (block, chunk) => {
        if (!options.streamTags.has(chunk.stream_tag) || !options.packetIds.has(block.packet_id)
            || (options.maxTimeMs !== null && block.timestamp_ms > options.maxTimeMs)) return;
        const replayPacketSeenCount = replayPacketSeenCounts.get(block.packet_id) ?? 0;
        replayPacketSeenCounts.set(block.packet_id, replayPacketSeenCount + 1);
        if (replayPacketSeenCount % options.sampleEvery !== 0) return;
        const replayPacketCount = replayPacketCounts.get(block.packet_id) ?? 0;
        if (options.maxPerPacketPerReplay !== null
            && replayPacketCount >= options.maxPerPacketPerReplay) return;
        const row = selectedBlock(replay, chunk, block, selectedCount);
        fs.writeSync(output, `${JSON.stringify(row)}\n`);
        selectedCount += 1;
        replaySelectedCount += 1;
        packetCounts[block.packet_id] += 1;
        replayPacketCounts.set(block.packet_id, replayPacketCount + 1);
      }, { includeStreams: [...options.streamTags], strict: true });
      replays.push({
        path: replay.source_path,
        sha256: replay.source_sha256,
        version: replay.header.version,
        selected_packet_count: replaySelectedCount,
        parser_error_count: walk.errors.length,
      });
    }
  } finally {
    fs.closeSync(output);
  }

  const manifest = {
    schema_version: 1,
    target_replay_version: options.replayVersion,
    max_time_ms: options.maxTimeMs,
    max_per_packet_per_replay: options.maxPerPacketPerReplay,
    sample_every: options.sampleEvery,
    output: options.output,
    packet_ids: [...options.packetIds].sort((a, b) => a - b),
    stream_tags: [...options.streamTags].sort((a, b) => a - b),
    selected_packet_count: selectedCount,
    packet_counts: packetCounts,
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

module.exports = { main, parseArgs, parsePacketId, selectedBlock };

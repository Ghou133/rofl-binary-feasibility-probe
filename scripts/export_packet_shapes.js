#!/usr/bin/env node

const fs = require('node:fs');
const path = require('node:path');

const { parseReplayFile, walkBlocks } = require('../src/rofl');

const TARGET_VERSION = '16.15.801.3452';

function parseArgs(argv) {
  const options = {
    output: path.resolve('artifacts', 'runtime_probe', 'all_packet_shapes.json'),
    samplesPerShape: 4,
    replayFiles: [],
  };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === '--output') options.output = path.resolve(argv[++index]);
    else if (value === '--samples-per-shape') options.samplesPerShape = Number(argv[++index]);
    else options.replayFiles.push(path.resolve(value));
  }
  if (options.replayFiles.length === 0) {
    throw new Error('at least one Replay path is required');
  }
  if (!Number.isSafeInteger(options.samplesPerShape) || options.samplesPerShape < 1) {
    throw new Error('--samples-per-shape must be a positive integer');
  }
  return options;
}

function blockReference(replay, chunk, block) {
  return {
    replay_path: replay.source_path,
    replay_sha256: replay.source_sha256,
    chunk_index: chunk.index,
    chunk_id: chunk.chunk_id,
    chunk_file_offset: chunk.offset,
    decompressed_block_offset: block.offset,
    decompressed_payload_offset: block.payload_offset,
    replay_time_ms: block.timestamp_ms,
    packet_id: block.packet_id,
    payload_length: block.payload_length,
    raw_param: block.param >>> 0,
    raw_param_hex: `0x${(block.param >>> 0).toString(16).padStart(8, '0')}`,
    raw_payload_hex: block.payload.toString('hex'),
  };
}

function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  const shapes = new Map();
  const replays = [];
  let blockCount = 0;

  for (const replayFile of options.replayFiles) {
    const replay = parseReplayFile(replayFile);
    if (replay.header.version !== TARGET_VERSION) {
      throw new Error(`${replayFile} has unsupported version ${replay.header.version}`);
    }
    let replayBlockCount = 0;
    const walk = walkBlocks(replay, (block, chunk) => {
      if (chunk.stream_tag !== 1) return;
      blockCount += 1;
      replayBlockCount += 1;
      const key = `${block.packet_id}/${block.payload_length}`;
      let shape = shapes.get(key);
      if (!shape) {
        shape = {
          packet_id: block.packet_id,
          payload_length: block.payload_length,
          occurrence_count: 0,
          replay_sha256s: new Set(),
          samples: [],
        };
        shapes.set(key, shape);
      }
      shape.occurrence_count += 1;
      shape.replay_sha256s.add(replay.source_sha256);
      if (shape.samples.length < options.samplesPerShape) {
        shape.samples.push(blockReference(replay, chunk, block));
      }
    }, { includeStreams: [1], strict: true });
    replays.push({
      path: replay.source_path,
      sha256: replay.source_sha256,
      version: replay.header.version,
      game_chunk_block_count: replayBlockCount,
      parser_error_count: walk.errors.length,
    });
  }

  const output = {
    schema_version: 1,
    target_replay_version: TARGET_VERSION,
    sample_policy: 'first N game-stream blocks per (packet_id,payload_length) shape',
    samples_per_shape: options.samplesPerShape,
    replay_count: replays.length,
    game_chunk_block_count: blockCount,
    shape_count: shapes.size,
    replays,
    shapes: [...shapes.values()]
      .map((shape) => ({
        ...shape,
        replay_count: shape.replay_sha256s.size,
        replay_sha256s: [...shape.replay_sha256s].sort(),
      }))
      .sort((left, right) => left.packet_id - right.packet_id
        || left.payload_length - right.payload_length),
  };
  fs.mkdirSync(path.dirname(options.output), { recursive: true });
  fs.writeFileSync(options.output, `${JSON.stringify(output, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify({
    output: options.output,
    replay_count: output.replay_count,
    game_chunk_block_count: output.game_chunk_block_count,
    shape_count: output.shape_count,
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

module.exports = { main, parseArgs };

'use strict';

// Research helper: inventory raw packets near verified yellow-trinket casts.
// It intentionally does not decode or label any packet as a Ward entity.
const fs = require('node:fs');
const path = require('node:path');
const { parseReplayFile, walkBlocks } = require('../src/rofl');

function readJsonl(filePath) {
  return fs.readFileSync(filePath, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

function main(argv = process.argv.slice(2)) {
  const replayPath = argv[0];
  const eventsPath = argv[1] || path.join('artifacts', 'semantic_probe', 'spell_events.jsonl');
  const windowBeforeMs = Number(argv[2] ?? 1000);
  const windowAfterMs = Number(argv[3] ?? 3000);
  if (!replayPath) throw new Error('usage: node scripts/inspect_ward_neighbors.js <replay.rofl> [spell-events.jsonl] [before-ms] [after-ms]');
  const replay = parseReplayFile(path.resolve(replayPath));
  const casts = readJsonl(eventsPath).filter((row) => (
    row.spell_identifier === 'TrinketTotemLvl1'
      && row.raw_packet_ref?.replay_sha256 === replay.source_sha256
  ));
  const windows = casts.map((cast, index) => ({
    index,
    timestamp_ms: cast.replay_time_ms,
    caster_participant: cast.caster_participant_id,
    position: cast.target_position ?? cast.position ?? null,
    packets: new Map(),
  }));
  const add = (window, block, chunk) => {
    const key = `${block.packet_id}:${block.payload_length}`;
    const item = window.packets.get(key) || {
      packet_id: block.packet_id,
      packet_type: block.packet_type,
      payload_length: block.payload_length,
      count: 0,
      samples: [],
    };
    item.count += 1;
    if (item.samples.length < 3) {
      item.samples.push({
        timestamp_ms: block.timestamp_ms,
        delta_ms: block.timestamp_ms - window.timestamp_ms,
        raw_param: block.param >>> 0,
        raw_payload_hex: block.payload.toString('hex'),
        chunk_index: chunk.index,
        decompressed_block_offset: block.offset,
      });
    }
    window.packets.set(key, item);
  };
  const walk = walkBlocks(replay, (block, chunk) => {
    for (const window of windows) {
      if (block.timestamp_ms >= window.timestamp_ms - windowBeforeMs
          && block.timestamp_ms <= window.timestamp_ms + windowAfterMs) {
        add(window, block, chunk);
      }
    }
  }, { includeStreams: [1], strict: true });
  const result = {
    replay_path: replay.source_path,
    replay_sha256: replay.source_sha256,
    replay_version: replay.header.version,
    cast_count: casts.length,
    window_before_ms: windowBeforeMs,
    window_after_ms: windowAfterMs,
    walk,
    windows: windows.map((window) => ({
      index: window.index,
      timestamp_ms: window.timestamp_ms,
      caster_participant: window.caster_participant,
      position: window.position,
      packets: [...window.packets.values()].sort((a, b) => b.count - a.count),
    })),
  };
  const outputPath = argv[4];
  if (outputPath) fs.writeFileSync(path.resolve(outputPath), `${JSON.stringify(result, null, 2)}\n`, 'utf8');
  else process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  return result;
}

if (require.main === module) main();

module.exports = { main };

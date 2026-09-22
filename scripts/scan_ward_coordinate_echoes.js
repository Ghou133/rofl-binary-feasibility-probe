'use strict';

// Look for raw payloads that repeat verified CastSpell coordinates. This is a
// hypothesis generator only; it never upgrades a candidate's provenance.
const fs = require('node:fs');
const path = require('node:path');
const { parseReplayFile, walkBlocks } = require('../src/rofl');

function jsonl(file) {
  return fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map(JSON.parse);
}

function finite(value) { return Number.isFinite(value); }

function scorePayload(payload, target) {
  const hits = [];
  for (let offset = 0; offset + 4 <= payload.length; offset += 1) {
    const value = payload.readFloatLE(offset);
    if (!finite(value)) continue;
    for (let axis = 0; axis < 3; axis += 1) {
      const expected = target[axis];
      const tolerance = axis === 1 ? 2 : 8;
      if (Math.abs(value - expected) <= tolerance) hits.push({ offset, axis, value });
    }
  }
  return hits;
}

function main(argv = process.argv.slice(2)) {
  const replayPath = argv[0];
  const eventsPath = argv[1] || path.join('artifacts', 'semantic_probe', 'spell_events.jsonl');
  const radiusMs = Number(argv[2] ?? 2000);
  const replay = parseReplayFile(path.resolve(replayPath));
  const casts = jsonl(eventsPath).filter((row) => (
    row.spell_identifier === 'TrinketTotemLvl1'
      && row.raw_packet_ref?.replay_sha256 === replay.source_sha256
      && Array.isArray(row.target_position)
  ));
  const results = [];
  const byCast = casts.map((cast, index) => ({ cast, index, hits: [] }));
  walkBlocks(replay, (block, chunk) => {
    if (block.packet_id === 0x0459) return;
    for (const item of byCast) {
      const delta = block.timestamp_ms - item.cast.replay_time_ms;
      if (delta < -radiusMs || delta > radiusMs) continue;
      const hits = scorePayload(block.payload, item.cast.target_position);
      if (hits.length === 0) continue;
      item.hits.push({
        packet_id: block.packet_id,
        packet_type: block.packet_type,
        payload_length: block.payload_length,
        timestamp_ms: block.timestamp_ms,
        delta_ms: delta,
        raw_param: block.param >>> 0,
        raw_payload_hex: block.payload.toString('hex'),
        chunk_index: chunk.index,
        decompressed_block_offset: block.offset,
        coordinate_hits: hits,
      });
    }
  }, { includeStreams: [1], strict: true });
  for (const item of byCast) {
    results.push({
      cast_index: item.index,
      cast_timestamp_ms: item.cast.replay_time_ms,
      caster_participant_id: item.cast.caster_participant_id,
      cast_position: item.cast.target_position,
      hits: item.hits,
    });
  }
  const output = { replay_path: replay.source_path, replay_sha256: replay.source_sha256, radius_ms: radiusMs, cast_count: casts.length, results };
  const outputPath = argv[3];
  if (outputPath) fs.writeFileSync(path.resolve(outputPath), `${JSON.stringify(output, null, 2)}\n`, 'utf8');
  else process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
  return output;
}

if (require.main === module) main();
module.exports = { main, scorePayload };

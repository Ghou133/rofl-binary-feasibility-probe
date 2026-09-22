'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { parseReplayFile, sha256, walkBlocks } = require('../src/rofl');

function readJsonl(filePath) {
  const buffer = fs.readFileSync(filePath);
  return {
    rows: buffer.toString('utf8').split('\n').filter(Boolean).map(JSON.parse),
    sha256: sha256(buffer),
  };
}

function main(argv = process.argv.slice(2)) {
  const replayPath = argv[0];
  const eventsPath = argv[1] || path.join('artifacts', 'semantic_probe', 'spell_events.jsonl');
  const radius = Number(argv[2] ?? 2000);
  const replay = parseReplayFile(path.resolve(replayPath));
  const resolvedEventsPath = path.resolve(eventsPath);
  const events = readJsonl(resolvedEventsPath);
  const casts = events.rows.filter((r) => r.spell_identifier === 'TrinketTotemLvl1'
    && r.raw_packet_ref?.replay_sha256 === replay.source_sha256);
  const byKey = new Map();
  let eligibleCount = 0;
  let nearbyCount = 0;
  const walk = walkBlocks(replay, (block, chunk) => {
    if (block.param < 0x400000b8) return;
    eligibleCount += 1;
    const nearest = casts.reduce((best, cast) => {
      const delta = block.timestamp_ms - cast.replay_time_ms;
      if (Math.abs(delta) > radius) return best;
      return !best || Math.abs(delta) < Math.abs(best.delta)
        ? { cast_time: cast.replay_time_ms, delta, caster: cast.caster_participant_id, position: cast.target_position }
        : best;
    }, null);
    if (!nearest) return;
    nearbyCount += 1;
    const key = `${block.packet_type}:${block.payload_length}`;
    const item = byKey.get(key) || { packet_type: block.packet_type, packet_id: block.packet_id, payload_length: block.payload_length, count: 0, params: new Map(), samples: [] };
    item.count += 1;
    const pkey = `0x${(block.param >>> 0).toString(16).padStart(8, '0')}`;
    item.params.set(pkey, (item.params.get(pkey) || 0) + 1);
    if (item.samples.length < 10) item.samples.push({ timestamp_ms: block.timestamp_ms, delta_ms: nearest.delta, caster: nearest.caster, cast_position: nearest.position, raw_param: block.param >>> 0, raw_payload_hex: block.payload.toString('hex'), chunk_index: chunk.index, offset: block.offset });
    byKey.set(key, item);
  }, { includeStreams: [1], strict: true });
  const result = [...byKey.values()].map((item) => ({ ...item, params: Object.fromEntries(item.params) })).sort((a, b) => b.count - a.count);
  const output = {
    replay_path: replay.source_path,
    replay_sha256: replay.source_sha256,
    replay_version: replay.header?.version ?? null,
    spell_events_path: resolvedEventsPath,
    spell_events_sha256: events.sha256,
    spell_identifier: 'TrinketTotemLvl1',
    stream_tag: 1,
    parameter_threshold: '0x400000b8',
    cast_count: casts.length,
    radius_ms: radius,
    eligible_count: eligibleCount,
    nearby_count: nearbyCount,
    candidate_count: result.length,
    walk,
    candidates: result,
  };
  const outputPath = argv[3];
  if (outputPath) fs.writeFileSync(path.resolve(outputPath), `${JSON.stringify(output, null, 2)}\n`, 'utf8');
  else process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
  return output;
}

if (require.main === module) main();
module.exports = { main };

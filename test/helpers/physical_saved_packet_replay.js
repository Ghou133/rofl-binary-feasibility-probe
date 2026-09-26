'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { parseReplayFile, walkBlocks } = require('../../src/rofl');
const { replayFromChunks } = require('./synthetic_replay');

// Give existing saved-query fixtures a physical, exact-build ROFL. The fixture
// keeps its original native input/output bytes; only Replay identity and packet
// positions are replaced with values obtained through the production framer.
function bindSavedPacketArtifactToPhysicalReplay(directory) {
  const semanticPath = path.join(directory, 'semantic_run.json');
  const analysisPath = path.join(directory, 'replay_analysis.json');
  const semantic = JSON.parse(fs.readFileSync(semanticPath, 'utf8'));
  const analysis = JSON.parse(fs.readFileSync(analysisPath, 'utf8'));
  const [eventKey] = Object.keys(analysis.event_counts);
  const eventPath = path.join(directory, `${eventKey}.jsonl`);
  const rows = fs.readFileSync(eventPath, 'utf8').trimEnd().split('\n').map(JSON.parse);
  const chunks = rows.map((row) => {
    const payload = Buffer.from(row.raw_packet_ref.raw_payload_hex, 'hex');
    const header = Buffer.alloc(12);
    header[0] = 0x10;
    header.writeFloatLE(row.replay_time_ms / 1000, 1);
    header[5] = payload.length;
    header.writeUInt16LE(row.raw_packet_ref.packet_id, 6);
    header.writeUInt32LE(row.raw_param >>> 0, 8);
    return { body: Buffer.concat([header, payload]),
      stream: row.raw_packet_ref.chunk_stream === 'keyframe' ? 2 : 1 };
  });
  const generated = replayFromChunks(chunks, semantic.replay_version);
  const sourcePath = path.join(path.dirname(path.dirname(directory)),
    `${path.basename(directory)}-source.rofl`);
  fs.writeFileSync(sourcePath, generated.buffer);
  const replay = parseReplayFile(sourcePath);
  let index = 0;
  walkBlocks(replay, (block, chunk) => {
    const row = rows[index++];
    if (!row || block.packet_id !== row.raw_packet_ref.packet_id) {
      throw new Error('synthetic source packet order differs from the saved fixture');
    }
    row.replay_sha256 = replay.source_sha256;
    row.replay_time_ms = block.timestamp_ms;
    Object.assign(row.raw_packet_ref, {
      source_path: sourcePath, replay_sha256: replay.source_sha256,
      chunk_index: chunk.index, chunk_id: chunk.chunk_id,
      chunk_stream: chunk.stream, chunk_file_offset: chunk.offset,
      decompressed_block_offset: block.offset,
      decompressed_payload_offset: block.payload_offset,
      replay_time_ms: block.timestamp_ms,
    });
  }, { strict: true });
  if (index !== rows.length) throw new Error('synthetic source packet count differs');
  semantic.replay_sha256 = replay.source_sha256;
  analysis.replay_sha256 = replay.source_sha256;
  analysis.source_path = sourcePath;
  fs.writeFileSync(semanticPath, JSON.stringify(semantic));
  fs.writeFileSync(analysisPath, JSON.stringify(analysis));
  fs.writeFileSync(eventPath, `${rows.map(JSON.stringify).join('\n')}\n`);
  return { sourcePath, rows, semantic, analysis, eventPath };
}

module.exports = { bindSavedPacketArtifactToPhysicalReplay };

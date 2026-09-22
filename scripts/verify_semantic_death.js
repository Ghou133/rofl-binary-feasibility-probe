#!/usr/bin/env node

const fs = require('node:fs');
const path = require('node:path');

const {
  decodeHeroDeathBlock,
} = require('../src/decoders/rofl_16_15_801_3452');
const {
  parseReplayFile,
  sha256,
  walkBlocks,
} = require('../src/rofl');

function usage() {
  return 'Usage: node scripts/verify_semantic_death.js <death_events.jsonl> [zero-based-index]';
}

function loadJsonl(filePath) {
  return fs.readFileSync(filePath, 'utf8')
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

function main(argv = process.argv.slice(2)) {
  if (!argv[0]) throw new Error(usage());
  const eventFile = path.resolve(argv[0]);
  const index = argv[1] === undefined ? 0 : Number(argv[1]);
  if (!Number.isSafeInteger(index) || index < 0) throw new Error(`invalid event index: ${argv[1]}`);

  const events = loadJsonl(eventFile);
  const expected = events[index];
  if (!expected) throw new Error(`event index is out of range: ${index}`);
  const reference = expected.raw_packet_ref;
  if (!reference?.source_path) throw new Error('event has no raw_packet_ref.source_path');

  const replay = parseReplayFile(reference.source_path);
  if (replay.source_sha256 !== reference.replay_sha256) {
    throw new Error(`Replay SHA-256 mismatch: ${replay.source_sha256}`);
  }

  let matchedBlock = null;
  let decoded = null;
  const walk = walkBlocks(replay, (block, chunk) => {
    if (chunk.index !== reference.chunk_index
      || block.offset !== reference.decompressed_block_offset) return;
    matchedBlock = {
      chunk_index: chunk.index,
      chunk_id: chunk.chunk_id,
      chunk_stream: chunk.stream,
      decompressed_block_offset: block.offset,
      decompressed_payload_offset: block.payload_offset,
      packet_id: block.packet_id,
      payload_length: block.payload_length,
      payload_sha256: sha256(block.payload),
      payload_hex: block.payload.toString('hex'),
      raw_param: block.param >>> 0,
      replay_time_ms: block.timestamp_ms,
    };
    decoded = decodeHeroDeathBlock(replay, chunk, block);
  }, { includeStreams: [1], strict: true });

  if (!matchedBlock) throw new Error('referenced Replay block was not found');
  if (!decoded) throw new Error('referenced Replay block was rejected by the death decoder');
  const checks = {
    payload_sha256: matchedBlock.payload_sha256 === expected.raw_payload_sha256,
    replay_time_ms: decoded.replay_time_ms === expected.replay_time_ms,
    victim_participant_id: decoded.victim_participant_id === expected.victim_participant_id,
    victim_network_id: decoded.victim_network_id === expected.victim_network_id,
    victim_champion: decoded.victim_champion === expected.victim_champion,
    raw_param: decoded.raw_param === expected.raw_param,
  };
  const passed = Object.values(checks).every(Boolean);
  if (!passed) throw new Error(`semantic checks failed: ${JSON.stringify(checks)}`);

  process.stdout.write(`${JSON.stringify({
    status: 'VERIFIED_SEMANTIC_DEATH',
    event_file: eventFile,
    event_index: index,
    replay_sha256: replay.source_sha256,
    parser_block_errors: walk.errors.length,
    chain: {
      replay_bytes: 'VERIFIED',
      chunk_record: 'VERIFIED',
      decompressed_block: 'VERIFIED',
      raw_packet: 'VERIFIED',
      decoded_event: 'VERIFIED',
      final_event_row: 'VERIFIED',
    },
    checks,
    matched_block: matchedBlock,
    decoded_event: decoded,
  }, null, 2)}\n`);
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.stack || error.message}\n${usage()}\n`);
    process.exitCode = 1;
  }
}

module.exports = { loadJsonl, main };

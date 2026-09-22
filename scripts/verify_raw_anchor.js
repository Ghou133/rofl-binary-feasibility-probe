#!/usr/bin/env node

const fs = require('node:fs');
const path = require('node:path');

const {
  parseReplayFile,
  sha256,
  walkBlocks,
} = require('../src/rofl');
const { safeStem } = require('../src/io');

function usage() {
  return 'Usage: node scripts/verify_raw_anchor.js <raw_packet_anchors.json> [index] [--output-root <path>]';
}

function parseArgs(argv) {
  const anchorFile = argv[0];
  let index = 0;
  let outputRoot = null;
  for (let cursor = 1; cursor < argv.length; cursor += 1) {
    const token = argv[cursor];
    if (token === '--output-root') {
      outputRoot = argv[++cursor];
      if (!outputRoot) throw new Error('Missing value for --output-root');
    } else if (/^\d+$/.test(token)) {
      index = Number(token);
    } else {
      throw new Error(`Unknown argument: ${token}`);
    }
  }
  if (!anchorFile) throw new Error(usage());
  return { anchorFile: path.resolve(anchorFile), index, outputRoot: outputRoot ? path.resolve(outputRoot) : null };
}

function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  const anchorDocument = JSON.parse(fs.readFileSync(options.anchorFile, 'utf8'));
  const anchors = Array.isArray(anchorDocument) ? anchorDocument : anchorDocument.anchors;
  if (!Array.isArray(anchors) || anchors.length === 0) throw new Error('Anchor file has no rows.');
  const anchor = anchors[options.index];
  if (!anchor) throw new Error(`Anchor index is out of range: ${options.index}`);
  const reference = anchor.raw_packet_ref;
  if (!reference || !reference.source_path) throw new Error('Anchor has no raw_packet_ref.source_path.');

  const sourceCandidates = [
    reference.source_path ? path.resolve(reference.source_path) : null,
    anchor.bundle_replay_path
      ? path.resolve(path.dirname(options.anchorFile), anchor.bundle_replay_path)
      : null,
  ].filter(Boolean);
  const sourcePath = sourceCandidates.find((candidate) => fs.existsSync(candidate));
  if (!sourcePath) throw new Error(`Replay file is unavailable: ${sourceCandidates.join(' or ')}`);
  const sourceBytes = fs.readFileSync(sourcePath);
  const sourceSha256 = sha256(sourceBytes);
  if (sourceSha256 !== reference.replay_sha256) {
    throw new Error(`Replay SHA-256 mismatch: expected ${reference.replay_sha256}, got ${sourceSha256}`);
  }

  const replay = parseReplayFile(sourcePath);
  let matched = null;
  const walk = walkBlocks(replay, (block, chunk) => {
    if (chunk.index !== reference.chunk_index || block.offset !== reference.decompressed_block_offset) return;
    matched = {
      chunk_index: chunk.index,
      chunk_id: chunk.chunk_id,
      block_offset: block.offset,
      payload_offset: block.payload_offset,
      packet_id: block.packet_id,
      timestamp_ms: block.timestamp_ms,
      payload_length: block.payload_length,
      payload_sha256: sha256(block.payload),
    };
  });
  if (!matched) throw new Error('Referenced chunk/block was not found while rescanning the Replay.');
  if (matched.payload_length !== reference.payload_length) throw new Error('Referenced payload length does not match.');
  const expectedPayloadSha256 = anchor.raw_payload_sha256 || reference.payload_sha256;
  if (matched.payload_sha256 !== expectedPayloadSha256) throw new Error('Referenced payload SHA-256 does not match.');

  let finalOutput = { status: 'NOT_CHECKED', event_rows: null, matching_raw_refs: null };
  if (anchor.event_file) {
    const eventFile = path.resolve(path.dirname(options.anchorFile), anchor.event_file);
    const rows = readEventRows(eventFile);
    const matchingRefs = matchingSemanticRows(rows, reference);
    finalOutput = {
      status: matchingRefs.length > 0 ? 'PRESENT' : 'MISSING_RAW_REFERENCE',
      event_file: eventFile,
      event_rows: rows.length,
      matching_raw_refs: matchingRefs.length,
      semantic_statuses: [...new Set(matchingRefs.map(
        (row) => row.semantic_status || row.confidence || null,
      ).filter(Boolean))],
    };
  }
  if (options.outputRoot) {
    const eventFile = path.join(options.outputRoot, 'replays', safeStem(sourcePath), 'events.json');
    if (fs.existsSync(eventFile)) {
      const events = JSON.parse(fs.readFileSync(eventFile, 'utf8'));
      const rows = Object.values(events).flatMap((value) => Array.isArray(value) ? value : []);
      const matchingRefs = matchingSemanticRows(rows, reference);
      finalOutput = {
        status: rows.length === 0 ? 'EMPTY_BY_DESIGN' : 'PRESENT',
        event_rows: rows.length,
        matching_raw_refs: matchingRefs.length,
      };
    }
  }

  process.stdout.write(`${JSON.stringify({
    status: finalOutput.matching_raw_refs > 0 ? 'VERIFIED_RAW_TO_SEMANTIC' : 'VERIFIED_RAW_ONLY',
    anchor_index: options.index,
    anchor_kind: anchor.anchor_kind,
    source_path: sourcePath,
    replay_sha256: sourceSha256,
    parser_block_errors: walk.errors.length,
    chain: {
      replay_bytes: 'VERIFIED',
      chunk_record: 'VERIFIED',
      decompressed_block: 'VERIFIED',
      raw_packet: 'VERIFIED',
      decoded_event: finalOutput.matching_raw_refs > 0 ? 'VERIFIED' : 'NOT_CHECKED',
      final_output: finalOutput.status,
    },
    matched,
    final_output: finalOutput,
  }, null, 2)}\n`);
}

function readEventRows(filePath) {
  if (!fs.existsSync(filePath)) throw new Error(`Semantic event file is unavailable: ${filePath}`);
  if (filePath.toLowerCase().endsWith('.jsonl')) {
    return fs.readFileSync(filePath, 'utf8').split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line));
  }
  const document = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  if (Array.isArray(document)) return document;
  return Object.values(document).flatMap((value) => Array.isArray(value) ? value : []);
}

function matchingSemanticRows(rows, reference) {
  return rows.filter((row) => row.raw_packet_ref
    && row.raw_packet_ref.replay_sha256 === reference.replay_sha256
    && row.raw_packet_ref.chunk_index === reference.chunk_index
    && row.raw_packet_ref.decompressed_block_offset === reference.decompressed_block_offset
    && row.raw_packet_ref.payload_sha256 === reference.payload_sha256);
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.message || error}\n${usage()}\n`);
    process.exitCode = 1;
  }
}

module.exports = { main, parseArgs };

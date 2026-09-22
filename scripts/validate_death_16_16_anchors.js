#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { parseReplayFile, walkBlocks } = require('../src/rofl');
const {
  DEATH_16_16_BUILD,
  DEATH_16_16_PACKET_ID,
  createDeathRouteAnchorValidation,
} = require('../src/validation/death_16_16');

function parseArgs(argv) {
  const options = { windowMs: 2 };
  for (let index = 0; index < argv.length; index += 1) {
    const key = argv[index];
    if (key === '--manifest') options.manifest = path.resolve(argv[++index]);
    else if (key === '--anchors') options.anchors = path.resolve(argv[++index]);
    else if (key === '--output') options.output = path.resolve(argv[++index]);
    else if (key === '--window-ms') options.windowMs = Number(argv[++index]);
    else throw new Error(`unknown option: ${key}`);
  }
  for (const key of ['manifest', 'anchors', 'output']) {
    if (!options[key]) throw new Error(`--${key} is required`);
  }
  if (!Number.isFinite(options.windowMs) || options.windowMs < 0) {
    throw new Error('--window-ms must be a non-negative number');
  }
  return options;
}

function sha256(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function readJsonl(filePath) {
  const text = fs.readFileSync(filePath, 'utf8').trim();
  return text ? text.split(/\r?\n/).map((line) => JSON.parse(line)) : [];
}

function assertSafeExplicitPath(filePath) {
  if (/jungle[ _-]*objective[ _-]*holdout/i.test(filePath)) {
    throw new Error('protected Jungle Objective Holdout path is forbidden');
  }
}

function collectRouteRows(replayManifest) {
  const routeRows = [];
  for (const entry of replayManifest.replays || []) {
    const replayPath = path.resolve(entry.replay.path);
    assertSafeExplicitPath(replayPath);
    const replay = parseReplayFile(replayPath);
    if (replay.header.version !== DEATH_16_16_BUILD) {
      throw new Error(`wrong Replay build: ${replay.header.version}`);
    }
    if (replay.source_sha256 !== entry.replay.sha256) {
      throw new Error(`Replay SHA-256 mismatch: ${replayPath}`);
    }
    const walked = walkBlocks(replay, (block, chunk) => {
      if (block.packet_id !== DEATH_16_16_PACKET_ID) return;
      routeRows.push({
        replay_sha256: replay.source_sha256,
        replay_build: replay.header.version,
        timestamp_ms: block.timestamp_ms,
        packet_id: block.packet_id,
        raw_param: block.param >>> 0,
        payload_length: block.payload_length,
        stream_tag: chunk.stream_tag,
        chunk_index: chunk.index,
        block_offset: block.offset,
        raw_payload_sha256: crypto.createHash('sha256').update(block.payload).digest('hex'),
      });
    }, { strict: true });
    if (walked.errors.length !== 0) throw new Error(`Replay walk failed: ${replayPath}`);
  }
  return routeRows;
}

function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  for (const filePath of [options.manifest, options.anchors, options.output]) {
    assertSafeExplicitPath(filePath);
  }
  const manifest = JSON.parse(fs.readFileSync(options.manifest, 'utf8'));
  const anchorRows = readJsonl(options.anchors);
  if (manifest.target?.replay_header_build !== DEATH_16_16_BUILD
      || manifest.jsonl?.sha256 !== sha256(options.anchors)) {
    throw new Error('P0 manifest does not attest the exact anchor input');
  }
  const routeRows = collectRouteRows(manifest);
  const report = createDeathRouteAnchorValidation({
    anchorRows,
    routeRows,
    provenance: {
      manifest: { path: options.manifest, sha256: sha256(options.manifest) },
      anchors: { path: options.anchors, sha256: sha256(options.anchors) },
      replays: manifest.replays.map((entry) => ({
        game_id: String(entry.game_id),
        path: entry.replay.path,
        sha256: entry.replay.sha256,
      })),
    },
  }, { windowMs: options.windowMs });
  fs.mkdirSync(path.dirname(options.output), { recursive: true });
  fs.writeFileSync(options.output, `${JSON.stringify(report, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify({
    status: report.status,
    details_death_anchor_count: report.details_death_anchor_count,
    route_packet_count: report.route_packet_count,
    matched_count: report.matched_count,
    timestamp_absolute_delta_ms: report.timestamp_absolute_delta_ms,
    output: options.output,
    output_sha256: sha256(options.output),
  }, null, 2)}\n`);
  if (report.status !== 'PASS') process.exitCode = 1;
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { assertSafeExplicitPath, collectRouteRows, main, parseArgs, readJsonl, sha256 };

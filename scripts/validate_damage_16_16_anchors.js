#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { parseReplayFile } = require('../src/rofl');
const { createDamageAnchorValidation } = require('../src/validation/damage_16_16');

function parseArgs(argv) {
  const result = { maxTimeMs: null, windowMs: 100 };
  for (let index = 0; index < argv.length; index += 1) {
    const key = argv[index];
    if (key === '--replay') result.replay = path.resolve(argv[++index]);
    else if (key === '--details') result.details = path.resolve(argv[++index]);
    else if (key === '--decoded') result.decoded = path.resolve(argv[++index]);
    else if (key === '--decoder-summary') result.decoderSummary = path.resolve(argv[++index]);
    else if (key === '--output') result.output = path.resolve(argv[++index]);
    else if (key === '--max-time-ms') result.maxTimeMs = Number(argv[++index]);
    else if (key === '--window-ms') result.windowMs = Number(argv[++index]);
    else throw new Error(`unknown option: ${key}`);
  }
  for (const key of ['replay', 'details', 'decoded', 'decoderSummary', 'output']) {
    if (!result[key]) throw new Error(`--${key.replace(/[A-Z]/g, (value) => `-${value.toLowerCase()}`)} is required`);
  }
  if (result.maxTimeMs !== null && (!Number.isFinite(result.maxTimeMs) || result.maxTimeMs < 0)) {
    throw new Error('--max-time-ms must be a non-negative number');
  }
  if (!Number.isFinite(result.windowMs) || result.windowMs < 0) {
    throw new Error('--window-ms must be a non-negative number');
  }
  return result;
}

function sha256(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function readJsonl(filePath) {
  const text = fs.readFileSync(filePath, 'utf8').trim();
  return text ? text.split(/\r?\n/).map((line) => JSON.parse(line)) : [];
}

function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  const replay = parseReplayFile(options.replay);
  if (replay.header.version !== '16.16.805.0442') {
    throw new Error(`wrong Replay build: ${replay.header.version}`);
  }
  const details = JSON.parse(fs.readFileSync(options.details, 'utf8'));
  const decodedRows = readJsonl(options.decoded);
  const decoderSummary = JSON.parse(fs.readFileSync(options.decoderSummary, 'utf8'));
  if (decoderSummary.image_sha256
      !== '0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55'
      || decoderSummary.successful_full_consume_count !== decodedRows.length
      || decoderSummary.event_count !== decodedRows.length) {
    throw new Error('decoder summary does not attest every exact-build decoded row');
  }
  const validation = createDamageAnchorValidation({
    details,
    decodedRows,
    provenance: {
      replay: { path: replay.source_path, sha256: replay.source_sha256 },
      details: { path: options.details, sha256: sha256(options.details) },
      decoded: { path: options.decoded, sha256: sha256(options.decoded) },
      decoder_summary: {
        path: options.decoderSummary,
        sha256: sha256(options.decoderSummary),
        runtime_image_sha256: decoderSummary.image_sha256,
        decoder_profile: decoderSummary.decoder_profile,
        decoder_profile_sha256: decoderSummary.profile_sha256,
      },
    },
  }, { maxTimeMs: options.maxTimeMs, windowMs: options.windowMs });
  fs.mkdirSync(path.dirname(options.output), { recursive: true });
  fs.writeFileSync(options.output, `${JSON.stringify(validation, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify({
    status: validation.status,
    matched_anchor_count: validation.matched_anchor_count,
    damage_type_match_counts: validation.damage_type_match_counts,
    output: options.output,
    output_sha256: sha256(options.output),
  }, null, 2)}\n`);
  if (validation.status !== 'PASS') process.exitCode = 1;
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { main, parseArgs, readJsonl, sha256 };


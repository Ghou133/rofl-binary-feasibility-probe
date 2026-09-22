#!/usr/bin/env node

const fs = require('node:fs');
const path = require('node:path');

const { PROFILE, decodeHeroDeaths } = require('../src/decoders/rofl_16_15_801_3452');
const { sha256File, writeJson, writeJsonl } = require('../src/io');
const { parseReplayFile } = require('../src/rofl');

function parseArgs(argv) {
  const options = { replay: null, output: null, manifest: null };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === '--replay') options.replay = path.resolve(argv[++index]);
    else if (value === '--output') options.output = path.resolve(argv[++index]);
    else if (value === '--manifest') options.manifest = path.resolve(argv[++index]);
    else throw new Error(`unknown argument: ${value}`);
  }
  if (!options.replay) throw new Error('--replay is required');
  if (!options.output) throw new Error('--output is required');
  options.manifest ||= `${options.output}.manifest.json`;
  return options;
}

async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  const replay = parseReplayFile(options.replay);
  const decoded = decodeHeroDeaths(replay);
  writeJsonl(options.output, decoded.events);
  const manifest = {
    schema_version: 1,
    status: decoded.walk.errors.length === 0
      && decoded.rejected_signature_count === 0
      && decoded.events.length === decoded.signature_count ? 'PASS' : 'FAIL',
    operation: 'REPLAY_ONLY_HERO_DEATH_EVENT_BUILD',
    details_or_oracle_input: false,
    decoder_profile: PROFILE,
    replay_path: replay.source_path,
    replay_sha256: replay.source_sha256,
    replay_version: replay.header.version,
    signature_count: decoded.signature_count,
    rejected_signature_count: decoded.rejected_signature_count,
    event_count: decoded.events.length,
    parser_error_count: decoded.walk.errors.length,
    output: options.output,
    output_sha256: await sha256File(options.output),
  };
  writeJson(options.manifest, manifest);
  process.stdout.write(`${JSON.stringify({ ...manifest, manifest: options.manifest }, null, 2)}\n`);
  if (manifest.status !== 'PASS') process.exitCode = 1;
}

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
  });
}

module.exports = { main, parseArgs };

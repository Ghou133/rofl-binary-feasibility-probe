#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const {
  assertSafePath,
  analyzeHeroReincarnateAlive,
} = require('../src/hero_reincarnate_alive_v2');

const ROOT = path.resolve(__dirname, '..');
const DEFAULTS = Object.freeze({
  decoded: path.join(
    ROOT,
    'artifacts/full_semantic_deep_recovery_v2/hero_respawn/packet_0265_p0_decoded.jsonl',
  ),
  anchors: path.join(
    ROOT,
    'artifacts/hero_combat_state_v2/anchors/details_p0_ground_truth.jsonl',
  ),
  anchorManifest: path.join(
    ROOT,
    'artifacts/hero_combat_state_v2/anchors/details_p0_manifest.json',
  ),
  outputDir: path.join(
    ROOT,
    'artifacts/full_semantic_deep_recovery_v2/hero_respawn',
  ),
});

function parseArgs(argv) {
  const options = { ...DEFAULTS };
  const aliases = {
    '--decoded': 'decoded',
    '--anchors': 'anchors',
    '--anchor-manifest': 'anchorManifest',
    '--output-dir': 'outputDir',
  };
  for (let index = 0; index < argv.length; index += 1) {
    const key = aliases[argv[index]];
    if (!key || index + 1 >= argv.length) {
      throw new Error(`unknown or incomplete argument: ${argv[index]}`);
    }
    options[key] = path.resolve(argv[++index]);
  }
  return options;
}

function sha256Buffer(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function readSafe(filePath) {
  assertSafePath(filePath);
  return fs.readFileSync(filePath);
}

function readJson(filePath) {
  return JSON.parse(readSafe(filePath).toString('utf8'));
}

function readJsonl(filePath) {
  return readSafe(filePath).toString('utf8').split(/\r?\n/)
    .filter(Boolean).map((line) => JSON.parse(line));
}

function verifyManifestFile(record, kind) {
  const filePath = record && record[kind] && record[kind].path;
  const expected = record && record[kind] && record[kind].sha256;
  if (!filePath || !expected) throw new Error(`P0 manifest is missing ${kind}`);
  const bytes = readSafe(filePath);
  const actual = sha256Buffer(bytes);
  if (actual !== expected) {
    throw new Error(`${kind} SHA-256 mismatch for safe P0 game ${record.game_id}`);
  }
  return { path: filePath, bytes, sha256: actual };
}

function stableJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  for (const filePath of Object.values(options)) assertSafePath(filePath);
  const decodedRows = readJsonl(options.decoded);
  const anchors = readJsonl(options.anchors);
  const anchorManifest = readJson(options.anchorManifest);
  const detailsByGame = new Map();
  const verifiedInputs = [];
  for (const replay of anchorManifest.replays || []) {
    const details = verifyManifestFile(replay, 'details');
    const wrapper = JSON.parse(details.bytes.toString('utf8'));
    if (!wrapper.json || !Array.isArray(wrapper.json.frames)) {
      throw new Error(`safe P0 DETAILS wrapper is invalid for ${replay.game_id}`);
    }
    detailsByGame.set(replay.game_id, wrapper.json.frames);
    verifiedInputs.push({
      game_id: replay.game_id,
      replay_build: replay.replay_build,
      replay_sha256: replay.replay.sha256,
      details_path: details.path,
      details_sha256: details.sha256,
    });
  }

  const { report, events } = analyzeHeroReincarnateAlive({
    decodedRows,
    anchors,
    detailsByGame,
  });
  report.inputs = {
    decoded_jsonl: {
      path: options.decoded,
      sha256: sha256Buffer(readSafe(options.decoded)),
      row_count: decodedRows.length,
    },
    anchors_jsonl: {
      path: options.anchors,
      sha256: sha256Buffer(readSafe(options.anchors)),
      row_count: anchors.length,
    },
    anchor_manifest: {
      path: options.anchorManifest,
      sha256: sha256Buffer(readSafe(options.anchorManifest)),
    },
    explicit_safe_details: verifiedInputs,
  };

  fs.mkdirSync(options.outputDir, { recursive: true });
  const reportPath = path.join(
    options.outputDir,
    'hero_reincarnate_alive_audit_16_16.json',
  );
  const eventsPath = path.join(
    options.outputDir,
    'hero_reincarnate_alive_events_16_16.jsonl',
  );
  fs.writeFileSync(reportPath, stableJson(report));
  fs.writeFileSync(eventsPath, `${events.map((event) => JSON.stringify(event)).join('\n')}\n`);

  const files = [
    path.join(ROOT, 'src/hero_reincarnate_alive_v2.js'),
    path.join(ROOT, 'scripts/audit_hero_reincarnate_alive_v2.js'),
    path.join(ROOT, 'test/hero_reincarnate_alive_v2.test.js'),
    options.decoded,
    options.anchors,
    options.anchorManifest,
    reportPath,
    eventsPath,
  ].map((filePath) => ({
    path: path.relative(ROOT, filePath).replaceAll('\\', '/'),
    sha256: sha256Buffer(readSafe(filePath)),
    byte_size: readSafe(filePath).length,
  }));
  const hashesPath = path.join(
    options.outputDir,
    'hero_reincarnate_alive_hashes_16_16.json',
  );
  fs.writeFileSync(hashesPath, stableJson({
    schema_version: 1,
    exact_build: '16.16.805.0442',
    deterministic: true,
    protected_holdout_access: false,
    files,
  }));

  process.stdout.write(`${JSON.stringify({
    report_path: reportPath,
    report_sha256: sha256Buffer(readSafe(reportPath)),
    events_path: eventsPath,
    events_sha256: sha256Buffer(readSafe(eventsPath)),
    hashes_path: hashesPath,
    row_count: events.length,
    matched_deaths:
      report.death_respawn_differential.matched_unique_death_to_route_count,
    unmatched_terminal_deaths:
      report.death_respawn_differential.unmatched_death_count,
  }, null, 2)}\n`);
}

if (require.main === module) main();

module.exports = { DEFAULTS, parseArgs, main };

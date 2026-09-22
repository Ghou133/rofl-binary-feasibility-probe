#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const {
  EXPECTED_SAFE_GAME_IDS,
  EXPECTED_SAFE_SAMPLES,
  HERO_STATS_16_16_BUILD,
  createHeroStatsScoreboardValidation,
  validateDecodeSummary,
  validateDetailsManifest,
  validatePacketManifest,
} = require('../src/validation/hero_stats_16_16');

const DEFAULT_PATHS = Object.freeze({
  packetManifest: path.resolve(
    'artifacts', 'full_semantic_baseline_v1', 'hero_stats',
    'packet_010c_p0_four.jsonl.manifest.json',
  ),
  decodedJsonl: path.resolve(
    'artifacts', 'full_semantic_baseline_v1', 'hero_stats',
    'packet_010c_p0_four_decoded.jsonl',
  ),
  decodeSummary: path.resolve(
    'artifacts', 'full_semantic_baseline_v1', 'hero_stats',
    'packet_010c_p0_four_decode_summary.json',
  ),
  detailsManifest: path.resolve(
    'artifacts', 'hero_combat_state_v2', 'anchors', 'details_p0_manifest.json',
  ),
  output: path.resolve(
    'artifacts', 'full_semantic_baseline_v1', 'hero_stats',
    'hero_stats_scoreboard_validation_16_16.json',
  ),
});

function fail(message) {
  throw new Error(`16.16 HeroStats validation CLI: ${message}`);
}

function assertSafeExplicitPath(filePath) {
  if (typeof filePath !== 'string' || filePath.length === 0) fail('path must be a non-empty string');
  const compact = filePath.toLowerCase().replace(/[^a-z0-9]+/g, '');
  if (compact.includes('jungleobjectiveholdout')) {
    fail('protected Jungle Objective Holdout path is forbidden');
  }
}

function sha256Buffer(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function readBuffer(filePath) {
  assertSafeExplicitPath(filePath);
  return fs.readFileSync(filePath);
}

function readJsonWithHash(filePath) {
  const buffer = readBuffer(filePath);
  return { value: JSON.parse(buffer.toString('utf8')), sha256: sha256Buffer(buffer) };
}

function readJsonlWithHash(filePath) {
  const buffer = readBuffer(filePath);
  const text = buffer.toString('utf8').trim();
  return {
    value: text ? text.split(/\r?\n/).map((line, index) => {
      try {
        return JSON.parse(line);
      } catch (error) {
        fail(`invalid JSONL at ${filePath}:${index + 1}: ${error.message}`);
      }
      return null;
    }) : [],
    sha256: sha256Buffer(buffer),
  };
}

function unwrapDetailsDocument(document, gameId) {
  if (!document || typeof document !== 'object' || Array.isArray(document)) {
    fail(`DETAILS ${gameId} wrapper must be an object`);
  }
  if (!Object.hasOwn(document, 'json') || !Object.hasOwn(document, 'metadata')) {
    fail(`DETAILS ${gameId} must use the top-level {json, metadata} wrapper`);
  }
  const metadata = document.metadata;
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) {
    fail(`DETAILS ${gameId} metadata must be an object`);
  }
  if (String(metadata.info_type ?? '').toLowerCase() !== 'details'
      || String(metadata.data_version ?? '') !== '2'
      || String(metadata.product ?? '').toLowerCase() !== 'lol') {
    fail(`DETAILS ${gameId} wrapper metadata mismatch`);
  }
  if (!String(metadata.match_id ?? '').endsWith(`_${gameId}`)) {
    fail(`DETAILS ${gameId} match_id mismatch`);
  }
  let payload = document.json;
  if (typeof payload === 'string') payload = JSON.parse(payload);
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    fail(`DETAILS ${gameId} payload must be an object`);
  }
  if (String(payload.gameId ?? '') !== gameId) fail(`DETAILS ${gameId} payload gameId mismatch`);
  return { metadata, payload };
}

function extractDetailsRows(detailsManifest) {
  validateDetailsManifest(detailsManifest);
  const rows = [];
  const sourceAttestations = [];
  for (const entry of detailsManifest.replays) {
    const gameId = String(entry.game_id);
    const expected = EXPECTED_SAFE_SAMPLES[gameId];
    const detailsPath = path.resolve(entry.details.path);
    assertSafeExplicitPath(detailsPath);
    const buffer = readBuffer(detailsPath);
    const actualDetailsSha256 = sha256Buffer(buffer);
    if (actualDetailsSha256 !== expected.details_sha256
        || actualDetailsSha256 !== entry.details.sha256) {
      fail(`DETAILS SHA-256 mismatch for ${gameId}`);
    }
    const { metadata, payload } = unwrapDetailsDocument(
      JSON.parse(buffer.toString('utf8')),
      gameId,
    );
    if (!Array.isArray(payload.frames) || payload.frames.length !== expected.frame_count) {
      fail(`DETAILS frame count mismatch for ${gameId}`);
    }
    let previousTimestamp = -1;
    for (let frameIndex = 0; frameIndex < payload.frames.length; frameIndex += 1) {
      const frame = payload.frames[frameIndex];
      if (!frame || typeof frame !== 'object' || Array.isArray(frame)) {
        fail(`DETAILS ${gameId} frame ${frameIndex} is invalid`);
      }
      if (!Number.isInteger(frame.timestamp) || frame.timestamp <= previousTimestamp) {
        fail(`DETAILS ${gameId} frame ${frameIndex} timestamp is not strictly increasing`);
      }
      previousTimestamp = frame.timestamp;
      const participantFrames = frame.participantFrames;
      if (!participantFrames || typeof participantFrames !== 'object'
          || Array.isArray(participantFrames)) {
        fail(`DETAILS ${gameId} frame ${frameIndex} participantFrames is invalid`);
      }
      const participantKeys = Object.keys(participantFrames).sort((left, right) => Number(left) - Number(right));
      if (participantKeys.length !== 10
          || participantKeys.some((value, index) => value !== String(index + 1))) {
        fail(`DETAILS ${gameId} frame ${frameIndex} does not contain participants 1..10 exactly`);
      }
      for (let participantId = 1; participantId <= 10; participantId += 1) {
        const participant = participantFrames[String(participantId)];
        if (!participant || typeof participant !== 'object' || Array.isArray(participant)
            || participant.participantId !== participantId) {
          fail(`DETAILS ${gameId} frame ${frameIndex} participant ${participantId} identity mismatch`);
        }
        rows.push({
          game_id: gameId,
          replay_sha256: expected.replay_sha256,
          replay_build: HERO_STATS_16_16_BUILD,
          details_sha256: actualDetailsSha256,
          frame_index: frameIndex,
          timestamp_ms: frame.timestamp,
          participant_id: participantId,
          fields: {
            minionsKilled: participant.minionsKilled,
            xp: participant.xp,
            totalGold: participant.totalGold,
            jungleMinionsKilled: participant.jungleMinionsKilled,
          },
          source_json_paths: {
            minionsKilled:
              `$.json.frames[${frameIndex}].participantFrames[\"${participantId}\"].minionsKilled`,
            xp: `$.json.frames[${frameIndex}].participantFrames[\"${participantId}\"].xp`,
            totalGold:
              `$.json.frames[${frameIndex}].participantFrames[\"${participantId}\"].totalGold`,
            jungleMinionsKilled:
              `$.json.frames[${frameIndex}].participantFrames[\"${participantId}\"].jungleMinionsKilled`,
          },
        });
      }
    }
    sourceAttestations.push({
      game_id: gameId,
      replay_path: entry.replay.path,
      replay_sha256: entry.replay.sha256,
      replay_build: entry.replay_build,
      details_path: detailsPath,
      expected_details_sha256: entry.details.sha256,
      actual_details_sha256: actualDetailsSha256,
      details_sha256_verification_method: 'SHA256_OF_EXPLICIT_FILE_BYTES',
      details_wrapper: {
        data_version: String(metadata.data_version),
        info_type: metadata.info_type,
        match_id: metadata.match_id,
        product: metadata.product,
      },
      frame_count: payload.frames.length,
      participant_frame_count: payload.frames.length * 10,
    });
  }
  return { rows, sourceAttestations };
}

function parseArgs(argv) {
  const options = { ...DEFAULT_PATHS, windowMs: 1 };
  const mappings = {
    '--packet-manifest': 'packetManifest',
    '--decoded-jsonl': 'decodedJsonl',
    '--decode-summary': 'decodeSummary',
    '--details-manifest': 'detailsManifest',
    '--output': 'output',
  };
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    if (Object.hasOwn(mappings, option)) {
      const value = argv[++index];
      if (value === undefined || value.startsWith('--')) fail(`${option} requires a path`);
      options[mappings[option]] = path.resolve(value);
    } else if (option === '--window-ms') {
      options.windowMs = Number(argv[++index]);
    } else {
      fail(`unknown option: ${option}`);
    }
  }
  if (options.windowMs !== 1) fail('--window-ms must remain exactly 1 for this strict baseline');
  for (const filePath of Object.values(options).filter((value) => typeof value === 'string')) {
    assertSafeExplicitPath(filePath);
  }
  return options;
}

function loadExactValidationInput(options = { ...DEFAULT_PATHS, windowMs: 1 }) {
  for (const key of ['packetManifest', 'decodedJsonl', 'decodeSummary', 'detailsManifest']) {
    assertSafeExplicitPath(options[key]);
  }
  const packetManifestInput = readJsonWithHash(options.packetManifest);
  const decodeSummaryInput = readJsonWithHash(options.decodeSummary);
  const detailsManifestInput = readJsonWithHash(options.detailsManifest);

  // Validate the exact hard-coded safe set before following any manifest-owned DETAILS path.
  validatePacketManifest(packetManifestInput.value);
  validateDecodeSummary(decodeSummaryInput.value);
  validateDetailsManifest(detailsManifestInput.value);
  for (const entry of packetManifestInput.value.replays) assertSafeExplicitPath(entry.path);
  for (const entry of detailsManifestInput.value.replays) {
    assertSafeExplicitPath(entry.replay.path);
    assertSafeExplicitPath(entry.details.path);
  }

  const decodedInput = readJsonlWithHash(options.decodedJsonl);
  const detailsInput = extractDetailsRows(detailsManifestInput.value);
  const packetGameIds = packetManifestInput.value.replays
    .map((entry) => String(entry.path).replace(/\\/g, '/').match(/\/([0-9]+)\.rofl$/i)?.[1])
    .sort();
  if (JSON.stringify(packetGameIds) !== JSON.stringify(EXPECTED_SAFE_GAME_IDS)) {
    fail('packet manifest is not the exact safe P0 set');
  }
  return {
    packetManifest: packetManifestInput.value,
    decodedRows: decodedInput.value,
    decodeSummary: decodeSummaryInput.value,
    detailsManifest: detailsManifestInput.value,
    detailsRows: detailsInput.rows,
    sourceAttestations: detailsInput.sourceAttestations,
    provenance: {
      packet_manifest: { path: options.packetManifest, sha256: packetManifestInput.sha256 },
      decoded_jsonl: { path: options.decodedJsonl, sha256: decodedInput.sha256 },
      decode_summary: { path: options.decodeSummary, sha256: decodeSummaryInput.sha256 },
      details_manifest: { path: options.detailsManifest, sha256: detailsManifestInput.sha256 },
      details_sources: detailsInput.sourceAttestations,
      replay_sha256_verification: {
        method:
          'HARD_CODED_SAFE_P0_IDENTITY_PLUS_PACKET_MANIFEST_PLUS_DETAILS_MANIFEST_PLUS_EVERY_DECODED_ROW',
        raw_replay_files_read_or_rehashed_by_this_validation: false,
      },
      input_boundary:
        'Only manifests, the pre-generated decoded 0x010c JSONL, and the four manifest-explicit safe P0 DETAILS files were read.',
    },
  };
}

function buildReportFromPaths(options) {
  return createHeroStatsScoreboardValidation(
    loadExactValidationInput(options),
    { windowMs: options.windowMs ?? 1 },
  );
}

function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  const report = buildReportFromPaths(options);
  assertSafeExplicitPath(options.output);
  fs.mkdirSync(path.dirname(options.output), { recursive: true });
  fs.writeFileSync(options.output, `${JSON.stringify(report, null, 2)}\n`);
  const outputSha256 = sha256Buffer(fs.readFileSync(options.output));
  const totalGoldAnomalies = report.fields.total_gold.aggregate.floor_mismatch_evidence;
  process.stdout.write(`${JSON.stringify({
    status: report.status,
    decoded_packet_count: report.decoded_packet_count,
    matched_count: report.matched_count,
    timestamp_delta_ms: report.timestamp_delta_ms,
    lane_minions_killed_exact: report.fields.lane_minions_killed.aggregate.exact,
    xp_floor: report.fields.xp.aggregate.transforms.floor,
    total_gold_floor: report.fields.total_gold.aggregate.transforms.floor,
    total_gold_floor_anomalies: totalGoldAnomalies,
    jungle_minions_killed_floor:
      report.fields.jungle_minions_killed.aggregate.transforms.floor,
    output: options.output,
    output_sha256: outputSha256,
  }, null, 2)}\n`);
  if (report.status !== 'PASS') process.exitCode = 1;
  return { report, outputSha256 };
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = {
  DEFAULT_PATHS,
  assertSafeExplicitPath,
  buildReportFromPaths,
  extractDetailsRows,
  loadExactValidationInput,
  main,
  parseArgs,
  readJsonlWithHash,
  sha256Buffer,
  unwrapDetailsDocument,
};

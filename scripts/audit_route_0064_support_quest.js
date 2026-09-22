#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { parseReplayFile, walkBlocks } = require('../src/rofl');
const {
  EXACT_BUILD,
  LEGACY_BUILD,
  LEGACY_PACKET_ID,
  PACKET_ID,
  analyzeRoute0064,
} = require('../src/route_0064_support_quest_audit');

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function requireValue(argv, index, option) {
  if (index >= argv.length || argv[index].startsWith('--')) throw new Error(`${option} requires a value`);
  return argv[index];
}

function rejectHoldout(value) {
  const resolved = path.resolve(value);
  if (resolved.toLowerCase().includes('holdout')) throw new Error(`protected Holdout path is forbidden: ${resolved}`);
  return resolved;
}

function parseArgs(argv) {
  const options = {
    build: EXACT_BUILD,
    latestReplays: [],
    legacyReplays: [],
    p0ManifestPath: 'artifacts/hero_combat_state_v2/anchors/details_p0_manifest.json',
    registryPath: 'artifacts/full_semantic_baseline_v1/observed_route_registry.json',
    outputPath: 'artifacts/full_semantic_deep_recovery_v2/unknown_mining/route_0064_support_quest_audit.json',
  };
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    if (option === '--build') options.build = requireValue(argv, ++index, option);
    else if (option === '--latest-replay') options.latestReplays.push(rejectHoldout(requireValue(argv, ++index, option)));
    else if (option === '--legacy-replay') options.legacyReplays.push(rejectHoldout(requireValue(argv, ++index, option)));
    else if (option === '--p0-manifest') options.p0ManifestPath = rejectHoldout(requireValue(argv, ++index, option));
    else if (option === '--registry') options.registryPath = rejectHoldout(requireValue(argv, ++index, option));
    else if (option === '--output') options.outputPath = rejectHoldout(requireValue(argv, ++index, option));
    else throw new Error(`unknown option: ${option}`);
  }
  if (options.build !== EXACT_BUILD) throw new Error(`exact build ${EXACT_BUILD} is required`);
  if (!options.latestReplays.length) throw new Error('at least one explicit --latest-replay is required');
  return options;
}

function extractReplay(replayPath, packetId, exactBuild) {
  const replay = parseReplayFile(replayPath);
  if (replay.header.version !== exactBuild) {
    throw new Error(`${replayPath} has build ${replay.header.version}; expected ${exactBuild}`);
  }
  const roster = replay.tail.stats.map((row, index) => ({
    participant_id: index + 1,
    champion: row.SKIN ?? null,
    team: row.TEAM === undefined ? null : Number(row.TEAM),
    team_position: row.TEAM_POSITION ?? null,
    role_quest_complete: row['2026_S1A1_SR_RoleQuestComplete'] ?? null,
    final_items: [row.ITEM0, row.ITEM1, row.ITEM2, row.ITEM3, row.ITEM4, row.ITEM5, row.ITEM6]
      .filter((value) => value !== undefined && value !== null),
  }));
  const events = [];
  const walk = walkBlocks(replay, (block, chunk) => {
    if (block.packet_id !== packetId) return;
    events.push({
      replay_version: replay.header.version,
      replay_sha256: replay.source_sha256,
      replay_label: path.basename(replay.source_path, path.extname(replay.source_path)),
      replay_time_ms: block.timestamp_ms,
      occurrence_index: events.length,
      packet_id: block.packet_id,
      raw_param: block.param >>> 0,
      chunk_stream: chunk.stream,
      payload_length: block.payload_length,
      raw_payload_hex: block.payload.toString('hex'),
    });
  }, { includeStreams: [1, 2, 3], strict: true });
  if (walk.errors.length) throw new Error(`${replayPath} parser errors: ${walk.errors.length}`);
  return {
    replay_path: replay.source_path,
    replay_label: path.basename(replay.source_path, path.extname(replay.source_path)),
    replay_sha256: replay.source_sha256,
    roster,
    events,
  };
}

function loadP0Records(manifestPath) {
  const manifestBytes = fs.readFileSync(manifestPath);
  const manifest = JSON.parse(manifestBytes);
  if (manifest.target?.replay_header_build !== EXACT_BUILD) throw new Error('P0 manifest exact-build mismatch');
  if (manifest.scope?.protected_holdout_enumerated !== false
    || manifest.scope?.protected_holdout_read !== false) throw new Error('P0 manifest does not attest Holdout exclusion');
  const records = [];
  for (const entry of manifest.replays) {
    const replayPath = rejectHoldout(entry.replay.path);
    const detailsPath = rejectHoldout(entry.details.path);
    const replay = extractReplay(replayPath, PACKET_ID, EXACT_BUILD);
    if (replay.replay_sha256 !== entry.replay.sha256) throw new Error(`P0 Replay SHA mismatch for ${entry.game_id}`);
    const detailsBytes = fs.readFileSync(detailsPath);
    if (sha256(detailsBytes) !== entry.details.sha256) throw new Error(`P0 DETAILS SHA mismatch for ${entry.game_id}`);
    const details = JSON.parse(detailsBytes);
    const itemEvents = [];
    for (const [frameIndex, frame] of details.json.frames.entries()) {
      for (const [eventIndex, event] of (frame.events ?? []).entries()) {
        if (!String(event.type).startsWith('ITEM_')) continue;
        itemEvents.push({
          type: event.type,
          timestamp_ms: event.timestamp,
          participant_id: event.participantId,
          item_id: event.itemId ?? null,
          before_id: event.beforeId ?? null,
          after_id: event.afterId ?? null,
          source_json_path: `$.json.frames[${frameIndex}].events[${eventIndex}]`,
        });
      }
    }
    records.push({
      ...replay,
      game_id: entry.game_id,
      item_events: itemEvents,
      provenance: {
        replay_path: replayPath,
        replay_sha256: entry.replay.sha256,
        details_path: detailsPath,
        details_sha256: entry.details.sha256,
      },
    });
  }
  return {
    manifest,
    manifest_path: path.resolve(manifestPath),
    manifest_sha256: sha256(manifestBytes),
    records,
  };
}

function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  const registryBytes = fs.readFileSync(options.registryPath);
  const registry = JSON.parse(registryBytes);
  if (registry.exact_build !== EXACT_BUILD) throw new Error('route registry exact-build mismatch');
  const route = registry.routes.find((row) => row.packet_id === PACKET_ID);
  if (!route) throw new Error('route registry is missing 0x0064');
  const latestRecords = options.latestReplays.map((replayPath) =>
    extractReplay(replayPath, PACKET_ID, EXACT_BUILD));
  const legacyRecords = options.legacyReplays.map((replayPath) =>
    extractReplay(replayPath, LEGACY_PACKET_ID, LEGACY_BUILD));
  const p0 = loadP0Records(options.p0ManifestPath);
  const report = analyzeRoute0064({
    latestRecords,
    p0Records: p0.records,
    legacyRecords,
    expectedLatestCount: route.observed.count,
  });
  report.input = {
    latest_replays: latestRecords.map((row) => ({
      path: row.replay_path,
      replay_sha256: row.replay_sha256,
      selected_packet_count: row.events.length,
    })),
    p0_manifest_path: p0.manifest_path,
    p0_manifest_sha256: p0.manifest_sha256,
    p0_replays: p0.records.map((row) => row.provenance),
    legacy_replays: legacyRecords.map((row) => ({
      path: row.replay_path,
      replay_sha256: row.replay_sha256,
      selected_packet_count: row.events.length,
    })),
    registry_path: path.resolve(options.registryPath),
    registry_sha256: sha256(registryBytes),
  };
  fs.mkdirSync(path.dirname(options.outputPath), { recursive: true });
  const text = `${JSON.stringify(report, null, 2)}\n`;
  fs.writeFileSync(options.outputPath, text, 'utf8');
  const summary = {
    output: path.resolve(options.outputPath),
    sha256: sha256(text),
    counts: report.counts,
    alignment: {
      expected: report.details_ground_truth_alignment.expected_alignment_count,
      matched: report.details_ground_truth_alignment.matched_alignment_count,
      lag_ms: report.details_ground_truth_alignment.lag_after_details_anchor_ms,
    },
    validations: report.validations,
    decision: report.route_decisions[0],
  };
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
  return summary;
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.stack ?? error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { extractReplay, loadP0Records, main, parseArgs };

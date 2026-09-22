#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { performance } = require('node:perf_hooks');
const { execFileSync } = require('node:child_process');

const {
  parseReplayFile,
  walkBlocks,
  decompressChunk,
  parseBlockAt,
  normalizePlayers,
  formatOpcode,
} = require('../src/rofl');
const { ensureDir, writeCsv, writeJson, sha256File } = require('../src/io');
const {
  REPLAY_VERSION,
  RUNTIME_IMAGE_SHA256,
  CONTAINER_PROFILE,
  SEMANTIC_PROFILE_REGISTRY,
} = require('../src/decoders/rofl_16_16_805_0442');

const OLD_VALIDATED_BUILD = '16.15.801.3452';
const DEFAULT_SAMPLE_COUNT = 40;
const CANDIDATE_IDS = Object.freeze({
  hero_path: 0x00f6,
  level_transition: 0x01e8,
  ward_spawn: 0x049a,
  hero_damage: 0x017f,
});
const OLD_SEMANTIC_IDS = Object.freeze([
  0x02d1, 0x025a, 0x0353, 0x028a, 0x0160, 0x0459,
  0x0406, 0x0031, 0x0256, 0x009e, 0x0017,
]);

function usage() {
  return [
    'Usage:',
    '  node scripts/validate_new_build_compatibility.js',
    '    --new-replays <16.16 replay directory>',
    '    --old-replays <16.15 replay directory>',
    '    --runtime-image <16.16 runtime memory image>',
    '    --output <artifact directory>',
    '    [--sample-count 40]',
  ].join('\n');
}

function parseArgs(argv) {
  const options = { sampleCount: DEFAULT_SAMPLE_COUNT };
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    const value = argv[index + 1];
    if (token === '--new-replays') options.newReplays = value;
    else if (token === '--old-replays') options.oldReplays = value;
    else if (token === '--runtime-image') options.runtimeImage = value;
    else if (token === '--output') options.output = value;
    else if (token === '--sample-count') options.sampleCount = Number.parseInt(value, 10);
    else if (token === '--help' || token === '-h') options.help = true;
    else throw new Error(`unknown option: ${token}`);
    index += 1;
  }
  if (options.help) return options;
  for (const key of ['newReplays', 'oldReplays', 'runtimeImage', 'output']) {
    if (!options[key]) throw new Error(`missing required option --${key.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`)}`);
  }
  if (!Number.isInteger(options.sampleCount) || options.sampleCount < 12 || options.sampleCount > 40) {
    throw new Error('--sample-count must be an integer from 12 through 40');
  }
  return options;
}

function listRoflFiles(directory) {
  return fs.readdirSync(directory, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.toLowerCase().endsWith('.rofl'))
    .map((entry) => path.join(directory, entry.name))
    .sort((left, right) => path.basename(left).localeCompare(path.basename(right), 'en'));
}

function selectFilesForBuild(files, replayVersion, count) {
  const selected = [];
  for (const filePath of files) {
    if (parseReplayFile(filePath).header.version === replayVersion) selected.push(filePath);
    if (selected.length === count) break;
  }
  return selected;
}

function topCounts(counts, limit = 12) {
  return [...counts.entries()]
    .sort((left, right) => right[1] - left[1] || left[0] - right[0])
    .slice(0, limit)
    .map(([value, count]) => `${value}:${count}`)
    .join('|');
}

function emptyPacketStats() {
  return { count: 0, champion_param_count: 0, payload_lengths: new Map() };
}

function updatePacketStats(stats, block) {
  stats.count += 1;
  if (block.param >= 0x400000ae && block.param <= 0x400000b7) {
    stats.champion_param_count += 1;
  }
  stats.payload_lengths.set(block.payload_length,
    (stats.payload_lengths.get(block.payload_length) || 0) + 1);
}

function inventoryReplay(filePath, selected) {
  const stat = fs.statSync(filePath);
  const replay = parseReplayFile(filePath);
  return {
    path: path.resolve(filePath),
    sha256_before: replay.source_sha256,
    sha256_after: null,
    original_unchanged: null,
    file_size: replay.file_size,
    creation_time: stat.birthtime.toISOString(),
    modified_time: stat.mtime.toISOString(),
    game_version: replay.header.version,
    duration_ms: replay.tail.metadata.gameLength ?? null,
    selected_for_validation: selected ? 'YES' : 'NO',
  };
}

function validateCoreReplay(filePath) {
  const started = performance.now();
  const replay = parseReplayFile(filePath);
  const packetStats = new Map();
  for (const packetId of [...Object.values(CANDIDATE_IDS), ...OLD_SEMANTIC_IDS]) {
    packetStats.set(packetId, emptyPacketStats());
  }
  const streamLastTimestamp = new Map();
  let timestampOrder = true;
  let maxTimestampMs = -Infinity;
  let walk;
  try {
    walk = walkBlocks(replay, (block, chunk) => {
      const previous = streamLastTimestamp.get(chunk.stream_tag);
      if (previous !== undefined && block.timestamp_ms < previous) timestampOrder = false;
      streamLastTimestamp.set(chunk.stream_tag, block.timestamp_ms);
      maxTimestampMs = Math.max(maxTimestampMs, block.timestamp_ms);
      const packet = packetStats.get(block.packet_id);
      if (packet) updatePacketStats(packet, block);
    }, { strict: true, includeStreams: [1, 2, 3] });
  } catch (error) {
    walk = { block_count: 0, errors: [{ code: error.code || 'STRICT_WALK_FAILURE', message: error.message }] };
  }
  const players = normalizePlayers(replay);
  const durationMs = replay.tail.metadata.gameLength ?? null;
  const durationBound = Number.isFinite(durationMs)
    && maxTimestampMs <= durationMs + 120_000;
  const row = {
    replay: path.basename(filePath),
    path: path.resolve(filePath),
    sha256: replay.source_sha256,
    game_version: replay.header.version,
    header: replay.header.magic === 'RIOT' ? 'PASS' : 'FAIL',
    metadata: durationMs !== null ? 'PASS' : 'FAIL',
    duration_ms: durationMs,
    chunk_count: replay.chunks.length,
    game_chunks: replay.chunks.filter((chunk) => chunk.stream_tag === 1).length,
    keyframes: replay.chunks.filter((chunk) => chunk.stream_tag === 2).length,
    start_keyframes: replay.chunks.filter((chunk) => chunk.stream_tag === 3).length,
    zstd: walk.errors.length === 0 ? 'PASS' : 'FAIL',
    block_count: walk.block_count,
    block_framing: walk.errors.length === 0 ? 'PASS' : 'FAIL',
    framing_errors: walk.errors.length,
    timestamp_order: timestampOrder ? 'PASS' : 'FAIL',
    maximum_timestamp_ms: Number.isFinite(maxTimestampMs) ? maxTimestampMs : null,
    duration_bound: durationBound ? 'PASS' : 'FAIL',
    metadata_roster_count: players.length,
    metadata_roster: players.length === 10 ? 'PASS' : 'FAIL',
    participant_packet_mapping: 'UNKNOWN',
    elapsed_ms: Number((performance.now() - started).toFixed(3)),
  };
  return { row, packetStats };
}

function mergePacketStats(target, source) {
  target.count += source.count;
  target.champion_param_count += source.champion_param_count;
  for (const [length, count] of source.payload_lengths) {
    target.payload_lengths.set(length, (target.payload_lengths.get(length) || 0) + count);
  }
}

function boundedGameWalk(replay, limitMs) {
  assertGameChunkChronology(replay);
  return boundedGameWalkAfterChronologyCheck(replay, limitMs);
}

function assertGameChunkChronology(replay) {
  let previousTimestampMs = null;
  walkBlocks(replay, (block) => {
    if (previousTimestampMs !== null && block.timestamp_ms < previousTimestampMs) {
      throw new Error(`non-monotonic game-chunk timestamp: ${block.timestamp_ms} < ${previousTimestampMs}`);
    }
    previousTimestampMs = block.timestamp_ms;
  }, { strict: true, includeStreams: [1] });
}

function boundedGameWalkAfterChronologyCheck(replay, limitMs) {
  let blockCount = 0;
  let chunkCount = 0;
  let maximumTimestampMs = null;
  outer: for (const chunk of replay.chunks) {
    if (chunk.stream_tag !== 1) continue;
    const body = decompressChunk(replay.buffer, chunk);
    const state = { timestamp: 0, packet_id: 0, param: 0 };
    let cursor = 0;
    chunkCount += 1;
    while (cursor < body.length) {
      const block = parseBlockAt(body, cursor, state);
      if (block.timestamp_ms > limitMs) break outer;
      blockCount += 1;
      maximumTimestampMs = block.timestamp_ms;
      cursor = block.next_offset;
    }
  }
  return { blockCount, chunkCount, maximumTimestampMs };
}

function fastpathRun(files, limitMs) {
  const started = performance.now();
  let blocks = 0;
  let chunks = 0;
  for (const filePath of files) {
    const replay = parseReplayFile(filePath);
    const result = boundedGameWalkAfterChronologyCheck(replay, limitMs);
    blocks += result.blockCount;
    chunks += result.chunkCount;
  }
  return {
    elapsed_ms: Number((performance.now() - started).toFixed(3)),
    blocks,
    game_chunks_decompressed: chunks,
  };
}

function runFastpath(newFiles, oldFiles) {
  for (const filePath of new Set([...newFiles, ...oldFiles])) {
    assertGameChunkChronology(parseReplayFile(filePath));
  }
  const rows = [];
  for (const limitMs of [130_000, 480_000]) {
    for (const sampleSize of [4, 8, 10]) {
      const cohorts = [
        [OLD_VALIDATED_BUILD, oldFiles.slice(0, sampleSize)],
        [REPLAY_VERSION, newFiles.slice(0, sampleSize)],
      ];
      const pair = [];
      for (const [build, files] of cohorts) {
        if (files.length !== sampleSize) continue;
        const result = fastpathRun(files, limitMs);
        pair.push({
          build,
          limit: limitMs === 130_000 ? '2:10' : '8:00',
          limit_ms: limitMs,
          sample_games: sampleSize,
          method: 'BOUNDED_GAME_CHUNK_STRICT_TRAVERSAL',
          elapsed_ms: result.elapsed_ms,
          elapsed_ms_per_game: Number((result.elapsed_ms / sampleSize).toFixed(3)),
          blocks: result.blocks,
          game_chunks_decompressed: result.game_chunks_decompressed,
          comparison_to_old_ratio: null,
          same_order_of_magnitude: build === OLD_VALIDATED_BUILD ? 'BASELINE' : null,
        });
      }
      const baseline = pair.find((row) => row.build === OLD_VALIDATED_BUILD);
      const current = pair.find((row) => row.build === REPLAY_VERSION);
      if (baseline && current) {
        const ratio = current.elapsed_ms_per_game / baseline.elapsed_ms_per_game;
        current.comparison_to_old_ratio = Number(ratio.toFixed(3));
        current.same_order_of_magnitude = ratio >= 0.1 && ratio <= 10 ? 'PASS' : 'FAIL';
      }
      rows.push(...pair);
    }
  }
  return rows;
}

function runtimeVersion(command, args) {
  try {
    return execFileSync(command, args, { encoding: 'utf8' }).trim();
  } catch (error) {
    return `UNAVAILABLE: ${error.message}`;
  }
}

async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.help) {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  const newRoot = path.resolve(options.newReplays);
  const oldRoot = path.resolve(options.oldReplays);
  const runtimeImage = path.resolve(options.runtimeImage);
  const output = path.resolve(options.output);
  ensureDir(output);
  ensureDir(path.join(output, 'trajectory_sanity'));

  const runtimeHash = await sha256File(runtimeImage);
  if (runtimeHash !== RUNTIME_IMAGE_SHA256) {
    throw new Error(`runtime image SHA mismatch: expected ${RUNTIME_IMAGE_SHA256}, got ${runtimeHash}`);
  }
  const newFiles = listRoflFiles(newRoot);
  const oldFiles = listRoflFiles(oldRoot);
  if (newFiles.length < options.sampleCount) {
    throw new Error(`need ${options.sampleCount} new replays, found ${newFiles.length}`);
  }
  const oldBaselineFiles = selectFilesForBuild(oldFiles, OLD_VALIDATED_BUILD, 10);
  if (oldBaselineFiles.length < 10) {
    throw new Error(`need 10 exact ${OLD_VALIDATED_BUILD} replays for fastpath baseline, found ${oldBaselineFiles.length}`);
  }
  const selectedFiles = newFiles.slice(0, options.sampleCount);
  const selected = new Set(selectedFiles.map((filePath) => path.resolve(filePath)));

  const inventory = newFiles.map((filePath) => inventoryReplay(filePath, selected.has(path.resolve(filePath))));
  const builds = [...new Set(inventory.map((row) => row.game_version))].sort();
  if (builds.length !== 1 || builds[0] !== REPLAY_VERSION) {
    throw new Error(`new replay directory must contain only ${REPLAY_VERSION}; found ${builds.join(', ')}`);
  }
  const uniqueHashes = new Set(inventory.map((row) => row.sha256_before));

  const aggregate = new Map();
  for (const packetId of [...Object.values(CANDIDATE_IDS), ...OLD_SEMANTIC_IDS]) {
    aggregate.set(packetId, emptyPacketStats());
  }
  const coreRows = [];
  const perReplayCandidates = [];
  for (const filePath of selectedFiles) {
    const { row, packetStats } = validateCoreReplay(filePath);
    coreRows.push(row);
    for (const [packetId, stats] of packetStats) mergePacketStats(aggregate.get(packetId), stats);
    perReplayCandidates.push({
      replay: row.replay,
      game_version: row.game_version,
      hero_path_candidate_packet: formatOpcode(CANDIDATE_IDS.hero_path),
      hero_path_candidate_count: packetStats.get(CANDIDATE_IDS.hero_path).count,
      hero_path_payload_shapes: packetStats.get(CANDIDATE_IDS.hero_path).payload_lengths.size,
      level_candidate_packet: formatOpcode(CANDIDATE_IDS.level_transition),
      level_candidate_count: packetStats.get(CANDIDATE_IDS.level_transition).count,
      ward_candidate_packet: formatOpcode(CANDIDATE_IDS.ward_spawn),
      ward_candidate_count: packetStats.get(CANDIDATE_IDS.ward_spawn).count,
      damage_candidate_packet: formatOpcode(CANDIDATE_IDS.hero_damage),
      damage_candidate_count: packetStats.get(CANDIDATE_IDS.hero_damage).count,
    });
  }

  for (const row of inventory) {
    row.sha256_after = await sha256File(row.path);
    row.original_unchanged = row.sha256_before === row.sha256_after ? 'YES' : 'NO';
  }
  const sourceIntegrity = inventory.every((row) => row.original_unchanged === 'YES');
  const totalSize = inventory.reduce((sum, row) => sum + row.file_size, 0);
  const oldOpcodeRows = OLD_SEMANTIC_IDS.map((packetId) => ({
    packet_id: formatOpcode(packetId),
    observed_count: aggregate.get(packetId).count,
  }));
  const oldOpcodesAbsent = oldOpcodeRows.every((row) => row.observed_count === 0);

  const levelStats = aggregate.get(CANDIDATE_IDS.level_transition);
  const wardStats = aggregate.get(CANDIDATE_IDS.ward_spawn);
  const damageStats = aggregate.get(CANDIDATE_IDS.hero_damage);
  const pathStats = aggregate.get(CANDIDATE_IDS.hero_path);

  writeCsv(path.join(output, 'new_build_replay_inventory.csv'), inventory, [
    'path', 'sha256_before', 'sha256_after', 'original_unchanged', 'file_size',
    'creation_time', 'modified_time', 'game_version', 'duration_ms', 'selected_for_validation',
  ]);
  writeCsv(path.join(output, 'core_compatibility.csv'), coreRows);
  writeCsv(path.join(output, 'level_transition_new_build_validation.csv'), [{
    game_version: REPLAY_VERSION,
    candidate_packet: formatOpcode(CANDIDATE_IDS.level_transition),
    profile_status: SEMANTIC_PROFILE_REGISTRY.level_transition.status,
    enabled: 'NO',
    constructor_rva: `0x${SEMANTIC_PROFILE_REGISTRY.level_transition.constructor_rva.toString(16)}`,
    vtable_rva: `0x${SEMANTIC_PROFILE_REGISTRY.level_transition.vtable_rva.toString(16)}`,
    deserialize_rva: `0x${SEMANTIC_PROFILE_REGISTRY.level_transition.deserialize_rva.toString(16)}`,
    sample_games: selectedFiles.length,
    observed_candidate_packets: levelStats.count,
    champion_param_packets: levelStats.champion_param_count,
    payload_length_distribution: topCounts(levelStats.payload_lengths),
    transition_occurrence: 'NOT_VERIFIED',
    entity_mapping: 'NOT_VERIFIED',
    timestamp: 'FRAMING_VERIFIED_ONLY',
    decoded_events: 0,
    conflicts: null,
    anomaly: 'REPLAY_ROUTE_SEMANTICS_AND_LEVEL_SEQUENCE_UNPROVEN',
  }]);
  writeJson(path.join(output, 'level_mapping_new_build.json'), {
    schema_version: 1,
    game_version: REPLAY_VERSION,
    status: 'LEVEL_AFTER_NEW_BUILD_NEEDS_EXTERNAL_ANCHOR',
    evidence_grade: 'UNAVAILABLE',
    candidate_packet: formatOpcode(CANDIDATE_IDS.level_transition),
    old_mapping_inherited: false,
    mapping: {},
    required_columns: [],
    sample_games: selectedFiles.length,
    participants: 0,
    verified_events: 0,
    conflicts: null,
    blocker: SEMANTIC_PROFILE_REGISTRY.level_transition.blocker,
  });
  writeCsv(path.join(output, 'ward_compatibility.csv'), [{
    game_version: REPLAY_VERSION,
    candidate_packet: formatOpcode(CANDIDATE_IDS.ward_spawn),
    status: 'CANDIDATE',
    enabled: 'NO',
    sample_games: selectedFiles.length,
    observed_candidate_packets: wardStats.count,
    payload_shape_count: wardStats.payload_lengths.size,
    payload_length_distribution: topCounts(wardStats.payload_lengths),
    decoder: 'NOT_VERIFIED',
    spawn_timestamp: 'FRAMING_VERIFIED_ONLY',
    coordinate: 'UNAVAILABLE',
    owner_entity: 'UNAVAILABLE',
    ward_type: 'UNAVAILABLE',
    participant_team_mapping: 'UNAVAILABLE',
    verdict: 'NOT_YET_VALIDATED_ON_NEW_BUILD',
  }]);
  writeCsv(path.join(output, 'damage_death_compatibility.csv'), [
    {
      capability: 'HERO_DAMAGE', game_version: REPLAY_VERSION,
      candidate_packet: formatOpcode(CANDIDATE_IDS.hero_damage), status: 'CANDIDATE',
      enabled: 'NO', sample_games: selectedFiles.length,
      observed_candidate_packets: damageStats.count,
      payload_shape_count: damageStats.payload_lengths.size,
      source: 'UNAVAILABLE', target: 'UNAVAILABLE', amount: 'UNAVAILABLE',
      timestamp: 'FRAMING_VERIFIED_ONLY', verdict: 'NOT_YET_VALIDATED_ON_NEW_BUILD',
    },
    {
      capability: 'HERO_DEATH', game_version: REPLAY_VERSION,
      candidate_packet: null, status: 'UNAVAILABLE', enabled: 'NO',
      sample_games: selectedFiles.length, observed_candidate_packets: null,
      payload_shape_count: null, source: null, target: 'UNAVAILABLE', amount: null,
      timestamp: 'UNAVAILABLE', verdict: 'NOT_YET_VALIDATED_ON_NEW_BUILD',
    },
  ]);

  const fastpathRows = runFastpath(selectedFiles, oldBaselineFiles);
  writeCsv(path.join(output, 'fastpath_sanity.csv'), fastpathRows);
  writeCsv(path.join(output, 'trajectory_sanity', 'candidate_hero_path_packets.csv'),
    perReplayCandidates.slice(0, 5));
  fs.writeFileSync(path.join(output, 'trajectory_sanity', 'README.md'), [
    '# Hero Path trajectory sanity',
    '',
    'No trajectory image is emitted for build `16.16.805.0442`.',
    '',
    'Packet `0x00f6` is an exact-build structural candidate only. The current gate did not',
    'complete a successful semantic payload decode, entity mapping, waypoint validation,',
    'or coordinate calibration. Rendering DETAILS positions or candidate bytes as a ROFL',
    'trajectory would overstate the evidence. `candidate_hero_path_packets.csv` records the',
    'five bounded packet-count/shape sanity inputs without assigning behavior or coordinates.',
    '',
    'Status: `HERO_PATH = UNKNOWN`.',
    '',
  ].join('\n'), 'utf8');

  writeJson(path.join(output, 'packet_profile_registry.json'), {
    schema_version: 1,
    replay_version: REPLAY_VERSION,
    runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    container_profile: CONTAINER_PROFILE,
    semantic_profiles: SEMANTIC_PROFILE_REGISTRY,
  });
  writeJson(path.join(output, 'source_integrity.json'), {
    schema_version: 1,
    replay_count: inventory.length,
    unique_sha256_count: uniqueHashes.size,
    status: sourceIntegrity ? 'PASS' : 'FAIL',
    original_rofl_unchanged: sourceIntegrity,
  });
  writeJson(path.join(output, 'core_compatibility_summary.json'), {
    schema_version: 1,
    old_validated_build: OLD_VALIDATED_BUILD,
    new_replay_builds: builds,
    newest_build: REPLAY_VERSION,
    replay_found: inventory.length,
    unique: uniqueHashes.size,
    used_for_validation: selectedFiles.length,
    total_size_bytes: totalSize,
    header_pass: coreRows.every((row) => row.header === 'PASS'),
    chunks_pass: coreRows.every((row) => row.chunk_count > 0),
    zstd_pass: coreRows.every((row) => row.zstd === 'PASS'),
    block_framing_pass: coreRows.every((row) => row.block_framing === 'PASS'),
    timestamp_order_pass: coreRows.every((row) => row.timestamp_order === 'PASS'),
    framing_errors: coreRows.reduce((sum, row) => sum + row.framing_errors, 0),
    block_count: coreRows.reduce((sum, row) => sum + row.block_count, 0),
    metadata_roster_10_of_10: coreRows.every((row) => row.metadata_roster_count === 10),
    participant_packet_mapping: 'UNKNOWN',
    old_semantic_opcodes_absent_in_selected_sample: oldOpcodesAbsent,
    old_semantic_opcode_counts_in_selected_sample: oldOpcodeRows,
    source_hash_integrity: sourceIntegrity ? 'PASS' : 'FAIL',
    downstream_release_gate: 'NEW_BUILD_CORE_COMPATIBILITY_BLOCKED',
  });
  writeJson(path.join(output, 'environment.json'), {
    schema_version: 1,
    captured_at: new Date().toISOString(),
    platform: process.platform,
    os_release: os.release(),
    os_arch: os.arch(),
    cpu_model: os.cpus()[0]?.model ?? null,
    cpu_count: os.cpus().length,
    total_memory_bytes: os.totalmem(),
    node: process.version,
    python: runtimeVersion('python', ['--version']),
    native_zstd: typeof require('node:zlib').zstdDecompressSync === 'function',
    validator: path.resolve(__filename),
    new_replay_root: newRoot,
    old_replay_root: oldRoot,
    old_fastpath_files: oldBaselineFiles.map((filePath) => path.resolve(filePath)),
    runtime_image: runtimeImage,
    runtime_image_sha256: runtimeHash,
    sample_selection: `lexicographically first ${options.sampleCount} of ${newFiles.length}`,
    fastpath_selection: 'lexicographically first 4/8/10 per exact build',
  });

  process.stdout.write(`${JSON.stringify({
    status: 'NEW_BUILD_CORE_COMPATIBILITY_BLOCKED',
    build: REPLAY_VERSION,
    found: inventory.length,
    unique: uniqueHashes.size,
    validated: selectedFiles.length,
    block_count: coreRows.reduce((sum, row) => sum + row.block_count, 0),
    framing_errors: coreRows.reduce((sum, row) => sum + row.framing_errors, 0),
    old_semantic_opcodes_absent_in_selected_sample: oldOpcodesAbsent,
    source_integrity: sourceIntegrity ? 'PASS' : 'FAIL',
    output,
  }, null, 2)}\n`);
}

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
  });
}

module.exports = {
  parseArgs,
  listRoflFiles,
  selectFilesForBuild,
  validateCoreReplay,
  assertGameChunkChronology,
  boundedGameWalk,
  fastpathRun,
};

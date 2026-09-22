#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { parseReplayFile, walkBlocks } = require('../src/rofl');
const {
  EXACT_BUILD,
  EXACT_IMAGE_SHA256,
  PRELUDE_PACKET_ID,
  ENVELOPE_PACKET_ID,
  RUNTIME_LAYOUT,
  analyzeRoutePair,
  validateRuntimeIdentity,
} = require('../src/route_pair_01c2_0473_batch_audit');
const { SAFE_REPLAYS } = require('../src/next_priority_wave_v2');

const SAFE_REPLAY_PATHS = Object.freeze(Object.keys(SAFE_REPLAYS));

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
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

function normalizedPath(value) {
  return path.basename(value).toLowerCase();
}

function ensureDedicatedOutput(value) {
  const resolved = rejectHoldout(value);
  const normalized = resolved.replaceAll('\\', '/').toLowerCase();
  if (!normalized.includes('/artifacts/full_semantic_deep_recovery_v2/unknown_mining/route_pair_01c2_0473_')) {
    throw new Error('output must be a dedicated route_pair_01c2_0473_* artifact');
  }
  return resolved;
}

function parseArgs(argv) {
  const options = {
    build: EXACT_BUILD,
    replayFiles: [],
    registryPath: 'artifacts/full_semantic_baseline_v1/observed_route_registry.json',
    callbackMapPath: 'artifacts/hero_combat_state_v2/runtime/observed_packet_callback_route_map_16_16.json',
    runtimeTracePath: 'artifacts/hero_combat_state_v2/runtime/hero_combat_state_runtime_trace_16_16.json',
    rawProfilerPath: 'artifacts/hero_combat_state_v2/profiler/high_frequency_raw_profiles_latest_four_v1_2.json',
    runtimeImagePath: 'artifacts/new_build_rofl_compatibility_gate_v1/runtime/league_16.16.805.0442.memory.bin',
    runtimeImmediateScanPath: 'artifacts/full_semantic_deep_recovery_v2/unknown_mining/route_pair_01c2_0473_runtime_immediate_scan.json',
    runtimeDisassemblyPath: 'artifacts/full_semantic_deep_recovery_v2/unknown_mining/route_pair_01c2_0473_runtime_disassembly.json',
    outputPath: 'artifacts/full_semantic_deep_recovery_v2/unknown_mining/route_pair_01c2_0473_batch_audit.json',
  };
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    if (option === '--build') options.build = requireValue(argv, ++index, option);
    else if (option === '--replay') options.replayFiles.push(rejectHoldout(requireValue(argv, ++index, option)));
    else if (option === '--registry') options.registryPath = rejectHoldout(requireValue(argv, ++index, option));
    else if (option === '--callback-map') options.callbackMapPath = rejectHoldout(requireValue(argv, ++index, option));
    else if (option === '--runtime-trace') options.runtimeTracePath = rejectHoldout(requireValue(argv, ++index, option));
    else if (option === '--raw-profiler') options.rawProfilerPath = rejectHoldout(requireValue(argv, ++index, option));
    else if (option === '--runtime-image') options.runtimeImagePath = rejectHoldout(requireValue(argv, ++index, option));
    else if (option === '--runtime-immediate-scan') options.runtimeImmediateScanPath = rejectHoldout(requireValue(argv, ++index, option));
    else if (option === '--runtime-disassembly') options.runtimeDisassemblyPath = rejectHoldout(requireValue(argv, ++index, option));
    else if (option === '--output') options.outputPath = ensureDedicatedOutput(requireValue(argv, ++index, option));
    else throw new Error(`unknown option: ${option}`);
  }
  if (options.build !== EXACT_BUILD) throw new Error(`exact build ${EXACT_BUILD} is required`);
  if (!options.replayFiles.length) throw new Error('all four explicit repeatable --replay arguments are required');
  const expected = new Set(SAFE_REPLAY_PATHS.map(normalizedPath));
  const actual = options.replayFiles.map(normalizedPath);
  if (new Set(actual).size !== actual.length) throw new Error('duplicate --replay path is forbidden');
  if (actual.length !== expected.size || actual.some((value) => !expected.has(value))) {
    throw new Error('only the four explicitly governed safe latest-four Replay identities are accepted');
  }
  options.outputPath = ensureDedicatedOutput(options.outputPath);
  return options;
}

function loadJson(filePath, exactBuildField = null) {
  const bytes = fs.readFileSync(filePath);
  const value = JSON.parse(bytes);
  if (exactBuildField && value[exactBuildField] !== EXACT_BUILD) {
    throw new Error(`${filePath}: exact-build mismatch at ${exactBuildField}`);
  }
  return { bytes, value, sha256: sha256(bytes) };
}

function compactCallbackRoute(row) {
  return {
    packet_id: row.packet_id,
    packet_id_hex: row.packet_id_hex,
    observed_count: row.observed_count,
    existing_decode_status: row.existing_decode_status,
    callback_mapping_status: row.callback_mapping_status,
    callback_names: row.callback_names,
    factory_packet_count_on_makefunction_surface: row.factory_packets.length,
  };
}

function compactProfilerRoute(row) {
  return {
    packet_id: row.packet_id,
    packet_discriminator: row.packet_discriminator,
    build: row.build,
    observed_record_count: row.observed_record_count,
    profiled_record_count: row.profiled_record_count,
    sample_rate: row.sample_rate,
    observed_max_payload_length: row.observed_max_payload_length,
    scanned_max_payload_length: row.scanned_max_payload_length,
    payload_truncated_by_policy: row.payload_truncated_by_policy,
    semantic_claim: row.known_route_semantics ?? null,
  };
}

function quoted(value) {
  return `"${String(value).replaceAll('"', '\\"')}"`;
}

function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  const registrySource = loadJson(options.registryPath, 'exact_build');
  const callbackSource = loadJson(options.callbackMapPath, 'build');
  const runtimeTraceSource = loadJson(options.runtimeTracePath, 'build');
  const rawProfilerSource = loadJson(options.rawProfilerPath, 'target_build');
  const immediateScanSource = loadJson(options.runtimeImmediateScanPath);
  const disassemblySource = loadJson(options.runtimeDisassemblyPath);
  const runtimeImage = fs.readFileSync(options.runtimeImagePath);
  const runtimeImageSha256 = sha256(runtimeImage);
  if (runtimeImageSha256 !== EXACT_IMAGE_SHA256) throw new Error('runtime image SHA-256 mismatch');
  if (runtimeTraceSource.value.image?.sha256 !== EXACT_IMAGE_SHA256) throw new Error('runtime trace image identity mismatch');

  const expectedCounts = {};
  for (const packetId of [PRELUDE_PACKET_ID, ENVELOPE_PACKET_ID]) {
    const route = registrySource.value.routes.find((row) => row.packet_id === packetId);
    if (!route) throw new Error(`registry is missing route 0x${packetId.toString(16)}`);
    expectedCounts[packetId] = route.observed.count;
  }
  const callbackRows = [PRELUDE_PACKET_ID, ENVELOPE_PACKET_ID].map((packetId) => {
    const row = callbackSource.value.routes.find((candidate) => candidate.packet_id === packetId);
    if (!row) throw new Error(`callback map is missing route 0x${packetId.toString(16)}`);
    return compactCallbackRoute(row);
  });
  const profilerRows = [PRELUDE_PACKET_ID, ENVELOPE_PACKET_ID].map((packetId) => {
    const row = rawProfilerSource.value.route_profiles.find((candidate) => candidate.packet_id === packetId);
    if (!row) throw new Error(`raw profiler is missing route 0x${packetId.toString(16)}`);
    return compactProfilerRoute(row);
  });
  const factoryTrace = runtimeTraceSource.value.shared_runtime?.packet_factory;
  if (factoryTrace?.switch_rva !== RUNTIME_LAYOUT.packet_factory.switch_rva
      || factoryTrace?.jump_table_rva !== RUNTIME_LAYOUT.packet_factory.jump_table_rva) {
    throw new Error('runtime trace packet factory does not match recovered exact factory');
  }

  const events = [];
  const replays = [];
  for (const replayPath of options.replayFiles) {
    const replay = parseReplayFile(replayPath);
    if (replay.header.version !== EXACT_BUILD) throw new Error(`${replayPath} has build ${replay.header.version}`);
    if (replay.source_sha256 !== SAFE_REPLAYS[path.basename(replayPath)]) {
      throw new Error(`${replayPath} is outside the hash-bound latest-four Replay set`);
    }
    const before = events.length;
    let globalBlockIndex = 0;
    let previousBlock = null;
    let selectedAwaitingNext = null;
    const walk = walkBlocks(replay, (block, chunk) => {
      if (selectedAwaitingNext !== null) {
        selectedAwaitingNext.next_global_packet_id = block.packet_id;
        selectedAwaitingNext.next_global_timestamp_ms = block.timestamp_ms;
        selectedAwaitingNext.next_global_timestamp_seconds_exact = block.timestamp;
        selectedAwaitingNext = null;
      }
      if ([PRELUDE_PACKET_ID, ENVELOPE_PACKET_ID].includes(block.packet_id)) {
        const event = {
          replay_version: replay.header.version,
          replay_sha256: replay.source_sha256,
          replay_label: path.basename(replay.source_path, path.extname(replay.source_path)),
          replay_time_ms: block.timestamp_ms,
          replay_time_seconds_exact: block.timestamp,
          global_block_index: globalBlockIndex,
          packet_id: block.packet_id,
          raw_param: block.param >>> 0,
          chunk_index: chunk.index,
          chunk_stream: chunk.stream,
          decompressed_block_offset: block.offset,
          payload_length: block.payload_length,
          raw_payload_hex: block.payload.toString('hex'),
          payload_buffer: Buffer.from(block.payload),
          previous_global_packet_id: previousBlock?.packet_id ?? null,
          previous_global_timestamp_ms: previousBlock?.timestamp_ms ?? null,
          next_global_packet_id: null,
          next_global_timestamp_ms: null,
          next_global_timestamp_seconds_exact: null,
        };
        events.push(event);
        selectedAwaitingNext = event;
      }
      previousBlock = { packet_id: block.packet_id, timestamp_ms: block.timestamp_ms };
      globalBlockIndex += 1;
    }, { includeStreams: [1, 2, 3], strict: true });
    if (walk.errors.length) throw new Error(`${replayPath} parser errors: ${walk.errors.length}`);
    replays.push({
      path: replay.source_path,
      replay_label: path.basename(replay.source_path, path.extname(replay.source_path)),
      replay_sha256: replay.source_sha256,
      build: replay.header.version,
      full_block_count: walk.block_count,
      selected_count: events.length - before,
    });
  }

  const runtimeIdentity = validateRuntimeIdentity(runtimeImage);
  if (!runtimeIdentity.all_checks_pass) throw new Error('exact runtime identity validation failed');
  const outerCountTable = runtimeImage.subarray(
    RUNTIME_LAYOUT.route_0473.outer_count_table_rva,
    RUNTIME_LAYOUT.route_0473.outer_count_table_rva + 256,
  );
  const report = analyzeRoutePair(events, {
    expectedCounts,
    outerCountTable,
    runtimeIdentity,
    staticSidecarCrosscheck: {
      callback_routes: callbackRows,
      makefunction_surface_is_static_negative_only: callbackRows.every((row) =>
        row.callback_mapping_status === 'UNMAPPED_ON_MAKEFUNCTION_CALLBACK_REGISTRATION_SURFACE'),
      independently_recovered_factory_identity: true,
    },
    rawProfilerCrosscheck: profilerRows,
  });

  const modulePath = path.resolve(__dirname, '../src/route_pair_01c2_0473_batch_audit.js');
  const commandParts = [
    'node', quoted(path.resolve(__filename)),
    ...options.replayFiles.flatMap((replayPath) => ['--replay', quoted(replayPath)]),
    '--output', quoted(options.outputPath),
  ];
  report.input = {
    replay_count: replays.length,
    replays,
    sources: {
      observed_route_registry: { path: path.resolve(options.registryPath), sha256: registrySource.sha256 },
      callback_route_map: { path: path.resolve(options.callbackMapPath), sha256: callbackSource.sha256 },
      runtime_trace: { path: path.resolve(options.runtimeTracePath), sha256: runtimeTraceSource.sha256 },
      raw_profiler: { path: path.resolve(options.rawProfilerPath), sha256: rawProfilerSource.sha256 },
      runtime_image: { path: path.resolve(options.runtimeImagePath), sha256: runtimeImageSha256, size: runtimeImage.length },
      runtime_immediate_scan: { path: path.resolve(options.runtimeImmediateScanPath), sha256: immediateScanSource.sha256 },
      runtime_disassembly: { path: path.resolve(options.runtimeDisassemblyPath), sha256: disassemblySource.sha256 },
      audit_script: { path: path.resolve(__filename), sha256: sha256(fs.readFileSync(__filename)) },
      audit_module: { path: modulePath, sha256: sha256(fs.readFileSync(modulePath)) },
    },
  };
  report.reproduction = {
    audit_command: commandParts.join(' '),
    test_command: `node --test ${quoted(path.resolve(__dirname, '../test/route_pair_01c2_0473_batch_audit.test.js'))}`,
    runtime_immediate_scan_command: `python scripts/inspect_runtime_image.py --image ${quoted(path.resolve(options.runtimeImagePath))} --immediate-value 0x1c2 --immediate-value 0x473 --context-instructions 16 --output ${quoted(path.resolve(options.runtimeImmediateScanPath))}`,
    runtime_disassembly_command: `python scripts/inspect_runtime_image.py --image ${quoted(path.resolve(options.runtimeImagePath))} --rva 0x00e8b0a0 --rva 0x00f66dd0 --rva 0x00e7a930 --rva 0x00f5e550 --rva 0x00edfe07 --rva 0x00ee8831 --size 0x400 --output ${quoted(path.resolve(options.runtimeDisassemblyPath))}`,
  };

  fs.mkdirSync(path.dirname(options.outputPath), { recursive: true });
  const text = `${JSON.stringify(report, null, 2)}\n`;
  fs.writeFileSync(options.outputPath, text, 'utf8');
  const outputSha256 = sha256(text);
  const hashPath = options.outputPath.replace(/\.json$/i, '.sha256.json');
  const hashRecord = {
    schema: 'ROUTE_PAIR_01C2_0473_ARTIFACT_HASH_V1',
    artifact_path: path.resolve(options.outputPath),
    artifact_sha256: outputSha256,
    artifact_size: Buffer.byteLength(text),
    exact_build: EXACT_BUILD,
    all_structural_repurpose_checks_pass: report.validations.all_structural_repurpose_checks_pass,
    decisions: {
      route_decisions: report.route_decisions.map((row) => ({ packet_discriminator: row.packet_discriminator, decision: row.decision })),
      capability_decisions: report.capability_decisions.map((row) => ({ capability: row.capability, decision: row.decision })),
      domain_decisions: report.domain_decisions.map((row) => ({ domain: row.domain, decision: row.decision })),
    },
  };
  fs.writeFileSync(hashPath, `${JSON.stringify(hashRecord, null, 2)}\n`, 'utf8');
  const summary = {
    output: path.resolve(options.outputPath),
    sha256: outputSha256,
    hash_record: path.resolve(hashPath),
    counts: report.counts,
    relationship: report.relationship,
    validations: report.validations,
    route_decisions: report.route_decisions,
    capability_decisions: report.capability_decisions,
    domain_decisions: report.domain_decisions,
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

module.exports = { SAFE_REPLAY_PATHS, main, parseArgs };

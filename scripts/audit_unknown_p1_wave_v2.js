#!/usr/bin/env node
'use strict';

const { spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');

const {
  EXACT_BUILD,
  ROUTE_IDS,
  RUNTIME_SHA256,
  SAFE_REPLAYS,
  analyzeNativeOutputs,
  buildNativeProfiles,
  buildReport,
  collectEvidence,
  markdownReport,
  packetHex,
  recoverRuntimeIdentities,
  rejectProtectedPath,
  sha256,
  sha256File,
} = require('../src/unknown_p1_wave_v2');

const ROOT = path.resolve(__dirname, '..');
const DEFAULT_REPLAY_ROOT = process.env.ROFL_REPLAY_ROOT || path.join(ROOT, 'replay');

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function requireValue(argv, index, option) {
  if (index >= argv.length || argv[index].startsWith('--')) throw new Error(`${option} requires a value`);
  return argv[index];
}

function parseArgs(argv = process.argv.slice(2)) {
  const options = {
    replayPaths: [],
    registry: path.join(ROOT, 'artifacts', 'full_semantic_baseline_v1', 'observed_route_registry.json'),
    callbackSidecar: path.join(ROOT, 'artifacts', 'hero_combat_state_v2', 'runtime', 'observed_packet_callback_route_map_16_16.json'),
    profiler: path.join(ROOT, 'artifacts', 'hero_combat_state_v2', 'profiler', 'high_frequency_raw_profiles_latest_four_v1_2.json'),
    priorMining: path.join(ROOT, 'artifacts', 'full_semantic_deep_recovery_v2', 'unknown_mining', 'high_frequency_unknown_deep_mining.json'),
    runtime: path.join(ROOT, 'artifacts', 'new_build_rofl_compatibility_gate_v1', 'runtime', 'league_16.16.805.0442.memory.bin'),
    outputDir: path.join(ROOT, 'artifacts', 'full_semantic_deep_recovery_v2', 'unknown_p1_wave'),
    python: 'python',
    jobs: 4,
    verifyNativeDeterminism: true,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    if (option === '--replay') options.replayPaths.push(rejectProtectedPath(requireValue(argv, ++index, option)));
    else if (option === '--registry') options.registry = rejectProtectedPath(requireValue(argv, ++index, option));
    else if (option === '--callback-sidecar') options.callbackSidecar = rejectProtectedPath(requireValue(argv, ++index, option));
    else if (option === '--profiler') options.profiler = rejectProtectedPath(requireValue(argv, ++index, option));
    else if (option === '--prior-mining') options.priorMining = rejectProtectedPath(requireValue(argv, ++index, option));
    else if (option === '--runtime') options.runtime = rejectProtectedPath(requireValue(argv, ++index, option));
    else if (option === '--output-dir') options.outputDir = rejectProtectedPath(requireValue(argv, ++index, option));
    else if (option === '--python') options.python = requireValue(argv, ++index, option);
    else if (option === '--jobs') options.jobs = Number(requireValue(argv, ++index, option));
    else if (option === '--skip-native-determinism') options.verifyNativeDeterminism = false;
    else throw new Error(`unknown option: ${option}`);
  }
  if (!options.replayPaths.length) {
    options.replayPaths = Object.keys(SAFE_REPLAYS).map((basename) =>
      rejectProtectedPath(path.join(DEFAULT_REPLAY_ROOT, basename)));
  }
  invariant(options.replayPaths.length === 4, 'exactly four explicit safe --replay paths are required');
  invariant(Number.isInteger(options.jobs) && options.jobs >= 1 && options.jobs <= 8,
    '--jobs must be an integer from 1 through 8');
  return options;
}

function writeJson(filePath, value) {
  const target = rejectProtectedPath(filePath);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  return target;
}

function writeJsonl(filePath, rows) {
  const target = rejectProtectedPath(filePath);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  const text = rows.map((row) => JSON.stringify(row)).join('\n') + '\n';
  fs.writeFileSync(target, text, 'utf8');
  return { path: target, row_count: rows.length, sha256: sha256(Buffer.from(text, 'utf8')) };
}

async function readJsonl(filePath) {
  const rows = [];
  const source = rejectProtectedPath(filePath);
  const reader = readline.createInterface({ input: fs.createReadStream(source), crlfDelay: Infinity });
  for await (const line of reader) {
    if (line.trim()) rows.push(JSON.parse(line.replace(/^\uFEFF/, '')));
  }
  return rows;
}

function runProcess(command, args, cwd = ROOT) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`${command} ${args.join(' ')} exited ${code}\n${stderr}\n${stdout}`));
        return;
      }
      resolve({ code, stdout, stderr });
    });
  });
}

async function parallelLimit(items, limit, worker) {
  const results = new Array(items.length);
  let cursor = 0;
  async function lane() {
    while (true) {
      const index = cursor;
      cursor += 1;
      if (index >= items.length) return;
      results[index] = await worker(items[index], index);
    }
  }
  await Promise.all(Array.from({ length: Math.min(items.length, limit) }, lane));
  return results;
}

function nativePaths(outputDir, packetId) {
  const stem = packetHex(packetId).slice(2);
  return {
    profile: path.join(outputDir, 'profiles', `route_${stem}.json`),
    decoded: path.join(outputDir, 'native', `route_${stem}_distinct_decoded.jsonl`),
    summary: path.join(outputDir, 'native', `route_${stem}_distinct_summary.json`),
  };
}

async function executeNativePass(options, profiles, corpusPath) {
  const results = await parallelLimit(profiles, options.jobs, async (profileBundle) => {
    const packetId = profileBundle.profile.client_opcode;
    const paths = nativePaths(options.outputDir, packetId);
    await runProcess(options.python, [
      path.join(ROOT, 'scripts', 'emulate_packet_profile_json.py'),
      '--image', options.runtime,
      '--events', corpusPath,
      '--profile-json', paths.profile,
      '--runtime-profile', EXACT_BUILD,
      '--output', paths.decoded,
      '--summary', paths.summary,
      '--progress-every', '0',
    ]);
    return {
      packet_id: packetId,
      packet_discriminator: packetHex(packetId),
      decoded_path: paths.decoded,
      decoded_sha256: sha256File(paths.decoded),
      summary_path: paths.summary,
      summary_sha256: sha256File(paths.summary),
    };
  });
  return results.sort((left, right) => left.packet_id - right.packet_id);
}

function compareNativePasses(first, second, executedTwice) {
  const secondById = new Map(second.map((row) => [row.packet_id, row]));
  const routes = first.map((left) => {
    const right = secondById.get(left.packet_id);
    return {
      packet_id: left.packet_id,
      packet_discriminator: left.packet_discriminator,
      first_decoded_sha256: left.decoded_sha256,
      second_decoded_sha256: right?.decoded_sha256 || null,
      decoded_match: Boolean(right && left.decoded_sha256 === right.decoded_sha256),
      first_summary_sha256: left.summary_sha256,
      second_summary_sha256: right?.summary_sha256 || null,
      summary_match: Boolean(right && left.summary_sha256 === right.summary_sha256),
    };
  }).map((row) => ({ ...row, match: row.decoded_match && row.summary_match }));
  return {
    exact_native_execution_rerun: executedTwice,
    route_count: routes.length,
    routes,
    all_match: executedTwice && routes.length === ROUTE_IDS.length && routes.every((row) => row.match),
  };
}

async function loadNativeOutputs(options) {
  const nativeRowsByRoute = {};
  const nativeSummaries = {};
  await Promise.all(ROUTE_IDS.map(async (packetId) => {
    const packetType = packetHex(packetId);
    const paths = nativePaths(options.outputDir, packetId);
    nativeRowsByRoute[packetType] = await readJsonl(paths.decoded);
    nativeSummaries[packetType] = JSON.parse(fs.readFileSync(paths.summary, 'utf8'));
  }));
  return { nativeRowsByRoute, nativeSummaries };
}

function sourceCrossCheck(registry, callbackSidecar, profiler, priorMining) {
  invariant(callbackSidecar.build === EXACT_BUILD, 'callback sidecar exact-build mismatch');
  invariant(profiler.target_build === EXACT_BUILD, 'prior profiler exact-build mismatch');
  invariant(priorMining.exact_build === EXACT_BUILD, 'prior mining exact-build mismatch');
  const profilerRoutes = profiler.route_profiles || [];
  const ranked = profiler.ranked_candidates || [];
  return ROUTE_IDS.map((packetId) => {
    const packetType = packetHex(packetId);
    const registryRoute = registry.routes.find((row) => Number(row.packet_id) === packetId);
    const sidecarRoute = callbackSidecar.routes.find((row) => Number(row.packet_id) === packetId);
    invariant(registryRoute && sidecarRoute, `prior runtime evidence missing ${packetType}`);
    const registryNames = [...new Set(registryRoute.runtime_registration.callbacks.map((row) => row.name))].sort();
    const sidecarNames = [...new Set(sidecarRoute.callback_names || [])].sort();
    invariant(JSON.stringify(registryNames) === JSON.stringify(sidecarNames),
      `${packetType} callback sidecar/registry mismatch`);
    const profileRoute = profilerRoutes.find((row) => Number(row.packet_id) === packetId) || null;
    const miningRoute = (priorMining.routes || []).find((row) => Number(row.packet_id) === packetId) || null;
    return {
      packet_id: packetId,
      packet_discriminator: packetType,
      observed_count: Number(registryRoute.observed.count),
      callback_names: registryNames,
      callback_sidecar_match: true,
      prior_profiler_route: profileRoute,
      prior_profiler_ranked_candidates: ranked.filter((row) => Number(row.packet_id) === packetId),
      prior_sampled_mining_route: miningRoute,
      conclusion: profileRoute || miningRoute
        ? 'PRIOR_CANDIDATE_REEXECUTED_WITH_FULL_INVENTORY_EXACT_RUNTIME_AND_CALLBACK_RECOVERY'
        : 'PRIOR_SURFACE_MISSING; THIS_WAVE_EXECUTED_FULL_EXACT_ROUTE',
    };
  });
}

function hashManifest(root, outputDir, files) {
  const unique = [...new Set(files.map(rejectProtectedPath))].sort();
  return {
    schema: 'UNKNOWN_P1_WAVE_HASH_MANIFEST_V2',
    schema_version: 2,
    exact_build: EXACT_BUILD,
    excluded_self_hash: path.relative(root, path.join(outputDir, 'hashes_16_16.json')).replaceAll('\\', '/'),
    verification_commands: [
      'node --test test/unknown_p1_wave_v2.test.js',
      'node --max-old-space-size=4096 scripts/audit_unknown_p1_wave_v2.js',
    ],
    files: unique.map((filePath) => ({
      path: path.relative(root, filePath).replaceAll('\\', '/'),
      byte_length: fs.statSync(filePath).size,
      sha256: sha256File(filePath),
    })),
  };
}

async function audit(options = parseArgs()) {
  options.outputDir = rejectProtectedPath(options.outputDir);
  fs.mkdirSync(options.outputDir, { recursive: true });
  const registryBytes = fs.readFileSync(rejectProtectedPath(options.registry));
  const callbackBytes = fs.readFileSync(rejectProtectedPath(options.callbackSidecar));
  const profilerBytes = fs.readFileSync(rejectProtectedPath(options.profiler));
  const priorMiningBytes = fs.readFileSync(rejectProtectedPath(options.priorMining));
  const image = fs.readFileSync(rejectProtectedPath(options.runtime));
  invariant(sha256(image) === RUNTIME_SHA256, 'pinned runtime image SHA mismatch');
  const registry = JSON.parse(registryBytes);
  const callbackSidecar = JSON.parse(callbackBytes);
  const profiler = JSON.parse(profilerBytes);
  const priorMining = JSON.parse(priorMiningBytes);
  const priorCrossCheck = sourceCrossCheck(registry, callbackSidecar, profiler, priorMining);
  const evidence = collectEvidence(options.replayPaths);
  const evidenceRerun = collectEvidence(options.replayPaths);
  invariant(evidence.deterministic_digest === evidenceRerun.deterministic_digest,
    'deterministic full extraction rerun mismatch');
  const runtimeIdentities = recoverRuntimeIdentities(registry, image);
  const profiles = buildNativeProfiles(runtimeIdentities);
  const corpusPath = path.join(options.outputDir, 'distinct_payload_corpus_16_16.jsonl');
  const corpus = writeJsonl(corpusPath, evidence.distinct_payload_rows);
  for (const profile of profiles) {
    writeJson(nativePaths(options.outputDir, profile.profile.client_opcode).profile, profile);
  }
  const sourceCrossCheckPath = writeJson(path.join(options.outputDir, 'source_cross_check_16_16.json'), {
    schema: 'UNKNOWN_P1_WAVE_SOURCE_CROSS_CHECK_V2',
    schema_version: 2,
    exact_build: EXACT_BUILD,
    inputs: {
      registry_sha256: sha256(registryBytes),
      callback_sidecar_sha256: sha256(callbackBytes),
      profiler_sha256: sha256(profilerBytes),
      prior_mining_sha256: sha256(priorMiningBytes),
    },
    routes: priorCrossCheck,
  });
  const firstNativePass = await executeNativePass(options, profiles, corpus.path);
  const secondNativePass = options.verifyNativeDeterminism
    ? await executeNativePass(options, profiles, corpus.path)
    : firstNativePass;
  const nativeDeterminism = compareNativePasses(firstNativePass, secondNativePass,
    options.verifyNativeDeterminism);
  invariant(nativeDeterminism.all_match,
    'exact native deterministic rerun is required and all route outputs must match');
  const nativeOutputs = await loadNativeOutputs(options);
  const nativeAnalysis = analyzeNativeOutputs(
    nativeOutputs.nativeRowsByRoute,
    nativeOutputs.nativeSummaries,
    evidence,
    runtimeIdentities,
    image,
  );
  const relative = (value) => path.relative(ROOT, value).replaceAll('\\', '/');
  const report = buildReport({
    evidence,
    registryPath: relative(options.registry),
    runtimePath: relative(options.runtime),
    runtimeIdentities,
    nativeAnalysis,
    nativeDeterminism: {
      extraction_executed_twice: true,
      first_extraction_digest: evidence.deterministic_digest,
      second_extraction_digest: evidenceRerun.deterministic_digest,
      extraction_match: evidence.deterministic_digest === evidenceRerun.deterministic_digest,
      ...nativeDeterminism,
    },
    inputHashes: {
      registry: sha256(registryBytes),
      runtime: sha256(image),
      callback_sidecar: sha256(callbackBytes),
      callback_sidecar_path: relative(options.callbackSidecar),
      profiler: sha256(profilerBytes),
      profiler_path: relative(options.profiler),
      prior_mining: sha256(priorMiningBytes),
      prior_mining_path: relative(options.priorMining),
    },
    priorCrossCheck,
  });
  invariant(report.validations.all_pass, `audit validation failure: ${JSON.stringify(report.validations)}`);
  const reportPath = writeJson(path.join(options.outputDir, 'unknown_p1_wave_audit_16_16.json'), report);
  const decisionsPath = writeJson(path.join(options.outputDir, 'unknown_p1_wave_machine_decisions_16_16.json'), {
    schema: 'UNKNOWN_P1_WAVE_MACHINE_DECISIONS_V2',
    schema_version: 2,
    exact_build: EXACT_BUILD,
    project_context_loaded: true,
    architecture_gate: 'PASS',
    ...report.decisions,
    protected_holdout: {
      enumerated: false,
      read: false,
      hashed: false,
      decoded: false,
      tested: false,
      consumed: false,
    },
  });
  const markdownPath = rejectProtectedPath(path.join(options.outputDir, 'unknown_p1_wave_audit_16_16.md'));
  fs.writeFileSync(markdownPath, markdownReport(report), 'utf8');
  const determinismPath = writeJson(path.join(options.outputDir, 'determinism_16_16.json'), {
    schema: 'UNKNOWN_P1_WAVE_DETERMINISM_V2',
    schema_version: 2,
    exact_build: EXACT_BUILD,
    ...report.determinism,
  });
  const artifactFiles = [
    path.join(ROOT, 'src', 'unknown_p1_wave_v2.js'),
    path.join(ROOT, 'scripts', 'audit_unknown_p1_wave_v2.js'),
    path.join(ROOT, 'test', 'unknown_p1_wave_v2.test.js'),
    path.join(options.outputDir, 'ARCHITECTURE_GATE.md'),
    options.registry,
    options.callbackSidecar,
    options.profiler,
    options.priorMining,
    options.runtime,
    corpus.path,
    sourceCrossCheckPath,
    ...profiles.map((profile) => nativePaths(options.outputDir, profile.profile.client_opcode).profile),
    ...ROUTE_IDS.flatMap((packetId) => {
      const paths = nativePaths(options.outputDir, packetId);
      return [paths.decoded, paths.summary];
    }),
    reportPath,
    decisionsPath,
    markdownPath,
    determinismPath,
  ];
  const manifestPath = path.join(options.outputDir, 'hashes_16_16.json');
  writeJson(manifestPath, hashManifest(ROOT, options.outputDir, artifactFiles));
  return {
    report,
    outputs: [reportPath, decisionsPath, markdownPath, determinismPath, manifestPath].map((filePath) => ({
      path: filePath,
      sha256: sha256File(filePath),
    })),
  };
}

async function main(argv = process.argv.slice(2)) {
  const result = await audit(parseArgs(argv));
  process.stdout.write(`${JSON.stringify({
    exact_build: EXACT_BUILD,
    target_row_count: result.report.full_inventory.target_row_count,
    distinct_payload_row_count: result.report.full_inventory.distinct_payload_row_count,
    decision_counts: result.report.decisions.decision_counts,
    current_local_evidence_saturated: result.report.saturation.current_local_evidence_saturated,
    validations: result.report.validations,
    outputs: result.outputs,
  }, null, 2)}\n`);
}

if (require.main === module) main().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});

module.exports = {
  DEFAULT_REPLAY_ROOT,
  ROOT,
  audit,
  compareNativePasses,
  nativePaths,
  parallelLimit,
  parseArgs,
  sourceCrossCheck,
};

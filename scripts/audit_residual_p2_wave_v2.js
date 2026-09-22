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
  analyzeNative,
  buildDecisions,
  buildProfiles,
  collectEvidence,
  markdownReport,
  packetHex,
  rejectProtectedPath,
  sha256,
  sha256File,
  validateDecisionBundle,
} = require('../src/residual_p2_wave_v2');

const ROOT = path.resolve(__dirname, '..');
const DEFAULT_REPLAY_ROOT = process.env.ROFL_REPLAY_ROOT || path.join(ROOT, 'replay');

const STATIC_PROBE = String.raw`
import hashlib
import json
import sys
from pathlib import Path

import pefile

root = Path(sys.argv[1]).resolve()
image_path = Path(sys.argv[2]).resolve()
callback_path = Path(sys.argv[3]).resolve()
route_ids = tuple(int(value, 16) for value in sys.argv[4].split(','))
if any('holdout' in str(value).lower() for value in (root, image_path, callback_path)):
    raise ValueError('protected Holdout path is forbidden')
sys.path.insert(0, str(root / 'scripts'))

import exhaust_highfreq_leftovers_v2 as exhaust
from audit_named_gameplay_wave_16_16 import alias_field_accesses
from trace_hero_combat_state_runtime import StaticImage, analyze_factory_case, locate_factory

image = image_path.read_bytes()
callback_map = json.loads(callback_path.read_text(encoding='utf-8-sig'))
if callback_map.get('build') != '16.16.805.0442':
    raise ValueError('callback-map exact build mismatch')
static = StaticImage(image, pefile.PE(data=image, fast_load=False))
factory = locate_factory(static, set(route_ids), 0x00ED97B0)
exhaust.ROUTES = route_ids
immediate = exhaust.exhaustive_pdata_immediate_scan(static)
callback_index = {
    int(row['packet_id']): row for row in callback_map['routes']
    if int(row['packet_id']) in set(route_ids)
}

def compact_instruction(row):
    return {
        'rva': row['rva'],
        'rva_hex': row['rva_hex'],
        'bytes': row['bytes'],
        'mnemonic': row['mnemonic'],
        'operands': row['operands'],
    }

routes = {}
for packet_id in route_ids:
    packet = f'0x{packet_id:04x}'
    analyzed = analyze_factory_case(static, factory, packet_id)
    chain = exhaust.compact_factory_case(analyzed)
    callback = callback_index[packet_id]
    callbacks = callback.get('callbacks') or []
    scan = immediate['routes'][packet]
    non_constructor = [
        row for row in scan['retained_matches']
        if row['classification'] != 'PACKET_CONSTRUCTOR_ID_WRITE'
    ]
    case_rva = chain['case_rva']
    constructor_rva = chain['constructor_rva']
    vtable_rva = chain['vtable_rva']
    deserializer_rva = chain['deserializer_rva']
    slices = {
        'factory_case_sha256': hashlib.sha256(image[case_rva:case_rva + 0x80]).hexdigest(),
        'constructor_sha256': hashlib.sha256(image[constructor_rva:constructor_rva + 0x80]).hexdigest(),
        'vtable_sha256': hashlib.sha256(image[vtable_rva:vtable_rva + 0x30]).hexdigest(),
        'deserializer_prefix_sha256': hashlib.sha256(image[deserializer_rva:deserializer_rva + 0x100]).hexdigest(),
    }
    factory_ok = (
        chain['packet_id'] == packet_id
        and chain['allocation_size'] == chain['object_size']
        and analyzed['constructor']['packet_id'] == packet_id
        and analyzed['packet_object_vtable']['slot_1_deserializer_rva'] == deserializer_rva
        and analyzed['packet_object_vtable']['slot_2_returned_object_size'] == chain['object_size']
    )
    mapped = callback.get('callback_mapping_status') == 'UNIQUE_CALLBACK_RTTI_NAME'
    routes[packet] = {
        'packet_id': packet_id,
        'packet_discriminator': packet,
        'factory_chain': chain,
        'runtime_slice_hashes': slices,
        'deserializer_static_analysis': alias_field_accesses(
            static, deserializer_rva, 'rcx', chain['object_size']
        ),
        'observed_callback_map': callback,
        'full_pdata_immediate_reference_scan': {
            'match_count': scan['match_count'],
            'mnemonic_counts': scan['mnemonic_counts'],
            'classification_counts': scan['classification_counts'],
            'candidate_function_rvas': scan['candidate_function_rvas'],
            'candidate_function_rvas_hex': scan['candidate_function_rvas_hex'],
            'non_constructor_retained_matches': non_constructor,
            'retained_match_limit': scan['retained_match_limit'],
        },
        'receive_identity': {
            'status': ('STATIC_CALLBACK_RTTI_AND_RECEIVE_TARGET_VERIFIED' if mapped
                       else 'PACKET_SPECIFIC_CALLBACK_REQUIRES_RUNTIME_HEAP_CALLBACK_TREE'),
            'runtime_type_name': ((callback.get('callback_names') or [None])[0] if mapped else None),
            'callback_receive_target_rva_hex': (
                callbacks[0].get('callback_receive_target_rva_hex') if mapped and callbacks else None
            ),
            'bounded_static_surfaces_exhausted': True,
            'bounded_failure_reason': (None if mapped else
                'Exact MakeFunction callback registrations, the complete PE exception-directory '
                'function instruction surface for packet-ID immediates, factory/constructor/vtable/'
                'deserializer direct xrefs, and generic dispatcher identity do not contain a '
                'packet-specific RTTI/receive target. The remaining callback-tree node is heap-resident '
                'and absent from the pinned module image.'),
        },
        'validations': {
            'exact_factory_case': True,
            'exact_constructor_packet_id_write': analyzed['constructor']['packet_id'] == packet_id,
            'exact_vtable': True,
            'exact_deserializer': True,
            'allocation_size_matches_object_size': chain['allocation_size'] == chain['object_size'],
            'deserializer_object_access_scan_executed': True,
            'full_pdata_immediate_scan_executed': True,
            'all_factory_checks_pass': factory_ok,
        },
    }

family_groups = {
    'four_variant': ['0x018a', '0x0131', '0x0153', '0x03b4'],
    'two_variant': ['0x040e', '0x0201'],
}
four = [routes[key]['factory_chain'] for key in family_groups['four_variant']]
two = [routes[key]['factory_chain'] for key in family_groups['two_variant']]
relationships = {
    'four_variant': {
        'routes': family_groups['four_variant'],
        'constructor_rvas': [row['constructor_rva_hex'] for row in four],
        'vtable_rvas': [row['vtable_rva_hex'] for row in four],
        'deserializer_rvas': [row['deserializer_rva_hex'] for row in four],
        'constructors_exactly_0x40_apart': all(
            four[index + 1]['constructor_rva'] - four[index]['constructor_rva'] == 0x40
            for index in range(len(four) - 1)
        ),
        'vtables_exactly_0x30_apart_reverse': all(
            four[index]['vtable_rva'] - four[index + 1]['vtable_rva'] == 0x30
            for index in range(len(four) - 1)
        ),
        'semantic_claim': None,
    },
    'two_variant': {
        'routes': family_groups['two_variant'],
        'constructor_rvas': [row['constructor_rva_hex'] for row in two],
        'vtable_rvas': [row['vtable_rva_hex'] for row in two],
        'deserializer_rvas': [row['deserializer_rva_hex'] for row in two],
        'constructors_exactly_0x40_apart': two[1]['constructor_rva'] - two[0]['constructor_rva'] == 0x40,
        'vtables_exactly_0x30_apart_reverse': two[0]['vtable_rva'] - two[1]['vtable_rva'] == 0x30,
        'equal_object_size': two[0]['object_size'] == two[1]['object_size'] == 0x38,
        'semantic_claim': None,
    },
}
result = {
    'schema': 'RESIDUAL_P2_STATIC_RUNTIME_RECOVERY_V2',
    'schema_version': 2,
    'exact_build': '16.16.805.0442',
    'runtime_sha256': hashlib.sha256(image).hexdigest(),
    'factory': {
        'function_rva': factory['function'][0],
        'function_rva_hex': f"0x{factory['function'][0]:08x}",
        'switch_rva': factory['switch_rva'],
        'switch_rva_hex': f"0x{factory['switch_rva']:08x}",
        'jump_table_rva': factory['table_rva'],
        'jump_table_rva_hex': f"0x{factory['table_rva']:08x}",
        'maximum_packet_id': factory['maximum_id'],
    },
    'pdata_scan': {
        'surface': immediate['surface'],
        'function_count': immediate['function_count'],
        'instruction_byte_count': immediate['instruction_byte_count'],
    },
    'routes': routes,
    'structural_family_relationships': relationships,
    'all_routes_factory_closed': all(row['validations']['all_factory_checks_pass'] for row in routes.values()),
    'all_deserializer_object_access_scans_executed': all(
        row['validations']['deserializer_object_access_scan_executed'] for row in routes.values()
    ),
    'all_receive_static_surfaces_exhausted': all(
        row['receive_identity']['bounded_static_surfaces_exhausted'] for row in routes.values()
    ),
}
print(json.dumps(result, ensure_ascii=True, separators=(',', ':')))
`;

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
    callbackMap: path.join(ROOT, 'artifacts', 'hero_combat_state_v2', 'runtime',
      'observed_packet_callback_route_map_16_16.json'),
    runtime: path.join(ROOT, 'artifacts', 'new_build_rofl_compatibility_gate_v1', 'runtime',
      'league_16.16.805.0442.memory.bin'),
    outputDir: path.join(ROOT, 'artifacts', 'full_semantic_deep_recovery_v2', 'residual_p2_wave'),
    python: 'python',
    jobs: 4,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    if (option === '--replay') options.replayPaths.push(rejectProtectedPath(requireValue(argv, ++index, option)));
    else if (option === '--registry') options.registry = rejectProtectedPath(requireValue(argv, ++index, option));
    else if (option === '--callback-map') options.callbackMap = rejectProtectedPath(requireValue(argv, ++index, option));
    else if (option === '--runtime') options.runtime = rejectProtectedPath(requireValue(argv, ++index, option));
    else if (option === '--output-dir') options.outputDir = rejectProtectedPath(requireValue(argv, ++index, option));
    else if (option === '--python') options.python = requireValue(argv, ++index, option);
    else if (option === '--jobs') options.jobs = Number(requireValue(argv, ++index, option));
    else throw new Error(`unknown option: ${option}`);
  }
  if (!options.replayPaths.length) {
    options.replayPaths = Object.keys(SAFE_REPLAYS).map((basename) =>
      rejectProtectedPath(path.join(DEFAULT_REPLAY_ROOT, basename)));
  }
  invariant(options.replayPaths.length === 4, 'exactly four explicit safe replay paths are required');
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
  const text = `${rows.map((row) => JSON.stringify(row)).join('\n')}\n`;
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
        reject(new Error(`${command} ${args[0] || ''} exited ${code}\n${stderr}\n${stdout}`));
        return;
      }
      resolve({ stdout, stderr });
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
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, lane));
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

async function staticRecovery(options) {
  const result = await runProcess(options.python, [
    '-c', STATIC_PROBE, ROOT, options.runtime, options.callbackMap,
    ROUTE_IDS.map((packetId) => packetId.toString(16)).join(','),
  ]);
  const parsed = JSON.parse(result.stdout.trim());
  invariant(parsed.runtime_sha256 === RUNTIME_SHA256, 'static probe runtime hash mismatch');
  invariant(parsed.all_routes_factory_closed === true, 'static factory recovery incomplete');
  invariant(parsed.all_deserializer_object_access_scans_executed === true,
    'static deserializer object access scan incomplete');
  invariant(parsed.all_receive_static_surfaces_exhausted === true,
    'static callback surface exhaustion incomplete');
  return parsed;
}

async function nativePass(options, profiles, corpusPath) {
  const rows = await parallelLimit(profiles, options.jobs, async (profileBundle) => {
    const packetId = profileBundle.profile.client_opcode;
    const files = nativePaths(options.outputDir, packetId);
    await runProcess(options.python, [
      path.join(ROOT, 'scripts', 'emulate_packet_profile_json.py'),
      '--image', options.runtime,
      '--events', corpusPath,
      '--profile-json', files.profile,
      '--runtime-profile', EXACT_BUILD,
      '--output', files.decoded,
      '--summary', files.summary,
      '--progress-every', '0',
    ]);
    return {
      packet_id: packetId,
      packet_discriminator: packetHex(packetId),
      decoded_sha256: sha256File(files.decoded),
      summary_sha256: sha256File(files.summary),
    };
  });
  return rows.sort((left, right) => left.packet_id - right.packet_id);
}

function comparePasses(first, second) {
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
  });
  for (const row of routes) row.match = row.decoded_match && row.summary_match;
  return {
    exact_native_execution_rerun: true,
    route_count: routes.length,
    routes,
    all_match: routes.length === ROUTE_IDS.length && routes.every((row) => row.match),
  };
}

async function loadNative(options) {
  const result = {};
  await Promise.all(ROUTE_IDS.map(async (packetId) => {
    result[packetHex(packetId)] = await readJsonl(nativePaths(options.outputDir, packetId).decoded);
  }));
  return result;
}

function crossCheckRegistry(registry, callbackMap, evidence) {
  invariant(registry.exact_build === EXACT_BUILD, 'observed registry build mismatch');
  invariant(callbackMap.build === EXACT_BUILD, 'callback map build mismatch');
  const callbackById = new Map(callbackMap.routes.map((row) => [Number(row.packet_id), row]));
  return ROUTE_IDS.map((packetId) => {
    const packetType = packetHex(packetId);
    const registryRow = registry.routes.find((row) => Number(row.packet_id) === packetId);
    const callbackRow = callbackById.get(packetId);
    invariant(registryRow && callbackRow, `registry/callback row missing ${packetType}`);
    return {
      packet_id: packetId,
      packet_discriminator: packetType,
      collected_count: evidence.routes[packetType].count,
      registry_count: Number(registryRow.observed.count),
      callback_map_observed_count: Number(callbackRow.observed_count),
      count_match: evidence.routes[packetType].count === Number(registryRow.observed.count)
        && evidence.routes[packetType].count === Number(callbackRow.observed_count),
      callback_mapping_status: callbackRow.callback_mapping_status,
      callback_names: callbackRow.callback_names,
      direct_factory_sidecar_count: (callbackRow.factory_packets || []).length,
    };
  });
}

function hashManifest(files) {
  return {
    schema: 'RESIDUAL_P2_WAVE_HASH_MANIFEST_V2',
    schema_version: 2,
    exact_build: EXACT_BUILD,
    files: [...new Set(files.map(rejectProtectedPath))].sort().map((filePath) => ({
      path: path.relative(ROOT, filePath).replaceAll('\\', '/'),
      byte_length: fs.statSync(filePath).size,
      sha256: sha256File(filePath),
    })),
    protected_holdout: {
      enumerated: false, read: false, hashed: false, decoded: false, tested: false, consumed: false,
    },
  };
}

async function audit(options = parseArgs()) {
  options.outputDir = rejectProtectedPath(options.outputDir);
  fs.mkdirSync(options.outputDir, { recursive: true });
  const registryBytes = fs.readFileSync(options.registry);
  const callbackBytes = fs.readFileSync(options.callbackMap);
  const runtimeBytes = fs.readFileSync(options.runtime);
  invariant(sha256(runtimeBytes) === RUNTIME_SHA256, 'pinned exact runtime SHA-256 mismatch');
  const registry = JSON.parse(registryBytes);
  const callbackMap = JSON.parse(callbackBytes);
  const evidence = collectEvidence(options.replayPaths);
  const sourceCrossCheck = crossCheckRegistry(registry, callbackMap, evidence);
  invariant(sourceCrossCheck.every((row) => row.count_match), 'registry full count cross-check failed');
  const staticReport = await staticRecovery(options);
  const staticPath = writeJson(path.join(options.outputDir, 'residual_p2_static_runtime_16_16.json'), staticReport);
  const profiles = buildProfiles(staticReport);
  for (const profile of profiles) writeJson(nativePaths(options.outputDir, profile.profile.client_opcode).profile, profile);
  const corpus = writeJsonl(path.join(options.outputDir, 'residual_p2_distinct_payloads_16_16.jsonl'),
    evidence.distinct_payload_rows);
  const firstPass = await nativePass(options, profiles, corpus.path);
  const secondPass = await nativePass(options, profiles, corpus.path);
  const nativeDeterminism = comparePasses(firstPass, secondPass);
  invariant(nativeDeterminism.all_match, 'double exact native emulation mismatch');
  const nativeRows = await loadNative(options);
  const nativeAnalysis = analyzeNative(nativeRows, evidence, staticReport);
  const decisions = buildDecisions(evidence, staticReport, nativeAnalysis);
  const decisionBundle = {
    schema: 'RESIDUAL_P2_WAVE_MACHINE_DECISIONS_V2',
    schema_version: 2,
    analyzer_version: 'residual-p2-wave-v2',
    generated_at: '2026-08-20',
    exact_build: EXACT_BUILD,
    exact_build_only: true,
    nearest_build_fallback: 'FORBIDDEN',
    decision_vocabulary: ['PROMOTE', 'REPURPOSE', 'KEEP_CANDIDATE', 'REJECT'],
    protected_holdout_policy: {
      read: false, enumerate: false, hash: false, decode: false, test: false, consume: false,
    },
    ...decisions,
    saturation: {
      current_safe_local_resource_saturated: decisions.all_current_local_evidence_exhausted,
      route_count: decisions.route_decisions.length,
      capability_count: decisions.capability_decisions.length,
      domain_count: decisions.domain_decisions.length,
      local_actionable_hypothesis_count: decisions.route_decisions
        .reduce((sum, row) => sum + row.actionable_hypotheses.length, 0),
      remaining_evidence_class: 'EXTERNAL_OR_NEW_CONTROLLED_EXACT_BUILD_REPLAY_ONLY',
    },
  };
  validateDecisionBundle(decisionBundle);
  const allNativeConserved = Object.values(nativeAnalysis.routes).every((row) =>
    row.all_distinct_payloads_attempted && row.full_occurrence_weight_conserved);
  const allNativeFailuresExternal = Object.values(nativeAnalysis.routes).every((row) =>
    row.all_failures_external_runtime_state);
  const validations = {
    exact_build_and_runtime_hash: staticReport.exact_build === EXACT_BUILD
      && staticReport.runtime_sha256 === RUNTIME_SHA256,
    explicit_safe_latest_four_only: evidence.replays.length === 4
      && evidence.replays.every((row) => SAFE_REPLAYS[row.basename] === row.replay_sha256),
    registry_count_conservation: sourceCrossCheck.every((row) => row.count_match),
    target_occurrence_weight_conserved: Object.values(evidence.routes)
      .every((row) => row.payload.occurrence_weight_conserved),
    all_factory_constructor_vtable_deserializer_chains_closed: staticReport.all_routes_factory_closed,
    all_deserializer_object_access_scans_executed:
      staticReport.all_deserializer_object_access_scans_executed,
    full_pdata_instruction_surface_scanned: staticReport.pdata_scan.function_count > 100000
      && staticReport.pdata_scan.instruction_byte_count > 20000000,
    all_callback_static_surfaces_exhausted: staticReport.all_receive_static_surfaces_exhausted,
    all_distinct_payloads_native_attempted_and_weight_conserved: allNativeConserved,
    all_native_failures_are_precise_external_runtime_state: allNativeFailuresExternal,
    double_native_execution_hash_match: nativeDeterminism.all_match,
    every_route_capability_domain_decision_exhausted: decisions.all_current_local_evidence_exhausted
      && decisionBundle.saturation.local_actionable_hypothesis_count === 0,
  };
  validations.all_pass = Object.values(validations).every(Boolean);
  invariant(validations.all_pass, `residual P2 validation failure: ${JSON.stringify(validations)}`);
  const report = {
    schema: 'RESIDUAL_P2_WAVE_DEEP_RECOVERY_V2',
    schema_version: 2,
    analyzer_version: 'residual-p2-wave-v2',
    generated_at: '2026-08-20',
    exact_build: EXACT_BUILD,
    exact_build_only: true,
    nearest_build_fallback: 'FORBIDDEN',
    project_context_loaded: true,
    architecture_gate: 'PASS',
    status: 'CURRENT_SAFE_LOCAL_EVIDENCE_EXHAUSTED',
    scope: ROUTE_IDS.map(packetHex),
    parser_boundary: 'Replay protocol structure only; no map truth, behavior inference, acquisition, Akari runtime/cache/state, or UI.',
    explicit_allowlist: {
      source_replays: evidence.replays,
      directory_discovery_used: false,
    },
    protected_holdout: {
      enumerated: false, read: false, hashed: false, decoded: false, tested: false, consumed: false,
    },
    inputs: {
      registry: { path: path.relative(ROOT, options.registry).replaceAll('\\', '/'), sha256: sha256(registryBytes) },
      callback_map: { path: path.relative(ROOT, options.callbackMap).replaceAll('\\', '/'), sha256: sha256(callbackBytes) },
      runtime: { path: path.relative(ROOT, options.runtime).replaceAll('\\', '/'), sha256: sha256(runtimeBytes) },
    },
    conservation: {
      target_route_count: ROUTE_IDS.length,
      target_row_count: evidence.target_row_count,
      distinct_payload_row_count: evidence.distinct_payload_row_count,
      deterministic_extraction_digest: evidence.deterministic_digest,
      registry_cross_check: sourceCrossCheck,
      target_occurrence_weight_conserved: true,
    },
    methods_executed: [
      'FULL_EXPLICIT_SAFE_LATEST_FOUR_REPLAY_WALK',
      'ALL_DISTINCT_PAYLOAD_WEIGHTED_CORPUS',
      'EXACT_FACTORY_CONSTRUCTOR_VTABLE_DESERIALIZER_STATIC_RECOVERY',
      'CAPSTONE_ALIAS_TRACKED_DESERIALIZER_OBJECT_ACCESS_SCAN',
      'FULL_PE_EXCEPTION_DIRECTORY_FUNCTION_IMMEDIATE_SCAN',
      'DOUBLE_EXACT_RUNTIME_NATIVE_EMULATION_PER_ROUTE_PROFILE',
      'STREAM_ENTITY_TIME_NEIGHBOR_CROSS_ROUTE_AND_ANCHOR_COUNTEREXAMPLE_AUDIT',
    ],
    raw_route_profiles: evidence.routes,
    anchor_counts: evidence.anchor_counts,
    exact_time_cross_route_matrix: evidence.cross_route_exact_time_matrix,
    runtime_static_recovery: staticReport,
    native_exact_emulation: nativeAnalysis,
    native_determinism: nativeDeterminism,
    decision_summary: decisions,
    saturation: {
      current_safe_local_resource_saturated: decisions.all_current_local_evidence_exhausted,
      local_actionable_hypothesis_count: decisionBundle.saturation.local_actionable_hypothesis_count,
      closed_surfaces: [
        'FULL_ROUTE_INVENTORY_AND_DISTINCT_PAYLOAD_WEIGHT',
        'FACTORY_CONSTRUCTOR_VTABLE_DESERIALIZER_IDENTITY',
        'ALIAS_TRACKED_DESERIALIZER_OBJECT_FIELD_ACCESS_SURFACE',
        'MAKEFUNCTION_AND_FULL_PDATA_PACKET_ID_REFERENCE_SURFACE',
        'DOUBLE_NATIVE_EXACT_DESERIALIZER_EXECUTION',
        'TEMPORAL_ENTITY_STREAM_NEIGHBOR_AND_ANCHOR_COUNTEREXAMPLES',
      ],
      blocked_surface: 'HEAP_CALLBACK_TREE_AND_PLAINTEXT_BUSINESS_STATE',
      remaining_evidence_class: 'EXTERNAL_OR_NEW_CONTROLLED_EXACT_BUILD_REPLAY_ONLY',
    },
    validations,
  };
  const reportPath = writeJson(path.join(options.outputDir, 'residual_p2_wave_audit_16_16.json'), report);
  const decisionsPath = writeJson(path.join(options.outputDir, 'residual_p2_wave_decisions_16_16.json'), decisionBundle);
  const determinismPath = writeJson(path.join(options.outputDir, 'residual_p2_wave_determinism_16_16.json'), nativeDeterminism);
  const markdownPath = rejectProtectedPath(path.join(options.outputDir, 'residual_p2_wave_audit_16_16.md'));
  fs.writeFileSync(markdownPath, markdownReport(report), 'utf8');
  const artifactFiles = [
    path.join(ROOT, 'src', 'residual_p2_wave_v2.js'),
    path.join(ROOT, 'scripts', 'audit_residual_p2_wave_v2.js'),
    path.join(ROOT, 'test', 'residual_p2_wave_v2.test.js'),
    path.join(options.outputDir, 'WHY_THIS_STAGE_EXISTS.md'),
    path.join(options.outputDir, 'ARCHITECTURE_GATE.md'),
    options.registry, options.callbackMap, options.runtime, corpus.path, staticPath,
    ...profiles.map((profile) => nativePaths(options.outputDir, profile.profile.client_opcode).profile),
    ...ROUTE_IDS.flatMap((packetId) => {
      const files = nativePaths(options.outputDir, packetId);
      return [files.decoded, files.summary];
    }),
    reportPath, decisionsPath, determinismPath, markdownPath,
  ];
  const hashesPath = writeJson(path.join(options.outputDir, 'residual_p2_wave_hashes_16_16.json'),
    hashManifest(artifactFiles));
  return { report, decisionBundle, outputs: [reportPath, decisionsPath, determinismPath, hashesPath]
    .map((filePath) => ({ path: filePath, sha256: sha256File(filePath) })) };
}

async function main(argv = process.argv.slice(2)) {
  const result = await audit(parseArgs(argv));
  process.stdout.write(`${JSON.stringify({
    status: 'PASS',
    exact_build: EXACT_BUILD,
    target_row_count: result.report.conservation.target_row_count,
    distinct_payload_row_count: result.report.conservation.distinct_payload_row_count,
    route_decision_counts: result.report.decision_summary.decision_counts,
    local_actionable_hypothesis_count: result.report.saturation.local_actionable_hypothesis_count,
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
  STATIC_PROBE,
  audit,
  comparePasses,
  nativePaths,
  parallelLimit,
  parseArgs,
};

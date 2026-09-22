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
} = require('../src/residual_p6_wave_v2');

const ROOT = path.resolve(__dirname, '..');
const DEFAULT_REPLAY_ROOT = process.env.ROFL_REPLAY_ROOT || path.join(ROOT, 'replay');

const STATIC_PROBE = String.raw`
import hashlib
import json
import sys
from pathlib import Path

import pefile
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_EAX, X86_REG_ECX, X86_REG_RAX, X86_REG_RCX, X86_REG_RIP

root = Path(sys.argv[1]).resolve()
image_path = Path(sys.argv[2]).resolve()
callback_path = Path(sys.argv[3]).resolve()
route_ids = tuple(int(value, 16) for value in sys.argv[4].split(','))
if any('holdout' in str(value).lower() for value in (root, image_path, callback_path)):
    raise ValueError('protected Holdout path is forbidden')
sys.path.insert(0, str(root / 'scripts'))

import exhaust_highfreq_leftovers_v2 as exhaust
from trace_hero_combat_state_runtime import (
    IMAGE_BASE, StaticImage, analyze_factory_case, direct_call_target,
    function_record, instruction_record, locate_factory, simple_immediate_return,
)

image = image_path.read_bytes()
callback_map = json.loads(callback_path.read_text(encoding='utf-8-sig'))
if callback_map.get('build') != '16.16.805.0442':
    raise ValueError('callback-map exact-build mismatch')
static = StaticImage(image, pefile.PE(data=image, fast_load=False))
factory = locate_factory(static, set(route_ids), 0x00ED97B0)
exhaust.ROUTES = route_ids
immediate = exhaust.exhaustive_pdata_immediate_scan(static)
callback_index = {
    int(row['packet_id']): row for row in callback_map['routes']
    if int(row['packet_id']) in set(route_ids)
}

named_factories = []
for callback_row in callback_map['routes']:
    names = callback_row.get('callback_names') or []
    for entry in callback_row.get('factory_packets') or []:
        named_factories.append({
            'packet_id': int(callback_row['packet_id']),
            'packet_discriminator': f"0x{int(callback_row['packet_id']):04x}",
            'callback_names': names,
            'callback_mapping_status': callback_row.get('callback_mapping_status'),
            'constructor_rva': int(entry['constructor_rva']),
            'packet_object_vtable_rva': int(entry['packet_object_vtable_rva']),
            'deserializer_rva': int(entry['deserializer_rva']),
            'object_size': int(entry['object_size']),
        })

def fragmented_pdata_factory_case(packet_id):
    """Recover the 0x001a constructor beyond its incorrectly short .pdata fragment."""
    case_rva = factory['case_rvas'][packet_id]
    case_insns = static.disassemble(case_rva, min(case_rva + 0x80, factory['function'][1]))
    direct_calls = [(insn, direct_call_target(insn)) for insn in case_insns
                    if direct_call_target(insn) is not None]
    if len(direct_calls) < 2:
        raise ValueError(f'fragmented factory case {case_rva:#x}: fewer than two calls')
    allocator_call, constructor_call = direct_calls[:2]
    allocator_index = case_insns.index(allocator_call[0])
    allocation_sizes = []
    for insn in case_insns[:allocator_index]:
        if insn.mnemonic != 'mov' or len(insn.operands) != 2:
            continue
        dst, src = insn.operands
        if (dst.type == X86_OP_REG and dst.reg in (X86_REG_ECX, X86_REG_RCX)
                and src.type == X86_OP_IMM):
            allocation_sizes.append(src.imm & 0xffffffff)
    if not allocation_sizes:
        raise ValueError('fragmented 0x001a factory allocation size missing')
    allocation_size = allocation_sizes[-1]
    constructor_rva = constructor_call[1]
    decoded = static.disassemble(constructor_rva, min(constructor_rva + 0x1000, len(image)))
    ret_index = next((index for index, insn in enumerate(decoded) if insn.mnemonic == 'ret'), None)
    if ret_index is None:
        raise ValueError('fragmented 0x001a constructor has no real RET within 0x1000 bytes')
    ctor_insns = decoded[:ret_index + 1]
    id_writes = []
    for insn in ctor_insns:
        if insn.mnemonic != 'mov' or len(insn.operands) != 2:
            continue
        dst, src = insn.operands
        if (dst.type == X86_OP_MEM and dst.size == 2
                and dst.mem.base == X86_REG_RCX and dst.mem.disp == 8
                and src.type == X86_OP_IMM and (src.imm & 0xffff) == packet_id):
            id_writes.append(insn)
    if len(id_writes) != 1:
        raise ValueError(f'fragmented 0x001a constructor ID writes: {len(id_writes)}')
    vtables = []
    for insn in ctor_insns:
        if insn.mnemonic != 'lea' or len(insn.operands) != 2:
            continue
        dst, src = insn.operands
        if not (dst.type == X86_OP_REG and dst.reg == X86_REG_RAX
                and src.type == X86_OP_MEM and src.mem.base == X86_REG_RIP):
            continue
        target = insn.address + insn.size + src.mem.disp - IMAGE_BASE
        entries = [static.qword_rva(target + index * 8) for index in range(6)]
        if any(entry is None for entry in entries[:3]):
            continue
        object_size = simple_immediate_return(static, entries[2])
        if object_size == allocation_size:
            vtables.append((insn, target, entries, object_size))
    if len(vtables) != 1:
        raise ValueError(f'fragmented 0x001a matching vtables: {len(vtables)}')
    vtable_insn, vtable_rva, entries, object_size = vtables[0]
    deserializer_rva = entries[1]
    return {
        'packet_id': packet_id,
        'packet_discriminator': f'0x{packet_id:04x}',
        'jump_table_entry_rva': factory['table_rva'] + packet_id * 4,
        'jump_table_entry_rva_hex': f"0x{factory['table_rva'] + packet_id * 4:08x}",
        'case_rva': case_rva,
        'case_rva_hex': f'0x{case_rva:08x}',
        'allocation_size': allocation_size,
        'constructor_rva': constructor_rva,
        'constructor_rva_hex': f'0x{constructor_rva:08x}',
        'constructor_packet_id_write': instruction_record(id_writes[0]),
        'vtable_rva': vtable_rva,
        'vtable_rva_hex': f'0x{vtable_rva:08x}',
        'vtable_entries_rva': entries,
        'vtable_entries_rva_hex': [f'0x{entry:08x}' for entry in entries],
        'object_size': object_size,
        'deserializer_rva': deserializer_rva,
        'deserializer_rva_hex': f'0x{deserializer_rva:08x}',
        'deserializer_function': function_record(static.function_for(deserializer_rva)),
        'constructor_boundary': {
            'source': 'FACTORY_PROVEN_ENTRY_TO_FIRST_REAL_RET',
            'misleading_pdata_range': [constructor_rva, static.function_for(constructor_rva)[1]],
            'decoded_end_rva': ctor_insns[-1].address - IMAGE_BASE + ctor_insns[-1].size,
            'instruction_count': len(ctor_insns),
            'counterexample': 'The exception-directory entry ends inside the constructor; using it alone hides the direct packet-ID write and final vtable.',
        },
    }

routes = {}
for packet_id in route_ids:
    packet = f'0x{packet_id:04x}'
    if packet_id == 0x001a:
        analyzed = None
        chain = fragmented_pdata_factory_case(packet_id)
    else:
        analyzed = analyze_factory_case(static, factory, packet_id)
        chain = exhaust.compact_factory_case(analyzed)
    callback = callback_index[packet_id]
    scan = immediate['routes'][packet]
    callbacks = callback.get('callbacks') or []
    callback_names = callback.get('callback_names') or []
    mapped = (callback.get('callback_mapping_status') == 'UNIQUE_CALLBACK_RTTI_NAME'
              and len(callback_names) == 1 and len(callbacks) == 1)
    callback_name = callback_names[0] if mapped else None
    callback_owner = callbacks[0].get('callback_owner_type') if mapped else None
    type_descriptor_rva = (
        int(callbacks[0]['type_descriptor_rva_hex'], 16) if mapped else None
    )
    receive_target_rva = (
        int(callbacks[0]['callback_receive_target_rva_hex'], 16) if mapped else None
    )
    type_descriptor_window = (
        image[type_descriptor_rva:type_descriptor_rva + 0x300] if mapped else b''
    )
    type_descriptor_text = (
        type_descriptor_window[0x10:].split(b'\x00', 1)[0].decode('ascii', errors='strict')
        if mapped else None
    )
    direct_rtti_packet_name_verified = (
        mapped and callback_name.encode('ascii') in type_descriptor_window
    )
    direct_rtti_owner_verified = (
        mapped and callback_owner.encode('ascii') in type_descriptor_window
    )
    receive_target_function = static.function_for(receive_target_rva) if mapped else None
    direct_receive_target_executable_verified = receive_target_function is not None
    direct_callback_identity_verified = (
        direct_rtti_packet_name_verified and direct_rtti_owner_verified
        and direct_receive_target_executable_verified
    )
    shared = [
        {
            **row,
            'relationship': 'EXACT_SHARED_PACKET_OBJECT_VTABLE_AND_DESERIALIZER',
            'semantic_transfer_allowed': False,
        }
        for row in named_factories
        if row['packet_object_vtable_rva'] == chain['vtable_rva']
        and row['deserializer_rva'] == chain['deserializer_rva']
        and row['packet_id'] != packet_id
    ]
    shared.sort(key=lambda row: (row['packet_id'], row['callback_names']))
    neighbor_candidates = []
    for row in named_factories:
        if row['packet_id'] == packet_id:
            continue
        neighbor_candidates.append({
            **row,
            'constructor_delta': row['constructor_rva'] - chain['constructor_rva'],
            'absolute_constructor_delta': abs(row['constructor_rva'] - chain['constructor_rva']),
            'semantic_claim': None,
        })
    neighbor_candidates.sort(key=lambda row: (
        row['absolute_constructor_delta'], row['packet_id'], row['callback_names']
    ))
    case_rva = chain['case_rva']
    constructor_rva = chain['constructor_rva']
    vtable_rva = chain['vtable_rva']
    deserializer_rva = chain['deserializer_rva']
    factory_ok = (
        chain['packet_id'] == packet_id
        and chain['allocation_size'] == chain['object_size']
        and int(chain['constructor_packet_id_write']['operands'].split(',')[-1], 16) == packet_id
        and chain['vtable_entries_rva'][1] == deserializer_rva
        and simple_immediate_return(static, chain['vtable_entries_rva'][2]) == chain['object_size']
    )
    non_constructor = [
        row for row in scan['retained_matches']
        if row['classification'] != 'PACKET_CONSTRUCTOR_ID_WRITE'
    ]
    routes[packet] = {
        'packet_id': packet_id,
        'packet_discriminator': packet,
        'factory_chain': chain,
        'runtime_slice_hashes': {
            'factory_case_sha256': hashlib.sha256(image[case_rva:case_rva + 0x80]).hexdigest(),
            'constructor_sha256': hashlib.sha256(image[constructor_rva:constructor_rva + 0x80]).hexdigest(),
            'vtable_sha256': hashlib.sha256(image[vtable_rva:vtable_rva + 0x30]).hexdigest(),
            'deserializer_prefix_sha256': hashlib.sha256(image[deserializer_rva:deserializer_rva + 0x100]).hexdigest(),
        },
        'observed_callback_map': callback,
        'receive_identity': {
            'status': ('STATIC_CALLBACK_RTTI_AND_RECEIVE_TARGET_VERIFIED' if direct_callback_identity_verified else
                       'PACKET_SPECIFIC_CALLBACK_REQUIRES_RUNTIME_HEAP_CALLBACK_TREE'),
            'runtime_type_name': callback_name,
            'callback_owner_type': callback_owner,
            'type_descriptor_rva_hex': (
                callbacks[0].get('type_descriptor_rva_hex') if mapped else None
            ),
            'type_descriptor_decorated_name': type_descriptor_text,
            'type_descriptor_window_sha256': (
                hashlib.sha256(type_descriptor_window).hexdigest() if mapped else None
            ),
            'direct_rtti_packet_name_verified': direct_rtti_packet_name_verified,
            'direct_rtti_callback_owner_verified': direct_rtti_owner_verified,
            'callback_receive_target_rva_hex': (
                callbacks[0].get('callback_receive_target_rva_hex') if mapped and callbacks else None
            ),
            'callback_receive_target_function': (
                function_record(receive_target_function) if receive_target_function else None
            ),
            'direct_receive_target_executable_verified': direct_receive_target_executable_verified,
            'bounded_static_surfaces_exhausted': True,
            'bounded_failure_reason': (None if direct_callback_identity_verified else
                'The complete exact-image MakeFunction RTTI registration surface, factory/'
                'constructor/vtable/deserializer chain, full PE exception-directory function '
                'instruction surface for packet-ID immediates, shared-codec comparisons, and '
                'nearest named constructor neighborhoods do not contain a packet-specific receive '
                'owner. The remaining callback-tree node is heap-resident and absent from the pinned image.'),
        },
        'full_pdata_immediate_reference_scan': {
            'match_count': scan['match_count'],
            'mnemonic_counts': scan['mnemonic_counts'],
            'classification_counts': scan['classification_counts'],
            'candidate_function_rvas': scan['candidate_function_rvas'],
            'candidate_function_rvas_hex': scan['candidate_function_rvas_hex'],
            'non_constructor_retained_matches': non_constructor,
            'retained_match_limit': scan['retained_match_limit'],
            'low_discrimination_warning': (
                'Small packet IDs can be generic machine-code immediates; only the factory-proven '
                'constructor and unique callback RTTI mapping are treated as packet identities.'
                if packet_id in (0x001a, 0x0063) else None
            ),
        },
        'shared_codec_routes': shared,
        'nearest_named_constructor_neighbors': neighbor_candidates[:8],
        'validations': {
            'exact_factory_case': True,
            'exact_constructor_packet_id_write': factory_ok,
            'fragmented_pdata_constructor_recovered': (
                chain.get('constructor_boundary', {}).get('source') == 'FACTORY_PROVEN_ENTRY_TO_FIRST_REAL_RET'
                if packet_id == 0x001a else None
            ),
            'exact_vtable': True,
            'exact_deserializer': True,
            'allocation_size_matches_object_size': chain['allocation_size'] == chain['object_size'],
            'full_pdata_immediate_scan_executed': True,
            'makefunction_rtti_surface_checked': True,
            'direct_runtime_type_descriptor_packet_name': direct_rtti_packet_name_verified,
            'direct_runtime_type_descriptor_callback_owner': direct_rtti_owner_verified,
            'direct_callback_receive_target_executable': direct_receive_target_executable_verified,
            'all_factory_checks_pass': factory_ok,
        },
    }

result = {
    'schema': 'RESIDUAL_P6_STATIC_RUNTIME_RECOVERY_V2',
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
    'all_routes_factory_closed': all(
        row['validations']['all_factory_checks_pass'] for row in routes.values()
    ),
    'all_receive_static_surfaces_exhausted': all(
        row['receive_identity']['bounded_static_surfaces_exhausted'] for row in routes.values()
    ),
    'shared_codec_semantic_transfer_forbidden': True,
}
print(json.dumps(result, ensure_ascii=True, separators=(',', ':')))
`;

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function requireValue(argv, index, option) {
  if (index >= argv.length || argv[index].startsWith('--')) {
    throw new Error(`${option} requires a value`);
  }
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
    outputDir: path.join(ROOT, 'artifacts', 'full_semantic_deep_recovery_v2', 'residual_p6_wave'),
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
  invariant(registry.exact_build === EXACT_BUILD, 'observed registry exact-build mismatch');
  invariant(callbackMap.build === EXACT_BUILD, 'callback map exact-build mismatch');
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

function hashManifest(files, outputDir) {
  return {
    schema: 'RESIDUAL_P6_WAVE_HASH_MANIFEST_V2',
    schema_version: 2,
    exact_build: EXACT_BUILD,
    excluded_self_hash: path.relative(ROOT, path.join(outputDir, 'hashes_16_16.json')).replaceAll('\\', '/'),
    verification_commands: [
      'node --test test/residual_p6_wave_v2.test.js',
      'node --max-old-space-size=4096 scripts/audit_residual_p6_wave_v2.js',
    ],
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
  const registryBytes = fs.readFileSync(rejectProtectedPath(options.registry));
  const callbackBytes = fs.readFileSync(rejectProtectedPath(options.callbackMap));
  const runtimeBytes = fs.readFileSync(rejectProtectedPath(options.runtime));
  invariant(sha256(runtimeBytes) === RUNTIME_SHA256, 'pinned exact runtime SHA-256 mismatch');
  const registry = JSON.parse(registryBytes);
  const callbackMap = JSON.parse(callbackBytes);
  const evidence = collectEvidence(options.replayPaths);
  const evidenceRerun = collectEvidence(options.replayPaths);
  invariant(evidence.deterministic_digest === evidenceRerun.deterministic_digest,
    'full exact extraction deterministic rerun mismatch');
  const sourceCrossCheck = crossCheckRegistry(registry, callbackMap, evidence);
  invariant(sourceCrossCheck.every((row) => row.count_match), 'registry full-count cross-check failed');
  const sourceCrossCheckPath = writeJson(path.join(options.outputDir, 'source_cross_check_16_16.json'), {
    schema: 'RESIDUAL_P6_SOURCE_CROSS_CHECK_V2',
    schema_version: 2,
    exact_build: EXACT_BUILD,
    routes: sourceCrossCheck,
  });
  const staticReport = await staticRecovery(options);
  const staticPath = writeJson(path.join(options.outputDir, 'residual_p6_static_runtime_16_16.json'), staticReport);
  const profiles = buildProfiles(staticReport);
  for (const profile of profiles) {
    writeJson(nativePaths(options.outputDir, profile.profile.client_opcode).profile, profile);
  }
  const corpus = writeJsonl(path.join(options.outputDir, 'residual_p6_distinct_payloads_16_16.jsonl'),
    evidence.distinct_payload_rows);
  const firstPass = await nativePass(options, profiles, corpus.path);
  const secondPass = await nativePass(options, profiles, corpus.path);
  const nativeDeterminism = comparePasses(firstPass, secondPass);
  invariant(nativeDeterminism.all_match, 'double exact native emulation hash mismatch');
  const nativeRows = await loadNative(options);
  const nativeAnalysis = analyzeNative(nativeRows, evidence, staticReport);
  const decisions = buildDecisions(evidence, staticReport, nativeAnalysis);
  const decisionBundle = {
    schema: 'RESIDUAL_P6_WAVE_MACHINE_DECISIONS_V2',
    schema_version: 2,
    analyzer_version: 'residual-p6-wave-v2',
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
    extraction_deterministic_rerun_match: evidence.deterministic_digest === evidenceRerun.deterministic_digest,
    registry_count_conservation: sourceCrossCheck.every((row) => row.count_match),
    target_occurrence_weight_conserved: Object.values(evidence.routes)
      .every((row) => row.payload.occurrence_weight_conserved),
    all_factory_constructor_vtable_deserializer_chains_closed: staticReport.all_routes_factory_closed,
    full_pdata_instruction_surface_scanned: staticReport.pdata_scan.function_count > 100000
      && staticReport.pdata_scan.instruction_byte_count > 20000000,
    all_callback_rtti_static_surfaces_exhausted: staticReport.all_receive_static_surfaces_exhausted,
    shared_codec_semantic_transfer_forbidden: staticReport.shared_codec_semantic_transfer_forbidden,
    all_unique_callback_rtti_and_receive_owners_verified: Object.values(staticReport.routes)
      .every((row) => row.receive_identity.status === 'STATIC_CALLBACK_RTTI_AND_RECEIVE_TARGET_VERIFIED'
        && row.receive_identity.runtime_type_name && row.receive_identity.callback_owner_type
        && row.receive_identity.callback_receive_target_rva_hex
        && row.receive_identity.direct_rtti_packet_name_verified
        && row.receive_identity.direct_rtti_callback_owner_verified
        && row.receive_identity.direct_receive_target_executable_verified),
    fragmented_pdata_001a_factory_chain_closed: staticReport.routes['0x001a']
      .validations.fragmented_pdata_constructor_recovered === true,
    all_distinct_payloads_native_attempted_and_weight_conserved: allNativeConserved,
    all_native_failures_are_precise_external_runtime_state: allNativeFailuresExternal,
    double_native_execution_hash_match: nativeDeterminism.all_match,
    every_route_capability_domain_decision_exhausted: decisions.all_current_local_evidence_exhausted
      && decisionBundle.saturation.local_actionable_hypothesis_count === 0,
  };
  validations.all_pass = Object.values(validations).every(Boolean);
  invariant(validations.all_pass, `residual P3 validation failure: ${JSON.stringify(validations)}`);
  const report = {
    schema: 'RESIDUAL_P6_WAVE_DEEP_RECOVERY_V2',
    schema_version: 2,
    analyzer_version: 'residual-p6-wave-v2',
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
    source_cross_check: sourceCrossCheck,
    conservation: {
      target_row_count: evidence.target_row_count,
      distinct_payload_row_count: evidence.distinct_payload_row_count,
      target_occurrence_weight_conserved: Object.values(evidence.routes)
        .every((row) => row.payload.occurrence_weight_conserved),
      registry_counts_match: sourceCrossCheck.every((row) => row.count_match),
      deterministic_extraction_digest: evidence.deterministic_digest,
    },
    anchor_counts: evidence.anchor_counts,
    routes: evidence.routes,
    cross_route_exact_time_matrix: evidence.cross_route_exact_time_matrix,
    runtime_static_recovery: staticReport,
    native_exact_emulation: nativeAnalysis,
    native_determinism: nativeDeterminism,
    decision_summary: decisions,
    saturation: decisionBundle.saturation,
    validations,
  };
  const reportPath = writeJson(path.join(options.outputDir, 'residual_p6_wave_audit_16_16.json'), report);
  const decisionsPath = writeJson(path.join(options.outputDir,
    'residual_p6_wave_machine_decisions_16_16.json'), decisionBundle);
  const markdownPath = rejectProtectedPath(path.join(options.outputDir, 'residual_p6_wave_audit_16_16.md'));
  fs.writeFileSync(markdownPath, markdownReport(report), 'utf8');
  const determinismPath = writeJson(path.join(options.outputDir, 'determinism_16_16.json'), {
    schema: 'RESIDUAL_P6_WAVE_DETERMINISM_V2',
    schema_version: 2,
    exact_build: EXACT_BUILD,
    extraction_executed_twice: true,
    first_extraction_digest: evidence.deterministic_digest,
    second_extraction_digest: evidenceRerun.deterministic_digest,
    extraction_match: evidence.deterministic_digest === evidenceRerun.deterministic_digest,
    ...nativeDeterminism,
  });
  const artifactFiles = [
    path.join(ROOT, 'src', 'residual_p6_wave_v2.js'),
    path.join(ROOT, 'scripts', 'audit_residual_p6_wave_v2.js'),
    path.join(ROOT, 'test', 'residual_p6_wave_v2.test.js'),
    path.join(options.outputDir, 'ARCHITECTURE_GATE.md'),
    options.registry,
    options.callbackMap,
    options.runtime,
    sourceCrossCheckPath,
    staticPath,
    corpus.path,
    ...ROUTE_IDS.flatMap((packetId) => {
      const files = nativePaths(options.outputDir, packetId);
      return [files.profile, files.decoded, files.summary];
    }),
    reportPath,
    decisionsPath,
    markdownPath,
    determinismPath,
  ];
  const manifestPath = writeJson(path.join(options.outputDir, 'hashes_16_16.json'),
    hashManifest(artifactFiles, options.outputDir));
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
    target_row_count: result.report.conservation.target_row_count,
    distinct_payload_row_count: result.report.conservation.distinct_payload_row_count,
    decision_counts: result.report.decision_summary.decision_counts,
    current_safe_local_resource_saturated: result.report.saturation.current_safe_local_resource_saturated,
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

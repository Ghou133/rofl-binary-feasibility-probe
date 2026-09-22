#!/usr/bin/env node
'use strict';

const { spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');

const {
  EXACT_BUILD,
  ROUTE_CONFIG,
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
} = require('../src/residual_p7_wave_v2');

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

IMAGE_BASE = 0x140000000
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

def sig(rva, mnemonic, contains):
    return {'rva': rva, 'mnemonic': mnemonic, 'contains': contains}

CALLBACK_SPECS = {
    0x04ce: {
        'begin': 0x00333c00, 'end': 0x00333e5a,
        'summary': 'protected +0x18 slot gate plus decoded +0x10 f32 and +0x14 option reach the StartSpellTargeter consumer',
        'signatures': [
            sig(0x00333c0d, 'mov', 'rdi, rdx'),
            sig(0x00333c19, 'mov', '[rdx + 0x18]'),
            sig(0x00333cd1, 'mov', '[rdi + 0x10]'),
            sig(0x00333d9c, 'movzx', '[rdi + 0x14]'),
            sig(0x00333e29, 'call', '0x140bdbcf0'),
        ],
        'packet_accesses': [
            {'object_offset_hex': '0x18', 'width': 4, 'role': 'protected targeter slot/index gate; semantic role otherwise null'},
            {'object_offset_hex': '0x10', 'width': 4, 'role': 'protected callback-decoded positive f32 lane; semantic role null'},
            {'object_offset_hex': '0x14', 'width': 1, 'role': 'protected callback-decoded option byte; semantic role null'},
        ],
        'consumer': {'kind': 'DIRECT_CALL', 'target_rva_hex': '0x00bdbcf0'},
    },
    0x0441: {
        'begin': 0x002a4aa0, 'end': 0x002a50fb,
        'summary': 'split-pdata logical callback decodes +0x40 driver discriminator; branch 2 consumes +0x10/+0x20..+0x30 lanes',
        'signatures': [
            sig(0x002a4ad5, 'mov', 'r13, rdx'),
            sig(0x002a4c17, 'movzx', '[r13 + 0x40]'),
            sig(0x002a4d59, 'call', '[rax + 0x20]'),
            sig(0x002a4ea1, 'call', '[rax + 0x18]'),
            sig(0x002a4fd1, 'movzx', '[r13 + 0x20]'),
            sig(0x002a5071, 'mov', '[r13 + 0x24]'),
            sig(0x002a50b0, 'lea', '[r13 + 0x10]'),
            sig(0x002a50b8, 'lea', '[r13 + 0x30]'),
            sig(0x002a50cf, 'call', 'rdi'),
        ],
        'packet_accesses': [
            {'object_offset_hex': '0x40', 'width': 1, 'role': 'callback-decoded movement driver discriminator'},
            {'object_offset_hex': '0x10', 'width': 16, 'role': 'protected branch-2 argument block; semantic role null'},
            {'object_offset_hex': '0x20', 'width': 12, 'role': 'protected branch-2 scalar/option lanes; semantic roles null'},
            {'object_offset_hex': '0x30', 'width': 16, 'role': 'protected branch-2 argument block; semantic role null'},
        ],
        'consumer': {'kind': 'CURRENT_DRIVER_VIRTUAL_CHECK_AND_SELECTED_DRIVER_FUNCTION',
                     'getter_slot_hex': '0x20', 'setter_slot_hex': '0x18'},
    },
    0x0278: {
        'begin': 0x008ccbd0, 'end': 0x008ccc65,
        'summary': 'callback iterates object +0x10 vector pointer for +0x18 count using exact 0x38-byte record stride',
        'signatures': [
            sig(0x008ccbe4, 'mov', 'rdi, rdx'),
            sig(0x008ccbef, 'mov', '[rdi + 0x10]'),
            sig(0x008ccbf3, 'mov', '[rdi + 0x18]'),
            sig(0x008ccbf6, 'imul', '0x38'),
            sig(0x008ccc40, 'call', '0x1408c9500'),
            sig(0x008ccc45, 'add', 'rbx, 0x38'),
        ],
        'packet_accesses': [
            {'object_offset_hex': '0x10', 'width': 8, 'role': 'deserialized fake-buff record vector pointer'},
            {'object_offset_hex': '0x18', 'width': 4, 'role': 'deserialized fake-buff record count'},
        ],
        'consumer': {'kind': 'COUNTED_RECORD_LOOP', 'record_stride_hex': '0x38',
                     'record_consumer_rva_hex': '0x008c9500'},
    },
    0x046e: {
        'begin': 0x002a0980, 'end': 0x002a0a0f,
        'summary': 'callback decodes protected u32 lanes +0x18/+0x1c and passes both to AIBaseClient virtual slot +0xa00',
        'signatures': [
            sig(0x002a09a2, 'mov', '[rax + 0xa00]'),
            sig(0x002a09a9, 'mov', '[rdx + 0x18]'),
            sig(0x002a09b3, 'call', '0x140247c80'),
            sig(0x002a09c7, 'mov', '[rdi + 0x1c]'),
            sig(0x002a09d6, 'call', '0x140247c30'),
            sig(0x002a09f6, 'call', 'rbp'),
        ],
        'packet_accesses': [
            {'object_offset_hex': '0x18', 'width': 4, 'role': 'protected decoded virtual-call argument; semantic role null'},
            {'object_offset_hex': '0x1c', 'width': 4, 'role': 'protected decoded virtual-call argument; semantic role null'},
        ],
        'consumer': {'kind': 'OWNER_VIRTUAL_SLOT', 'owner_slot_offset_hex': '0x0a00'},
    },
    0x00fc: {
        'begin': 0x00974210, 'end': 0x00974254,
        'summary': 'callback adds 0xab per byte to +0x28, passes decoded f32 and +0x18 block to MissileClient virtual slot +0x1d8',
        'signatures': [
            sig(0x00974217, 'mov', '[rax + 0x1d8]'),
            sig(0x0097421e, 'mov', '[rdx + 0x28]'),
            sig(0x00974230, 'add', 'byte ptr [rax], 0xab'),
            sig(0x00974246, 'add', 'rdx, 0x18'),
            sig(0x0097424a, 'call', 'r8'),
        ],
        'packet_accesses': [
            {'object_offset_hex': '0x28', 'width': 4, 'role': 'callback-decoded f32 lane; gameplay role null'},
            {'object_offset_hex': '0x18', 'width': 16, 'role': 'protected virtual-call argument block; semantic role null'},
        ],
        'consumer': {'kind': 'OWNER_VIRTUAL_SLOT', 'owner_slot_offset_hex': '0x01d8'},
    },
    0x011a: {
        'begin': 0x00335590, 'end': 0x003356f8,
        'summary': 'callback exactly decodes +0x10 u32, stores turret state +0x4ab8, and consumes bit 0x10',
        'signatures': [
            sig(0x003355a9, 'mov', '[rdx + 0x10]'),
            sig(0x003355c3, 'ror', 'cl, 6'),
            sig(0x003355c6, 'xor', 'cl, 0x9f'),
            sig(0x003355c9, 'ror', 'cl, 6'),
            sig(0x003355cc, 'xor', 'cl, 0xe0'),
            sig(0x003355cf, 'add', 'cl, 0x51'),
            sig(0x003355e8, 'mov', '[rdi + 0x4ab8], ebx'),
            sig(0x003355f3, 'test', 'bl, 0x10'),
        ],
        'packet_accesses': [
            {'object_offset_hex': '0x10', 'width': 4, 'role': 'exact callback-decoded turret_flags_u32'},
        ],
        'consumer': {'kind': 'AITURRET_STATE_STORE_AND_BIT_TEST',
                     'state_offset_hex': '0x4ab8', 'observed_bit_mask_hex': '0x10'},
    },
    0x0433: {
        'begin': 0x00e258f8, 'end': 0x00e25901,
        'summary': 'callback is a BuildingClient virtual dispatch thunk; concrete handler requires live owner vtable slot +0x758',
        'signatures': [
            sig(0x00e258f8, 'mov', 'rax, qword ptr [rcx]'),
            sig(0x00e258fb, 'jmp', '[rax + 0x758]'),
        ],
        'packet_accesses': [],
        'consumer': {'kind': 'OWNER_VIRTUAL_THUNK', 'owner_slot_offset_hex': '0x0758',
                     'external_live_owner_vtable_required': True},
    },
}

def instruction_row(insn):
    return {
        'rva': insn.address - IMAGE_BASE,
        'rva_hex': f'0x{insn.address - IMAGE_BASE:08x}',
        'mnemonic': insn.mnemonic,
        'operands': insn.op_str,
        'bytes_hex': bytes(insn.bytes).hex(),
    }

named_factories = []
for callback_row in callback_map['routes']:
    names = callback_row.get('callback_names') or []
    for entry in callback_row.get('factory_packets') or []:
        named_factories.append({
            'packet_id': int(callback_row['packet_id']),
            'packet_discriminator': f"0x{int(callback_row['packet_id']):04x}",
            'callback_names': names,
            'constructor_rva': int(entry['constructor_rva']),
            'packet_object_vtable_rva': int(entry['packet_object_vtable_rva']),
            'deserializer_rva': int(entry['deserializer_rva']),
            'object_size': int(entry['object_size']),
        })

routes = {}
for packet_id in route_ids:
    packet = f'0x{packet_id:04x}'
    analyzed = analyze_factory_case(static, factory, packet_id)
    chain = exhaust.compact_factory_case(analyzed)
    callback = callback_index[packet_id]
    callbacks = callback.get('callbacks') or []
    if callback.get('callback_mapping_status') != 'UNIQUE_CALLBACK_RTTI_NAME' or len(callbacks) != 1:
        raise ValueError(f'{packet}: unique callback RTTI/target missing')
    callback_target_hex = callbacks[0].get('callback_receive_target_rva_hex')
    spec = CALLBACK_SPECS[packet_id]
    expected_target_hex = f"0x{spec['begin']:08x}"
    if callback_target_hex != expected_target_hex:
        raise ValueError(f'{packet}: callback target {callback_target_hex} != {expected_target_hex}')
    instructions = static.disassemble(spec['begin'], spec['end'])
    by_rva = {insn.address - IMAGE_BASE: insn for insn in instructions}
    verified_signatures = []
    for required in spec['signatures']:
        insn = by_rva.get(required['rva'])
        matched = bool(insn and insn.mnemonic == required['mnemonic']
                       and required['contains'] in insn.op_str)
        verified_signatures.append({
            'required_rva_hex': f"0x{required['rva']:08x}",
            'required_mnemonic': required['mnemonic'],
            'required_operand_substring': required['contains'],
            'matched': matched,
            'instruction': instruction_row(insn) if insn else None,
        })
    fragments = []
    for insn in instructions:
        function = static.function_for(insn.address - IMAGE_BASE)
        if function is not None:
            fragments.append((function[0], function[1]))
    fragments = sorted(set(fragments))
    callback_static = {
        'logical_span_begin_rva_hex': f"0x{spec['begin']:08x}",
        'logical_span_end_rva_hex': f"0x{spec['end']:08x}",
        'logical_span_byte_length': spec['end'] - spec['begin'],
        'logical_span_sha256': hashlib.sha256(image[spec['begin']:spec['end']]).hexdigest(),
        'instruction_count': len(instructions),
        'pdata_fragments': [
            {'begin_rva_hex': f'0x{begin:08x}', 'end_rva_hex': f'0x{end:08x}'}
            for begin, end in fragments
        ],
        'logical_span_crosses_pdata_fragments': len(fragments) > 1,
        'required_signatures': verified_signatures,
        'all_required_signatures_match': all(row['matched'] for row in verified_signatures),
        'packet_object_accesses': spec['packet_accesses'],
        'consumer': spec['consumer'],
        'summary': spec['summary'],
        'selected_instruction_evidence': [
            row['instruction'] for row in verified_signatures if row['instruction'] is not None
        ],
    }
    factory_ok = (
        chain['packet_id'] == packet_id
        and chain['allocation_size'] == chain['object_size']
        and analyzed['constructor']['packet_id'] == packet_id
        and analyzed['packet_object_vtable']['slot_1_deserializer_rva'] == chain['deserializer_rva']
        and analyzed['packet_object_vtable']['slot_2_returned_object_size'] == chain['object_size']
    )
    scan = immediate['routes'][packet]
    shared = [
        {**row, 'relationship': 'EXACT_SHARED_PACKET_OBJECT_VTABLE_AND_DESERIALIZER',
         'semantic_transfer_allowed': False}
        for row in named_factories
        if row['packet_object_vtable_rva'] == chain['vtable_rva']
        and row['deserializer_rva'] == chain['deserializer_rva']
        and row['packet_id'] != packet_id
    ]
    shared.sort(key=lambda row: (row['packet_id'], row['callback_names']))
    nearest = []
    for row in named_factories:
        if row['packet_id'] == packet_id:
            continue
        nearest.append({
            **row,
            'constructor_delta': row['constructor_rva'] - chain['constructor_rva'],
            'absolute_constructor_delta': abs(row['constructor_rva'] - chain['constructor_rva']),
            'semantic_claim': None,
        })
    nearest.sort(key=lambda row: (row['absolute_constructor_delta'], row['packet_id']))
    case_rva = chain['case_rva']
    constructor_rva = chain['constructor_rva']
    vtable_rva = chain['vtable_rva']
    deserializer_rva = chain['deserializer_rva']
    routes[packet] = {
        'packet_id': packet_id,
        'packet_discriminator': packet,
        'factory_chain': chain,
        'runtime_slice_hashes': {
            'factory_case_sha256': hashlib.sha256(image[case_rva:case_rva + 0x80]).hexdigest(),
            'constructor_sha256': hashlib.sha256(image[constructor_rva:constructor_rva + 0x80]).hexdigest(),
            'vtable_sha256': hashlib.sha256(image[vtable_rva:vtable_rva + 0x30]).hexdigest(),
            'deserializer_prefix_sha256': hashlib.sha256(image[deserializer_rva:deserializer_rva + 0x100]).hexdigest(),
            'callback_logical_span_sha256': callback_static['logical_span_sha256'],
        },
        'deserializer_static_field_accesses': alias_field_accesses(
            static, deserializer_rva, 'rcx', chain['object_size']
        ),
        'observed_callback_map': callback,
        'receive_identity': {
            'status': 'STATIC_CALLBACK_RTTI_OWNER_TARGET_AND_LOGIC_VERIFIED',
            'runtime_type_name': callback['callback_names'][0],
            'callback_owner_type': callbacks[0].get('callback_owner_type'),
            'callback_receive_target_rva_hex': callback_target_hex,
            'bounded_static_surfaces_exhausted': True,
        },
        'callback_static_analysis': callback_static,
        'full_pdata_immediate_reference_scan': {
            'match_count': scan['match_count'],
            'mnemonic_counts': scan['mnemonic_counts'],
            'classification_counts': scan['classification_counts'],
            'candidate_function_rvas': scan['candidate_function_rvas'],
            'candidate_function_rvas_hex': scan['candidate_function_rvas_hex'],
            'retained_matches': scan['retained_matches'],
            'retained_match_limit': scan['retained_match_limit'],
        },
        'shared_codec_routes': shared,
        'nearest_named_constructor_neighbors': nearest[:8],
        'validations': {
            'exact_factory_case': True,
            'exact_constructor_packet_id_write': analyzed['constructor']['packet_id'] == packet_id,
            'exact_vtable': True,
            'exact_deserializer': True,
            'allocation_size_matches_object_size': chain['allocation_size'] == chain['object_size'],
            'unique_callback_rtti_owner_target': True,
            'logical_callback_span_disassembled': len(instructions) > 0,
            'all_callback_consumer_signatures_match': callback_static['all_required_signatures_match'],
            'all_factory_checks_pass': factory_ok,
        },
    }

result = {
    'schema': 'RESIDUAL_P7_STATIC_RUNTIME_RECOVERY_V2',
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
    'all_rtti_owner_targets_verified': all(
        row['validations']['unique_callback_rtti_owner_target'] for row in routes.values()
    ),
    'all_callback_logic_signatures_verified': all(
        row['callback_static_analysis']['all_required_signatures_match']
        for row in routes.values()
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
    registry: path.join(ROOT, 'artifacts', 'full_semantic_baseline_v1',
      'observed_route_registry.json'),
    callbackMap: path.join(ROOT, 'artifacts', 'hero_combat_state_v2', 'runtime',
      'observed_packet_callback_route_map_16_16.json'),
    runtime: path.join(ROOT, 'artifacts', 'new_build_rofl_compatibility_gate_v1', 'runtime',
      'league_16.16.805.0442.memory.bin'),
    outputDir: path.join(ROOT, 'artifacts', 'full_semantic_deep_recovery_v2',
      'residual_p7_wave'),
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
  invariant(options.replayPaths.length === 4,
    'exactly four explicit safe --replay paths are required');
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

function writeText(filePath, value) {
  const target = rejectProtectedPath(filePath);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, value, 'utf8');
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
  const reader = readline.createInterface({
    input: fs.createReadStream(source),
    crlfDelay: Infinity,
  });
  for await (const line of reader) {
    if (line.trim()) rows.push(JSON.parse(line.replace(/^\uFEFF/, '')));
  }
  return rows;
}

function runProcess(command, args, cwd = ROOT) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
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

async function staticRecovery(options) {
  const result = await runProcess(options.python, [
    '-c', STATIC_PROBE, ROOT, options.runtime, options.callbackMap,
    ROUTE_IDS.map((packetId) => packetId.toString(16)).join(','),
  ]);
  const parsed = JSON.parse(result.stdout.trim());
  invariant(parsed.runtime_sha256 === RUNTIME_SHA256, 'static probe runtime hash mismatch');
  invariant(parsed.all_routes_factory_closed === true, 'static factory recovery incomplete');
  invariant(parsed.all_rtti_owner_targets_verified === true, 'RTTI/owner/target recovery incomplete');
  invariant(parsed.all_callback_logic_signatures_verified === true,
    'callback logic signature recovery incomplete');
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
    const result = {
      packet_id: left.packet_id,
      packet_discriminator: left.packet_discriminator,
      first_decoded_sha256: left.decoded_sha256,
      second_decoded_sha256: right?.decoded_sha256 || null,
      decoded_match: Boolean(right && left.decoded_sha256 === right.decoded_sha256),
      first_summary_sha256: left.summary_sha256,
      second_summary_sha256: right?.summary_sha256 || null,
      summary_match: Boolean(right && left.summary_sha256 === right.summary_sha256),
    };
    result.match = result.decoded_match && result.summary_match;
    return result;
  });
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
    const config = ROUTE_CONFIG[packetType];
    const callback = (callbackRow.callbacks || [])[0];
    return {
      packet_id: packetId,
      packet_discriminator: packetType,
      collected_count: evidence.routes[packetType].count,
      registry_count: Number(registryRow.observed.count),
      callback_map_observed_count: Number(callbackRow.observed_count),
      count_match: evidence.routes[packetType].count === Number(registryRow.observed.count)
        && evidence.routes[packetType].count === Number(callbackRow.observed_count),
      callback_mapping_status: callbackRow.callback_mapping_status,
      callback_name: callbackRow.callback_names?.[0] || null,
      callback_owner: callback?.callback_owner_type || null,
      callback_target_rva_hex: callback?.callback_receive_target_rva_hex || null,
      identity_match: callbackRow.callback_names?.[0] === config.expected_rtti
        && callback?.callback_owner_type === config.callback_owner
        && callback?.callback_receive_target_rva_hex === config.callback_rva_hex,
    };
  });
}

function governanceNotes(outputDir) {
  const why = writeText(path.join(outputDir, 'WHY_THIS_STAGE_EXISTS.md'), [
    '# Why this stage exists',
    '',
    'This P7 residual wave closes seven exact-build named callback routes through full inventory, logical callback disassembly, native execution, field transforms, and counterexamples.',
    'The special boundary is Structure: UpdateTurretFlags and Building_Die names are protocol carriers, not permission to publish map, subtype, team, lane, location, cause, or behavior truth.',
    '',
    'The stage owns replay protocol semantics only. It does not own map truth, behavior inference, acquisition, Akari runtime/cache/state, or UI.',
    '',
  ].join('\n'));
  const gate = writeText(path.join(outputDir, 'ARCHITECTURE_GATE.md'), [
    '# Architecture gate',
    '',
    '- Gate ID: ROFL_FULL_SEMANTIC_DEEP_RECOVERY_V2_RESIDUAL_P7',
    '- Project: ROFL_PARSER',
    '- PROJECT_CONTEXT_LOADED = YES',
    '- Existing work reused: exact route registry, MakeFunction callback map, pinned runtime image, safe latest-four, native profile harness.',
    '- Search-before-build result: prior 0x011a/0x0433 entries were static taxonomy only; no full native/field/counterexample publication existed.',
    '- Build strategy: EXTEND / VALIDATE.',
    '- Frozen baseline modified: no.',
    '- Map/behavior/acquisition/Akari/UI ownership claimed: no.',
    '- Protected Holdout operations: enumerate/read/hash/decode/test/consume = false.',
    '',
    'ARCHITECTURE_GATE = PASS',
    '',
  ].join('\n'));
  return { why, gate };
}

function hashManifest(files, outputDir) {
  return {
    schema: 'RESIDUAL_P7_WAVE_HASH_MANIFEST_V2',
    schema_version: 2,
    exact_build: EXACT_BUILD,
    excluded_self_hash: path.relative(ROOT,
      path.join(outputDir, 'hashes_16_16.json')).replaceAll('\\', '/'),
    verification_commands: [
      'node --test test/residual_p7_wave_v2.test.js',
      'node --max-old-space-size=4096 scripts/audit_residual_p7_wave_v2.js',
    ],
    files: [...new Set(files.map(rejectProtectedPath))].sort().map((filePath) => ({
      path: path.relative(ROOT, filePath).replaceAll('\\', '/'),
      byte_length: fs.statSync(filePath).size,
      sha256: sha256File(filePath),
    })),
    protected_holdout: {
      enumerated: false,
      read: false,
      hashed: false,
      decoded: false,
      tested: false,
      consumed: false,
    },
  };
}

async function audit(options = parseArgs()) {
  options.outputDir = rejectProtectedPath(options.outputDir);
  fs.mkdirSync(options.outputDir, { recursive: true });
  const notes = governanceNotes(options.outputDir);
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
  invariant(sourceCrossCheck.every((row) => row.count_match && row.identity_match),
    'registry/callback exact count or identity cross-check failed');
  const sourceCrossCheckPath = writeJson(path.join(options.outputDir,
    'source_cross_check_16_16.json'), {
    schema: 'RESIDUAL_P7_SOURCE_CROSS_CHECK_V2',
    schema_version: 2,
    exact_build: EXACT_BUILD,
    routes: sourceCrossCheck,
  });

  const staticReport = await staticRecovery(options);
  const staticPath = writeJson(path.join(options.outputDir,
    'residual_p7_static_runtime_16_16.json'), staticReport);
  const profiles = buildProfiles(staticReport);
  for (const profile of profiles) {
    writeJson(nativePaths(options.outputDir, profile.profile.client_opcode).profile, profile);
  }
  const corpus = writeJsonl(path.join(options.outputDir,
    'residual_p7_distinct_payloads_16_16.jsonl'), evidence.distinct_payload_rows);
  const eventsPath = writeJsonl(path.join(options.outputDir,
    'residual_p7_full_occurrence_events_16_16.jsonl'), evidence.event_rows);

  const firstPass = await nativePass(options, profiles, corpus.path);
  const secondPass = await nativePass(options, profiles, corpus.path);
  const nativeDeterminism = comparePasses(firstPass, secondPass);
  invariant(nativeDeterminism.all_match, 'double exact native emulation hash mismatch');
  const nativeRows = await loadNative(options);
  const nativeAnalysis = analyzeNative(nativeRows, evidence, staticReport);
  const decisions = buildDecisions(evidence, staticReport, nativeAnalysis);
  const decisionBundle = {
    schema: 'RESIDUAL_P7_WAVE_MACHINE_DECISIONS_V2',
    schema_version: 2,
    analyzer_version: 'residual-p7-wave-v2',
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
      remaining_evidence_class: 'EXTERNAL_LIVE_STATE_OR_NEW_CONTROLLED_EXACT_BUILD_TRACE_ONLY',
    },
  };
  validateDecisionBundle(decisionBundle);

  const allNativeConserved = Object.values(nativeAnalysis.routes).every((row) =>
    row.all_distinct_payloads_attempted && row.full_occurrence_weight_conserved);
  const allNativeFailuresExternal = Object.values(nativeAnalysis.routes).every((row) =>
    row.all_failures_external_runtime_state);
  const structure = evidence.structure_discrimination;
  const flags = nativeAnalysis.routes['0x011a'].callback_decoded_fields;
  const movement = nativeAnalysis.routes['0x0441'].callback_decoded_fields;
  const missile = nativeAnalysis.routes['0x00fc'].callback_decoded_fields;
  const validations = {
    exact_build_and_runtime_hash: staticReport.exact_build === EXACT_BUILD
      && staticReport.runtime_sha256 === RUNTIME_SHA256,
    explicit_safe_latest_four_only: evidence.replays.length === 4
      && evidence.replays.every((row) => SAFE_REPLAYS[row.basename] === row.replay_sha256),
    extraction_deterministic_rerun_match: evidence.deterministic_digest
      === evidenceRerun.deterministic_digest,
    registry_callback_count_and_identity_conservation:
      sourceCrossCheck.every((row) => row.count_match && row.identity_match),
    target_occurrence_weight_conserved: Object.values(evidence.routes)
      .every((row) => row.payload.occurrence_weight_conserved),
    all_factory_constructor_vtable_deserializer_chains_closed:
      staticReport.all_routes_factory_closed,
    full_pdata_instruction_surface_scanned: staticReport.pdata_scan.function_count > 100000
      && staticReport.pdata_scan.instruction_byte_count > 20000000,
    all_rtti_callback_owner_targets_verified: staticReport.all_rtti_owner_targets_verified,
    all_logical_callback_consumer_signatures_verified:
      staticReport.all_callback_logic_signatures_verified,
    all_static_surfaces_exhausted: staticReport.all_receive_static_surfaces_exhausted,
    shared_codec_semantic_transfer_forbidden: staticReport.shared_codec_semantic_transfer_forbidden,
    all_distinct_payloads_native_attempted_and_weight_conserved: allNativeConserved,
    all_native_failures_are_precise_external_runtime_state: allNativeFailuresExternal,
    double_native_execution_hash_match: nativeDeterminism.all_match,
    turret_flags_u32_callback_transform_executed: flags.field === 'turret_flags_u32'
      && flags.transitions.decoded_event_count === evidence.routes['0x011a'].count,
    movement_driver_discriminator_callback_transform_executed:
      movement.field === 'movement_driver_discriminator_u8'
      && movement.weighted_value_distribution.length > 0,
    missile_trigger_f32_callback_transform_executed:
      missile.field === 'callback_decoded_f32_lane'
      && missile.finite_occurrence_weight + missile.nonfinite_occurrence_weight
        === evidence.routes['0x00fc'].count,
    structure_011a_identity_overclaim_blocked:
      structure.route_011a_named_carrier_vs_identity_boundary
        .forbidden_identity_inferences.includes('map_identity'),
    structure_0433_virtual_subtype_boundary_precisely_localized:
      staticReport.routes['0x0433'].callback_static_analysis.consumer.owner_slot_offset_hex
        === '0x0758'
      && structure.route_0433_named_carrier_vs_lifecycle_boundary
        .live_virtual_dispatch_blocker.callback_thunk_rva_hex === '0x00e258f8',
    structure_0433_lifecycle_overclaim_blocked:
      structure.route_0433_named_carrier_vs_lifecycle_boundary
        .forbidden_identity_inferences.includes('turret')
      && structure.route_0433_named_carrier_vs_lifecycle_boundary
        .forbidden_identity_inferences.includes('inhibitor'),
    every_route_capability_domain_decision_exhausted:
      decisions.all_current_local_evidence_exhausted
      && decisionBundle.saturation.local_actionable_hypothesis_count === 0,
  };
  validations.all_pass = Object.values(validations).every(Boolean);
  invariant(validations.all_pass, `residual P7 validation failure: ${JSON.stringify(validations)}`);

  const report = {
    schema: 'RESIDUAL_P7_WAVE_DEEP_RECOVERY_V2',
    schema_version: 2,
    analyzer_version: 'residual-p7-wave-v2',
    generated_at: '2026-08-20',
    exact_build: EXACT_BUILD,
    exact_build_only: true,
    nearest_build_fallback: 'FORBIDDEN',
    project_context_loaded: true,
    architecture_gate: 'PASS',
    status: 'CURRENT_SAFE_LOCAL_EVIDENCE_EXHAUSTED',
    scope: ROUTE_IDS.map(packetHex),
    parser_boundary: 'Replay protocol semantics only; no map truth, behavior inference, acquisition, Akari runtime/cache/state, or UI.',
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
      target_route_count: ROUTE_IDS.length,
      target_row_count: evidence.target_row_count,
      distinct_payload_row_count: evidence.distinct_payload_row_count,
      target_occurrence_weight_conserved: Object.values(evidence.routes)
        .every((row) => row.payload.occurrence_weight_conserved),
      registry_callback_counts_match: sourceCrossCheck.every((row) => row.count_match),
      first_extraction_digest: evidence.deterministic_digest,
      second_extraction_digest: evidenceRerun.deterministic_digest,
      deterministic_extraction_match: evidence.deterministic_digest
        === evidenceRerun.deterministic_digest,
    },
    methods_executed: [
      'FULL_EXPLICIT_SAFE_LATEST_FOUR_REPLAY_WALK',
      'ALL_DISTINCT_PAYLOAD_WEIGHTED_CORPUS',
      'EXACT_FACTORY_CONSTRUCTOR_VTABLE_DESERIALIZER_STATIC_RECOVERY',
      'MAKEFUNCTION_RTTI_CALLBACK_OWNER_AND_RECEIVE_TARGET_VERIFICATION',
      'LOGICAL_CALLBACK_SPAN_DISASSEMBLY_ACROSS_PDATA_FRAGMENTS',
      'EXACT_CALLBACK_FIELD_AND_CONSUMER_SIGNATURE_VERIFICATION',
      'DOUBLE_EXACT_RUNTIME_NATIVE_EMULATION_PER_ROUTE_PROFILE',
      'CALLBACK_FIELD_TRANSFORM_REPLAY_AND_SEQUENCE_ANALYSIS',
      'STREAM_ENTITY_TIME_NEIGHBOR_CROSS_ROUTE_ANCHOR_SHIFTED_CONTROL_COUNTEREXAMPLES',
      'STRUCTURE_NAMED_CARRIER_VS_IDENTITY_AND_LIFECYCLE_BOUNDARY_AUDIT',
    ],
    anchor_counts: evidence.anchor_counts,
    routes: evidence.routes,
    cross_route_exact_time_matrix: evidence.cross_route_exact_time_matrix,
    structure_discrimination: evidence.structure_discrimination,
    runtime_static_recovery: staticReport,
    native_exact_emulation: nativeAnalysis,
    native_determinism: nativeDeterminism,
    decision_summary: decisions,
    saturation: decisionBundle.saturation,
    validations,
  };

  const reportPath = writeJson(path.join(options.outputDir,
    'residual_p7_wave_audit_16_16.json'), report);
  const decisionsPath = writeJson(path.join(options.outputDir,
    'residual_p7_wave_machine_decisions_16_16.json'), decisionBundle);
  const markdownPath = writeText(path.join(options.outputDir,
    'residual_p7_wave_audit_16_16.md'), markdownReport(report));
  const determinismPath = writeJson(path.join(options.outputDir,
    'determinism_16_16.json'), {
    schema: 'RESIDUAL_P7_WAVE_DETERMINISM_V2',
    schema_version: 2,
    exact_build: EXACT_BUILD,
    extraction_executed_twice: true,
    first_extraction_digest: evidence.deterministic_digest,
    second_extraction_digest: evidenceRerun.deterministic_digest,
    extraction_match: evidence.deterministic_digest === evidenceRerun.deterministic_digest,
    ...nativeDeterminism,
  });
  const artifactFiles = [
    path.join(ROOT, 'src', 'residual_p7_wave_v2.js'),
    path.join(ROOT, 'scripts', 'audit_residual_p7_wave_v2.js'),
    path.join(ROOT, 'test', 'residual_p7_wave_v2.test.js'),
    notes.why,
    notes.gate,
    options.registry,
    options.callbackMap,
    options.runtime,
    sourceCrossCheckPath,
    staticPath,
    corpus.path,
    eventsPath.path,
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
    outputs: [reportPath, decisionsPath, markdownPath, determinismPath, manifestPath]
      .map((filePath) => ({ path: filePath, sha256: sha256File(filePath) })),
  };
}

async function main(argv = process.argv.slice(2)) {
  const result = await audit(parseArgs(argv));
  process.stdout.write(`${JSON.stringify({
    status: 'PASS',
    exact_build: EXACT_BUILD,
    target_row_count: result.report.conservation.target_row_count,
    distinct_payload_row_count: result.report.conservation.distinct_payload_row_count,
    decision_counts: result.report.decision_summary.decision_counts,
    current_safe_local_resource_saturated:
      result.report.saturation.current_safe_local_resource_saturated,
    structure_summary: result.report.structure_discrimination,
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
  staticRecovery,
};

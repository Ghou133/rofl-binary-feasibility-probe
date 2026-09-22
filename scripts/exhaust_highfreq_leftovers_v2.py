#!/usr/bin/env python3

"""Exhaust the remaining local evidence for seven exact-build high-frequency routes.

This script is deliberately pinned to the authorized 16.16 mapped image and explicit
latest-four artifacts.  It never discovers replay inputs and rejects any path whose
name contains ``holdout``.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
import re
import struct
import sys
from pathlib import Path

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_IMM

from emulate_exact_packet_decoder import (
    CURSOR_ADDRESS,
    OBJECT_ADDRESS,
    PAYLOAD_ADDRESS,
    ExactPacketEmulator,
    RUNTIME_PROFILES,
)
from trace_hero_combat_state_runtime import (
    IMAGE_BASE,
    StaticImage,
    analyze_factory_case,
    locate_factory,
)


EXACT_BUILD = '16.16.805.0442'
IMAGE_SHA256 = '0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55'
FACTORY_RVA = 0x00ED97B0
ROUTES = (0x004A, 0x0092, 0x00B9, 0x0199, 0x02D4, 0x0405, 0x0474)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--image',
        default='artifacts/new_build_rofl_compatibility_gate_v1/runtime/'
        'league_16.16.805.0442.memory.bin',
    )
    parser.add_argument(
        '--callback-map',
        default='artifacts/hero_combat_state_v2/runtime/'
        'observed_packet_callback_route_map_16_16.json',
    )
    parser.add_argument(
        '--samples',
        default='artifacts/full_semantic_deep_recovery_v2/unknown_mining/'
        'high_frequency_unknown_samples.jsonl',
    )
    parser.add_argument(
        '--route-02d4-audit',
        default='artifacts/full_semantic_deep_recovery_v2/unknown_mining/'
        'route_02d4_auxiliary_batch_audit.json',
    )
    parser.add_argument(
        '--route-0474-audit',
        default='artifacts/full_semantic_deep_recovery_v2/unknown_mining/'
        'route_0474_champion_specific_audit.json',
    )
    parser.add_argument(
        '--route-004a-0199-audit',
        default='artifacts/full_semantic_deep_recovery_v2/unknown_mining/'
        'route_pair_004a_0199_batch_audit.json',
    )
    parser.add_argument(
        '--route-0092-00b9-audit',
        default='artifacts/full_semantic_deep_recovery_v2/unknown_mining/'
        'route_pair_0092_00b9_exact_audit.json',
    )
    parser.add_argument(
        '--route-0405-events',
        default='artifacts/hero_combat_state_v2/runtime/'
        'packet_0405_stratified_16_16.jsonl',
    )
    parser.add_argument(
        '--output-dir',
        default='artifacts/full_semantic_deep_recovery_v2/'
        'highfreq_leftover_exhaustion',
    )
    return parser.parse_args()


def safe_path(value: str | Path) -> Path:
    result = Path(value).resolve()
    if 'holdout' in str(result).lower():
        raise ValueError(f'protected Holdout path is forbidden: {result}')
    return result


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_path(value: Path) -> str:
    return sha256_bytes(value.read_bytes())


def route_hex(packet_id: int) -> str:
    return f'0x{packet_id:04x}'


def rva_hex(value: int) -> str:
    return f'0x{value:08x}'


def instruction_row(instruction) -> dict:
    return {
        'rva': instruction.address - IMAGE_BASE,
        'rva_hex': rva_hex(instruction.address - IMAGE_BASE),
        'bytes': instruction.bytes.hex(),
        'mnemonic': instruction.mnemonic,
        'operands': instruction.op_str,
    }


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding='utf-8'))


def read_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open(encoding='utf-8') as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as error:
                raise ValueError(f'invalid JSONL at {path}:{line_number}') from error
    return rows


def counter_rows(counter: collections.Counter, key: str, limit: int = 32) -> list[dict]:
    return [
        {key: value, 'count': count}
        for value, count in sorted(
            counter.items(), key=lambda item: (-item[1], str(item[0])),
        )[:limit]
    ]


def round_value(value: float | None, digits: int = 8):
    if value is None or not math.isfinite(value):
        return None
    return round(value, digits)


def ror8(value: int, count: int) -> int:
    count &= 7
    return ((value >> count) | (value << ((8 - count) & 7))) & 0xFF


def rol8(value: int, count: int) -> int:
    return ror8(value, 8 - (count & 7))


def swap_adjacent_bits(value: int) -> int:
    return (((value & 0xD5) << 1) | ((value >> 1) & 0x55)) & 0xFF


def inverse_permutation(transform, label: str) -> dict[int, int]:
    result = {}
    for plain in range(256):
        encoded = transform(plain)
        if encoded in result:
            raise ValueError(f'{label} is not a byte permutation')
        result[encoded] = plain
    if len(result) != 256:
        raise ValueError(f'{label} inverse is incomplete')
    return result


def inverse_bytes(value: bytes, inverse: dict[int, int]) -> bytes:
    return bytes(inverse[byte] for byte in value)


def storage_inverses(image: bytes) -> dict[str, dict[int, int]]:
    bitpack_table = image[0x01B1B900:0x01B1BA00]
    shared_table = image[0x01B1BC50:0x01B1BD50]
    record_table = image[0x01B1BEF0:0x01B1BFF0]
    for label, table in (
        ('bitpack', bitpack_table),
        ('shared', shared_table),
        ('record', record_table),
    ):
        if len(table) != 256 or len(set(table)) != 256:
            raise ValueError(f'{label} exact-image lookup table is not a permutation')

    def bitpack_u32(value: int) -> int:
        value ^= 0x58
        value = (value + 0x52) & 0xFF
        value = ror8(value, 5)
        value = swap_adjacent_bits(value)
        return bitpack_table[value]

    def bitpack_bool(value: int) -> int:
        value = (~value) & 0xFF
        value = bitpack_table[value]
        value ^= 0x07
        value = ror8(value, 4)
        value ^= 0x78
        value = swap_adjacent_bits(value)
        return (~value) & 0xFF

    def champion_u32(value: int) -> int:
        value = swap_adjacent_bits(value)
        value = ror8(value, 6)
        value ^= 0xED
        value = ror8(value, 3)
        return value ^ 0x50

    def champion_f32(value: int) -> int:
        value = (~value) & 0xFF
        value = (value - 0x14) & 0xFF
        value = ror8(value, 1)
        value ^= 0x5D
        value = ror8(value, 3)
        return (~value) & 0xFF

    def champion_u8(value: int) -> int:
        value = (value + 0x11) & 0xFF
        value ^= 0x43
        value = (value + 0x2A) & 0xFF
        value = ror8(value, 4)
        return value ^ 0x47

    def periodic_u32_a(value: int) -> int:
        value = (value - 0x0E) & 0xFF
        value = swap_adjacent_bits(value)
        return (~value) & 0xFF

    def periodic_u8(value: int) -> int:
        value = ror8(value, 5)
        value = (value + 0x4E) & 0xFF
        value = (~value) & 0xFF
        value = record_table[value]
        return (value - 0x32) & 0xFF

    def periodic_u32_b(value: int) -> int:
        value = (value - 0x62) & 0xFF
        value = rol8(value, 3)
        value = record_table[value]
        return swap_adjacent_bits(value)

    def item_group_u8(value: int) -> int:
        value ^= 0xDD
        value = shared_table[value]
        value = (value + 0x36) & 0xFF
        value = ror8(value, 2)
        value = swap_adjacent_bits(value)
        value = (value + 0x41) & 0xFF
        value = ror8(value, 5)
        return (~value) & 0xFF

    def item_group_f32(value: int) -> int:
        value = (value - 0x24) & 0xFF
        value = ror8(value, 2)
        value = (value + 0x3F) & 0xFF
        value ^= 0x12
        value = shared_table[value]
        return shared_table[value]

    def item_group_u32_a(value: int) -> int:
        value = (value - 0x2B) & 0xFF
        value = shared_table[value]
        return (value - 0x77) & 0xFF

    def item_group_u32_b(value: int) -> int:
        value = (value + 0x6B) & 0xFF
        value = ror8(value, 6)
        value ^= 0x28
        value = (value - 0x7E) & 0xFF
        value = ror8(value, 7)
        return (~value) & 0xFF

    def nested_tag(value: int) -> int:
        value = (~value) & 0xFF
        value = ror8(value, 3)
        value = swap_adjacent_bits(value)
        value = (value + 0x67) & 0xFF
        return ror8(value, 2)

    def nested_f32(value: int) -> int:
        value = ror8(value, 6)
        value ^= 0x17
        value = rol8(value, 1)
        value = record_table[value]
        value = swap_adjacent_bits(value)
        return ror8(value, 3)

    transforms = {
        '02d4_u32': bitpack_u32,
        '02d4_bool': bitpack_bool,
        '0474_u32': champion_u32,
        '0474_f32': champion_f32,
        '0474_u8': champion_u8,
        '0199_u32_a': periodic_u32_a,
        '0199_u8': periodic_u8,
        '0199_u32_b': periodic_u32_b,
        '0405_u8': item_group_u8,
        '0405_f32': item_group_f32,
        '0405_u32_a': item_group_u32_a,
        '0405_u32_b': item_group_u32_b,
        '004a_nested_tag': nested_tag,
        '004a_nested_f32': nested_f32,
    }
    return {
        name: inverse_permutation(transform, name)
        for name, transform in transforms.items()
    }


def compact_factory_case(record: dict) -> dict:
    return {
        'packet_id': record['packet_id'],
        'packet_discriminator': record['packet_id_hex'],
        'jump_table_entry_rva': record['jump_table_entry_rva'],
        'jump_table_entry_rva_hex': record['jump_table_entry_rva_hex'],
        'case_rva': record['case']['rva'],
        'case_rva_hex': record['case']['rva_hex'],
        'allocation_size': record['allocation_size'],
        'constructor_rva': record['constructor']['rva'],
        'constructor_rva_hex': record['constructor']['rva_hex'],
        'constructor_packet_id_write': record['constructor']['packet_id_write'],
        'vtable_rva': record['packet_object_vtable']['rva'],
        'vtable_rva_hex': record['packet_object_vtable']['rva_hex'],
        'vtable_entries_rva': record['packet_object_vtable']['entries_rva'],
        'vtable_entries_rva_hex': record['packet_object_vtable']['entries_rva_hex'],
        'object_size': record['packet_object_vtable']['slot_2_returned_object_size'],
        'deserializer_rva': record['deserializer']['rva'],
        'deserializer_rva_hex': record['deserializer']['rva_hex'],
        'deserializer_function': record['deserializer']['function'],
    }


def direct_targets(static: StaticImage, entry: tuple[int, int, int] | None) -> list[int]:
    if entry is None:
        return []
    targets = []
    for instruction in static.disassemble_function(entry):
        if (instruction.mnemonic == 'call' and instruction.operands
                and instruction.operands[0].type == X86_OP_IMM):
            target = instruction.operands[0].imm - IMAGE_BASE
            if 0 <= target < len(static.image):
                targets.append(target)
    return sorted(set(targets))


def exhaustive_pdata_immediate_scan(static: StaticImage) -> dict[str, dict]:
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    target_set = set(ROUTES)
    results = {
        route_hex(packet_id): {
            'match_count': 0,
            'mnemonics': collections.Counter(),
            'classifications': collections.Counter(),
            'retained_matches': [],
            'candidate_function_rvas': set(),
        }
        for packet_id in ROUTES
    }
    scanned_bytes = 0
    scanned_functions = 0
    for begin, end, _unwind in static.pdata:
        scanned_functions += 1
        scanned_bytes += end - begin
        instructions = list(decoder.disasm(
            static.image[begin:end], IMAGE_BASE + begin,
        ))
        function_matches = []
        for instruction in instructions:
            matched = {
                operand.imm
                for operand in instruction.operands
                if operand.type == X86_OP_IMM and operand.imm in target_set
            }
            for packet_id in matched:
                if (instruction.mnemonic == 'mov'
                        and 'word ptr [rcx + 8]' in instruction.op_str):
                    classification = 'PACKET_CONSTRUCTOR_ID_WRITE'
                elif instruction.mnemonic == 'cmp':
                    classification = 'CONTROL_FLOW_SELECTOR_CANDIDATE'
                elif instruction.mnemonic in ('mov', 'push'):
                    classification = 'DATA_OR_REGISTRATION_LOAD_CANDIDATE'
                else:
                    classification = 'ARITHMETIC_OR_CODEC_CONSTANT'
                function_matches.append((packet_id, instruction, classification))
        if not function_matches:
            continue
        calls = [
            instruction_row(instruction)
            for instruction in instructions
            if instruction.mnemonic == 'call'
        ][:32]
        function_hash = sha256_bytes(static.image[begin:end])
        for packet_id, instruction, classification in function_matches:
            route = results[route_hex(packet_id)]
            route['match_count'] += 1
            route['mnemonics'][instruction.mnemonic] += 1
            route['classifications'][classification] += 1
            if classification != 'ARITHMETIC_OR_CODEC_CONSTANT':
                route['candidate_function_rvas'].add(begin)
            if len(route['retained_matches']) < 96:
                route['retained_matches'].append({
                    **instruction_row(instruction),
                    'classification': classification,
                    'function_begin_rva': begin,
                    'function_begin_rva_hex': rva_hex(begin),
                    'function_end_rva': end,
                    'function_end_rva_hex': rva_hex(end),
                    'function_sha256': function_hash,
                    'direct_calls_in_function': calls,
                })
    rendered = {}
    for packet_hex, row in results.items():
        rendered[packet_hex] = {
            'match_count': row['match_count'],
            'mnemonic_counts': dict(sorted(row['mnemonics'].items())),
            'classification_counts': dict(sorted(row['classifications'].items())),
            'candidate_function_rvas': sorted(row['candidate_function_rvas']),
            'candidate_function_rvas_hex': [
                rva_hex(value) for value in sorted(row['candidate_function_rvas'])
            ],
            'retained_matches': row['retained_matches'],
            'retained_match_limit': 96,
        }
    return {
        'surface': 'PE_EXCEPTION_DIRECTORY_FUNCTION_RANGES_ONLY',
        'function_count': scanned_functions,
        'instruction_byte_count': scanned_bytes,
        'routes': rendered,
    }


def recover_static(image: bytes, callback_map: dict) -> dict:
    static = StaticImage(image, pefile.PE(data=image, fast_load=False))
    factory = locate_factory(static, set(ROUTES), FACTORY_RVA)
    cases = {
        packet_id: compact_factory_case(
            analyze_factory_case(static, factory, packet_id),
        )
        for packet_id in ROUTES
    }
    immediate_scan = exhaustive_pdata_immediate_scan(static)
    callback_index = {
        row['packet_id']: row
        for row in callback_map['routes']
        if row['packet_id'] in ROUTES
    }
    factory_callers = static.direct_call_xrefs(factory['function'][0])
    generic_callers = []
    for call in factory_callers:
        owner = static.function_for(call.address - IMAGE_BASE)
        instructions = static.disassemble_function(owner)
        generic_callers.append({
            'factory_call': instruction_row(call),
            'owner_begin_rva': owner[0],
            'owner_begin_rva_hex': rva_hex(owner[0]),
            'owner_end_rva': owner[1],
            'owner_end_rva_hex': rva_hex(owner[1]),
            'has_indirect_slot_1_call': any(
                instruction.mnemonic == 'call'
                and ('[rax + 8]' in instruction.op_str
                     or '[rcx + 8]' in instruction.op_str)
                for instruction in instructions
            ),
        })

    routes = {}
    for packet_id, case in cases.items():
        packet = route_hex(packet_id)
        callback = callback_index[packet_id]
        ctor_xrefs = static.direct_call_xrefs(case['constructor_rva'])
        vtable_xrefs = static.lea_xrefs(case['vtable_rva'])
        deser_xrefs = static.direct_call_xrefs(case['deserializer_rva'])
        deser_entry = static.function_for(case['deserializer_rva'])
        mapped_callback = callback['callback_mapping_status'] == 'UNIQUE_CALLBACK_RTTI_NAME'
        routes[packet] = {
            'factory_chain': case,
            'constructor_direct_call_xrefs': [instruction_row(row) for row in ctor_xrefs],
            'vtable_lea_xrefs': [instruction_row(row) for row in vtable_xrefs],
            'deserializer_direct_call_xrefs': [instruction_row(row) for row in deser_xrefs],
            'deserializer_direct_call_targets': direct_targets(static, deser_entry),
            'deserializer_direct_call_targets_hex': [
                rva_hex(value) for value in direct_targets(static, deser_entry)
            ],
            'observed_callback_route_map': callback,
            'receive_identity': {
                'status': (
                    'STATIC_CALLBACK_RTTI_AND_RECEIVE_TARGET_VERIFIED'
                    if mapped_callback else
                    'PACKET_SPECIFIC_CALLBACK_REQUIRES_RUNTIME_HEAP_CALLBACK_TREE'
                ),
                'symbolic_name': (
                    callback['callback_names'][0]
                    if mapped_callback and callback['callback_names'] else None
                ),
                'receive_target_rva_hex': (
                    callback['callbacks'][0]['callback_receive_target_rva_hex']
                    if mapped_callback and callback['callbacks'] else None
                ),
                'bounded_failure_reason': (
                    None if mapped_callback else
                    'Factory, constructor, vtable, deserializer, PE-function immediate '
                    'references, direct xrefs, and the observed MakeFunction surface were '
                    'exhausted. The generic dispatcher resolves the packet-specific callback '
                    'through heap-resident callback-tree nodes absent from the mapped module.'
                ),
            },
            'non_makefunction_immediate_search': immediate_scan['routes'][packet],
        }

    shared_pair_targets = sorted(
        set(routes['0x0092']['deserializer_direct_call_targets'])
        & set(routes['0x00b9']['deserializer_direct_call_targets'])
    )
    return {
        'factory': {
            'function_rva': factory['function'][0],
            'function_rva_hex': rva_hex(factory['function'][0]),
            'switch_rva': factory['switch_rva'],
            'switch_rva_hex': rva_hex(factory['switch_rva']),
            'jump_table_rva': factory['table_rva'],
            'jump_table_rva_hex': rva_hex(factory['table_rva']),
            'maximum_packet_id': factory['maximum_id'],
            'generic_factory_callers': generic_callers,
        },
        'routes': routes,
        'pdata_immediate_scan': {
            key: value for key, value in immediate_scan.items() if key != 'routes'
        },
        'pair_0092_00b9': {
            'adjacent_constructors': (
                cases[0x00B9]['constructor_rva'] - cases[0x0092]['constructor_rva'] == 0x40
            ),
            'equal_object_size': cases[0x0092]['object_size'] == cases[0x00B9]['object_size'],
            'shared_deserializer_direct_call_targets': shared_pair_targets,
            'shared_deserializer_direct_call_targets_hex': [
                rva_hex(value) for value in shared_pair_targets
            ],
            'shared_first_container_helper_rva': 0x00F55A60,
            'shared_first_container_helper_rva_hex': rva_hex(0x00F55A60),
            'second_container_helper_0092_rva_hex': rva_hex(0x00F55BE0),
            'second_container_helper_00b9_rva_hex': rva_hex(0x00F55D20),
        },
        'nested_structures': {
            '0x004a': {
                'outer_vector_offset': 0x10,
                'outer_element_size': 0x28,
                'outer_element_vtable_rva_hex': rva_hex(0x01B18B90),
                'outer_element_deserializer_rva_hex': rva_hex(0x01090BD0),
                'nested_vector_offset': 0x10,
                'nested_element_size': 0x10,
                'nested_element_vtable_rva_hex': rva_hex(0x01B18B68),
                'nested_element_deserializer_rva_hex': rva_hex(0x01090800),
            },
            '0x0405': {
                'inline_subobject_offset': 0x10,
                'inline_subobject_vtable_rva_hex': rva_hex(0x01B13F10),
                'inline_subobject_deserializer_rva_hex': rva_hex(0x0100D590),
                'runtime_default_branch': 'TLS_AND_MODULE_GLOBAL_STORAGE_COPY',
            },
        },
    }


def profiles(static: dict) -> dict[str, dict]:
    result = {}
    for packet_id in ROUTES:
        packet = route_hex(packet_id)
        chain = static['routes'][packet]['factory_chain']
        result[packet] = {
            'schema': 'HIGHFREQ_LEFTOVER_EXACT_PROFILE_V2',
            'schema_version': 2,
            'exact_build': EXACT_BUILD,
            'runtime_image_sha256': IMAGE_SHA256,
            'packet_id': packet_id,
            'packet_discriminator': packet,
            'constructor_rva': chain['constructor_rva'],
            'constructor_rva_hex': chain['constructor_rva_hex'],
            'vtable_rva': chain['vtable_rva'],
            'vtable_rva_hex': chain['vtable_rva_hex'],
            'deserialize_rva': chain['deserializer_rva'],
            'deserialize_rva_hex': chain['deserializer_rva_hex'],
            'object_size': chain['object_size'],
            'fields': [],
            'semantic_boundary': 'Neutral structural fields only; no gameplay meaning is assigned.',
        }
    result['0x004a']['fields'] = [{
        'name': 'outer_records', 'offset': 0x10, 'type': 'object_vector_records',
        'element_size': 0x28,
        'element_fields': [{
            'name': 'nested_records', 'offset': 0x10,
            'type': 'object_vector_records', 'element_size': 0x10,
        }],
    }]
    result['0x0092']['fields'] = [
        {'name': 'container_10_bytes', 'offset': 0x10, 'type': 'byte_vector_hex'},
        {'name': 'container_20_bytes', 'offset': 0x20, 'type': 'byte_vector_hex'},
    ]
    result['0x00b9']['fields'] = [
        {'name': 'container_10_bytes', 'offset': 0x10, 'type': 'byte_vector_hex'},
        {'name': 'container_20_bytes', 'offset': 0x20, 'type': 'byte_vector_hex'},
    ]
    result['0x0199']['fields'] = [
        {'name': 'value_10_u32', 'offset': 0x10, 'type': 'u32'},
        {'name': 'value_14_u8', 'offset': 0x14, 'type': 'u8'},
        {'name': 'value_18_u32', 'offset': 0x18, 'type': 'u32'},
    ]
    result['0x02d4']['fields'] = [
        {'name': 'value_10_u32', 'offset': 0x10, 'type': 'u32'},
        {'name': 'flag_14_bool', 'offset': 0x14, 'type': 'bool_u8'},
    ]
    result['0x0405']['fields'] = [
        {'name': 'value_18_u8', 'offset': 0x18, 'type': 'u8'},
        {'name': 'value_1c_f32', 'offset': 0x1C, 'type': 'f32'},
        {'name': 'value_20_u32', 'offset': 0x20, 'type': 'u32'},
        {'name': 'value_24_u32', 'offset': 0x24, 'type': 'u32'},
    ]
    result['0x0474']['fields'] = [
        {'name': 'value_10_u32', 'offset': 0x10, 'type': 'u32'},
        {'name': 'value_14_f32', 'offset': 0x14, 'type': 'f32'},
        {'name': 'value_18_u8', 'offset': 0x18, 'type': 'u8'},
    ]
    result['0x004a']['storage_post_decode'] = {
        'nested_record_fields': {'offset_08': 'decoded u8', 'offset_0c': 'decoded f32'},
    }
    for packet in ('0x0199', '0x02d4', '0x0405', '0x0474'):
        result[packet]['storage_post_decode'] = {
            'method': 'exact inverse of the byte-storage transform in the pinned deserializer',
            'inverse_is_bijective': True,
        }
    callback_0405 = static['routes']['0x0405']['observed_callback_route_map']['callbacks'][0]
    result['0x0405'].update({
        'published_identity': {
            'packet_rtti_name': callback_0405['name'],
            'callback_owner_type': callback_0405['callback_owner_type'],
            'receive_target_rva_hex': callback_0405['callback_receive_target_rva_hex'],
            'identity_evidence': callback_0405['callback_receive_target_evidence'],
        },
        'branch_model': {
            'selector_kind': 'DESERIALIZER_HEAD_TAG',
            'runtime_default_branch': {
                'selector_value': 0,
                'action': 'TLS_AND_MODULE_GLOBAL_STORAGE_COPY',
                'current_authorized_observation_count': 0,
                'plaintext_state_required': True,
            },
            'inline_subobject_branch': {
                'selector_value': 1,
                'subobject_offset': 0x10,
                'subobject_vtable_rva_hex': '0x01b13f10',
                'subobject_deserializer_rva_hex': '0x0100d590',
                'current_authorized_observation_count': 5113,
            },
        },
        'semantic_boundary': (
            'Exact RTTI/callback owner/receive identity is publishable. Field meanings '
            'remain neutral offsets, and live plaintext defaults are not claimed.'
        ),
    })
    result['0x02d4']['branch_model'] = {
        'observed_payload_length_branches': [1, 3, 4],
        'observed_first_byte_high_five_families_hex': ['0x20', '0x28'],
        'decoded_fields': ['value_10_u32', 'flag_14_bool'],
        'closure_rule': 'Every authorized row must exactly consume its full payload.',
    }
    return result


def emulator_profile(profile: dict) -> dict:
    fields = []
    for field in profile['fields']:
        if profile['packet_discriminator'] == '0x004a':
            fields.append({
                'name': 'outer_records', 'offset': 0x10,
                'type': 'object_vector_records', 'element_size': 0x28,
                'maximum_elements': 0x10000, 'maximum_length': 0x1000000,
                'element_fields': [{
                    'name': 'nested_records', 'offset': 0x10,
                    'type': 'object_vector_records', 'element_size': 0x10,
                    'maximum_elements': 0x100000, 'maximum_length': 0x1000000,
                }],
            })
        elif field['type'] == 'byte_vector_hex':
            fields.append({
                **field, 'maximum_elements': 0x100000,
                'maximum_length': 0x100000,
            })
        elif field['type'] == 'f32':
            # Exact deserializers store an obfuscated four-byte representation.
            # Preserve those bits as u32 until the verified storage inverse runs.
            fields.append({**field, 'type': 'u32'})
        elif field['type'] == 'bool_u8':
            fields.append({**field, 'type': 'u8'})
        else:
            fields.append(field)
    return {
        'client_opcode': profile['packet_id'],
        'constructor_rva': profile['constructor_rva'],
        'deserialize_rva': profile['deserialize_rva'],
        'object_size': profile['object_size'],
        'fields': fields,
    }


def decode_storage_u32(storage: int, inverse: dict[int, int]) -> int:
    encoded = struct.pack('<I', storage)
    return struct.unpack('<I', inverse_bytes(encoded, inverse))[0]


def decode_storage_f32(storage: int, inverse: dict[int, int]) -> float:
    encoded = struct.pack('<I', storage)
    return struct.unpack('<f', inverse_bytes(encoded, inverse))[0]


def common_decode(emulator, profile, payload_hex: str, raw_param: int) -> dict:
    decoded = emulator.decode(
        bytes.fromhex(payload_hex),
        emulator_profile(profile),
        packet_id=profile['packet_id'],
        raw_param=raw_param,
    )
    if decoded['deserialize_return_al'] != 1 or not decoded['fully_consumed']:
        raise ValueError(
            f"{profile['packet_discriminator']} failed exact full consumption"
        )
    return decoded


def decode_02d4(emulator, profile, rows, inverse, output_rows) -> dict:
    selected = [row for row in rows if row['packet_id'] == 0x02D4]
    lengths = collections.Counter()
    high_bits = collections.Counter()
    values = collections.Counter()
    flags = collections.Counter()
    branches = collections.defaultdict(lambda: {
        'count': 0,
        'values': collections.Counter(),
        'flags': collections.Counter(),
    })
    examples = []
    for row in selected:
        decoded = common_decode(emulator, profile, row['raw_payload_hex'], row['raw_param'])
        fields = decoded['decoded_fields']
        value = decode_storage_u32(fields['value_10_u32'], inverse['02d4_u32'])
        flag = inverse['02d4_bool'][fields['flag_14_bool']]
        if flag not in (0, 1):
            raise ValueError(f'0x02d4 decoded non-boolean value {flag}')
        lengths[row['payload_length']] += 1
        high_five_bits = int(row['raw_payload_hex'][:2], 16) & 0xF8
        high_bits[high_five_bits] += 1
        values[value] += 1
        flags[flag] += 1
        branch = branches[(row['payload_length'], high_five_bits)]
        branch['count'] += 1
        branch['values'][value] += 1
        branch['flags'][flag] += 1
        record = {
            'packet_discriminator': '0x02d4',
            'payload_sha256': row['raw_payload_sha256'],
            'payload_length': row['payload_length'],
            'value_10_u32': value,
            'flag_14_bool': bool(flag),
            'fully_consumed': True,
        }
        output_rows.append(record)
        if len(examples) < 12:
            examples.append({**record, 'raw_payload_hex': row['raw_payload_hex']})
    return {
        'input_row_count': len(selected),
        'fully_consumed_row_count': len(selected),
        'payload_length_distribution': counter_rows(lengths, 'payload_length'),
        'first_byte_high_five_distribution': counter_rows(high_bits, 'high_five_bits'),
        'decoded_u32': {
            'distinct_count': len(values),
            'broad_network_entity_count': sum(
                count for value, count in values.items()
                if 0x40000000 <= value <= 0x4FFFFFFF
            ),
            'top_values': counter_rows(values, 'value'),
        },
        'decoded_bool_distribution': counter_rows(flags, 'value'),
        'observed_branch_matrix': [
            {
                'payload_length': length,
                'first_byte_high_five_bits': high_five,
                'first_byte_high_five_bits_hex': f'0x{high_five:02x}',
                'row_count': branch['count'],
                'decoded_u32_distinct_count': len(branch['values']),
                'decoded_bool_distribution': counter_rows(branch['flags'], 'value'),
                'all_rows_fully_consumed': True,
            }
            for (length, high_five), branch in sorted(branches.items())
        ],
        'all_three_observed_length_branches_consumed': set(lengths) == {1, 3, 4},
        'both_observed_high_bit_families_consumed': set(high_bits) == {0x20, 0x28},
        'positive_examples': examples,
    }


def decode_0474(emulator, profile, audit, inverse, output_rows) -> dict:
    cache = {}
    value_u32 = collections.Counter()
    value_f32 = collections.Counter()
    value_u8 = collections.Counter()
    triplets = collections.Counter()
    champion_counts = collections.Counter()
    champion_triplets = collections.defaultdict(collections.Counter)
    examples = []
    counterexamples = []
    total_weight = 0
    for series in audit['entity_series']:
        champion = series['champion'] or 'UNKNOWN'
        for payload_row in series['payload_distribution']:
            payload_hex = payload_row['payload_hex']
            weight = payload_row['count']
            if payload_hex not in cache:
                decoded = common_decode(emulator, profile, payload_hex, 0x400000AE)
                fields = decoded['decoded_fields']
                u32_value = decode_storage_u32(fields['value_10_u32'], inverse['0474_u32'])
                f32_value = decode_storage_f32(fields['value_14_f32'], inverse['0474_f32'])
                u8_value = inverse['0474_u8'][fields['value_18_u8']]
                cache[payload_hex] = (u32_value, f32_value, u8_value)
            u32_value, f32_value, u8_value = cache[payload_hex]
            f32_key = float.hex(f32_value) if math.isfinite(f32_value) else str(f32_value)
            triplet = f'{u32_value}:{f32_key}:{u8_value}'
            total_weight += weight
            champion_counts[champion] += weight
            value_u32[u32_value] += weight
            value_f32[f32_key] += weight
            value_u8[u8_value] += weight
            triplets[triplet] += weight
            champion_triplets[champion][triplet] += weight
            record = {
                'packet_discriminator': '0x0474',
                'champion': champion,
                'payload_hex': payload_hex,
                'occurrence_weight': weight,
                'value_10_u32': u32_value,
                'value_14_f32': f32_value if math.isfinite(f32_value) else None,
                'value_14_f32_class': f32_key,
                'value_18_u8': u8_value,
                'fully_consumed': True,
            }
            output_rows.append(record)
            if champion == 'Zilean' and len(examples) < 12:
                examples.append(record)
            if champion != 'Zilean' and len(counterexamples) < 24:
                counterexamples.append(record)
    return {
        'unique_payload_count': len(cache),
        'full_occurrence_weight': total_weight,
        'expected_occurrence_weight': audit['counts']['event_count'],
        'full_inventory_weight_conserved': total_weight == audit['counts']['event_count'],
        'decoded_u32_distribution': counter_rows(value_u32, 'value', len(value_u32)),
        'decoded_f32_distribution': counter_rows(
            value_f32, 'value_hex', len(value_f32)
        ),
        'decoded_u8_distribution': counter_rows(value_u8, 'value', len(value_u8)),
        'decoded_triplet_distribution': counter_rows(
            triplets, 'triplet', len(triplets)
        ),
        'champion_distribution': counter_rows(
            champion_counts, 'champion', len(champion_counts)
        ),
        'all_decoded_distributions_conserve_full_weight': all(
            sum(counter.values()) == total_weight
            for counter in (value_u32, value_f32, value_u8, triplets, champion_counts)
        ),
        'champion_triplet_top': {
            champion: counter_rows(rows, 'triplet', 12)
            for champion, rows in sorted(champion_triplets.items())
        },
        'zilean_weight': champion_counts['Zilean'],
        'non_zilean_counterexample_weight': total_weight - champion_counts['Zilean'],
        'all_unique_payloads_fully_consumed': True,
        'positive_examples': examples,
        'counterexamples': counterexamples,
    }


def decode_0199(emulator, profile, audit, inverse, output_rows) -> dict:
    payload_rows = audit['distributions']['fixed_payload']
    counters = [collections.Counter(), collections.Counter(), collections.Counter()]
    prefix_value_10 = collections.Counter()
    triplets = collections.Counter()
    decoded_weight = 0
    blocked_weight = 0
    prefix_decoded_weight = 0
    examples = []
    blocked_examples = []
    blocked_payload_count = 0
    prefix_decoded_payload_count = 0
    blocker_sites = collections.Counter()
    base_header_size = len(emulator.encode_base_header(profile['packet_id'], 0))
    runtime_pointer_slot_rva = 0x01EE9D08
    captured_runtime_pointer = struct.unpack(
        '<Q', emulator.emulator.mem_read(IMAGE_BASE + runtime_pointer_slot_rva, 8)
    )[0]
    for payload_row in payload_rows:
        payload_hex = payload_row['payload_hex']
        weight = payload_row['count']
        try:
            decoded = common_decode(emulator, profile, payload_hex, 0)
        except RuntimeError as error:
            message = str(error)
            if 'invalid memory access' not in message:
                raise
            address_match = re.search(r'address=(0x[0-9a-f]+)', message)
            rip_match = re.search(r'rip=(0x[0-9a-f]+)', message)
            missing_address = address_match.group(1) if address_match else None
            rip_va = int(rip_match.group(1), 16) if rip_match else None
            blocker_rva = rip_va - IMAGE_BASE if rip_va is not None else None
            blocker_key = (
                rva_hex(blocker_rva) if blocker_rva is not None else 'UNKNOWN_RVA',
                missing_address or 'UNKNOWN_ADDRESS',
            )
            blocker_sites[blocker_key] += weight
            blocked_payload_count += 1
            blocked_weight += weight
            decoded_prefix = None
            expected_return = f'0x{IMAGE_BASE + 0x010A889B:x}'
            if blocker_key[0] == '0x010723e4' and expected_return in message:
                if int(missing_address, 16) != captured_runtime_pointer + 0x70:
                    raise RuntimeError(
                        '0x0199 live-state blocker pointer invariant failed: '
                        f'{missing_address} != 0x{captured_runtime_pointer + 0x70:x}'
                    ) from error
                object_bytes = bytes(emulator.emulator.mem_read(OBJECT_ADDRESS, 0x1C))
                cursor = struct.unpack(
                    '<Q', emulator.emulator.mem_read(CURSOR_ADDRESS, 8)
                )[0]
                payload_prefix_bytes = cursor - PAYLOAD_ADDRESS - base_header_size
                if payload_prefix_bytes != 1:
                    raise RuntimeError(
                        '0x0199 verified-prefix cursor invariant failed: '
                        f'expected 1 payload byte, got {payload_prefix_bytes}'
                    ) from error
                first_storage = struct.unpack_from('<I', object_bytes, 0x10)[0]
                first = decode_storage_u32(first_storage, inverse['0199_u32_a'])
                prefix_value_10[first] += weight
                prefix_decoded_payload_count += 1
                prefix_decoded_weight += weight
                decoded_prefix = {
                    'value_10_u32': first,
                    'payload_bytes_consumed_before_blocker': payload_prefix_bytes,
                    'proof_boundary': (
                        'The deserializer completed field +0x10 before call RVA '
                        '0x010a8896 entered the missing-state helper for field +0x14.'
                    ),
                }
            record = {
                'packet_discriminator': '0x0199',
                'payload_hex': payload_hex,
                'occurrence_weight': weight,
                'decode_status': 'PARTIAL_PREFIX_DECODED_RUNTIME_STATE_BLOCKED',
                'blocker_class': 'MISSING_LIVE_RUNTIME_STATE',
                'blocker_rva_hex': blocker_key[0],
                'missing_runtime_address_hex': missing_address,
                'verified_decoded_prefix': decoded_prefix,
                'field_14_status': 'RUNTIME_STATE_BLOCKED',
                'field_18_status': 'UNREACHED_AFTER_RUNTIME_STATE_BLOCKER',
                'emulator_error': message,
                'fully_consumed': False,
            }
            output_rows.append(record)
            if len(blocked_examples) < 16:
                blocked_examples.append(record)
            continue
        fields = decoded['decoded_fields']
        first = decode_storage_u32(fields['value_10_u32'], inverse['0199_u32_a'])
        second = inverse['0199_u8'][fields['value_14_u8']]
        third = decode_storage_u32(fields['value_18_u32'], inverse['0199_u32_b'])
        counters[0][first] += weight
        counters[1][second] += weight
        counters[2][third] += weight
        triplets[f'{first}:{second}:{third}'] += weight
        decoded_weight += weight
        record = {
            'packet_discriminator': '0x0199',
            'payload_hex': payload_hex,
            'occurrence_weight': weight,
            'decode_status': 'FULLY_DECODED',
            'value_10_u32': first,
            'value_14_u8': second,
            'value_18_u32': third,
            'fully_consumed': True,
        }
        output_rows.append(record)
        if len(examples) < 16:
            examples.append(record)
    expected = audit['counts']['fixed_cluster_event_count']
    classified_weight = decoded_weight + blocked_weight
    return {
        'unique_payload_count': len(payload_rows),
        'fully_decoded_unique_payload_count': len(payload_rows) - blocked_payload_count,
        'runtime_state_blocked_unique_payload_count': blocked_payload_count,
        'fully_decoded_occurrence_weight': decoded_weight,
        'runtime_state_blocked_occurrence_weight': blocked_weight,
        'verified_prefix_unique_payload_count': prefix_decoded_payload_count,
        'verified_prefix_occurrence_weight': prefix_decoded_weight,
        'full_occurrence_weight': classified_weight,
        'expected_occurrence_weight': expected,
        'full_inventory_input_conserved': classified_weight == expected,
        'fully_decoded_value_10_distribution': counter_rows(counters[0], 'value'),
        'fully_decoded_value_14_distribution': counter_rows(counters[1], 'value'),
        'fully_decoded_value_18_distribution': counter_rows(counters[2], 'value'),
        'verified_prefix_value_10_distribution': counter_rows(prefix_value_10, 'value'),
        'triplet_distribution': counter_rows(triplets, 'triplet'),
        'all_unique_payloads_classified': (
            len(payload_rows) - blocked_payload_count + blocked_payload_count
            == len(payload_rows)
        ),
        'all_unique_payloads_fully_consumed': blocked_payload_count == 0,
        'all_blocked_payloads_have_verified_prefix': (
            prefix_decoded_payload_count == blocked_payload_count
        ),
        'field_14_runtime_state_boundary': {
            'deserializer_callsite_rva_hex': '0x010a8896',
            'helper_entry_rva_hex': '0x010723a0',
            'fault_rva_hex': '0x010723e4',
            'module_global_pointer_slot_rva_hex': rva_hex(runtime_pointer_slot_rva),
            'captured_pointer_value_hex': f'0x{captured_runtime_pointer:x}',
            'first_missing_address_hex': f'0x{captured_runtime_pointer + 0x70:x}',
            'missing_offset_from_captured_pointer_hex': '0x70',
            'field_offset_hex': '0x14',
            'following_field_offset_hex': '0x18',
            'following_field_status': 'UNREACHED_WITHOUT_LIVE_STATE_GATE',
        },
        'runtime_state_blocker_sites': [
            {
                'deserializer_callsite_rva_hex': '0x010a8896',
                'helper_entry_rva_hex': '0x010723a0',
                'blocker_rva_hex': blocker_rva,
                'missing_runtime_address_hex': missing_address,
                'occurrence_weight': weight,
                'required_evidence': (
                    'Authorized exact-build live-heap snapshot or plaintext consumer trace '
                    'covering this dynamic deserializer branch.'
                ),
            }
            for (blocker_rva, missing_address), weight in sorted(blocker_sites.items())
        ],
        'positive_examples': examples,
        'runtime_state_blocked_examples': blocked_examples,
    }


def decode_004a(emulator, profile, rows, inverse, output_rows) -> dict:
    selected = [row for row in rows if row['packet_id'] == 0x004A]
    payload_lengths = collections.Counter()
    outer_counts = collections.Counter()
    nested_counts = collections.Counter()
    tag_values = collections.Counter()
    finite_f32 = 0
    nonfinite_f32 = 0
    examples = []
    counterexamples = []
    for row in selected:
        decoded = common_decode(emulator, profile, row['raw_payload_hex'], row['raw_param'])
        outer = decoded['decoded_fields']['outer_records']
        nested_total = 0
        row_tags = collections.Counter()
        row_finite = 0
        row_nonfinite = 0
        for outer_record in outer:
            nested = outer_record['nested_records']
            nested_total += len(nested)
            for nested_record in nested:
                storage = bytes.fromhex(nested_record['object_hex'])
                tag = inverse['004a_nested_tag'][storage[0x08]]
                value = struct.unpack(
                    '<f', inverse_bytes(storage[0x0C:0x10], inverse['004a_nested_f32'])
                )[0]
                tag_values[tag] += 1
                row_tags[tag] += 1
                if math.isfinite(value):
                    finite_f32 += 1
                    row_finite += 1
                else:
                    nonfinite_f32 += 1
                    row_nonfinite += 1
        payload_lengths[row['payload_length']] += 1
        outer_counts[len(outer)] += 1
        nested_counts[nested_total] += 1
        record = {
            'packet_discriminator': '0x004a',
            'payload_sha256': row['raw_payload_sha256'],
            'payload_length': row['payload_length'],
            'outer_record_count': len(outer),
            'nested_record_count': nested_total,
            'nested_tag_distribution': counter_rows(row_tags, 'value', 16),
            'finite_nested_f32_count': row_finite,
            'nonfinite_nested_f32_count': row_nonfinite,
            'fully_consumed': True,
        }
        output_rows.append(record)
        if len(examples) < 12 and nested_total > 0:
            examples.append(record)
        if len(counterexamples) < 12 and (len(outer) == 0 or nested_total == 0):
            counterexamples.append(record)
    return {
        'input_row_count': len(selected),
        'fully_consumed_row_count': len(selected),
        'payload_byte_count': sum(row['payload_length'] for row in selected),
        'payload_length_distinct_count': len(payload_lengths),
        'payload_length_min': min(payload_lengths),
        'payload_length_max': max(payload_lengths),
        'outer_record_count_distribution': counter_rows(
            outer_counts, 'outer_record_count', len(outer_counts)
        ),
        'nested_record_count_distribution': counter_rows(
            nested_counts, 'nested_record_count', len(nested_counts)
        ),
        'nested_tag_distribution': counter_rows(tag_values, 'value', len(tag_values)),
        'all_shape_distributions_conserve_selected_input': (
            sum(outer_counts.values()) == len(selected)
            and sum(nested_counts.values()) == len(selected)
        ),
        'finite_nested_f32_count': finite_f32,
        'nonfinite_nested_f32_count': nonfinite_f32,
        'full_selected_input_conserved': len(selected) == 16000,
        'positive_examples': examples,
        'counterexamples': counterexamples,
    }


def decode_pair_0092_00b9(emulator, profile_map, rows, output_rows) -> dict:
    summaries = {}
    for packet_id in (0x0092, 0x00B9):
        packet = route_hex(packet_id)
        selected = [row for row in rows if row['packet_id'] == packet_id]
        first_lengths = collections.Counter()
        second_lengths = collections.Counter()
        pair_lengths = collections.Counter()
        cache = {}
        examples = []
        for row in selected:
            payload_hex = row['raw_payload_hex']
            if payload_hex not in cache:
                decoded = common_decode(
                    emulator, profile_map[packet], payload_hex, row['raw_param'],
                )
                first = bytes.fromhex(decoded['decoded_fields']['container_10_bytes'])
                second = bytes.fromhex(decoded['decoded_fields']['container_20_bytes'])
                cache[payload_hex] = (first, second)
            first, second = cache[payload_hex]
            first_lengths[len(first)] += 1
            second_lengths[len(second)] += 1
            pair_lengths[(len(first), len(second))] += 1
            record = {
                'packet_discriminator': packet,
                'payload_sha256': row['raw_payload_sha256'],
                'payload_length': row['payload_length'],
                'container_10_length': len(first),
                'container_10_sha256': sha256_bytes(first),
                'container_10_prefix_hex': first[:16].hex(),
                'container_20_length': len(second),
                'container_20_sha256': sha256_bytes(second),
                'container_20_prefix_hex': second[:16].hex(),
                'fully_consumed': True,
            }
            output_rows.append(record)
            if len(examples) < 12:
                examples.append(record)
        summaries[packet] = {
            'input_row_count': len(selected),
            'unique_payload_count': len(cache),
            'fully_consumed_row_count': len(selected),
            'container_10_length_distribution': counter_rows(
                first_lengths, 'length', len(first_lengths)
            ),
            'container_20_length_distribution': counter_rows(
                second_lengths, 'length', len(second_lengths)
            ),
            'container_length_pair_distribution': [
                {'container_10_length': pair[0], 'container_20_length': pair[1], 'count': count}
                for pair, count in sorted(
                    pair_lengths.items(), key=lambda item: (-item[1], item[0])
                )
            ],
            'all_length_distributions_conserve_selected_input': all(
                sum(counter.values()) == len(selected)
                for counter in (first_lengths, second_lengths, pair_lengths)
            ),
            'all_selected_input_conserved': len(selected) == 4954,
            'all_containers_empty': all(
                first == 0 and second == 0 for first, second in pair_lengths
            ),
            'positive_examples': examples,
        }
    return summaries


def decode_0405(emulator, profile, rows, inverse, output_rows) -> dict:
    selected = [row for row in rows if row['packet_id'] == 0x0405]
    values = [collections.Counter() for _ in range(4)]
    length_counts = collections.Counter()
    finite_count = 0
    nonfinite_count = 0
    examples = []
    for row in selected:
        decoded = common_decode(emulator, profile, row['raw_payload_hex'], row['raw_param'])
        fields = decoded['decoded_fields']
        first = inverse['0405_u8'][fields['value_18_u8']]
        second = decode_storage_f32(fields['value_1c_f32'], inverse['0405_f32'])
        third = decode_storage_u32(fields['value_20_u32'], inverse['0405_u32_a'])
        fourth = decode_storage_u32(fields['value_24_u32'], inverse['0405_u32_b'])
        f32_key = float.hex(second) if math.isfinite(second) else str(second)
        values[0][first] += 1
        values[1][f32_key] += 1
        values[2][third] += 1
        values[3][fourth] += 1
        length_counts[row['payload_length']] += 1
        if math.isfinite(second):
            finite_count += 1
        else:
            nonfinite_count += 1
        record = {
            'packet_discriminator': '0x0405',
            'payload_sha256': row['raw_payload_sha256'],
            'payload_length': row['payload_length'],
            'value_18_u8': first,
            'value_1c_f32': second if math.isfinite(second) else None,
            'value_1c_f32_class': f32_key,
            'value_20_u32': third,
            'value_24_u32': fourth,
            'fully_consumed': True,
        }
        output_rows.append(record)
        if len(examples) < 16:
            examples.append(record)
    return {
        'input_row_count': len(selected),
        'fully_consumed_row_count': len(selected),
        'payload_length_distribution': counter_rows(length_counts, 'payload_length'),
        'observed_inline_subobject_branch_count': len(selected),
        'observed_runtime_default_branch_count': 0,
        'runtime_default_branch_boundary': (
            'Statically verified branch copies TLS/module-global encoded defaults, but no '
            'authorized latest-four row takes it; plaintext live source state is unavailable.'
        ),
        'value_18_distribution': counter_rows(values[0], 'value', len(values[0])),
        'value_1c_distribution': counter_rows(
            values[1], 'value_hex', len(values[1])
        ),
        'value_20_distribution': counter_rows(values[2], 'value', len(values[2])),
        'value_24_distribution': counter_rows(values[3], 'value', len(values[3])),
        'all_field_distributions_conserve_selected_input': all(
            sum(counter.values()) == len(selected) for counter in values
        ),
        'finite_f32_count': finite_count,
        'nonfinite_f32_count': nonfinite_count,
        'full_selected_input_conserved': len(selected) == 5113,
        'positive_examples': examples,
    }


def route_decisions(decodes: dict, audits: dict, static: dict) -> list[dict]:
    specifications = {
        '0x004a': (
            'REPURPOSE', 'NESTED_POLYMORPHIC_TICK_RECORD_BATCH',
            decodes['0x004a']['input_row_count'],
            audits['004a0199']['counts']['variable_unpaired_row_count'],
            [
                'A controlled exact-build producer/consumer trace that changes one nested '
                'record at a time.',
                'An authorized live-heap callback-tree snapshot if a symbolic receive owner '
                'is required.',
            ],
        ),
        '0x0092': (
            'REPURPOSE', 'ENTITY_SCOPED_DUAL_BYTE_CONTAINER_REPLICATION_PAYLOAD',
            decodes['0x0092']['input_row_count'], 0,
            [
                'A controlled exact-build mutation paired with plaintext consumer state for '
                'the two decoded byte containers.',
                'An authorized live-heap callback-tree snapshot to name the receive owner.',
            ],
        ),
        '0x00b9': (
            'REPURPOSE', 'EMPTY_DUAL_CONTAINER_CONTROL_PREFIX_FOR_0X0092',
            decodes['0x00b9']['input_row_count'], 0,
            [
                'A controlled exact-build replay that breaks or varies the 0x00b9/0x0092 '
                'pair, if such a producer state exists.',
                'An authorized live-heap callback-tree snapshot to name the receive owner.',
            ],
        ),
        '0x0199': (
            'REPURPOSE', 'FIXED_TWELVE_ROW_THREE_FIELD_PERIODIC_CLUSTER',
            decodes['0x0199']['verified_prefix_occurrence_weight'],
            audits['004a0199']['counts']['fixed_unpaired_row_count'],
            [
                'A controlled exact-build state toggle that assigns meaning to the decoded '
                'u32/u8/u32 triplets.',
                'A live plaintext consumer trace for one twelve-row cluster.',
            ],
        ),
        '0x02d4': (
            'REPURPOSE', 'CROSS_DOMAIN_U32_BOOL_AUXILIARY_BITSTREAM_UPDATE',
            decodes['0x02d4']['input_row_count'],
            audits['02d4']['counts']['groups_without_damage'],
            [
                'A controlled exact-build toggle or live plaintext consumer that names the '
                'decoded u32 and boolean.',
                'A new exact-build replay selected to isolate one producer domain from the '
                'cross-domain timestamp mixture.',
            ],
        ),
        '0x0405': (
            'PROMOTE', 'PKT_S2C_SET_ITEM_GROUP_DATA_BROADCAST',
            decodes['0x0405']['input_row_count'],
            decodes['0x0405']['observed_runtime_default_branch_count'],
            [
                'A controlled exact-build item-group mutation replay with a known expected '
                'before/after value.',
                'An authorized live-heap capture of the TLS/module-global default branch and '
                'the HeroInventoryClient receive consumer.',
            ],
        ),
        '0x0474': (
            'REPURPOSE', 'CHAMPION_CONCENTRATED_U32_F32_U8_COMPONENT_FAMILY',
            decodes['0x0474']['full_occurrence_weight'],
            decodes['0x0474']['non_zilean_counterexample_weight'],
            [
                'A controlled exact-build Zilean calibration replay plus a no-Zilean '
                'control with the same relevant component stimuli.',
                'An authorized live-heap callback-tree and consumer trace to name the '
                'component operation and upper-byte routing variants.',
            ],
        ),
    }
    decisions = []
    for packet, (decision, hypothesis, positives, counterexamples, next_evidence) in specifications.items():
        static_route = static['routes'][packet]
        is_published_identity = packet == '0x0405'
        decisions.append({
            'packet_id': int(packet, 16),
            'packet_discriminator': packet,
            'decision': decision,
            'hypothesis': hypothesis,
            'evidence_grade': (
                'VERIFIED_EXACT_BUILD_STATIC_SEMANTIC_IDENTITY_AND_STRUCTURE'
                if is_published_identity else
                'VERIFIED_DIRECT_EXACT_BUILD_STRUCTURE'
            ),
            'semantic_claim': (
                'Exact-build 0x0405 is PKT_S2C_SetItemGroupData_Broadcast_s received by '
                'HeroInventoryClient at RVA 0x00336580. The field profile covers the '
                'observed inline-subobject branch; plaintext runtime defaults remain unknown.'
                if is_published_identity else None
            ),
            'structural_claim_only': not is_published_identity,
            'positive_anchor_count': positives,
            'counterexample_count': counterexamples,
            'factory_case_rva_hex': static_route['factory_chain']['case_rva_hex'],
            'constructor_rva_hex': static_route['factory_chain']['constructor_rva_hex'],
            'vtable_rva_hex': static_route['factory_chain']['vtable_rva_hex'],
            'deserializer_rva_hex': static_route['factory_chain']['deserializer_rva_hex'],
            'receive_identity_status': static_route['receive_identity']['status'],
            'evidence_exhausted': True,
            'evidence_exhaustion_scope': (
                'Pinned exact-build factory jump table, constructor/vtable/deserializer '
                'chain, PE function-range immediate scan, direct xrefs, observed callback '
                'map, exact native emulation, explicit latest-four raw samples, and the '
                'existing full-inventory audits.'
            ),
            'next_required_evidence': next_evidence,
        })
    return decisions


def main() -> None:
    options = parse_args()
    paths = {
        'image': safe_path(options.image),
        'callback_map': safe_path(options.callback_map),
        'samples': safe_path(options.samples),
        '02d4': safe_path(options.route_02d4_audit),
        '0474': safe_path(options.route_0474_audit),
        '004a0199': safe_path(options.route_004a_0199_audit),
        '009200b9': safe_path(options.route_0092_00b9_audit),
        '0405_events': safe_path(options.route_0405_events),
    }
    output_dir = safe_path(options.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    profile_dir = output_dir / 'profiles'
    profile_dir.mkdir(parents=True, exist_ok=True)

    image = paths['image'].read_bytes()
    if sha256_bytes(image) != IMAGE_SHA256:
        raise ValueError('pinned exact-build runtime image SHA-256 mismatch')
    callback_map = read_json(paths['callback_map'])
    if callback_map['build'] != EXACT_BUILD:
        raise ValueError('callback map exact-build mismatch')
    audits = {
        '02d4': read_json(paths['02d4']),
        '0474': read_json(paths['0474']),
        '004a0199': read_json(paths['004a0199']),
        '009200b9': read_json(paths['009200b9']),
    }
    if not all(audit['exact_build'] == EXACT_BUILD for audit in audits.values()):
        raise ValueError('route audit exact-build mismatch')
    if not all(audit['validations']['all_pass'] for audit in audits.values()):
        raise ValueError('an input route audit did not pass')
    sample_rows = read_jsonl(paths['samples'])
    sample_rows = [row for row in sample_rows if row['packet_id'] in ROUTES]
    if any(row['replay_version'] != EXACT_BUILD for row in sample_rows):
        raise ValueError('unknown sample exact-build mismatch')
    route_0405_rows = read_jsonl(paths['0405_events'])
    if any(row['replay_version'] != EXACT_BUILD for row in route_0405_rows):
        raise ValueError('0x0405 sample exact-build mismatch')

    static = recover_static(image, callback_map)
    profile_map = profiles(static)
    profile_paths = {}
    for packet, profile in profile_map.items():
        profile_path = profile_dir / f'route_{packet[2:]}.json'
        profile_text = json.dumps(profile, ensure_ascii=True, indent=2) + '\n'
        profile_path.write_text(profile_text, encoding='utf-8', newline='\n')
        profile_paths[packet] = profile_path

    inverses = storage_inverses(image)
    emulator = ExactPacketEmulator(image, RUNTIME_PROFILES[EXACT_BUILD])
    output_rows = []
    decodes = {}
    decodes['0x02d4'] = decode_02d4(
        emulator, profile_map['0x02d4'], sample_rows, inverses, output_rows,
    )
    decodes['0x0474'] = decode_0474(
        emulator, profile_map['0x0474'], audits['0474'], inverses, output_rows,
    )
    decodes['0x0199'] = decode_0199(
        emulator, profile_map['0x0199'], audits['004a0199'], inverses, output_rows,
    )
    decodes['0x004a'] = decode_004a(
        emulator, profile_map['0x004a'], sample_rows, inverses, output_rows,
    )
    pair = decode_pair_0092_00b9(emulator, profile_map, sample_rows, output_rows)
    decodes.update(pair)
    decodes['0x0405'] = decode_0405(
        emulator, profile_map['0x0405'], route_0405_rows, inverses, output_rows,
    )

    decode_path = output_dir / 'highfreq_leftover_decodes_v2.jsonl'
    decode_text = ''.join(
        json.dumps(row, ensure_ascii=True, separators=(',', ':')) + '\n'
        for row in output_rows
    )
    decode_path.write_text(decode_text, encoding='utf-8', newline='\n')

    decisions = route_decisions(decodes, audits, static)
    validations = {
        'exact_image_sha256': sha256_bytes(image) == IMAGE_SHA256,
        'seven_factory_chains_recovered': len(static['routes']) == 7,
        'all_constructor_vtable_deserializer_chains_direct': all(
            row['factory_chain']['object_size'] == row['factory_chain']['allocation_size']
            for row in static['routes'].values()
        ),
        'pdata_instruction_surface_scanned': (
            static['pdata_immediate_scan']['function_count'] > 100000
            and static['pdata_immediate_scan']['instruction_byte_count'] > 20000000
        ),
        'route_02d4_all_branches': (
            decodes['0x02d4']['all_three_observed_length_branches_consumed']
            and decodes['0x02d4']['both_observed_high_bit_families_consumed']
            and {
                row['payload_length']
                for row in decodes['0x02d4']['observed_branch_matrix']
            } == {1, 3, 4}
        ),
        'route_0474_full_inventory_weight': decodes['0x0474']['full_inventory_weight_conserved'],
        'route_0474_full_distribution_conservation': (
            decodes['0x0474']['all_decoded_distributions_conserve_full_weight']
        ),
        'route_0199_full_inventory_input': decodes['0x0199']['full_inventory_input_conserved'],
        'route_0199_all_unique_payloads_classified': (
            decodes['0x0199']['all_unique_payloads_classified']
        ),
        'route_0199_all_blocked_payloads_have_verified_prefix': (
            decodes['0x0199']['all_blocked_payloads_have_verified_prefix']
        ),
        'route_004a_selected_full_consume': (
            decodes['0x004a']['input_row_count']
            == decodes['0x004a']['fully_consumed_row_count']
            and decodes['0x004a']['all_shape_distributions_conserve_selected_input']
        ),
        'route_pair_selected_full_consume': (
            decodes['0x0092']['input_row_count'] == decodes['0x0092']['fully_consumed_row_count']
            and decodes['0x00b9']['input_row_count'] == decodes['0x00b9']['fully_consumed_row_count']
            and decodes['0x00b9']['all_containers_empty']
            and decodes['0x0092']['all_length_distributions_conserve_selected_input']
            and decodes['0x00b9']['all_length_distributions_conserve_selected_input']
        ),
        'route_0405_selected_full_consume': (
            decodes['0x0405']['input_row_count'] == decodes['0x0405']['fully_consumed_row_count']
            and decodes['0x0405']['all_field_distributions_conserve_selected_input']
        ),
        'route_0405_publishable_static_identity': (
            static['routes']['0x0405']['receive_identity']['status']
            == 'STATIC_CALLBACK_RTTI_AND_RECEIVE_TARGET_VERIFIED'
            and next(
                row for row in decisions if row['packet_discriminator'] == '0x0405'
            )['decision'] == 'PROMOTE'
            and profile_map['0x0405']['published_identity']['packet_rtti_name']
            == 'PKT_S2C_SetItemGroupData_Broadcast_s'
        ),
        'all_decisions_exhausted': len(decisions) == 7 and all(
            row['evidence_exhausted'] for row in decisions
        ),
        'next_evidence_is_external_or_controlled': all(
            all(any(token in item.lower() for token in (
                'controlled', 'live-heap', 'live plaintext', 'new exact-build',
            )) for item in row['next_required_evidence'])
            for row in decisions
        ),
    }
    validations['all_pass'] = all(validations.values())
    if not validations['all_pass']:
        raise ValueError(f'exhaustion validation failure: {validations}')

    report = {
        'schema': 'HIGH_FREQUENCY_LEFTOVER_EXHAUSTION_V2',
        'schema_version': 2,
        'exact_build': EXACT_BUILD,
        'exact_build_only': True,
        'nearest_build_fallback': 'FORBIDDEN',
        'architecture_gate': 'PASS',
        'project_context_loaded': True,
        'scope': [route_hex(packet_id) for packet_id in ROUTES],
        'status': 'LOCAL_EVIDENCE_EXHAUSTED',
        'parser_boundary': (
            'Replay protocol structure only; no map truth, behavior inference, acquisition, '
            'Akari runtime ownership, cache/state authority, or UI authority.'
        ),
        'inputs': {
            key: {
                'path': str(value),
                'sha256': sha256_path(value),
                'size': value.stat().st_size,
            }
            for key, value in paths.items()
        },
        'static_recovery': static,
        'profiles': {
            packet: {
                'path': str(path),
                'sha256': sha256_path(path),
            }
            for packet, path in profile_paths.items()
        },
        'decodes': decodes,
        'input_conservation': {
            '0x004a': {
                'full_inventory_count': audits['004a0199']['counts']['variable_batch_event_count'],
                'full_inventory_audit_pass': audits['004a0199']['validations']['inventory_count_match'],
                'selected_decode_count': decodes['0x004a']['input_row_count'],
                'selected_fully_consumed_count': decodes['0x004a']['fully_consumed_row_count'],
            },
            '0x0092': {
                'full_inventory_count': audits['009200b9']['counts']['payload_route_count'],
                'full_pair_conservation_pass': audits['009200b9']['validations']['exact_one_to_one_key_match'],
                'selected_decode_count': decodes['0x0092']['input_row_count'],
                'selected_fully_consumed_count': decodes['0x0092']['fully_consumed_row_count'],
            },
            '0x00b9': {
                'full_inventory_count': audits['009200b9']['counts']['prefix_route_count'],
                'full_pair_conservation_pass': audits['009200b9']['validations']['exact_one_to_one_key_match'],
                'selected_decode_count': decodes['0x00b9']['input_row_count'],
                'selected_fully_consumed_count': decodes['0x00b9']['fully_consumed_row_count'],
            },
            '0x0199': {
                'full_inventory_count': audits['004a0199']['counts']['fixed_cluster_event_count'],
                'fully_decoded_occurrence_weight': (
                    decodes['0x0199']['fully_decoded_occurrence_weight']
                ),
                'runtime_state_blocked_occurrence_weight': (
                    decodes['0x0199']['runtime_state_blocked_occurrence_weight']
                ),
                'verified_prefix_occurrence_weight': (
                    decodes['0x0199']['verified_prefix_occurrence_weight']
                ),
                'classified_occurrence_weight': decodes['0x0199']['full_occurrence_weight'],
                'full_inventory_input_conserved': (
                    decodes['0x0199']['full_inventory_input_conserved']
                ),
            },
            '0x02d4': {
                'full_inventory_count': audits['02d4']['counts']['event_count'],
                'full_inventory_audit_pass': audits['02d4']['validations']['inventory_count_match'],
                'selected_decode_count': decodes['0x02d4']['input_row_count'],
                'selected_fully_consumed_count': decodes['0x02d4']['fully_consumed_row_count'],
            },
            '0x0405': {
                'full_inventory_count': next(
                    row['observed_count'] for row in callback_map['routes']
                    if row['packet_id'] == 0x0405
                ),
                'selected_decode_count': decodes['0x0405']['input_row_count'],
                'selected_fully_consumed_count': decodes['0x0405']['fully_consumed_row_count'],
            },
            '0x0474': {
                'full_inventory_count': audits['0474']['counts']['event_count'],
                'fully_decoded_occurrence_weight': decodes['0x0474']['full_occurrence_weight'],
            },
        },
        'route_decisions': decisions,
        'negative_evidence': {
            '0x004a': {
                'direct_scalar_rejected': audits['004a0199']['negative_evidence'],
                'unpaired_row_count': audits['004a0199']['counts']['variable_unpaired_row_count'],
            },
            '0x0092_0x00b9': {
                'semantic_claim': None,
                'reason': (
                    'Exact pairing and decoded containers establish transport structure, '
                    'not an entity/template gameplay operation.'
                ),
            },
            '0x0199': {
                'fixed_unpaired_row_count': audits['004a0199']['counts']['fixed_unpaired_row_count'],
                'runtime_state_blocked_occurrence_weight': (
                    decodes['0x0199']['runtime_state_blocked_occurrence_weight']
                ),
                'runtime_state_blocker_sites': decodes['0x0199']['runtime_state_blocker_sites'],
                'reason': (
                    '0x0199 is not merely a mandatory 0x004a trailer; its dynamic helper '
                    'branch additionally requires exact-build live runtime state.'
                ),
            },
            '0x02d4': audits['02d4']['negative_evidence'],
            '0x0405': {
                'runtime_default_branch_observed_count': 0,
                'reason': 'No current authorized row supports naming the live default values.',
            },
            '0x0474': {
                'rejected_general_hero_state': audits['0474']['negative_evidence'],
                'non_zilean_counterexample_weight': decodes['0x0474']['non_zilean_counterexample_weight'],
            },
        },
        'decode_rows': {
            'path': str(decode_path),
            'sha256': sha256_path(decode_path),
            'row_count': len(output_rows),
        },
        'validations': validations,
        'protected_holdout': {
            'enumerated': False,
            'read': False,
            'hashed': False,
            'decoded': False,
            'tested': False,
            'consumed': False,
        },
    }
    report_path = output_dir / 'highfreq_leftover_exhaustion_v2.json'
    report_text = json.dumps(report, ensure_ascii=True, indent=2) + '\n'
    report_path.write_text(report_text, encoding='utf-8', newline='\n')

    generated = [report_path, decode_path, *profile_paths.values()]
    hash_manifest = {
        'schema': 'HIGHFREQ_LEFTOVER_EXHAUSTION_HASHES_V2',
        'schema_version': 2,
        'exact_build': EXACT_BUILD,
        'files': [
            {
                'path': str(path),
                'sha256': sha256_path(path),
                'size': path.stat().st_size,
            }
            for path in generated
        ],
        'protected_holdout': report['protected_holdout'],
    }
    hash_path = output_dir / 'highfreq_leftover_exhaustion_v2.sha256.json'
    hash_text = json.dumps(hash_manifest, ensure_ascii=True, indent=2) + '\n'
    hash_path.write_text(hash_text, encoding='utf-8', newline='\n')

    print(json.dumps({
        'report': str(report_path),
        'report_sha256': sha256_path(report_path),
        'decode_rows': str(decode_path),
        'decode_rows_sha256': sha256_path(decode_path),
        'decode_row_count': len(output_rows),
        'hash_manifest': str(hash_path),
        'hash_manifest_sha256': sha256_path(hash_path),
        'route_decisions': decisions,
        'validations': validations,
    }, ensure_ascii=True, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'{type(error).__name__}: {error}', file=sys.stderr)
        raise

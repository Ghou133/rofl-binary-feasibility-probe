#!/usr/bin/env python3

"""Exact-build static/runtime audit for the remaining high-frequency routes."""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
import statistics
import struct
import sys
from pathlib import Path

import pefile

from emulate_exact_packet_decoder import ExactPacketEmulator, RUNTIME_PROFILES
from trace_hero_combat_state_runtime import (
    IMAGE_BASE,
    StaticImage,
    analyze_factory_case,
    locate_factory,
    simple_immediate_return,
)


EXACT_BUILD = '16.16.805.0442'
IMAGE_SHA256 = '0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55'
FACTORY_RVA = 0x00ED97B0
ROUTES = (0x0105, 0x029D, 0x03AA, 0x0404)
EXPECTED_STATIC = {
    0x0105: {
        'case_rva': 0x00EDD737,
        'allocation_size': 0x5C,
        'constructor_rva': 0x00E78DA0,
        'vtable_rva': 0x01B14B50,
        'deserializer_rva': 0x00FC5E80,
    },
    0x029D: {
        'case_rva': 0x00EE2A20,
        'allocation_size': 0x30,
        'constructor_rva': 0x00E7E710,
        'vtable_rva': 0x01B112C8,
        'deserializer_rva': 0x00EF8820,
    },
    0x03AA: {
        'case_rva': 0x00EE6092,
        'allocation_size': 0x20,
        'constructor_rva': 0x00E9A510,
        'vtable_rva': 0x01B14488,
        'deserializer_rva': 0x0100B0E0,
    },
    0x0404: {
        'case_rva': 0x00EE7370,
        'allocation_size': 0x14,
        'constructor_rva': 0x00E8DEE0,
        'vtable_rva': 0x01B13A28,
        'deserializer_rva': 0x00FED2D0,
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--image',
        default='artifacts/new_build_rofl_compatibility_gate_v1/runtime/'
        'league_16.16.805.0442.memory.bin',
    )
    parser.add_argument(
        '--raw-audit',
        default='artifacts/full_semantic_deep_recovery_v2/remaining_highfreq/'
        'remaining_highfreq_raw_audit.json',
    )
    parser.add_argument(
        '--corpus',
        default='artifacts/full_semantic_deep_recovery_v2/remaining_highfreq/'
        'remaining_highfreq_runtime_corpus.jsonl',
    )
    parser.add_argument(
        '--registry',
        default='artifacts/full_semantic_baseline_v1/observed_route_registry.json',
    )
    parser.add_argument(
        '--runtime-trace',
        default='artifacts/hero_combat_state_v2/runtime/'
        'hero_combat_state_runtime_trace_16_16.json',
    )
    parser.add_argument(
        '--output',
        default='artifacts/full_semantic_deep_recovery_v2/remaining_highfreq/'
        'remaining_highfreq_deep_audit.json',
    )
    parser.add_argument(
        '--decodes',
        default='artifacts/full_semantic_deep_recovery_v2/remaining_highfreq/'
        'remaining_highfreq_runtime_decodes.jsonl',
    )
    return parser.parse_args()


def safe_path(value: str) -> Path:
    path = Path(value).resolve()
    if 'holdout' in str(path).lower():
        raise ValueError(f'protected corpus path is forbidden: {path}')
    return path


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def packet_hex(packet_id: int) -> str:
    return f'0x{packet_id:04x}'


def hx(value: int) -> str:
    return f'0x{value:08x}'


def round_value(value: float | None, digits: int = 8):
    if value is None or not math.isfinite(value):
        return None
    return round(value, digits)


def quantile(values: list[float], fraction: float):
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def pearson(left: list[float], right: list[float]):
    if len(left) != len(right) or len(left) < 2:
        return None
    left_mean = statistics.fmean(left)
    right_mean = statistics.fmean(right)
    numerator = sum(
        (left_value - left_mean) * (right_value - right_mean)
        for left_value, right_value in zip(left, right)
    )
    left_sum = sum((value - left_mean) ** 2 for value in left)
    right_sum = sum((value - right_mean) ** 2 for value in right)
    denominator = math.sqrt(left_sum * right_sum)
    return numerator / denominator if denominator else None


def counter_rows(counter: collections.Counter, key_name: str, limit: int = 24):
    return [
        {key_name: key, 'count': count}
        for key, count in sorted(
            counter.items(),
            key=lambda item: (-item[1], str(item[0])),
        )[:limit]
    ]


def weighted_numeric_summary(counter: collections.Counter):
    values = []
    for value, weight in counter.items():
        values.extend([value] * weight)
    return {
        'observation_count': len(values),
        'distinct_count': len(counter),
        'min': min(values) if values else None,
        'p50': quantile(values, 0.5),
        'p90': quantile(values, 0.9),
        'p99': quantile(values, 0.99),
        'max': max(values) if values else None,
        'top_values': counter_rows(counter, 'value'),
    }


def ror8(value: int, count: int) -> int:
    return ((value >> count) | (value << (8 - count))) & 0xFF


def swap_adjacent_bits(value: int) -> int:
    return (((value & 0xD5) << 1) | ((value >> 1) & 0x55)) & 0xFF


def inverse_table(transform):
    result = {}
    for value in range(256):
        encoded = transform(value)
        if encoded in result:
            raise ValueError('byte storage transform is not bijective')
        result[encoded] = value
    if len(result) != 256:
        raise ValueError('incomplete byte storage inverse')
    return result


def build_storage_inverses(image: bytes):
    shared_table = image[0x01B1BC50:0x01B1BD50]
    envelope_table = image[0x01B0FC50:0x01B0FD50]
    if len(set(shared_table)) != 256 or len(set(envelope_table)) != 256:
        raise ValueError('exact-image codec lookup table is not a permutation')

    def route_03aa_u32_a(value):
        value = ror8(value, 7)
        value ^= 0xAE
        value = (value + 0x50) & 0xFF
        value = (~value) & 0xFF
        value = (value + 0x32) & 0xFF
        return ror8(value, 6)

    def route_03aa_u32_b(value):
        value ^= 0xFE
        value = ror8(value, 1)
        value = (~value) & 0xFF
        value = ror8(value, 3)
        value = (value - 0x65) & 0xFF
        value = ror8(value, 2)
        return swap_adjacent_bits(value)

    def route_03aa_bool(value):
        value = ror8(value, 1) ^ 0x83
        value = ror8(value, 3)
        value = swap_adjacent_bits(value)
        value = shared_table[value]
        value = swap_adjacent_bits(value)
        return shared_table[value]

    def route_0404_u32(value):
        index = ((ror8(value, 4) + 0x45) & 0xFF) ^ 0x5A
        return shared_table[index]

    def route_029d_f32(value):
        value = (value + 0x63) & 0xFF
        value = envelope_table[value]
        value = (0x56 - envelope_table[value]) & 0xFF
        value = ror8(value, 2)
        return swap_adjacent_bits(value)

    def route_029d_u8(value):
        value = ror8(value, 2) ^ 0xAA
        value = swap_adjacent_bits(value)
        value = (value + 0x76) & 0xFF
        return ror8(value, 4) ^ 0xB7

    def route_029d_u32(value):
        value = envelope_table[value]
        value = (value - 0x6A) & 0xFF
        value = envelope_table[value]
        value = ror8(value, 1)
        value = (~value) & 0xFF
        return ror8(value, 3)

    return {
        '03aa_a': inverse_table(route_03aa_u32_a),
        '03aa_b': inverse_table(route_03aa_u32_b),
        '03aa_bool': inverse_table(route_03aa_bool),
        '0404': inverse_table(route_0404_u32),
        '029d_f32': inverse_table(route_029d_f32),
        '029d_u8': inverse_table(route_029d_u8),
        '029d_u32': inverse_table(route_029d_u32),
    }


def decode_bytes(value: bytes, inverse: dict[int, int]) -> bytes:
    return bytes(inverse[byte] for byte in value)


def function_hash(static: StaticImage, rva: int):
    entry = static.function_for(rva)
    if entry is None:
        return None
    begin, end, _unwind = entry
    return {
        'begin_rva': begin,
        'begin_rva_hex': hx(begin),
        'end_rva': end,
        'end_rva_hex': hx(end),
        'size': end - begin,
        'sha256': sha256_bytes(static.image[begin:end]),
    }


def compact_factory_case(record: dict):
    return {
        'packet_id': record['packet_id'],
        'packet_discriminator': record['packet_id_hex'],
        'jump_table_entry_rva': record['jump_table_entry_rva'],
        'jump_table_entry_rva_hex': record['jump_table_entry_rva_hex'],
        'case_rva': record['case']['rva'],
        'case_rva_hex': record['case']['rva_hex'],
        'allocation_size': record['allocation_size'],
        'allocator_rva': record['allocator_rva'],
        'allocator_rva_hex': record['allocator_rva_hex'],
        'constructor_rva': record['constructor']['rva'],
        'constructor_rva_hex': record['constructor']['rva_hex'],
        'packet_id_write': record['constructor']['packet_id_write'],
        'vtable_rva': record['packet_object_vtable']['rva'],
        'vtable_rva_hex': record['packet_object_vtable']['rva_hex'],
        'vtable_entries_rva': record['packet_object_vtable']['entries_rva'],
        'vtable_entries_rva_hex': record['packet_object_vtable']['entries_rva_hex'],
        'object_size': record['packet_object_vtable']['slot_2_returned_object_size'],
        'deserializer_rva': record['deserializer']['rva'],
        'deserializer_rva_hex': record['deserializer']['rva_hex'],
    }


def recover_static(image: bytes, runtime_trace: dict):
    static = StaticImage(image, pefile.PE(data=image, fast_load=False))
    factory = locate_factory(static, set(ROUTES), FACTORY_RVA)
    cases = {}
    validations = {}
    for packet_id in ROUTES:
        record = analyze_factory_case(static, factory, packet_id)
        compact = compact_factory_case(record)
        expected = EXPECTED_STATIC[packet_id]
        checks = {
            'case_rva': compact['case_rva'] == expected['case_rva'],
            'allocation_size': compact['allocation_size'] == expected['allocation_size'],
            'constructor_rva': compact['constructor_rva'] == expected['constructor_rva'],
            'vtable_rva': compact['vtable_rva'] == expected['vtable_rva'],
            'deserializer_rva': compact['deserializer_rva'] == expected['deserializer_rva'],
            'object_size': compact['object_size'] == expected['allocation_size'],
        }
        compact['deserializer_function'] = function_hash(static, compact['deserializer_rva'])
        compact['validation'] = {'checks': checks, 'all_match': all(checks.values())}
        cases[packet_id] = compact
        validations[packet_hex(packet_id)] = compact['validation']['all_match']

    nested = {
        0x0105: {
            'embedding_offset': 0x10,
            'vtable_rva': 0x01B14B28,
            'object_size': 0x48,
            'layout': 'fixed nested composite record at outer +0x10; outer encoded f32 at +0x58',
        },
        0x03AA: {
            'vector_header_offset': 0x10,
            'vtable_rva': 0x01A23B18,
            'object_size': 0x14,
            'layout': 'vector element: encoded u32 at +0x08, encoded u32 at +0x0c, encoded bool at +0x10',
        },
    }
    for packet_id, row in nested.items():
        entries = [
            static.qword_rva(row['vtable_rva'] + index * 8)
            for index in range(6)
        ]
        row['vtable_rva_hex'] = hx(row['vtable_rva'])
        row['vtable_entries_rva'] = entries
        row['vtable_entries_rva_hex'] = [hx(value) for value in entries]
        row['deserializer_rva'] = entries[1]
        row['deserializer_rva_hex'] = hx(entries[1])
        row['size_getter_rva'] = entries[2]
        row['size_getter_rva_hex'] = hx(entries[2])
        row['size_getter_return'] = simple_immediate_return(static, entries[2])
        row['deserializer_function'] = function_hash(static, entries[1])
        row['validated'] = row['size_getter_return'] == row['object_size']

    route_index = runtime_trace['callback_registration_inventory']['route_index']
    registration = {}
    for packet_id in ROUTES:
        key = packet_hex(packet_id)
        matches = route_index.get(key)
        registration[packet_id] = {
            'callback_registration_surface': 'MSVC_MAKEFUNCTION_TYPE_DESCRIPTOR_ENUMERATION',
            'route_index_entry': matches,
            'callback_rtti_name_status': (
                'UNMAPPED_ON_EXHAUSTIVE_LOCAL_DESCRIPTOR_SURFACE'
                if not matches else 'MAPPED'
            ),
            'registration_status': (
                'UNMAPPED_ON_EXHAUSTIVE_LOCAL_DESCRIPTOR_SURFACE'
                if not matches else 'MAPPED'
            ),
            'factory_status': 'VERIFIED_DIRECT_FACTORY_OBJECT',
            'semantic_warning': (
                'Factory identity is direct structural evidence. Absence from this callback '
                'surface does not prove that no other dispatcher or consumer exists.'
            ),
        }

    return {
        'factory': {
            'function_rva': factory['function'][0],
            'function_rva_hex': hx(factory['function'][0]),
            'switch_rva': factory['switch_rva'],
            'switch_rva_hex': hx(factory['switch_rva']),
            'jump_table_rva': factory['table_rva'],
            'jump_table_rva_hex': hx(factory['table_rva']),
            'maximum_packet_id': factory['maximum_id'],
        },
        'routes': {
            packet_hex(packet_id): {
                'registration_and_rtti': registration[packet_id],
                'factory_chain': cases[packet_id],
                'nested_object': nested.get(packet_id),
            }
            for packet_id in ROUTES
        },
        'callback_inventory_summary': {
            key: runtime_trace['callback_registration_inventory'][key]
            for key in (
                'scope',
                'discovered_descriptor_instance_count',
                'verified_registration_instance_count',
                'unique_verified_registration_id_count',
                'direct_factory_verified_count',
            )
        },
        'validations': {
            **validations,
            'nested_0105': nested[0x0105]['validated'],
            'nested_03aa': nested[0x03AA]['validated'],
            'all_pass': all(validations.values())
            and nested[0x0105]['validated']
            and nested[0x03AA]['validated'],
        },
    }


def runtime_profiles():
    return {
        0x0105: {
            'client_opcode': 0x0105,
            'constructor_rva': 0x00E78DA0,
            'deserialize_rva': 0x00FC5E80,
            'object_size': 0x5C,
            'fields': [],
        },
        0x029D: {
            'client_opcode': 0x029D,
            'constructor_rva': 0x00E7E710,
            'deserialize_rva': 0x00EF8820,
            'object_size': 0x30,
            'fields': [
                {
                    'name': 'byte_vector_hex',
                    'offset': 0x18,
                    'type': 'byte_vector_hex',
                    'maximum_length': 0x10000,
                },
            ],
        },
        0x03AA: {
            'client_opcode': 0x03AA,
            'constructor_rva': 0x00E9A510,
            'deserialize_rva': 0x0100B0E0,
            'object_size': 0x20,
            'fields': [
                {
                    'name': 'elements',
                    'offset': 0x10,
                    'type': 'object_vector_records',
                    'element_size': 0x14,
                    'maximum_elements': 0x1000,
                    'maximum_length': 0x10000,
                },
            ],
        },
        0x0404: {
            'client_opcode': 0x0404,
            'constructor_rva': 0x00E8DEE0,
            'deserialize_rva': 0x00FED2D0,
            'object_size': 0x14,
            'fields': [],
        },
    }


def load_corpus(path: Path):
    rows = []
    with path.open(encoding='utf-8') as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if row['exact_build'] != EXACT_BUILD or row['packet_id'] not in ROUTES:
                raise ValueError(f'bad runtime corpus row at line {line_number}')
            rows.append(row)
    return rows


def decode_runtime(image: bytes, corpus_rows: list[dict]):
    inverses = build_storage_inverses(image)
    emulator = ExactPacketEmulator(image, RUNTIME_PROFILES[EXACT_BUILD])
    profiles = runtime_profiles()
    decoded_rows = []

    for corpus in corpus_rows:
        packet_id = corpus['packet_id']
        payload = bytes.fromhex(corpus['raw_payload_hex'])
        base = {
            'schema_version': 1,
            'exact_build': EXACT_BUILD,
            'packet_id': packet_id,
            'packet_discriminator': packet_hex(packet_id),
            'payload_sha256': corpus['payload_sha256'],
            'payload_length': corpus['payload_length'],
            'occurrence_count': corpus['occurrence_count'],
            'selection_policy': corpus['selection_policy'],
            'replay_label': corpus['replay_label'],
            'replay_time_ms': corpus['replay_time_ms'],
            'raw_param': corpus['raw_param'],
            'raw_param_distinct_count': corpus.get('raw_param_distinct_count'),
            'raw_param_top_values': corpus.get('raw_param_top_values'),
        }
        try:
            decoded = emulator.decode(
                payload,
                profiles[packet_id],
                packet_id=packet_id,
                raw_param=corpus['raw_param'],
            )
            object_bytes = bytes.fromhex(decoded['object_hex'])
            record = {
                **base,
                'deserialize_return_al': decoded['deserialize_return_al'],
                'bytes_consumed': decoded['bytes_consumed'],
                'fully_consumed': decoded['fully_consumed'],
                'decoded_fields': {},
            }
            if packet_id == 0x029D:
                f32_bytes = decode_bytes(object_bytes[0x10:0x14], inverses['029d_f32'])
                f32_value = struct.unpack('<f', f32_bytes)[0]
                byte_vector = bytes.fromhex(decoded['decoded_fields']['byte_vector_hex'])
                u8_value = inverses['029d_u8'][object_bytes[0x28]]
                u32_value = struct.unpack(
                    '<I',
                    decode_bytes(object_bytes[0x2C:0x30], inverses['029d_u32']),
                )[0]
                record['decoded_fields'] = {
                    'f32_10': f32_value if math.isfinite(f32_value) else None,
                    'byte_vector_length': len(byte_vector),
                    'byte_vector_sha256': sha256_bytes(byte_vector),
                    'byte_vector_prefix_hex': byte_vector[:16].hex(),
                    'u8_28': u8_value,
                    'u32_2c': u32_value,
                }
            elif packet_id == 0x03AA:
                elements = []
                for element in decoded['decoded_fields']['elements']:
                    element_bytes = bytes.fromhex(element['object_hex'])
                    elements.append({
                        'u32_08': struct.unpack(
                            '<I',
                            decode_bytes(element_bytes[0x08:0x0C], inverses['03aa_a']),
                        )[0],
                        'u32_0c': struct.unpack(
                            '<I',
                            decode_bytes(element_bytes[0x0C:0x10], inverses['03aa_b']),
                        )[0],
                        'bool_10': inverses['03aa_bool'][element_bytes[0x10]],
                    })
                record['decoded_fields'] = {
                    'element_count': len(elements),
                    'elements': elements,
                }
            elif packet_id == 0x0404:
                value = struct.unpack(
                    '<I',
                    decode_bytes(object_bytes[0x10:0x14], inverses['0404']),
                )[0]
                record['decoded_fields'] = {'u32_10': value}
            elif packet_id == 0x0105:
                record['decoded_fields'] = {
                    'object_sha256': sha256_bytes(object_bytes),
                    'outer_f32_storage_hex': object_bytes[0x58:0x5C].hex(),
                }
            decoded_rows.append(record)
        except Exception as error:
            decoded_rows.append({
                **base,
                'fully_consumed': False,
                'error_type': type(error).__name__,
                'error': str(error),
            })
    return decoded_rows


def summarize_common(packet_id: int, rows: list[dict], expected_count: int):
    selected = [row for row in rows if row['packet_id'] == packet_id]
    successes = [row for row in selected if 'error' not in row]
    full = [row for row in successes if row['fully_consumed']]
    selected_weight = sum(row['occurrence_count'] for row in selected)
    full_weight = sum(row['occurrence_count'] for row in full)
    errors = collections.Counter(row.get('error') for row in selected if 'error' in row)
    return {
        'corpus_row_count': len(selected),
        'selected_occurrence_weight': selected_weight,
        'expected_full_occurrence_count': expected_count,
        'selected_occurrence_coverage_rate': round_value(selected_weight / expected_count),
        'successful_row_count': len(successes),
        'fully_consumed_row_count': len(full),
        'fully_consumed_occurrence_weight': full_weight,
        'full_inventory_weight_covered': full_weight == expected_count,
        'error_count': len(selected) - len(successes),
        'error_distribution': counter_rows(errors, 'error', 8),
    }


def summarize_0105(rows: list[dict], expected_count: int):
    summary = summarize_common(0x0105, rows, expected_count)
    failures = [row for row in rows if row['packet_id'] == 0x0105 and 'error' in row]
    summary.update({
        'recovered_layout': {
            'outer_object_size': 0x5C,
            'nested_object_offset': 0x10,
            'nested_object_size': 0x48,
            'nested_vtable_rva': hx(0x01B14B28),
            'nested_deserializer_rva': hx(0x00FB1B00),
            'outer_f32_offset': 0x58,
            'layout_family': 'NESTED_FIXED_COMPOSITE_RECORD_PLUS_ENCODED_F32',
        },
        'runtime_boundary': {
            'status': 'BLOCKED_BY_EXACT_IMAGE_LIVE_STATE_POINTER',
            'first_failure': failures[0]['error'] if failures else None,
            'failure_instruction_rva': hx(0x00F9F4F4),
            'dependency': (
                'Nested decoding reaches a mutable module-global lookup object. The mapped '
                'module image preserves its captured pointer value but not the pointed-to live '
                'heap object; inventing a stub would no longer be exact evidence.'
            ),
            'bounded_retry_count': len(failures),
        },
    })
    return summary


def summarize_029d(rows: list[dict], expected_count: int):
    selected = [
        row for row in rows
        if row['packet_id'] == 0x029D and 'error' not in row
    ]
    summary = summarize_common(0x029D, rows, expected_count)
    f32_values = [row['decoded_fields']['f32_10'] for row in selected]
    u8_counter = collections.Counter(row['decoded_fields']['u8_28'] for row in selected)
    u32_counter = collections.Counter(row['decoded_fields']['u32_2c'] for row in selected)
    vector_lengths = collections.Counter(
        row['decoded_fields']['byte_vector_length'] for row in selected
    )
    overhead = collections.Counter(
        row['payload_length'] - row['decoded_fields']['byte_vector_length']
        for row in selected
    )
    time_offsets_by_replay = collections.defaultdict(list)
    for row in selected:
        time_offsets_by_replay[row['replay_label']].append(
            row['decoded_fields']['f32_10'] * 1000 - row['replay_time_ms']
        )
    offset_rows = []
    timestamp_match_count = 0
    for replay_label, values in sorted(time_offsets_by_replay.items()):
        median = statistics.median(values)
        residuals = [value - median for value in values]
        timestamp_match_count += sum(abs(value) <= 2 for value in residuals)
        offset_rows.append({
            'replay_label': replay_label,
            'sample_count': len(values),
            'median_f32_minus_replay_time_ms': round_value(median, 6),
            'maximum_absolute_residual_ms': round_value(max(abs(value) for value in residuals), 6),
            'within_2ms_after_per_replay_offset_count': sum(abs(value) <= 2 for value in residuals),
        })
    monotonic_rows = []
    for replay_label in sorted(time_offsets_by_replay):
        replay_rows = sorted(
            (row for row in selected if row['replay_label'] == replay_label),
            key=lambda row: (row['replay_time_ms'], row['payload_sha256']),
        )
        time_values = [row['replay_time_ms'] for row in replay_rows]
        cursor_values = [row['decoded_fields']['u32_2c'] for row in replay_rows]
        transitions = max(0, len(cursor_values) - 1)
        nondecreasing = sum(
            cursor_values[index] >= cursor_values[index - 1]
            for index in range(1, len(cursor_values))
        )
        monotonic_rows.append({
            'replay_label': replay_label,
            'sample_count': len(replay_rows),
            'nondecreasing_transition_count': nondecreasing,
            'transition_count': transitions,
            'nondecreasing_transition_rate': round_value(
                nondecreasing / max(1, transitions)
            ),
            'pearson_with_replay_time_ms': round_value(
                pearson(time_values, cursor_values)
            ),
            'first_value': cursor_values[0] if cursor_values else None,
            'last_value': cursor_values[-1] if cursor_values else None,
        })
    vector_bytes = sum(row['decoded_fields']['byte_vector_length'] for row in selected)
    summary.update({
        'recovered_layout': {
            'object_size': 0x30,
            'fields': [
                {'offset': 0x10, 'shape': 'encoded_f32'},
                {'offset': 0x18, 'shape': 'byte_vector_header', 'element_stride': 1},
                {'offset': 0x28, 'shape': 'encoded_u8'},
                {'offset': 0x2C, 'shape': 'encoded_u32'},
            ],
            'layout_family': 'TIMESTAMPED_OPAQUE_BYTE_VECTOR_ENVELOPE',
        },
        'field_behavior': {
            'f32_10': {
                'finite_count': sum(math.isfinite(value) for value in f32_values),
                'distinct_count': len(set(f32_values)),
                'min': min(f32_values),
                'p50': quantile(f32_values, 0.5),
                'p90': quantile(f32_values, 0.9),
                'max': max(f32_values),
                'per_replay_constant_offset_correlation': offset_rows,
                'within_2ms_after_per_replay_offset_rate': round_value(
                    timestamp_match_count / max(1, len(selected))
                ),
                'structural_interpretation': 'GAME_TIME_SECONDS_WITH_REPLAY_LOCAL_ORIGIN_OFFSET',
                'gameplay_semantic_claim': None,
            },
            'byte_vector_18': {
                **weighted_numeric_summary(vector_lengths),
                'sampled_total_byte_count': vector_bytes,
                'distinct_content_sha256_count': len({
                    row['decoded_fields']['byte_vector_sha256'] for row in selected
                }),
                'payload_minus_vector_length_distribution': counter_rows(
                    overhead, 'byte_count', 16
                ),
                'interpretation': 'OPAQUE_BULK_BYTES',
            },
            'u8_28': {
                **weighted_numeric_summary(u8_counter),
                'pearson_with_byte_vector_length': round_value(pearson(
                    [row['decoded_fields']['u8_28'] for row in selected],
                    [row['decoded_fields']['byte_vector_length'] for row in selected],
                )),
                'interpretation': 'CARDINALITY_OR_KIND_LIKE_SCALAR_CANDIDATE',
                'semantic_claim': None,
            },
            'u32_2c': {
                **weighted_numeric_summary(u32_counter),
                'per_replay_time_order_behavior': monotonic_rows,
                'all_sampled_transitions_nondecreasing': all(
                    row['nondecreasing_transition_rate'] == 1
                    for row in monotonic_rows
                ),
                'interpretation': 'MONOTONIC_SEQUENCE_OR_CUMULATIVE_OFFSET_CANDIDATE',
                'semantic_claim': None,
            },
        },
    })
    return summary


def summarize_03aa(rows: list[dict], expected_count: int):
    selected = [
        row for row in rows
        if row['packet_id'] == 0x03AA and 'error' not in row
    ]
    summary = summarize_common(0x03AA, rows, expected_count)
    count_counter = collections.Counter()
    first_counter = collections.Counter()
    second_counter = collections.Counter()
    bool_counter = collections.Counter()
    pair_total = 0
    pair_equal = 0
    raw_coverage = 0
    raw_field_match = 0
    mismatch_witnesses = []
    match_witnesses = []
    for row in selected:
        weight = row['occurrence_count']
        elements = row['decoded_fields']['elements']
        count_counter[len(elements)] += weight
        for element in elements:
            first_counter[element['u32_08']] += weight
            second_counter[element['u32_0c']] += weight
            bool_counter[element['bool_10']] += weight
        for index in range(0, len(elements) - 1, 2):
            pair_total += weight
            if elements[index] == elements[index + 1]:
                pair_equal += weight
        raw_rows = row.get('raw_param_top_values') or [
            {'raw_param': row['raw_param'], 'count': weight}
        ]
        for raw_row in raw_rows:
            raw = raw_row['raw_param']
            raw_weight = raw_row['count']
            raw_coverage += raw_weight
            matches = any(
                raw in (element['u32_08'], element['u32_0c'])
                for element in elements
            )
            if matches:
                raw_field_match += raw_weight
                if len(match_witnesses) < 12:
                    match_witnesses.append({
                        'payload_sha256': row['payload_sha256'],
                        'raw_param': raw,
                        'elements': elements[:4],
                    })
            elif len(mismatch_witnesses) < 12:
                mismatch_witnesses.append({
                    'payload_sha256': row['payload_sha256'],
                    'raw_param': raw,
                    'elements': elements[:4],
                })
    summary.update({
        'recovered_layout': {
            'outer_object_size': 0x20,
            'vector_header_offset': 0x10,
            'element_size': 0x14,
            'element_vtable_rva': hx(0x01A23B18),
            'element_deserializer_rva': hx(0x010334D0),
            'element_fields': [
                {'offset': 0x08, 'shape': 'encoded_u32'},
                {'offset': 0x0C, 'shape': 'encoded_u32'},
                {'offset': 0x10, 'shape': 'encoded_bool'},
            ],
            'layout_family': 'ENTITY_SCOPED_PAIRED_HASH_RECORD_VECTOR',
        },
        'field_behavior': {
            'element_count': weighted_numeric_summary(count_counter),
            'element_count_always_even': all(value % 2 == 0 for value in count_counter),
            'adjacent_pair_exact_duplicate_rate': round_value(
                pair_equal / max(1, pair_total)
            ),
            'u32_08': {
                **weighted_numeric_summary(first_counter),
                'broad_network_entity_rate': round_value(
                    sum(count for value, count in first_counter.items()
                        if 0x40000000 <= value <= 0x4FFFFFFF)
                    / max(1, sum(first_counter.values()))
                ),
                'interpretation': 'LOW_CARDINALITY_HASH_OR_ENUM_LIKE_U32',
            },
            'u32_0c': {
                **weighted_numeric_summary(second_counter),
                'broad_network_entity_rate': round_value(
                    sum(count for value, count in second_counter.items()
                        if 0x40000000 <= value <= 0x4FFFFFFF)
                    / max(1, sum(second_counter.values()))
                ),
                'interpretation': 'HASH_OR_ENUM_LIKE_U32',
            },
            'bool_10': {
                'distribution': counter_rows(bool_counter, 'value', 8),
                'true_rate': round_value(
                    bool_counter[1] / max(1, sum(bool_counter.values()))
                ),
            },
            'raw_param_vs_element_u32': {
                'covered_event_count': raw_coverage,
                'match_count': raw_field_match,
                'match_rate': round_value(raw_field_match / max(1, raw_coverage)),
                'positive_witnesses': match_witnesses,
                'counterexamples': mismatch_witnesses,
                'interpretation': (
                    'Envelope raw_param is the entity routing key; the two nested u32 values '
                    'are not direct echoes of that key.'
                ),
            },
        },
    })
    return summary


def summarize_0404(rows: list[dict], expected_count: int):
    selected = [
        row for row in rows
        if row['packet_id'] == 0x0404 and 'error' not in row
    ]
    summary = summarize_common(0x0404, rows, expected_count)
    value_counter = collections.Counter()
    raw_coverage = 0
    exact_match = 0
    low_byte_match = 0
    difference_counter = collections.Counter()
    match_examples = []
    mismatch_examples = []
    for row in selected:
        value = row['decoded_fields']['u32_10']
        weight = row['occurrence_count']
        value_counter[value] += weight
        raw_rows = row.get('raw_param_top_values') or [
            {'raw_param': row['raw_param'], 'count': weight}
        ]
        for raw_row in raw_rows:
            raw = raw_row['raw_param']
            raw_weight = raw_row['count']
            raw_coverage += raw_weight
            difference_counter[value - raw] += raw_weight
            if (value & 0xFF) == (raw & 0xFF):
                low_byte_match += raw_weight
            if raw == value:
                exact_match += raw_weight
                if len(match_examples) < 16:
                    match_examples.append({
                        'payload_sha256': row['payload_sha256'],
                        'raw_param': raw,
                        'decoded_u32': value,
                        'count': raw_weight,
                    })
            elif len(mismatch_examples) < 16:
                mismatch_examples.append({
                    'payload_sha256': row['payload_sha256'],
                    'raw_param': raw,
                    'decoded_u32': value,
                    'count': raw_weight,
                })
    broad_count = sum(
        count for value, count in value_counter.items()
        if 0x40000000 <= value <= 0x4FFFFFFF
    )
    summary.update({
        'recovered_layout': {
            'object_size': 0x14,
            'field': {'offset': 0x10, 'shape': 'encoded_u32'},
            'layout_family': 'ENTITY_SCOPED_NETWORK_ID_ECHO',
        },
        'field_behavior': {
            'u32_10': {
                **weighted_numeric_summary(value_counter),
                'broad_network_entity_count': broad_count,
                'broad_network_entity_rate': round_value(
                    broad_count / max(1, sum(value_counter.values()))
                ),
                'raw_param_comparison': {
                    'covered_event_count': raw_coverage,
                    'exact_match_count': exact_match,
                    'exact_match_rate': round_value(
                        exact_match / max(1, raw_coverage)
                    ),
                    'low_byte_match_count': low_byte_match,
                    'low_byte_match_rate': round_value(
                        low_byte_match / max(1, raw_coverage)
                    ),
                    'decoded_minus_raw_param_distribution': counter_rows(
                        difference_counter, 'difference', 16
                    ),
                    'positive_examples': match_examples,
                    'mismatch_examples': mismatch_examples,
                },
                'interpretation': (
                    'Decoded payload is a broad-network entity identifier and overwhelmingly '
                    'echoes the packet envelope raw_param. Every bounded mismatch preserves '
                    'the low byte and differs by a negative multiple of 0x100; mismatch rows '
                    'prohibit claiming unconditional full-ID equality.'
                ),
                'gameplay_semantic_claim': None,
            },
        },
    })
    return summary


def make_decisions(raw_routes: dict[str, dict], runtime_routes: dict[str, dict]):
    decisions = []
    specifications = {
        '0x0105': {
            'decision': 'KEEP_CANDIDATE',
            'hypothesis': 'NESTED_FIXED_COMPOSITE_RECORD_PLUS_F32',
            'evidence_grade': 'VERIFIED_DIRECT_STATIC_ONLY_RUNTIME_STATE_BLOCKED',
            'next': [
                'Acquire an authorized exact-build live-state snapshot that preserves the '
                'lookup object dereferenced at RVA 0x00f9f4f4, or trace the exact consumer.',
                'Recover a callback/dispatcher identity outside the enumerated MakeFunction '
                'TypeDescriptor registration surface.',
                'Obtain controlled producer/consumer evidence before assigning any nested '
                'field a gameplay meaning.',
            ],
        },
        '0x029d': {
            'decision': 'REPURPOSE',
            'hypothesis': 'TIMESTAMPED_OPAQUE_BYTE_VECTOR_ENVELOPE',
            'evidence_grade': 'VERIFIED_DIRECT_REPRESENTATIVE_RUNTIME',
            'next': [
                'Recover the byte-vector consumer or an inner schema/discriminator.',
                'Use controlled exact-build producer evidence to distinguish record batches '
                'from telemetry, replication, or presentation data.',
                'Name the u8/u32 tail fields only after independent anchors exist.',
            ],
        },
        '0x03aa': {
            'decision': 'REPURPOSE',
            'hypothesis': 'ENTITY_SCOPED_PAIRED_HASH_RECORD_VECTOR',
            'evidence_grade': 'VERIFIED_DIRECT_FULL_INVENTORY_WEIGHT',
            'next': [
                'Recover the callback/consumer that names the two u32 values and boolean.',
                'Use controlled exact-build entity-state stimuli to identify record meaning.',
                'Explain the adjacent duplicate-pair invariant before exposing a semantic API.',
            ],
        },
        '0x0404': {
            'decision': 'REPURPOSE',
            'hypothesis': 'ENTITY_SCOPED_NETWORK_ID_ECHO_WITH_0X100_STEP_VARIANTS',
            'evidence_grade': 'VERIFIED_DIRECT_FULL_INVENTORY_WEIGHT',
            'next': [
                'Recover the callback/consumer to explain why the network identifier is echoed.',
                'Resolve mismatch rows with controlled exact-build lifecycle or visibility '
                'evidence before claiming identity equality as an invariant.',
                'Do not assign combat, HP, defense, or resource semantics without an '
                'independent positive anchor.',
            ],
        },
    }
    for route_hex, specification in specifications.items():
        raw = raw_routes[route_hex]
        runtime = runtime_routes[route_hex]
        damage = raw['damage_neighborhood']
        counterexamples = damage['far_over_500ms_count']
        rejected = [
            'DIRECT_DAMAGE_EVENT',
            'DAMAGE_SOURCE_OR_TARGET_EVENT',
            'DIRECT_HP_SCALAR',
            'DIRECT_ARMOR_OR_MAGIC_RESIST_SCALAR',
            'DIRECT_RESOURCE_SCALAR',
        ]
        decisions.append({
            'packet_id': int(route_hex, 16),
            'packet_discriminator': route_hex,
            'decision': specification['decision'],
            'hypothesis': specification['hypothesis'],
            'evidence_grade': specification['evidence_grade'],
            'semantic_claim': None,
            'structural_claim_only': True,
            'positive_anchor_count': runtime['fully_consumed_occurrence_weight'],
            'counterexample_count': counterexamples,
            'rejected_hypotheses': rejected,
            'damage_rejection_evidence': {
                'exact_time_rate': damage['exact_time_rate'],
                'shifted_137ms_control_within_10ms_rate':
                    damage['shifted_137ms_control_within_10ms_rate'],
                'raw_param_matches_either_within_10ms_rate':
                    damage['raw_param_matches_either_within_10ms_rate'],
                'far_over_500ms_counterexample_count': counterexamples,
                'cotimed_raw_mismatch_count': damage['cotimed_raw_mismatch_count'],
                'retained_far_counterexample_witness_count':
                    len(damage['far_counterexamples']),
            },
            'evidence_exhausted': True,
            'evidence_exhaustion_scope': (
                'Authorized local exact-build static image, exhaustive local callback '
                'descriptor trace, full latest-four packet inventory, prior bounded profiler, '
                'verified Damage anchors, and the dedicated runtime corpus.'
            ),
            'next_required_evidence': specification['next'],
        })
    return decisions


def main() -> None:
    options = parse_args()
    image_path = safe_path(options.image)
    raw_path = safe_path(options.raw_audit)
    corpus_path = safe_path(options.corpus)
    registry_path = safe_path(options.registry)
    runtime_trace_path = safe_path(options.runtime_trace)
    output_path = safe_path(options.output)
    decodes_path = safe_path(options.decodes)

    image = image_path.read_bytes()
    if sha256_bytes(image) != IMAGE_SHA256:
        raise ValueError('exact mapped runtime image SHA-256 mismatch')
    raw_bytes = raw_path.read_bytes()
    corpus_bytes = corpus_path.read_bytes()
    registry_bytes = registry_path.read_bytes()
    runtime_trace_bytes = runtime_trace_path.read_bytes()
    raw = json.loads(raw_bytes)
    registry = json.loads(registry_bytes)
    runtime_trace = json.loads(runtime_trace_bytes)
    if raw['exact_build'] != EXACT_BUILD or registry['exact_build'] != EXACT_BUILD:
        raise ValueError('input exact-build mismatch')
    if not raw['validations']['all_pass']:
        raise ValueError('raw audit validations did not pass')
    if runtime_trace['build'] != EXACT_BUILD:
        raise ValueError('runtime callback trace exact-build mismatch')

    corpus_rows = load_corpus(corpus_path)
    static = recover_static(image, runtime_trace)
    decoded_rows = decode_runtime(image, corpus_rows)
    raw_routes = {
        row['packet_discriminator']: row
        for row in raw['routes']
    }
    expected = {
        route_hex: raw_routes[route_hex]['count']
        for route_hex in raw_routes
    }
    runtime_routes = {
        '0x0105': summarize_0105(decoded_rows, expected['0x0105']),
        '0x029d': summarize_029d(decoded_rows, expected['0x029d']),
        '0x03aa': summarize_03aa(decoded_rows, expected['0x03aa']),
        '0x0404': summarize_0404(decoded_rows, expected['0x0404']),
    }

    decodes_text = ''.join(
        json.dumps(row, ensure_ascii=True, separators=(',', ':')) + '\n'
        for row in decoded_rows
    )
    decodes_path.parent.mkdir(parents=True, exist_ok=True)
    decodes_path.write_text(decodes_text, encoding='utf-8', newline='\n')
    decisions = make_decisions(raw_routes, runtime_routes)

    registration_unmapped = all(
        row['registration_and_rtti']['registration_status']
        == 'UNMAPPED_ON_EXHAUSTIVE_LOCAL_DESCRIPTOR_SURFACE'
        for row in static['routes'].values()
    )
    runtime_all_expected = (
        runtime_routes['0x029d']['fully_consumed_row_count']
        == runtime_routes['0x029d']['corpus_row_count']
        and runtime_routes['0x03aa']['full_inventory_weight_covered']
        and runtime_routes['0x0404']['full_inventory_weight_covered']
    )
    report = {
        'schema': 'REMAINING_HIGH_FREQUENCY_DEEP_AUDIT_V2',
        'schema_version': 2,
        'exact_build': EXACT_BUILD,
        'exact_build_only': True,
        'nearest_build_fallback': 'FORBIDDEN',
        'architecture_gate': 'PASS',
        'project_context_loaded': True,
        'scope': [packet_hex(packet_id) for packet_id in ROUTES],
        'parser_boundary': (
            'Structural Replay protocol recovery only. No map truth, gameplay behavior '
            'inference, acquisition/cache/runtime state ownership, or UI authority.'
        ),
        'inputs': {
            'mapped_runtime_image': {
                'path': str(image_path),
                'sha256': sha256_bytes(image),
                'size': len(image),
            },
            'raw_audit': {'path': str(raw_path), 'sha256': sha256_bytes(raw_bytes)},
            'runtime_corpus': {
                'path': str(corpus_path),
                'sha256': sha256_bytes(corpus_bytes),
                'row_count': len(corpus_rows),
            },
            'observed_registry': {
                'path': str(registry_path),
                'sha256': sha256_bytes(registry_bytes),
            },
            'runtime_callback_trace': {
                'path': str(runtime_trace_path),
                'sha256': sha256_bytes(runtime_trace_bytes),
            },
            'runtime_decodes': {
                'path': str(decodes_path),
                'sha256': sha256_bytes(decodes_text.encode('utf-8')),
                'row_count': len(decoded_rows),
            },
            'raw_audit_transitive_inputs': raw['input'],
        },
        'static_recovery': static,
        'routes': {
            route_hex: {
                'static_chain': static['routes'][route_hex],
                'raw_behavior': raw_routes[route_hex],
                'runtime_decode': runtime_routes[route_hex],
                'decision': next(
                    row for row in decisions
                    if row['packet_discriminator'] == route_hex
                ),
            }
            for route_hex in ('0x0105', '0x029d', '0x03aa', '0x0404')
        },
        'route_decisions': decisions,
        'negative_evidence_summary': {
            'all_gameplay_semantic_claims_null': all(
                row['semantic_claim'] is None for row in decisions
            ),
            'all_direct_damage_hypotheses_rejected': all(
                'DIRECT_DAMAGE_EVENT' in row['rejected_hypotheses']
                for row in decisions
            ),
            'dense_damage_timestamps_are_not_causality': True,
            'shifted_time_controls_retained': True,
            'raw_param_endpoint_mismatch_retained': True,
        },
        'validations': {
            'exact_image_sha256': sha256_bytes(image) == IMAGE_SHA256,
            'raw_audit_all_pass': raw['validations']['all_pass'],
            'static_factory_and_nested_chains': static['validations']['all_pass'],
            'callback_surface_bounded_unmapped': registration_unmapped,
            'runtime_expected_routes_full_consume': runtime_all_expected,
            'route_0105_failure_bounded_and_explained':
                runtime_routes['0x0105']['runtime_boundary']['status']
                == 'BLOCKED_BY_EXACT_IMAGE_LIVE_STATE_POINTER',
            'all_route_decisions_machine_readable': len(decisions) == 4
            and all(row['decision'] in {
                'PROMOTE', 'KEEP_CANDIDATE', 'REJECT', 'REPURPOSE'
            } for row in decisions),
        },
        'protected_holdout': {
            'enumerated': False,
            'read': False,
            'hashed': False,
            'decoded': False,
            'tested': False,
            'consumed': False,
        },
    }
    report['validations']['all_pass'] = all(report['validations'].values())
    if not report['validations']['all_pass']:
        raise ValueError('deep audit validations did not all pass')

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_text = json.dumps(report, ensure_ascii=True, indent=2) + '\n'
    output_path.write_text(output_text, encoding='utf-8', newline='\n')
    print(json.dumps({
        'output': str(output_path),
        'output_sha256': sha256_bytes(output_text.encode('utf-8')),
        'decodes': str(decodes_path),
        'decodes_sha256': sha256_bytes(decodes_text.encode('utf-8')),
        'decode_row_count': len(decoded_rows),
        'decisions': decisions,
        'validations': report['validations'],
    }, ensure_ascii=True, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'{type(error).__name__}: {error}', file=sys.stderr)
        raise

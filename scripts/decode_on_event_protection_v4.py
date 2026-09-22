#!/usr/bin/env python3

import argparse
import collections
import hashlib
import json
import math
import os
import struct
import sys
from pathlib import Path

from unicorn import UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_R8,
    UC_X86_REG_RAX,
    UC_X86_REG_RCX,
    UC_X86_REG_RDX,
)

from emulate_exact_packet_decoder import (
    ExactPacketEmulator,
    HEAP_BASE,
    HEAP_SIZE,
    IMAGE_BASE,
)


ON_EVENT_PROFILE = {
    'client_opcode': 0x009E,
    'constructor_rva': 0x00E827E0,
    'deserialize_rva': 0x00FE12F0,
    'object_size': 0x28,
    'fields': [],
}
DECODER_PROFILE = 'rofl-16.15.801.3452-on-event-protection-v4'
EXPECTED_IMAGE_SHA256 = (
    '7ee788155b9ba61d10603694cffb095e66ab3c641f933e4e7b181000c69f61bb'
)

DECODE_TABLE_RVA = 0x01A5C900
RUNTIME_MEMSET_ENTRY_RVA = 0x019DA180

EVENT_TYPES = {
    0x4B: {
        'event_name': 'OnCastHeal',
        'parameter_type': 'ParamsHeal',
        'expected_schema_id': 0x7C044FE1,
        'expected_size': 0x34,
        'event_kind': 'HEAL_REPORTED_DIRECT',
        'route_kind': 'HEAL_EVENT',
        'canonical_route': True,
        'semantic_status': 'VERIFIED_DIRECT',
    },
    0xED: {
        'event_name': 'OnReceiveShield',
        'parameter_type': 'ShieldingParams',
        'expected_schema_id': 0x8F7F3F4E,
        'expected_size': 0x14,
        'event_kind': 'SHIELD_APPLICATION_DIRECT',
        'route_kind': 'TARGET_ROUTE',
        'canonical_route': True,
        'semantic_status': 'VERIFIED_DIRECT',
    },
    0xEE: {
        'event_name': 'OnGrantShield',
        'parameter_type': 'ShieldingParams',
        'expected_schema_id': 0x8F7F3F4E,
        'expected_size': 0x14,
        'event_kind': 'SHIELD_APPLICATION_DIRECT',
        'route_kind': 'SOURCE_ROUTE_DUPLICATE',
        'canonical_route': False,
        'semantic_status': 'VERIFIED_DIRECT',
    },
    0xEF: {
        'event_name': 'OnDamageShielded',
        'parameter_type': 'DamageShieldedParams',
        'expected_schema_id': None,
        'expected_size': None,
        'event_kind': 'DAMAGE_SHIELDED_LAYOUT_UNRESOLVED',
        'route_kind': 'DAMAGE_SHIELDED_EVENT',
        'canonical_route': False,
        'semantic_status': 'UNRESOLVED_LAYOUT',
    },
}

ORDER_FIELDS = (
    'chunk_index',
    'chunk_id',
    'chunk_stream',
    'chunk_file_offset',
    'compressed_body_offset',
    'decompressed_block_offset',
    'decompressed_payload_offset',
    'replay_time_ms',
    'occurrence_index',
)


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            'Decode current-client PKT_OnEvent_s heal/shield payloads without '
            'changing the frozen generic emulator.'
        ),
    )
    parser.add_argument('--image', required=True)
    parser.add_argument('--events', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--summary')
    parser.add_argument('--limit', type=int)
    parser.add_argument('--progress-every', type=int, default=25000)
    parser.add_argument('--self-test', action='store_true')
    return parser.parse_args()


def rotate_right_8(value, count):
    return ((value >> count) | (value << (8 - count))) & 0xFF


def decode_event_id(encoded, table):
    decoded = bytearray()
    for value in encoded:
        value ^= 0x0F
        value = rotate_right_8(value, 1)
        value = (value - 0x65) & 0xFF
        value ^= 0x46
        value = (value + 0x67) & 0xFF
        decoded.append(table[value])
    return int.from_bytes(decoded, 'little')


def decode_schema_id(encoded, table):
    decoded = bytearray()
    for value in encoded:
        value = rotate_right_8(value, 4)
        value = ((((value & 0xD5) << 1) & 0xFF) | ((value >> 1) & 0x55))
        value ^= 0x5A
        value = ((value << 2) | (value >> 6)) & 0xFF
        value = table[value] ^ 0x81
        value = ((((value & 0xD5) << 1) & 0xFF) | ((value >> 1) & 0x55))
        decoded.append(value)
    return int.from_bytes(decoded, 'little')


class OnEventProtectionEmulator(ExactPacketEmulator):
    """V4-only emulator with a semantic CRT memset stub for Unicorn AVX gaps."""

    def __init__(self, image):
        super().__init__(image)
        self.emulator.hook_add(
            UC_HOOK_CODE,
            self._runtime_memset,
            begin=IMAGE_BASE + RUNTIME_MEMSET_ENTRY_RVA,
            end=IMAGE_BASE + RUNTIME_MEMSET_ENTRY_RVA,
        )

    def _runtime_memset(self, _emulator, _address, _size, _user_data):
        destination = self.emulator.reg_read(UC_X86_REG_RCX)
        value = self.emulator.reg_read(UC_X86_REG_RDX) & 0xFF
        size = self.emulator.reg_read(UC_X86_REG_R8)
        if size:
            self.emulator.mem_write(destination, bytes([value]) * size)
        self.emulator.reg_write(UC_X86_REG_RAX, destination)
        self._return_from_stub()


def decode_parameter_fields(event_id, parameter_bytes):
    fields = {}
    if event_id == 0x4B and len(parameter_bytes) == 0x34:
        amount_bits = struct.unpack_from('<I', parameter_bytes, 0x18)[0]
        fields.update({
            'target_network_id': struct.unpack_from('<I', parameter_bytes, 0x04)[0],
            'source_network_id': struct.unpack_from('<I', parameter_bytes, 0x14)[0],
            'amount': struct.unpack_from('<f', parameter_bytes, 0x18)[0],
            'amount_bits_hex': f'0x{amount_bits:08x}',
            'protocol_field_08': struct.unpack_from('<I', parameter_bytes, 0x08)[0],
            'protocol_field_0c': struct.unpack_from('<I', parameter_bytes, 0x0C)[0],
            'protocol_field_10': struct.unpack_from('<I', parameter_bytes, 0x10)[0],
            'protocol_field_1c': struct.unpack_from('<I', parameter_bytes, 0x1C)[0],
            'protocol_field_20': struct.unpack_from('<I', parameter_bytes, 0x20)[0],
            'protocol_field_24': struct.unpack_from('<I', parameter_bytes, 0x24)[0],
            'protocol_field_28': struct.unpack_from('<I', parameter_bytes, 0x28)[0],
            'protocol_field_2c': struct.unpack_from('<I', parameter_bytes, 0x2C)[0],
            'protocol_field_30': struct.unpack_from('<I', parameter_bytes, 0x30)[0],
            'heal_amount_interpretation': (
                'DIRECT_REPORTED_AMOUNT_RAW_VS_EFFECTIVE_UNRESOLVED'
            ),
        })
    elif event_id in (0xED, 0xEE) and len(parameter_bytes) == 0x14:
        amount_bits = struct.unpack_from('<I', parameter_bytes, 0x10)[0]
        fields.update({
            'source_network_id': struct.unpack_from('<I', parameter_bytes, 0x08)[0],
            'target_network_id': struct.unpack_from('<I', parameter_bytes, 0x0C)[0],
            'amount': struct.unpack_from('<f', parameter_bytes, 0x10)[0],
            'amount_bits_hex': f'0x{amount_bits:08x}',
            'protocol_field_04': struct.unpack_from('<I', parameter_bytes, 0x04)[0],
            'shield_amount_interpretation': 'DIRECT_APPLICATION_GENERATED_AMOUNT',
        })
    return fields


def decode_row(emulator, event, table, image_sha256):
    decoded = emulator.decode(
        bytes.fromhex(event['raw_payload_hex']),
        ON_EVENT_PROFILE,
        packet_id=event.get('packet_id'),
        raw_param=event.get('raw_param'),
    )
    object_bytes = bytes.fromhex(decoded['object_hex'])
    event_id = decode_event_id(object_bytes[0x10:0x12], table)
    schema_id = decode_schema_id(object_bytes[0x14:0x18], table)
    parameter_pointer = struct.unpack_from('<Q', object_bytes, 0x18)[0]
    parameter_size = struct.unpack_from('<I', object_bytes, 0x20)[0]
    parameter_capacity = struct.unpack_from('<I', object_bytes, 0x24)[0]
    if parameter_size > parameter_capacity:
        raise RuntimeError(
            f'parameter size exceeded capacity: {parameter_size} > {parameter_capacity}'
        )
    parameter_end = parameter_pointer + parameter_size
    if parameter_size and not (
        HEAP_BASE <= parameter_pointer <= parameter_end <= HEAP_BASE + HEAP_SIZE
    ):
        raise RuntimeError(
            f'parameter blob outside emulated heap: '
            f'pointer=0x{parameter_pointer:x} size={parameter_size}'
        )
    parameter_bytes = (
        bytes(emulator.emulator.mem_read(parameter_pointer, parameter_size))
        if parameter_size
        else b''
    )
    event_type = EVENT_TYPES.get(event_id)
    if event_type is None:
        return decoded, None

    expected_schema_id = event_type['expected_schema_id']
    expected_size = event_type['expected_size']
    source = {key: event.get(key) for key in ORDER_FIELDS}
    source.update({
        'replay_path': event.get('replay_path'),
        'replay_sha256': event.get('replay_sha256'),
        'replay_version': event.get('replay_version'),
        'replay_label': event.get('replay_label'),
    })
    row = {
        'schema_version': 1,
        **source,
        'event_id': event_id,
        'event_id_hex': f'0x{event_id:04x}',
        **event_type,
        'schema_id': schema_id,
        'schema_id_hex': f'0x{schema_id:08x}',
        'schema_matches_expected': (
            expected_schema_id is None or schema_id == expected_schema_id
        ),
        'parameter_size': parameter_size,
        'parameter_capacity': parameter_capacity,
        'parameter_size_matches_expected': (
            expected_size is None or parameter_size == expected_size
        ),
        'parameter_blob_hex': parameter_bytes.hex(),
        'parameter_blob_sha256': hashlib.sha256(parameter_bytes).hexdigest(),
        'outer_object_hex': decoded['object_hex'],
        'deserialize_return_al': decoded['deserialize_return_al'],
        'fully_consumed': decoded['fully_consumed'],
        'raw_param': event.get('raw_param'),
        'raw_param_hex': event.get('raw_param_hex'),
        'raw_payload_hex': event.get('raw_payload_hex'),
        'raw_payload_sha256': event.get('raw_payload_sha256'),
        'raw_packet_ref': {
            key: event.get(key)
            for key in (
                'replay_path',
                'replay_sha256',
                *ORDER_FIELDS,
                'packet_id',
                'payload_length',
                'raw_param',
                'raw_param_hex',
                'raw_payload_sha256',
            )
        },
        'decoder_profile': DECODER_PROFILE,
        'decoder_runtime_image_sha256': image_sha256,
        **decode_parameter_fields(event_id, parameter_bytes),
    }
    if 'source_network_id' in row:
        row['source_network_id_hex'] = f"0x{row['source_network_id']:08x}"
    if 'target_network_id' in row:
        row['target_network_id_hex'] = f"0x{row['target_network_id']:08x}"
    if 'amount' in row:
        row['amount_is_finite'] = math.isfinite(row['amount'])
        fingerprint_source = (
            f"{row['replay_sha256']}|{row['replay_time_ms']}|"
            f"{row['event_kind']}|{row['source_network_id']}|"
            f"{row['target_network_id']}|{row['amount_bits_hex']}"
        )
        row['route_fingerprint'] = hashlib.sha256(
            fingerprint_source.encode('ascii'),
        ).hexdigest()
    return decoded, row


def histogram(counter):
    return {str(key): counter[key] for key in sorted(counter)}


def manifest_scan_coverage(events_path):
    """Return only manifest-backed 0x009e scan coverage for zero-row proof."""
    empty = {
        'events_manifest_path': None,
        'events_manifest_sha256': None,
        'scan_replays': [],
        'scan_replay_count': 0,
        'scan_selected_packet_count': 0,
        'scan_parser_error_count': None,
    }
    manifest_path = Path(f'{events_path}.manifest.json')
    try:
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        entries = manifest.get('replays')
        if (
            manifest.get('schema_version') != 1
            or manifest.get('target_replay_version') != '16.15.801.3452'
            or manifest.get('packet_ids') != [ON_EVENT_PROFILE['client_opcode']]
            or Path(manifest.get('output', '')).resolve() != Path(events_path).resolve()
        ):
            return empty
        if not isinstance(entries, list):
            return empty
        scan_replays = [
            {
                'replay_path': entry['path'],
                'replay_sha256': entry['sha256'],
                'replay_version': entry['version'],
                'selected_packet_count': int(entry['selected_packet_count']),
                'parser_error_count': int(entry['parser_error_count']),
            }
            for entry in entries
        ]
        selected_count = sum(entry['selected_packet_count'] for entry in scan_replays)
        if manifest.get('replay_count') != len(scan_replays):
            return empty
        if manifest.get('selected_packet_count') != selected_count:
            return empty
        if manifest.get('packet_counts') != {str(ON_EVENT_PROFILE['client_opcode']): selected_count}:
            return empty
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
        return empty
    return {
        'events_manifest_path': str(manifest_path.resolve()),
        'events_manifest_sha256': hashlib.sha256(
            manifest_path.read_bytes()
        ).hexdigest(),
        'scan_replays': scan_replays,
        'scan_replay_count': len(scan_replays),
        'scan_selected_packet_count': selected_count,
        'scan_parser_error_count': sum(
            entry['parser_error_count'] for entry in scan_replays
        ),
    }


def run_self_test(table):
    checks = {
        'event_ff': decode_event_id(bytes.fromhex('36e2'), table) == 0x00FF,
        'schema_ff': (
            decode_schema_id(bytes.fromhex('c7f1900e'), table) == 0xC03C9E4E
        ),
        'event_grant_shield': decode_event_id(bytes.fromhex('5be2'), table) == 0x00EE,
        'event_receive_shield': (
            decode_event_id(bytes.fromhex('06e2'), table) == 0x00ED
        ),
        'event_cast_heal': decode_event_id(bytes.fromhex('e6e2'), table) == 0x004B,
        'schema_shield': (
            decode_schema_id(bytes.fromhex('c7f82949'), table) == 0x8F7F3F4E
        ),
        'schema_heal': (
            decode_schema_id(bytes.fromhex('4f9e251f'), table) == 0x7C044FE1
        ),
    }
    failed = [name for name, passed in checks.items() if not passed]
    if failed:
        raise AssertionError(f'on-event transform self-test failed: {failed}')
    return checks


def main():
    options = parse_args()
    if options.limit is not None and options.limit < 1:
        raise ValueError('--limit must be positive')
    image = open(options.image, 'rb').read()
    image_sha256 = hashlib.sha256(image).hexdigest()
    if image_sha256 != EXPECTED_IMAGE_SHA256:
        raise RuntimeError(
            'PROTECTION_PROFILE_UNSUPPORTED: runtime image hash does not match '
            f'the verified 16.15.801.3452 image ({image_sha256})'
        )
    table = image[DECODE_TABLE_RVA:DECODE_TABLE_RVA + 0x100]
    if len(table) != 0x100:
        raise RuntimeError('runtime image does not contain the on-event decode table')
    self_test = run_self_test(table)
    if options.self_test:
        print(json.dumps({'self_test': self_test}, indent=2))

    emulator = OnEventProtectionEmulator(image)
    output_path = os.path.abspath(options.output)
    summary_path = os.path.abspath(options.summary or f'{options.output}.summary.json')
    scan_coverage = manifest_scan_coverage(options.events)
    if scan_coverage['events_manifest_path'] is None:
        raise RuntimeError('0x009e decoder requires a valid export manifest bound to --events')
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    os.makedirs(os.path.dirname(summary_path), exist_ok=True)

    counts = collections.Counter()
    event_counts = collections.Counter()
    selected_counts = collections.Counter()
    schema_counts = collections.Counter()
    size_counts = collections.Counter()
    replay_counts = collections.Counter()
    output_replay_counts = collections.Counter()
    amount_sign_counts = collections.Counter()
    heal_key_counts = collections.Counter()
    heal_blob_counts = collections.Counter()
    heal_last_occurrence = {}
    heal_duplicate_gaps = collections.Counter()
    previous_selected = None
    shield_pair_occurrence_deltas = collections.Counter()
    shield_receive_only_by_replay = collections.Counter()

    with open(options.events, encoding='utf-8') as source, open(
        output_path,
        'w',
        encoding='utf-8',
        newline='\n',
    ) as destination:
        for line_number, line in enumerate(source, start=1):
            if options.limit is not None and counts['input_event_count'] >= options.limit:
                break
            if not line.strip():
                continue
            event = json.loads(line)
            if event.get('packet_id') != ON_EVENT_PROFILE['client_opcode']:
                raise ValueError(
                    f"line {line_number} has packet {event.get('packet_id')}; "
                    f"expected {ON_EVENT_PROFILE['client_opcode']}"
                )
            decoded, row = decode_row(emulator, event, table, image_sha256)
            counts['input_event_count'] += 1
            counts['deserialize_success_count'] += int(
                decoded['deserialize_return_al'] != 0
            )
            counts['fully_consumed_count'] += int(decoded['fully_consumed'])
            object_bytes = bytes.fromhex(decoded['object_hex'])
            event_id = decode_event_id(object_bytes[0x10:0x12], table)
            event_counts[event_id] += 1
            replay_counts[event.get('replay_label')] += 1
            if row is None:
                continue

            selected_counts[event_id] += 1
            schema_counts[(event_id, row['schema_id'])] += 1
            size_counts[(event_id, row['parameter_size'])] += 1
            counts['output_event_count'] += 1
            if not row['schema_matches_expected']:
                counts['schema_mismatch_count'] += 1
            if not row['parameter_size_matches_expected']:
                counts['parameter_size_mismatch_count'] += 1
            if 'amount' in row:
                if not row['amount_is_finite']:
                    amount_sign_counts[(event_id, 'nonfinite')] += 1
                elif row['amount'] > 0:
                    amount_sign_counts[(event_id, 'positive')] += 1
                elif row['amount'] == 0:
                    amount_sign_counts[(event_id, 'zero')] += 1
                else:
                    amount_sign_counts[(event_id, 'negative')] += 1

            if event_id == 0x4B:
                heal_key = (
                    row['replay_label'],
                    row['replay_time_ms'],
                    row['source_network_id'],
                    row['target_network_id'],
                    row['amount_bits_hex'],
                )
                heal_blob_key = (
                    row['replay_label'],
                    row['replay_time_ms'],
                    row['parameter_blob_sha256'],
                )
                heal_key_counts[heal_key] += 1
                heal_blob_counts[heal_blob_key] += 1
                previous_occurrence = heal_last_occurrence.get(heal_blob_key)
                if previous_occurrence is not None:
                    heal_duplicate_gaps[
                        row['occurrence_index'] - previous_occurrence
                    ] += 1
                heal_last_occurrence[heal_blob_key] = row['occurrence_index']

            shield_pair = (
                previous_selected is not None
                and previous_selected['event_id'] == 0xEE
                and event_id == 0xED
                and previous_selected['replay_label'] == row['replay_label']
                and previous_selected['replay_time_ms'] == row['replay_time_ms']
                and previous_selected['parameter_blob_hex'] == row['parameter_blob_hex']
                and row['occurrence_index'] - previous_selected['occurrence_index'] == 1
            )
            if shield_pair:
                shield_pair_occurrence_deltas[
                    row['occurrence_index'] - previous_selected['occurrence_index']
                ] += 1
            elif event_id == 0xED:
                shield_receive_only_by_replay[row['replay_label']] += 1
            previous_selected = row
            output_replay_counts[row['replay_sha256']] += 1
            destination.write(json.dumps(row, ensure_ascii=True, separators=(',', ':')))
            destination.write('\n')
            if (
                options.progress_every
                and counts['input_event_count'] % options.progress_every == 0
            ):
                print(
                    f"decoded {counts['input_event_count']} on-event packets",
                    file=sys.stderr,
                )

    def duplicate_summary(counter):
        multiplicity = collections.Counter(counter.values())
        duplicate_group_count = sum(
            group_count
            for group_size, group_count in multiplicity.items()
            if group_size > 1
        )
        duplicate_row_count = sum(
            group_size * group_count
            for group_size, group_count in multiplicity.items()
            if group_size > 1
        )
        return {
            'group_count': len(counter),
            'duplicate_group_count': duplicate_group_count,
            'duplicate_row_count': duplicate_row_count,
            'excess_duplicate_row_count': sum(counter.values()) - len(counter),
            'multiplicity_histogram': histogram(multiplicity),
        }

    grant_count = selected_counts[0xEE]
    receive_count = selected_counts[0xED]
    paired_grant_count = sum(shield_pair_occurrence_deltas.values())
    heal_key_summary = duplicate_summary(heal_key_counts)
    heal_blob_summary = duplicate_summary(heal_blob_counts)
    # These zero values are part of the signed artifact contract; Counter
    # otherwise omits them for an empty route scan.
    for name in (
        'input_event_count', 'deserialize_success_count', 'fully_consumed_count',
        'output_event_count', 'schema_mismatch_count',
        'parameter_size_mismatch_count',
    ):
        counts.setdefault(name, 0)
    summary = {
        'schema_version': 1,
        'method': (
            'Unicorn x86-64 exact current-client constructor/deserializer with '
            'a V4-local semantic CRT memset stub'
        ),
        'image_path': os.path.abspath(options.image),
        'image_sha256': image_sha256,
        'decoder_profile': DECODER_PROFILE,
        'decoder_runtime_image_sha256': image_sha256,
        'events_path': os.path.abspath(options.events),
        'events_sha256': hashlib.sha256(
            Path(options.events).read_bytes()
        ).hexdigest(),
        'output_path': output_path,
        'client_opcode': '0x009e',
        'constructor_rva': '0x00e827e0',
        'deserialize_rva': '0x00fe12f0',
        'memset_stub_entry_rva': '0x019da180',
        'self_test': self_test,
        **counts,
        'event_counts': {
            f'0x{event_id:04x}': count
            for event_id, count in event_counts.most_common()
        },
        'selected_event_counts': {
            f'0x{event_id:04x}': selected_counts[event_id]
            for event_id in sorted(selected_counts)
        },
        'schema_counts': {
            f'0x{event_id:04x}:0x{schema_id:08x}': count
            for (event_id, schema_id), count in sorted(schema_counts.items())
        },
        'parameter_size_counts': {
            f'0x{event_id:04x}:{size}': count
            for (event_id, size), count in sorted(size_counts.items())
        },
        'amount_sign_counts': {
            f'0x{event_id:04x}:{sign}': count
            for (event_id, sign), count in sorted(amount_sign_counts.items())
        },
        'shield_route_deduplication': {
            'grant_count': grant_count,
            'receive_count': receive_count,
            'paired_grant_count': paired_grant_count,
            'grant_pair_rate': (
                paired_grant_count / grant_count if grant_count else None
            ),
            'paired_receive_count': paired_grant_count,
            'receive_pair_rate': (
                paired_grant_count / receive_count if receive_count else None
            ),
            'receive_only_count': receive_count - paired_grant_count,
            'receive_only_by_replay': dict(
                sorted(shield_receive_only_by_replay.items())
            ),
            'occurrence_delta_histogram': histogram(
                shield_pair_occurrence_deltas
            ),
            'canonical_rule': (
                'Use all 0x00ed OnReceiveShield rows. Every 0x00ee row is an '
                'exact immediately-followed duplicate route in this corpus.'
            ),
        },
        'heal_duplication': {
            'raw_row_count': selected_counts[0x4B],
            'timestamp_source_target_amount_bits': heal_key_summary,
            'timestamp_exact_parameter_blob': heal_blob_summary,
            'conservative_canonical_count_bounds': {
                'lower_bound_exact_blob_collapse': heal_blob_summary['group_count'],
                'upper_bound_preserve_raw_rows': selected_counts[0x4B],
            },
            'exact_blob_occurrence_gap_histogram': histogram(heal_duplicate_gaps),
            'canonical_rule': (
                'Preserve raw rows. Exact-blob collapse is only a conservative '
                'lower-bound candidate until HP-state validation.'
            ),
        },
        'replay_event_counts': dict(sorted(replay_counts.items())),
        'output_replay_counts': dict(sorted(output_replay_counts.items())),
        **scan_coverage,
    }
    summary['output_sha256'] = hashlib.sha256(open(output_path, 'rb').read()).hexdigest()
    with open(summary_path, 'w', encoding='utf-8', newline='\n') as stream:
        json.dump(summary, stream, ensure_ascii=True, indent=2)
        stream.write('\n')
    print(json.dumps({**summary, 'summary_path': summary_path}, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'{type(error).__name__}: {error}', file=sys.stderr)
        sys.exit(1)

#!/usr/bin/env python3

"""Execute current-build WardSpawn candidates and trace every object write."""

import argparse
import hashlib
import json
import math
import os
import struct
import sys
from collections import Counter

from unicorn import UC_HOOK_MEM_WRITE

import emulate_exact_packet_decoder as exact


CANDIDATES = {
    'exact_16_15_801': {
        'client_opcode': 0x0353,
        'constructor_rva': 0x00EB0640,
        'deserialize_rva': 0x0103B1C0,
        'deserialize_end_rva': 0x0103D737,
        'object_size': 0x90,
        'source': 'vtable 0x01b141b0 in exact 16.15.801.3452 runtime image',
        'runtime_singletons': [
            {
                'pointer_rva': 0x01EE9B18,
                'required_byte_offset': 0x70,
                'required_byte_value': 1,
                'reason': '0x00fa9810 requires the live runtime codec enable flag',
            },
        ],
    },
}

WARD_NAMES = (
    b'YellowTrinket',
    b'SightWard',
    b'JammerDevice',
    b'TrinketTotemLvl1',
)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--shapes', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--candidate', choices=sorted(CANDIDATES), default='exact_16_15_801')
    parser.add_argument('--packet-id', type=lambda value: int(value, 0))
    parser.add_argument('--max-shapes', type=int)
    parser.add_argument('--progress-every', type=int, default=250)
    return parser.parse_args()


class WardTraceEmulator(exact.ExactPacketEmulator):
    def __init__(self, image, candidate):
        super().__init__(image)
        self.candidate = candidate
        self.runtime_singleton_mappings = []
        for dependency in candidate.get('runtime_singletons', []):
            pointer = struct.unpack_from('<Q', image, dependency['pointer_rva'])[0]
            page = pointer & -exact.PAGE_SIZE
            try:
                self.emulator.mem_map(page, exact.PAGE_SIZE)
            except Exception:
                # Multiple globals may point into the same already mapped page.
                pass
            address = pointer + dependency['required_byte_offset']
            self.emulator.mem_write(address, bytes([dependency['required_byte_value']]))
            self.runtime_singleton_mappings.append({
                **dependency,
                'pointer_rva': f"0x{dependency['pointer_rva']:08x}",
                'resolved_pointer': f'0x{pointer:x}',
                'mapped_page': f'0x{page:x}',
                'written_address': f'0x{address:x}',
            })
        self.trace_enabled = False
        self.write_sequence = 0
        self.offset_writes = {}
        self.heap_high_water = exact.HEAP_BASE
        self.emulator.hook_add(
            UC_HOOK_MEM_WRITE,
            self._trace_object_write,
            begin=exact.OBJECT_ADDRESS,
            end=exact.OBJECT_ADDRESS + candidate['object_size'] - 1,
        )

    def reset_heap(self):
        if hasattr(self, 'heap_high_water'):
            used_size = self.heap_high_water - exact.HEAP_BASE
            if used_size > 0:
                self.emulator.mem_write(exact.HEAP_BASE, b'\x00' * used_size)
        super().reset_heap()

    def call(self, address, rcx=0, rdx=0, r8=0):
        tracing = address == exact.IMAGE_BASE + self.candidate['deserialize_rva']
        if tracing:
            self.write_sequence = 0
            self.offset_writes = {}
            self.trace_enabled = True
        try:
            result = super().call(address, rcx=rcx, rdx=rdx, r8=r8)
            self.heap_high_water = max(self.heap_high_water, self.heap_cursor)
            return result
        finally:
            if tracing:
                self.trace_enabled = False

    def _trace_object_write(self, _emulator, _access, address, size, value, _user_data):
        if not self.trace_enabled:
            return
        self.write_sequence += 1
        instruction = self.emulator.reg_read(exact.UC_X86_REG_RIP)
        first = max(address, exact.OBJECT_ADDRESS)
        last = min(address + size, exact.OBJECT_ADDRESS + self.candidate['object_size'])
        for byte_address in range(first, last):
            source_shift = (byte_address - address) * 8
            byte_value = (value >> source_shift) & 0xFF
            offset = byte_address - exact.OBJECT_ADDRESS
            self.offset_writes.setdefault(offset, []).append({
                'sequence': self.write_sequence,
                'instruction_rva': f'0x{instruction - exact.IMAGE_BASE:08x}',
                'write_offset': address - exact.OBJECT_ADDRESS,
                'write_size': size,
                'write_value_hex': f'0x{value & ((1 << (min(size, 8) * 8)) - 1):0{min(size, 8) * 2}x}',
                'byte_value': byte_value,
            })

    def ward_names(self, object_bytes):
        used_size = self.heap_cursor - exact.HEAP_BASE
        heap = (
            bytes(self.emulator.mem_read(exact.HEAP_BASE, used_size))
            if used_size > 0 else b''
        )
        return [
            name.decode('ascii')
            for name in WARD_NAMES
            if name in object_bytes or name in heap
        ]


def candidate_profile(candidate):
    return {
        **candidate,
        'fields': [],
    }


def event_values(offset_writes, size):
    """Reconstitute same-sequence writes of a given size at their starting offset."""
    values = []
    for offset, writes in offset_writes.items():
        for event in writes:
            if event['write_offset'] != offset or event['write_size'] != size:
                continue
            values.append((offset, event['sequence'], int(event['write_value_hex'], 16)))
    return values


def field_evidence(offset_writes, heap_name_hits):
    u32_values = event_values(offset_writes, 4)
    network_ids = [
        {'offset': offset, 'sequence': sequence, 'value_hex': f'0x{value:08x}'}
        for offset, sequence, value in u32_values
        if 0x40000000 <= value <= 0x4FFFFFFF
    ]
    coordinates = []
    for offset, sequence, value in u32_values:
        decoded = struct.unpack('<f', struct.pack('<I', value))[0]
        if math.isfinite(decoded) and -1000.0 <= decoded <= 20000.0:
            coordinates.append({
                'offset': offset,
                'sequence': sequence,
                'value': decoded,
            })
    coordinate_offsets = {item['offset'] for item in coordinates}
    def last_u32(offset):
        matches = [value for item_offset, _sequence, value in u32_values if item_offset == offset]
        return matches[-1] if matches else None

    def as_float(value):
        if value is None:
            return None
        decoded = struct.unpack('<f', struct.pack('<I', value))[0]
        return decoded if math.isfinite(decoded) else None

    owner_id = last_u32(0x30)
    entity_id = last_u32(0x44)
    position = {
        'x': as_float(last_u32(0x18)),
        'height': as_float(last_u32(0x1C)),
        'y': as_float(last_u32(0x20)),
    }
    reasonable = (
        bool(heap_name_hits)
        and owner_id is not None and 0x40000000 <= owner_id <= 0x4FFFFFFF
        and entity_id is not None and 0x40000000 <= entity_id <= 0x4FFFFFFF
        and position['x'] is not None and -1000.0 <= position['x'] <= 20000.0
        and position['y'] is not None and -1000.0 <= position['y'] <= 20000.0
    )
    return {
        'ward_name_hits': heap_name_hits,
        'network_id_write_candidates': network_ids,
        'coordinate_write_candidates': coordinates,
        'reasonable_ward_fields': reasonable,
        'recovered_fields': {
            'owner_network_id': owner_id,
            'owner_network_id_hex': f'0x{owner_id:08x}' if owner_id is not None else None,
            'entity_network_id': entity_id,
            'entity_network_id_hex': f'0x{entity_id:08x}' if entity_id is not None else None,
            'position': position,
        },
        'reasonableness_rule': (
            'known Ward name in object/allocated heap, 0x4xxxxxxx owner at +0x30, '
            '0x4xxxxxxx entity id at +0x44, and map-range x/y at +0x18/+0x20; '
            'values use the last 4-byte write before bytewise encrypted storage'
        ),
    }


def classify_error(error):
    message = str(error)
    if 'invalid memory access' in message:
        category = 'invalid_memory'
    elif 'heap exhausted' in message:
        category = 'heap_exhausted'
    elif 'payload is too large' in message:
        category = 'workspace_limit'
    else:
        category = type(error).__name__
    return {'category': category, 'type': type(error).__name__, 'message': message}


def main():
    options = parse_args()
    with open(options.image, 'rb') as stream:
        image = stream.read()
    with open(options.shapes, encoding='utf-8-sig') as stream:
        shape_bundle = json.load(stream)

    candidate = CANDIDATES[options.candidate]
    profile = candidate_profile(candidate)
    emulator = WardTraceEmulator(image, candidate)
    shapes = shape_bundle['shapes']
    if options.packet_id is not None:
        shapes = [shape for shape in shapes if shape['packet_id'] == options.packet_id]
    if options.max_shapes is not None:
        shapes = shapes[:options.max_shapes]

    results = []
    counters = Counter()
    max_payload_length = 0
    for shape_index, shape in enumerate(shapes, 1):
        samples = []
        max_payload_length = max(max_payload_length, shape['payload_length'])
        for sample in shape['samples']:
            counters['sample_count'] += 1
            try:
                decoded = emulator.decode(
                    bytes.fromhex(sample['raw_payload_hex']),
                    profile,
                    packet_id=sample.get('packet_id'),
                    raw_param=sample.get('raw_param'),
                )
                offset_writes = {
                    f'0x{offset:02x}': writes
                    for offset, writes in sorted(emulator.offset_writes.items())
                }
                evidence = field_evidence(
                    emulator.offset_writes,
                    emulator.ward_names(bytes.fromhex(decoded['object_hex'])),
                )
                cursor_valid = 0 <= decoded['bytes_consumed'] <= (
                    len(bytes.fromhex(decoded['base_header_hex'])) + shape['payload_length']
                )
                decoder_accepted = decoded['deserialize_return_al'] != 0
                accepted_candidate = (
                    decoder_accepted and cursor_valid and evidence['reasonable_ward_fields']
                )
                counters['decoder_accept_count'] += int(decoder_accepted)
                counters['accepted_candidate_count'] += int(accepted_candidate)
                counters['fully_consumed_count'] += int(decoded['fully_consumed'])
                samples.append({
                    **sample,
                    'execution_status': 'completed',
                    'deserialize_return_al': decoded['deserialize_return_al'],
                    'bytes_consumed': decoded['bytes_consumed'],
                    'fully_consumed': decoded['fully_consumed'],
                    'base_header_hex': decoded['base_header_hex'],
                    'wrapper_return_al': decoded['wrapper_return_al'],
                    'wrapper_bytes_consumed': decoded['wrapper_bytes_consumed'],
                    'decoded_opcode': decoded['decoded_opcode'],
                    'decoded_opcode_hex': decoded['decoded_opcode_hex'],
                    'opcode_matches_profile': decoded['opcode_matches_profile'],
                    'cursor_valid': cursor_valid,
                    'decoder_accepted': decoder_accepted,
                    'accepted_candidate': accepted_candidate,
                    'object_hex': decoded['object_hex'],
                    'object_write_event_count': emulator.write_sequence,
                    'object_offset_writes': offset_writes,
                    'field_evidence': evidence,
                })
            except Exception as error:  # Keep infrastructure failures distinct from rejects.
                failure = classify_error(error)
                counters['infrastructure_failure_count'] += 1
                counters[f"infrastructure_failure:{failure['category']}"] += 1
                samples.append({
                    **sample,
                    'execution_status': 'infrastructure_failure',
                    'infrastructure_failure': failure,
                    'object_write_event_count_before_failure': emulator.write_sequence,
                    'object_offset_writes_before_failure': {
                        f'0x{offset:02x}': writes
                        for offset, writes in sorted(emulator.offset_writes.items())
                    },
                })
        results.append({
            'packet_id': shape['packet_id'],
            'payload_length': shape['payload_length'],
            'occurrence_count': shape['occurrence_count'],
            'replay_count': shape['replay_count'],
            'samples': samples,
        })
        if options.progress_every and shape_index % options.progress_every == 0:
            print(
                f'{shape_index}/{len(shapes)} shapes; '
                f"samples={counters['sample_count']} accepts={counters['decoder_accept_count']} "
                f"plausible={counters['accepted_candidate_count']} "
                f"infra={counters['infrastructure_failure_count']}",
                file=sys.stderr,
                flush=True,
            )

    summary = {key: value for key, value in sorted(counters.items())}
    summary['shape_count'] = len(results)
    summary['max_payload_length'] = max_payload_length
    summary['fully_consumed_is_success_criterion'] = False
    output = {
        'schema_version': 1,
        'target_replay_version': shape_bundle['target_replay_version'],
        'method': 'Unicorn x86-64 exact-image execution with UC_HOOK_MEM_WRITE object tracing',
        'image_path': os.path.abspath(options.image),
        'image_sha256': hashlib.sha256(image).hexdigest(),
        'shape_source_path': os.path.abspath(options.shapes),
        'shape_source_sha256': hashlib.sha256(open(options.shapes, 'rb').read()).hexdigest(),
        'candidate_name': options.candidate,
        'candidate': {
            **candidate,
            'constructor_rva': f"0x{candidate['constructor_rva']:08x}",
            'deserialize_rva': f"0x{candidate['deserialize_rva']:08x}",
            'deserialize_end_rva': f"0x{candidate['deserialize_end_rva']:08x}",
        },
        'runtime_singleton_mappings': emulator.runtime_singleton_mappings,
        'packet_id_filter': options.packet_id,
        'max_shapes': options.max_shapes,
        'success_policy': (
            'accepted_candidate requires nonzero deserialize AL, cursor within wire payload, '
            'and reasonable Ward field evidence; fully_consumed alone is never success'
        ),
        'summary': summary,
        'results': results,
    }
    output_path = os.path.abspath(options.output)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8', newline='\n') as stream:
        json.dump(output, stream, ensure_ascii=True, separators=(',', ':'))
        stream.write('\n')
    print(json.dumps({'output': output_path, 'summary': summary}, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'{type(error).__name__}: {error}', file=sys.stderr)
        sys.exit(1)

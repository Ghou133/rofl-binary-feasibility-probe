#!/usr/bin/env python3

"""Verify and emulate the 16.15 PathPacket candidate against replay shapes."""

import argparse
import bisect
from collections import Counter, defaultdict
import glob
import hashlib
import json
import math
import os
import struct
import sys

import emulate_exact_packet_decoder as exact


IMAGE_BASE = exact.IMAGE_BASE
VTABLE_RVA = 0x01B135D8
DESERIALIZE_RVA = 0x0103F810
DESERIALIZE_END_RVA = 0x0103FBC9
PATH_CONSTRUCTOR_RVA = 0x00EB1B90
ALTERNATE_CONSTRUCTOR_RVA = 0x00EB1AD0
COPY_FACTORY_RVA = 0x00EDDAE0
OBJECT_SIZE = 0x28
PATH_OPCODE = 0x02D1
ALTERNATE_OPCODE = 0x041E
RUNTIME_MEMSET_RVA = 0x019DA180


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--shapes', required=True)
    parser.add_argument('--analysis-output', required=True)
    parser.add_argument('--emulation-output', required=True)
    parser.add_argument('--max-shapes', type=int)
    parser.add_argument('--packet-id', type=lambda value: int(value, 0))
    parser.add_argument('--progress-every', type=int, default=250)
    parser.add_argument('--raw-packets')
    parser.add_argument('--cast-events-root')
    parser.add_argument('--decoded-packets-output')
    parser.add_argument('--hero-path-output')
    parser.add_argument('--hero-positions-output')
    parser.add_argument('--calibration-output')
    return parser.parse_args()


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def file_evidence(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return {
        'path': os.path.abspath(path),
        'bytes': os.path.getsize(path),
        'sha256': digest.hexdigest(),
    }


def read_u16(value, offset):
    return struct.unpack_from('<H', value, offset)[0]


def read_u32(value, offset):
    return struct.unpack_from('<I', value, offset)[0]


def read_u64(value, offset):
    return struct.unpack_from('<Q', value, offset)[0]


def static_analysis(image):
    vtable = [read_u64(image, VTABLE_RVA + index * 8) for index in range(6)]
    expected_vtable = [
        IMAGE_BASE + 0x001F0BB0,
        IMAGE_BASE + DESERIALIZE_RVA,
        IMAGE_BASE + 0x00309220,
        IMAGE_BASE + 0x00369930,
        IMAGE_BASE + 0x0021AAC0,
        IMAGE_BASE + COPY_FACTORY_RVA,
    ]
    ctor_checks = []
    for name, rva, opcode in (
        ('path', PATH_CONSTRUCTOR_RVA, PATH_OPCODE),
        ('alternate_same_vtable', ALTERNATE_CONSTRUCTOR_RVA, ALTERNATE_OPCODE),
    ):
        body = image[rva:rva + 0x82]
        opcode_bytes = b'\x66\xc7\x41\x08' + struct.pack('<H', opcode)
        vtable_lea_offset = 0x24
        lea_rva = rva + vtable_lea_offset
        lea = image[lea_rva:lea_rva + 7]
        lea_target = None
        if lea[:3] == b'\x48\x8d\x05':
            lea_target = lea_rva + 7 + struct.unpack_from('<i', lea, 3)[0]
        ctor_checks.append({
            'name': name,
            'constructor_rva': f'0x{rva:08x}',
            'opcode': f'0x{opcode:04x}',
            'opcode_store_found': opcode_bytes in body,
            'derived_vtable_lea_rva': f'0x{lea_rva:08x}',
            'derived_vtable_target_rva': (
                f'0x{lea_target:08x}' if lea_target is not None else None
            ),
            'derived_vtable_matches': lea_target == VTABLE_RVA,
            'constructor_slice_sha256': sha256(body),
        })

    factory = image[COPY_FACTORY_RVA:COPY_FACTORY_RVA + 0x98]
    allocation_signature = b'\xb9\x28\x00\x00\x00\xe8'
    copies_payload_member = (
        b'\x48\x8d\x56\x18' in factory
        and b'\x48\x8d\x4b\x18' in factory
    )
    checks = {
        'vtable_matches': vtable == expected_vtable,
        'constructors_match': all(
            item['opcode_store_found'] and item['derived_vtable_matches']
            for item in ctor_checks
        ),
        'factory_allocates_0x28': allocation_signature in factory,
        'factory_copies_payload_member_at_0x18': copies_payload_member,
    }
    return {
        'schema_version': 1,
        'scope': 'Independent static verification in the exact 16.15 runtime image.',
        'image_sha256': sha256(image),
        'candidate': {
            'vtable_rva': f'0x{VTABLE_RVA:08x}',
            'vtable_slots': [f'0x{value - IMAGE_BASE:08x}' for value in vtable],
            'deserialize_slot': 1,
            'deserialize_rva': f'0x{DESERIALIZE_RVA:08x}',
            'deserialize_end_rva_exclusive': f'0x{DESERIALIZE_END_RVA:08x}',
            'deserialize_bytes': DESERIALIZE_END_RVA - DESERIALIZE_RVA,
            'deserialize_sha256': sha256(image[DESERIALIZE_RVA:DESERIALIZE_END_RVA]),
            'object_size': OBJECT_SIZE,
            'payload_pointer_offset': '0x18',
            'payload_size_u32_offset': '0x20',
        },
        'constructors': ctor_checks,
        'copy_factory': {
            'rva': f'0x{COPY_FACTORY_RVA:08x}',
            'slice_sha256': sha256(factory),
            'allocation_size': OBJECT_SIZE,
        },
        'checks': checks,
        'all_checks_pass': all(checks.values()),
        'opcode_conclusion': {
            'path_replay_packet_id': PATH_OPCODE,
            'path_replay_packet_id_hex': f'0x{PATH_OPCODE:04x}',
            'basis': (
                'The exact-image constructor at 0x00eb1b90 stores 0x02d1 at '
                'object+8 and installs vtable 0x01b135d8. Dynamic execution is '
                'required separately to establish payload semantics.'
            ),
            'alternate_opcode_same_vtable': f'0x{ALTERNATE_OPCODE:04x}',
            'qualification': (
                'The shared vtable means both packet classes use the same wire '
                'field container; it does not make 0x041e a movement packet.'
            ),
        },
    }


def historical_compatible_parse_record(payload):
    """Parse one old-layout record from the front of a current plaintext buffer."""
    if len(payload) < 10:
        raise ValueError('payload shorter than 10-byte path prefix')
    parsing_type = read_u16(payload, 0)
    entity_id = read_u32(payload, 2)
    speed = struct.unpack_from('<f', payload, 6)[0]
    if not math.isfinite(speed):
        raise ValueError('non-finite speed')
    cursor = 10
    if parsing_type & 1:
        if cursor >= len(payload):
            raise ValueError('missing optional byte')
        cursor += 1
    temp = payload[cursor:]
    count = (parsing_type & 0xff) >> 1
    if count == 0:
        raise ValueError('zero waypoint count')
    if count > 1:
        cursor += ((count - 2) >> 2) + 1
    if cursor > len(payload):
        raise ValueError('missing compression bitmap')
    encoded = []
    bit_index = 0
    x_coord = 0
    y_coord = 0
    for waypoint_index in range(count):
        x_width = 2
        y_width = 2
        if waypoint_index:
            byte_index = bit_index >> 3
            if byte_index >= len(temp):
                raise ValueError('compression bitmap truncated')
            x_width = 1 if temp[byte_index] & (1 << (bit_index & 7)) else 2
            bit_index += 1
            byte_index = bit_index >> 3
            if byte_index >= len(temp):
                raise ValueError('compression bitmap truncated')
            y_width = 1 if temp[byte_index] & (1 << (bit_index & 7)) else 2
            bit_index += 1
        if cursor + x_width + y_width > len(payload):
            raise ValueError('coordinate stream truncated')
        if x_width == 1:
            x_coord = (x_coord + payload[cursor]) & 0xffff
            cursor += 1
        else:
            x_coord = read_u16(payload, cursor)
            cursor += 2
        if y_width == 1:
            y_coord = (y_coord + payload[cursor]) & 0xffff
            cursor += 1
        else:
            y_coord = read_u16(payload, cursor)
            cursor += 2
        encoded.append([x_coord, y_coord])
    return {
        'parsing_type': parsing_type,
        'entity_id': entity_id,
        'entity_id_hex': f'0x{entity_id:08x}',
        'speed': speed,
        'waypoint_count': count,
        'encoded_waypoints': encoded,
        'parser_bytes_consumed': cursor,
        'coordinate_transform_applied': False,
    }


def historical_compatible_parse(payload):
    """Probe a stream of records without claiming the old map transform is current."""
    records = []
    cursor = 0
    while cursor < len(payload):
        record = historical_compatible_parse_record(payload[cursor:])
        consumed = record['parser_bytes_consumed']
        if consumed <= 0:
            raise ValueError('path record parser made no progress')
        record['stream_offset'] = cursor
        records.append(record)
        cursor += consumed
    return {
        'record_count': len(records),
        'records': records,
        'parser_bytes_consumed': cursor,
        'parser_fully_consumed': cursor == len(payload),
        'coordinate_transform_applied': False,
    }


def classify_error(error):
    message = str(error)
    if 'invalid memory access' in message:
        category = 'invalid_memory'
    elif 'Invalid instruction' in message:
        category = 'invalid_instruction'
    elif 'heap exhausted' in message:
        category = 'heap_exhausted'
    else:
        category = type(error).__name__
    return {'category': category, 'type': type(error).__name__, 'message': message}


def extract_payload(emulator, object_hex):
    object_bytes = bytes.fromhex(object_hex)
    pointer = read_u64(object_bytes, 0x18)
    size = read_u32(object_bytes, 0x20)
    valid = (
        size > 0
        and exact.HEAP_BASE <= pointer < exact.HEAP_BASE + exact.HEAP_SIZE
        and pointer + size <= exact.HEAP_BASE + exact.HEAP_SIZE
    )
    result = {
        'payload_pointer': f'0x{pointer:x}',
        'payload_size': size,
        'payload_pointer_size_valid': valid,
    }
    if valid:
        payload = bytes(emulator.emulator.mem_read(pointer, size))
        result['decoded_payload_hex'] = payload.hex()
        try:
            result['historical_compatible_parse'] = historical_compatible_parse(payload)
        except Exception as error:
            result['historical_compatible_parse_error'] = str(error)
    return result


class PathPacketEmulator(exact.ExactPacketEmulator):
    """Exact decoder with a semantic stub for the runtime's AVX memset."""

    def __init__(self, image):
        super().__init__(image)
        self.emulator.hook_add(
            exact.UC_HOOK_CODE,
            self._memset,
            begin=IMAGE_BASE + RUNTIME_MEMSET_RVA,
            end=IMAGE_BASE + RUNTIME_MEMSET_RVA,
        )

    def _memset(self, _emulator, _address, _size, _user_data):
        destination = self.emulator.reg_read(exact.UC_X86_REG_RCX)
        byte_value = self.emulator.reg_read(exact.UC_X86_REG_RDX) & 0xff
        length = self.emulator.reg_read(exact.UC_X86_REG_R8)
        if length > exact.HEAP_SIZE:
            raise RuntimeError(f'emulated memset exceeded heap limit: {length}')
        if length:
            self.emulator.mem_write(destination, bytes([byte_value]) * length)
        self.emulator.reg_write(exact.UC_X86_REG_RAX, destination)
        self._return_from_stub()


def emulate(image, shape_bundle, max_shapes=None, packet_id=None, progress_every=250):
    profile = {
        'client_opcode': PATH_OPCODE,
        'constructor_rva': PATH_CONSTRUCTOR_RVA,
        'deserialize_rva': DESERIALIZE_RVA,
        'object_size': OBJECT_SIZE,
        'fields': [],
    }
    emulator = PathPacketEmulator(image)
    shapes = shape_bundle['shapes']
    if packet_id is not None:
        shapes = [shape for shape in shapes if shape['packet_id'] == packet_id]
    if max_shapes is not None:
        shapes = shapes[:max_shapes]
    counters = Counter()
    accepted_by_packet = defaultdict(lambda: Counter())
    results = []
    for shape_index, shape in enumerate(shapes, 1):
        samples = []
        for sample in shape['samples']:
            counters['sample_count'] += 1
            try:
                decoded = emulator.decode(
                    bytes.fromhex(sample['raw_payload_hex']),
                    profile,
                    packet_id=sample.get('packet_id'),
                    raw_param=sample.get('raw_param'),
                )
                extracted = extract_payload(emulator, decoded['object_hex'])
                accepted = decoded['deserialize_return_al'] != 0
                current_path_payload = accepted and extracted['payload_pointer_size_valid']
                compatible = bool(
                    extracted.get('historical_compatible_parse', {}).get(
                        'parser_fully_consumed'
                    )
                )
                counters['decoder_accept_count'] += int(accepted)
                counters['current_payload_count'] += int(current_path_payload)
                counters['compatible_parse_count'] += int(current_path_payload and compatible)
                if accepted:
                    accepted_by_packet[shape['packet_id']]['accepted_samples'] += 1
                    accepted_by_packet[shape['packet_id']]['valid_payloads'] += int(
                        current_path_payload
                    )
                    accepted_by_packet[shape['packet_id']]['compatible_parses'] += int(
                        current_path_payload and compatible
                    )
                record = {
                    'replay': sample.get('replay'),
                    'packet_id': sample.get('packet_id'),
                    'raw_param': sample.get('raw_param'),
                    'execution_status': 'completed',
                    'deserialize_return_al': decoded['deserialize_return_al'],
                    'bytes_consumed': decoded['bytes_consumed'],
                    'fully_consumed': decoded['fully_consumed'],
                    'decoder_accepted': accepted,
                    'current_path_payload': current_path_payload,
                }
                if accepted:
                    record.update(extracted)
                samples.append(record)
            except Exception as error:
                failure = classify_error(error)
                counters['infrastructure_failure_count'] += 1
                counters[f"infrastructure_failure:{failure['category']}"] += 1
                samples.append({
                    'replay': sample.get('replay'),
                    'packet_id': sample.get('packet_id'),
                    'raw_param': sample.get('raw_param'),
                    'execution_status': 'infrastructure_failure',
                    'infrastructure_failure': failure,
                })
        results.append({
            'packet_id': shape['packet_id'],
            'payload_length': shape['payload_length'],
            'occurrence_count': shape['occurrence_count'],
            'replay_count': shape['replay_count'],
            'samples': samples,
        })
        if progress_every and shape_index % progress_every == 0:
            print(
                f'{shape_index}/{len(shapes)} shapes samples={counters["sample_count"]} '
                f'accepts={counters["decoder_accept_count"]} '
                f'payloads={counters["current_payload_count"]} '
                f'infra={counters["infrastructure_failure_count"]}',
                file=sys.stderr,
                flush=True,
            )
    packet_summary = []
    for pid, counts in sorted(accepted_by_packet.items()):
        packet_summary.append({
            'packet_id': pid,
            'packet_id_hex': f'0x{pid:04x}',
            **dict(counts),
        })
    return {
        'schema_version': 1,
        'target_replay_version': shape_bundle['target_replay_version'],
        'method': 'Unicorn x86-64 execution of exact unpacked 16.15 image',
        'runtime_stubs': [{
            'rva': f'0x{RUNTIME_MEMSET_RVA:08x}',
            'operation': 'memset(rcx, dl, r8)',
            'reason': (
                'Semantic equivalent for the runtime AVX implementation because '
                'Unicorn rejects its VEX instruction path.'
            ),
        }],
        'success_rule': (
            'deserialize AL is nonzero and object +0x18/+0x20 is a nonempty '
            'pointer/size pair wholly inside the emulator allocation heap'
        ),
        'fully_consumed_alone_is_success': False,
        'image_sha256': sha256(image),
        'candidate': {
            'packet_id': PATH_OPCODE,
            'packet_id_hex': f'0x{PATH_OPCODE:04x}',
            'constructor_rva': f'0x{PATH_CONSTRUCTOR_RVA:08x}',
            'deserialize_rva': f'0x{DESERIALIZE_RVA:08x}',
            'object_size': OBJECT_SIZE,
            'payload_pointer_offset': '0x18',
            'payload_size_u32_offset': '0x20',
        },
        'input_shape_count': len(shapes),
        'input_sample_count': counters['sample_count'],
        'packet_id_filter': packet_id,
        'counters': dict(sorted(counters.items())),
        'accepted_packet_summary': packet_summary,
        'historical_compatibility_qualification': (
            'The parser tests whether the current plaintext payload still follows '
            'the old prefix/compression grammar. It deliberately does not apply or '
            'validate the historical 7358/7412 map transform.'
        ),
        'results': results,
    }


def write_json(path, value):
    output = os.path.abspath(path)
    os.makedirs(os.path.dirname(output), exist_ok=True)
    with open(output, 'w', encoding='utf-8', newline='\n') as stream:
        json.dump(value, stream, ensure_ascii=True, indent=2)
        stream.write('\n')
    return output


def summarize_path_packet(emulation):
    shapes = [
        shape for shape in emulation['results']
        if shape['packet_id'] == PATH_OPCODE
    ]
    samples = [sample for shape in shapes for sample in shape['samples']]
    payload_sizes = []
    records = []
    for sample in samples:
        if sample.get('current_path_payload'):
            payload_sizes.append(sample['payload_size'])
            parsed = sample.get('historical_compatible_parse')
            if parsed:
                records.extend(parsed['records'])
    speeds = [record['speed'] for record in records]
    waypoint_counts = [record['waypoint_count'] for record in records]
    entity_ids = {record['entity_id'] for record in records}
    return {
        'packet_id': PATH_OPCODE,
        'packet_id_hex': f'0x{PATH_OPCODE:04x}',
        'shape_count': len(shapes),
        'sample_count': len(samples),
        'completed_count': sum(
            sample['execution_status'] == 'completed' for sample in samples
        ),
        'deserialize_accept_count': sum(
            bool(sample.get('decoder_accepted')) for sample in samples
        ),
        'valid_plaintext_payload_count': len(payload_sizes),
        'fully_compatible_payload_count': sum(
            bool(sample.get('historical_compatible_parse', {}).get(
                'parser_fully_consumed'
            ))
            for sample in samples
        ),
        'decoded_record_count': len(records),
        'unique_entity_id_count': len(entity_ids),
        'network_id_like_record_count': sum(
            0x40000000 <= record['entity_id'] <= 0x4fffffff
            for record in records
        ),
        'payload_size_range': (
            [min(payload_sizes), max(payload_sizes)] if payload_sizes else None
        ),
        'speed_range': [min(speeds), max(speeds)] if speeds else None,
        'waypoint_count_range': (
            [min(waypoint_counts), max(waypoint_counts)]
            if waypoint_counts else None
        ),
        'all_samples_verified': bool(samples) and all(
            sample['execution_status'] == 'completed'
            and sample.get('decoder_accepted')
            and sample.get('current_path_payload')
            and sample.get('historical_compatible_parse', {}).get(
                'parser_fully_consumed'
            )
            for sample in samples
        ),
    }


def signed_u16(value):
    return value - 0x10000 if value & 0x8000 else value


def candidate_position(encoded):
    return [signed_u16(encoded[0]) * 2 + 7358, signed_u16(encoded[1]) * 2 + 7412]


def path_raw_packet_ref(raw):
    """Return the stable source fields needed to audit a decoded path record."""
    return {
        'replay_sha256': raw['replay_sha256'],
        'chunk_index': raw['chunk_index'],
        'decompressed_block_offset': raw['decompressed_block_offset'],
        'packet_id': raw['packet_id'],
        'packet_type': raw.get('packet_type', f"0x{raw['packet_id']:04x}"),
        'payload_length': raw['payload_length'],
        'raw_param': raw['raw_param'],
        'raw_payload_sha256': raw['raw_payload_sha256'],
        'packet_timestamp_ms': raw['replay_time_ms'],
    }


def load_cast_events(root):
    events = []
    hero_ids = defaultdict(set)
    paths = sorted(glob.glob(os.path.join(root, '*', 'spell_events.jsonl')))
    for path in paths:
        with open(path, encoding='utf-8') as stream:
            for line in stream:
                event = json.loads(line)
                replay_sha = event.get('raw_packet_ref', {}).get('replay_sha256')
                entity_id = event.get('caster_network_id')
                position = event.get('target_position')
                if replay_sha is None or entity_id is None or position is None:
                    continue
                if event.get('caster_participant_id') is not None:
                    hero_ids[replay_sha].add(entity_id)
                events.append({
                    'replay_sha256': replay_sha,
                    'timestamp_ms': event['replay_time_ms'],
                    'entity_id': entity_id,
                    'position_xz': [position[0], position[2]],
                    'target_position_end_xz': (
                        [event['target_position_end'][0], event['target_position_end'][2]]
                        if event.get('target_position_end') else None
                    ),
                    'is_ward_cast': event.get('spell_identifier') == 'TrinketTotemLvl1',
                    'spell_identifier': event.get('spell_identifier'),
                })
    return paths, events, hero_ids


def decode_raw_packets(image, raw_path, decoded_path, hero_path, hero_ids, progress_every):
    profile = {
        'client_opcode': PATH_OPCODE,
        'constructor_rva': PATH_CONSTRUCTOR_RVA,
        'deserialize_rva': DESERIALIZE_RVA,
        'object_size': OBJECT_SIZE,
        'fields': [],
    }
    emulator = PathPacketEmulator(image)
    decoded_output = os.path.abspath(decoded_path)
    hero_output = os.path.abspath(hero_path)
    os.makedirs(os.path.dirname(decoded_output), exist_ok=True)
    os.makedirs(os.path.dirname(hero_output), exist_ok=True)
    counters = Counter()
    replay_counts = Counter()
    hero_events = defaultdict(list)
    with open(raw_path, encoding='utf-8') as source, open(
        decoded_output, 'w', encoding='utf-8', newline='\n'
    ) as decoded_stream, open(
        hero_output, 'w', encoding='utf-8', newline='\n'
    ) as hero_stream:
        for line in source:
            raw = json.loads(line)
            counters['packet_count'] += 1
            decoded = emulator.decode(
                bytes.fromhex(raw['raw_payload_hex']),
                profile,
                packet_id=raw['packet_id'],
                raw_param=raw['raw_param'],
            )
            if decoded['deserialize_return_al'] == 0:
                raise RuntimeError(
                    f"Path decoder rejected occurrence {raw['occurrence_index']}"
                )
            extracted = extract_payload(emulator, decoded['object_hex'])
            if not extracted['payload_pointer_size_valid']:
                raise RuntimeError(
                    f"invalid Path payload at occurrence {raw['occurrence_index']}"
                )
            parsed = extracted.get('historical_compatible_parse')
            if not parsed or not parsed['parser_fully_consumed']:
                raise RuntimeError(
                    f"Path grammar failed at occurrence {raw['occurrence_index']}: "
                    f"{extracted.get('historical_compatible_parse_error')}"
                )
            records = []
            for record_index, record in enumerate(parsed['records']):
                compact = {
                    'record_index': record_index,
                    'stream_offset': record['stream_offset'],
                    'parsing_type': record['parsing_type'],
                    'entity_id': record['entity_id'],
                    'speed': record['speed'],
                    'encoded_waypoints': record['encoded_waypoints'],
                }
                records.append(compact)
                counters['record_count'] += 1
                if record['entity_id'] in hero_ids.get(raw['replay_sha256'], set()):
                    waypoints = [candidate_position(item) for item in record['encoded_waypoints']]
                    hero_event = {
                        'schema_version': 1,
                        'event_type': 'hero_path_candidate',
                        'replay_sha256': raw['replay_sha256'],
                        'replay_label': raw['replay_label'],
                        'timestamp_ms': raw['replay_time_ms'],
                        'entity_id': record['entity_id'],
                        'speed': record['speed'],
                        'encoded_waypoints': record['encoded_waypoints'],
                        'candidate_waypoints_xz': waypoints,
                        'coordinate_transform_status': 'CANDIDATE_PENDING_CALIBRATION',
                        'raw_packet_occurrence_index': raw['occurrence_index'],
                        'record_index': record_index,
                        'raw_packet_ref': path_raw_packet_ref(raw),
                    }
                    hero_stream.write(json.dumps(hero_event, separators=(',', ':')) + '\n')
                    hero_events[(raw['replay_sha256'], record['entity_id'])].append(hero_event)
                    counters['hero_record_count'] += 1
            row = {
                'schema_version': 1,
                'event_type': 'path_packet_plaintext',
                'replay_sha256': raw['replay_sha256'],
                'replay_label': raw['replay_label'],
                'timestamp_ms': raw['replay_time_ms'],
                'packet_id': raw['packet_id'],
                'raw_param': raw['raw_param'],
                'occurrence_index': raw['occurrence_index'],
                'payload_size': extracted['payload_size'],
                'records': records,
                'raw_packet_ref': {
                    'chunk_index': raw['chunk_index'],
                    'decompressed_block_offset': raw['decompressed_block_offset'],
                    'raw_payload_sha256': raw['raw_payload_sha256'],
                },
            }
            decoded_stream.write(json.dumps(row, separators=(',', ':')) + '\n')
            replay_counts[raw['replay_sha256']] += 1
            if progress_every and counters['packet_count'] % progress_every == 0:
                print(
                    f"raw packets={counters['packet_count']} records={counters['record_count']} "
                    f"hero={counters['hero_record_count']}",
                    file=sys.stderr,
                    flush=True,
                )
    for events in hero_events.values():
        events.sort(key=lambda item: item['timestamp_ms'])
    return {
        'decoded_packets_output': decoded_output,
        'hero_path_output': hero_output,
        'counters': dict(counters),
        'replay_packet_counts': dict(replay_counts),
    }, hero_events


def percentile(values, probability):
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * probability)))
    return ordered[index]


def error_summary(values):
    return {
        'count': len(values),
        'mean': sum(values) / len(values) if values else None,
        'p50': percentile(values, 0.50),
        'p90': percentile(values, 0.90),
        'p95': percentile(values, 0.95),
        'p99': percentile(values, 0.99),
        'max': max(values) if values else None,
        'within_100': sum(value <= 100 for value in values),
        'within_250': sum(value <= 250 for value in values),
        'within_500': sum(value <= 500 for value in values),
    }


def nearest_path_event(events, timestamp_ms, window_ms=250):
    if not events:
        return None
    times = [item['timestamp_ms'] for item in events]
    index = bisect.bisect_left(times, timestamp_ms)
    candidates = events[max(0, index - 1):min(len(events), index + 1)]
    if not candidates:
        return None
    result = min(candidates, key=lambda item: abs(item['timestamp_ms'] - timestamp_ms))
    return result if abs(result['timestamp_ms'] - timestamp_ms) <= window_ms else None


def fit_linear(pairs):
    mean_x = sum(pair[0] for pair in pairs) / len(pairs)
    mean_y = sum(pair[1] for pair in pairs) / len(pairs)
    denominator = sum((pair[0] - mean_x) ** 2 for pair in pairs)
    slope = sum((x - mean_x) * (y - mean_y) for x, y in pairs) / denominator
    return slope, mean_y - slope * mean_x


def calibrate_transform(cast_events, hero_events):
    matches = []
    for cast in cast_events:
        path = nearest_path_event(
            hero_events.get((cast['replay_sha256'], cast['entity_id']), []),
            cast['timestamp_ms'],
        )
        if path is None or not path['encoded_waypoints']:
            continue
        encoded = path['encoded_waypoints'][0]
        signed = [signed_u16(encoded[0]), signed_u16(encoded[1])]
        old = candidate_position(encoded)
        actual = cast['position_xz']
        old_error = math.hypot(old[0] - actual[0], old[1] - actual[1])
        swapped = [signed[1] * 2 + 7358, signed[0] * 2 + 7412]
        swapped_error = math.hypot(swapped[0] - actual[0], swapped[1] - actual[1])
        end_error = None
        if cast['target_position_end_xz'] is not None:
            end = cast['target_position_end_xz']
            end_error = math.hypot(old[0] - end[0], old[1] - end[1])
        matches.append({
            'replay_sha256': cast['replay_sha256'],
            'entity_id': cast['entity_id'],
            'cast_timestamp_ms': cast['timestamp_ms'],
            'path_timestamp_ms': path['timestamp_ms'],
            'delta_ms': path['timestamp_ms'] - cast['timestamp_ms'],
            'encoded_first_waypoint': encoded,
            'actual_cast_start_xz': actual,
            'candidate_xz': old,
            'candidate_error': old_error,
            'swapped_error': swapped_error,
            'is_ward_cast': cast['is_ward_cast'],
            'ward_target_end_error': end_error if cast['is_ward_cast'] else None,
        })
    direct_x = [(signed_u16(m['encoded_first_waypoint'][0]), m['actual_cast_start_xz'][0]) for m in matches]
    direct_y = [(signed_u16(m['encoded_first_waypoint'][1]), m['actual_cast_start_xz'][1]) for m in matches]
    swapped_x = [(signed_u16(m['encoded_first_waypoint'][1]), m['actual_cast_start_xz'][0]) for m in matches]
    swapped_y = [(signed_u16(m['encoded_first_waypoint'][0]), m['actual_cast_start_xz'][1]) for m in matches]
    fit = None
    swapped_fit = None
    if len(matches) >= 2:
        fit = {'x': fit_linear(direct_x), 'z': fit_linear(direct_y)}
        swapped_fit = {'x_from_y': fit_linear(swapped_x), 'z_from_x': fit_linear(swapped_y)}
    ward_matches = [match for match in matches if match['is_ward_cast']]
    accepted = (
        len(matches) >= 100
        and error_summary([m['candidate_error'] for m in matches])['p95'] <= 500
        and error_summary([m['candidate_error'] for m in matches])['p50']
        < error_summary([m['swapped_error'] for m in matches])['p50'] * 0.25
    )
    return {
        'match_window_ms': 250,
        'match_count': len(matches),
        'replay_count': len({match['replay_sha256'] for match in matches}),
        'candidate': {'scale': [2, 2], 'offset': [7358, 7412], 'axis': 'x,z'},
        'candidate_error': error_summary([m['candidate_error'] for m in matches]),
        'swapped_axis_error': error_summary([m['swapped_error'] for m in matches]),
        'least_squares_fit': fit,
        'swapped_least_squares_fit': swapped_fit,
        'ward_cast_count': len(ward_matches),
        'ward_cast_start_error': error_summary([m['candidate_error'] for m in ward_matches]),
        'ward_cast_target_end_error': error_summary([
            m['ward_target_end_error'] for m in ward_matches
            if m['ward_target_end_error'] is not None
        ]),
        'acceptance_rule': '>=100 matches, candidate p95<=500, direct p50 < 25% swapped p50',
        'transform_verified': accepted,
        'matches': matches,
    }


def interpolate_position(event, timestamp_ms):
    waypoints = event['candidate_waypoints_xz']
    if not waypoints:
        return None
    remaining = max(0.0, (timestamp_ms - event['timestamp_ms']) / 1000.0)
    if len(waypoints) == 1 or event['speed'] <= 0:
        return waypoints[0]
    for first, second in zip(waypoints, waypoints[1:]):
        distance = math.hypot(second[0] - first[0], second[1] - first[1])
        duration = distance / event['speed'] if event['speed'] else 0
        if remaining <= duration:
            ratio = remaining / duration if duration else 0
            return [first[0] + (second[0] - first[0]) * ratio,
                    first[1] + (second[1] - first[1]) * ratio]
        remaining -= duration
    return waypoints[-1]


def path_duration_seconds(event):
    if event['speed'] <= 0:
        return 0.0
    return sum(
        math.hypot(second[0] - first[0], second[1] - first[1]) / event['speed']
        for first, second in zip(
            event['candidate_waypoints_xz'], event['candidate_waypoints_xz'][1:]
        )
    )


def write_hero_positions(path, hero_events, transform_verified):
    output = os.path.abspath(path)
    os.makedirs(os.path.dirname(output), exist_ok=True)
    counters = Counter()
    replay_counts = Counter()
    source_ages = []
    x_values = []
    z_values = []
    with open(output, 'w', encoding='utf-8', newline='\n') as stream:
        if transform_verified:
            for (replay_sha, entity_id), events in sorted(hero_events.items()):
                start = ((events[0]['timestamp_ms'] + 999) // 1000) * 1000
                end = events[-1]['timestamp_ms']
                times = [event['timestamp_ms'] for event in events]
                for timestamp_ms in range(start, end + 1, 1000):
                    index = bisect.bisect_right(times, timestamp_ms) - 1
                    if index < 0:
                        continue
                    event = events[index]
                    position = interpolate_position(event, timestamp_ms)
                    source_age = timestamp_ms - event['timestamp_ms']
                    moving = (
                        len(event['candidate_waypoints_xz']) > 1
                        and source_age / 1000.0 < path_duration_seconds(event)
                    )
                    row = {
                        'schema_version': 1,
                        'event_type': 'hero_position_1s',
                        'replay_sha256': replay_sha,
                        'timestamp_ms': timestamp_ms,
                        'entity_id': entity_id,
                        'position_xz': position,
                        'source_path_timestamp_ms': event['timestamp_ms'],
                        'source_raw_packet_occurrence_index': event[
                            'raw_packet_occurrence_index'
                        ],
                        'source_record_index': event['record_index'],
                        'raw_packet_ref': event['raw_packet_ref'],
                        'coordinate_transform_status': 'VERIFIED_CURRENT_CALIBRATION',
                    }
                    stream.write(json.dumps(row, separators=(',', ':')) + '\n')
                    counters['position_count'] += 1
                    counters['moving_interpolation_count'] += int(moving)
                    counters['terminal_or_stationary_count'] += int(not moving)
                    replay_counts[replay_sha] += 1
                    source_ages.append(source_age)
                    x_values.append(position[0])
                    z_values.append(position[1])
    return {
        'output': output,
        **dict(counters),
        'replay_count': len(replay_counts),
        'entity_series_count': len(hero_events) if transform_verified else 0,
        'per_replay_position_counts': dict(replay_counts),
        'source_age_ms': {
            'p50': percentile(source_ages, 0.50),
            'p90': percentile(source_ages, 0.90),
            'p95': percentile(source_ages, 0.95),
            'p99': percentile(source_ages, 0.99),
            'max': max(source_ages) if source_ages else None,
        },
        'coordinate_range_xz': (
            [[min(x_values), max(x_values)], [min(z_values), max(z_values)]]
            if x_values else None
        ),
    }


def finalize_hero_paths(path, hero_events, transform_verified):
    status = (
        'VERIFIED_CURRENT_CALIBRATION'
        if transform_verified else 'CANDIDATE_TRANSFORM_UNVERIFIED'
    )
    count = 0
    with open(path, 'w', encoding='utf-8', newline='\n') as stream:
        for events in hero_events.values():
            for event in events:
                event['coordinate_transform_status'] = status
                event['event_type'] = (
                    'hero_path' if transform_verified else 'hero_path_candidate'
                )
                stream.write(json.dumps(event, separators=(',', ':')) + '\n')
                count += 1
    return {'output': os.path.abspath(path), 'event_count': count, 'status': status}


def build_compact_artifacts(options, analysis, calibration, practical):
    directory = os.path.dirname(os.path.abspath(options.calibration_output))
    summary_path = os.path.join(directory, 'current_path_summary.json')
    profile_path = os.path.join(directory, 'path_packet_profile_16_15.json')
    raw_manifest = f'{os.path.abspath(options.raw_packets)}.manifest.json'
    raw_manifest_value = json.load(open(raw_manifest, encoding='utf-8'))
    cast_event_evidence = [
        file_evidence(path) for path in calibration['cast_event_files']
    ]
    calibration_compact = {
        key: value for key, value in calibration.items()
        if key not in ('matches', 'cast_event_files', 'decoded_packets', 'hero_paths',
                       'hero_positions_1s')
    }
    artifacts = {
        'runtime_image': file_evidence(options.image),
        'raw_packet_manifest': file_evidence(raw_manifest),
        'decoded_packets': file_evidence(options.decoded_packets_output),
        'hero_paths': file_evidence(options.hero_path_output),
        'hero_positions_1s': file_evidence(options.hero_positions_output),
        'full_calibration': file_evidence(options.calibration_output),
        'migration_script': file_evidence(__file__),
        'cast_event_files': cast_event_evidence,
    }
    validation_checks = {
        'static_profile_checks_pass': analysis['all_checks_pass'],
        'ten_replays_exported': raw_manifest_value['replay_count'] == 10,
        'raw_packet_count_matches_decode': (
            raw_manifest_value['selected_packet_count']
            == practical['decoded_packets']['counters']['packet_count']
        ),
        'all_raw_packets_produced_records': (
            practical['decoded_packets']['counters']['record_count'] > 0
        ),
        'coordinate_transform_verified': calibration['transform_verified'],
        'direct_axis_beats_swapped': (
            calibration['candidate_error']['p50']
            < calibration['swapped_axis_error']['p50'] * 0.25
        ),
        'least_squares_matches_exact_scale': (
            abs(calibration['least_squares_fit']['x'][0] - 2) < 0.01
            and abs(calibration['least_squares_fit']['z'][0] - 2) < 0.01
        ),
        'hero_paths_emitted': practical['hero_paths']['event_count'] > 0,
        'hero_positions_emitted': practical['hero_positions_1s']['position_count'] > 0,
    }
    validation = {
        'status': (
            'CURRENT_PATH_POSITION_VERIFIED'
            if all(validation_checks.values()) else 'CURRENT_PATH_VALIDATION_FAILED'
        ),
        'checks': validation_checks,
        'all_checks_pass': all(validation_checks.values()),
    }
    summary = {
        'schema_version': 1,
        'target_replay_version': '16.15.801.3452',
        'validation': validation,
        'packet_profile': {
            'packet_id': PATH_OPCODE,
            'packet_id_hex': f'0x{PATH_OPCODE:04x}',
            'constructor_rva': f'0x{PATH_CONSTRUCTOR_RVA:08x}',
            'deserialize_rva': f'0x{DESERIALIZE_RVA:08x}',
            'object_size': OBJECT_SIZE,
            'payload_pointer_offset': '0x18',
            'payload_size_u32_offset': '0x20',
        },
        'full_decode': practical['decoded_packets']['counters'],
        'replay_count': raw_manifest_value['replay_count'],
        'calibration': calibration_compact,
        'hero_paths': practical['hero_paths'],
        'hero_positions_1s': practical['hero_positions_1s'],
        'artifacts': artifacts,
        'lightweight_package_include': [
            os.path.abspath(summary_path), os.path.abspath(profile_path),
            os.path.abspath(options.analysis_output),
        ],
        'lightweight_package_exclude': [
            os.path.abspath(options.raw_packets),
            os.path.abspath(options.decoded_packets_output),
            os.path.abspath(options.hero_path_output),
            os.path.abspath(options.hero_positions_output),
            os.path.abspath(options.calibration_output),
        ],
    }
    profile = {
        'schema_version': 1,
        'target_replay_version': '16.15.801.3452',
        'validation_status': validation['status'],
        'runtime_image': artifacts['runtime_image'],
        'packet': {
            'replay_packet_id': PATH_OPCODE,
            'replay_packet_id_hex': f'0x{PATH_OPCODE:04x}',
            'vtable_rva': f'0x{VTABLE_RVA:08x}',
            'constructor_rva': f'0x{PATH_CONSTRUCTOR_RVA:08x}',
            'deserialize_range': [
                f'0x{DESERIALIZE_RVA:08x}', f'0x{DESERIALIZE_END_RVA:08x}'
            ],
            'copy_factory_rva': f'0x{COPY_FACTORY_RVA:08x}',
            'object_size': OBJECT_SIZE,
            'plaintext_payload_pointer_offset': '0x18',
            'plaintext_payload_size_u32_offset': '0x20',
        },
        'plaintext_record_grammar': {
            'prefix': ['u16 parsing_type', 'u32 entity_id', 'f32 speed'],
            'optional_byte': 'present when parsing_type bit 0 is set',
            'waypoint_count': '(parsing_type & 0xff) >> 1',
            'waypoints': 'bitmap-selected u8 deltas or little-endian u16 absolutes',
            'packet_payload_may_concatenate_records': True,
        },
        'coordinate_transform': {
            'status': 'VERIFIED_CURRENT_CALIBRATION',
            'axis': 'encoded x/y -> game x/z',
            'x': 'sign_extend(encoded_x, 16) * 2 + 7358',
            'z': 'sign_extend(encoded_y, 16) * 2 + 7412',
            'least_squares_fit': calibration['least_squares_fit'],
            'match_count': calibration['match_count'],
            'replay_count': calibration['replay_count'],
            'candidate_error': calibration['candidate_error'],
            'swapped_axis_error': calibration['swapped_axis_error'],
            'ward_cast_start_error': calibration['ward_cast_start_error'],
            'ward_cast_target_end_error': calibration['ward_cast_target_end_error'],
        },
        'coverage': {
            'raw_packet_count': practical['decoded_packets']['counters']['packet_count'],
            'decoded_record_count': practical['decoded_packets']['counters']['record_count'],
            'hero_path_event_count': practical['hero_paths']['event_count'],
            'hero_position_1s_count': practical['hero_positions_1s']['position_count'],
        },
        'provenance': {
            'raw_packet_manifest': artifacts['raw_packet_manifest'],
            'migration_script': artifacts['migration_script'],
            'cast_event_files': cast_event_evidence,
            'independent_anchor': (
                'CastSpell target_position x/z for same replay, caster entity, and '
                'nearest Path record within 250 ms.'
            ),
        },
        'validation': validation,
    }
    write_json(summary_path, summary)
    write_json(profile_path, profile)
    return {
        'summary': file_evidence(summary_path),
        'profile': file_evidence(profile_path),
        'validation': validation,
    }


def main():
    options = parse_args()
    with open(options.image, 'rb') as stream:
        image = stream.read()
    with open(options.shapes, encoding='utf-8-sig') as stream:
        shape_bundle = json.load(stream)
    analysis = static_analysis(image)
    if not analysis['all_checks_pass']:
        raise RuntimeError('static candidate verification failed')
    analysis['image_path'] = os.path.abspath(options.image)
    emulation = emulate(
        image,
        shape_bundle,
        max_shapes=options.max_shapes,
        packet_id=options.packet_id,
        progress_every=options.progress_every,
    )
    emulation['image_path'] = os.path.abspath(options.image)
    emulation['shapes_path'] = os.path.abspath(options.shapes)
    emulation['path_packet_verification'] = summarize_path_packet(emulation)
    analysis['dynamic_verification'] = {
        'source_artifact': os.path.abspath(options.emulation_output),
        'all_shapes_executed': (
            options.max_shapes is None and options.packet_id is None
        ),
        'input_shape_count': emulation['input_shape_count'],
        'input_sample_count': emulation['input_sample_count'],
        'infrastructure_failure_count': emulation['counters'].get(
            'infrastructure_failure_count', 0
        ),
        'path_packet': emulation['path_packet_verification'],
    }
    analysis_path = write_json(options.analysis_output, analysis)
    emulation_path = write_json(options.emulation_output, emulation)
    practical = None
    if options.raw_packets:
        required = {
            '--cast-events-root': options.cast_events_root,
            '--decoded-packets-output': options.decoded_packets_output,
            '--hero-path-output': options.hero_path_output,
            '--hero-positions-output': options.hero_positions_output,
            '--calibration-output': options.calibration_output,
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise ValueError(f"raw packet mode requires {', '.join(missing)}")
        cast_paths, cast_events, hero_ids = load_cast_events(options.cast_events_root)
        raw_summary, hero_events = decode_raw_packets(
            image,
            options.raw_packets,
            options.decoded_packets_output,
            options.hero_path_output,
            hero_ids,
            options.progress_every,
        )
        calibration = calibrate_transform(cast_events, hero_events)
        hero_path_summary = finalize_hero_paths(
            options.hero_path_output,
            hero_events,
            calibration['transform_verified'],
        )
        positions = write_hero_positions(
            options.hero_positions_output,
            hero_events,
            calibration['transform_verified'],
        )
        calibration.update({
            'cast_event_files': [os.path.abspath(path) for path in cast_paths],
            'cast_event_count': len(cast_events),
            'raw_packet_input': os.path.abspath(options.raw_packets),
            'decoded_packets': raw_summary,
            'hero_paths': hero_path_summary,
            'hero_positions_1s': positions,
            'coordinate_semantics': (
                'Path coordinates are game-plane x/z. CastSpell target_position '
                'components [0]/[2] are used as independent caster position anchors.'
            ),
        })
        calibration_path = write_json(options.calibration_output, calibration)
        practical = {
            'calibration_output': calibration_path,
            'transform_verified': calibration['transform_verified'],
            'match_count': calibration['match_count'],
            'candidate_error': calibration['candidate_error'],
            'swapped_axis_error': calibration['swapped_axis_error'],
            'ward_cast_start_error': calibration['ward_cast_start_error'],
            'ward_cast_target_end_error': calibration['ward_cast_target_end_error'],
            'decoded_packets': raw_summary,
            'hero_paths': hero_path_summary,
            'hero_positions_1s': positions,
        }
        practical['compact_artifacts'] = build_compact_artifacts(
            options, analysis, calibration, practical
        )
        if not practical['compact_artifacts']['validation']['all_checks_pass']:
            raise RuntimeError('focused current Path artifact validation failed')
        analysis['practical_path_layer'] = practical
        write_json(options.analysis_output, analysis)
    print(json.dumps({
        'analysis_output': analysis_path,
        'emulation_output': emulation_path,
        'all_static_checks_pass': analysis['all_checks_pass'],
        'shape_count': emulation['input_shape_count'],
        'sample_count': emulation['input_sample_count'],
        'counters': emulation['counters'],
        'path_packet_verification': emulation['path_packet_verification'],
        'accepted_packet_summary': emulation['accepted_packet_summary'],
        'practical_path_layer': practical,
    }, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'{type(error).__name__}: {error}', file=sys.stderr)
        sys.exit(1)

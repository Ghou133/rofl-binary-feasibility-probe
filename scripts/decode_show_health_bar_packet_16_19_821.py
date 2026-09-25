#!/usr/bin/env python3
"""Bounded exact-image native witness for KR 821 ShowHealthBar packets.

Batch mode checks every selected original packet. Probe mode is for explicit
negative controls and reports native acceptance even for unobserved bytes.
"""

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

from decode_mapview_inventory_16_19_821 import make_emulator


BUILD = '16.19.821.7343'
IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325'
IMAGE_BASE = 0x7ff67f410000
IMAGE_SIZE = 48_488_448
PACKET_ID = 0x0165
FACTORY_TABLE_RVA = 0xf0e4bc
FACTORY_CASE_RVA = 0xf0292f
CONSTRUCTOR_RVA = 0xec12b0
VTABLE_RVA = 0x1baa830
DESERIALIZER_RVA = 0x10eaa10
CALLBACK_RVA = 0x2c2c20
CALLBACK_TABLE_RVA = 0x1ab62d0
CALLBACK_TABLE_SHA256 = '328528d693ab5d96a815b6706694025a980e609019304aeb2e5e32797011c04b'
MAX_REQUEST_BYTES = 16 * 1024 * 1024
MAX_BATCH_PACKETS = 100_000
MAX_PROBE_PACKETS = 32
PROFILE = {
    'constructor_rva': CONSTRUCTOR_RVA,
    'deserialize_rva': DESERIALIZER_RVA,
    'object_size': 0x14,
    'fields': [],
}


def rel32_target(image, rva):
    return rva + 5 + struct.unpack_from('<i', image, rva + 1)[0]


def lea_target(image, rva):
    return rva + 7 + struct.unpack_from('<i', image, rva + 3)[0]


def read_image(image_path):
    if not image_path.is_file() or image_path.stat().st_size != IMAGE_SIZE:
        raise ValueError('exact 821 mapped image is missing or has the wrong length')
    image = image_path.read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    if digest != IMAGE_SHA256:
        raise ValueError(f'exact 821 mapped image SHA-256 mismatch: {digest}')
    factory_case = struct.unpack_from('<I', image,
                                      FACTORY_TABLE_RVA + PACKET_ID * 4)[0]
    if factory_case != FACTORY_CASE_RVA or image[factory_case:factory_case + 5] != bytes.fromhex('b914000000'):
        raise ValueError('exact 821 ShowHealthBar factory case differs')
    if image[0xf02943] != 0xe8 or rel32_target(image, 0xf02943) != CONSTRUCTOR_RVA:
        raise ValueError('exact 821 ShowHealthBar factory constructor call differs')
    if image[CONSTRUCTOR_RVA + 7:CONSTRUCTOR_RVA + 13] != bytes.fromhex('66c741086501'):
        raise ValueError('exact 821 ShowHealthBar constructor route write differs')
    if image[0xec12d1:0xec12d4] != bytes.fromhex('488d05') or lea_target(image, 0xec12d1) != VTABLE_RVA:
        raise ValueError('exact 821 ShowHealthBar constructor vtable differs')
    if struct.unpack_from('<Q', image, VTABLE_RVA + 8)[0] - IMAGE_BASE != DESERIALIZER_RVA:
        raise ValueError('exact 821 ShowHealthBar deserializer differs')
    if image[0x2612d9:0x2612df] != bytes.fromhex('41b865010000'):
        raise ValueError('exact 821 ShowHealthBar registration differs')
    if image[0x261299:0x26129c] != bytes.fromhex('488d05') or lea_target(image, 0x261299) != CALLBACK_RVA:
        raise ValueError('exact 821 ShowHealthBar callback registration differs')
    table = image[CALLBACK_TABLE_RVA:CALLBACK_TABLE_RVA + 256]
    if hashlib.sha256(table).hexdigest() != CALLBACK_TABLE_SHA256:
        raise ValueError('exact 821 ShowHealthBar callback table differs')
    return image, digest, table


def read_request(probe):
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError('ShowHealthBar native request exceeds 16 MiB')
    request = json.loads(raw)
    if (not isinstance(request, dict) or request.get('replay_version') != BUILD
            or request.get('packet_id') != PACKET_ID):
        raise ValueError('ShowHealthBar native request requires exact build and route')
    packets = request.get('packets')
    maximum = MAX_PROBE_PACKETS if probe else MAX_BATCH_PACKETS
    if not isinstance(packets, list) or not 0 < len(packets) <= maximum:
        raise ValueError(f'ShowHealthBar native packets must have 1..{maximum} rows')
    return packets


def validate_tuple(entry, probe):
    if not isinstance(entry, list) or len(entry) != 2:
        raise ValueError('packet must be [raw_param, payload_hex]')
    raw_param, payload_hex = entry
    if type(raw_param) is not int or not 0 < raw_param <= 0xffffffff:
        raise ValueError('raw_param must be a nonzero u32')
    if not isinstance(payload_hex, str) or len(payload_hex) % 2:
        raise ValueError('payload_hex must be even-length hexadecimal text')
    try:
        payload = bytes.fromhex(payload_hex)
    except ValueError as error:
        raise ValueError('payload_hex is invalid hexadecimal text') from error
    if probe:
        if len(payload) > 2:
            raise ValueError('native probe accepts at most two payload bytes')
    elif payload not in (b'J', b'K'):
        raise ValueError('native batch accepts only observed 4a/4b payloads')
    return raw_param, payload


def callback_value(encoded, table):
    value = table[(encoded + 0x41) & 0xff]
    value = (~value) & 0xff
    value = ((value >> 7) | (value << 1)) & 0xff
    value = (~value) & 0xff
    return value, int(value == 0)


def native_decode(emulator, context, raw_param, payload, table):
    context['raw_param'] = raw_param
    native = emulator.decode(payload, PROFILE)
    object_bytes = bytes.fromhex(native['object_hex'])
    callback_byte, callback_flag = callback_value(object_bytes[0x10], table)
    return {
        'deserialize_return_al': native['deserialize_return_al'],
        'bytes_consumed': native['bytes_consumed'],
        'fully_consumed': native['fully_consumed'],
        'object_opcode': struct.unpack_from('<H', object_bytes, 8)[0],
        'object_raw_param': struct.unpack_from('<I', object_bytes, 0x0c)[0],
        'object_byte_0x10': object_bytes[0x10],
        'callback_byte': callback_byte,
        'callback_zero_flag': callback_flag,
    }


def run_batch(packets, image, digest, table):
    emulator, context = make_emulator(image)
    input_digest = hashlib.sha256()
    accepted_count = 0
    flag_one_count = 0
    first_failure = None
    for index, packet in enumerate(packets):
        raw_param, payload = validate_tuple(packet, False)
        input_digest.update(struct.pack('<II', raw_param, len(payload)))
        input_digest.update(payload)
        if first_failure is not None:
            continue
        try:
            native = native_decode(emulator, context, raw_param, payload, table)
            expected_object = 0xa5 if payload == b'J' else 0xfd
            expected_byte = 1 if payload == b'J' else 0
            expected_flag = int(payload == b'K')
            accepted = (native['deserialize_return_al'] == 1
                        and native['bytes_consumed'] == 1
                        and native['fully_consumed']
                        and native['object_opcode'] == PACKET_ID
                        and native['object_raw_param'] == raw_param
                        and native['object_byte_0x10'] == expected_object
                        and native['callback_byte'] == expected_byte
                        and native['callback_zero_flag'] == expected_flag)
            if not accepted:
                first_failure = {
                    'index': index,
                    'reason': 'native deserializer, object binding, or callback differs',
                    **native,
                }
                continue
            accepted_count += 1
            flag_one_count += expected_flag
        except Exception as error:
            first_failure = {'index': index, 'reason': str(error)}
    print(json.dumps({
        'replay_version': BUILD,
        'runtime_image_sha256': digest,
        'packet_id': PACKET_ID,
        'packet_count': len(packets),
        'input_sha256': input_digest.hexdigest(),
        'native_full_success_count': accepted_count,
        'callback_flag_one_count': flag_one_count,
        'first_failure': first_failure,
    }))


def run_probe(packets, image, digest, table):
    emulator, context = make_emulator(image)
    rows = []
    for index, packet in enumerate(packets):
        raw_param, payload = validate_tuple(packet, True)
        try:
            native = native_decode(emulator, context, raw_param, payload, table)
            rows.append({
                'index': index,
                'raw_payload_hex': payload.hex(),
                'observed_shape': payload in (b'J', b'K'),
                **native,
            })
        except Exception as error:
            rows.append({'index': index, 'raw_payload_hex': payload.hex(),
                         'observed_shape': payload in (b'J', b'K'),
                         'error': str(error)})
            emulator, context = make_emulator(image)
    print(json.dumps({
        'replay_version': BUILD,
        'runtime_image_sha256': digest,
        'packet_id': PACKET_ID,
        'rows': rows,
    }))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True, type=Path)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--batch', action='store_true')
    mode.add_argument('--probe', action='store_true')
    options = parser.parse_args()
    packets = read_request(options.probe)
    image, digest, table = read_image(options.image)
    if options.probe:
        run_probe(packets, image, digest, table)
    else:
        run_batch(packets, image, digest, table)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'821 ShowHealthBar exact-runtime witness error: {error}', file=sys.stderr)
        raise SystemExit(1)

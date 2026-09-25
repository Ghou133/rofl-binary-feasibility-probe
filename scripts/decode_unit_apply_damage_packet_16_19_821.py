#!/usr/bin/env python3
"""Bounded native witness for exact 821 UnitApplyDamage packet payloads.

The --batch mode validates every selected packet in one replay with one exact
image and one emulator. The ordinary mode retains verbose research samples.
"""

import argparse
import hashlib
import json
import math
import struct
import sys
from pathlib import Path

from decode_mapview_inventory_16_19_821 import make_emulator


BUILD = '16.19.821.7343'
IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325'
IMAGE_BASE = 0x7ff67f410000
IMAGE_SIZE = 48_488_448
MAX_REQUEST_BYTES = 1_000_000
MAX_PACKETS = 1_024
MAX_BATCH_REQUEST_BYTES = 16 * 1024 * 1024
MAX_BATCH_PACKETS = 100_000
PACKET_ID = 0x005f
FACTORY_TABLE_RVA = 0xf0e4bc
FACTORY_CASE_RVA = 0xeff3bf
CONSTRUCTOR_RVA = 0xecec40
VTABLE_RVA = 0x1ba21c8
DESERIALIZER_RVA = 0xf49dd0
CALLBACK_FLOAT_HELPER_RVA = 0x251c60
PROFILE = {
    'constructor_rva': CONSTRUCTOR_RVA,
    'deserialize_rva': DESERIALIZER_RVA,
    'object_size': 0x30,
    'fields': [{
        'name': 'callback_f32_0x20',
        'offset': 0x20,
        'type': 'f32',
        'byte_helper_rva': CALLBACK_FLOAT_HELPER_RVA,
    }],
}


def read_request():
    request_bytes = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(request_bytes) > MAX_REQUEST_BYTES:
        raise ValueError('native witness request exceeds bounded size')
    request = json.loads(request_bytes)
    if not isinstance(request, dict) or request.get('replay_version') != BUILD:
        raise ValueError(f'replay_version must be exactly {BUILD}')
    packets = request.get('packets')
    if not isinstance(packets, list) or len(packets) > MAX_PACKETS:
        raise ValueError(f'packets must be an array of at most {MAX_PACKETS} entries')
    return packets


def read_batch_request():
    request_bytes = sys.stdin.buffer.read(MAX_BATCH_REQUEST_BYTES + 1)
    if len(request_bytes) > MAX_BATCH_REQUEST_BYTES:
        raise ValueError('native batch request exceeds bounded size')
    request = json.loads(request_bytes)
    if (not isinstance(request, dict) or request.get('replay_version') != BUILD
            or request.get('packet_id') != PACKET_ID):
        raise ValueError('native batch requires the exact build and route')
    packets = request.get('packets')
    if not isinstance(packets, list) or not 0 < len(packets) <= MAX_BATCH_PACKETS:
        raise ValueError(f'packets must be an array of 1..{MAX_BATCH_PACKETS} entries')
    return packets


def read_image(image_path):
    if not image_path.is_file() or image_path.stat().st_size != IMAGE_SIZE:
        raise ValueError('exact 821 mapped image is missing or has the wrong length')
    image = image_path.read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    if digest != IMAGE_SHA256:
        raise ValueError(f'exact 821 mapped image SHA-256 mismatch: {digest}')
    case = struct.unpack_from('<I', image, FACTORY_TABLE_RVA + PACKET_ID * 4)[0]
    if case != FACTORY_CASE_RVA or image[case:case + 5] != bytes.fromhex('b930000000'):
        raise ValueError('exact 821 factory case differs')
    if image[CONSTRUCTOR_RVA + 0x0c:CONSTRUCTOR_RVA + 0x12] != bytes.fromhex('66c741085f00'):
        raise ValueError('exact 821 constructor opcode write differs')
    if struct.unpack_from('<Q', image, VTABLE_RVA + 8)[0] - IMAGE_BASE != DESERIALIZER_RVA:
        raise ValueError('exact 821 UnitApplyDamage deserializer differs')
    if image[0x26efbc:0x26efc2] != bytes.fromhex('41b85f000000'):
        raise ValueError('exact 821 UnitApplyDamage registration differs')
    return image, digest


def validate_packet(packet):
    if not isinstance(packet, dict) or packet.get('packet_id') != PACKET_ID:
        raise ValueError('packet_id must be exact 821 route 0x005f')
    if packet.get('stream_tag') != 1:
        raise ValueError('UnitApplyDamage witness requires game stream')
    raw_param = packet.get('raw_param')
    if type(raw_param) is not int or not 0 < raw_param <= 0xffffffff:
        raise ValueError('raw_param must be a nonzero u32')
    payload_hex = packet.get('payload_hex')
    if not isinstance(payload_hex, str) or len(payload_hex) % 2:
        raise ValueError('payload_hex must be even-length hexadecimal text')
    try:
        payload = bytes.fromhex(payload_hex)
    except ValueError as error:
        raise ValueError('payload_hex is invalid hexadecimal text') from error
    if not 7 <= len(payload) <= 26:
        raise ValueError('payload is outside bounded native witness size')
    return raw_param, payload


def validate_batch_tuple(packet):
    if not isinstance(packet, list) or len(packet) != 3:
        raise ValueError('native batch packet must be [raw_param, payload_hex, has_float]')
    raw_param, payload_hex, has_float = packet
    if type(raw_param) is not int or not 0 < raw_param <= 0xffffffff:
        raise ValueError('native batch raw_param must be a nonzero u32')
    if not isinstance(payload_hex, str) or not 16 <= len(payload_hex) <= 50:
        raise ValueError('native batch payload hex length is outside observed scope')
    if len(payload_hex) % 2:
        raise ValueError('native batch payload hex length must be even')
    try:
        payload = bytes.fromhex(payload_hex)
    except ValueError as error:
        raise ValueError('native batch payload is invalid hexadecimal') from error
    expected_float = (len(payload) == 15 and payload[3] & 7 == 6
                      and payload[0] & 7 == 1 and (payload[0] >> 3) & 7 == 6)
    if type(has_float) is not bool or has_float != expected_float:
        raise ValueError('native batch float-family flag differs from payload')
    return raw_param, payload, has_float


def run_batch(packets, image, digest):
    emulator, context = make_emulator(image)
    input_digest = hashlib.sha256()
    float_rows = []
    accepted_count = 0
    first_failure = None
    for index, packet in enumerate(packets):
        raw_param, payload, has_float = validate_batch_tuple(packet)
        input_digest.update(struct.pack('<II', raw_param, len(payload)))
        input_digest.update(payload)
        if first_failure is not None:
            continue
        context['raw_param'] = raw_param
        try:
            native = emulator.decode(payload, PROFILE)
            object_bytes = bytes.fromhex(native['object_hex'])
            opcode = struct.unpack_from('<H', object_bytes, 8)[0]
            object_param = struct.unpack_from('<I', object_bytes, 0x0c)[0]
            accepted = (native['deserialize_return_al'] == 1
                        and native['fully_consumed']
                        and opcode == PACKET_ID
                        and object_param == raw_param)
            if not accepted:
                first_failure = {
                    'index': index, 'reason': 'native deserializer did not fully accept packet',
                    'deserialize_return_al': native['deserialize_return_al'],
                    'bytes_consumed': native['bytes_consumed'],
                    'fully_consumed': native['fully_consumed'],
                    'object_opcode': opcode, 'object_raw_param': object_param,
                }
                continue
            if has_float:
                value = native['decoded_fields']['callback_f32_0x20']
                if value is None or not math.isfinite(value):
                    first_failure = {'index': index,
                                     'reason': 'native callback float is unavailable or nonfinite'}
                    continue
                float_rows.append([index, value])
            accepted_count += 1
        except Exception as error:
            first_failure = {'index': index, 'reason': str(error)}
    print(json.dumps({
        'replay_version': BUILD,
        'runtime_image_sha256': digest,
        'packet_id': PACKET_ID,
        'packet_count': len(packets),
        'input_sha256': input_digest.hexdigest(),
        'native_full_success_count': accepted_count,
        'first_failure': first_failure,
        'float_rows': float_rows,
    }, allow_nan=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--batch', action='store_true',
                        help='validate up to 100000 packets in one replay')
    options = parser.parse_args()
    packets = read_batch_request() if options.batch else read_request()
    image, digest = read_image(options.image)
    if options.batch:
        run_batch(packets, image, digest)
        return
    emulator, context = make_emulator(image)
    rows = []
    for index, packet in enumerate(packets):
        raw_param, payload = validate_packet(packet)
        context['raw_param'] = raw_param
        try:
            native = emulator.decode(payload, PROFILE)
            object_bytes = bytes.fromhex(native['object_hex'])
            opcode = struct.unpack_from('<H', object_bytes, 8)[0]
            object_param = struct.unpack_from('<I', object_bytes, 0x0c)[0]
            accepted = (native['deserialize_return_al'] == 1
                        and native['fully_consumed']
                        and opcode == PACKET_ID
                        and object_param == raw_param)
            value = native['decoded_fields']['callback_f32_0x20'] if accepted else None
            if value is not None and not math.isfinite(value):
                accepted = False
                value = None
            rows.append({
                'index': index,
                'status': 'DECODED' if accepted else 'FAILED',
                'deserialize_return_al': native['deserialize_return_al'],
                'bytes_consumed': native['bytes_consumed'],
                'fully_consumed': native['fully_consumed'],
                'object_opcode': opcode,
                'object_raw_param': object_param,
                'object_field_0x20_encoded_bytes_hex': object_bytes[0x20:0x24].hex(),
                'callback_f32_0x20_candidate': value,
            })
        except Exception as error:
            rows.append({'index': index, 'status': 'FAILED', 'error': str(error)})
    print(json.dumps({
        'replay_version': BUILD,
        'runtime_image_sha256': digest,
        'packet_id': PACKET_ID,
        'packet_count': len(rows),
        'native_full_success_count': sum(row['status'] == 'DECODED' for row in rows),
        'rows': rows,
    }, allow_nan=False))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps({'status': 'FAILED', 'error': str(exc)}), file=sys.stderr)
        sys.exit(1)

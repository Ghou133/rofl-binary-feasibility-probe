#!/usr/bin/env python3
"""Decode exact 821 direct-input movement turn packet fields without position claims.

The JavaScript caller owns Replay framing and provenance. This helper executes
the pinned client constructor and deserializer, then applies the byte transform
visible in its registered AIBaseClient callback to the three stored f32 fields.
"""

import argparse
import hashlib
import json
import math
import string
import struct
import sys
from pathlib import Path

from decode_mapview_inventory_16_19_821 import make_emulator, read_image


BUILD = '16.19.821.7343'
IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325'
IMAGE_BASE = 0x7ff67f410000
CALLBACK_TRANSFORM_SHA256 = 'ca8d6ef04b90a4c767e9801b47ea4ee8d38e70b59c2dd80ec0bceb7b3563517e'
PACKET_ID = 0x00ba
VTABLE_RVA = 0x01ab68f0
PROFILE = {'constructor_rva': 0x00e9a9f0, 'deserialize_rva': 0x00f1b190,
           'object_size': 0x1c, 'fields': []}
MAX_INPUT_BYTES = 4_000_000
MAX_PACKETS = 8192


def failure(message, *, return_al=None, consumed=None):
    return {'status': 'FAILED', 'deserialize_return_al': return_al,
            'bytes_consumed': consumed, 'error': message}


def read_request():
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError('direct-input movement turn request exceeds bounded input size')
    request = json.loads(raw)
    if not isinstance(request, dict) or request.get('replay_version') != BUILD:
        raise ValueError(f'replay_version must be exactly {BUILD}')
    packets = request.get('packets')
    if not isinstance(packets, list) or len(packets) > MAX_PACKETS:
        raise ValueError(f'packets must be an array with at most {MAX_PACKETS} entries')
    return packets


def validate_packet(packet):
    if not isinstance(packet, dict) or packet.get('packet_id') != PACKET_ID:
        raise ValueError('packet ID must be exact 821 direct-input movement turn route')
    if packet.get('stream_tag') not in (1, 2):
        raise ValueError('direct-input movement turn requires game or keyframe stream')
    raw_param = packet.get('raw_param')
    if type(raw_param) is not int or not 0 < raw_param <= 0xffffffff:
        raise ValueError('raw_param must be a nonzero unsigned 32-bit integer')
    payload_hex = packet.get('payload_hex')
    if not isinstance(payload_hex, str) or len(payload_hex) != 26:
        raise ValueError('payload must be exactly 13 hexadecimal bytes')
    if any(character not in string.hexdigits for character in payload_hex):
        raise ValueError('payload_hex contains non-hexadecimal characters')
    payload = bytes.fromhex(payload_hex)
    if payload[0] != 0x85:
        raise ValueError('selector differs from observed 821 direct-input movement turn route')
    return raw_param, payload


def ror8(value, amount):
    return ((value >> amount) | (value << (8 - amount))) & 0xff


def callback_transform(byte):
    # Callback RVA 0x002bbfb0..0x002bbfcd, pinned by the full image SHA.
    rotated = ror8(byte, 1)
    shuffled = (((rotated & 0xd5) << 1) | ((rotated >> 1) & 0x55)) & 0xff
    return ror8((ror8(shuffled, 6) + 0x25) & 0xff, 3)


def inverse_callback_transform(byte):
    # Callback RVA 0x002bbff0..0x002bc00d restores its packet object bytes.
    rotated = ror8((ror8(byte, 5) - 0x25) & 0xff, 2)
    shuffled = (((rotated & 0xd5) << 1) | ((rotated >> 1) & 0x55)) & 0xff
    return ror8(shuffled, 7)


def callback_table():
    table = bytes(callback_transform(value) for value in range(256))
    if (len(set(table)) != 256
            or hashlib.sha256(table).hexdigest() != CALLBACK_TRANSFORM_SHA256
            or any(inverse_callback_transform(table[value]) != value
                   for value in range(256))):
        raise ValueError('exact 821 direct-input callback transform differs')
    return table


def decode_packet(emulator, context, table, raw_param, payload):
    # make_emulator hooks the shared base-parameter decoder and supplies this
    # Replay framing value. Object +0x0c checks stub consistency, not a second
    # independent native decoding of the parameter.
    context['raw_param'] = raw_param
    native = emulator.decode(payload, PROFILE)
    return_al = native['deserialize_return_al']
    consumed = native['bytes_consumed']
    if return_al != 1 or not native['fully_consumed'] or consumed != len(payload):
        return failure('native direct-input movement turn did not fully consume payload',
                       return_al=return_al, consumed=consumed)
    obj = bytes.fromhex(native['object_hex'])
    if len(obj) != PROFILE['object_size']:
        return failure('native direct-input movement turn object size differs',
                       return_al=return_al, consumed=consumed)
    if struct.unpack_from('<Q', obj, 0)[0] != IMAGE_BASE + VTABLE_RVA:
        return failure('native direct-input movement turn object vtable differs',
                       return_al=return_al, consumed=consumed)
    if struct.unpack_from('<H', obj, 8)[0] != PACKET_ID:
        return failure('native direct-input movement turn packet ID differs',
                       return_al=return_al, consumed=consumed)
    if struct.unpack_from('<I', obj, 0x0c)[0] != raw_param:
        return failure('native direct-input movement turn raw param differs from Replay',
                       return_al=return_al, consumed=consumed)
    raw_vector = obj[0x10:0x1c]
    callback_vector = raw_vector.translate(table)
    values = struct.unpack('<fff', callback_vector)
    if not all(math.isfinite(value) for value in values):
        return failure('callback-transformed f32 triple is nonfinite',
                       return_al=return_al, consumed=consumed)
    return {'status': 'DECODED', 'deserialize_return_al': return_al,
            'bytes_consumed': consumed, 'native_packet_id': PACKET_ID,
            'native_raw_param': raw_param,
            'raw_object_vector_bytes_hex': raw_vector.hex(),
            'callback_vector_bytes_hex': callback_vector.hex(),
            'opaque_f32_0x10': values[0], 'opaque_f32_0x14': values[1],
            'opaque_f32_0x18': values[2]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    options = parser.parse_args()
    digest = None
    try:
        packets = read_request()
        image, digest, _ = read_image(options.image)
        if digest != IMAGE_SHA256:
            raise ValueError('direct-input movement turn runtime image SHA-256 mismatch')
        table = callback_table()
        emulator, context = make_emulator(image)
        results = []
        for index, packet in enumerate(packets):
            try:
                raw_param, payload = validate_packet(packet)
            except ValueError as exc:
                row = failure(str(exc))
                row.update(input_index=index, raw_param=None, raw_payload_sha256=None)
                results.append(row)
                continue
            binding = {'input_index': index, 'raw_param': raw_param,
                       'raw_payload_sha256': hashlib.sha256(payload).hexdigest()}
            try:
                row = decode_packet(emulator, context, table, raw_param, payload)
                if row['status'] != 'DECODED':
                    emulator, context = make_emulator(image)
            except Exception as exc:
                row = failure(f'exact-runtime direct-input movement turn emulation failed: {exc}')
                emulator, context = make_emulator(image)
            row.update(binding)
            results.append(row)
        json.dump({'status': 'PASS', 'runtime_image_sha256': digest,
                   'callback_transform_sha256': CALLBACK_TRANSFORM_SHA256,
                   'results': results}, sys.stdout, separators=(',', ':'))
        sys.stdout.write('\n')
        return 0
    except Exception as exc:
        print(f'821 direct-input movement turn exact-runtime decoder error: {exc}',
              file=sys.stderr)
        json.dump({'status': 'ERROR', 'runtime_image_sha256': digest,
                   'results': [], 'error': str(exc)}, sys.stdout,
                  separators=(',', ':'))
        sys.stdout.write('\n')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

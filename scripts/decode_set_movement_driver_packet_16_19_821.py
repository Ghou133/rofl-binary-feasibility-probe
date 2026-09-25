#!/usr/bin/env python3
"""Decode an exact 821 SetMovementDriver packet callback selector.

Replay framing and provenance belong to the JavaScript caller. The shared
emulator injects Replay raw_param at native object +0x0c through its base-reader
hook; that value is a consistency check, not an independent identity result.
"""

import argparse
import hashlib
import json
import string
import struct
import sys
from pathlib import Path

from decode_mapview_inventory_16_19_821 import make_emulator, read_image


BUILD = '16.19.821.7343'
IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325'
IMAGE_BASE = 0x7ff67f410000
CALLBACK_TRANSFORM_SHA256 = '49a25c8d31448ba9cbcc1810c937e3c297a6a85e0724436994e8d31501cd8526'
PACKET_ID = 0x0335
VTABLE_RVA = 0x01ba7440
PROFILE = {'constructor_rva': 0x00ebed60, 'deserialize_rva': 0x01044010,
           'object_size': 0x48, 'fields': []}
OBSERVED_SHAPES = {(2, 0x54): (0x09, 1), (28, 0x26): (0x29, 2)}
MAX_INPUT_BYTES = 4_000_000
MAX_PACKETS = 8192


def failure(message, *, return_al=None, consumed=None):
    return {'status': 'FAILED', 'deserialize_return_al': return_al,
            'bytes_consumed': consumed, 'error': message}


def read_request():
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError('SetMovementDriver request exceeds bounded input size')
    request = json.loads(raw)
    if not isinstance(request, dict) or request.get('replay_version') != BUILD:
        raise ValueError(f'replay_version must be exactly {BUILD}')
    packets = request.get('packets')
    if not isinstance(packets, list) or len(packets) > MAX_PACKETS:
        raise ValueError(f'packets must be an array with at most {MAX_PACKETS} entries')
    return packets


def validate_packet(packet):
    if not isinstance(packet, dict) or packet.get('packet_id') != PACKET_ID:
        raise ValueError('packet ID must be exact 821 SetMovementDriver route')
    if packet.get('stream_tag') != 1:
        raise ValueError('SetMovementDriver candidate requires game stream')
    raw_param = packet.get('raw_param')
    if type(raw_param) is not int or not 0 < raw_param <= 0xffffffff:
        raise ValueError('raw_param must be a nonzero unsigned 32-bit integer')
    payload_hex = packet.get('payload_hex')
    if not isinstance(payload_hex, str) or len(payload_hex) % 2:
        raise ValueError('payload_hex must be even-length hexadecimal text')
    if any(character not in string.hexdigits for character in payload_hex):
        raise ValueError('payload_hex contains non-hexadecimal characters')
    payload = bytes.fromhex(payload_hex)
    if not payload or (len(payload), payload[0]) not in OBSERVED_SHAPES:
        raise ValueError('payload differs from observed 821 SetMovementDriver shape')
    return raw_param, payload


def ror8(value, amount):
    return ((value >> amount) | (value << (8 - amount))) & 0xff


def callback_transform(byte):
    # Registered callback RVA 0x002c1fec..0x002c2022 transforms object +0x2a.
    value = (byte - 0x73) & 0xff
    value = ror8(value, 2)
    value = (~value - 0x4a) & 0xff
    value = ror8(value, 7)
    value = (((value & 0xd5) << 1) | ((value >> 1) & 0x55)) & 0xff
    return ror8(value, 4)


def callback_table():
    table = bytes(callback_transform(value) for value in range(256))
    if len(set(table)) != 256 or hashlib.sha256(table).hexdigest() != CALLBACK_TRANSFORM_SHA256:
        raise ValueError('exact 821 SetMovementDriver callback transform differs')
    return table


def decode_packet(emulator, context, table, raw_param, payload):
    context['raw_param'] = raw_param
    native = emulator.decode(payload, PROFILE)
    return_al = native['deserialize_return_al']
    consumed = native['bytes_consumed']
    if return_al != 1 or not native['fully_consumed'] or consumed != len(payload):
        return failure('native SetMovementDriver did not fully consume payload',
                       return_al=return_al, consumed=consumed)
    obj = bytes.fromhex(native['object_hex'])
    if len(obj) != PROFILE['object_size']:
        return failure('native SetMovementDriver object size differs',
                       return_al=return_al, consumed=consumed)
    if struct.unpack_from('<Q', obj, 0)[0] != IMAGE_BASE + VTABLE_RVA:
        return failure('native SetMovementDriver object vtable differs',
                       return_al=return_al, consumed=consumed)
    if struct.unpack_from('<H', obj, 8)[0] != PACKET_ID:
        return failure('native SetMovementDriver packet ID differs',
                       return_al=return_al, consumed=consumed)
    if struct.unpack_from('<I', obj, 0x0c)[0] != raw_param:
        return failure('native SetMovementDriver Replay-param hook consistency failed',
                       return_al=return_al, consumed=consumed)
    raw_byte = obj[0x2a]
    opaque = table[raw_byte]
    expected_raw, expected_opaque = OBSERVED_SHAPES[(len(payload), payload[0])]
    if raw_byte != expected_raw or opaque != expected_opaque:
        return failure('native SetMovementDriver callback selector differs from observed shape',
                       return_al=return_al, consumed=consumed)
    return {'status': 'DECODED', 'deserialize_return_al': return_al,
            'bytes_consumed': consumed, 'native_packet_id': PACKET_ID,
            'native_raw_param': raw_param, 'raw_u8_byte_0x2a_hex': f'{raw_byte:02x}',
            'opaque_u8_0x2a': opaque}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    options = parser.parse_args()
    digest = None
    try:
        packets = read_request()
        image, digest, _ = read_image(options.image)
        if digest != IMAGE_SHA256:
            raise ValueError('SetMovementDriver runtime image SHA-256 mismatch')
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
                row = failure(f'exact-runtime SetMovementDriver emulation failed: {exc}')
                emulator, context = make_emulator(image)
            row.update(binding)
            results.append(row)
        json.dump({'status': 'PASS', 'runtime_image_sha256': digest,
                   'callback_transform_sha256': CALLBACK_TRANSFORM_SHA256,
                   'results': results}, sys.stdout, separators=(',', ':'))
        sys.stdout.write('\n')
        return 0
    except Exception as exc:
        print(f'821 SetMovementDriver exact-runtime decoder error: {exc}', file=sys.stderr)
        json.dump({'status': 'ERROR', 'runtime_image_sha256': digest,
                   'results': [], 'error': str(exc)}, sys.stdout,
                  separators=(',', ':'))
        sys.stdout.write('\n')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

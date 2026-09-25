#!/usr/bin/env python3
"""Decode exact 821 BuffReplace packet fields without assigning gameplay meaning.

The JavaScript caller owns Replay framing and provenance. This helper executes
the exact captured client constructor, deserializer and callback byte helpers.
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
PACKET_ID = 0x01ad
VTABLE_RVA = 0x01ba86d8
PROFILE = {'constructor_rva': 0x00e9d450, 'deserialize_rva': 0x010dcac0,
           'object_size': 0x20, 'fields': []}
HELPERS = {
    # Callback RVA 0x8f29c0 inlines the same byte paths as these 821 helpers.
    'opaque_u8_0x10': (0x00873df0, '61fc4c46a9d37a0903bbf158b451700ef9fe3a1e696c03e64ed6ff822c29a0a6'),
    'opaque_f32_0x14': (0x00873dd0, '0a2ced1eb36b6eb3436e42dc4a057436c7bc01a28cf72e6b98e631a97910fb27'),
    'opaque_f32_0x1c': (0x00873c40, '3340642441bdc1f66c2c855975ae3e284b950a52c5dc07ff2a065bf3888a6e0c'),
}
CALLBACK_LOOKUP_TABLE_RVA = 0x01b41db0
CALLBACK_LOOKUP_TABLE_SHA256 = '328528d693ab5d96a815b6706694025a980e609019304aeb2e5e32797011c04b'
U32_0X18_SHA256 = '3151a2d39b9cbf30a07bf71a8d8517d120bc7fe711a1f5a19bd6434b78ddbb49'
OBSERVED_PAYLOAD_LENGTHS = frozenset((4, 5, 6, 8, 9, 10))
MAX_INPUT_BYTES = 4_000_000
MAX_PACKETS = 10_000


def failure(message, *, return_al=None, consumed=None):
    return {'status': 'FAILED', 'deserialize_return_al': return_al,
            'bytes_consumed': consumed, 'error': message}


def read_request():
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError('BuffReplace request exceeds bounded input size')
    request = json.loads(raw)
    if not isinstance(request, dict) or request.get('replay_version') != BUILD:
        raise ValueError(f'replay_version must be exactly {BUILD}')
    packets = request.get('packets')
    if not isinstance(packets, list) or len(packets) > MAX_PACKETS:
        raise ValueError(f'packets must be an array with at most {MAX_PACKETS} entries')
    return packets


def validate_packet(packet):
    if not isinstance(packet, dict) or packet.get('packet_id') != PACKET_ID:
        raise ValueError('packet ID must be exact 821 BuffReplace route')
    if packet.get('stream_tag') != 1:
        raise ValueError('BuffReplace candidate requires game stream')
    raw_param = packet.get('raw_param')
    if type(raw_param) is not int or not 0 < raw_param <= 0xffffffff:
        raise ValueError('raw_param must be a nonzero unsigned 32-bit integer')
    payload_hex = packet.get('payload_hex')
    if not isinstance(payload_hex, str) or len(payload_hex) % 2:
        raise ValueError('payload_hex must be even-length hexadecimal text')
    if any(character not in string.hexdigits for character in payload_hex):
        raise ValueError('payload_hex contains non-hexadecimal characters')
    payload = bytes.fromhex(payload_hex)
    if len(payload) not in OBSERVED_PAYLOAD_LENGTHS:
        raise ValueError('payload length differs from observed 821 BuffReplace scope')
    return raw_param, payload


def ror8(value, count):
    return ((value >> count) | (value << (8 - count))) & 0xff


def callback_tables(emulator, image):
    tables = {}
    digests = {}
    for name, (rva, expected) in HELPERS.items():
        table = emulator.decode_bytes(bytes(range(256)), rva)
        digest = hashlib.sha256(table).hexdigest()
        if len(table) != 256 or len(set(table)) != 256 or digest != expected:
            raise ValueError(f'exact 821 BuffReplace callback transform differs: {name}')
        tables[name] = table
        digests[name] = digest
    lookup = image[CALLBACK_LOOKUP_TABLE_RVA:CALLBACK_LOOKUP_TABLE_RVA + 256]
    if len(lookup) != 256 or hashlib.sha256(lookup).hexdigest() != CALLBACK_LOOKUP_TABLE_SHA256:
        raise ValueError('exact 821 BuffReplace callback lookup table differs')
    # Callback RVA 0x8f2a50..0x8f2a75 reads object +0x18 as four bytes.
    def transform_u32_byte(value):
        low = (value >> 1) & 0x55
        transformed = (((value & 0xd5) << 1) | low) & 0xff
        transformed = ror8(transformed, 7) ^ 0x10
        transformed = (((transformed & 0xd5) << 1) | low) & 0xff
        return (~transformed) & 0xff

    u32 = bytes(transform_u32_byte(value) for value in range(256))
    digest = hashlib.sha256(u32).hexdigest()
    if len(set(u32)) != 256 or digest != U32_0X18_SHA256:
        raise ValueError('exact 821 BuffReplace callback +0x18 transform differs')
    tables['opaque_u32_0x18'] = u32
    digests['opaque_u32_0x18'] = digest
    return tables, digests


def decode_packet(emulator, context, tables, raw_param, payload):
    context['raw_param'] = raw_param
    native = emulator.decode(payload, PROFILE)
    return_al = native['deserialize_return_al']
    consumed = native['bytes_consumed']
    if return_al != 1 or not native['fully_consumed'] or consumed != len(payload):
        return failure('native BuffReplace did not fully consume payload',
                       return_al=return_al, consumed=consumed)
    obj = bytes.fromhex(native['object_hex'])
    if len(obj) != PROFILE['object_size']:
        return failure('native BuffReplace object size differs',
                       return_al=return_al, consumed=consumed)
    if struct.unpack_from('<Q', obj, 0)[0] != IMAGE_BASE + VTABLE_RVA:
        return failure('native BuffReplace object vtable differs',
                       return_al=return_al, consumed=consumed)
    if struct.unpack_from('<H', obj, 8)[0] != PACKET_ID:
        return failure('native BuffReplace packet ID differs',
                       return_al=return_al, consumed=consumed)
    if struct.unpack_from('<I', obj, 0x0c)[0] != raw_param:
        return failure('native BuffReplace raw param differs from Replay',
                       return_al=return_al, consumed=consumed)
    raw_u8_0x10 = obj[0x10:0x11]
    raw_f32_0x14 = obj[0x14:0x18]
    raw_u32_0x18 = obj[0x18:0x1c]
    raw_f32_0x1c = obj[0x1c:0x20]
    opaque_f32_0x14 = struct.unpack(
        '<f', raw_f32_0x14.translate(tables['opaque_f32_0x14']))[0]
    opaque_f32_0x1c = struct.unpack(
        '<f', raw_f32_0x1c.translate(tables['opaque_f32_0x1c']))[0]
    if not math.isfinite(opaque_f32_0x14) or not math.isfinite(opaque_f32_0x1c):
        return failure('callback-transformed f32 is nonfinite',
                       return_al=return_al, consumed=consumed)
    return {'status': 'DECODED', 'deserialize_return_al': return_al,
            'bytes_consumed': consumed, 'native_packet_id': PACKET_ID,
            'native_raw_param': raw_param,
            'opaque_u8_0x10': raw_u8_0x10.translate(tables['opaque_u8_0x10'])[0],
            'opaque_f32_0x14': opaque_f32_0x14,
            'opaque_u32_0x18': struct.unpack(
                '<I', raw_u32_0x18.translate(tables['opaque_u32_0x18']))[0],
            'opaque_f32_0x1c': opaque_f32_0x1c,
            'raw_u8_0x10_hex': raw_u8_0x10.hex(),
            'raw_f32_0x14_hex': raw_f32_0x14.hex(),
            'raw_u32_0x18_hex': raw_u32_0x18.hex(),
            'raw_f32_0x1c_hex': raw_f32_0x1c.hex()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    options = parser.parse_args()
    digest = None
    try:
        packets = read_request()
        image, digest, _ = read_image(options.image)
        if digest != IMAGE_SHA256:
            raise ValueError('BuffReplace runtime image SHA-256 mismatch')
        emulator, context = make_emulator(image)
        tables, table_digests = callback_tables(emulator, image)
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
                row = decode_packet(emulator, context, tables, raw_param, payload)
                if row['status'] != 'DECODED':
                    emulator, context = make_emulator(image)
            except Exception as exc:
                row = failure(f'exact-runtime BuffReplace emulation failed: {exc}')
                emulator, context = make_emulator(image)
            row.update(binding)
            results.append(row)
        json.dump({'status': 'PASS', 'runtime_image_sha256': digest,
                   'callback_table_sha256': table_digests, 'results': results},
                  sys.stdout, separators=(',', ':'))
        sys.stdout.write('\n')
        return 0
    except Exception as exc:
        print(f'821 BuffReplace exact-runtime decoder error: {exc}', file=sys.stderr)
        json.dump({'status': 'ERROR', 'runtime_image_sha256': digest,
                   'results': [], 'error': str(exc)}, sys.stdout,
                  separators=(',', ':'))
        sys.stdout.write('\n')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

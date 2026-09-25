#!/usr/bin/env python3
"""Decode exact KR 821 SetSpellTimerFromBuff packet fields as candidates.

The JavaScript caller owns Replay framing and provenance. This helper runs the
pinned client's constructor/deserializer and the callback's byte transforms.
Neither the packet name nor these fields establishes a timer or buff effect.
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
PACKET_ID = 0x00fd
FACTORY_TABLE_RVA = 0x00f0e4bc
FACTORY_CASE_RVA = 0x00f013cf
VTABLE_RVA = 0x01ba8f08
CALLBACK_RVA = 0x002c2760
PROFILE = {'constructor_rva': 0x00ebf9a0, 'deserialize_rva': 0x010fe3e0,
           'object_size': 0x24, 'fields': []}
LOOKUP_TABLE_RVA = 0x01ab62d0
LOOKUP_TABLE_SHA256 = '328528d693ab5d96a815b6706694025a980e609019304aeb2e5e32797011c04b'
CALLBACK_TABLE_SHA256 = {
    'opaque_u8_0x10': '48a697d580affb9688308aa3f7a09ee24d87378dd299a5128a4447f1795c39a4',
    'opaque_u8_0x11': 'cddd28e48f36e54efe3d10a70fd25121d665001654b661c121767c2ca23f2425',
    'opaque_f32_0x14': '24206a5cc1586f42dd59c98818754f592a18e7ee3026115615e69e5814630c68',
    'opaque_u32_0x18': 'b097f9ce648ac9593a43258eb81b7ee20dc37e7162a8bd584e768785c24ddbb3',
    'opaque_u32_0x1c': 'a90f34d17c8715929574f708ea279badb13f527d6d025a6138fb179b7329c84b',
    'opaque_u8_0x20': '8aa1a1d1b3c61b2717fbf3b7349dcc659f21d91cd0fe98404e4dc6b700214cb5',
}
OBSERVED_PAYLOAD_LENGTHS = frozenset((7, 8, 10, 11, 12))
MAX_INPUT_BYTES = 4_000_000
MAX_PACKETS = 10_000


def failure(message, *, return_al=None, consumed=None):
    return {'status': 'FAILED', 'deserialize_return_al': return_al,
            'bytes_consumed': consumed, 'error': message}


def read_request():
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError('SetSpellTimerFromBuff request exceeds bounded input size')
    request = json.loads(raw)
    if not isinstance(request, dict) or request.get('replay_version') != BUILD:
        raise ValueError(f'replay_version must be exactly {BUILD}')
    packets = request.get('packets')
    if not isinstance(packets, list) or len(packets) > MAX_PACKETS:
        raise ValueError(f'packets must be an array with at most {MAX_PACKETS} entries')
    return packets


def validate_packet(packet):
    if not isinstance(packet, dict) or packet.get('packet_id') != PACKET_ID:
        raise ValueError('packet ID must be exact 821 SetSpellTimerFromBuff route')
    if packet.get('stream_tag') != 1:
        raise ValueError('SetSpellTimerFromBuff candidate requires game stream')
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
        raise ValueError('payload length differs from observed 821 SetSpellTimerFromBuff scope')
    return raw_param, payload


def ror8(value, count):
    return ((value >> count) | (value << (8 - count))) & 0xff


def swap_bits(value):
    return (((value & 0xd5) << 1) | ((value >> 1) & 0x55)) & 0xff


def callback_tables(image):
    # Exact callback RVA 0x2c2760 reads six anonymous object offsets. The
    # static lookup table and every 256-byte transform are checked against the
    # pinned image before any Replay packet is emitted.
    table = image[LOOKUP_TABLE_RVA:LOOKUP_TABLE_RVA + 256]
    if len(table) != 256 or hashlib.sha256(table).hexdigest() != LOOKUP_TABLE_SHA256:
        raise ValueError('exact 821 SetSpellTimerFromBuff callback lookup table differs')
    transformations = {
        'opaque_u8_0x10': lambda x: table[(table[x] + 0x51) & 0xff],
        'opaque_u8_0x11': lambda x: (ror8((~x + 0x19) & 0xff, 1) - 0x29) & 0xff,
        'opaque_f32_0x14': lambda x: ror8((ror8(swap_bits((x - 0x6d) & 0xff), 5) + 9) & 0xff, 4),
        'opaque_u32_0x18': lambda x: ((ror8(x, 6) + 0x41) & 0xff) ^ 8,
        'opaque_u32_0x1c': lambda x: ror8(x, 1),
        'opaque_u8_0x20': lambda x: (ror8((~ror8((swap_bits(x) + 0x68) & 0xff, 6)) & 0xff, 6) - 2) & 0xff,
    }
    tables = {}
    for name, transform in transformations.items():
        value = bytes(transform(x) for x in range(256))
        if (len(set(value)) != 256
                or hashlib.sha256(value).hexdigest() != CALLBACK_TABLE_SHA256[name]):
            raise ValueError(f'exact 821 SetSpellTimerFromBuff callback transform differs: {name}')
        tables[name] = value
    return tables


def check_static_identity(image):
    if struct.unpack_from('<I', image, FACTORY_TABLE_RVA + PACKET_ID * 4)[0] != FACTORY_CASE_RVA:
        raise ValueError('exact 821 SetSpellTimerFromBuff factory route differs')
    constructor = PROFILE['constructor_rva']
    if image[constructor + 7:constructor + 13] != b'\x66\xc7\x41\x08\xfd\x00':
        raise ValueError('exact 821 SetSpellTimerFromBuff constructor ID differs')
    if struct.unpack_from('<Q', image, VTABLE_RVA + 8)[0] != IMAGE_BASE + PROFILE['deserialize_rva']:
        raise ValueError('exact 821 SetSpellTimerFromBuff deserializer route differs')
    if image[CALLBACK_RVA:CALLBACK_RVA + 6] != b'\x40\x53\x48\x83\xec\x40':
        raise ValueError('exact 821 SetSpellTimerFromBuff callback differs')


def decode_packet(emulator, context, tables, raw_param, payload):
    context['raw_param'] = raw_param
    native = emulator.decode(payload, PROFILE)
    return_al = native['deserialize_return_al']
    consumed = native['bytes_consumed']
    if return_al != 1 or not native['fully_consumed'] or consumed != len(payload):
        return failure('native SetSpellTimerFromBuff did not fully consume payload',
                       return_al=return_al, consumed=consumed)
    obj = bytes.fromhex(native['object_hex'])
    if len(obj) != PROFILE['object_size']:
        return failure('native SetSpellTimerFromBuff object size differs',
                       return_al=return_al, consumed=consumed)
    if struct.unpack_from('<Q', obj, 0)[0] != IMAGE_BASE + VTABLE_RVA:
        return failure('native SetSpellTimerFromBuff object vtable differs',
                       return_al=return_al, consumed=consumed)
    if struct.unpack_from('<H', obj, 8)[0] != PACKET_ID:
        return failure('native SetSpellTimerFromBuff packet ID differs',
                       return_al=return_al, consumed=consumed)
    if struct.unpack_from('<I', obj, 0x0c)[0] != raw_param:
        return failure('native SetSpellTimerFromBuff raw param differs from Replay',
                       return_al=return_al, consumed=consumed)
    offsets = (('opaque_u8_0x10', 0x10, 1), ('opaque_u8_0x11', 0x11, 1),
               ('opaque_f32_0x14', 0x14, 4), ('opaque_u32_0x18', 0x18, 4),
               ('opaque_u32_0x1c', 0x1c, 4), ('opaque_u8_0x20', 0x20, 1))
    fields = {}
    for name, offset, size in offsets:
        raw = obj[offset:offset + size]
        decoded = raw.translate(tables[name])
        fields['raw_' + name[7:] + '_hex'] = raw.hex()
        if name.startswith('opaque_f32'):
            value = struct.unpack('<f', decoded)[0]
            if not math.isfinite(value):
                return failure('callback-transformed f32 is nonfinite',
                               return_al=return_al, consumed=consumed)
        else:
            value = int.from_bytes(decoded, 'little')
        fields[name] = value
    return {'status': 'DECODED', 'deserialize_return_al': return_al,
            'bytes_consumed': consumed, 'native_packet_id': PACKET_ID,
            'native_raw_param': raw_param, **fields}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    options = parser.parse_args()
    digest = None
    try:
        packets = read_request()
        image, digest, _ = read_image(options.image)
        if digest != IMAGE_SHA256:
            raise ValueError('SetSpellTimerFromBuff runtime image SHA-256 mismatch')
        check_static_identity(image)
        tables = callback_tables(image)
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
                row = decode_packet(emulator, context, tables, raw_param, payload)
                if row['status'] != 'DECODED':
                    emulator, context = make_emulator(image)
            except Exception as exc:
                row = failure(f'exact-runtime SetSpellTimerFromBuff emulation failed: {exc}')
                emulator, context = make_emulator(image)
            row.update(binding)
            results.append(row)
        json.dump({'status': 'PASS', 'runtime_image_sha256': digest,
                   'callback_table_sha256': CALLBACK_TABLE_SHA256, 'results': results},
                  sys.stdout, separators=(',', ':'))
        sys.stdout.write('\n')
        return 0
    except Exception as exc:
        print(f'821 SetSpellTimerFromBuff exact-runtime decoder error: {exc}', file=sys.stderr)
        json.dump({'status': 'ERROR', 'runtime_image_sha256': digest,
                   'results': [], 'error': str(exc)}, sys.stdout,
                  separators=(',', ':'))
        sys.stdout.write('\n')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
"""Decode exact 821 BuffAdd2 packet fields without assigning gameplay meaning.

The JavaScript caller owns Replay framing and provenance. This helper executes
the exact captured client constructor, deserializer and callback byte helpers.
"""

import argparse
import hashlib
import json
import string
import struct
import sys
from pathlib import Path

from decode_mapview_inventory_16_19_821 import make_emulator, read_image
from emulate_exact_packet_decoder import HEAP_BASE, HEAP_SIZE


BUILD = '16.19.821.7343'
IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325'
IMAGE_BASE = 0x7ff67f410000
PACKET_ID = 0x00ae
VTABLE_RVA = 0x01ba8650
PROFILE = {'constructor_rva': 0x00e9cbd0, 'deserialize_rva': 0x010d88d0,
           'object_size': 0x68, 'fields': []}
HELPERS = {
    'opaque_u32_0x10': (0x00873b80, 'a90f34d17c8715929574f708ea279badb13f527d6d025a6138fb179b7329c84b'),
    'opaque_u8_0x14': (0x00873df0, '61fc4c46a9d37a0903bbf158b451700ef9fe3a1e696c03e64ed6ff822c29a0a6'),
}
OBSERVED_PAYLOAD_LENGTHS = {
    1: frozenset((12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 28)),
    2: frozenset((13, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
                  29, 30, 31, 32, 33, 41, 42)),
}
MAX_INPUT_BYTES = 8_000_000
MAX_PACKETS = 40_000


def failure(message, *, return_al=None, consumed=None):
    return {'status': 'FAILED', 'deserialize_return_al': return_al,
            'bytes_consumed': consumed, 'error': message}


def read_request():
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError('BuffAdd2 request exceeds bounded input size')
    request = json.loads(raw)
    if not isinstance(request, dict) or request.get('replay_version') != BUILD:
        raise ValueError(f'replay_version must be exactly {BUILD}')
    packets = request.get('packets')
    if not isinstance(packets, list) or len(packets) > MAX_PACKETS:
        raise ValueError(f'packets must be an array with at most {MAX_PACKETS} entries')
    return packets


def validate_packet(packet):
    if not isinstance(packet, dict) or packet.get('packet_id') != PACKET_ID:
        raise ValueError('packet ID must be exact 821 BuffAdd2 route')
    stream_tag = packet.get('stream_tag')
    if stream_tag not in OBSERVED_PAYLOAD_LENGTHS:
        raise ValueError('BuffAdd2 candidate requires observed game/keyframe stream')
    raw_param = packet.get('raw_param')
    if type(raw_param) is not int or not 0 < raw_param <= 0xffffffff:
        raise ValueError('raw_param must be a nonzero unsigned 32-bit integer')
    payload_hex = packet.get('payload_hex')
    if not isinstance(payload_hex, str) or len(payload_hex) % 2:
        raise ValueError('payload_hex must be even-length hexadecimal text')
    if any(character not in string.hexdigits for character in payload_hex):
        raise ValueError('payload_hex contains non-hexadecimal characters')
    payload = bytes.fromhex(payload_hex)
    if len(payload) not in OBSERVED_PAYLOAD_LENGTHS[stream_tag]:
        raise ValueError('stream/payload length differs from observed 821 BuffAdd2 scope')
    return raw_param, payload


def callback_tables(emulator):
    tables = {}
    digests = {}
    for name, (rva, expected) in HELPERS.items():
        table = emulator.decode_bytes(bytes(range(256)), rva)
        digest = hashlib.sha256(table).hexdigest()
        if len(table) != 256 or len(set(table)) != 256 or digest != expected:
            raise ValueError(f'exact 821 BuffAdd2 callback transform differs: {name}')
        tables[name] = table
        digests[name] = digest
    return tables, digests


def rare_vector_shape_valid(emulator, obj, payload_length):
    first = struct.unpack_from('<QII', obj, 0x20)
    second = struct.unpack_from('<QII', obj, 0x50)
    if payload_length == 41:
        pointer, count, capacity = first
        other = second
        element_size, vtable_rva = 0x1c, 0x01ba8600
    else:
        pointer, count, capacity = second
        other = first
        element_size, vtable_rva = 0x28, 0x01ba8628
    end = pointer + element_size
    if (other != (0, 0, 0) or (count, capacity) != (1, 1)
            or pointer < HEAP_BASE or end > HEAP_BASE + HEAP_SIZE
            or end > emulator.heap_cursor):
        return False
    element = bytes(emulator.emulator.mem_read(pointer, element_size))
    return struct.unpack_from('<Q', element, 0)[0] == IMAGE_BASE + vtable_rva


def decode_packet(emulator, context, tables, raw_param, payload):
    context['raw_param'] = raw_param
    native = emulator.decode(payload, PROFILE)
    return_al = native['deserialize_return_al']
    consumed = native['bytes_consumed']
    if return_al != 1 or not native['fully_consumed'] or consumed != len(payload):
        return failure('native BuffAdd2 did not fully consume payload',
                       return_al=return_al, consumed=consumed)
    obj = bytes.fromhex(native['object_hex'])
    if len(obj) != PROFILE['object_size']:
        return failure('native BuffAdd2 object size differs',
                       return_al=return_al, consumed=consumed)
    if struct.unpack_from('<Q', obj, 0)[0] != IMAGE_BASE + VTABLE_RVA:
        return failure('native BuffAdd2 object vtable differs',
                       return_al=return_al, consumed=consumed)
    if struct.unpack_from('<H', obj, 8)[0] != PACKET_ID:
        return failure('native BuffAdd2 packet ID differs',
                       return_al=return_al, consumed=consumed)
    if struct.unpack_from('<I', obj, 0x0c)[0] != raw_param:
        return failure('native BuffAdd2 raw param differs from Replay',
                       return_al=return_al, consumed=consumed)
    if len(payload) in (41, 42) and not rare_vector_shape_valid(emulator, obj, len(payload)):
        return failure('native BuffAdd2 rare vector shape differs',
                       return_al=return_al, consumed=consumed)
    raw_u32 = obj[0x10:0x14]
    raw_u8 = obj[0x14:0x15]
    opaque_u32 = struct.unpack('<I', raw_u32.translate(tables['opaque_u32_0x10']))[0]
    opaque_u8 = raw_u8.translate(tables['opaque_u8_0x14'])[0]
    return {'status': 'DECODED', 'deserialize_return_al': return_al,
            'bytes_consumed': consumed, 'native_packet_id': PACKET_ID,
            'native_raw_param': raw_param, 'opaque_u32_0x10': opaque_u32,
            'opaque_u8_0x14': opaque_u8,
            'raw_u32_bytes_hex': raw_u32.hex(),
            'raw_u8_byte_hex': raw_u8.hex()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    options = parser.parse_args()
    digest = None
    try:
        packets = read_request()
        image, digest, _ = read_image(options.image)
        if digest != IMAGE_SHA256:
            raise ValueError('BuffAdd2 runtime image SHA-256 mismatch')
        emulator, context = make_emulator(image)
        tables, table_digests = callback_tables(emulator)
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
                row = failure(f'exact-runtime BuffAdd2 emulation failed: {exc}')
                emulator, context = make_emulator(image)
            row.update(binding)
            results.append(row)
        json.dump({'status': 'PASS', 'runtime_image_sha256': digest,
                   'callback_table_sha256': table_digests, 'results': results},
                  sys.stdout, separators=(',', ':'))
        sys.stdout.write('\n')
        return 0
    except Exception as exc:
        print(f'821 BuffAdd2 exact-runtime decoder error: {exc}', file=sys.stderr)
        json.dump({'status': 'ERROR', 'runtime_image_sha256': digest,
                   'results': [], 'error': str(exc)}, sys.stdout,
                  separators=(',', ':'))
        sys.stdout.write('\n')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

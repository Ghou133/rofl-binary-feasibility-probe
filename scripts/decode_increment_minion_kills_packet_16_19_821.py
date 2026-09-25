#!/usr/bin/env python3
"""Decode exact 821 IncrementMinionKills packet lookup keys, not CS effects.

The native base-reader hook receives Replay framing raw_param at object +0x0c.
The callback separately transforms object +0x10 into its lookup key. Agreement
between those two values is checked, but live lookup and stat mutation are not
executed here.
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
TRANSFORM_SHA256 = '51a5a168ef2528cbf77c181560d98a91ee83478d556568d0ba855a16ce0e4150'
PACKET_ID = 0x03a7
VTABLE_RVA = 0x01ba6258
PROFILE = {'constructor_rva': 0x00eae360, 'deserialize_rva': 0x00ffce60,
           'object_size': 0x14, 'fields': []}
OBSERVED_PAYLOADS = frozenset(bytes.fromhex(value) for value in (
    '380718', '382618', '382718', '38e518',
    '390718', '392618', '392718', '39e518',
    '3a0718', '3a2618', '3a2718', '3ae518',
    '3d0718', '3d2618', '3d2718', '3de518',
    '3e0718', '3e2618', '3e2718', '3e8b18', '3ecb18', '3ee518', '3ee618',
    '3f0718', '3f2618', '3f2718', '3fcb18', '3fe518', '3fe618',
))
HERO_PARAM_FIRST = 0x400000ae
HERO_PARAM_LAST = 0x400000b7
MAX_INPUT_BYTES = 4_000_000
MAX_PACKETS = 2048


def failure(message, *, return_al=None, consumed=None):
    return {'status': 'FAILED', 'deserialize_return_al': return_al,
            'bytes_consumed': consumed, 'error': message}


def read_request():
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError('IncrementMinionKills request exceeds bounded input size')
    request = json.loads(raw)
    if not isinstance(request, dict) or request.get('replay_version') != BUILD:
        raise ValueError(f'replay_version must be exactly {BUILD}')
    packets = request.get('packets')
    if not isinstance(packets, list) or len(packets) > MAX_PACKETS:
        raise ValueError(f'packets must be an array with at most {MAX_PACKETS} entries')
    return packets


def validate_packet(packet):
    if not isinstance(packet, dict) or packet.get('packet_id') != PACKET_ID:
        raise ValueError('packet ID must be exact 821 IncrementMinionKills route')
    if packet.get('stream_tag') != 1:
        raise ValueError('IncrementMinionKills candidate requires game stream')
    raw_param = packet.get('raw_param')
    if type(raw_param) is not int or not HERO_PARAM_FIRST <= raw_param <= HERO_PARAM_LAST:
        raise ValueError('raw_param is outside the observed canonical hero family')
    payload_hex = packet.get('payload_hex')
    if not isinstance(payload_hex, str) or len(payload_hex) != 6:
        raise ValueError('payload_hex must encode exactly three bytes')
    if any(character not in string.hexdigits for character in payload_hex):
        raise ValueError('payload_hex contains non-hexadecimal characters')
    payload = bytes.fromhex(payload_hex)
    if payload not in OBSERVED_PAYLOADS:
        raise ValueError('payload differs from the 29 observed 821 route bodies')
    return raw_param, payload


def ror8(value, amount):
    return ((value >> amount) | (value << (8 - amount))) & 0xff


def callback_transform(byte):
    # Registered callback RVA 0x002c91f0..0x002c9225 transforms object +0x10.
    value = (byte - 2) & 0xff
    value = ror8(value, 7)
    value = (value + 0x1c) & 0xff
    value = ror8(value, 4)
    value = (value + 0x75) & 0xff
    value = ror8(value, 2)
    value = (value - 0x7c) & 0xff
    return (((value & 0xd5) << 1) | ((value >> 1) & 0x55)) & 0xff


def callback_table():
    table = bytes(callback_transform(value) for value in range(256))
    if len(set(table)) != 256 or hashlib.sha256(table).hexdigest() != TRANSFORM_SHA256:
        raise ValueError('exact 821 IncrementMinionKills callback transform differs')
    return table


def decode_packet(emulator, context, table, raw_param, payload):
    context['raw_param'] = raw_param
    native = emulator.decode(payload, PROFILE)
    return_al = native['deserialize_return_al']
    consumed = native['bytes_consumed']
    if return_al != 1 or not native['fully_consumed'] or consumed != len(payload):
        return failure('native IncrementMinionKills did not fully consume payload',
                       return_al=return_al, consumed=consumed)
    obj = bytes.fromhex(native['object_hex'])
    if len(obj) != PROFILE['object_size']:
        return failure('native IncrementMinionKills object size differs',
                       return_al=return_al, consumed=consumed)
    if struct.unpack_from('<Q', obj, 0)[0] != IMAGE_BASE + VTABLE_RVA:
        return failure('native IncrementMinionKills object vtable differs',
                       return_al=return_al, consumed=consumed)
    if struct.unpack_from('<H', obj, 8)[0] != PACKET_ID:
        return failure('native IncrementMinionKills packet ID differs',
                       return_al=return_al, consumed=consumed)
    native_param = struct.unpack_from('<I', obj, 0x0c)[0]
    if native_param != raw_param:
        return failure('native IncrementMinionKills base-reader hook differs',
                       return_al=return_al, consumed=consumed)
    raw_lookup = obj[0x10:0x14]
    lookup_key = int.from_bytes(bytes(table[byte] for byte in raw_lookup), 'little')
    if lookup_key != raw_param:
        return failure('native callback lookup key differs from Replay raw_param',
                       return_al=return_al, consumed=consumed)
    return {'status': 'DECODED', 'deserialize_return_al': return_al,
            'bytes_consumed': consumed, 'native_packet_id': PACKET_ID,
            'native_raw_param': native_param,
            'native_object_lookup_key_bytes_hex': raw_lookup.hex(),
            'callback_lookup_key_candidate': lookup_key}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    options = parser.parse_args()
    digest = None
    try:
        packets = read_request()
        image, digest, _ = read_image(options.image)
        if digest != IMAGE_SHA256:
            raise ValueError('IncrementMinionKills runtime image SHA-256 mismatch')
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
                row = failure(f'exact-runtime IncrementMinionKills emulation failed: {exc}')
                emulator, context = make_emulator(image)
            row.update(binding)
            results.append(row)
        json.dump({'status': 'PASS', 'runtime_image_sha256': digest,
                   'callback_transform_sha256': TRANSFORM_SHA256,
                   'results': results}, sys.stdout, separators=(',', ':'))
        sys.stdout.write('\n')
        return 0
    except Exception as exc:
        print(f'821 IncrementMinionKills exact-runtime decoder error: {exc}',
              file=sys.stderr)
        json.dump({'status': 'ERROR', 'runtime_image_sha256': digest,
                   'results': [], 'error': str(exc)}, sys.stdout,
                  separators=(',', ':'))
        sys.stdout.write('\n')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

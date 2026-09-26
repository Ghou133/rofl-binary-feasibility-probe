#!/usr/bin/env python3
"""Exact KR 821 packet-local lookup-key witness for route 0x039d.

Stops before receiver lookup. A lookup key does not establish cooldown state.
"""

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_RDX, UC_X86_REG_RIP

import emulate_exact_packet_decoder as exact
from decode_broadcast_inventory_16_19_821 import make_emulator


BUILD = '16.19.821.7343'
IMAGE_BASE = 0x7ff67f410000
IMAGE_SIZE = 48_488_448
IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325'
PACKET_ID = 0x039d
FACTORY_TABLE_RVA = 0xf0e4bc
FACTORY_CASE_RVA = 0xf09d3f
CONSTRUCTOR_RVA = 0xe99ba0
VTABLE_RVA = 0x1ba2930
DESERIALIZER_RVA = 0xf1a4e0
CALLBACK_RVA = 0x2bbc90
LOOKUP_CALLSITE_RVA = 0x2bbcc5
LOOKUP_RVA = 0x98a840
PROFILE = {'constructor_rva': CONSTRUCTOR_RVA,
           'deserialize_rva': DESERIALIZER_RVA,
           'object_size': 0x28, 'fields': []}
OBSERVED_LENGTHS = frozenset({2, 3, 6, 7, 10, 11, 14, 15})
MAX_REQUEST_BYTES = 512 * 1024
MAX_PACKETS = 10_000


def ror8(value, count):
    return ((value >> count) | (value << (8 - count))) & 0xff


def decode_lookup_key(protected):
    value = ror8(protected, 6) ^ 0x6d
    value = ror8((value - 0x2e) & 0xff, 5) ^ 0x11
    return ror8(value, 6) ^ 0xbd


def read_image(path):
    if not path.is_file() or path.stat().st_size != IMAGE_SIZE:
        raise ValueError('exact 821 runtime image is missing or has the wrong size')
    image = path.read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    if digest != IMAGE_SHA256:
        raise ValueError(f'exact 821 runtime image SHA-256 mismatch: {digest}')
    if (struct.unpack_from('<I', image, FACTORY_TABLE_RVA + PACKET_ID * 4)[0]
            != FACTORY_CASE_RVA
            or image[CONSTRUCTOR_RVA:CONSTRUCTOR_RVA + 13]
            != bytes.fromhex('488d051985c10066c741089d03')
            or struct.unpack_from('<Q', image, VTABLE_RVA + 8)[0]
            != IMAGE_BASE + DESERIALIZER_RVA
            or image[CALLBACK_RVA + 15:CALLBACK_RVA + 19]
            != bytes.fromhex('0fb64210')
            or image[LOOKUP_CALLSITE_RVA] != 0xe8
            or LOOKUP_CALLSITE_RVA + 5
            + struct.unpack_from('<i', image, LOOKUP_CALLSITE_RVA + 1)[0]
            != LOOKUP_RVA):
        raise ValueError('exact 821 factory, native reader, or callback differs')
    # The pinned image's registration names AIBaseClient and the packet class.
    if b'PKT_CHAR_SetCooldown_Broadcast_s' not in image:
        raise ValueError('exact 821 packet RTTI name differs')
    return image, digest


def read_request():
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError('native request exceeds 512 KiB')
    request = json.loads(raw)
    if (not isinstance(request, dict) or request.get('replay_version') != BUILD
            or request.get('packet_id') != PACKET_ID):
        raise ValueError('native request requires exact build and route')
    source = request.get('packets')
    if not isinstance(source, list) or not 0 < len(source) <= MAX_PACKETS:
        raise ValueError('native packets must contain 1..10000 rows')
    packets = []
    for entry in source:
        if not isinstance(entry, list) or len(entry) != 2:
            raise ValueError('packet must be [raw_param, payload_hex]')
        raw_param, payload_hex = entry
        if type(raw_param) is not int or not 0 <= raw_param <= 0xffffffff:
            raise ValueError('raw parameter must be u32')
        if not isinstance(payload_hex, str) or len(payload_hex) % 2:
            raise ValueError('payload must be even-length hexadecimal text')
        payload = bytes.fromhex(payload_hex)
        if len(payload) not in OBSERVED_LENGTHS:
            raise ValueError('payload length differs from observed exact-build lengths')
        packets.append((raw_param, payload))
    return packets


def input_hash(packets):
    digest = hashlib.sha256()
    for raw_param, payload in packets:
        digest.update(struct.pack('<II', raw_param, len(payload)))
        digest.update(payload)
    return digest.hexdigest()


def output_hash(rows):
    digest = hashlib.sha256()
    for row in rows:
        digest.update(bytes.fromhex(row['native_protected_lookup_byte_hex']))
        digest.update(struct.pack('<I', row['native_callback_lookup_key_u32']))
    return digest.hexdigest()


def make_native(image):
    emulator, context = make_emulator(image)
    captured = []

    def capture_lookup(uc, _address, _size, _user_data):
        captured.append(uc.reg_read(UC_X86_REG_RDX) & 0xffffffff)
        uc.reg_write(UC_X86_REG_RIP, exact.RETURN_ADDRESS)

    emulator.emulator.hook_add(
        UC_HOOK_CODE, capture_lookup,
        begin=IMAGE_BASE + LOOKUP_CALLSITE_RVA,
        end=IMAGE_BASE + LOOKUP_CALLSITE_RVA)
    return emulator, context, captured


def decode_one(emulator, context, captured, raw_param, payload):
    context['raw_param'] = raw_param
    native = emulator.decode(payload, PROFILE)
    if (native['deserialize_return_al'] != 1 or not native['fully_consumed']
            or native['bytes_consumed'] != len(payload)):
        raise ValueError('native reader did not fully consume packet')
    obj = bytes.fromhex(native['object_hex'])
    if (struct.unpack_from('<Q', obj)[0] != IMAGE_BASE + VTABLE_RVA
            or struct.unpack_from('<H', obj, 8)[0] != PACKET_ID
            or struct.unpack_from('<I', obj, 0x0c)[0] != raw_param):
        raise ValueError('native object identity differs from Replay packet')
    protected = obj[0x10]
    captured.clear()
    emulator.call(IMAGE_BASE + CALLBACK_RVA,
                  rcx=exact.BUSINESS_OBJECT_ADDRESS,
                  rdx=exact.OBJECT_ADDRESS)
    if captured != [decode_lookup_key(protected)]:
        raise ValueError('native callback key differs from packet object')
    return {
        'native_protected_lookup_byte_hex': f'{protected:02x}',
        'native_callback_lookup_key_u32': captured[0],
        'raw_payload_sha256': hashlib.sha256(payload).hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True, type=Path)
    options = parser.parse_args()
    packets = read_request()
    image, image_sha = read_image(options.image)
    emulator, context, captured = make_native(image)
    rows = []
    first_failure = None
    for index, (raw_param, payload) in enumerate(packets):
        try:
            rows.append(decode_one(emulator, context, captured, raw_param, payload))
        except Exception as error:
            first_failure = {'index': index,
                             'reason': f'{type(error).__name__}: {error}'}
            break
    print(json.dumps({
        'replay_version': BUILD,
        'runtime_image_sha256': image_sha,
        'packet_id': PACKET_ID,
        'packet_count': len(packets),
        'input_sha256': input_hash(packets),
        'native_output_sha256': output_hash(rows) if first_failure is None else None,
        'native_full_success_count': len(rows),
        'first_failure': first_failure,
        'rows': rows if first_failure is None else [],
    }, separators=(',', ':')))
    return 0 if first_failure is None else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f'821 cooldown native witness error: {error}', file=sys.stderr)
        raise SystemExit(1)

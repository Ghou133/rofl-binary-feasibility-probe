#!/usr/bin/env python3
"""Exact KR 821 packet-local callback lookup witness for route 0x013f.

The receiver lookup is deliberately forced to miss. Its observed key is a
native packet field, not an item, group identity, owner, or applied state.
"""

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RDX

import emulate_exact_packet_decoder as exact
from decode_broadcast_inventory_16_19_821 import make_emulator


BUILD = '16.19.821.7343'
IMAGE_BASE = 0x7ff67f410000
IMAGE_SIZE = 48_488_448
IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325'
PACKET_ID = 0x013f
FACTORY_TABLE_RVA = 0xf0e4bc
FACTORY_CASE_RVA = 0xf0214f
CONSTRUCTOR_RVA = 0xebdd70
VTABLE_RVA = 0x1ba5a40
DESERIALIZER_RVA = 0x10425b0
NESTED_VTABLE_RVA = 0x1ba5a18
NESTED_DESERIALIZER_RVA = 0x1041d90
REGISTRATION_ID_RVA = 0x323fc9
CALLBACK_THUNK_RVA = 0x3505f0
CALLBACK_RVA = 0x350440
LOOKUP_RVA = 0x5d3bd0
TRANSFORM_TABLE_RVA = 0x1ac5610
TRANSFORM_TABLE_SHA256 = '328528d693ab5d96a815b6706694025a980e609019304aeb2e5e32797011c04b'
TRANSFORM_SHA256 = '61f9f62e7192a413310d9d7ed4367cfa0cfabad1c194a1c09428b1833e69a046'
PROFILE = {'constructor_rva': CONSTRUCTOR_RVA,
           'deserialize_rva': DESERIALIZER_RVA,
           'object_size': 0x28, 'fields': []}
OBSERVED_SHAPES = frozenset({
    (7, 0x50), (7, 0x54), (7, 0x56),
    (8, 0x50), (8, 0x51), (8, 0x52), (8, 0x53),
    (8, 0x54), (8, 0x55), (8, 0x56), (8, 0x57),
    (9, 0x51), (9, 0x52), (9, 0x55), (9, 0x57),
})
RAW_PARAMS = frozenset(range(0x400000ae, 0x400000b8))
MAX_REQUEST_BYTES = 512 * 1024
MAX_PACKETS = 10_000


def ror8(value, count):
    return ((value >> count) | (value << (8 - count))) & 0xff


def transform_table(image):
    raw = image[TRANSFORM_TABLE_RVA:TRANSFORM_TABLE_RVA + 256]
    if len(raw) != 256 or hashlib.sha256(raw).hexdigest() != TRANSFORM_TABLE_SHA256:
        raise ValueError('exact 821 callback table differs')
    decoded = bytes((~ror8((raw[(~ror8((byte - 0x7e) & 0xff, 6)) & 0xff]
                           + 0x78) & 0xff, 5)) & 0xff for byte in range(256))
    if (hashlib.sha256(decoded).hexdigest() != TRANSFORM_SHA256
            or len(set(decoded)) != 256):
        raise ValueError('exact 821 callback byte transform differs')
    return decoded


def read_image(path):
    if not path.is_file() or path.stat().st_size != IMAGE_SIZE:
        raise ValueError('exact 821 runtime image is missing or has the wrong size')
    image = path.read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    if digest != IMAGE_SHA256:
        raise ValueError(f'exact 821 runtime image SHA-256 mismatch: {digest}')
    if (struct.unpack_from('<I', image, FACTORY_TABLE_RVA + PACKET_ID * 4)[0]
            != FACTORY_CASE_RVA
            or image[CONSTRUCTOR_RVA + 0x11:CONSTRUCTOR_RVA + 0x13]
            != struct.pack('<H', PACKET_ID)
            or struct.unpack_from('<Q', image, VTABLE_RVA + 8)[0]
            != IMAGE_BASE + DESERIALIZER_RVA
            or struct.unpack_from('<Q', image, NESTED_VTABLE_RVA + 8)[0]
            != IMAGE_BASE + NESTED_DESERIALIZER_RVA
            or image[REGISTRATION_ID_RVA:REGISTRATION_ID_RVA + 6]
            != b'\x41\xb8\x3f\x01\x00\x00'
            or image[CALLBACK_THUNK_RVA:CALLBACK_THUNK_RVA + 4]
            != b'\x48\x83\xc2\x10'
            or image[CALLBACK_THUNK_RVA + 4] != 0xe9
            or CALLBACK_THUNK_RVA + 9
            + struct.unpack_from('<i', image, CALLBACK_THUNK_RVA + 5)[0]
            != CALLBACK_RVA):
        raise ValueError('exact 821 factory, native reader, or callback route differs')
    # This registered closure's captured RTTI names both its receiver and
    # packet class. A name alone does not establish a replay-side item state.
    closure_vtable = 0x1acfb88
    type_function = struct.unpack_from('<Q', image, closure_vtable + 0x18)[0] - IMAGE_BASE
    if image[type_function:type_function + 3] != b'\x48\x8d\x05':
        raise ValueError('exact 821 item-group closure type route differs')
    descriptor = type_function + 7 + struct.unpack_from('<i', image, type_function + 3)[0]
    name = image[descriptor + 16:descriptor + 256]
    if (b'HeroInventoryClient' not in name
            or b'PKT_S2C_SetItemGroupData_Broadcast_s' not in name):
        raise ValueError('exact 821 item-group registered type differs')
    return image, digest, transform_table(image)


def read_request():
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError('native request exceeds 512 KiB')
    request = json.loads(raw)
    if (not isinstance(request, dict) or request.get('replay_version') != BUILD
            or request.get('packet_id') != PACKET_ID
            or request.get('stream_tag') != 2):
        raise ValueError('native request requires exact build, route, and keyframe')
    source = request.get('packets')
    if not isinstance(source, list) or not 0 < len(source) <= MAX_PACKETS:
        raise ValueError('native packets must contain 1..10000 rows')
    packets = []
    for entry in source:
        if not isinstance(entry, list) or len(entry) != 2:
            raise ValueError('packet must be [raw_param, payload_hex]')
        raw_param, payload_hex = entry
        if type(raw_param) is not int or raw_param not in RAW_PARAMS:
            raise ValueError('raw parameter differs from the observed 821 keyframe family')
        if not isinstance(payload_hex, str) or len(payload_hex) % 2:
            raise ValueError('payload must be even-length hexadecimal text')
        payload = bytes.fromhex(payload_hex)
        if ((len(payload), payload[1] if len(payload) > 1 else -1)
                not in OBSERVED_SHAPES or payload[0] != 0x1e):
            raise ValueError('payload differs from observed exact-build shapes')
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
        digest.update(bytes.fromhex(row['native_protected_lookup_bytes_hex']))
        digest.update(struct.pack('<I', row['native_callback_lookup_key_u32']))
    return digest.hexdigest()


def make_native(image):
    emulator, context = make_emulator(image)
    captured = []

    def lookup_miss(uc, _address, _size, _user_data):
        captured.append(uc.reg_read(UC_X86_REG_RDX) & 0xffffffff)
        uc.reg_write(UC_X86_REG_RAX, 0)
        emulator._return_from_stub()

    emulator.emulator.hook_add(
        UC_HOOK_CODE, lookup_miss,
        begin=IMAGE_BASE + LOOKUP_RVA, end=IMAGE_BASE + LOOKUP_RVA)
    return emulator, context, captured


def decode_one(emulator, context, captured, transform, raw_param, payload):
    context['raw_param'] = raw_param
    native = emulator.decode(payload, PROFILE)
    if (native['deserialize_return_al'] != 1 or not native['fully_consumed']
            or native['bytes_consumed'] != len(payload)):
        raise ValueError('native reader did not fully consume packet')
    obj = bytes.fromhex(native['object_hex'])
    if (struct.unpack_from('<Q', obj)[0] != IMAGE_BASE + VTABLE_RVA
            or struct.unpack_from('<H', obj, 8)[0] != PACKET_ID
            or struct.unpack_from('<I', obj, 0x0c)[0] != raw_param
            or struct.unpack_from('<Q', obj, 0x10)[0]
            != IMAGE_BASE + NESTED_VTABLE_RVA):
        raise ValueError('native object identity differs from the Replay packet')
    protected = obj[0x20:0x24]
    decoded = struct.unpack('<I', bytes(transform[byte] for byte in protected))[0]
    captured.clear()
    # The exact callback transforms +0x20 and forwards it to this lookup.
    # The captured image contains no live receiver map, so the lookup is
    # synthetic and its miss does not prove the callback effect.
    emulator.call(IMAGE_BASE + CALLBACK_RVA,
                  rcx=exact.BUSINESS_OBJECT_ADDRESS,
                  rdx=exact.OBJECT_ADDRESS + 0x10)
    if captured != [decoded]:
        raise ValueError('native callback lookup key differs from packet transform')
    return {
        'native_protected_lookup_bytes_hex': protected.hex(),
        'native_callback_lookup_key_u32': decoded,
        'raw_payload_sha256': hashlib.sha256(payload).hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True, type=Path)
    options = parser.parse_args()
    packets = read_request()
    image, image_sha, transform = read_image(options.image)
    emulator, context, captured = make_native(image)
    rows = []
    first_failure = None
    for index, (raw_param, payload) in enumerate(packets):
        try:
            rows.append(decode_one(emulator, context, captured, transform,
                                   raw_param, payload))
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
        print(f'821 item-group native witness error: {error}', file=sys.stderr)
        raise SystemExit(1)

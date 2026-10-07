#!/usr/bin/env python3
"""Exact KR 821 packet-local callback witness for route 0x0437.

Executes the native callback's range check and stops before its receiver method.
Packet-local call arguments do not establish item identity or applied state.
"""

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

from unicorn import UC_HOOK_CODE
from unicorn.x86_const import (UC_X86_REG_R8, UC_X86_REG_RCX, UC_X86_REG_RDX,
                               UC_X86_REG_RIP)

import emulate_exact_packet_decoder as exact
from decode_broadcast_inventory_16_19_821 import make_emulator


BUILD = '16.19.821.7343'
IMAGE_BASE = 0x7ff67f410000
IMAGE_SIZE = 48_488_448
IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325'
PACKET_ID = 0x0437
FACTORY_TABLE_RVA = 0xf0e4bc
FACTORY_CASE_RVA = 0xf0bb2a
CONSTRUCTOR_RVA = 0xebda80
VTABLE_RVA = 0x1ba5868
DESERIALIZER_RVA = 0x1041380
REGISTRATION_RVA = 0x3246d7
CLOSURE_VTABLE_RVA = 0x1acfdf8
TYPE_FUNCTION_RVA = 0x36cb70
CALLBACK_RVA = 0x350250
FIRST_CALL_RVA = 0x35028e
FIRST_TARGET_RVA = 0x2af490
SECOND_CALL_RVA = 0x350310
SECOND_TARGET_RVA = 0x292770
CALLBACK_CODE_SHA256 = 'c34dee97cf2c91cbf31fceb8b9b68a8d14be2a67bc8d796c4ace3daf6a825774'
TABLE_RVA = 0x1ac5610
TABLE_SHA256 = '328528d693ab5d96a815b6706694025a980e609019304aeb2e5e32797011c04b'
SELECTOR_TRANSFORM_SHA256 = '61f9f62e7192a413310d9d7ed4367cfa0cfabad1c194a1c09428b1833e69a046'
VALUE_BYTE_TRANSFORM_SHA256 = '44dee3eddb30902944dade859ea00c11fb6df5699cf2baad986e6c17d54e7a13'
PROFILE = {'constructor_rva': CONSTRUCTOR_RVA,
           'deserialize_rva': DESERIALIZER_RVA,
           'object_size': 0x14, 'fields': []}
OBSERVED_LENGTHS = frozenset({1, 2, 3, 4})
MAX_REQUEST_BYTES = 512 * 1024
MAX_PACKETS = 10_000


def ror8(value, count):
    return ((value >> count) | (value << (8 - count))) & 0xff


def rol8(value, count):
    return ((value << count) | (value >> (8 - count))) & 0xff


def rip_target(image, rva):
    if image[rva:rva + 3] != b'\x48\x8d\x05':
        raise ValueError(f'exact 821 RIP-relative LEA differs at {rva:#x}')
    return rva + 7 + struct.unpack_from('<i', image, rva + 3)[0]


def call_target(image, rva):
    if image[rva] != 0xe8:
        raise ValueError(f'exact 821 direct call differs at {rva:#x}')
    return rva + 5 + struct.unpack_from('<i', image, rva + 1)[0]


def transforms(image):
    table = image[TABLE_RVA:TABLE_RVA + 256]
    if len(table) != 256 or hashlib.sha256(table).hexdigest() != TABLE_SHA256:
        raise ValueError('exact 821 callback table differs')
    selector = bytes((~ror8((table[(~ror8((byte - 0x7e) & 0xff, 6)) & 0xff]
                             + 0x78) & 0xff, 5)) & 0xff for byte in range(256))
    value_byte = bytes(table[(table[table[rol8((~byte) & 0xff, 2)]] - 0x1b)
                              & 0xff] for byte in range(256))
    if (hashlib.sha256(selector).hexdigest() != SELECTOR_TRANSFORM_SHA256
            or hashlib.sha256(value_byte).hexdigest() != VALUE_BYTE_TRANSFORM_SHA256
            or len(set(selector)) != 256 or len(set(value_byte)) != 256):
        raise ValueError('exact 821 callback transforms differ')
    return selector, value_byte


def read_image(path):
    if not path.is_file() or path.stat().st_size != IMAGE_SIZE:
        raise ValueError('exact 821 runtime image is missing or has the wrong size')
    image = path.read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    if digest != IMAGE_SHA256:
        raise ValueError(f'exact 821 runtime image SHA-256 mismatch: {digest}')
    if (struct.unpack_from('<I', image, FACTORY_TABLE_RVA + PACKET_ID * 4)[0]
            != FACTORY_CASE_RVA
            or image[FACTORY_CASE_RVA:FACTORY_CASE_RVA + 5]
            != b'\xb9\x14\x00\x00\x00'
            or call_target(image, FACTORY_CASE_RVA + 0x12) != CONSTRUCTOR_RVA
            or image[CONSTRUCTOR_RVA + 7:CONSTRUCTOR_RVA + 13]
            != b'\x66\xc7\x41\x08\x37\x04'
            or rip_target(image, CONSTRUCTOR_RVA + 0x28) != VTABLE_RVA
            or struct.unpack_from('<Q', image, VTABLE_RVA + 8)[0]
            != IMAGE_BASE + DESERIALIZER_RVA
            or image[REGISTRATION_RVA:REGISTRATION_RVA + 6]
            != b'\x41\xb8\x37\x04\x00\x00'
            or rip_target(image, 0x324690) != CLOSURE_VTABLE_RVA
            or rip_target(image, 0x3246aa) != CALLBACK_RVA
            or struct.unpack_from('<Q', image, CLOSURE_VTABLE_RVA + 0x18)[0]
            != IMAGE_BASE + TYPE_FUNCTION_RVA
            or call_target(image, FIRST_CALL_RVA) != FIRST_TARGET_RVA
            or call_target(image, SECOND_CALL_RVA) != SECOND_TARGET_RVA
            or image[FIRST_TARGET_RVA:FIRST_TARGET_RVA + 7]
            != bytes.fromhex('83fa260f96c0c3')
            or hashlib.sha256(image[CALLBACK_RVA:CALLBACK_RVA + 0xd7]).hexdigest()
            != CALLBACK_CODE_SHA256):
        raise ValueError('exact 821 factory, native reader, or callback differs')
    descriptor = rip_target(image, TYPE_FUNCTION_RVA)
    name = image[descriptor + 16:descriptor + 256].split(b'\x00')[0]
    if (b'HeroInventoryClient' not in name
            or b'PKT_S2C_SetItemCharges_s' not in name):
        raise ValueError('exact 821 registered callback RTTI differs')
    return image, digest, transforms(image)


def read_request():
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError('native request exceeds 512 KiB')
    request = json.loads(raw)
    if (not isinstance(request, dict) or request.get('replay_version') != BUILD
            or request.get('packet_id') != PACKET_ID
            or request.get('stream_tag') != 1):
        raise ValueError('native request requires exact build, route, and game chunk')
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
        digest.update(bytes.fromhex(row['native_protected_callback_bytes_hex']))
        digest.update(struct.pack('<I', row['native_callback_selector_u8']))
        digest.update(struct.pack('<H', row['native_callback_value_u16']))
    return digest.hexdigest()


def make_native(image):
    emulator, context = make_emulator(image)
    captured = {'first': [], 'second': []}

    def observe_range_check(uc, _address, _size, _user_data):
        captured['first'].append((uc.reg_read(UC_X86_REG_RCX),
                                  uc.reg_read(UC_X86_REG_RDX)))
        # The exact image's cmp/setbe/ret executes normally.

    def before_receiver_call(uc, _address, _size, _user_data):
        captured['second'].append((uc.reg_read(UC_X86_REG_RCX),
                                   uc.reg_read(UC_X86_REG_RDX),
                                   uc.reg_read(UC_X86_REG_R8)))
        # Stop at the callsite; receiver object/state is not in the image.
        uc.reg_write(UC_X86_REG_RIP, exact.RETURN_ADDRESS)

    emulator.emulator.hook_add(
        UC_HOOK_CODE, observe_range_check,
        begin=IMAGE_BASE + FIRST_CALL_RVA,
        end=IMAGE_BASE + FIRST_CALL_RVA)
    emulator.emulator.hook_add(
        UC_HOOK_CODE, before_receiver_call,
        begin=IMAGE_BASE + SECOND_CALL_RVA,
        end=IMAGE_BASE + SECOND_CALL_RVA)
    return emulator, context, captured


def decode_one(emulator, context, captured, transforms_pair, raw_param, payload):
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
    protected = obj[0x10:0x14]
    captured['first'].clear()
    captured['second'].clear()
    emulator.call(IMAGE_BASE + CALLBACK_RVA,
                  rcx=exact.BUSINESS_OBJECT_ADDRESS,
                  rdx=exact.OBJECT_ADDRESS)
    if len(captured['first']) != 1 or len(captured['second']) != 1:
        raise ValueError('native callback range check did not reach receiver callsite')
    first_receiver, selector = captured['first'][0]
    second_receiver, second_selector, value = captured['second'][0]
    selector_transform, value_byte_transform = transforms_pair
    expected_selector = selector_transform[protected[2]]
    expected_value = value_byte_transform[protected[0]] \
        | (value_byte_transform[protected[1]] << 8)
    if (first_receiver != exact.BUSINESS_OBJECT_ADDRESS
            or second_receiver != exact.BUSINESS_OBJECT_ADDRESS
            or selector != second_selector or selector != expected_selector
            or value != expected_value or selector > 0x26):
        raise ValueError('native callback arguments differ from protected object bytes')
    return {
        'native_protected_callback_bytes_hex': protected.hex(),
        'native_callback_selector_u8': selector,
        'native_callback_value_u16': value,
        'raw_payload_sha256': hashlib.sha256(payload).hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True, type=Path)
    options = parser.parse_args()
    packets = read_request()
    image, image_sha, transforms_pair = read_image(options.image)
    emulator, context, captured = make_native(image)
    rows = []
    first_failure = None
    for index, (raw_param, payload) in enumerate(packets):
        try:
            rows.append(decode_one(emulator, context, captured, transforms_pair,
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
        print(f'821 item charges native witness error: {error}', file=sys.stderr)
        raise SystemExit(1)

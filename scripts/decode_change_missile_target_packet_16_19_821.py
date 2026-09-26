#!/usr/bin/env python3
"""Exact KR 821 ChangeMissileTarget packet-local callback comparison witness.

The callback stops before comparing with a synthetic receiver. Live receiver
state, missile identity, target and effect are not observed.
"""

import argparse
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_RBX, UC_X86_REG_RIP

import emulate_exact_packet_decoder as exact
from decode_mapview_inventory_16_19_821 import make_emulator


BUILD = '16.19.821.7343'
IMAGE_BASE = 0x7ff67f410000
IMAGE_SIZE = 48_488_448
IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325'
PACKET_ID = 0x040c
FACTORY_TABLE_RVA = 0xf0e4bc
FACTORY_CASE_RVA = 0xf0b2cf
CONSTRUCTOR_RVA = 0xea4f10
VTABLE_RVA = 0x1ba8fc8
DESERIALIZER_RVA = 0x10e8e30
REGISTRATION_ID_RVA = 0x991d92
REGISTRATION_VTABLE_LEA_RVA = 0x991d51
REGISTRATION_CALLBACK_LEA_RVA = 0x991d67
CLOSURE_VTABLE_RVA = 0x1b4dda0
TYPE_FUNCTION_RVA = 0x9a5fc0
TYPE_DESCRIPTOR_RVA = 0x1f7a3a0
CALLBACK_RVA = 0x997c80
CALLBACK_END_RVA = 0x997d03
CALLBACK_PRE_COMPARE_RVA = 0x997cd0
CALLBACK_CODE_SHA256 = '01b66ec7e01cf1c2342d592aa228dea8036379ae24ee31e0b5308289564e644d'
PROFILE = {'constructor_rva': CONSTRUCTOR_RVA,
           'deserialize_rva': DESERIALIZER_RVA,
           'object_size': 0x20, 'fields': []}
SHORT_PREFIXES = frozenset({0x91, 0x93, 0x95, 0x99, 0x9d, 0x9f})
MAX_REQUEST_BYTES = 512 * 1024
MAX_PACKETS = 10_000


def rip_target(image, rva):
    if image[rva:rva + 3] != b'\x48\x8d\x05':
        raise ValueError(f'exact 821 RIP-relative instruction differs at {rva:#x}')
    return rva + 7 + struct.unpack_from('<i', image, rva + 3)[0]


def call_target(image, rva):
    if image[rva] != 0xe8:
        raise ValueError(f'exact 821 direct call differs at {rva:#x}')
    return rva + 5 + struct.unpack_from('<i', image, rva + 1)[0]


def ror8(value, amount):
    return ((value >> amount) | (value << (8 - amount))) & 255


def decode_comparison_key(protected):
    if len(protected) != 4:
        raise ValueError('expected four protected bytes')
    return struct.unpack('<I', bytes(
        (ror8((ror8(value, 6) - 0x56) & 255, 3) - 0x3a) & 255
        for value in protected))[0]


def observed_payload(payload):
    return ((len(payload) == 13 and payload[0] == 0x96)
            or (len(payload) in (3, 4) and payload[0] in SHORT_PREFIXES))


def read_image(path):
    if not path.is_file() or path.stat().st_size != IMAGE_SIZE:
        raise ValueError('exact 821 runtime image is missing or has the wrong size')
    image = path.read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    if digest != IMAGE_SHA256:
        raise ValueError(f'exact 821 runtime image SHA-256 mismatch: {digest}')
    if (struct.unpack_from('<I', image, FACTORY_TABLE_RVA + PACKET_ID * 4)[0]
            != FACTORY_CASE_RVA
            or call_target(image, FACTORY_CASE_RVA + 0x12) != CONSTRUCTOR_RVA
            or image[CONSTRUCTOR_RVA + 4:CONSTRUCTOR_RVA + 10]
            != bytes.fromhex('66c741080c04')
            or rip_target(image, CONSTRUCTOR_RVA + 0x27) != VTABLE_RVA
            or struct.unpack_from('<Q', image, VTABLE_RVA + 8)[0]
            != IMAGE_BASE + DESERIALIZER_RVA
            or image[REGISTRATION_ID_RVA:REGISTRATION_ID_RVA + 6]
            != bytes.fromhex('41b80c040000')
            or rip_target(image, REGISTRATION_VTABLE_LEA_RVA)
            != CLOSURE_VTABLE_RVA
            or rip_target(image, REGISTRATION_CALLBACK_LEA_RVA)
            != CALLBACK_RVA
            or struct.unpack_from('<Q', image, CLOSURE_VTABLE_RVA + 0x18)[0]
            != IMAGE_BASE + TYPE_FUNCTION_RVA
            or rip_target(image, TYPE_FUNCTION_RVA) != TYPE_DESCRIPTOR_RVA
            or hashlib.sha256(image[CALLBACK_RVA:CALLBACK_END_RVA]).hexdigest()
            != CALLBACK_CODE_SHA256):
        raise ValueError('exact 821 factory, registration or callback route differs')
    name = image[TYPE_DESCRIPTOR_RVA + 16:TYPE_DESCRIPTOR_RVA + 300].split(b'\x00')[0]
    if b'MissileClient' not in name or b'PKT_S2C_ChangeMissileTarget_s' not in name:
        raise ValueError('exact 821 callback RTTI name differs')
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
        if not isinstance(payload_hex, str) or not re.fullmatch(r'(?:[0-9a-f]{2})+', payload_hex):
            raise ValueError('payload must be even-length hexadecimal text')
        payload = bytes.fromhex(payload_hex)
        if not observed_payload(payload):
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
        digest.update(bytes.fromhex(row['native_protected_comparison_bytes_hex']))
        digest.update(struct.pack('<I', row['native_callback_comparison_key_u32']))
    return digest.hexdigest()


def make_native(image):
    emulator, context = make_emulator(image)
    witness = []

    def before_compare(uc, _address, _size, _data):
        witness.append(uc.reg_read(UC_X86_REG_RBX) & 0xffffffff)
        uc.reg_write(UC_X86_REG_RIP, exact.RETURN_ADDRESS)

    emulator.emulator.hook_add(UC_HOOK_CODE, before_compare,
        begin=IMAGE_BASE + CALLBACK_PRE_COMPARE_RVA,
        end=IMAGE_BASE + CALLBACK_PRE_COMPARE_RVA)
    return emulator, context, witness


def decode_one(emulator, context, witness, raw_param, payload):
    context['raw_param'] = raw_param
    native = emulator.decode(payload, PROFILE)
    if (native['deserialize_return_al'] != 1 or not native['fully_consumed']
            or native['bytes_consumed'] != len(payload)):
        raise ValueError('native deserializer did not fully consume packet')
    obj = bytes.fromhex(native['object_hex'])
    if (len(obj) != 0x20
            or struct.unpack_from('<Q', obj)[0] != IMAGE_BASE + VTABLE_RVA
            or struct.unpack_from('<H', obj, 8)[0] != PACKET_ID
            or struct.unpack_from('<I', obj, 0x0c)[0] != raw_param):
        raise ValueError('native object identity differs from Replay packet')
    protected = obj[0x1c:0x20]
    expected = decode_comparison_key(protected)
    witness.clear()
    emulator.emulator.mem_write(exact.BUSINESS_OBJECT_ADDRESS + 0x438,
                                struct.pack('<Q', exact.BUSINESS_OBJECT_ADDRESS + 0x800))
    emulator.call(IMAGE_BASE + CALLBACK_RVA,
                  rcx=exact.BUSINESS_OBJECT_ADDRESS,
                  rdx=exact.OBJECT_ADDRESS)
    if witness != [expected]:
        raise ValueError('native callback pre-compare key differs from packet-local inverse')
    return {
        'native_protected_comparison_bytes_hex': protected.hex(),
        'native_callback_comparison_key_u32': expected,
        'native_callback_witness_status': 'SYNTHETIC_RECEIVER_PRE_COMPARE',
        'raw_payload_sha256': hashlib.sha256(payload).hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True, type=Path)
    options = parser.parse_args()
    packets = read_request()
    image, image_sha = read_image(options.image)
    emulator, context, witness = make_native(image)
    rows = []
    first_failure = None
    for index, (raw_param, payload) in enumerate(packets):
        try:
            rows.append(decode_one(emulator, context, witness, raw_param, payload))
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
        print(f'821 ChangeMissileTarget native witness error: {error}', file=sys.stderr)
        raise SystemExit(1)

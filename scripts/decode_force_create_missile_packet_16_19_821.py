#!/usr/bin/env python3
"""Exact KR 821 0x0087 packet-local callback comparison witness.

A synthetic receiver advances native callback execution only to the comparison.
No live receiver lookup, missile creation or gameplay effect is observed.
"""
import argparse
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RDX, UC_X86_REG_RIP, UC_X86_REG_RSP

import emulate_exact_packet_decoder as exact
from decode_mapview_inventory_16_19_821 import make_emulator

BUILD = '16.19.821.7343'
IMAGE_BASE = 0x7ff67f410000
IMAGE_SIZE = 48_488_448
IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325'
PACKET_ID = 0x0087
FACTORY_TABLE_RVA = 0xf0e4bc
FACTORY_CASE_RVA = 0xeffb9f
CONSTRUCTOR_RVA = 0xeac850
VTABLE_RVA = 0x1ba8f98
DESERIALIZER_RVA = 0x10f0690
REGISTRATION_ID_RVA = 0x2619f5
REGISTRATION_MANAGER_LEA_RVA = 0x261999
REGISTRATION_CALLBACK_LEA_RVA = 0x2619b5
MANAGER_TABLE_RVA = 0x1ac2510
TYPE_FUNCTION_RVA = 0x303ad0
TYPE_DESCRIPTOR_RVA = 0x1f2abe0
CALLBACK_RVA = 0x2bf6d0
CALLBACK_END_RVA = 0x2bf7e8
CALLBACK_CODE_SHA256 = 'ebc9cedb7234d33849b33b38106ef438f8c70db3fa9ea70a9610c62b1cf2311d'
CALLBACK_SHARED_LOOKUP_RVA = 0x98b410
CALLBACK_RECEIVER_ACCESS_RVA = 0x21d780
CALLBACK_ACTION_RVA = 0x985630
CALLBACK_PRE_COMPARE_RVA = 0x2bf790
PROFILE = {'constructor_rva': CONSTRUCTOR_RVA,
           'deserialize_rva': DESERIALIZER_RVA,
           'object_size': 0x14, 'fields': []}
OBSERVED_PREFIXES = frozenset({0xf0, 0xf1, 0xf2, 0xf4, 0xf6, 0xf7})
MAX_REQUEST_BYTES = 512 * 1024
MAX_PACKETS = 10_000
FAKE_RECEIVER = exact.WORK_BASE + 0xa000
FAKE_CONTROL = exact.WORK_BASE + 0xb000
FAKE_TARGET = exact.WORK_BASE + 0xc000


def rip_target(image, rva):
    if image[rva:rva + 3] != b'\x48\x8d\x05':
        raise ValueError('exact 821 RIP-relative route differs')
    return rva + 7 + struct.unpack_from('<i', image, rva + 3)[0]


def call_target(image, rva):
    if image[rva] != 0xe8:
        raise ValueError('exact 821 direct call differs')
    return rva + 5 + struct.unpack_from('<i', image, rva + 1)[0]


def ror8(value, amount):
    return ((value >> amount) | (value << (8 - amount))) & 255


def decode_comparison_bytes(protected):
    if len(protected) != 4:
        raise ValueError('expected four protected bytes')
    decoded = bytes((ror8((ror8(value, 6) - 0x56) & 255, 3) - 0x3a) & 255
                    for value in protected)
    return struct.unpack('<I', decoded)[0]


def observed_payload(payload):
    return len(payload) in (3, 4) and payload[0] in OBSERVED_PREFIXES


def read_image(path):
    if not path.is_file() or path.stat().st_size != IMAGE_SIZE:
        raise ValueError('exact 821 runtime image is missing or has the wrong size')
    image = path.read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    if digest != IMAGE_SHA256:
        raise ValueError(f'exact 821 runtime image SHA-256 mismatch: {digest}')
    if (struct.unpack_from('<I', image, FACTORY_TABLE_RVA + PACKET_ID * 4)[0]
            != FACTORY_CASE_RVA
            or call_target(image, FACTORY_CASE_RVA + 0x14) != CONSTRUCTOR_RVA
            or image[CONSTRUCTOR_RVA + 7:CONSTRUCTOR_RVA + 13]
            != bytes.fromhex('66c741088700')
            or rip_target(image, CONSTRUCTOR_RVA + 0x1c) != VTABLE_RVA
            or struct.unpack_from('<Q', image, VTABLE_RVA + 8)[0]
            != IMAGE_BASE + DESERIALIZER_RVA
            or image[REGISTRATION_ID_RVA:REGISTRATION_ID_RVA + 6]
            != bytes.fromhex('41b887000000')
            or rip_target(image, REGISTRATION_MANAGER_LEA_RVA) != MANAGER_TABLE_RVA
            or rip_target(image, REGISTRATION_CALLBACK_LEA_RVA) != CALLBACK_RVA
            or struct.unpack_from('<Q', image, MANAGER_TABLE_RVA + 0x18)[0]
            != IMAGE_BASE + TYPE_FUNCTION_RVA
            or rip_target(image, TYPE_FUNCTION_RVA) != TYPE_DESCRIPTOR_RVA
            or call_target(image, CALLBACK_RVA + 0x23) != CALLBACK_SHARED_LOOKUP_RVA
            or call_target(image, CALLBACK_RVA + 0x81) != CALLBACK_RECEIVER_ACCESS_RVA
            or call_target(image, CALLBACK_RVA + 0xd0) != CALLBACK_ACTION_RVA):
        raise ValueError('exact 821 factory, registration, or callback route differs')
    name = image[TYPE_DESCRIPTOR_RVA + 16:TYPE_DESCRIPTOR_RVA + 300].split(b'\x00')[0]
    if b'AIBaseClient' not in name or b'PKT_S2C_ForceCreateMissile_s' not in name:
        raise ValueError('exact 821 callback RTTI name differs')
    if hashlib.sha256(image[CALLBACK_RVA:CALLBACK_END_RVA]).hexdigest() != CALLBACK_CODE_SHA256:
        raise ValueError('exact 821 callback code differs')
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
    witness = {'shared_calls': 0, 'receiver_calls': 0, 'transformed': []}

    def shared(uc, _address, _size, _data):
        destination = uc.reg_read(UC_X86_REG_RDX)
        uc.mem_write(destination, struct.pack('<QQ', FAKE_RECEIVER, FAKE_CONTROL))
        uc.reg_write(UC_X86_REG_RAX, destination)
        witness['shared_calls'] += 1
        emulator._return_from_stub()

    def receiver(uc, _address, _size, _data):
        witness['receiver_calls'] += 1
        uc.reg_write(UC_X86_REG_RAX, FAKE_TARGET)
        emulator._return_from_stub()

    def before_compare(uc, _address, _size, _data):
        stack = uc.reg_read(UC_X86_REG_RSP)
        witness['transformed'].append(bytes(uc.mem_read(stack + 0x20, 4)))
        uc.reg_write(UC_X86_REG_RIP, exact.RETURN_ADDRESS)

    emulator.emulator.hook_add(UC_HOOK_CODE, shared,
        begin=IMAGE_BASE + CALLBACK_SHARED_LOOKUP_RVA,
        end=IMAGE_BASE + CALLBACK_SHARED_LOOKUP_RVA)
    emulator.emulator.hook_add(UC_HOOK_CODE, receiver,
        begin=IMAGE_BASE + CALLBACK_RECEIVER_ACCESS_RVA,
        end=IMAGE_BASE + CALLBACK_RECEIVER_ACCESS_RVA)
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
    if (len(obj) != 0x14
            or struct.unpack_from('<Q', obj)[0] != IMAGE_BASE + VTABLE_RVA
            or struct.unpack_from('<H', obj, 8)[0] != PACKET_ID
            or struct.unpack_from('<I', obj, 0x0c)[0] != raw_param):
        raise ValueError('native object identity differs from Replay packet')
    protected = obj[0x10:0x14]
    expected = decode_comparison_bytes(protected)
    witness.update(shared_calls=0, receiver_calls=0, transformed=[])
    emulator.emulator.mem_write(FAKE_CONTROL + 8, struct.pack('<II', 10, 10))
    emulator.call(IMAGE_BASE + CALLBACK_RVA,
                  rcx=exact.BUSINESS_OBJECT_ADDRESS,
                  rdx=exact.OBJECT_ADDRESS)
    if (witness['shared_calls'] != 1 or witness['receiver_calls'] != 1
            or len(witness['transformed']) != 1
            or struct.unpack('<I', witness['transformed'][0])[0] != expected):
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
        print(f'821 ForceCreateMissile native witness error: {error}', file=sys.stderr)
        raise SystemExit(1)

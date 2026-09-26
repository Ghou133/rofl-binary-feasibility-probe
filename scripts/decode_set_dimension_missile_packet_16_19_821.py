#!/usr/bin/env python3
"""Exact KR 821 SetDimensionMissile packet-local callback argument witness.

The callback stops before the receiver method. No live missile state or effect
is observed, even though the registered packet type has a suggestive name.
"""

import argparse
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_RDX, UC_X86_REG_RIP

import emulate_exact_packet_decoder as exact
from decode_mapview_inventory_16_19_821 import make_emulator


BUILD = '16.19.821.7343'
IMAGE_BASE = 0x7ff67f410000
IMAGE_SIZE = 48_488_448
IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325'
PACKET_ID = 0x008a
FACTORY_TABLE_RVA = 0xf0e4bc
FACTORY_CASE_RVA = 0xeffc77
CONSTRUCTOR_RVA = 0xeccbe0
VTABLE_RVA = 0x1ba92a8
DESERIALIZER_RVA = 0x111f960
REGISTRATION_ID_RVA = 0x9924a6
REGISTRATION_VTABLE_LEA_RVA = 0x99244d
REGISTRATION_CALLBACK_LEA_RVA = 0x992469
CLOSURE_VTABLE_RVA = 0x1b4dfb0
TYPE_FUNCTION_RVA = 0x9a6070
TYPE_DESCRIPTOR_RVA = 0x1f797e0
CALLBACK_RVA = 0x998520
CALLBACK_PRE_RECEIVER_RVA = 0x99855e
CALLBACK_END_RVA = 0x99856b
CALLBACK_CODE_SHA256 = '7225ed237639152471166a5926b22f5caf48d7c0a9ca848fc660f580ddec1aeb'
CALLBACK_TABLE_LEA_RVA = 0x998536
CALLBACK_TABLE_RVA = 0x1b49380
CALLBACK_TABLE_SHA256 = '328528d693ab5d96a815b6706694025a980e609019304aeb2e5e32797011c04b'
PROFILE = {'constructor_rva': CONSTRUCTOR_RVA,
           'deserialize_rva': DESERIALIZER_RVA,
           'object_size': 0x18, 'fields': []}
SHORT_PREFIXES = frozenset({0x45, 0x4d, 0x55, 0x65, 0x75, 0x7d})
LONG_PREFIXES = frozenset({0x40, 0x42, 0x44, 0x46, 0x48, 0x4a,
                           0x4c, 0x4e, 0x50, 0x52, 0x54, 0x56,
                           0x60, 0x62, 0x64, 0x66,
                           0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e})
MAX_REQUEST_BYTES = 512 * 1024
MAX_PACKETS = 10_000


def rip_target(image, rva, prefix):
    if image[rva:rva + 3] != prefix:
        raise ValueError(f'exact 821 RIP-relative instruction differs at {rva:#x}')
    return rva + 7 + struct.unpack_from('<i', image, rva + 3)[0]


def call_target(image, rva):
    if image[rva] != 0xe8:
        raise ValueError(f'exact 821 direct call differs at {rva:#x}')
    return rva + 5 + struct.unpack_from('<i', image, rva + 1)[0]


def ror8(value, amount):
    return ((value >> amount) | (value << (8 - amount))) & 255


def decode_callback_argument(protected_byte, table):
    value = (protected_byte + 0x34) & 255
    value = ((value << 4) | (value >> 4)) & 255
    value = table[value ^ 0x15]
    return table[(~ror8((value - 0x1f) & 255, 5)) & 255]


def observed_payload(payload):
    return ((len(payload) == 3 and payload[0] in SHORT_PREFIXES)
            or (len(payload) == 4
                and payload[0] in SHORT_PREFIXES | LONG_PREFIXES)
            or (len(payload) == 5 and payload[0] in LONG_PREFIXES))


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
            != bytes.fromhex('66c741088a00')
            or rip_target(image, CONSTRUCTOR_RVA + 0x1c, b'\x48\x8d\x05')
            != VTABLE_RVA
            or struct.unpack_from('<Q', image, VTABLE_RVA + 8)[0]
            != IMAGE_BASE + DESERIALIZER_RVA
            or image[REGISTRATION_ID_RVA:REGISTRATION_ID_RVA + 6]
            != bytes.fromhex('41b88a000000')
            or rip_target(image, REGISTRATION_VTABLE_LEA_RVA, b'\x48\x8d\x05')
            != CLOSURE_VTABLE_RVA
            or rip_target(image, REGISTRATION_CALLBACK_LEA_RVA, b'\x48\x8d\x05')
            != CALLBACK_RVA
            or struct.unpack_from('<Q', image, CLOSURE_VTABLE_RVA + 0x18)[0]
            != IMAGE_BASE + TYPE_FUNCTION_RVA
            or rip_target(image, TYPE_FUNCTION_RVA, b'\x48\x8d\x05')
            != TYPE_DESCRIPTOR_RVA
            or rip_target(image, CALLBACK_TABLE_LEA_RVA, b'\x48\x8d\x15')
            != CALLBACK_TABLE_RVA):
        raise ValueError('exact 821 factory, registration, callback or table route differs')
    name = image[TYPE_DESCRIPTOR_RVA + 16:TYPE_DESCRIPTOR_RVA + 300].split(b'\x00')[0]
    if b'MissileClient' not in name or b'PKT_SetDimensionMissile_s' not in name:
        raise ValueError('exact 821 callback RTTI name differs')
    table = image[CALLBACK_TABLE_RVA:CALLBACK_TABLE_RVA + 256]
    if (hashlib.sha256(table).hexdigest() != CALLBACK_TABLE_SHA256
            or hashlib.sha256(image[CALLBACK_RVA:CALLBACK_END_RVA]).hexdigest()
            != CALLBACK_CODE_SHA256):
        raise ValueError('exact 821 callback code or table differs')
    return image, digest, table


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
        digest.update(bytes.fromhex(row['native_protected_dimension_byte_hex']))
        digest.update(bytes([row['native_callback_argument_u8']]))
    return digest.hexdigest()


def make_native(image):
    emulator, context = make_emulator(image)
    witness = []

    def before_receiver(uc, _address, _size, _data):
        witness.append(uc.reg_read(UC_X86_REG_RDX))
        uc.reg_write(UC_X86_REG_RIP, exact.RETURN_ADDRESS)

    emulator.emulator.hook_add(
        UC_HOOK_CODE, before_receiver,
        begin=IMAGE_BASE + CALLBACK_PRE_RECEIVER_RVA,
        end=IMAGE_BASE + CALLBACK_PRE_RECEIVER_RVA,
    )
    return emulator, context, witness


def decode_one(emulator, context, witness, table, raw_param, payload):
    context['raw_param'] = raw_param
    native = emulator.decode(payload, PROFILE)
    if (native['deserialize_return_al'] != 1 or not native['fully_consumed']
            or native['bytes_consumed'] != len(payload)):
        raise ValueError('native deserializer did not fully consume packet')
    obj = bytes.fromhex(native['object_hex'])
    if (len(obj) != 0x18
            or struct.unpack_from('<Q', obj)[0] != IMAGE_BASE + VTABLE_RVA
            or struct.unpack_from('<H', obj, 8)[0] != PACKET_ID
            or struct.unpack_from('<I', obj, 0x0c)[0] != raw_param):
        raise ValueError('native object identity differs from Replay packet')
    protected = obj[0x14]
    expected = decode_callback_argument(protected, table)
    witness.clear()
    emulator.emulator.mem_write(exact.BUSINESS_OBJECT_ADDRESS, b'\x00' * 8)
    emulator.call(IMAGE_BASE + CALLBACK_RVA,
                  rcx=exact.BUSINESS_OBJECT_ADDRESS,
                  rdx=exact.OBJECT_ADDRESS)
    if len(witness) != 1 or witness[0] != expected:
        raise ValueError('native callback argument differs from packet-local inverse')
    return {
        'native_protected_dimension_byte_hex': f'{protected:02x}',
        'native_callback_argument_u8': expected,
        'native_callback_witness_status': 'STOPPED_BEFORE_RECEIVER_METHOD',
        'raw_payload_sha256': hashlib.sha256(payload).hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True, type=Path)
    options = parser.parse_args()
    packets = read_request()
    image, image_sha, table = read_image(options.image)
    emulator, context, witness = make_native(image)
    rows = []
    first_failure = None
    for index, (raw_param, payload) in enumerate(packets):
        try:
            rows.append(decode_one(emulator, context, witness, table,
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
        print(f'821 SetDimensionMissile native witness error: {error}', file=sys.stderr)
        raise SystemExit(1)

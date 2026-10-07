#!/usr/bin/env python3
"""Exact KR 821 packet-local lookup-key witness for route 0x0265.

Stops before the receiver-dependent call. A callback u32 does not establish a resolved target or state.
"""

import argparse
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RIP

import emulate_exact_packet_decoder as exact
from decode_broadcast_inventory_16_19_821 import make_emulator


BUILD = '16.19.821.7343'
IMAGE_BASE = 0x7ff67f410000
IMAGE_SIZE = 48_488_448
IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325'
PACKET_ID = 0x0265
FACTORY_TABLE_RVA = 0xf0e4bc
FACTORY_CASE_RVA = 0xf05c17
CONSTRUCTOR_RVA = 0xe99060
VTABLE_RVA = 0x1ba1b20
DESERIALIZER_RVA = 0xf19ec0
REGISTRATION_RVA = 0x261223
CLOSURE_VTABLE_RVA = 0x1ac2300
TYPE_FUNCTION_RVA = 0x303780
TYPE_DESCRIPTOR_RVA = 0x1f2b6d0
CALLBACK_RVA = 0x2bb950
CALLBACK_END_RVA = 0x2bb9be
LOOKUP_CALLSITE_RVA = 0x2bb9b2
LOOKUP_RVA = 0x2d2be0
CALLBACK_TABLE_RVA = 0x1ab62d0
CALLBACK_TABLE_SHA256 = '328528d693ab5d96a815b6706694025a980e609019304aeb2e5e32797011c04b'
CALLBACK_CODE_SHA256 = 'd390dfdc0c6e32a0ca6d51094aad9ae19e23d590cd501785761448b9200b1070'
PROFILE = {'constructor_rva': CONSTRUCTOR_RVA,
           'deserialize_rva': DESERIALIZER_RVA,
           'object_size': 0x14, 'fields': []}
OBSERVED_THREE_BYTE_PREFIXES = frozenset({0x30, 0x31, 0x32, 0x34, 0x35, 0x37})
MAX_REQUEST_BYTES = 512 * 1024
MAX_PACKETS = 10_000


def rip_target(image, rva):
    if image[rva:rva + 3] != b'\x48\x8d\x05':
        raise ValueError('exact 821 RIP-relative registration differs')
    return rva + 7 + struct.unpack_from('<i', image, rva + 3)[0]


def call_target(image, rva):
    if image[rva] != 0xe8:
        raise ValueError('exact 821 direct call differs')
    return rva + 5 + struct.unpack_from('<i', image, rva + 1)[0]


def decode_lookup_key(protected, table):
    if len(protected) != 4:
        raise ValueError('expected four protected object bytes')
    decoded = bytearray(4)
    for index, byte in enumerate(protected):
        first = table[byte]
        second = table[(~first) & 0xff]
        folded = (((second & 0xd5) << 1) | ((second >> 1) & 0x55)) & 0xff
        decoded[index] = table[folded]
    return struct.unpack('<I', decoded)[0]


def observed_payload(payload):
    return ((len(payload) == 1 and payload[0] == 0x33)
            or (len(payload) == 3 and payload[0] in OBSERVED_THREE_BYTE_PREFIXES))


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
            != bytes.fromhex('66c741086502')
            or rip_target(image, CONSTRUCTOR_RVA + 0x1c) != VTABLE_RVA
            or struct.unpack_from('<Q', image, VTABLE_RVA + 8)[0]
            != IMAGE_BASE + DESERIALIZER_RVA
            or image[REGISTRATION_RVA:REGISTRATION_RVA + 6]
            != bytes.fromhex('41b865020000')
            or rip_target(image, 0x2611c7) != CLOSURE_VTABLE_RVA
            or rip_target(image, 0x2611e3) != CALLBACK_RVA
            or struct.unpack_from('<Q', image, CLOSURE_VTABLE_RVA + 0x18)[0]
            != IMAGE_BASE + TYPE_FUNCTION_RVA
            or rip_target(image, TYPE_FUNCTION_RVA) != TYPE_DESCRIPTOR_RVA
            or call_target(image, LOOKUP_CALLSITE_RVA) != LOOKUP_RVA):
        raise ValueError('exact 821 factory, registration, reader or callback differs')
    name = image[TYPE_DESCRIPTOR_RVA + 16:TYPE_DESCRIPTOR_RVA + 300].split(b'\x00')[0]
    if b'AIBaseClient' not in name or b'PKT_AI_TargetHeroS2C_s' not in name:
        raise ValueError('exact 821 callback RTTI name differs')
    table = image[CALLBACK_TABLE_RVA:CALLBACK_TABLE_RVA + 256]
    if (hashlib.sha256(table).hexdigest() != CALLBACK_TABLE_SHA256
            or hashlib.sha256(image[CALLBACK_RVA:CALLBACK_END_RVA]).hexdigest()
            != CALLBACK_CODE_SHA256):
        raise ValueError('exact 821 callback table or code differs')
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
        digest.update(bytes.fromhex(row['native_protected_lookup_bytes_hex']))
        digest.update(struct.pack('<I', row['native_callback_lookup_key_u32']))
    return digest.hexdigest()


def make_native(image):
    emulator, context = make_emulator(image)
    captured = []

    def capture_lookup(uc, _address, _size, _user_data):
        captured.append((uc.reg_read(UC_X86_REG_RCX),
                         uc.reg_read(UC_X86_REG_RDX) & 0xffffffff))
        uc.reg_write(UC_X86_REG_RIP, exact.RETURN_ADDRESS)

    emulator.emulator.hook_add(
        UC_HOOK_CODE, capture_lookup,
        begin=IMAGE_BASE + LOOKUP_CALLSITE_RVA,
        end=IMAGE_BASE + LOOKUP_CALLSITE_RVA)
    return emulator, context, captured


def decode_one(emulator, context, captured, table, raw_param, payload):
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
    captured.clear()
    emulator.call(IMAGE_BASE + CALLBACK_RVA,
                  rcx=exact.BUSINESS_OBJECT_ADDRESS,
                  rdx=exact.OBJECT_ADDRESS)
    if captured != [(exact.BUSINESS_OBJECT_ADDRESS, decode_lookup_key(protected, table))]:
        raise ValueError('native callback key differs from packet object')
    return {
        'native_protected_lookup_bytes_hex': protected.hex(),
        'native_callback_lookup_key_u32': captured[0][1],
        'raw_payload_sha256': hashlib.sha256(payload).hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True, type=Path)
    options = parser.parse_args()
    packets = read_request()
    image, image_sha, table = read_image(options.image)
    emulator, context, captured = make_native(image)
    rows = []
    first_failure = None
    for index, (raw_param, payload) in enumerate(packets):
        try:
            rows.append(decode_one(emulator, context, captured, table, raw_param, payload))
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
        print(f'821 target hero native witness error: {error}', file=sys.stderr)
        raise SystemExit(1)

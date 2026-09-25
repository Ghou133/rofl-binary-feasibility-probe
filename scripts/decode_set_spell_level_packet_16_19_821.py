#!/usr/bin/env python3
"""Decode exact KR 821 SetSpellLevel packet fields as anonymous candidates.

Replay framing and provenance belong to the JavaScript caller. The pinned
client's constructor and deserializer supply the object bytes, and the exact
registered callback supplies the two byte transforms. A packet class name is
not proof of a spell identity, level change, owner, or gameplay effect.
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
PACKET_ID = 0x025d
FACTORY_TABLE_RVA = 0x00f0e4bc
FACTORY_CASE_RVA = 0x00f05a67
CONSTRUCTOR_RVA = 0x00ebf800
VTABLE_RVA = 0x01ba8b28
DESERIALIZER_RVA = 0x010fddc0
CALLBACK_RVA = 0x00998630
REGISTRATION_ID_WRITE_RVA = 0x00976e9b
REGISTRATION_CALL_RVA = 0x00976eb0
GENERIC_REGISTRATION_RVA = 0x00711e90
DESCRIPTOR_RVA = 0x01f79520
PROFILE = {'constructor_rva': CONSTRUCTOR_RVA,
           'deserialize_rva': DESERIALIZER_RVA,
           'object_size': 0x18, 'fields': []}
CALLBACK_TABLE_SHA256 = {
    'opaque_u32_0x10': '8aa1a1d1b3c61b2717fbf3b7349dcc659f21d91cd0fe98404e4dc6b700214cb5',
    'opaque_u32_0x14': 'b097f9ce648ac9593a43258eb81b7ee20dc37e7162a8bd584e768785c24ddbb3',
}
OBSERVED_PAYLOAD_LENGTHS = frozenset((1, 2, 3))
MAX_INPUT_BYTES = 4_000_000
MAX_PACKETS = 10_000


def failure(message, *, return_al=None, consumed=None):
    return {'status': 'FAILED', 'deserialize_return_al': return_al,
            'bytes_consumed': consumed, 'error': message}


def read_request():
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError('SetSpellLevel request exceeds bounded input size')
    request = json.loads(raw)
    if not isinstance(request, dict) or request.get('replay_version') != BUILD:
        raise ValueError(f'replay_version must be exactly {BUILD}')
    packets = request.get('packets')
    if not isinstance(packets, list) or len(packets) > MAX_PACKETS:
        raise ValueError(f'packets must be an array with at most {MAX_PACKETS} entries')
    return packets


def validate_packet(packet):
    if not isinstance(packet, dict) or packet.get('packet_id') != PACKET_ID:
        raise ValueError('packet ID must be exact 821 SetSpellLevel route')
    if packet.get('stream_tag') != 1:
        raise ValueError('SetSpellLevel candidate requires game stream')
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
        raise ValueError('payload length differs from observed 821 SetSpellLevel scope')
    return raw_param, payload


def ror8(value, count):
    return ((value >> count) | (value << (8 - count))) & 0xff


def swap_bits(value):
    return (((value & 0xd5) << 1) | ((value >> 1) & 0x55)) & 0xff


def callback_tables():
    # Callback RVA 0x998630 reads object +0x10 and +0x14 as dwords, applies
    # these byte transforms, then uses a live receiver that is not in the
    # mapped image. Bind every byte result to the exact callback SHA profile.
    transformations = {
        'opaque_u32_0x10': lambda x: (ror8((~ror8((swap_bits(x) + 0x68) & 0xff, 6)) & 0xff, 6) - 2) & 0xff,
        'opaque_u32_0x14': lambda x: ((ror8(x, 6) + 0x41) & 0xff) ^ 8,
    }
    tables = {}
    for name, transform in transformations.items():
        value = bytes(transform(x) for x in range(256))
        if (len(set(value)) != 256
                or hashlib.sha256(value).hexdigest() != CALLBACK_TABLE_SHA256[name]):
            raise ValueError(f'exact 821 SetSpellLevel callback transform differs: {name}')
        tables[name] = value
    return tables


def check_static_identity(image):
    if struct.unpack_from('<I', image, FACTORY_TABLE_RVA + PACKET_ID * 4)[0] != FACTORY_CASE_RVA:
        raise ValueError('exact 821 SetSpellLevel factory route differs')
    if image[CONSTRUCTOR_RVA + 7:CONSTRUCTOR_RVA + 13] != b'\x66\xc7\x41\x08\x5d\x02':
        raise ValueError('exact 821 SetSpellLevel constructor ID differs')
    if struct.unpack_from('<Q', image, VTABLE_RVA + 8)[0] != IMAGE_BASE + DESERIALIZER_RVA:
        raise ValueError('exact 821 SetSpellLevel deserializer route differs')
    if image[REGISTRATION_ID_WRITE_RVA:REGISTRATION_ID_WRITE_RVA + 6] != b'\x41\xb8\x5d\x02\x00\x00':
        raise ValueError('exact 821 SetSpellLevel callback registration ID differs')
    if (image[REGISTRATION_CALL_RVA] != 0xe8
            or REGISTRATION_CALL_RVA + 5
            + struct.unpack_from('<i', image, REGISTRATION_CALL_RVA + 1)[0]
            != GENERIC_REGISTRATION_RVA):
        raise ValueError('exact 821 SetSpellLevel generic registration differs')
    if b'PKT_S2C_SetSpellLevel_s' not in image[DESCRIPTOR_RVA:DESCRIPTOR_RVA + 200]:
        raise ValueError('exact 821 SetSpellLevel type descriptor differs')
    if image[CALLBACK_RVA:CALLBACK_RVA + 7] != b'\x48\x83\xec\x38\x8b\x42\x10':
        raise ValueError('exact 821 SetSpellLevel callback differs')


def decode_packet(emulator, context, tables, raw_param, payload):
    context['raw_param'] = raw_param
    native = emulator.decode(payload, PROFILE)
    return_al = native['deserialize_return_al']
    consumed = native['bytes_consumed']
    if return_al != 1 or not native['fully_consumed'] or consumed != len(payload):
        return failure('native SetSpellLevel did not fully consume payload',
                       return_al=return_al, consumed=consumed)
    obj = bytes.fromhex(native['object_hex'])
    if len(obj) != PROFILE['object_size']:
        return failure('native SetSpellLevel object size differs',
                       return_al=return_al, consumed=consumed)
    if struct.unpack_from('<Q', obj, 0)[0] != IMAGE_BASE + VTABLE_RVA:
        return failure('native SetSpellLevel object vtable differs',
                       return_al=return_al, consumed=consumed)
    if struct.unpack_from('<H', obj, 8)[0] != PACKET_ID:
        return failure('native SetSpellLevel packet ID differs',
                       return_al=return_al, consumed=consumed)
    if struct.unpack_from('<I', obj, 0x0c)[0] != raw_param:
        return failure('native SetSpellLevel raw param differs from Replay',
                       return_al=return_al, consumed=consumed)
    fields = {}
    for name, offset in (('opaque_u32_0x10', 0x10), ('opaque_u32_0x14', 0x14)):
        raw = obj[offset:offset + 4]
        fields['raw_u32_' + name[-4:] + '_hex'] = raw.hex()
        fields[name] = int.from_bytes(raw.translate(tables[name]), 'little')
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
            raise ValueError('SetSpellLevel runtime image SHA-256 mismatch')
        check_static_identity(image)
        tables = callback_tables()
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
                row = failure(f'exact-runtime SetSpellLevel emulation failed: {exc}')
                emulator, context = make_emulator(image)
            row.update(binding)
            results.append(row)
        json.dump({'status': 'PASS', 'runtime_image_sha256': digest,
                   'callback_table_sha256': CALLBACK_TABLE_SHA256,
                   'results': results}, sys.stdout, separators=(',', ':'))
        sys.stdout.write('\n')
        return 0
    except Exception as exc:
        print(f'821 SetSpellLevel exact-runtime decoder error: {exc}', file=sys.stderr)
        json.dump({'status': 'ERROR', 'runtime_image_sha256': digest,
                   'results': [], 'error': str(exc)}, sys.stdout,
                  separators=(',', ':'))
        sys.stdout.write('\n')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

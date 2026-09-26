#!/usr/bin/env python3
"""Exact-runtime, packet-level 821 CastSpellAns candidate fields.

The caller owns Replay framing and provenance. The runtime packet class name
does not establish that any packet represents a successful spell cast.
"""

import argparse
import hashlib
import json
import math
import string
import struct
import sys
from pathlib import Path

# Reuse the exact 821 image loader and native emulator setup. The whole-image
# SHA below is the Cast gate; the loader's additional table check is fixed by
# that same image identity and does not assign inventory semantics here.
from decode_mapview_inventory_16_19_821 import make_emulator, read_image


BUILD = '16.19.821.7343'
IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325'
IMAGE_BASE = 0x7ff67f410000
PACKET_ID = 0x01da
VTABLE_RVA = 0x01ba8ca0
CALLBACK_TABLE_RVA = 0x01ab62d0
CALLBACK_TABLE_SHA256 = '328528d693ab5d96a815b6706694025a980e609019304aeb2e5e32797011c04b'
NESTED_U32_CALLBACK_TABLE_RVA = 0x01b41db0
NESTED_U32_TRANSFORM_SHA256 = '5b858c9ef8d1393d05d867112316c3344ff777044719d839ad8cd64867d7f537'
NESTED_U32_0X4C_TRANSFORM_SHA256 = 'ad5ff48a6d097a43b6880bcafd30d0f8ef7f30f3988c049e1add1261f626eb4c'
NESTED_U32_0X4C_INVERSE_TABLE_RVA = 0x01badb60
NESTED_U32_0X4C_INVERSE_TABLE_SHA256 = 'ae15d606869d66dc47309b26cb489e01bf841e9dd57d540683e2dc7f5e394588'
NESTED_F32_0XA0_TRANSFORM_SHA256 = '38b9182f05f84284e1e6b877971aa4401ac0c3c3d98ea7f90f4768d90e1388ca'
NESTED_F32_0XA0_INVERSE_SHA256 = '682d276b04d72c6400afd3e39c36074ece86577d5431950ff228c3faada64324'
NESTED_U32_0X28_TRANSFORM_SHA256 = '8aa1a1d1b3c61b2717fbf3b7349dcc659f21d91cd0fe98404e4dc6b700214cb5'
NESTED_U32_0X28_INVERSE_SHA256 = '442516bee22a1147d65334928ed5300c815deeab1ac6c92002960045590a4e71'
NESTED_FLOAT_INVERSE_SHA256 = 'cce644f3775d31b6be55e5abc79ed029298be5110b8f81be8957bd3b066019f5'
NESTED_BYTE_INVERSE_SHA256 = 'b5d220967c423848c278651d068786e3aaedf4994c6d30dd1d3d0c8fe6892516'
PROFILE = {'constructor_rva': 0x00e9da90, 'deserialize_rva': 0x010df350,
           'object_size': 0x150, 'fields': []}
MAX_INPUT_BYTES = 4_000_000
MAX_PACKETS = 8192
MAX_PAYLOAD_BYTES = 256
MIN_OBSERVED_PAYLOAD_BYTES = 97
MAX_OBSERVED_PAYLOAD_BYTES = 189
OBSERVED_SELECTORS = frozenset((0x05, 0x11, 0x15, 0x17, 0x19, 0x1b))


def failure(message, *, return_al=None, consumed=None):
    return {'status': 'FAILED', 'deserialize_return_al': return_al,
            'bytes_consumed': consumed, 'error': message}


def read_request():
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError('cast packet request exceeds bounded input size')
    request = json.loads(raw)
    if not isinstance(request, dict) or request.get('replay_version') != BUILD:
        raise ValueError(f'replay_version must be exactly {BUILD}')
    packets = request.get('packets')
    if not isinstance(packets, list) or len(packets) > MAX_PACKETS:
        raise ValueError(f'packets must be an array with at most {MAX_PACKETS} entries')
    return packets


def validate_packet(packet):
    if not isinstance(packet, dict):
        raise ValueError('packet must be an object')
    raw_param = packet.get('raw_param')
    if type(raw_param) is not int or not 0 < raw_param <= 0xffffffff:
        raise ValueError('raw_param must be a nonzero unsigned 32-bit integer')
    payload_hex = packet.get('payload_hex')
    if not isinstance(payload_hex, str) or len(payload_hex) % 2:
        raise ValueError('payload_hex must be even-length hexadecimal text')
    if len(payload_hex) // 2 > MAX_PAYLOAD_BYTES:
        raise ValueError('payload exceeds bounded cast packet size')
    if any(character not in string.hexdigits for character in payload_hex):
        raise ValueError('payload_hex contains non-hexadecimal characters')
    payload = bytes.fromhex(payload_hex)
    if not MIN_OBSERVED_PAYLOAD_BYTES <= len(payload) <= MAX_OBSERVED_PAYLOAD_BYTES:
        raise ValueError('payload length differs from observed 821 cast packet scope')
    if payload[0] not in OBSERVED_SELECTORS:
        raise ValueError('payload selector differs from observed 821 cast packet scope')
    return raw_param, payload


def ror8(value, count):
    return ((value >> count) | (value << (8 - count))) & 0xff


def swap(value):
    return (((value & 0xd5) << 1) | ((value >> 1) & 0x55)) & 0xff


def nested_float_inverse():
    # The 0x01da nested deserializer writes a protected f32 at nested +0xd0,
    # packet object +0xe0. Exact 821 code: RVA 0x10bec00..0x10bec19 (and
    # equivalent branches at 0x10bec50, 0x10beca0, 0x10becf0, 0x10bed40).
    def encode(byte):
        return (swap(ror8((byte - 0x73) & 0xff, 2)) + 0x6c) & 0xff

    inverse = {encode(byte): byte for byte in range(256)}
    if (len(inverse) != 256 or encode(0) != 0xff
            or hashlib.sha256(bytes(inverse[index] for index in range(256))).hexdigest()
            != NESTED_FLOAT_INVERSE_SHA256):
        raise ValueError('cast nested float byte transform differs')
    return inverse


NESTED_FLOAT_INVERSE = nested_float_inverse()


def nested_byte_inverse():
    # The nested deserializer writes a protected byte at nested +0x130,
    # packet +0x140. Exact 821 RVA 0x10bf400..0x10bf422 and wire reader
    # RVA 0x10a1900..0x10a197f use inverse stages of the same transform.
    def encode(byte):
        value = ror8((byte + 0x78) & 0xff, 7)
        value = (~((value + 0x44) & 0xff)) & 0xff
        return swap((ror8(value, 6) - 0x13) & 0xff)

    inverse = {encode(byte): byte for byte in range(256)}
    if (len(inverse) != 256 or encode(0) != 0x2c
            or hashlib.sha256(bytes(inverse[index] for index in range(256))).hexdigest()
            != NESTED_BYTE_INVERSE_SHA256):
        raise ValueError('cast nested byte transform differs')
    return inverse


NESTED_BYTE_INVERSE = nested_byte_inverse()


def decode_flag(encoded, table):
    # Exact callback byte path at RVA 0x002bd2ec and 0x002bd4c2.
    value = table[swap(ror8(encoded, 2))] ^ 0xea
    return ror8((((value + 0x4f) & 0xff) ^ 0xb0), 4) ^ 0xeb


def decode_i32_byte(encoded):
    # Exact callback dword byte path at RVA 0x002bd406-0x002bd451.
    value = ror8((swap(encoded) + 0x68) & 0xff, 6)
    return (ror8((~value) & 0xff, 6) - 2) & 0xff


def nested_u32_at_0x28_transform():
    # Nested +0x18 (packet +0x28) is protected by the exact 821 deserializer
    # at RVA 0x10babce..0x10bae7b. The callback converts it at
    # RVA 0x8d75b3..0x8d75f5 and uses it as a conditional tree lookup key at
    # RVA 0x8d86c2..0x8d875a. Lookup success needs the absent live heap.
    def encode(byte):
        value = ror8((byte + 2) & 0xff, 2)
        value = ror8((~value) & 0xff, 2)
        return swap((value - 0x68) & 0xff)

    transform = bytes(decode_i32_byte(byte) for byte in range(256))
    inverse = bytes(encode(byte) for byte in range(256))
    if (len(set(transform)) != 256 or len(set(inverse)) != 256
            or hashlib.sha256(transform).hexdigest() != NESTED_U32_0X28_TRANSFORM_SHA256
            or hashlib.sha256(inverse).hexdigest() != NESTED_U32_0X28_INVERSE_SHA256
            or any(transform[inverse[byte]] != byte
                   or inverse[transform[byte]] != byte for byte in range(256))):
        raise ValueError('cast nested +0x28 lookup-key transform differs')
    return transform


def decode_nested_bits(encoded):
    # Nested +0x14 is packet +0x24. The exact 821 callback conversion at
    # RVA 0x8d7eb9..0x8d7f26 splits this decoded byte into opaque bit fields.
    value = swap(encoded)
    return ((((value - 0x54) & 0xff) ^ 0xcc) + 0x48) & 0xff


def rol8(value, count):
    return ((value << count) | (value >> (8 - count))) & 0xff


def nested_u32_transform(table):
    # The exact 821 callback at RVA 0x8d77ed..0x8d785a reads nested +0x0c
    # (packet object +0x1c) and writes the converted word to temporary +0xa8.
    # Its r15-relative lookup is the same 256-byte table copied in the image
    # at RVA 0x1b41db0. The word is deliberately anonymous.
    def decode(byte):
        value = table[rol8(table[byte], 2)]
        return table[rol8((~((value + 0x48) & 0xff)) & 0xff, 3)]

    transform = bytes(decode(byte) for byte in range(256))
    if (len(set(transform)) != 256 or hashlib.sha256(transform).hexdigest()
            != NESTED_U32_TRANSFORM_SHA256):
        raise ValueError('cast nested u32 callback transform differs')
    return transform


def nested_u32_at_4c_transform(table, inverse_table):
    # The exact 821 callback at RVA 0x8d7860..0x8d78cb reads nested +0x3c
    # (packet object +0x4c) and writes the converted word to temporary +0xac.
    # The nested deserializer protects that word at RVA 0x10bb405..0x10bb744
    # using the inverse table at RVA 0x1badb60. No gameplay role is assigned.
    def decode(byte):
        value = swap(byte)
        value = swap((~value) & 0xff)
        value = swap((value + 0x30) & 0xff)
        return table[value]

    transform = bytes(decode(byte) for byte in range(256))
    if (len(set(transform)) != 256 or hashlib.sha256(transform).hexdigest()
            != NESTED_U32_0X4C_TRANSFORM_SHA256):
        raise ValueError('cast nested +0x4c u32 callback transform differs')

    def encode(byte):
        value = swap(inverse_table[byte])
        value = swap((value - 0x30) & 0xff)
        return swap((~value) & 0xff)

    if (len(inverse_table) != 256 or hashlib.sha256(inverse_table).hexdigest()
            != NESTED_U32_0X4C_INVERSE_TABLE_SHA256
            or any(decode(encode(byte)) != byte or encode(decode(byte)) != byte
                   for byte in range(256))):
        raise ValueError('cast nested +0x4c deserializer inverse differs')
    return transform


def nested_f32_at_a0_transform(table, inverse_table):
    # Nested +0x90 is packet object +0xa0. The exact 821 callback at
    # RVA 0x8d76da..0x8d7710 converts its four bytes to temporary +0x9c.
    # The nested deserializer writes it at RVA 0x10bd7d4..0x10bd991 using
    # the inverse table at RVA 0x1badb60. This is an anonymous packet float.
    transform = bytes((0x65 - (table[byte] ^ 0x2b)) & 0xff
                      for byte in range(256))
    inverse = bytes(inverse_table[((~byte + 0x66) & 0xff) ^ 0x2b]
                    for byte in range(256))
    if (len(set(transform)) != 256 or len(set(inverse)) != 256
            or hashlib.sha256(transform).hexdigest() != NESTED_F32_0XA0_TRANSFORM_SHA256
            or hashlib.sha256(inverse).hexdigest() != NESTED_F32_0XA0_INVERSE_SHA256
            or any(transform[inverse[byte]] != byte
                   or inverse[transform[byte]] != byte for byte in range(256))):
        raise ValueError('cast nested +0xa0 f32 callback/deserializer transform differs')
    return transform


def decode_packet(emulator, context, raw_param, payload, table,
                  nested_u32_table=None, nested_u32_at_4c_table=None,
                  nested_f32_at_a0_table=None, nested_u32_at_0x28_table=None):
    context['raw_param'] = raw_param
    native = emulator.decode(payload, PROFILE)
    return_al = native['deserialize_return_al']
    consumed = native['bytes_consumed']
    if return_al != 1 or not native['fully_consumed'] or consumed != len(payload):
        return failure('native cast packet did not fully consume payload',
                       return_al=return_al, consumed=consumed)
    obj = bytes.fromhex(native['object_hex'])
    if len(obj) != PROFILE['object_size']:
        return failure('native cast packet object size differs',
                       return_al=return_al, consumed=consumed)
    if struct.unpack_from('<Q', obj, 0)[0] != IMAGE_BASE + VTABLE_RVA:
        return failure('native cast packet object vtable differs',
                       return_al=return_al, consumed=consumed)
    if struct.unpack_from('<H', obj, 8)[0] != PACKET_ID:
        return failure('native cast packet ID differs',
                       return_al=return_al, consumed=consumed)
    if struct.unpack_from('<I', obj, 0x0c)[0] != raw_param:
        return failure('native cast packet raw param differs from Replay',
                       return_al=return_al, consumed=consumed)
    raw_flag = obj[0x148]
    opaque_flag = decode_flag(raw_flag, table)
    if opaque_flag not in (0, 1):
        return failure('callback-transformed cast packet flag differs from observed scope',
                       return_al=return_al, consumed=consumed)
    raw_i32 = obj[0x14c:0x150]
    opaque_i32 = struct.unpack('<i', bytes(map(decode_i32_byte, raw_i32)))[0]
    raw_float = obj[0xe0:0xe4]
    opaque_float = struct.unpack('<f', bytes(NESTED_FLOAT_INVERSE[byte]
                                             for byte in raw_float))[0]
    if not math.isfinite(opaque_float):
        return failure('nested cast packet float is not finite',
                       return_al=return_al, consumed=consumed)
    raw_byte = obj[0x140]
    opaque_byte = NESTED_BYTE_INVERSE[raw_byte]
    raw_nested_bits = obj[0x24]
    opaque_nested_bits = decode_nested_bits(raw_nested_bits)
    result = {'status': 'DECODED', 'deserialize_return_al': return_al,
            'bytes_consumed': consumed, 'native_packet_id': PACKET_ID,
            'native_raw_param': raw_param, 'raw_flag_byte_hex': f'{raw_flag:02x}',
            'opaque_flag_0x148': opaque_flag,
            'raw_f32_bytes_hex': raw_float.hex(), 'opaque_f32_0xe0': opaque_float,
            'raw_u8_0x140_hex': f'{raw_byte:02x}', 'opaque_u8_0x140': opaque_byte,
            'raw_nested_bits_0x24_hex': f'{raw_nested_bits:02x}',
            'opaque_nested_bits_0x24': opaque_nested_bits,
            'raw_i32_bytes_hex': raw_i32.hex(), 'opaque_i32_0x14c': opaque_i32}
    if nested_u32_table is not None:
        raw_u32 = obj[0x1c:0x20]
        result['raw_u32_0x1c_hex'] = raw_u32.hex()
        result['opaque_u32_0x1c'] = struct.unpack(
            '<I', raw_u32.translate(nested_u32_table))[0]
    if nested_u32_at_4c_table is not None:
        raw_u32_at_4c = obj[0x4c:0x50]
        result['raw_u32_0x4c_hex'] = raw_u32_at_4c.hex()
        result['opaque_u32_0x4c'] = struct.unpack(
            '<I', raw_u32_at_4c.translate(nested_u32_at_4c_table))[0]
    if nested_f32_at_a0_table is not None:
        raw_f32_at_a0 = obj[0xa0:0xa4]
        opaque_f32_at_a0 = struct.unpack(
            '<f', raw_f32_at_a0.translate(nested_f32_at_a0_table))[0]
        if not math.isfinite(opaque_f32_at_a0):
            return failure('nested cast packet +0xa0 float is not finite',
                           return_al=return_al, consumed=consumed)
        result['raw_f32_0xa0_hex'] = raw_f32_at_a0.hex()
        result['opaque_f32_0xa0'] = opaque_f32_at_a0
    if nested_u32_at_0x28_table is not None:
        raw_u32_at_0x28 = obj[0x28:0x2c]
        result['raw_u32_0x28_hex'] = raw_u32_at_0x28.hex()
        result['opaque_u32_0x28'] = struct.unpack(
            '<I', raw_u32_at_0x28.translate(nested_u32_at_0x28_table))[0]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--nested-u32-0x1c', action='store_true',
                        help='opt in to the anonymous nested callback u32')
    parser.add_argument('--nested-u32-0x4c', action='store_true',
                        help='opt in to the anonymous nested callback +0x4c u32')
    parser.add_argument('--nested-f32-0xa0', action='store_true',
                        help='opt in to the anonymous nested callback +0xa0 f32')
    parser.add_argument('--nested-u32-0x28', action='store_true',
                        help='opt in to the anonymous nested callback lookup key')
    options = parser.parse_args()
    digest = None
    try:
        packets = read_request()
        image, digest, _inventory_table = read_image(options.image)
        if digest != IMAGE_SHA256:
            raise ValueError('cast runtime image SHA-256 mismatch')
        table = image[CALLBACK_TABLE_RVA:CALLBACK_TABLE_RVA + 256]
        table_sha = hashlib.sha256(table).hexdigest()
        if len(table) != 256 or table_sha != CALLBACK_TABLE_SHA256:
            raise ValueError('cast callback transform table differs')
        nested_u32_table = None
        nested_u32_at_4c_table = None
        nested_f32_at_a0_table = None
        nested_u32_at_0x28_table = None
        if (options.nested_u32_0x1c or options.nested_u32_0x4c
                or options.nested_f32_0xa0):
            callback_copy = image[NESTED_U32_CALLBACK_TABLE_RVA:
                                  NESTED_U32_CALLBACK_TABLE_RVA + 256]
            if callback_copy != table:
                raise ValueError('cast nested u32 callback table differs')
        if options.nested_u32_0x1c:
            nested_u32_table = nested_u32_transform(callback_copy)
        if options.nested_u32_0x4c:
            inverse_copy = image[NESTED_U32_0X4C_INVERSE_TABLE_RVA:
                                 NESTED_U32_0X4C_INVERSE_TABLE_RVA + 256]
            nested_u32_at_4c_table = nested_u32_at_4c_transform(
                callback_copy, inverse_copy)
        if options.nested_f32_0xa0:
            inverse_copy = image[NESTED_U32_0X4C_INVERSE_TABLE_RVA:
                                 NESTED_U32_0X4C_INVERSE_TABLE_RVA + 256]
            nested_f32_at_a0_table = nested_f32_at_a0_transform(
                callback_copy, inverse_copy)
        if options.nested_u32_0x28:
            nested_u32_at_0x28_table = nested_u32_at_0x28_transform()
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
                row = decode_packet(emulator, context, raw_param, payload, table,
                                    nested_u32_table, nested_u32_at_4c_table,
                                    nested_f32_at_a0_table,
                                    nested_u32_at_0x28_table)
                if row['status'] != 'DECODED':
                    emulator, context = make_emulator(image)
            except Exception as exc:
                row = failure(f'exact-runtime cast packet emulation failed: {exc}')
                emulator, context = make_emulator(image)
            row.update(binding)
            results.append(row)
        output = {'status': 'PASS', 'runtime_image_sha256': digest,
                   'callback_table_sha256': table_sha,
                   'nested_float_inverse_sha256': NESTED_FLOAT_INVERSE_SHA256,
                   'nested_byte_inverse_sha256': NESTED_BYTE_INVERSE_SHA256,
                   'results': results}
        if nested_u32_table is not None:
            output['nested_u32_transform_sha256'] = NESTED_U32_TRANSFORM_SHA256
        if nested_u32_at_4c_table is not None:
            output['nested_u32_0x4c_transform_sha256'] = NESTED_U32_0X4C_TRANSFORM_SHA256
        if nested_f32_at_a0_table is not None:
            output['nested_f32_0xa0_transform_sha256'] = NESTED_F32_0XA0_TRANSFORM_SHA256
            output['nested_f32_0xa0_inverse_sha256'] = NESTED_F32_0XA0_INVERSE_SHA256
        if nested_u32_at_0x28_table is not None:
            output['nested_u32_0x28_transform_sha256'] = NESTED_U32_0X28_TRANSFORM_SHA256
            output['nested_u32_0x28_inverse_sha256'] = NESTED_U32_0X28_INVERSE_SHA256
        json.dump(output, sys.stdout, separators=(',', ':'))
        sys.stdout.write('\n')
        return 0
    except Exception as exc:
        print(f'821 cast packet exact-runtime decoder error: {exc}', file=sys.stderr)
        json.dump({'status': 'ERROR', 'runtime_image_sha256': digest,
                   'results': [], 'error': str(exc)}, sys.stdout,
                  separators=(',', ':'))
        sys.stdout.write('\n')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

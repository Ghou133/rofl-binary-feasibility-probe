#!/usr/bin/env python3
"""Decode exact KR 821 SetSpellTimerFromBuff packet fields as candidates.

The JavaScript caller owns Replay framing and provenance. This helper runs the
pinned client's constructor/deserializer and the callback's byte transforms.
Neither the packet name nor these fields establishes a timer or buff effect.
"""

import argparse
import hashlib
import json
import math
import string
import struct
import sys
from pathlib import Path

from decode_mapview_inventory_16_19_821 import make_emulator, read_image


BUILD = '16.19.821.7343'
IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325'
IMAGE_BASE = 0x7ff67f410000
PACKET_ID = 0x00fd
FACTORY_TABLE_RVA = 0x00f0e4bc
FACTORY_CASE_RVA = 0x00f013cf
VTABLE_RVA = 0x01ba8f08
CALLBACK_RVA = 0x002c2760
CALLBACK_END_RVA = 0x002c28d7
RECEIVER_LOOKUP_RVA = 0x0098a840
RECEIVER_LOOKUP_END_RVA = 0x0098a859
RECEIVER_CALL_RVA = 0x00946cf0
CALLBACK_INDEX_63_CHECK_RVA = 0x002c27c1
CALLBACK_ACCEPTED_PATH_RVA = 0x002c27ca
CALLBACK_LOOKUP_CALL_RVA = 0x002c27f2
CALLBACK_RECEIVER_CALL_RVA = 0x002c28ca
CALLBACK_REGION_SHA256 = '8aa6f881b0a6a05e5ba169da4d2521a390b947f214dbd587c946e00b0112b9c2'
RECEIVER_LOOKUP_REGION_SHA256 = '88974afa23e856901f874805af9cb11670298ac9082f8bc4526e9a1a1c70a1d5'
CALLBACK_WITNESS_MODE = 'NATIVE_SYNTHETIC_RECEIVER_CALL_ENTRY'
PROFILE = {'constructor_rva': 0x00ebf9a0, 'deserialize_rva': 0x010fe3e0,
           'object_size': 0x24, 'fields': []}
LOOKUP_TABLE_RVA = 0x01ab62d0
LOOKUP_TABLE_SHA256 = '328528d693ab5d96a815b6706694025a980e609019304aeb2e5e32797011c04b'
CALLBACK_TABLE_SHA256 = {
    'opaque_u8_0x10': '48a697d580affb9688308aa3f7a09ee24d87378dd299a5128a4447f1795c39a4',
    'opaque_u8_0x11': 'cddd28e48f36e54efe3d10a70fd25121d665001654b661c121767c2ca23f2425',
    'opaque_f32_0x14': '24206a5cc1586f42dd59c98818754f592a18e7ee3026115615e69e5814630c68',
    'opaque_u32_0x18': 'b097f9ce648ac9593a43258eb81b7ee20dc37e7162a8bd584e768785c24ddbb3',
    'opaque_u32_0x1c': 'a90f34d17c8715929574f708ea279badb13f527d6d025a6138fb179b7329c84b',
    'opaque_u8_0x20': '8aa1a1d1b3c61b2717fbf3b7349dcc659f21d91cd0fe98404e4dc6b700214cb5',
}
OBSERVED_PAYLOAD_LENGTHS = frozenset((7, 8, 10, 11, 12))
MAX_INPUT_BYTES = 4_000_000
MAX_PACKETS = 10_000


def failure(message, *, return_al=None, consumed=None):
    return {'status': 'FAILED', 'deserialize_return_al': return_al,
            'bytes_consumed': consumed, 'error': message}


def read_request():
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError('SetSpellTimerFromBuff request exceeds bounded input size')
    request = json.loads(raw)
    if not isinstance(request, dict) or request.get('replay_version') != BUILD:
        raise ValueError(f'replay_version must be exactly {BUILD}')
    packets = request.get('packets')
    if not isinstance(packets, list) or len(packets) > MAX_PACKETS:
        raise ValueError(f'packets must be an array with at most {MAX_PACKETS} entries')
    return packets


def validate_packet(packet):
    if not isinstance(packet, dict) or packet.get('packet_id') != PACKET_ID:
        raise ValueError('packet ID must be exact 821 SetSpellTimerFromBuff route')
    if packet.get('stream_tag') != 1:
        raise ValueError('SetSpellTimerFromBuff candidate requires game stream')
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
        raise ValueError('payload length differs from observed 821 SetSpellTimerFromBuff scope')
    return raw_param, payload


def ror8(value, count):
    return ((value >> count) | (value << (8 - count))) & 0xff


def swap_bits(value):
    return (((value & 0xd5) << 1) | ((value >> 1) & 0x55)) & 0xff


def callback_tables(image):
    # Exact callback RVA 0x2c2760 reads six anonymous object offsets. The
    # static lookup table and every 256-byte transform are checked against the
    # pinned image before any Replay packet is emitted.
    table = image[LOOKUP_TABLE_RVA:LOOKUP_TABLE_RVA + 256]
    if len(table) != 256 or hashlib.sha256(table).hexdigest() != LOOKUP_TABLE_SHA256:
        raise ValueError('exact 821 SetSpellTimerFromBuff callback lookup table differs')
    transformations = {
        'opaque_u8_0x10': lambda x: table[(table[x] + 0x51) & 0xff],
        'opaque_u8_0x11': lambda x: (ror8((~x + 0x19) & 0xff, 1) - 0x29) & 0xff,
        'opaque_f32_0x14': lambda x: ror8((ror8(swap_bits((x - 0x6d) & 0xff), 5) + 9) & 0xff, 4),
        'opaque_u32_0x18': lambda x: ((ror8(x, 6) + 0x41) & 0xff) ^ 8,
        'opaque_u32_0x1c': lambda x: ror8(x, 1),
        'opaque_u8_0x20': lambda x: (ror8((~ror8((swap_bits(x) + 0x68) & 0xff, 6)) & 0xff, 6) - 2) & 0xff,
    }
    tables = {}
    for name, transform in transformations.items():
        value = bytes(transform(x) for x in range(256))
        if (len(set(value)) != 256
                or hashlib.sha256(value).hexdigest() != CALLBACK_TABLE_SHA256[name]):
            raise ValueError(f'exact 821 SetSpellTimerFromBuff callback transform differs: {name}')
        tables[name] = value
    return tables


def check_static_identity(image, *, callback_witness_v2=False):
    if struct.unpack_from('<I', image, FACTORY_TABLE_RVA + PACKET_ID * 4)[0] != FACTORY_CASE_RVA:
        raise ValueError('exact 821 SetSpellTimerFromBuff factory route differs')
    constructor = PROFILE['constructor_rva']
    if image[constructor + 7:constructor + 13] != b'\x66\xc7\x41\x08\xfd\x00':
        raise ValueError('exact 821 SetSpellTimerFromBuff constructor ID differs')
    if struct.unpack_from('<Q', image, VTABLE_RVA + 8)[0] != IMAGE_BASE + PROFILE['deserialize_rva']:
        raise ValueError('exact 821 SetSpellTimerFromBuff deserializer route differs')
    if image[CALLBACK_RVA:CALLBACK_RVA + 6] != b'\x40\x53\x48\x83\xec\x40':
        raise ValueError('exact 821 SetSpellTimerFromBuff callback differs')
    if callback_witness_v2:
        if hashlib.sha256(image[CALLBACK_RVA:CALLBACK_END_RVA]).hexdigest() != CALLBACK_REGION_SHA256:
            raise ValueError('exact 821 SetSpellTimerFromBuff callback region differs')
        if hashlib.sha256(image[RECEIVER_LOOKUP_RVA:RECEIVER_LOOKUP_END_RVA]).hexdigest() != RECEIVER_LOOKUP_REGION_SHA256:
            raise ValueError('exact 821 SetSpellTimerFromBuff receiver lookup region differs')
        for call_rva, expected in (
                (CALLBACK_LOOKUP_CALL_RVA, RECEIVER_LOOKUP_RVA),
                (CALLBACK_RECEIVER_CALL_RVA, RECEIVER_CALL_RVA)):
            if (image[call_rva] != 0xe8 or
                    call_rva + 5 + struct.unpack_from('<i', image, call_rva + 1)[0]
                    != expected):
                raise ValueError('exact 821 SetSpellTimerFromBuff callback call route differs')


def make_decoder_emulator(image, *, callback_witness_v2=False):
    emulator, context = make_emulator(image)
    if not callback_witness_v2:
        return emulator, context

    from unicorn import UC_HOOK_CODE
    from unicorn.x86_const import (
        UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RCX, UC_X86_REG_RDX,
        UC_X86_REG_RSP,
    )

    context['lookup_calls'] = []
    context['receiver_calls'] = []
    context['index_63_checks'] = 0
    context['accepted_path_hits'] = 0

    def capture_lookup(uc, _address, _size, _user_data):
        context['lookup_calls'].append((
            uc.reg_read(UC_X86_REG_RCX),
            uc.reg_read(UC_X86_REG_RDX) & 0xffffffff,
        ))

    def capture_index_63_check(_uc, _address, _size, _user_data):
        context['index_63_checks'] += 1

    def capture_accepted_path(_uc, _address, _size, _user_data):
        context['accepted_path_hits'] += 1

    def capture_receiver_entry(uc, _address, _size, _user_data):
        rsp = uc.reg_read(UC_X86_REG_RSP)
        context['receiver_calls'].append({
            'target': uc.reg_read(UC_X86_REG_RCX),
            'u32_0x18': uc.reg_read(UC_X86_REG_RDX) & 0xffffffff,
            'u8_0x11': uc.reg_read(UC_X86_REG_R8) & 0xff,
            'u32_0x1c': uc.reg_read(UC_X86_REG_R9) & 0xffffffff,
            'f32_0x14_bits': bytes(uc.mem_read(rsp + 0x28, 4)),
            'u8_0x10': uc.mem_read(rsp + 0x30, 1)[0],
        })
        # The Replay-time receiver heap and live clock are unavailable.
        # Return at the callee entry after witnessing its exact arguments.
        emulator._return_from_stub()

    for rva, callback in (
            (RECEIVER_LOOKUP_RVA, capture_lookup),
            (CALLBACK_INDEX_63_CHECK_RVA, capture_index_63_check),
            (CALLBACK_ACCEPTED_PATH_RVA, capture_accepted_path),
            (RECEIVER_CALL_RVA, capture_receiver_entry)):
        emulator.emulator.hook_add(
            UC_HOOK_CODE, callback,
            begin=IMAGE_BASE + rva, end=IMAGE_BASE + rva,
        )
    return emulator, context


def witness_receiver_call(emulator, context, tables):
    """Witness exact callback dispatch and arguments on a synthetic table."""
    import emulate_exact_packet_decoder as exact

    if 'receiver_calls' not in context:
        raise ValueError('SetSpellTimerFromBuff V2 callback hooks are unavailable')
    obj = bytes(emulator.emulator.mem_read(exact.OBJECT_ADDRESS, PROFILE['object_size']))
    selector = tables['opaque_u8_0x20'][obj[0x20]]

    receiver = exact.WORK_BASE + 0x100000
    target_base = receiver + 0x6000
    targets = tuple(target_base + index * 0x80 for index in range(64))
    emulator.emulator.mem_write(receiver, bytes(0x4000))
    emulator.emulator.mem_write(target_base, bytes(64 * 0x80))
    for index, target in enumerate(targets):
        emulator.emulator.mem_write(
            receiver + 0x3110 + 0xae0 + index * 8, struct.pack('<Q', target))
    context['lookup_calls'].clear()
    context['receiver_calls'].clear()
    context['index_63_checks'] = 0
    context['accepted_path_hits'] = 0

    callback_return = emulator.call(
        IMAGE_BASE + CALLBACK_RVA, rcx=receiver, rdx=exact.OBJECT_ADDRESS)
    if (callback_return & 0xff != 1 or context['accepted_path_hits'] != 1
            or len(context['lookup_calls']) != 1
            or len(context['receiver_calls']) != 1):
        raise ValueError('SetSpellTimerFromBuff V2 receiver call was not witnessed')
    if selector not in (*range(6), 63):
        raise ValueError('SetSpellTimerFromBuff V2 selector is outside accepted callback branch')
    expected_path = 'INDEX_63' if selector == 63 else 'INDEX_0_TO_5'
    if context['index_63_checks'] != (1 if selector == 63 else 0):
        raise ValueError('SetSpellTimerFromBuff V2 callback selector branch differs')
    manager, lookup_selector = context['lookup_calls'][0]
    if manager != receiver + 0x3110 or lookup_selector != selector:
        raise ValueError('SetSpellTimerFromBuff V2 receiver lookup differs')
    call = context['receiver_calls'][0]
    if (call['target'] != targets[selector] + 0x38
            or call['u32_0x18'] != int.from_bytes(
                obj[0x18:0x1c].translate(tables['opaque_u32_0x18']), 'little')
            or call['u8_0x11'] != tables['opaque_u8_0x11'][obj[0x11]]
            or call['u32_0x1c'] != int.from_bytes(
                obj[0x1c:0x20].translate(tables['opaque_u32_0x1c']), 'little')
            or call['f32_0x14_bits'] != obj[0x14:0x18].translate(tables['opaque_f32_0x14'])
            or call['u8_0x10'] != tables['opaque_u8_0x10'][obj[0x10]]):
        raise ValueError('SetSpellTimerFromBuff V2 forwarded callback arguments differ')
    return {
        'native_receiver_slot_candidate': selector,
        'native_receiver_selection_path': expected_path,
        'native_receiver_forwarded_fields_witnessed': True,
    }


def decode_packet(emulator, context, tables, raw_param, payload,
                  *, callback_witness_v2=False):
    context['raw_param'] = raw_param
    native = emulator.decode(payload, PROFILE)
    return_al = native['deserialize_return_al']
    consumed = native['bytes_consumed']
    if return_al != 1 or not native['fully_consumed'] or consumed != len(payload):
        return failure('native SetSpellTimerFromBuff did not fully consume payload',
                       return_al=return_al, consumed=consumed)
    obj = bytes.fromhex(native['object_hex'])
    if len(obj) != PROFILE['object_size']:
        return failure('native SetSpellTimerFromBuff object size differs',
                       return_al=return_al, consumed=consumed)
    if struct.unpack_from('<Q', obj, 0)[0] != IMAGE_BASE + VTABLE_RVA:
        return failure('native SetSpellTimerFromBuff object vtable differs',
                       return_al=return_al, consumed=consumed)
    if struct.unpack_from('<H', obj, 8)[0] != PACKET_ID:
        return failure('native SetSpellTimerFromBuff packet ID differs',
                       return_al=return_al, consumed=consumed)
    if struct.unpack_from('<I', obj, 0x0c)[0] != raw_param:
        return failure('native SetSpellTimerFromBuff raw param differs from Replay',
                       return_al=return_al, consumed=consumed)
    offsets = (('opaque_u8_0x10', 0x10, 1), ('opaque_u8_0x11', 0x11, 1),
               ('opaque_f32_0x14', 0x14, 4), ('opaque_u32_0x18', 0x18, 4),
               ('opaque_u32_0x1c', 0x1c, 4), ('opaque_u8_0x20', 0x20, 1))
    fields = {}
    for name, offset, size in offsets:
        raw = obj[offset:offset + size]
        decoded = raw.translate(tables[name])
        fields['raw_' + name[7:] + '_hex'] = raw.hex()
        if name.startswith('opaque_f32'):
            value = struct.unpack('<f', decoded)[0]
            if not math.isfinite(value):
                return failure('callback-transformed f32 is nonfinite',
                               return_al=return_al, consumed=consumed)
        else:
            value = int.from_bytes(decoded, 'little')
        fields[name] = value
    if callback_witness_v2:
        fields.update(witness_receiver_call(emulator, context, tables))
    return {'status': 'DECODED', 'deserialize_return_al': return_al,
            'bytes_consumed': consumed, 'native_packet_id': PACKET_ID,
            'native_raw_param': raw_param, **fields}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--callback-witness-v2', action='store_true')
    options = parser.parse_args()
    digest = None
    try:
        packets = read_request()
        image, digest, _ = read_image(options.image)
        if digest != IMAGE_SHA256:
            raise ValueError('SetSpellTimerFromBuff runtime image SHA-256 mismatch')
        check_static_identity(image, callback_witness_v2=options.callback_witness_v2)
        tables = callback_tables(image)
        emulator, context = make_decoder_emulator(
            image, callback_witness_v2=options.callback_witness_v2)
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
                row = decode_packet(
                    emulator, context, tables, raw_param, payload,
                    callback_witness_v2=options.callback_witness_v2)
                if row['status'] != 'DECODED':
                    emulator, context = make_decoder_emulator(
                        image, callback_witness_v2=options.callback_witness_v2)
            except Exception as exc:
                row = failure(f'exact-runtime SetSpellTimerFromBuff emulation failed: {exc}')
                emulator, context = make_decoder_emulator(
                    image, callback_witness_v2=options.callback_witness_v2)
            row.update(binding)
            results.append(row)
        response = {'status': 'PASS', 'runtime_image_sha256': digest,
                    'callback_table_sha256': CALLBACK_TABLE_SHA256,
                    'results': results}
        if options.callback_witness_v2:
            response.update(
                callback_rva=f'0x{CALLBACK_RVA:08x}',
                receiver_lookup_rva=f'0x{RECEIVER_LOOKUP_RVA:08x}',
                receiver_call_rva=f'0x{RECEIVER_CALL_RVA:08x}',
                callback_region_sha256=CALLBACK_REGION_SHA256,
                receiver_lookup_region_sha256=RECEIVER_LOOKUP_REGION_SHA256,
                callback_witness_mode=CALLBACK_WITNESS_MODE,
            )
        json.dump(response, sys.stdout, separators=(',', ':'))
        sys.stdout.write('\n')
        return 0
    except Exception as exc:
        print(f'821 SetSpellTimerFromBuff exact-runtime decoder error: {exc}', file=sys.stderr)
        json.dump({'status': 'ERROR', 'runtime_image_sha256': digest,
                   'results': [], 'error': str(exc)}, sys.stdout,
                  separators=(',', ':'))
        sys.stdout.write('\n')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

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
CALLBACK_END_RVA = 0x009986cb
RECEIVER_WRITE_RVA = 0x00947f20
RECEIVER_WRITE_END_RVA = 0x00947f36
CALLBACK_FALLBACK_RVA = 0x0099868b
RECEIVER_SCALAR_WRITE_RVA = 0x00947f2a
RECEIVER_FLAG_WRITE_RVA = 0x00947f31
CALLBACK_REGION_SHA256 = 'f365aa3bc45e3a21abc7a8039cb9402ce270539a863a49b9333138e8a93321ab'
RECEIVER_WRITE_REGION_SHA256 = '550b1300a158e61bb8e7ee4502a0d823defcc9c694ab000198799d22f57d781e'
CALLBACK_WITNESS_MODE = 'NATIVE_SYNTHETIC_RECEIVER'
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


def check_static_identity(image, *, callback_witness_v2=False):
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
    if callback_witness_v2:
        if hashlib.sha256(image[CALLBACK_RVA:CALLBACK_END_RVA]).hexdigest() != CALLBACK_REGION_SHA256:
            raise ValueError('exact 821 SetSpellLevel callback region differs')
        if hashlib.sha256(image[RECEIVER_WRITE_RVA:RECEIVER_WRITE_END_RVA]).hexdigest() != RECEIVER_WRITE_REGION_SHA256:
            raise ValueError('exact 821 SetSpellLevel receiver write region differs')


def make_decoder_emulator(image, *, callback_witness_v2=False):
    emulator, context = make_emulator(image)
    if not callback_witness_v2:
        return emulator, context

    from unicorn import UC_HOOK_CODE
    from unicorn.x86_const import UC_X86_REG_RCX, UC_X86_REG_RDX

    context['callback_calls'] = []
    context['fallback_hits'] = 0
    context['scalar_write_hits'] = 0
    context['flag_write_hits'] = 0

    def capture_receiver_write(uc, _address, _size, _user_data):
        context['callback_calls'].append((
            uc.reg_read(UC_X86_REG_RCX),
            uc.reg_read(UC_X86_REG_RDX) & 0xffffffff,
        ))

    def capture_fallback(_uc, _address, _size, _user_data):
        context['fallback_hits'] += 1

    def capture_scalar_write(_uc, _address, _size, _user_data):
        context['scalar_write_hits'] += 1

    def capture_flag_write(_uc, _address, _size, _user_data):
        context['flag_write_hits'] += 1

    for rva, callback in (
            (RECEIVER_WRITE_RVA, capture_receiver_write),
            (CALLBACK_FALLBACK_RVA, capture_fallback),
            (RECEIVER_SCALAR_WRITE_RVA, capture_scalar_write),
            (RECEIVER_FLAG_WRITE_RVA, capture_flag_write)):
        emulator.emulator.hook_add(
            UC_HOOK_CODE, callback,
            begin=IMAGE_BASE + rva, end=IMAGE_BASE + rva,
        )
    return emulator, context


def witness_callback(emulator, context, tables):
    """Run the exact callback on native packet bytes with a synthetic receiver.

    The synthetic table proves only the callback's selection and write path.
    It cannot identify a Replay-time receiver, spell, or gameplay change.
    """
    import emulate_exact_packet_decoder as exact

    if 'callback_calls' not in context:
        raise ValueError('SetSpellLevel V2 callback hooks are unavailable')
    obj = bytes(emulator.emulator.mem_read(exact.OBJECT_ADDRESS, PROFILE['object_size']))
    selector = int.from_bytes(
        obj[0x10:0x14].translate(tables['opaque_u32_0x10']), 'little')
    scalar = int.from_bytes(
        obj[0x14:0x18].translate(tables['opaque_u32_0x14']), 'little')

    receiver = exact.WORK_BASE + 0x100000
    target_base = receiver + 0x2000
    targets = tuple(target_base + index * 0x40 for index in range(64))
    emulator.emulator.mem_write(receiver, bytes(0xd00))
    emulator.emulator.mem_write(target_base, bytes(64 * 0x40))
    for index, target in enumerate(targets):
        emulator.emulator.mem_write(receiver + 0xae0 + index * 8,
                                    struct.pack('<Q', target))
    context['callback_calls'].clear()
    context['fallback_hits'] = 0
    context['scalar_write_hits'] = 0
    context['flag_write_hits'] = 0

    callback_return = emulator.call(
        IMAGE_BASE + CALLBACK_RVA, rcx=receiver, rdx=exact.OBJECT_ADDRESS)
    if callback_return & 0xff != 1 or len(context['callback_calls']) != 1:
        raise ValueError('SetSpellLevel V2 callback did not call receiver once')
    if context['scalar_write_hits'] != 1:
        raise ValueError('SetSpellLevel V2 receiver scalar write was not witnessed')
    target, passed_scalar = context['callback_calls'][0]
    if target not in targets:
        raise ValueError('SetSpellLevel V2 callback selected an unknown receiver')
    slot = targets.index(target)
    source = 'FALLBACK_0' if context['fallback_hits'] == 1 else 'INDEXED'
    expected_source = 'INDEXED' if selector <= 63 else 'FALLBACK_0'
    expected_slot = selector if selector <= 63 else 0
    if (context['fallback_hits'] not in (0, 1)
            or source != expected_source or slot != expected_slot
            or passed_scalar != scalar):
        raise ValueError('SetSpellLevel V2 native receiver selection differs')

    native_scalar = struct.unpack(
        '<i', emulator.emulator.mem_read(target + 0x28, 4))[0]
    flag = emulator.emulator.mem_read(target + 0x2c, 1)[0]
    flag_written = context['flag_write_hits'] == 1
    if (not 0 <= native_scalar <= 6 or scalar > 0x7fffffff
            or native_scalar != min(scalar, 6)
            or context['flag_write_hits'] not in (0, 1)
            or flag not in (0, 1) or bool(flag) != flag_written
            or flag_written != (native_scalar > 0)):
        raise ValueError('SetSpellLevel V2 receiver scalar or flag differs')
    for other in targets:
        if other != target and emulator.emulator.mem_read(other + 0x28, 5) != bytes(5):
            raise ValueError('SetSpellLevel V2 callback wrote a different receiver')
    return {
        'native_receiver_slot_candidate': slot,
        'native_receiver_selection_source': source,
        'native_clamped_scalar_candidate': native_scalar,
        'native_positive_flag_written': flag_written,
    }


def decode_packet(emulator, context, tables, raw_param, payload,
                  *, callback_witness_v2=False):
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
    if callback_witness_v2:
        fields.update(witness_callback(emulator, context, tables))
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
            raise ValueError('SetSpellLevel runtime image SHA-256 mismatch')
        check_static_identity(image, callback_witness_v2=options.callback_witness_v2)
        tables = callback_tables()
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
                row = failure(f'exact-runtime SetSpellLevel emulation failed: {exc}')
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
                receiver_write_rva=f'0x{RECEIVER_WRITE_RVA:08x}',
                callback_region_sha256=CALLBACK_REGION_SHA256,
                receiver_write_region_sha256=RECEIVER_WRITE_REGION_SHA256,
                callback_witness_mode=CALLBACK_WITNESS_MODE,
            )
        json.dump(response, sys.stdout, separators=(',', ':'))
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

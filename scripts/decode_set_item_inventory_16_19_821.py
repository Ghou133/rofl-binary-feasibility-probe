#!/usr/bin/env python3
"""Decode exact KR 821 SetItem packet fields with the pinned client image.

The JavaScript caller owns ROFL framing and source binding. This helper runs
the exact client constructor and deserializer for selected 0x002d bodies and
inverts byte transforms from the same image. It does not infer transactions.
"""

import argparse
import hashlib
import json
import string
import struct
import sys
from pathlib import Path

import decode_mapview_inventory_16_19_821 as shared_inventory


REPLAY_VERSION = '16.19.821.7343'
IMAGE_SHA256 = shared_inventory.IMAGE_SHA256
IMAGE_BASE = shared_inventory.IMAGE_BASE
MAX_INPUT_BYTES = 2_000_000
MAX_PACKETS = 256
PAYLOAD_BYTES = 7
PACKET_ID = 0x002d
CANONICAL_PARAMS = frozenset(range(0x400000ae, 0x400000b8))
OBSERVED_VARIANT_PARAMS = frozenset({0x400001b2})

FACTORY_TABLE_RVA = 0xf0e4bc
FACTORY_CASE_RVA = 0xefea41
CONSTRUCTOR_RVA = 0xecd170
OBJECT_VTABLE_RVA = 0x1ba5838
DESERIALIZER_RVA = 0x1056660
NESTED_INIT_RVA = 0xecfc40
NESTED_VTABLE_RVA = 0x1ba5680
NESTED_READER_RVA = 0x105f4f0
REGISTRATION_CLOSURE_LEA_RVA = 0x3245fe
REGISTRATION_CALLBACK_LEA_RVA = 0x324618
REGISTRATION_OPCODE_RVA = 0x324645
REGISTRATION_CALL_RVA = 0x32465c
CLOSURE_VTABLE_RVA = 0x1acfdc8
TYPE_FUNCTION_RVA = 0x36cc30
TYPE_DESCRIPTOR_RVA = 0x1f2feb0
CALLBACK_RVA = 0x3510e0

OBJECT_SIZE = 0x90
NESTED_VTABLE_OFFSET = 0x10
SLOT_OFFSET = 0x18
ITEM_ID_OFFSET = 0x48


def failure(message, *, return_al=None, consumed=None):
    return {'status': 'FAILED', 'deserialize_return_al': return_al,
            'bytes_consumed': consumed, 'slot': None, 'item_id': None,
            'error': message}


def rip_target(image, instruction_rva):
    if image[instruction_rva:instruction_rva + 3] != b'\x48\x8d\x05':
        raise ValueError('exact 821 SetItem LEA differs')
    return instruction_rva + 7 + struct.unpack_from('<i', image, instruction_rva + 3)[0]


def call_target(image, instruction_rva):
    if image[instruction_rva] != 0xe8:
        raise ValueError('exact 821 SetItem CALL differs')
    return instruction_rva + 5 + struct.unpack_from('<i', image, instruction_rva + 1)[0]


def check_static_identity(image):
    if struct.unpack_from('<I', image, FACTORY_TABLE_RVA + PACKET_ID * 4)[0] != FACTORY_CASE_RVA \
            or image[FACTORY_CASE_RVA:FACTORY_CASE_RVA + 5] != b'\xb9\x90\x00\x00\x00' \
            or call_target(image, FACTORY_CASE_RVA + 0x14) != CONSTRUCTOR_RVA:
        raise ValueError('exact 821 0x002d factory route differs')
    if image[CONSTRUCTOR_RVA + 0xd:CONSTRUCTOR_RVA + 0x13] != b'\x66\xc7\x41\x08\x2d\x00' \
            or rip_target(image, CONSTRUCTOR_RVA + 0x22) != OBJECT_VTABLE_RVA \
            or struct.unpack_from('<Q', image, OBJECT_VTABLE_RVA + 8)[0] != IMAGE_BASE + DESERIALIZER_RVA:
        raise ValueError('exact 821 0x002d constructor or deserializer differs')
    if call_target(image, CONSTRUCTOR_RVA + 0x30) != NESTED_INIT_RVA \
            or rip_target(image, NESTED_INIT_RVA + 0x10) != NESTED_VTABLE_RVA \
            or struct.unpack_from('<Q', image, NESTED_VTABLE_RVA + 8)[0] != IMAGE_BASE + NESTED_READER_RVA:
        raise ValueError('exact 821 SetItem nested reader differs')
    if rip_target(image, REGISTRATION_CLOSURE_LEA_RVA) != CLOSURE_VTABLE_RVA \
            or rip_target(image, REGISTRATION_CALLBACK_LEA_RVA) != CALLBACK_RVA \
            or image[REGISTRATION_OPCODE_RVA:REGISTRATION_OPCODE_RVA + 6] != b'\x41\xb8\x2d\x00\x00\x00' \
            or call_target(image, REGISTRATION_CALL_RVA) != 0x711e90:
        raise ValueError('exact 821 SetItem callback registration differs')
    if struct.unpack_from('<Q', image, CLOSURE_VTABLE_RVA + 0x18)[0] != IMAGE_BASE + TYPE_FUNCTION_RVA \
            or rip_target(image, TYPE_FUNCTION_RVA) != TYPE_DESCRIPTOR_RVA:
        raise ValueError('exact 821 SetItem closure type differs')
    descriptor = image[TYPE_DESCRIPTOR_RVA + 16:TYPE_DESCRIPTOR_RVA + 256]
    if b'HeroInventoryClient' not in descriptor or b'PKT_SetItem_s' not in descriptor:
        raise ValueError('exact 821 SetItem class name differs')


def read_request():
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError(f'input exceeds {MAX_INPUT_BYTES} bytes')
    request = json.loads(raw)
    if not isinstance(request, dict) or request.get('replay_version') != REPLAY_VERSION:
        raise ValueError(f'replay_version must be exactly {REPLAY_VERSION}')
    packets = request.get('packets')
    if not isinstance(packets, list) or len(packets) > MAX_PACKETS:
        raise ValueError(f'packets must be an array with at most {MAX_PACKETS} entries')
    return packets


def validate_packet(packet):
    if not isinstance(packet, dict):
        raise ValueError('packet must be an object')
    raw_param = packet.get('raw_param')
    if type(raw_param) is not int or raw_param not in CANONICAL_PARAMS | OBSERVED_VARIANT_PARAMS:
        raise ValueError('raw_param is outside observed exact 821 SetItem family')
    stream = packet.get('chunk_stream')
    if stream != 'game_chunk':
        raise ValueError('SetItem route was observed only in game chunks')
    payload_hex = packet.get('payload_hex')
    if not isinstance(payload_hex, str) or len(payload_hex) != PAYLOAD_BYTES * 2 \
            or any(character not in string.hexdigits for character in payload_hex):
        raise ValueError('payload_hex must be exactly seven hexadecimal bytes')
    payload = bytes.fromhex(payload_hex)
    if payload[0] != 0x1e:
        raise ValueError('payload selector differs from observed 821 SetItem scope')
    return raw_param, stream, payload


def make_emulator(image):
    from unicorn.x86_const import UC_X86_REG_GS_BASE

    emulator, context = shared_inventory.make_emulator(image)
    # The exact reader's first use checks the Windows TLS epoch through GS.
    # This supplies host thread plumbing only; client packet code runs intact.
    teb = 0x400000000
    tls_array = teb + 0x1000
    tls_block = teb + 0x2000
    emulator.emulator.mem_map(teb, 0x4000)
    emulator.emulator.reg_write(UC_X86_REG_GS_BASE, teb)
    emulator.emulator.mem_write(teb + 0x58, struct.pack('<Q', tls_array))
    emulator.emulator.mem_write(tls_array, struct.pack('<Q', tls_block))
    emulator.emulator.mem_write(tls_block + 0x140, struct.pack('<i', -1))
    return emulator, context


def decode_packet(emulator, context, slot_inverse, item_inverse, raw_param, payload):
    import emulate_exact_packet_decoder as exact

    context['raw_param'] = raw_param
    native = emulator.decode(payload, {
        'constructor_rva': CONSTRUCTOR_RVA,
        'deserialize_rva': DESERIALIZER_RVA,
        'object_size': OBJECT_SIZE,
        'fields': [],
    })
    return_al = native['deserialize_return_al']
    consumed = native['bytes_consumed']
    if return_al != 1 or not native['fully_consumed']:
        return failure('exact client deserializer did not fully consume payload',
                       return_al=return_al, consumed=consumed)
    obj = bytes(emulator.emulator.mem_read(exact.OBJECT_ADDRESS, OBJECT_SIZE))
    if struct.unpack_from('<H', obj, 8)[0] != PACKET_ID \
            or struct.unpack_from('<I', obj, 0x0c)[0] != raw_param \
            or struct.unpack_from('<Q', obj, NESTED_VTABLE_OFFSET)[0] != IMAGE_BASE + NESTED_VTABLE_RVA:
        return failure('native SetItem object identity differs from Replay framing',
                       return_al=return_al, consumed=consumed)
    raw_slot = obj[SLOT_OFFSET]
    slot = slot_inverse[raw_slot]
    raw_item = obj[ITEM_ID_OFFSET:ITEM_ID_OFFSET + 4]
    item_id = struct.unpack('<I', bytes(item_inverse[byte] for byte in raw_item))[0]
    if slot != 8:
        return failure('native SetItem slot differs from observed exact 821 scope',
                       return_al=return_al, consumed=consumed)
    return {'status': 'DECODED', 'deserialize_return_al': return_al,
            'bytes_consumed': consumed, 'slot': slot, 'item_id': item_id,
            'raw_slot_byte_hex': f'{raw_slot:02x}',
            'raw_item_id_bytes_hex': raw_item.hex()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    options = parser.parse_args()
    digest = None
    try:
        packets = read_request()
        image, digest, table = shared_inventory.read_image(options.image)
        check_static_identity(image)
        slot_inverse, item_inverse = shared_inventory.record_inverses(table)
        emulator, context = make_emulator(image)
        results = []
        for index, packet in enumerate(packets):
            try:
                raw_param, stream, payload = validate_packet(packet)
            except ValueError as exc:
                row = failure(str(exc))
                row.update(input_index=index, raw_param=None, chunk_stream=None,
                           raw_payload_sha256=None)
                results.append(row)
                continue
            binding = {'input_index': index, 'raw_param': raw_param,
                       'chunk_stream': stream,
                       'raw_payload_sha256': hashlib.sha256(payload).hexdigest()}
            try:
                row = decode_packet(emulator, context, slot_inverse, item_inverse,
                                    raw_param, payload)
                row.update(binding)
                results.append(row)
                if row['status'] != 'DECODED':
                    emulator, context = make_emulator(image)
            except Exception as exc:
                row = failure(f'exact-runtime emulation failed: {exc}')
                row.update(binding)
                results.append(row)
                emulator, context = make_emulator(image)
        json.dump({'status': 'PASS', 'runtime_image_sha256': digest,
                   'results': results}, sys.stdout, separators=(',', ':'))
        sys.stdout.write('\n')
        return 0
    except Exception as exc:
        print(f'821 SetItem exact-runtime decoder error: {exc}', file=sys.stderr)
        json.dump({'status': 'ERROR', 'runtime_image_sha256': digest,
                   'results': [], 'error': str(exc)}, sys.stdout,
                  separators=(',', ':'))
        sys.stdout.write('\n')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
"""Decode exact KR 821 SetInventory Broadcast packet bodies with the pinned image.

The JavaScript caller owns Replay framing and source binding. This helper runs
the exact client constructor and deserializer for selected 0x0357 bodies. The
byte inverses are reused from the same-image inventory record reader used by
0x018d; no inventory lifecycle or transaction is inferred here.
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
MAX_PACKETS = 512
MIN_OBSERVED_PAYLOAD_BYTES = 76
MAX_OBSERVED_PAYLOAD_BYTES = 166
CANONICAL_PARAMS = frozenset(range(0x400000ae, 0x400000b8))
OBSERVED_VARIANT_PARAMS = frozenset({0x400001af, 0x400001b1, 0x400001b3,
                                     0x400002af})
PACKET_ID = 0x0357
FACTORY_TABLE_RVA = 0xf0e4bc
FACTORY_CASE_RVA = 0xf08e27
CONSTRUCTOR_RVA = 0xebd7e0
DESERIALIZER_RVA = 0x10410c0
OBJECT_VTABLE_RVA = 0x1ba5778
VECTOR_VTABLE_RVA = 0x1ba5720
VECTOR_READER_RVA = 0x1040d40
REGISTRATION_CLOSURE_LEA_RVA = 0x324448
REGISTRATION_CALLBACK_LEA_RVA = 0x324462
REGISTRATION_OPCODE_RVA = 0x32448f
CLOSURE_VTABLE_RVA = 0x1acfd38
TYPE_FUNCTION_RVA = 0x36cb50
TYPE_DESCRIPTOR_RVA = 0x1f301c0
CALLBACK_THUNK_RVA = 0x350240
CALLBACK_BODY_RVA = 0x354c60
OBJECT_SIZE = 0x30
VECTOR_OFFSET = 0x18
RECORD_SIZE = 0xa8
SLOT_OFFSET = 0x10
ITEM_ID_OFFSET = 0x40


def failure(message, *, return_al=None, consumed=None):
    return {'status': 'FAILED', 'deserialize_return_al': return_al,
            'bytes_consumed': consumed, 'record_count': None, 'records': [],
            'error': message}


def rip_target(image, instruction_rva):
    if image[instruction_rva:instruction_rva + 3] != b'\x48\x8d\x05':
        raise ValueError('exact 821 registration LEA differs')
    return instruction_rva + 7 + struct.unpack_from('<i', image, instruction_rva + 3)[0]


def check_static_identity(image):
    if struct.unpack_from('<I', image, FACTORY_TABLE_RVA + PACKET_ID * 4)[0] != FACTORY_CASE_RVA:
        raise ValueError('exact 821 0x0357 factory route differs')
    if image[CONSTRUCTOR_RVA:CONSTRUCTOR_RVA + 4] != b'\x66\xc7\x41\x08' \
            or struct.unpack_from('<H', image, CONSTRUCTOR_RVA + 4)[0] != PACKET_ID:
        raise ValueError('exact 821 0x0357 constructor differs')
    if struct.unpack_from('<Q', image, OBJECT_VTABLE_RVA + 8)[0] != IMAGE_BASE + DESERIALIZER_RVA:
        raise ValueError('exact 821 0x0357 deserializer route differs')
    if rip_target(image, CONSTRUCTOR_RVA + 0x2e) != VECTOR_VTABLE_RVA \
            or struct.unpack_from('<Q', image, VECTOR_VTABLE_RVA + 8)[0] != IMAGE_BASE + VECTOR_READER_RVA:
        raise ValueError('exact 821 0x0357 vector reader differs')
    if rip_target(image, REGISTRATION_CLOSURE_LEA_RVA) != CLOSURE_VTABLE_RVA \
            or rip_target(image, REGISTRATION_CALLBACK_LEA_RVA) != CALLBACK_THUNK_RVA \
            or image[REGISTRATION_OPCODE_RVA:REGISTRATION_OPCODE_RVA + 6] != b'\x41\xb8\x57\x03\x00\x00':
        raise ValueError('exact 821 0x0357 callback registration differs')
    if struct.unpack_from('<Q', image, CLOSURE_VTABLE_RVA + 0x18)[0] != IMAGE_BASE + TYPE_FUNCTION_RVA \
            or rip_target(image, TYPE_FUNCTION_RVA) != TYPE_DESCRIPTOR_RVA:
        raise ValueError('exact 821 Broadcast closure type differs')
    descriptor = image[TYPE_DESCRIPTOR_RVA + 16:TYPE_DESCRIPTOR_RVA + 256]
    if b'HeroInventoryClient' not in descriptor \
            or b'PKT_S2C_SetInventory_Broadcast_s' not in descriptor:
        raise ValueError('exact 821 Broadcast class name differs')
    if image[CALLBACK_THUNK_RVA:CALLBACK_THUNK_RVA + 4] != b'\x48\x83\xc2\x10':
        raise ValueError('exact 821 Broadcast callback thunk differs')
    if image[CALLBACK_THUNK_RVA + 4] != 0xe9 \
            or CALLBACK_THUNK_RVA + 9 + struct.unpack_from('<i', image, CALLBACK_THUNK_RVA + 5)[0] != CALLBACK_BODY_RVA:
        raise ValueError('exact 821 Broadcast callback target differs')


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
        raise ValueError('raw_param is outside observed exact 821 Broadcast family')
    stream = packet.get('chunk_stream')
    if stream not in ('game_chunk', 'keyframe'):
        raise ValueError('chunk_stream is outside observed exact 821 Broadcast scope')
    if raw_param in OBSERVED_VARIANT_PARAMS and stream != 'game_chunk':
        raise ValueError('noncanonical raw_param was observed only in game chunks')
    payload_hex = packet.get('payload_hex')
    if not isinstance(payload_hex, str) or len(payload_hex) % 2 \
            or any(character not in string.hexdigits for character in payload_hex):
        raise ValueError('payload_hex must be even-length hexadecimal text')
    payload = bytes.fromhex(payload_hex)
    if not MIN_OBSERVED_PAYLOAD_BYTES <= len(payload) <= MAX_OBSERVED_PAYLOAD_BYTES \
            or payload[0] != 0x1e:
        raise ValueError('payload differs from observed exact 821 Broadcast scope')
    return raw_param, stream, payload


def make_emulator(image):
    from unicorn.x86_const import UC_X86_REG_GS_BASE

    emulator, context = shared_inventory.make_emulator(image)
    # Vector first use reads the Windows TLS epoch via GS. This supplies only
    # host thread plumbing; the client packet deserializer runs unchanged.
    teb = 0x400000000
    tls_array = teb + 0x1000
    tls_block = teb + 0x2000
    emulator.emulator.mem_map(teb, 0x4000)
    emulator.emulator.reg_write(UC_X86_REG_GS_BASE, teb)
    emulator.emulator.mem_write(teb + 0x58, struct.pack('<Q', tls_array))
    emulator.emulator.mem_write(tls_array, struct.pack('<Q', tls_block))
    emulator.emulator.mem_write(tls_block + 0x140, struct.pack('<i', -1))
    return emulator, context


def decode_packet(emulator, context, slot_inverse, item_inverse, raw_param, stream, payload):
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
            or struct.unpack_from('<I', obj, 0x0c)[0] != raw_param:
        return failure('native object identity differs from Replay framing',
                       return_al=return_al, consumed=consumed)
    pointer, count, capacity = struct.unpack_from('<QII', obj, VECTOR_OFFSET)
    if count > capacity or (count > 0 and pointer == 0) \
            or (stream == 'keyframe' and count != 10) \
            or (stream == 'game_chunk' and not 6 <= count <= 9):
        return failure('native Broadcast vector differs from observed stream bounds',
                       return_al=return_al, consumed=consumed)
    records = []
    prior_slot = -1
    for index in range(count):
        record = bytes(emulator.emulator.mem_read(pointer + index * RECORD_SIZE, RECORD_SIZE))
        raw_slot = record[SLOT_OFFSET]
        slot = slot_inverse[raw_slot]
        raw_item = record[ITEM_ID_OFFSET:ITEM_ID_OFFSET + 4]
        item_id = struct.unpack('<I', bytes(item_inverse[byte] for byte in raw_item))[0]
        if slot > 9 or slot <= prior_slot \
                or (stream == 'game_chunk' and slot == 9) \
                or (stream == 'keyframe' and slot != index):
            return failure('native Broadcast slot differs from observed ordered layout',
                           return_al=return_al, consumed=consumed)
        prior_slot = slot
        records.append({'record_index': index, 'slot': slot, 'item_id': item_id,
                        'raw_slot_byte_hex': f'{raw_slot:02x}',
                        'raw_item_id_bytes_hex': raw_item.hex()})
    return {'status': 'DECODED', 'deserialize_return_al': return_al,
            'bytes_consumed': consumed, 'record_count': count, 'records': records}


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
                                    raw_param, stream, payload)
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
        print(f'821 Broadcast exact-runtime decoder error: {exc}', file=sys.stderr)
        json.dump({'status': 'ERROR', 'runtime_image_sha256': digest,
                   'results': [], 'error': str(exc)}, sys.stdout,
                  separators=(',', ':'))
        sys.stdout.write('\n')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

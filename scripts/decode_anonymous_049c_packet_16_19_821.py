#!/usr/bin/env python3
"""Exact-821 numeric 0x049c native nested bytes and dynamic byte vector.

The pinned decoder owns packet processing. Only a proven memset leaf is replaced
with its host-memory semantics because this Unicorn build lacks its AVX path.
No game object lookup, callback, actor or gameplay effect is stubbed.
"""
import argparse
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

from decode_mapview_inventory_16_19_821 import make_emulator, read_image

BUILD = '16.19.821.7343'
IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325'
PACKET_ID = 0x049c
CONSTRUCTOR_RVA = 0xe9a6c0
DESERIALIZER_RVA = 0x10d0d30
VTABLE_RVA = 0x1ba8de8
NESTED_VTABLE_RVA = 0x1ba8dc0
MEMSET_LEAF_RVA = 0x1a653c3
MEMSET_PREFIX_SHA256 = '961ec6b7a19ad835ada16a4cd076ebd87c7038c770e0ca8db6cf0aa6b04b3d38'
PROFILE = {'constructor_rva': CONSTRUCTOR_RVA, 'deserialize_rva': DESERIALIZER_RVA,
           'object_size': 0x38, 'fields': []}
LENGTHS = {
    1: frozenset([5, 6, *range(9, 41), 42, 48, 49, 52]),
    2: frozenset([5, 6, *range(10, 38), 39, 49, 52]),
}
MAX_PACKETS = 10_000
MAX_INPUT_BYTES = 4_000_000
MAX_VECTOR_BYTES = 64


def create_emulator(image):
    import emulate_exact_packet_decoder as exact
    from unicorn import UC_HOOK_CODE
    prefix = image[0x1a653a0:MEMSET_LEAF_RVA]
    if hashlib.sha256(prefix).hexdigest() != MEMSET_PREFIX_SHA256:
        raise ValueError('exact 821 memset prefix differs')
    if struct.unpack_from('<I', image, 0xf0e4bc + PACKET_ID * 4)[0] != 0xf0cfeb:
        raise ValueError('exact 821 factory route differs')
    if struct.unpack_from('<Q', image, VTABLE_RVA + 8)[0] != 0x7ff67f410000 + DESERIALIZER_RVA:
        raise ValueError('exact 821 vtable decoder differs')
    emulator, context = make_emulator(image)
    emulator.emulator.hook_add(UC_HOOK_CODE, emulator._memset_leaf,
        begin=exact.IMAGE_BASE + MEMSET_LEAF_RVA, end=exact.IMAGE_BASE + MEMSET_LEAF_RVA)
    return emulator, context


def validate_packet(packet):
    if not isinstance(packet, dict) or packet.get('packet_id') != PACKET_ID:
        raise ValueError('packet must have numeric route 0x049c')
    stream = packet.get('stream_tag')
    raw_param = packet.get('raw_param')
    if type(stream) is not int or stream not in LENGTHS:
        raise ValueError('observed game/keyframe stream is required')
    if type(raw_param) is not int or not 0 < raw_param <= 0xffffffff:
        raise ValueError('raw_param must be a nonzero uint32')
    text = packet.get('payload_hex')
    if not isinstance(text, str) or len(text) % 2 or len(text) > 104 or not re.fullmatch(r'[0-9a-fA-F]*', text):
        raise ValueError('bounded hexadecimal payload is required')
    payload = bytes.fromhex(text)
    if len(payload) not in LENGTHS[stream]:
        raise ValueError('payload is outside observed exact-821 stream/length shapes')
    return raw_param, payload


def decode_packet(emulator, context, packet):
    import emulate_exact_packet_decoder as exact
    raw_param, payload = validate_packet(packet)
    context['raw_param'] = raw_param
    result = emulator.decode(payload, PROFILE)
    if result['deserialize_return_al'] != 1 or not result['fully_consumed']:
        raise ValueError('native decoder did not accept and fully consume payload')
    obj = bytes(emulator.emulator.mem_read(exact.OBJECT_ADDRESS, 0x38))
    if struct.unpack_from('<H', obj, 8)[0] != PACKET_ID or struct.unpack_from('<I', obj, 12)[0] != raw_param:
        raise ValueError('native opcode/raw-param differs')
    if struct.unpack_from('<Q', obj, 0)[0] != exact.IMAGE_BASE + VTABLE_RVA or struct.unpack_from('<Q', obj, 16)[0] != exact.IMAGE_BASE + NESTED_VTABLE_RVA:
        raise ValueError('native outer/nested vtable differs')
    pointer, count, capacity = struct.unpack_from('<QII', obj, 0x28)
    if count > capacity or count > MAX_VECTOR_BYTES:
        raise ValueError('native byte vector exceeds bounded observed scope')
    if count and not (exact.HEAP_BASE <= pointer and pointer + count <= emulator.heap_cursor):
        raise ValueError('native byte vector is outside current allocated emulator heap')
    vector = bytes(emulator.emulator.mem_read(pointer, count)) if count else b''
    visible = vector[:-1] if vector.endswith(b'\x00') else vector
    printable = bool(visible) and all(0x20 <= value <= 0x7e for value in visible)
    return {'status': 'NATIVE_ACCEPTED', 'deserialize_return_al': 1,
        'bytes_consumed': len(payload), 'native_nested_field_bytes_hex':
            {'0x18': obj[0x18:0x19].hex(), '0x1c': obj[0x1c:0x20].hex(),
             '0x20': obj[0x20:0x23].hex()},
        'native_byte_vector_length': count, 'native_byte_vector_hex': vector.hex(),
        'native_byte_vector_ascii_candidate': visible.decode('ascii') if printable else None,
        'native_byte_vector_text_status': 'PRINTABLE_ASCII_CANDIDATE' if printable else 'OPAQUE_BYTES',
        'native_byte_vector_terminal_nul': vector.endswith(b'\x00')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    args = parser.parse_args()
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError('native request exceeds bounded size')
    request = json.loads(raw)
    packets = request.get('packets') if isinstance(request, dict) else None
    if not isinstance(request, dict) or request.get('replay_version') != BUILD or not isinstance(packets, list) or len(packets) > MAX_PACKETS:
        raise ValueError('exact build and bounded packets array are required')
    image, image_sha, _ = read_image(args.image)
    emulator, context = create_emulator(image)
    rows = []
    for index, packet in enumerate(packets):
        try:
            rows.append({'index': index, **decode_packet(emulator, context, packet)})
        except Exception as error:
            rows.append({'index': index, 'status': 'FAILED', 'error': str(error)})
    print(json.dumps({'replay_version': BUILD, 'runtime_image_sha256': image_sha,
        'memory_compatibility': {'operation': 'MEMSET_ONLY', 'leaf_rva': hex(MEMSET_LEAF_RVA),
            'prefix_sha256': MEMSET_PREFIX_SHA256}, 'rows': rows}, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'status': 'FAILED', 'error': str(error)}))
        raise SystemExit(1)

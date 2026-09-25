#!/usr/bin/env python3
"""Decode the exact 821 OnEvent/ParamsHeal packet candidate fields.

JavaScript owns Replay framing and packet provenance. The pinned client image
owns the OnEvent constructor/deserializer. Its callback transforms the child
event ID; its ParamsHeal handler reads the reported f32 at child offset 0x18.
No effective-heal or actor-role interpretation is made here.
"""

import argparse
import hashlib
import json
import math
import string
import struct
import sys
from pathlib import Path

from decode_mapview_inventory_16_19_821 import make_emulator
from emulate_exact_packet_decoder import HEAP_BASE, HEAP_SIZE


BUILD = '16.19.821.7343'
IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325'
IMAGE_BASE = 0x7ff67f410000
PACKET_ID = 0x040a
EVENT_ID = 0x004b
VTABLE_RVA = 0x01ba6ea8
PROFILE = {'constructor_rva': 0x00e9eb00, 'deserialize_rva': 0x00ffbe20,
           'object_size': 0x28, 'fields': []}
MAX_IMAGE_BYTES = 64 * 1024 * 1024
MAX_INPUT_BYTES = 4_000_000
MAX_PACKETS = 20_000
PAYLOAD_LENGTH = 60
BLOB_LENGTH = 52


def ror8(value, count):
    return ((value >> count) | (value << (8 - count))) & 0xff


def decode_event_id_byte(raw):
    # Exact PKT_OnEvent_s receive callback RVA 0x4ce450..0x4ce472.
    value = ror8((raw - 0x73) & 0xff, 2)
    value = ((~value) - 0x4a) & 0xff
    value = ror8(value, 7)
    shuffle = ((((value & 0xd5) << 1) | ((value >> 1) & 0x55)) & 0xff)
    return ror8(shuffle, 4)


def read_request():
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError('ParamsHeal request exceeds bounded input size')
    request = json.loads(raw)
    if not isinstance(request, dict) or request.get('replay_version') != BUILD:
        raise ValueError(f'replay_version must be exactly {BUILD}')
    packets = request.get('packets')
    if not isinstance(packets, list) or len(packets) > MAX_PACKETS:
        raise ValueError(f'packets must be an array with at most {MAX_PACKETS} entries')
    return packets


def read_image(path):
    if not path.is_file() or path.stat().st_size > MAX_IMAGE_BYTES:
        raise ValueError('runtime image is missing, not a file, or exceeds the bounded size')
    image = path.read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    if digest != IMAGE_SHA256 or len(image) != 48488448:
        raise ValueError(f'ParamsHeal runtime image SHA-256 mismatch: {digest}')
    return image, digest


def validate_packet(packet):
    if not isinstance(packet, dict) or packet.get('packet_id') != PACKET_ID:
        raise ValueError('packet ID must be exact 821 PKT_OnEvent_s route')
    if packet.get('stream_tag') != 1:
        raise ValueError('ParamsHeal candidate requires observed game stream')
    raw_param = packet.get('raw_param')
    if type(raw_param) is not int or not 0 < raw_param <= 0xffffffff:
        raise ValueError('raw_param must be a nonzero unsigned 32-bit integer')
    payload_hex = packet.get('payload_hex')
    if not isinstance(payload_hex, str) or len(payload_hex) != PAYLOAD_LENGTH * 2:
        raise ValueError('payload_hex must encode one observed 60-byte OnEvent packet')
    if any(character not in string.hexdigits for character in payload_hex):
        raise ValueError('payload_hex contains non-hexadecimal characters')
    return raw_param, bytes.fromhex(payload_hex)


def make_runtime(image):
    from unicorn import UC_HOOK_CODE
    from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8

    emulator, context = make_emulator(image)

    # The image's CRT memset uses AVX unavailable in Unicorn. This hook only
    # supplies the ordinary host-memory fill contract; packet logic runs native.
    def memset(_uc, _address, _size, _user_data):
        target = emulator.emulator.reg_read(UC_X86_REG_RCX)
        fill = emulator.emulator.reg_read(UC_X86_REG_RDX) & 255
        length = emulator.emulator.reg_read(UC_X86_REG_R8)
        if length > 0x100000:
            raise RuntimeError(f'unexpected native memset length {length}')
        emulator.emulator.mem_write(target, bytes([fill]) * length)
        emulator.emulator.reg_write(UC_X86_REG_RAX, target)
        emulator._return_from_stub()

    emulator.emulator.hook_add(UC_HOOK_CODE, memset,
        begin=IMAGE_BASE + 0x1a653a0, end=IMAGE_BASE + 0x1a653a0)
    return emulator, context


def decode_packet(emulator, context, raw_param, payload):
    context['raw_param'] = raw_param
    native = emulator.decode(payload, PROFILE)
    if native['deserialize_return_al'] != 1 or not native['fully_consumed'] \
            or native['bytes_consumed'] != len(payload):
        raise ValueError('native OnEvent deserializer did not fully consume payload')
    obj = bytes.fromhex(native['object_hex'])
    if len(obj) != PROFILE['object_size']:
        raise ValueError('native OnEvent object size differs')
    if struct.unpack_from('<Q', obj, 0)[0] != IMAGE_BASE + VTABLE_RVA:
        raise ValueError('native OnEvent vtable differs')
    if struct.unpack_from('<H', obj, 8)[0] != PACKET_ID:
        raise ValueError('native OnEvent packet ID differs')
    if struct.unpack_from('<I', obj, 0x0c)[0] != raw_param:
        raise ValueError('native OnEvent raw param differs from Replay')
    pointer, count, capacity = struct.unpack_from('<QII', obj, 0x10)
    if count != BLOB_LENGTH or capacity != BLOB_LENGTH \
            or pointer < HEAP_BASE or pointer + count > HEAP_BASE + HEAP_SIZE \
            or pointer + count > emulator.heap_cursor:
        raise ValueError('native OnEvent child blob differs from 52-byte ParamsHeal shape')
    raw_event_id = struct.unpack_from('<H', obj, 0x24)[0]
    event_id = (decode_event_id_byte(raw_event_id & 255)
                | (decode_event_id_byte(raw_event_id >> 8) << 8))
    if event_id != EVENT_ID:
        raise ValueError(f'native OnEvent child ID differs from ParamsHeal: 0x{event_id:04x}')
    blob = bytes(emulator.emulator.mem_read(pointer, count))
    amount = struct.unpack_from('<f', blob, 0x18)[0]
    if not math.isfinite(amount):
        raise ValueError('native ParamsHeal +0x18 reported amount is not finite')
    return {
        'status': 'DECODED', 'deserialize_return_al': 1,
        'bytes_consumed': len(payload), 'native_packet_id': PACKET_ID,
        'native_raw_param': raw_param, 'event_id': event_id,
        'raw_event_id_hex': f'0x{raw_event_id:04x}',
        'event_blob_length': count, 'event_blob_sha256': hashlib.sha256(blob).hexdigest(),
        'event_entity_u32_0x04': struct.unpack_from('<I', blob, 4)[0],
        'event_entity_u32_0x14': struct.unpack_from('<I', blob, 0x14)[0],
        'reported_amount_candidate': amount,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    options = parser.parse_args()
    digest = None
    try:
        packets = read_request()
        image, digest = read_image(options.image)
        emulator, context = make_runtime(image)
        results = []
        for index, packet in enumerate(packets):
            raw_param, payload = validate_packet(packet)
            result = decode_packet(emulator, context, raw_param, payload)
            result.update(input_index=index, raw_param=raw_param,
                          raw_payload_sha256=hashlib.sha256(payload).hexdigest())
            results.append(result)
        json.dump({'status': 'PASS', 'runtime_image_sha256': digest,
                   'results': results}, sys.stdout, separators=(',', ':'))
        sys.stdout.write('\n')
        return 0
    except Exception as exc:
        print(f'821 ParamsHeal exact-runtime decoder error: {exc}', file=sys.stderr)
        json.dump({'status': 'ERROR', 'runtime_image_sha256': digest,
                   'results': [], 'error': str(exc)}, sys.stdout,
                  separators=(',', ':'))
        sys.stdout.write('\n')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

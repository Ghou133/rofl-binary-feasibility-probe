#!/usr/bin/env python3
"""Decode exact 821 OnEvent ShieldingParams packet candidates with native code.

Replay framing and source binding belong to the JavaScript caller. This helper
runs the pinned client OnEvent constructor/deserializer, checks the callback's
child ID transform, and returns opaque child fields for pair validation.
"""

import argparse
import hashlib
import json
import math
import string
import struct
import sys
from pathlib import Path

from decode_params_heal_packet_16_19_821 import (
    BUILD,
    IMAGE_BASE,
    IMAGE_SHA256,
    PROFILE,
    decode_event_id_byte,
    make_runtime,
    read_image,
)
from emulate_exact_packet_decoder import HEAP_BASE, HEAP_SIZE


PACKET_ID = 0x040a
CHILD_EVENT_IDS = frozenset((0x00ef, 0x00f0))
RAW_EVENT_IDS = {0x00ef: 0x4951, 0x00f0: 0x492b}
VTABLE_RVA = 0x01ba6ea8
PAYLOAD_LENGTH = 29
BLOB_LENGTH = 20
SCHEMA_U32 = 469
MAX_INPUT_BYTES = 1_000_000
MAX_PACKETS = 3_000


def read_request():
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError('ShieldingParams request exceeds bounded input size')
    request = json.loads(raw)
    if not isinstance(request, dict) or request.get('replay_version') != BUILD:
        raise ValueError(f'replay_version must be exactly {BUILD}')
    packets = request.get('packets')
    if not isinstance(packets, list) or len(packets) > MAX_PACKETS:
        raise ValueError(f'packets must be an array with at most {MAX_PACKETS} entries')
    return packets


def validate_packet(packet):
    if not isinstance(packet, dict) or packet.get('packet_id') != PACKET_ID:
        raise ValueError('packet ID must be exact 821 PKT_OnEvent_s route')
    if packet.get('stream_tag') != 1:
        raise ValueError('ShieldingParams candidate requires observed game stream')
    raw_param = packet.get('raw_param')
    if type(raw_param) is not int or not 0 < raw_param <= 0xffffffff:
        raise ValueError('raw_param must be a nonzero unsigned 32-bit integer')
    payload_hex = packet.get('payload_hex')
    if not isinstance(payload_hex, str) or len(payload_hex) != PAYLOAD_LENGTH * 2:
        raise ValueError('payload_hex must encode one observed 29-byte OnEvent packet')
    if any(character not in string.hexdigits for character in payload_hex):
        raise ValueError('payload_hex contains non-hexadecimal characters')
    return raw_param, bytes.fromhex(payload_hex)


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
        raise ValueError('native OnEvent child blob differs from 20-byte ShieldingParams shape')
    raw_event_id = struct.unpack_from('<H', obj, 0x24)[0]
    event_id = (decode_event_id_byte(raw_event_id & 255)
                | (decode_event_id_byte(raw_event_id >> 8) << 8))
    if event_id not in CHILD_EVENT_IDS or raw_event_id != RAW_EVENT_IDS[event_id]:
        raise ValueError(f'native OnEvent child ID differs from 0x00ef/0x00f0: 0x{event_id:04x}')
    blob = bytes(emulator.emulator.mem_read(pointer, count))
    if struct.unpack_from('<I', blob, 0)[0] != SCHEMA_U32 \
            or struct.unpack_from('<I', blob, 4)[0] != 0:
        raise ValueError('native ShieldingParams child header differs from observed 821 shape')
    raw_float = struct.unpack_from('<f', blob, 0x10)[0]
    if not math.isfinite(raw_float):
        raise ValueError('native ShieldingParams +0x10 raw f32 is not finite')
    return {
        'status': 'DECODED', 'deserialize_return_al': 1,
        'bytes_consumed': len(payload), 'native_packet_id': PACKET_ID,
        'native_raw_param': raw_param, 'event_id': event_id,
        'raw_event_id_hex': f'0x{raw_event_id:04x}',
        'event_blob_length': count, 'event_blob_hex': blob.hex(),
        'event_blob_sha256': hashlib.sha256(blob).hexdigest(),
        'event_schema_u32_0x00': SCHEMA_U32,
        'event_reserved_u32_0x04': 0,
        'event_u32_0x08': struct.unpack_from('<I', blob, 8)[0],
        'event_u32_0x0c': struct.unpack_from('<I', blob, 12)[0],
        'event_raw_f32_0x10': raw_float,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    options = parser.parse_args()
    digest = None
    try:
        packets = read_request()
        image, digest = read_image(options.image)
        assert digest == IMAGE_SHA256
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
        print(f'821 ShieldingParams exact-runtime decoder error: {exc}', file=sys.stderr)
        json.dump({'status': 'ERROR', 'runtime_image_sha256': digest,
                   'results': [], 'error': str(exc)}, sys.stdout,
                  separators=(',', ':'))
        sys.stdout.write('\n')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

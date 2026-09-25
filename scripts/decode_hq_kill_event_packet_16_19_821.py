#!/usr/bin/env python3
"""Decode exact-821 OnEvent child 0x0046 as a packet-local candidate.

OnHQKill is the pinned image name-table label. The 108-byte child
blob is left anonymous: packet identity does not establish an actor, target,
state transition, or gameplay effect.
"""

import argparse
import hashlib
import json
import string
import struct
import sys
from pathlib import Path

from decode_params_heal_packet_16_19_821 import (
    BUILD, IMAGE_BASE, IMAGE_SHA256, PROFILE, VTABLE_RVA,
    decode_event_id_byte, make_runtime,
)
from emulate_exact_packet_decoder import HEAP_BASE, HEAP_SIZE


PACKET_ID = 0x040a
EVENT_ID = 0x0046
RAW_EVENT_ID = 0x4918
PAYLOAD_LENGTH = 116
BLOB_LENGTH = 108
EXPECTED_IMAGE_BYTES = 48_488_448
NAME_TABLE_RVA = 0x1ef7330
NAME_TABLE_STRIDE = 0x28
MAX_IMAGE_BYTES = 64 * 1024 * 1024
MAX_INPUT_BYTES = 1_000_000
MAX_PACKETS = 2_000


def read_request():
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError('OnHQKill request exceeds bounded input size')
    request = json.loads(raw)
    if not isinstance(request, dict) or request.get('replay_version') != BUILD:
        raise ValueError(f'replay_version must be exactly {BUILD}')
    packets = request.get('packets')
    if not isinstance(packets, list) or len(packets) > MAX_PACKETS:
        raise ValueError(f'packets must be an array with at most {MAX_PACKETS} entries')
    return packets


def check_image_identity(image):
    if struct.unpack_from('<Q', image, VTABLE_RVA + 8)[0] != IMAGE_BASE + PROFILE['deserialize_rva']:
        raise ValueError('exact 821 OnEvent deserializer vtable route differs')
    name_entry_rva = NAME_TABLE_RVA + EVENT_ID * NAME_TABLE_STRIDE
    name_rva = struct.unpack_from('<Q', image, name_entry_rva)[0] - IMAGE_BASE
    name = b'OnHQKill\0'
    if name_rva < 0 or image[name_rva:name_rva + len(name)] != name:
        raise ValueError('exact 821 child 0x0046 name table differs')


def read_image(path):
    if not path.is_file() or path.stat().st_size > MAX_IMAGE_BYTES:
        raise ValueError('runtime image is missing, not a file, or exceeds the bounded size')
    image = path.read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    if digest != IMAGE_SHA256 or len(image) != EXPECTED_IMAGE_BYTES:
        raise ValueError(f'OnHQKill runtime image SHA-256 mismatch: {digest}')
    check_image_identity(image)
    return image, digest


def validate_packet(packet):
    if not isinstance(packet, dict) or packet.get('packet_id') != PACKET_ID:
        raise ValueError('packet ID must be exact 821 PKT_OnEvent_s route')
    if packet.get('stream_tag') != 1:
        raise ValueError('OnHQKill candidate requires observed game stream')
    raw_param = packet.get('raw_param')
    if type(raw_param) is not int or not 0 < raw_param <= 0xffffffff:
        raise ValueError('raw_param must be a nonzero unsigned 32-bit integer')
    payload_hex = packet.get('payload_hex')
    if not isinstance(payload_hex, str) or len(payload_hex) != PAYLOAD_LENGTH * 2:
        raise ValueError('payload_hex must encode one observed 116-byte OnEvent packet')
    if any(character not in string.hexdigits for character in payload_hex):
        raise ValueError('payload_hex contains non-hexadecimal characters')
    return raw_param, bytes.fromhex(payload_hex)


def decode_packet(emulator, context, raw_param, payload):
    context['raw_param'] = raw_param
    native = emulator.decode(payload, PROFILE)
    if (native['deserialize_return_al'] != 1 or not native['fully_consumed']
            or native['bytes_consumed'] != PAYLOAD_LENGTH):
        raise ValueError('native OnEvent deserializer did not fully consume 116-byte payload')
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
    if (count != BLOB_LENGTH or capacity != BLOB_LENGTH
            or pointer < HEAP_BASE or pointer + count > HEAP_BASE + HEAP_SIZE
            or pointer + count > emulator.heap_cursor):
        raise ValueError('native OnEvent child blob differs from observed 108-byte shape')
    raw_event_id = struct.unpack_from('<H', obj, 0x24)[0]
    event_id = (decode_event_id_byte(raw_event_id & 255)
                | decode_event_id_byte(raw_event_id >> 8) << 8)
    if event_id != EVENT_ID or raw_event_id != RAW_EVENT_ID:
        raise ValueError(f'unexpected length-116 OnEvent child/raw ID: 0x{event_id:04x}/0x{raw_event_id:04x}')
    blob = bytes(emulator.emulator.mem_read(pointer, count))
    return {
        'status': 'DECODED', 'deserialize_return_al': 1,
        'bytes_consumed': PAYLOAD_LENGTH,
        'native_packet_id': PACKET_ID, 'native_raw_param': raw_param,
        'event_id': event_id, 'raw_event_id_hex': f'0x{raw_event_id:04x}',
        'event_blob_length': count, 'event_blob_hex': blob.hex(),
        'event_blob_sha256': hashlib.sha256(blob).hexdigest(),
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
        print(f'821 OnHQKill exact-runtime decoder error: {exc}', file=sys.stderr)
        json.dump({'status': 'ERROR', 'runtime_image_sha256': digest,
                   'results': [], 'error': str(exc)}, sys.stdout,
                  separators=(',', ':'))
        sys.stdout.write('\n')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

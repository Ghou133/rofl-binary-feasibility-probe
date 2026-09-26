#!/usr/bin/env python3
"""Classify exact-821 OnEvent child 0x0017 with the pinned native reader.

OnFirstBloodAssist is the runtime name-table label. This helper reports the
opaque child blob and does not infer an assist, participant, or game effect.
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
    decode_event_id_byte, make_runtime, read_image,
)
from emulate_exact_packet_decoder import HEAP_BASE, HEAP_SIZE


PACKET_ID = 0x040a
PAYLOAD_LENGTH = 16
BLOB_LENGTH = 8
CHILD_IDS = {0x0017: ('OnFirstBloodAssist', 0x49e4),
             0x002c: ('OnReviveAlly', 0x49ca)}
EVENT_TABLE_RVA = 0x1ef7330
MAX_INPUT_BYTES = 1_000_000
MAX_PACKETS = 2_000


def verify_image_route(image):
    if struct.unpack_from('<Q', image, VTABLE_RVA + 8)[0] != IMAGE_BASE + PROFILE['deserialize_rva']:
        raise ValueError('exact 821 OnEvent vtable/deserializer route differs')
    for child_id, (name, _) in CHILD_IDS.items():
        entry = EVENT_TABLE_RVA + child_id * 0x28
        string_rva = struct.unpack_from('<Q', image, entry)[0] - IMAGE_BASE
        expected = name.encode('ascii') + b'\0'
        if not 0 <= string_rva <= len(image) - len(expected) \
                or image[string_rva:string_rva + len(expected)] != expected:
            raise ValueError(f'exact 821 child 0x{child_id:04x} name-table label differs')


def read_request():
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError('OnFirstBloodAssist request exceeds bounded input size')
    request = json.loads(raw)
    if not isinstance(request, dict) or request.get('replay_version') != BUILD:
        raise ValueError(f'replay_version must be exactly {BUILD}')
    packets = request.get('packets')
    if not isinstance(packets, list) or len(packets) > MAX_PACKETS:
        raise ValueError(f'packets must be an array with at most {MAX_PACKETS} entries')
    return packets


def validate_packet(packet):
    if not isinstance(packet, dict) or packet.get('packet_id') != PACKET_ID \
            or packet.get('stream_tag') != 1:
        raise ValueError('expected game-stream exact 821 PKT_OnEvent_s packet')
    raw_param = packet.get('raw_param')
    if type(raw_param) is not int or not 0 < raw_param <= 0xffffffff:
        raise ValueError('raw_param must be a nonzero unsigned 32-bit integer')
    payload_hex = packet.get('payload_hex')
    if not isinstance(payload_hex, str) or len(payload_hex) != PAYLOAD_LENGTH * 2 \
            or any(character not in string.hexdigits for character in payload_hex):
        raise ValueError('payload_hex must encode one 16-byte OnEvent packet')
    return raw_param, bytes.fromhex(payload_hex)


def decode_packet(machine, context, raw_param, payload):
    context['raw_param'] = raw_param
    native = machine.decode(payload, PROFILE)
    if native['deserialize_return_al'] != 1 or not native['fully_consumed'] \
            or native['bytes_consumed'] != PAYLOAD_LENGTH:
        raise ValueError('native OnEvent deserializer did not fully consume 16 bytes')
    obj = bytes.fromhex(native['object_hex'])
    if len(obj) != PROFILE['object_size'] \
            or struct.unpack_from('<Q', obj, 0)[0] != IMAGE_BASE + VTABLE_RVA \
            or struct.unpack_from('<H', obj, 8)[0] != PACKET_ID \
            or struct.unpack_from('<I', obj, 0x0c)[0] != raw_param:
        raise ValueError('native OnEvent object identity differs')
    pointer, count, capacity = struct.unpack_from('<QII', obj, 0x10)
    if count != BLOB_LENGTH or capacity != BLOB_LENGTH \
            or pointer < HEAP_BASE or pointer + count > HEAP_BASE + HEAP_SIZE \
            or pointer + count > machine.heap_cursor:
        raise ValueError('native OnEvent child blob differs from observed 8-byte scope')
    raw_id = struct.unpack_from('<H', obj, 0x24)[0]
    child_id = (decode_event_id_byte(raw_id & 0xff)
                | (decode_event_id_byte(raw_id >> 8) << 8))
    if child_id not in CHILD_IDS or raw_id != CHILD_IDS[child_id][1]:
        raise ValueError(f'unexpected length-16 OnEvent child/raw ID 0x{child_id:04x}/0x{raw_id:04x}')
    blob = bytes(machine.emulator.mem_read(pointer, count))
    return {
        'status': 'DECODED' if child_id == 0x0017 else 'EXCLUDED_CHILD',
        'deserialize_return_al': 1, 'bytes_consumed': PAYLOAD_LENGTH,
        'native_packet_id': PACKET_ID, 'native_raw_param': raw_param,
        'event_id': child_id, 'raw_event_id_hex': f'0x{raw_id:04x}',
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
        if digest != IMAGE_SHA256:
            raise ValueError('exact 821 runtime image SHA-256 mismatch')
        verify_image_route(image)
        machine, context = make_runtime(image)
        results = []
        for index, packet in enumerate(packets):
            raw_param, payload = validate_packet(packet)
            row = decode_packet(machine, context, raw_param, payload)
            row.update(input_index=index, raw_param=raw_param,
                       raw_payload_sha256=hashlib.sha256(payload).hexdigest())
            results.append(row)
        json.dump({'status': 'PASS', 'runtime_image_sha256': digest,
                   'results': results}, sys.stdout, separators=(',', ':'))
        sys.stdout.write('\n')
        return 0
    except Exception as error:
        print(f'821 OnFirstBloodAssist exact-runtime decoder error: {error}', file=sys.stderr)
        json.dump({'status': 'ERROR', 'runtime_image_sha256': digest,
                   'results': [], 'error': str(error)}, sys.stdout, separators=(',', ':'))
        sys.stdout.write('\n')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

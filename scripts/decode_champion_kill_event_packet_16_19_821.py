#!/usr/bin/env python3
"""Decode exact 821 OnEvent child 0x0007 candidate packets with the pinned image.

The image's OnEvent constructor/deserializer and callback child-ID transform
own decoding. A registered OnChampionKill marker is exposed without assigning
killer, victim, or a confirmed game-state effect.
"""

import argparse
import hashlib
import json
import string
import struct
import sys
from pathlib import Path

from decode_params_heal_packet_16_19_821 import (
    BUILD, IMAGE_BASE, PACKET_ID, PROFILE, VTABLE_RVA,
    decode_event_id_byte, make_runtime, read_image,
)
from emulate_exact_packet_decoder import HEAP_BASE, HEAP_SIZE


EVENT_ID = 0x0007
CONTROL_IDS = frozenset({0x000b, 0x000c, 0x000d})
PAYLOAD_LENGTH = 104
BLOB_LENGTH = 96
MAX_INPUT_BYTES = 1_000_000
MAX_PACKETS = 1_000


def read_request():
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError('ChampionKill request exceeds bounded input size')
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
        raise ValueError('ChampionKill candidate requires observed game stream')
    raw_param = packet.get('raw_param')
    if type(raw_param) is not int or not 0 < raw_param <= 0xffffffff:
        raise ValueError('raw_param must be a nonzero unsigned 32-bit integer')
    payload_hex = packet.get('payload_hex')
    if not isinstance(payload_hex, str) or len(payload_hex) != PAYLOAD_LENGTH * 2:
        raise ValueError('payload_hex must encode one observed 104-byte OnEvent packet')
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
        raise ValueError('native OnEvent child blob differs from observed 96-byte shape')
    raw_event_id = struct.unpack_from('<H', obj, 0x24)[0]
    event_id = (decode_event_id_byte(raw_event_id & 255)
                | decode_event_id_byte(raw_event_id >> 8) << 8)
    if event_id not in {EVENT_ID, *CONTROL_IDS}:
        raise ValueError(f'unobserved 104-byte OnEvent child ID: 0x{event_id:04x}')
    blob = bytes(emulator.emulator.mem_read(pointer, count))
    result = {
        'status': 'DECODED' if event_id == EVENT_ID else 'EXCLUDED_CHILD',
        'deserialize_return_al': 1, 'bytes_consumed': len(payload),
        'native_packet_id': PACKET_ID, 'native_raw_param': raw_param,
        'event_id': event_id, 'raw_event_id_hex': f'0x{raw_event_id:04x}',
        'event_blob_length': count,
        'event_blob_hex': blob.hex(),
        'event_blob_sha256': hashlib.sha256(blob).hexdigest(),
    }
    if event_id == EVENT_ID:
        result.update({
            'event_u32_0x04': struct.unpack_from('<I', blob, 0x04)[0],
            'event_u32_0x58': struct.unpack_from('<I', blob, 0x58)[0],
            'event_u32_0x5c': struct.unpack_from('<I', blob, 0x5c)[0],
        })
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    options = parser.parse_args()
    digest = None
    try:
        packets = read_request()
        try:
            image, digest = read_image(options.image)
        except ValueError as error:
            raise ValueError(str(error).replace('ParamsHeal runtime image',
                                                'ChampionKill runtime image')) from error
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
    except Exception as error:
        print(f'821 ChampionKill exact-runtime decoder error: {error}', file=sys.stderr)
        json.dump({'status': 'ERROR', 'runtime_image_sha256': digest,
                   'results': [], 'error': str(error)}, sys.stdout, separators=(',', ':'))
        sys.stdout.write('\n')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

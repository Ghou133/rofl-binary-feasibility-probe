#!/usr/bin/env python3
"""Exact 821 native packet-local string witness for route 0x0113."""

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

from decode_mapview_inventory_16_19_821 import make_emulator
from emulate_exact_packet_decoder import HEAP_BASE, HEAP_SIZE


BUILD = '16.19.821.7343'
IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325'
IMAGE_SIZE = 48_488_448
IMAGE_BASE = 0x7ff67f410000
PACKET_ID = 0x0113
VTABLE_RVA = 0x1ba6ff0
PROFILE = {
    'constructor_rva': 0xeb3b50,
    'deserialize_rva': 0x102d520,
    'object_size': 0x20,
    'fields': [],
}
OBSERVED_LENGTHS = frozenset({14, 15, 16, 17, 19, 24})
OBSERVED_STRINGS = frozenset({
    'RecallChannelingUpdate', 'RecallLeadIn', 'RecallWindDown',
    'RecallCancel', 'AttackVisionplant', 'AttackBlastcone', 'EatHoneyfruit',
})
MAX_REQUEST_BYTES = 8 * 1024 * 1024
MAX_PACKETS = 8_000


def input_hash(packets):
    digest = hashlib.sha256()
    for raw_param, payload in packets:
        digest.update(struct.pack('<II', raw_param, len(payload)))
        digest.update(payload)
    return digest.hexdigest()


def read_request():
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError('native request exceeds 8 MiB')
    request = json.loads(raw)
    if (not isinstance(request, dict) or request.get('replay_version') != BUILD
            or request.get('packet_id') != PACKET_ID):
        raise ValueError('native request requires exact build and packet route')
    source = request.get('packets')
    if not isinstance(source, list) or not 0 < len(source) <= MAX_PACKETS:
        raise ValueError('packets must contain 1..8000 rows')
    packets = []
    for entry in source:
        if not isinstance(entry, list) or len(entry) != 2:
            raise ValueError('packet must be [raw_param, payload_hex]')
        raw_param, payload_hex = entry
        if type(raw_param) is not int or not 0 < raw_param <= 0xffffffff:
            raise ValueError('raw_param must be nonzero u32')
        if not isinstance(payload_hex, str) or len(payload_hex) % 2:
            raise ValueError('payload_hex must be even-length hexadecimal')
        payload = bytes.fromhex(payload_hex)
        if len(payload) not in OBSERVED_LENGTHS:
            raise ValueError('payload length is outside observed exact-build shapes')
        packets.append((raw_param, payload))
    return packets


def read_image(path):
    if not path.is_file() or path.stat().st_size != IMAGE_SIZE:
        raise ValueError('exact 821 runtime image is missing or has the wrong size')
    image = path.read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    if digest != IMAGE_SHA256:
        raise ValueError(f'exact 821 runtime image SHA-256 mismatch: {digest}')
    return image, digest


def decode_one(emulator, context, raw_param, payload):
    context['raw_param'] = raw_param
    native = emulator.decode(payload, PROFILE)
    if (native['deserialize_return_al'] != 1 or not native['fully_consumed']
            or native['bytes_consumed'] != len(payload)):
        raise ValueError('native constructor/deserializer did not fully consume packet')
    obj = bytes.fromhex(native['object_hex'])
    if (struct.unpack_from('<Q', obj)[0] != IMAGE_BASE + VTABLE_RVA
            or struct.unpack_from('<H', obj, 8)[0] != PACKET_ID
            or struct.unpack_from('<I', obj, 0x0c)[0] != raw_param):
        raise ValueError('native packet vtable, route, or raw parameter differs')
    pointer, count, capacity = struct.unpack_from('<QII', obj, 0x10)
    if not (HEAP_BASE <= pointer < emulator.heap_cursor
            and 0 < count < capacity <= 512
            and pointer + capacity <= emulator.heap_cursor
            and pointer + capacity <= HEAP_BASE + HEAP_SIZE):
        raise ValueError('native string pointer, length, or capacity is outside bounded heap')
    raw = bytes(emulator.emulator.mem_read(pointer, count + 1))
    if raw[-1] != 0 or 0 in raw[:-1]:
        raise ValueError('native string is not exactly NUL terminated')
    value = raw[:-1].decode('utf-8', errors='strict')
    if value not in OBSERVED_STRINGS:
        raise ValueError('native string differs from seven observed exact-build values')
    return {
        'contextual_situation': value,
        'contextual_situation_utf8_hex': raw[:-1].hex(),
        'native_string_length': count,
        'native_string_capacity': capacity,
        'raw_payload_sha256': hashlib.sha256(payload).hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    options = parser.parse_args()
    packets = read_request()
    image, image_digest = read_image(options.image)
    emulator, context = make_emulator(image)
    rows = []
    first_failure = None
    for index, (raw_param, payload) in enumerate(packets):
        try:
            rows.append(decode_one(emulator, context, raw_param, payload))
        except Exception as error:
            first_failure = {'index': index, 'reason': f'{type(error).__name__}: {error}'}
            break
    print(json.dumps({
        'replay_version': BUILD,
        'runtime_image_sha256': image_digest,
        'packet_id': PACKET_ID,
        'packet_count': len(packets),
        'input_sha256': input_hash(packets),
        'native_full_success_count': len(rows),
        'first_failure': first_failure,
        'rows': rows if first_failure is None else [],
    }, separators=(',', ':')))
    return 0 if first_failure is None else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f'821 NotifyContextualSituation native decoder error: {error}', file=sys.stderr)
        raise SystemExit(1)

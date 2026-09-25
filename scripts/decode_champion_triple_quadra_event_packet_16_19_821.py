#!/usr/bin/env python3
"""Normalize exact-821 native 104-byte OnEvent rows for children 0x000c/0x000d.

The existing 104-byte native route helper owns constructor/deserializer,
vtable, full-consumption, child-ID, and blob extraction checks. This wrapper
selects the exact-image OnChampionTripleKill/QuadraKill-named children without interpreting
any of its native blob fields.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

from decode_champion_kill_event_packet_16_19_821 import (
    decode_packet as decode_native_104_packet,
    validate_packet,
)
from decode_params_heal_packet_16_19_821 import BUILD, make_runtime, read_image


MAX_INPUT_BYTES = 1_000_000
MAX_PACKETS = 1_000
TARGET_IDS = frozenset((0x000c, 0x000d))
RAW_IDS = {0x0007: '0x49e8', 0x000b: '0x4968',
           0x000c: '0x49c8', 0x000d: '0x4988'}


def read_request():
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError('triple/quadra marker request exceeds bounded input size')
    request = json.loads(raw)
    if not isinstance(request, dict) or request.get('replay_version') != BUILD:
        raise ValueError(f'replay_version must be exactly {BUILD}')
    packets = request.get('packets')
    if not isinstance(packets, list) or len(packets) > MAX_PACKETS:
        raise ValueError(f'packets must be an array with at most {MAX_PACKETS} entries')
    return packets


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
            row = decode_native_104_packet(emulator, context, raw_param, payload)
            child = row['event_id']
            if row['raw_event_id_hex'] != RAW_IDS[child]:
                raise ValueError(f'protected event ID differs for child 0x{child:04x}')
            # The reused helper's status and three u32 fields refer to its
            # own 0x0007 target. Reclassify only the native child marker here.
            row['status'] = 'DECODED' if child in TARGET_IDS else 'EXCLUDED_CHILD'
            for field in ('event_u32_0x04', 'event_u32_0x58', 'event_u32_0x5c'):
                row.pop(field, None)
            row.update(input_index=index, raw_param=raw_param,
                       raw_payload_sha256=hashlib.sha256(payload).hexdigest())
            results.append(row)
        json.dump({'status': 'PASS', 'runtime_image_sha256': digest,
                   'results': results}, sys.stdout, separators=(',', ':'))
        sys.stdout.write('\n')
        return 0
    except Exception as error:
        print(f'821 triple/quadra marker exact-runtime decoder error: {error}',
              file=sys.stderr)
        json.dump({'status': 'ERROR', 'runtime_image_sha256': digest,
                   'results': [], 'error': str(error)}, sys.stdout,
                  separators=(',', ':'))
        sys.stdout.write('\n')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

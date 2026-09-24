#!/usr/bin/env python3
"""Decode exact KR 16.19.821.7343 MapView packet bodies with the pinned client image.

Replay framing and source binding belong to the JavaScript caller. This helper
only runs the exact client constructor and deserializer for selected 0x018d
payloads, then inverts the same image's record byte transforms.
"""

import argparse
import hashlib
import json
import string
import struct
import sys
from pathlib import Path


REPLAY_VERSION = '16.19.821.7343'
IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325'
TABLE_SHA256 = 'ae15d606869d66dc47309b26cb489e01bf841e9dd57d540683e2dc7f5e394588'
IMAGE_BASE = 0x7ff67f410000
MAX_IMAGE_BYTES = 64 * 1024 * 1024
MAX_INPUT_BYTES = 2_000_000
MAX_PACKETS = 256
MAX_PAYLOAD_BYTES = 512
MAX_RECORDS = 9
MIN_OBSERVED_PAYLOAD_BYTES = 23
MAX_OBSERVED_PAYLOAD_BYTES = 159
RAW_PARAMS = frozenset(range(0x400000ae, 0x400000b8)) | {0x400001b2, 0x400001b5}

CONSTRUCTOR_RVA = 0xebd860
DESERIALIZER_RVA = 0x1041220
BASE_PARAM_DECODE_RVA = 0x1269bb0
ALLOC_RVA = 0x11cb240
ALT_ALLOC_RVA = 0x1a53b84
FREE_RVA = 0x11cb270
OBJECT_SIZE = 0x30
VECTOR_OFFSET = 0x18
RECORD_SIZE = 0xa8
SLOT_OFFSET = 0x10
ITEM_ID_OFFSET = 0x40
TABLE_RVA = 0x1bad8c0


def failure(message, *, return_al=None, consumed=None):
    return {
        'status': 'FAILED',
        'deserialize_return_al': return_al,
        'bytes_consumed': consumed,
        'record_count': None,
        'records': [],
        'error': message,
    }


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


def read_image(path):
    if not path.is_file() or path.stat().st_size > MAX_IMAGE_BYTES:
        raise ValueError('runtime image is missing, not a file, or exceeds the bounded size')
    image = path.read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    if digest != IMAGE_SHA256:
        raise ValueError(f'runtime image SHA-256 mismatch: {digest}')
    table = image[TABLE_RVA:TABLE_RVA + 0x100]
    if len(table) != 256 or hashlib.sha256(table).hexdigest() != TABLE_SHA256:
        raise ValueError('exact 821 record transform table differs')
    return image, digest, table


def validate_packet(packet):
    if not isinstance(packet, dict):
        raise ValueError('packet must be an object')
    raw_param = packet.get('raw_param')
    if type(raw_param) is not int or raw_param not in RAW_PARAMS:
        raise ValueError('raw_param is outside exact observed 821 MapView family')
    payload_hex = packet.get('payload_hex')
    if not isinstance(payload_hex, str) or len(payload_hex) % 2:
        raise ValueError('payload_hex must be even-length hexadecimal text')
    if len(payload_hex) // 2 > MAX_PAYLOAD_BYTES:
        raise ValueError('payload exceeds bounded 821 MapView size')
    if any(character not in string.hexdigits for character in payload_hex):
        raise ValueError('payload_hex contains non-hexadecimal characters')
    payload = bytes.fromhex(payload_hex)
    if not MIN_OBSERVED_PAYLOAD_BYTES <= len(payload) <= MAX_OBSERVED_PAYLOAD_BYTES:
        raise ValueError('payload length differs from observed 821 MapView scope')
    if payload[0] != 0x1e:
        raise ValueError('payload selector differs from observed 821 MapView scope')
    return raw_param, payload


def ror8(value, count):
    return ((value >> count) | (value << (8 - count))) & 0xff


def record_inverses(table):
    def encode_slot(byte):
        return (~ror8(table[table[(table[byte] + 0x1b) & 0xff]], 2)) & 0xff

    def encode_item_byte(byte):
        index = (ror8((~byte) & 0xff, 3) - 0x78) & 0xff
        return (ror8((~table[index]) & 0xff, 2) + 0x7e) & 0xff

    slot = {encode_slot(byte): byte for byte in range(256)}
    item = {encode_item_byte(byte): byte for byte in range(256)}
    if len(slot) != 256 or len(item) != 256:
        raise ValueError('exact 821 record byte transform is not bijective')
    if [encode_slot(value) for value in range(9)] != [
            0xc1, 0x15, 0x9f, 0x2e, 0xf6, 0x6b, 0xdb, 0x68, 0x46]:
        raise ValueError('exact 821 slot transform differs from observed runtime')
    return slot, item


def make_emulator(image):
    try:
        from unicorn import UC_HOOK_CODE
        from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RCX
        import emulate_exact_packet_decoder as exact
    except ImportError as exc:
        raise RuntimeError('exact-runtime decoder requires the installed unicorn dependency') from exc

    exact.IMAGE_BASE = IMAGE_BASE
    emulator = exact.ExactPacketEmulator(image, {
        'runtime_alloc_rva': ALLOC_RVA,
        'runtime_free_rva': FREE_RVA,
        'runtime_memset_leaf_rva': None,
        'enable_legacy_business_stubs': False,
    })
    context = {'raw_param': 0}

    def base_param_from_replay(_uc, _address, _size, _user_data):
        address = emulator.emulator.reg_read(UC_X86_REG_RCX)
        emulator.emulator.mem_write(address + 0x0c, struct.pack('<I', context['raw_param']))
        emulator.emulator.reg_write(UC_X86_REG_RAX, 1)
        emulator._return_from_stub()

    emulator.emulator.hook_add(
        UC_HOOK_CODE, base_param_from_replay,
        begin=IMAGE_BASE + BASE_PARAM_DECODE_RVA,
        end=IMAGE_BASE + BASE_PARAM_DECODE_RVA,
    )
    # The exact client calls two allocation paths while growing its MapView
    # vector. Only host-memory management is stubbed; packet code runs native.
    emulator.emulator.hook_add(
        UC_HOOK_CODE, emulator._allocate,
        begin=IMAGE_BASE + ALT_ALLOC_RVA,
        end=IMAGE_BASE + ALT_ALLOC_RVA,
    )
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
    object_bytes = bytes(emulator.emulator.mem_read(exact.OBJECT_ADDRESS, OBJECT_SIZE))
    if struct.unpack_from('<H', object_bytes, 8)[0] != 0x018d:
        return failure('native object opcode differs from 0x018d',
                       return_al=return_al, consumed=consumed)
    if struct.unpack_from('<I', object_bytes, 0x0c)[0] != raw_param:
        return failure('native object raw param differs from Replay framing',
                       return_al=return_al, consumed=consumed)
    pointer, count, capacity = struct.unpack_from('<QII', object_bytes, VECTOR_OFFSET)
    if count > MAX_RECORDS or count > capacity or (count > 0 and pointer == 0):
        return failure('native MapView vector exceeds observed record bounds',
                       return_al=return_al, consumed=consumed)
    records = []
    prior_slot = -1
    for index in range(count):
        record = bytes(emulator.emulator.mem_read(pointer + index * RECORD_SIZE,
                                                 RECORD_SIZE))
        raw_slot = record[SLOT_OFFSET]
        slot = slot_inverse[raw_slot]
        raw_item = record[ITEM_ID_OFFSET:ITEM_ID_OFFSET + 4]
        item_id = struct.unpack('<I', bytes(item_inverse[byte] for byte in raw_item))[0]
        if slot > 8 or slot <= prior_slot or item_id == 0:
            return failure('native MapView record slot or item definition key is outside observed bounds',
                           return_al=return_al, consumed=consumed)
        prior_slot = slot
        records.append({
            'record_index': index,
            'slot': slot,
            'item_id': item_id,
            'raw_slot_byte_hex': f'{raw_slot:02x}',
            'raw_item_id_bytes_hex': raw_item.hex(),
        })
    return {
        'status': 'DECODED',
        'deserialize_return_al': return_al,
        'bytes_consumed': consumed,
        'record_count': count,
        'records': records,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    options = parser.parse_args()
    digest = None
    try:
        packets = read_request()
        image, digest, table = read_image(options.image)
        slot_inverse, item_inverse = record_inverses(table)
        emulator, context = make_emulator(image)
        results = []
        for index, packet in enumerate(packets):
            try:
                raw_param, payload = validate_packet(packet)
            except ValueError as exc:
                row = failure(str(exc))
                row.update(input_index=index, raw_param=None, raw_payload_sha256=None)
                results.append(row)
                continue
            binding = {
                'input_index': index,
                'raw_param': raw_param,
                'raw_payload_sha256': hashlib.sha256(payload).hexdigest(),
            }
            try:
                decoded = decode_packet(emulator, context, slot_inverse, item_inverse,
                                        raw_param, payload)
                decoded.update(binding)
                results.append(decoded)
                if decoded['status'] != 'DECODED':
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
        print(f'821 MapView exact-runtime decoder error: {exc}', file=sys.stderr)
        json.dump({'status': 'ERROR', 'runtime_image_sha256': digest,
                   'results': [], 'error': str(exc)}, sys.stdout,
                  separators=(',', ':'))
        sys.stdout.write('\n')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

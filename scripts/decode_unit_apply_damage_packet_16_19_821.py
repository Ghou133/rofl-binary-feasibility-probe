#!/usr/bin/env python3
"""Bounded native witness for exact 821 UnitApplyDamage packet payloads.

The --batch mode validates every selected packet in one replay with one exact
image and one emulator. The ordinary mode retains verbose research samples.
"""

import argparse
import hashlib
import json
import math
import struct
import sys
from pathlib import Path

from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.x86_const import UC_X86_REG_RIP, UC_X86_REG_RSI

from decode_mapview_inventory_16_19_821 import make_emulator
import emulate_exact_packet_decoder as exact


BUILD = '16.19.821.7343'
IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325'
IMAGE_BASE = 0x7ff67f410000
IMAGE_SIZE = 48_488_448
MAX_REQUEST_BYTES = 1_000_000
MAX_PACKETS = 1_024
MAX_BATCH_REQUEST_BYTES = 16 * 1024 * 1024
MAX_BATCH_PACKETS = 100_000
PACKET_ID = 0x005f
FACTORY_TABLE_RVA = 0xf0e4bc
FACTORY_CASE_RVA = 0xeff3bf
CONSTRUCTOR_RVA = 0xecec40
VTABLE_RVA = 0x1ba21c8
DESERIALIZER_RVA = 0xf49dd0
CALLBACK_FLOAT_HELPER_RVA = 0x251c60
CALLBACK_F32_0X18_HELPER_RVA = 0x251be0
CALLBACK_F32_0X18_TABLE_SHA256 = '2a45ee14ca77f364f9f662dada6377ed01ef9e2e3b8fb074ee0c5ee3ae7d6d3d'
CALLBACK_U32_0X10_HELPER_RVA = 0x251e40
CALLBACK_U32_0X10_TABLE_SHA256 = 'd347ff60e28a7757cc3858fd550e5ced34e0ffccdfd5400248ae547b96e76453'
LOOKUP_KEY_0X24_HELPER_RVA = 0x251ba0
LOOKUP_KEY_0X2C_HELPER_RVA = 0x251c30
LOOKUP_KEY_TABLE_SHA256 = {
    0x24: 'fdc699513c7ecb8b85f86b8420a6eb3d0a90005495c0ce2a5d19bdeb2be5fa1f',
    0x2c: 'dde1767c7329b3624d423418742a52991a43e357a75a426c9d895e0d4d1b8eb1',
}
RAW_FLOAT_READER_RVA = 0xe79810
U32_0X10_RAW_READ_CALL_RVAS = (0xf49f7f, 0xf49fd2, 0xf4a031, 0xf4a082)
U32_0X10_RAW_SELECTORS = (0, 1, 4, 7)
U32_0X10_CONSTANT_ZERO_SELECTOR = 6
F32_0X18_RAW_READ_CALL_RVAS = {
    0: 0xf4a3cb, 2: 0xf4a4e9, 3: 0xf4a488, 6: 0xf4a429,
}
F32_0X18_FINAL_WRITE_RVAS = {
    0: 0xf4a409, 2: 0xf4a528, 3: 0xf4a4c8,
    5: 0xf4a3ab, 6: 0xf4a468,
}
F32_0X18_CONSTANT_ZERO_SELECTOR = 5
FLOAT_READ_CALL_RVAS = (0xf4a911, 0xf4a97f, 0xf4a9ef, 0xf4aa60)
FLOAT_FINAL_WRITE_RVAS = {
    0: 0xf4aaaf,
    2: 0xf4aa3f,
    3: 0xf4a7d0,
    4: 0xf4a9cf,
    5: 0xf4a8f0,
    6: 0xf4a95f,
    7: 0xf4a890,
}
FLOAT_CONSTANTS = {3: ('CONSTANT_0', 0.0, '9f9f9f9f'),
                   5: ('CONSTANT_1', 1.0, '9f9f36ef'),
                   7: ('CONSTANT_2', 2.0, '9f9f9fed')}
PROFILE = {
    'constructor_rva': CONSTRUCTOR_RVA,
    'deserialize_rva': DESERIALIZER_RVA,
    'object_size': 0x30,
    'fields': [
        {'name': 'callback_u32_0x10', 'offset': 0x10, 'type': 'u32',
         'byte_helper_rva': CALLBACK_U32_0X10_HELPER_RVA},
        {'name': 'callback_f32_0x18', 'offset': 0x18, 'type': 'f32',
         'byte_helper_rva': CALLBACK_F32_0X18_HELPER_RVA},
        {'name': 'callback_f32_0x20', 'offset': 0x20, 'type': 'f32',
         'byte_helper_rva': CALLBACK_FLOAT_HELPER_RVA},
        {'name': 'lookup_key_u32_0x24', 'offset': 0x24, 'type': 'u32',
         'byte_helper_rva': LOOKUP_KEY_0X24_HELPER_RVA},
        {'name': 'lookup_key_u32_0x2c', 'offset': 0x2c, 'type': 'u32',
         'byte_helper_rva': LOOKUP_KEY_0X2C_HELPER_RVA},
    ],
}


def read_request():
    request_bytes = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(request_bytes) > MAX_REQUEST_BYTES:
        raise ValueError('native witness request exceeds bounded size')
    request = json.loads(request_bytes)
    if not isinstance(request, dict) or request.get('replay_version') != BUILD:
        raise ValueError(f'replay_version must be exactly {BUILD}')
    packets = request.get('packets')
    if not isinstance(packets, list) or len(packets) > MAX_PACKETS:
        raise ValueError(f'packets must be an array of at most {MAX_PACKETS} entries')
    return packets


def read_batch_request():
    request_bytes = sys.stdin.buffer.read(MAX_BATCH_REQUEST_BYTES + 1)
    if len(request_bytes) > MAX_BATCH_REQUEST_BYTES:
        raise ValueError('native batch request exceeds bounded size')
    request = json.loads(request_bytes)
    if (not isinstance(request, dict) or request.get('replay_version') != BUILD
            or request.get('packet_id') != PACKET_ID):
        raise ValueError('native batch requires the exact build and route')
    packets = request.get('packets')
    if not isinstance(packets, list) or not 0 < len(packets) <= MAX_BATCH_PACKETS:
        raise ValueError(f'packets must be an array of 1..{MAX_BATCH_PACKETS} entries')
    return packets


def read_image(image_path):
    if not image_path.is_file() or image_path.stat().st_size != IMAGE_SIZE:
        raise ValueError('exact 821 mapped image is missing or has the wrong length')
    image = image_path.read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    if digest != IMAGE_SHA256:
        raise ValueError(f'exact 821 mapped image SHA-256 mismatch: {digest}')
    case = struct.unpack_from('<I', image, FACTORY_TABLE_RVA + PACKET_ID * 4)[0]
    if case != FACTORY_CASE_RVA or image[case:case + 5] != bytes.fromhex('b930000000'):
        raise ValueError('exact 821 factory case differs')
    if image[CONSTRUCTOR_RVA + 0x0c:CONSTRUCTOR_RVA + 0x12] != bytes.fromhex('66c741085f00'):
        raise ValueError('exact 821 constructor opcode write differs')
    if struct.unpack_from('<Q', image, VTABLE_RVA + 8)[0] - IMAGE_BASE != DESERIALIZER_RVA:
        raise ValueError('exact 821 UnitApplyDamage deserializer differs')
    if image[0x26efbc:0x26efc2] != bytes.fromhex('41b85f000000'):
        raise ValueError('exact 821 UnitApplyDamage registration differs')
    return image, digest


def validate_packet(packet):
    if not isinstance(packet, dict) or packet.get('packet_id') != PACKET_ID:
        raise ValueError('packet_id must be exact 821 route 0x005f')
    if packet.get('stream_tag') != 1:
        raise ValueError('UnitApplyDamage witness requires game stream')
    raw_param = packet.get('raw_param')
    if type(raw_param) is not int or not 0 < raw_param <= 0xffffffff:
        raise ValueError('raw_param must be a nonzero u32')
    payload_hex = packet.get('payload_hex')
    if not isinstance(payload_hex, str) or len(payload_hex) % 2:
        raise ValueError('payload_hex must be even-length hexadecimal text')
    try:
        payload = bytes.fromhex(payload_hex)
    except ValueError as error:
        raise ValueError('payload_hex is invalid hexadecimal text') from error
    if not 7 <= len(payload) <= 26:
        raise ValueError('payload is outside bounded native witness size')
    return raw_param, payload


def validate_batch_tuple(packet):
    if not isinstance(packet, list) or len(packet) != 3:
        raise ValueError('native batch packet must be [raw_param, payload_hex, has_float]')
    raw_param, payload_hex, has_float = packet
    if type(raw_param) is not int or not 0 < raw_param <= 0xffffffff:
        raise ValueError('native batch raw_param must be a nonzero u32')
    if not isinstance(payload_hex, str) or not 16 <= len(payload_hex) <= 50:
        raise ValueError('native batch payload hex length is outside observed scope')
    if len(payload_hex) % 2:
        raise ValueError('native batch payload hex length must be even')
    try:
        payload = bytes.fromhex(payload_hex)
    except ValueError as error:
        raise ValueError('native batch payload is invalid hexadecimal') from error
    expected_float = (len(payload) == 15 and payload[3] & 7 == 6
                      and payload[0] & 7 == 1 and (payload[0] >> 3) & 7 == 6)
    if type(has_float) is not bool or has_float != expected_float:
        raise ValueError('native batch float-family flag differs from payload')
    return raw_param, payload, has_float


def make_damage_emulator(image):
    """Trace exact deserializer field writes and packet-local raw readers."""
    emulator, context = make_emulator(image)
    state = {'in_deserializer': False, 'float_write_rvas': set(),
             'float_read_offsets': [], 'u32_0x10_raw_read_offsets': [],
             'u32_0x10_write_mask': 0,
             'f32_0x18_final_write_masks': {}, 'f32_0x18_raw_reads': [],
             'lookup_write_masks': {0x24: 0, 0x2c: 0}}

    def enter_deserializer(uc, _address, _size, _user_data):
        state['in_deserializer'] = True

    def float_write(uc, _access, _address, _size, _value, _user_data):
        if state['in_deserializer']:
            state['float_write_rvas'].add(uc.reg_read(UC_X86_REG_RIP) - IMAGE_BASE)

    def float_read(uc, _address, _size, _user_data):
        cursor_address = uc.reg_read(UC_X86_REG_RSI)
        payload_pointer = struct.unpack('<Q', bytes(uc.mem_read(cursor_address, 8)))[0]
        state['float_read_offsets'].append(payload_pointer - exact.PAYLOAD_ADDRESS)

    def u32_0x10_read(uc, _address, _size, _user_data):
        cursor_address = uc.reg_read(UC_X86_REG_RSI)
        payload_pointer = struct.unpack('<Q', bytes(uc.mem_read(cursor_address, 8)))[0]
        state['u32_0x10_raw_read_offsets'].append(payload_pointer - exact.PAYLOAD_ADDRESS)

    def u32_0x10_write(_uc, _access, address, size, _value, _user_data):
        if not state['in_deserializer']:
            return
        for byte_index in range(4):
            field_address = exact.OBJECT_ADDRESS + 0x10 + byte_index
            if address <= field_address < address + size:
                state['u32_0x10_write_mask'] |= 1 << byte_index

    def f32_0x18_read(uc, address, _size, _user_data):
        cursor_address = uc.reg_read(UC_X86_REG_RSI)
        payload_pointer = struct.unpack('<Q', bytes(uc.mem_read(cursor_address, 8)))[0]
        state['f32_0x18_raw_reads'].append(
            (address - IMAGE_BASE, payload_pointer - exact.PAYLOAD_ADDRESS))

    def f32_0x18_write(uc, _access, address, size, _value, _user_data):
        if not state['in_deserializer']:
            return
        rva = uc.reg_read(UC_X86_REG_RIP) - IMAGE_BASE
        if rva not in F32_0X18_FINAL_WRITE_RVAS.values():
            return
        mask = state['f32_0x18_final_write_masks'].get(rva, 0)
        for byte_index in range(4):
            field_address = exact.OBJECT_ADDRESS + 0x18 + byte_index
            if address <= field_address < address + size:
                mask |= 1 << byte_index
        state['f32_0x18_final_write_masks'][rva] = mask

    def lookup_write(_uc, _access, address, size, _value, _user_data):
        if not state['in_deserializer']:
            return
        for offset in (0x24, 0x2c):
            for byte_index in range(4):
                field_address = exact.OBJECT_ADDRESS + offset + byte_index
                if address <= field_address < address + size:
                    state['lookup_write_masks'][offset] |= 1 << byte_index

    emulator.emulator.hook_add(UC_HOOK_CODE, enter_deserializer,
                               begin=IMAGE_BASE + DESERIALIZER_RVA,
                               end=IMAGE_BASE + DESERIALIZER_RVA)
    emulator.emulator.hook_add(UC_HOOK_MEM_WRITE, float_write,
                                begin=exact.OBJECT_ADDRESS + 0x20,
                                end=exact.OBJECT_ADDRESS + 0x23)
    emulator.emulator.hook_add(UC_HOOK_MEM_WRITE, u32_0x10_write,
                               begin=exact.OBJECT_ADDRESS + 0x10,
                               end=exact.OBJECT_ADDRESS + 0x13)
    emulator.emulator.hook_add(UC_HOOK_MEM_WRITE, f32_0x18_write,
                               begin=exact.OBJECT_ADDRESS + 0x18,
                               end=exact.OBJECT_ADDRESS + 0x1b)
    emulator.emulator.hook_add(UC_HOOK_MEM_WRITE, lookup_write,
                               begin=exact.OBJECT_ADDRESS + 0x24,
                               end=exact.OBJECT_ADDRESS + 0x2f)
    for rva in FLOAT_READ_CALL_RVAS:
        emulator.emulator.hook_add(UC_HOOK_CODE, float_read,
                                   begin=IMAGE_BASE + rva, end=IMAGE_BASE + rva)
    for rva in U32_0X10_RAW_READ_CALL_RVAS:
        emulator.emulator.hook_add(UC_HOOK_CODE, u32_0x10_read,
                                   begin=IMAGE_BASE + rva, end=IMAGE_BASE + rva)
    for rva in F32_0X18_RAW_READ_CALL_RVAS.values():
        emulator.emulator.hook_add(UC_HOOK_CODE, f32_0x18_read,
                                   begin=IMAGE_BASE + rva, end=IMAGE_BASE + rva)
    return emulator, context, state


def reset_float_trace(state):
    state['in_deserializer'] = False
    state['float_write_rvas'].clear()
    state['float_read_offsets'].clear()
    state['u32_0x10_raw_read_offsets'].clear()
    state['u32_0x10_write_mask'] = 0
    state['f32_0x18_final_write_masks'].clear()
    state['f32_0x18_raw_reads'].clear()
    state['lookup_write_masks'][0x24] = 0
    state['lookup_write_masks'][0x2c] = 0


def checked_lookup_tables(emulator):
    tables = emulator.prepare_profile(PROFILE)['byte_tables']
    result = {}
    for offset, helper in ((0x24, LOOKUP_KEY_0X24_HELPER_RVA),
                           (0x2c, LOOKUP_KEY_0X2C_HELPER_RVA)):
        table = tables[helper]
        if (len(table) != 256 or len(set(table)) != 256
                or hashlib.sha256(table).hexdigest() != LOOKUP_KEY_TABLE_SHA256[offset]):
            raise ValueError(f'exact 821 +0x{offset:x} lookup-key helper table differs')
        result[offset] = table
    return result


def checked_callback_u32_0x10_table(emulator):
    table = emulator.prepare_profile(PROFILE)['byte_tables'][CALLBACK_U32_0X10_HELPER_RVA]
    if (len(table) != 256 or len(set(table)) != 256
            or hashlib.sha256(table).hexdigest() != CALLBACK_U32_0X10_TABLE_SHA256):
        raise ValueError('exact 821 +0x10 callback helper table differs')
    return table


def checked_callback_f32_0x18_table(emulator):
    table = emulator.prepare_profile(PROFILE)['byte_tables'][CALLBACK_F32_0X18_HELPER_RVA]
    if (len(table) != 256 or len(set(table)) != 256
            or hashlib.sha256(table).hexdigest() != CALLBACK_F32_0X18_TABLE_SHA256):
        raise ValueError('exact 821 +0x18 callback helper table differs')
    return table


def inspect_callback_f32_0x18(payload, object_bytes, decoded_value, state, table):
    """Bind an anonymous float to its exact branch, final write and raw bytes."""
    selector = ((payload[0] >> 6) | (payload[1] << 2)) & 7
    final_rva = F32_0X18_FINAL_WRITE_RVAS.get(selector)
    if final_rva is None or state['f32_0x18_final_write_masks'].get(final_rva) != 0xf:
        raise ValueError('821 +0x18 callback f32 selector or final write differs')
    if len(state['f32_0x18_final_write_masks']) != 1:
        raise ValueError('821 +0x18 callback f32 wrote from multiple final branches')
    encoded = object_bytes[0x18:0x1c]
    value = struct.unpack('<f', encoded.translate(table))[0]
    if not math.isfinite(value) or decoded_value != value:
        raise ValueError('821 +0x18 callback f32 transform is nonfinite or differs')
    if selector == F32_0X18_CONSTANT_ZERO_SELECTOR:
        if (state['f32_0x18_raw_reads'] or value != 0
                or encoded.hex() != '3e3e3e3e'):
            raise ValueError('821 +0x18 constant-zero branch differs')
        return encoded.hex(), value, 'CONSTANT_0', None
    reads = state['f32_0x18_raw_reads']
    if len(reads) != 1 or reads[0][0] != F32_0X18_RAW_READ_CALL_RVAS[selector]:
        raise ValueError('821 +0x18 raw f32 reader was not invoked exactly once')
    offset = reads[0][1]
    if not 0 <= offset <= len(payload) - 4 or encoded != payload[offset:offset + 4][::-1]:
        raise ValueError('821 +0x18 native encoded bytes differ from reversed raw bytes')
    return encoded.hex(), value, 'RAW_READER', offset


def inspect_callback_u32_0x10(payload, object_bytes, decoded_value, state, table):
    """Check the exact native write, source branch, and callback transform."""
    selector = payload[3] & 7
    if state['u32_0x10_write_mask'] != 0xf:
        raise ValueError('821 +0x10 callback u32 was not fully written')
    encoded = object_bytes[0x10:0x14]
    decoded = struct.unpack('<I', encoded.translate(table))[0]
    if decoded != decoded_value:
        raise ValueError('821 +0x10 callback u32 transform differs')
    if selector in U32_0X10_RAW_SELECTORS:
        offsets = state['u32_0x10_raw_read_offsets']
        if len(offsets) != 1 or not 0 <= offsets[0] < len(payload):
            raise ValueError('821 +0x10 raw u32 reader was not invoked exactly once')
        return encoded.hex(), decoded, 'RAW_READER'
    if selector == U32_0X10_CONSTANT_ZERO_SELECTOR:
        if state['u32_0x10_raw_read_offsets'] or decoded != 0 or encoded.hex() != '85858585':
            raise ValueError('821 +0x10 constant-zero branch differs')
        return encoded.hex(), decoded, 'CONSTANT_0'
    raise ValueError('821 +0x10 selector is outside observed scope')


def inspect_lookup_keys(object_bytes, decoded_fields, state, tables):
    """Bind callback lookup values to fully written native object bytes."""
    values = []
    for offset in (0x24, 0x2c):
        if state['lookup_write_masks'][offset] != 0xf:
            raise ValueError(f'821 +0x{offset:x} lookup key was not fully written')
        encoded = object_bytes[offset:offset + 4]
        name = f'lookup_key_u32_0x{offset:x}'
        decoded = struct.unpack('<I', encoded.translate(tables[offset]))[0]
        if decoded == 0 or decoded_fields[name] != decoded:
            raise ValueError(f'821 +0x{offset:x} lookup key transform differs')
        values.extend((encoded.hex(), decoded))
    return values


def inspect_callback_float(payload, object_bytes, decoded_value, state, byte_table):
    """Require a concrete +0x20 write and distinguish raw-read from constants."""
    selector = (payload[0] >> 3) & 7
    if selector not in FLOAT_FINAL_WRITE_RVAS:
        raise ValueError('821 +0x20 float selector is outside observed scope')
    if FLOAT_FINAL_WRITE_RVAS[selector] not in state['float_write_rvas']:
        raise ValueError('821 +0x20 float was not explicitly written')
    if decoded_value is None or not math.isfinite(decoded_value):
        raise ValueError('821 +0x20 callback float is unavailable or nonfinite')
    encoded = object_bytes[0x20:0x24]
    if selector in FLOAT_CONSTANTS:
        source, expected_value, expected_hex = FLOAT_CONSTANTS[selector]
        if (state['float_read_offsets'] or decoded_value != expected_value
                or encoded.hex() != expected_hex):
            raise ValueError('821 +0x20 constant branch differs')
        return source, None
    if len(state['float_read_offsets']) != 1:
        raise ValueError('821 +0x20 raw reader was not invoked exactly once')
    offset = state['float_read_offsets'][0]
    raw = payload[offset:offset + 4] if 0 <= offset <= len(payload) - 4 else b''
    if len(raw) != 4 or raw != encoded:
        raise ValueError('821 +0x20 raw bytes differ from native object')
    redecoded = struct.unpack('<f', raw.translate(byte_table))[0]
    if redecoded != decoded_value:
        raise ValueError('821 +0x20 raw helper transform differs')
    return 'RAW_READER', offset


def run_batch(packets, image, digest):
    emulator, context, trace = make_damage_emulator(image)
    float_table = emulator.prepare_profile(PROFILE)['byte_tables'][CALLBACK_FLOAT_HELPER_RVA]
    u32_0x10_table = checked_callback_u32_0x10_table(emulator)
    f32_0x18_table = checked_callback_f32_0x18_table(emulator)
    lookup_tables = checked_lookup_tables(emulator)
    input_digest = hashlib.sha256()
    float_rows = []
    native_float_rows = []
    native_u32_0x10_rows = []
    native_f32_0x18_rows = []
    lookup_rows = []
    native_float_source_counts = {'RAW_READER': 0, 'CONSTANT_0': 0,
                                   'CONSTANT_1': 0, 'CONSTANT_2': 0}
    native_u32_0x10_source_counts = {'RAW_READER': 0, 'CONSTANT_0': 0}
    native_f32_0x18_source_counts = {'RAW_READER': 0, 'CONSTANT_0': 0}
    accepted_count = 0
    first_failure = None
    for index, packet in enumerate(packets):
        raw_param, payload, has_float = validate_batch_tuple(packet)
        input_digest.update(struct.pack('<II', raw_param, len(payload)))
        input_digest.update(payload)
        if first_failure is not None:
            continue
        context['raw_param'] = raw_param
        reset_float_trace(trace)
        try:
            native = emulator.decode(payload, PROFILE)
            object_bytes = bytes.fromhex(native['object_hex'])
            opcode = struct.unpack_from('<H', object_bytes, 8)[0]
            object_param = struct.unpack_from('<I', object_bytes, 0x0c)[0]
            accepted = (native['deserialize_return_al'] == 1
                        and native['fully_consumed']
                        and opcode == PACKET_ID
                        and object_param == raw_param)
            if not accepted:
                first_failure = {
                    'index': index, 'reason': 'native deserializer did not fully accept packet',
                    'deserialize_return_al': native['deserialize_return_al'],
                    'bytes_consumed': native['bytes_consumed'],
                    'fully_consumed': native['fully_consumed'],
                    'object_opcode': opcode, 'object_raw_param': object_param,
                }
                continue
            value = native['decoded_fields']['callback_f32_0x20']
            source, raw_offset = inspect_callback_float(
                payload, object_bytes, value, trace, float_table)
            lookup_values = inspect_lookup_keys(
                object_bytes, native['decoded_fields'], trace, lookup_tables)
            u32_0x10_values = inspect_callback_u32_0x10(
                payload, object_bytes, native['decoded_fields']['callback_u32_0x10'],
                trace, u32_0x10_table)
            f32_0x18_values = inspect_callback_f32_0x18(
                payload, object_bytes, native['decoded_fields']['callback_f32_0x18'],
                trace, f32_0x18_table)
            if has_float and (source != 'RAW_READER' or raw_offset != 5):
                first_failure = {'index': index,
                                 'reason': 'legacy 15-byte float family raw offset differs'}
                continue
            native_float_rows.append([index, value, source, raw_offset])
            native_u32_0x10_rows.append([index, *u32_0x10_values])
            native_f32_0x18_rows.append([index, *f32_0x18_values])
            lookup_rows.append([index, *lookup_values])
            native_float_source_counts[source] += 1
            native_u32_0x10_source_counts[u32_0x10_values[2]] += 1
            native_f32_0x18_source_counts[f32_0x18_values[2]] += 1
            if has_float:
                float_rows.append([index, value])
            accepted_count += 1
        except Exception as error:
            first_failure = {'index': index, 'reason': str(error)}
    print(json.dumps({
        'replay_version': BUILD,
        'runtime_image_sha256': digest,
        'packet_id': PACKET_ID,
        'packet_count': len(packets),
        'input_sha256': input_digest.hexdigest(),
        'native_full_success_count': accepted_count,
        'first_failure': first_failure,
        'float_rows': float_rows,
        'native_float_rows': native_float_rows,
        'native_float_source_counts': native_float_source_counts,
        'native_u32_0x10_rows': native_u32_0x10_rows,
        'native_u32_0x10_full_write_count': len(native_u32_0x10_rows),
        'native_u32_0x10_source_counts': native_u32_0x10_source_counts,
        'callback_u32_0x10_table_sha256': CALLBACK_U32_0X10_TABLE_SHA256,
        'native_f32_0x18_rows': native_f32_0x18_rows,
        'native_f32_0x18_full_write_count': len(native_f32_0x18_rows),
        'native_f32_0x18_source_counts': native_f32_0x18_source_counts,
        'callback_f32_0x18_table_sha256': CALLBACK_F32_0X18_TABLE_SHA256,
        'lookup_rows': lookup_rows,
        'native_lookup_full_write_count': len(lookup_rows),
        'lookup_table_sha256': {
            '0x24': LOOKUP_KEY_TABLE_SHA256[0x24],
            '0x2c': LOOKUP_KEY_TABLE_SHA256[0x2c],
        },
    }, allow_nan=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--batch', action='store_true',
                        help='validate up to 100000 packets in one replay')
    options = parser.parse_args()
    packets = read_batch_request() if options.batch else read_request()
    image, digest = read_image(options.image)
    if options.batch:
        run_batch(packets, image, digest)
        return
    emulator, context, trace = make_damage_emulator(image)
    float_table = emulator.prepare_profile(PROFILE)['byte_tables'][CALLBACK_FLOAT_HELPER_RVA]
    u32_0x10_table = checked_callback_u32_0x10_table(emulator)
    f32_0x18_table = checked_callback_f32_0x18_table(emulator)
    lookup_tables = checked_lookup_tables(emulator)
    rows = []
    for index, packet in enumerate(packets):
        raw_param, payload = validate_packet(packet)
        context['raw_param'] = raw_param
        reset_float_trace(trace)
        try:
            native = emulator.decode(payload, PROFILE)
            object_bytes = bytes.fromhex(native['object_hex'])
            opcode = struct.unpack_from('<H', object_bytes, 8)[0]
            object_param = struct.unpack_from('<I', object_bytes, 0x0c)[0]
            accepted = (native['deserialize_return_al'] == 1
                        and native['fully_consumed']
                        and opcode == PACKET_ID
                        and object_param == raw_param)
            value = native['decoded_fields']['callback_f32_0x20'] if accepted else None
            source = None
            raw_offset = None
            lookup_values = None
            u32_0x10_values = None
            f32_0x18_values = None
            if accepted:
                source, raw_offset = inspect_callback_float(
                    payload, object_bytes, value, trace, float_table)
                lookup_values = inspect_lookup_keys(
                    object_bytes, native['decoded_fields'], trace, lookup_tables)
                u32_0x10_values = inspect_callback_u32_0x10(
                    payload, object_bytes, native['decoded_fields']['callback_u32_0x10'],
                    trace, u32_0x10_table)
                f32_0x18_values = inspect_callback_f32_0x18(
                    payload, object_bytes, native['decoded_fields']['callback_f32_0x18'],
                    trace, f32_0x18_table)
            rows.append({
                'index': index,
                'status': 'DECODED' if accepted else 'FAILED',
                'deserialize_return_al': native['deserialize_return_al'],
                'bytes_consumed': native['bytes_consumed'],
                'fully_consumed': native['fully_consumed'],
                'object_opcode': opcode,
                'object_raw_param': object_param,
                'object_field_0x20_encoded_bytes_hex': object_bytes[0x20:0x24].hex(),
                'object_field_0x10_encoded_bytes_hex': u32_0x10_values[0] if u32_0x10_values else None,
                'native_callback_u32_0x10_candidate': u32_0x10_values[1] if u32_0x10_values else None,
                'native_callback_u32_0x10_source': u32_0x10_values[2] if u32_0x10_values else None,
                'u32_0x10_full_write': trace['u32_0x10_write_mask'] == 0xf if accepted else False,
                'object_field_0x18_encoded_bytes_hex': f32_0x18_values[0] if f32_0x18_values else None,
                'native_callback_f32_0x18_candidate': f32_0x18_values[1] if f32_0x18_values else None,
                'native_callback_f32_0x18_source': f32_0x18_values[2] if f32_0x18_values else None,
                'native_callback_f32_0x18_raw_offset': f32_0x18_values[3] if f32_0x18_values else None,
                'f32_0x18_full_write': bool(f32_0x18_values) if accepted else False,
                'callback_f32_0x20_candidate': value,
                'native_callback_f32_0x20_source': source,
                'native_callback_f32_0x20_raw_offset': raw_offset,
                'lookup_key_u32_0x24_encoded_bytes_hex': lookup_values[0] if lookup_values else None,
                'lookup_key_u32_0x24_candidate': lookup_values[1] if lookup_values else None,
                'lookup_key_u32_0x2c_encoded_bytes_hex': lookup_values[2] if lookup_values else None,
                'lookup_key_u32_0x2c_candidate': lookup_values[3] if lookup_values else None,
                'lookup_full_write': (trace['lookup_write_masks'][0x24] == 0xf
                                      and trace['lookup_write_masks'][0x2c] == 0xf) if accepted else False,
            })
        except Exception as error:
            rows.append({'index': index, 'status': 'FAILED', 'error': str(error)})
    print(json.dumps({
        'replay_version': BUILD,
        'runtime_image_sha256': digest,
        'packet_id': PACKET_ID,
        'packet_count': len(rows),
        'native_full_success_count': sum(row['status'] == 'DECODED' for row in rows),
        'rows': rows,
    }, allow_nan=False))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps({'status': 'FAILED', 'error': str(exc)}), file=sys.stderr)
        sys.exit(1)

#!/usr/bin/env python3

import argparse
import hashlib
import json
import math
import os
import struct
import sys

from unicorn import (
    Uc,
    UcError,
    UC_ARCH_X86,
    UC_HOOK_CODE,
    UC_HOOK_MEM_INVALID,
    UC_MODE_64,
    UC_PROT_ALL,
)
from unicorn.x86_const import (
    UC_X86_REG_R8,
    UC_X86_REG_RAX,
    UC_X86_REG_RCX,
    UC_X86_REG_RDX,
    UC_X86_REG_RIP,
    UC_X86_REG_RSI,
    UC_X86_REG_RSP,
    UC_X86_REG_XMM0,
)


IMAGE_BASE = 0x140000000
PAGE_SIZE = 0x1000
WORK_BASE = 0x200000000
OBJECT_ADDRESS = WORK_BASE
CURSOR_ADDRESS = WORK_BASE + 0x1000
PAYLOAD_ADDRESS = WORK_BASE + 0x2000
STACK_BASE = WORK_BASE + 0x200000
STACK_SIZE = 0x20000
RETURN_ADDRESS = WORK_BASE + 0x230000
BASE_PACKET_ADDRESS = WORK_BASE + 0x3000
VECTOR_ADDRESS = WORK_BASE + 0x4000
VECTOR_BUFFER_ADDRESS = WORK_BASE + 0x5000
OPCODE_ADDRESS = WORK_BASE + 0x6000
BUSINESS_OBJECT_ADDRESS = WORK_BASE + 0x10000
HEAP_BASE = 0x300000000
HEAP_SIZE = 0x1000000
RUNTIME_ALLOC_RVA = 0x0119B460
RUNTIME_FREE_RVA = 0x0119B490
BUSINESS_ID_LOOKUP_RVA = 0x00569D50
BUSINESS_OBJECT_LOOKUP_RVA = 0x005655C0
BUSINESS_SPELL_LOOKUP_RVA = 0x0090D43B
BUSINESS_SPELL_LOOKUP_RESUME_RVA = 0x0090D4DD
BUSINESS_OPTIONAL_LIST_RVA = 0x0090C99D
BUSINESS_OPTIONAL_LIST_RESUME_RVA = 0x0090CACF
CAST_SPELL_LOOKUP_TABLE_RVA = 0x01AB4960
BASE_PACKET_VTABLE_RVA = 0x01A239A0
BASE_PACKET_SERIALIZE_RVA = 0x01254AF0
BASE_PACKET_DECODE_RVA = 0x012370A0

RUNTIME_PROFILES = {
    '16.15.801.3452': {
        'runtime_alloc_rva': RUNTIME_ALLOC_RVA,
        'runtime_free_rva': RUNTIME_FREE_RVA,
        'base_packet_vtable_rva': BASE_PACKET_VTABLE_RVA,
        'base_packet_serialize_rva': BASE_PACKET_SERIALIZE_RVA,
        'base_packet_decode_rva': BASE_PACKET_DECODE_RVA,
        'enable_legacy_business_stubs': True,
        'runtime_memset_leaf_rva': None,
    },
    '16.16.805.0442': {
        'runtime_alloc_rva': 0x011928C0,
        'runtime_free_rva': 0x011928F0,
        'base_packet_vtable_rva': 0x01A23AB0,
        'base_packet_serialize_rva': 0x0124C2E0,
        'base_packet_decode_rva': 0x0122E820,
        'enable_legacy_business_stubs': False,
        'runtime_memset_leaf_rva': 0x019D9662,
    },
}

PROFILES = {
    'hero_die': {
        'client_opcode': 0x0454,
        'constructor_rva': 0x00E81E10,
        'deserialize_rva': 0x00EFA1F0,
        'object_size': 0x20,
        'fields': [],
    },
    'notification_012e': {
        'client_opcode': 0x012E,
        'constructor_rva': 0x00E8D650,
        'deserialize_rva': 0x00EF7EA0,
        'object_size': 0x10,
        'fields': [
            {'name': 'decoded_dword', 'offset': 0x0C, 'type': 'u32'},
        ],
    },
    'unit_apply_damage': {
        'client_opcode': 0x028A,
        'constructor_rva': 0x00EB1300,
        'deserialize_rva': 0x00F1C4B0,
        'object_size': 0x34,
        'fields': [
            {
                'name': 'source_network_id',
                'offset': 0x10,
                'type': 'u32',
                'byte_helper_rva': 0x00244840,
            },
            {
                'name': 'extra_amount',
                'offset': 0x14,
                'type': 'f32',
                'byte_helper_rva': 0x002446B0,
            },
            {
                'name': 'field_18',
                'offset': 0x18,
                'type': 'u8',
                'byte_helper_rva': 0x002446E0,
            },
            {
                'name': 'field_1c',
                'offset': 0x1C,
                'type': 'u32',
                'byte_helper_rva': 0x00244890,
            },
            {
                'name': 'field_20',
                'offset': 0x20,
                'type': 'u8',
                'byte_helper_rva': 0x00244870,
            },
            {
                'name': 'field_21',
                'offset': 0x21,
                'type': 'u8',
                'byte_helper_rva': 0x002447B0,
            },
            {
                'name': 'target_network_id',
                'offset': 0x24,
                'type': 'u32',
                'byte_helper_rva': 0x00244700,
            },
            {
                'name': 'amount',
                'offset': 0x2C,
                'type': 'f32',
                'byte_helper_rva': 0x00244600,
            },
            {
                'name': 'field_30',
                'offset': 0x30,
                'type': 'u32',
                'byte_helper_rva': 0x002447F0,
            },
        ],
    },
    'npc_buff_remove2': {
        'client_opcode': 0x0031,
        'constructor_rva': 0x00E80F90,
        'deserialize_rva': 0x010B8500,
        'object_size': 0x1C,
        'fields': [
            {'name': 'raw_param', 'offset': 0x0C, 'type': 'u32'},
            {
                'name': 'buff_slot',
                'offset': 0x10,
                'type': 'u8',
                'byte_helper_rva': 0x008DCFC0,
            },
            {
                'name': 'removal_time_seconds',
                'offset': 0x14,
                'type': 'f32',
                'byte_helper_rva': 0x008DCF60,
            },
            {
                'name': 'buff_name_hash',
                'offset': 0x18,
                'type': 'u32',
                'byte_helper_rva': 0x008DCED0,
            },
        ],
    },
    'npc_buff_add2': {
        'client_opcode': 0x0406,
        'constructor_rva': 0x00E80970,
        'deserialize_rva': 0x010B53F0,
        'object_size': 0x70,
        'fields': [
            {'name': 'raw_param', 'offset': 0x0C, 'type': 'u32'},
            {
                'name': 'running_time_seconds',
                'offset': 0x10,
                'type': 'f32',
                'byte_helper_rva': 0x008DCF30,
            },
            {
                'name': 'field_14',
                'offset': 0x14,
                'type': 'u8',
                'byte_helper_rva': 0x008DD080,
            },
            {
                'name': 'field_18',
                'offset': 0x18,
                'type': 'u32',
                'byte_helper_rva': 0x008DCE90,
            },
            {
                'name': 'duration_seconds',
                'offset': 0x1C,
                'type': 'f32',
                'byte_helper_rva': 0x008DD050,
            },
            {
                'name': 'buff_type',
                'offset': 0x20,
                'type': 'u8',
                'byte_helper_rva': 0x008DCED0,
            },
            {
                'name': 'count',
                'offset': 0x21,
                'type': 'u8',
                'byte_helper_rva': 0x008DCF60,
            },
            {
                'name': 'buff_name_hash',
                'offset': 0x24,
                'type': 'u32',
                'byte_helper_rva': 0x008DCF10,
            },
            {
                'name': 'field_28',
                'offset': 0x28,
                'type': 'u8',
                'byte_helper_rva': 0x008DD0D0,
            },
            {
                'name': 'caster_network_id',
                'offset': 0x2C,
                'type': 'u32',
                'byte_helper_rva': 0x008DCF90,
            },
            {
                'name': 'field_30',
                'offset': 0x30,
                'type': 'u32',
                'byte_helper_rva': 0x008DD030,
            },
            {
                'name': 'field_34',
                'offset': 0x34,
                'type': 'u8',
                'byte_helper_rva': 0x008DCFF0,
            },
            {
                'name': 'field_38',
                'offset': 0x38,
                'type': 'u32',
                'byte_helper_rva': 0x008DCFD0,
            },
            {
                'name': 'field_50',
                'offset': 0x50,
                'type': 'u8',
                'byte_helper_rva': 0x008DCF70,
            },
            {
                'name': 'field_68',
                'offset': 0x68,
                'type': 'u32',
                'byte_helper_rva': 0x008DD0A0,
            },
            {
                'name': 'buff_slot',
                'offset': 0x6C,
                'type': 'u8',
                'byte_helper_rva': 0x008DCFC0,
            },
        ],
    },
    'npc_buff_update_count': {
        'client_opcode': 0x0256,
        'constructor_rva': 0x00E81440,
        'deserialize_rva': 0x010BA590,
        'object_size': 0x24,
        'fields': [
            {'name': 'raw_param', 'offset': 0x0C, 'type': 'u32'},
            {
                'name': 'time_10_seconds',
                'offset': 0x10,
                'type': 'f32',
                'byte_helper_rva': 0x008DCF60,
            },
            {
                'name': 'buff_slot',
                'offset': 0x14,
                'type': 'u8',
                'byte_helper_rva': 0x008DCFC0,
            },
            {
                'name': 'time_18_seconds',
                'offset': 0x18,
                'type': 'f32',
                'byte_helper_rva': 0x008DCFF0,
            },
            {
                'name': 'caster_network_id',
                'offset': 0x1C,
                'type': 'u32',
                'transform': 'buff_update_caster',
            },
            {
                'name': 'count',
                'offset': 0x20,
                'type': 'u8',
                'byte_helper_rva': 0x008DCED0,
            },
        ],
    },
    'cast_spell': {
        'client_opcode': 0x0459,
        'constructor_rva': 0x00E817A0,
        'deserialize_rva': 0x010BBB00,
        'object_size': 0x158,
        'business_constructor_rva': 0x008F5970,
        'business_translate_rva': 0x0090C4C0,
        'business_source_offset': 0x18,
        'business_object_size': 0x194,
        'fields': [
            {'name': 'raw_param', 'offset': 0x0C, 'type': 'u32'},
            {
                'name': 'state_10',
                'offset': 0x10,
                'type': 'u8',
                'transform': 'cast_spell_state',
            },
            {
                'name': 'field_14',
                'offset': 0x14,
                'type': 'u32',
                'transform': 'cast_spell_enum',
            },
        ],
    },
}


def align_up(value, alignment=PAGE_SIZE):
    return (value + alignment - 1) & -alignment


def rotate_right_8(value, count):
    return ((value >> count) | (value << (8 - count))) & 0xFF


def rotate_left_8(value, count):
    return ((value << count) | (value >> (8 - count))) & 0xFF


def parse_args():
    parser = argparse.ArgumentParser(
        description='Emulate the exact Tencent packet constructor and deserializer.',
    )
    parser.add_argument('--image', required=True)
    parser.add_argument('--shapes', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--profile', choices=sorted(PROFILES), default='notification_012e')
    parser.add_argument('--packet-id', type=lambda value: int(value, 0))
    return parser.parse_args()


class ExactPacketEmulator:
    def __init__(self, image, runtime_profile=None):
        self.image = image
        self.runtime_profile = dict(
            RUNTIME_PROFILES['16.15.801.3452'] if runtime_profile is None else runtime_profile
        )
        self.emulator = Uc(UC_ARCH_X86, UC_MODE_64)
        self.emulator.mem_map(IMAGE_BASE, align_up(len(image)), UC_PROT_ALL)
        self.emulator.mem_write(IMAGE_BASE, image)
        self.emulator.mem_map(WORK_BASE, 0x240000, UC_PROT_ALL)
        self.emulator.mem_map(HEAP_BASE, HEAP_SIZE, UC_PROT_ALL)
        self.emulator.mem_write(RETURN_ADDRESS, b'\xcc')
        self.emulator.hook_add(
            UC_HOOK_CODE,
            self._allocate,
            begin=IMAGE_BASE + self.runtime_profile['runtime_alloc_rva'],
            end=IMAGE_BASE + self.runtime_profile['runtime_alloc_rva'],
        )
        self.emulator.hook_add(
            UC_HOOK_CODE,
            self._free,
            begin=IMAGE_BASE + self.runtime_profile['runtime_free_rva'],
            end=IMAGE_BASE + self.runtime_profile['runtime_free_rva'],
        )
        memset_leaf_rva = self.runtime_profile.get('runtime_memset_leaf_rva')
        if memset_leaf_rva is not None:
            self.emulator.hook_add(
                UC_HOOK_CODE,
                self._memset_leaf,
                begin=IMAGE_BASE + memset_leaf_rva,
                end=IMAGE_BASE + memset_leaf_rva,
            )
        if self.runtime_profile.get('enable_legacy_business_stubs', False):
            self.emulator.hook_add(
                UC_HOOK_CODE,
                self._business_id_lookup,
                begin=IMAGE_BASE + BUSINESS_ID_LOOKUP_RVA,
                end=IMAGE_BASE + BUSINESS_ID_LOOKUP_RVA,
            )
            self.emulator.hook_add(
                UC_HOOK_CODE,
                self._business_object_lookup,
                begin=IMAGE_BASE + BUSINESS_OBJECT_LOOKUP_RVA,
                end=IMAGE_BASE + BUSINESS_OBJECT_LOOKUP_RVA,
            )
            self.emulator.hook_add(
                UC_HOOK_CODE,
                self._skip_business_spell_lookup,
                begin=IMAGE_BASE + BUSINESS_SPELL_LOOKUP_RVA,
                end=IMAGE_BASE + BUSINESS_SPELL_LOOKUP_RVA,
            )
            self.emulator.hook_add(
                UC_HOOK_CODE,
                self._skip_business_optional_list,
                begin=IMAGE_BASE + BUSINESS_OPTIONAL_LIST_RVA,
                end=IMAGE_BASE + BUSINESS_OPTIONAL_LIST_RVA,
            )
        self.emulator.hook_add(UC_HOOK_MEM_INVALID, self._invalid_memory)
        self.heap_cursor = HEAP_BASE
        self.invalid_memory = None
        self.profile_state = {}
        self.base_header_cache = {}

    def _return_from_stub(self):
        stack_pointer = self.emulator.reg_read(UC_X86_REG_RSP)
        return_address = struct.unpack(
            '<Q',
            self.emulator.mem_read(stack_pointer, 8),
        )[0]
        self.emulator.reg_write(UC_X86_REG_RSP, stack_pointer + 8)
        self.emulator.reg_write(UC_X86_REG_RIP, return_address)

    def _allocate(self, _emulator, _address, _size, _user_data):
        requested_size = self.emulator.reg_read(UC_X86_REG_RCX)
        allocation_size = max(1, align_up(requested_size, 16))
        allocation_end = self.heap_cursor + allocation_size
        if allocation_end > HEAP_BASE + HEAP_SIZE:
            raise RuntimeError(
                f'emulated heap exhausted while allocating {requested_size} bytes'
            )
        allocation = self.heap_cursor
        self.heap_cursor = allocation_end
        self.emulator.mem_write(allocation, b'\x00' * allocation_size)
        self.emulator.reg_write(UC_X86_REG_RAX, allocation)
        self._return_from_stub()

    def _free(self, _emulator, _address, _size, _user_data):
        self.emulator.reg_write(UC_X86_REG_RAX, 0)
        self._return_from_stub()

    def _memset_leaf(self, _emulator, _address, _size, _user_data):
        destination = self.emulator.reg_read(UC_X86_REG_RCX)
        length = self.emulator.reg_read(UC_X86_REG_R8)
        if length > 0x1000000:
            raise RuntimeError(f'emulated memset length is unreasonable: {length}')
        xmm0 = self.emulator.reg_read(UC_X86_REG_XMM0)
        fill = xmm0 & 0xFF
        if length:
            self.emulator.mem_write(destination, bytes([fill]) * length)
        self.emulator.reg_write(UC_X86_REG_RAX, destination)
        self._return_from_stub()

    def _business_id_lookup(self, _emulator, _address, _size, _user_data):
        output = self.emulator.reg_read(UC_X86_REG_RDX)
        lookup_id = self.emulator.reg_read(UC_X86_REG_R8) & 0xFFFFFFFF
        self.emulator.mem_write(output, struct.pack('<I', lookup_id))
        self.emulator.reg_write(UC_X86_REG_RAX, output)
        self._return_from_stub()

    def _business_object_lookup(self, _emulator, _address, _size, _user_data):
        self.emulator.reg_write(UC_X86_REG_RAX, 0)
        self._return_from_stub()

    def _skip_business_spell_lookup(self, _emulator, _address, _size, _user_data):
        business_object = self.emulator.reg_read(UC_X86_REG_RSI)
        self.emulator.mem_write(business_object, struct.pack('<Q', 0))
        self.emulator.reg_write(
            UC_X86_REG_RIP,
            IMAGE_BASE + BUSINESS_SPELL_LOOKUP_RESUME_RVA,
        )

    def _skip_business_optional_list(self, _emulator, _address, _size, _user_data):
        self.emulator.reg_write(
            UC_X86_REG_RIP,
            IMAGE_BASE + BUSINESS_OPTIONAL_LIST_RESUME_RVA,
        )

    def _invalid_memory(self, _emulator, access, address, size, value, _user_data):
        instruction = self.emulator.reg_read(UC_X86_REG_RIP)
        stack_pointer = self.emulator.reg_read(UC_X86_REG_RSP)
        stack = bytes(self.emulator.mem_read(stack_pointer, 0x100))
        return_addresses = []
        for offset in range(0, len(stack), 8):
            candidate = struct.unpack_from('<Q', stack, offset)[0]
            if IMAGE_BASE <= candidate < IMAGE_BASE + len(self.image):
                return_addresses.append(f'0x{candidate:x}')
        self.invalid_memory = (
            f'invalid memory access type={access} address=0x{address:x} '
            f'size={size} value=0x{value:x} rip=0x{instruction:x} '
            f'stack_returns={return_addresses[:12]}'
        )
        return False

    def reset_heap(self):
        self.heap_cursor = HEAP_BASE

    def call(self, address, rcx=0, rdx=0, r8=0):
        stack_pointer = STACK_BASE + STACK_SIZE - 0x100
        self.emulator.mem_write(stack_pointer, struct.pack('<Q', RETURN_ADDRESS))
        self.emulator.reg_write(UC_X86_REG_RSP, stack_pointer)
        self.emulator.reg_write(UC_X86_REG_RCX, rcx)
        self.emulator.reg_write(UC_X86_REG_RDX, rdx)
        self.emulator.reg_write(UC_X86_REG_R8, r8)
        self.emulator.reg_write(UC_X86_REG_RIP, address)
        self.invalid_memory = None
        try:
            self.emulator.emu_start(address, RETURN_ADDRESS)
        except UcError as error:
            if self.invalid_memory is not None:
                raise RuntimeError(self.invalid_memory) from error
            instruction = self.emulator.reg_read(UC_X86_REG_RIP)
            raise RuntimeError(
                f'Unicorn execution failed at rip=0x{instruction:x}: {error}'
            ) from error
        return self.emulator.reg_read(UC_X86_REG_RAX)

    def decode_bytes(self, value, helper_rva):
        return bytes(
            self.call(IMAGE_BASE + helper_rva, rcx=byte) & 0xFF
            for byte in value
        )

    def prepare_profile(self, profile):
        profile_key = (
            profile['constructor_rva'],
            profile['deserialize_rva'],
            profile['object_size'],
        )
        if profile_key in self.profile_state:
            return self.profile_state[profile_key]

        object_size = profile['object_size']
        self.emulator.mem_write(OBJECT_ADDRESS, b'\xe6' * object_size)
        self.call(IMAGE_BASE + profile['constructor_rva'], rcx=OBJECT_ADDRESS)
        initial_object = bytes(self.emulator.mem_read(OBJECT_ADDRESS, object_size))
        byte_tables = {}
        for field in profile['fields']:
            helper_rva = field.get('byte_helper_rva')
            if helper_rva is None or helper_rva in byte_tables:
                continue
            byte_tables[helper_rva] = bytes(
                self.call(IMAGE_BASE + helper_rva, rcx=byte) & 0xFF
                for byte in range(0x100)
            )
        state = {
            'initial_object': initial_object,
            'byte_tables': byte_tables,
        }
        self.profile_state[profile_key] = state
        return state

    def decode_field(self, object_bytes, field, byte_tables):
        if field['type'] == 'object_vector_records':
            pointer = struct.unpack_from('<Q', object_bytes, field['offset'])[0]
            element_count = struct.unpack_from('<I', object_bytes, field['offset'] + 8)[0]
            capacity = struct.unpack_from('<I', object_bytes, field['offset'] + 12)[0]
            element_size = field.get('element_size')
            if not isinstance(element_size, int) or element_size < 1:
                raise RuntimeError('object_vector_records requires a positive element_size')
            maximum_elements = field.get('maximum_elements', 0x10000)
            length = element_count * element_size
            maximum_length = field.get('maximum_length', 0x100000)
            if (element_count > capacity or element_count > maximum_elements
                    or length > maximum_length):
                raise RuntimeError(
                    f'invalid emulated object vector count={element_count} capacity={capacity} '
                    f'element_size={element_size} byte_length={length}'
                )
            if element_count == 0:
                return []
            valid_ranges = (
                (WORK_BASE, WORK_BASE + 0x240000),
                (HEAP_BASE, HEAP_BASE + HEAP_SIZE),
                (IMAGE_BASE, IMAGE_BASE + len(self.image)),
            )
            if not any(start <= pointer and pointer + length <= end for start, end in valid_ranges):
                raise RuntimeError(
                    f'emulated object vector is outside mapped memory: '
                    f'pointer=0x{pointer:x} byte_length={length}'
                )
            element_fields = field.get('element_fields', [])
            records = []
            for element_index in range(element_count):
                start = pointer + element_index * element_size
                element_bytes = bytes(self.emulator.mem_read(start, element_size))
                record = {'object_hex': element_bytes.hex()}
                for element_field in element_fields:
                    record[element_field['name']] = self.decode_field(
                        element_bytes,
                        element_field,
                        byte_tables,
                    )
                records.append(record)
            return records
        if field['type'] in ('byte_vector_hex', 'object_vector_hex'):
            pointer = struct.unpack_from('<Q', object_bytes, field['offset'])[0]
            element_count = struct.unpack_from('<I', object_bytes, field['offset'] + 8)[0]
            capacity = struct.unpack_from('<I', object_bytes, field['offset'] + 12)[0]
            element_size = 1
            if field['type'] == 'object_vector_hex':
                element_size = field.get('element_size')
                if not isinstance(element_size, int) or element_size < 1:
                    raise RuntimeError('object_vector_hex requires a positive element_size')
            maximum_elements = field.get('maximum_elements', 0x100000)
            maximum_length = field.get('maximum_length', 0x100000)
            length = element_count * element_size
            if (element_count > capacity or element_count > maximum_elements
                    or length > maximum_length):
                raise RuntimeError(
                    f'invalid emulated vector count={element_count} capacity={capacity} '
                    f'element_size={element_size} byte_length={length}'
                )
            if length == 0:
                return ''
            valid_ranges = (
                (WORK_BASE, WORK_BASE + 0x240000),
                (HEAP_BASE, HEAP_BASE + HEAP_SIZE),
                (IMAGE_BASE, IMAGE_BASE + len(self.image)),
            )
            if not any(start <= pointer and pointer + length <= end for start, end in valid_ranges):
                raise RuntimeError(
                    f'emulated byte vector is outside mapped memory: '
                    f'pointer=0x{pointer:x} length={length}'
                )
            return bytes(self.emulator.mem_read(pointer, length)).hex()
        field_size = {
            'u8': 1,
            'u16': 2,
            'u32': 4,
            'u64': 8,
            'i32': 4,
            'f32': 4,
            'f64': 8,
        }[field['type']]
        value = object_bytes[field['offset']:field['offset'] + field_size]
        if 'byte_helper_rva' in field:
            value = value.translate(byte_tables[field['byte_helper_rva']])
        if field.get('transform') == 'cast_spell_state':
            decoded = (value[0] + 0x4F) & 0xFF
            decoded = rotate_right_8(decoded, 3)
            decoded = ((decoded + 0x58) & 0xFF) ^ 0xA0
            decoded = (~self.image[0x01A27940 + decoded]) & 0xFF
            value = bytes([decoded])
        if field.get('transform') == 'cast_spell_enum':
            transformed = bytearray(value)
            for index, encoded in enumerate(transformed):
                decoded = ((encoded - 0x2D) & 0xFF) ^ 0x48
                decoded = (((decoded & 0xD5) << 1) | ((decoded >> 1) & 0x55)) & 0xFF
                transformed[index] = ((decoded + 0x80) & 0xFF) ^ 0x3A
            value = bytes(transformed)
        if field.get('transform') == 'buff_update_caster':
            table = self.image[
                CAST_SPELL_LOOKUP_TABLE_RVA:CAST_SPELL_LOOKUP_TABLE_RVA + 0x100
            ]
            transformed = bytearray(value)
            for index, encoded in enumerate(transformed):
                decoded = table[(encoded + 0x24) & 0xFF]
                decoded = table[(~decoded) & 0xFF]
                decoded = rotate_right_8(((decoded + 0x7F) & 0xFF) ^ 0x1B, 5)
                transformed[index] = decoded
            value = bytes(transformed)
        if field['type'] == 'u8':
            return value[0]
        if field['type'] == 'u16':
            return struct.unpack('<H', value)[0]
        if field['type'] == 'u32':
            return struct.unpack('<I', value)[0]
        if field['type'] == 'u64':
            return struct.unpack('<Q', value)[0]
        if field['type'] == 'i32':
            return struct.unpack('<i', value)[0]
        decoded = struct.unpack('<f' if field['type'] == 'f32' else '<d', value)[0]
        return decoded if math.isfinite(decoded) else None

    def read_emulated_string(self, object_bytes, offset):
        length = struct.unpack_from('<Q', object_bytes, offset + 0x10)[0]
        capacity = struct.unpack_from('<Q', object_bytes, offset + 0x18)[0]
        if length > capacity or length > 0x1000:
            raise RuntimeError(
                f'invalid emulated string length={length} capacity={capacity}'
            )
        if capacity <= 0x0F:
            value = object_bytes[offset:offset + length]
        else:
            pointer = struct.unpack_from('<Q', object_bytes, offset)[0]
            value = bytes(self.emulator.mem_read(pointer, length))
        return value.decode('utf-8', errors='replace')

    def decode_cast_spell_targets(self, object_bytes):
        target_pointer = struct.unpack_from('<Q', object_bytes, 0xA8)[0]
        target_count = struct.unpack_from('<I', object_bytes, 0xB0)[0]
        if target_count > 0x20:
            raise RuntimeError(f'cast spell target count exceeded client limit: {target_count}')
        if target_count == 0:
            return []
        target_end = target_pointer + target_count * 0x10
        if target_pointer < HEAP_BASE or target_end > HEAP_BASE + HEAP_SIZE:
            raise RuntimeError(
                f'cast spell target list is outside emulated heap: '
                f'pointer=0x{target_pointer:x} count={target_count}'
            )
        table = self.image[
            CAST_SPELL_LOOKUP_TABLE_RVA:CAST_SPELL_LOOKUP_TABLE_RVA + 0x100
        ]
        targets = []
        for index in range(target_count):
            entry = bytes(self.emulator.mem_read(target_pointer + index * 0x10, 0x10))
            decoded_id = bytearray(4)
            for byte_index, encoded in enumerate(entry[0x0C:0x10]):
                lookup_index = rotate_left_8(
                    (rotate_right_8(encoded, 3) + 0x1C) & 0xFF,
                    1,
                )
                decoded_id[byte_index] = (~table[lookup_index]) & 0xFF
            hit_index = ((entry[0x08] + 0x1D) & 0xFF) ^ 0x6A
            hit_index = table[hit_index] ^ 0xEB
            hit_result = table[table[hit_index]]
            targets.append({
                'network_id': struct.unpack('<I', decoded_id)[0],
                'hit_result': hit_result,
            })
        return targets

    def decode_cast_spell_business_fields(self, object_bytes, business_object_bytes):
        targets = self.decode_cast_spell_targets(object_bytes)
        cast_time_seconds = struct.unpack_from('<f', business_object_bytes, 0x164)[0]
        vectors = {}
        for name, offset in (
            ('target_position', 0xD0),
            ('target_position_end', 0xDC),
            ('cast_direction', 0x100),
        ):
            value = struct.unpack_from('<fff', business_object_bytes, offset)
            vectors[name] = list(value) if all(math.isfinite(item) for item in value) else None
        return {
            'spell_key': struct.unpack_from('<I', business_object_bytes, 0x14)[0],
            'caster_name': self.read_emulated_string(business_object_bytes, 0x20),
            'caster_network_id': struct.unpack_from('<I', business_object_bytes, 0xA0)[0],
            'spell_chain_owner_network_id': struct.unpack_from(
                '<I', business_object_bytes, 0xA4
            )[0],
            'targets': targets,
            'target_network_id': targets[0]['network_id'] if len(targets) == 1 else None,
            'cast_time_seconds': (
                cast_time_seconds if math.isfinite(cast_time_seconds) else None
            ),
            **vectors,
        }

    def encode_base_header(self, packet_id, raw_param):
        cache_key = (packet_id, raw_param)
        cached = self.base_header_cache.get(cache_key)
        if cached is not None:
            return cached
        self.emulator.mem_write(
            BASE_PACKET_ADDRESS,
            struct.pack(
                '<QHHI',
                IMAGE_BASE + self.runtime_profile['base_packet_vtable_rva'],
                packet_id,
                0,
                raw_param,
            ),
        )
        self.emulator.mem_write(
            VECTOR_ADDRESS,
            struct.pack('<QII', VECTOR_BUFFER_ADDRESS, 0, 0x100),
        )
        self.call(
            IMAGE_BASE + self.runtime_profile['base_packet_serialize_rva'],
            rcx=BASE_PACKET_ADDRESS,
            rdx=VECTOR_ADDRESS,
        )
        header_size = struct.unpack(
            '<I',
            self.emulator.mem_read(VECTOR_ADDRESS + 8, 4),
        )[0]
        if header_size > 0x100:
            raise RuntimeError(f'base packet header exceeded workspace: {header_size}')
        header = bytes(self.emulator.mem_read(VECTOR_BUFFER_ADDRESS, header_size))
        self.base_header_cache[cache_key] = header
        return header

    def decode(self, payload, profile, packet_id=None, raw_param=None):
        wrapped = packet_id is not None and raw_param is not None
        if wrapped:
            base_header = self.encode_base_header(packet_id, raw_param)
            wire_payload = base_header + payload
        else:
            base_header = b''
            wire_payload = payload
        if len(wire_payload) > STACK_BASE - PAYLOAD_ADDRESS:
            raise ValueError(
                f'payload is too large for emulator workspace: {len(wire_payload)}'
            )
        object_size = profile['object_size']
        state = self.prepare_profile(profile)
        self.reset_heap()
        self.emulator.mem_write(OBJECT_ADDRESS, state['initial_object'])
        self.emulator.mem_write(CURSOR_ADDRESS, struct.pack('<Q', PAYLOAD_ADDRESS))
        if wire_payload:
            self.emulator.mem_write(PAYLOAD_ADDRESS, wire_payload)
        wrapper_return = None
        decoded_opcode = None
        wrapper_bytes_consumed = 0
        if wrapped:
            self.emulator.mem_write(OPCODE_ADDRESS, b'\x00' * 8)
            wrapper_return = self.call(
                IMAGE_BASE + self.runtime_profile['base_packet_decode_rva'],
                rcx=CURSOR_ADDRESS,
                rdx=PAYLOAD_ADDRESS + len(wire_payload),
                r8=OPCODE_ADDRESS,
            )
            decoded_opcode = struct.unpack(
                '<H',
                self.emulator.mem_read(OPCODE_ADDRESS, 2),
            )[0]
            wrapper_cursor = struct.unpack(
                '<Q',
                self.emulator.mem_read(CURSOR_ADDRESS, 8),
            )[0]
            wrapper_bytes_consumed = wrapper_cursor - PAYLOAD_ADDRESS
        self.call(IMAGE_BASE + profile['constructor_rva'], rcx=OBJECT_ADDRESS)
        return_value = self.call(
            IMAGE_BASE + profile['deserialize_rva'],
            rcx=OBJECT_ADDRESS,
            rdx=CURSOR_ADDRESS,
            r8=PAYLOAD_ADDRESS + len(wire_payload),
        )
        cursor = struct.unpack('<Q', self.emulator.mem_read(CURSOR_ADDRESS, 8))[0]
        object_bytes = bytes(self.emulator.mem_read(OBJECT_ADDRESS, object_size))
        business_object_bytes = None
        if 'business_translate_rva' in profile:
            business_object_size = profile['business_object_size']
            self.emulator.mem_write(
                BUSINESS_OBJECT_ADDRESS,
                b'\xe6' * business_object_size,
            )
            self.call(
                IMAGE_BASE + profile['business_constructor_rva'],
                rcx=BUSINESS_OBJECT_ADDRESS,
            )
            self.call(
                IMAGE_BASE + profile['business_translate_rva'],
                rcx=BUSINESS_OBJECT_ADDRESS,
                rdx=OBJECT_ADDRESS + profile['business_source_offset'],
            )
            business_object_bytes = bytes(
                self.emulator.mem_read(BUSINESS_OBJECT_ADDRESS, business_object_size)
            )
        fields = {
            field['name']: self.decode_field(object_bytes, field, state['byte_tables'])
            for field in profile['fields']
        }
        if profile is PROFILES['cast_spell']:
            fields.update(
                self.decode_cast_spell_business_fields(object_bytes, business_object_bytes)
            )
        result = {
            'deserialize_return_al': return_value & 0xFF,
            'bytes_consumed': cursor - PAYLOAD_ADDRESS,
            'fully_consumed': cursor == PAYLOAD_ADDRESS + len(wire_payload),
            'object_hex': object_bytes.hex(),
            'decoded_fields': fields,
        }
        if business_object_bytes is not None:
            result['business_object_hex'] = business_object_bytes.hex()
        if wrapped:
            result.update({
                'base_header_hex': base_header.hex(),
                'wrapper_return_al': wrapper_return & 0xFF,
                'wrapper_bytes_consumed': wrapper_bytes_consumed,
                'decoded_opcode': decoded_opcode,
                'decoded_opcode_hex': f'0x{decoded_opcode:04x}',
                'opcode_matches_profile': decoded_opcode == profile['client_opcode'],
            })
        for field in profile['fields']:
            if field['type'] == 'u32':
                result[f"{field['name']}_hex"] = f"0x{fields[field['name']]:08x}"
        if profile is PROFILES['notification_012e']:
            result['decoded_dword'] = fields['decoded_dword']
            result['decoded_dword_hex'] = result['decoded_dword_hex']
            result['decoded_float'] = struct.unpack_from('<f', object_bytes, 0x0C)[0]
            if not math.isfinite(result['decoded_float']):
                result['decoded_float'] = None
        return result


def main():
    options = parse_args()
    with open(options.image, 'rb') as stream:
        image = stream.read()
    with open(options.shapes, encoding='utf-8-sig') as stream:
        shape_bundle = json.load(stream)
    profile = PROFILES[options.profile]
    emulator = ExactPacketEmulator(image)
    shapes = shape_bundle['shapes']
    if options.packet_id is not None:
        shapes = [shape for shape in shapes if shape['packet_id'] == options.packet_id]
    results = []
    full_consume_shape_count = 0
    successful_shape_count = 0
    for shape in shapes:
        samples = []
        for sample in shape['samples']:
            decoded = emulator.decode(
                bytes.fromhex(sample['raw_payload_hex']),
                profile,
                packet_id=sample.get('packet_id'),
                raw_param=sample.get('raw_param'),
            )
            samples.append({**sample, **decoded})
        all_successful = bool(samples) and all(
            sample['deserialize_return_al'] != 0 for sample in samples
        )
        all_fully_consumed = all_successful and all(
            sample['fully_consumed'] for sample in samples
        )
        successful_shape_count += int(all_successful)
        full_consume_shape_count += int(all_fully_consumed)
        results.append({
            'packet_id': shape['packet_id'],
            'payload_length': shape['payload_length'],
            'occurrence_count': shape['occurrence_count'],
            'replay_count': shape['replay_count'],
            'all_samples_successful': all_successful,
            'all_samples_fully_consumed': all_fully_consumed,
            'samples': samples,
        })
    output = {
        'schema_version': 1,
        'target_replay_version': shape_bundle['target_replay_version'],
        'method': 'Unicorn x86-64 execution of exact unpacked Tencent image',
        'profile': options.profile,
        'image_path': os.path.abspath(options.image),
        'image_sha256': hashlib.sha256(image).hexdigest(),
        'image_base': f'0x{IMAGE_BASE:x}',
        'client_opcode': f"0x{profile['client_opcode']:04x}",
        'constructor_rva': f"0x{profile['constructor_rva']:08x}",
        'deserialize_rva': f"0x{profile['deserialize_rva']:08x}",
        'object_size': profile['object_size'],
        'fields': profile['fields'],
        'packet_id_filter': options.packet_id,
        'shape_count': len(results),
        'successful_shape_count': successful_shape_count,
        'full_consume_shape_count': full_consume_shape_count,
        'results': results,
    }
    output_path = os.path.abspath(options.output)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8', newline='\n') as stream:
        json.dump(output, stream, ensure_ascii=True, indent=2)
        stream.write('\n')
    print(json.dumps({
        'output': output_path,
        'shape_count': output['shape_count'],
        'successful_shape_count': successful_shape_count,
        'full_consume_shape_count': full_consume_shape_count,
    }, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'{type(error).__name__}: {error}', file=sys.stderr)
        sys.exit(1)

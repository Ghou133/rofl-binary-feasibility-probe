#!/usr/bin/env python3

"""Trace exact-build hero/combat callback names to packet factory objects.

The input is a mapped League x86-64 module image: file offsets equal RVAs.  The
script intentionally separates the compiler-generated ``std::function`` manager
table used by callback registration from the packet object's real vtable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
from pathlib import Path

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import (
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_EAX,
    X86_REG_ECX,
    X86_REG_ESI,
    X86_REG_R8,
    X86_REG_R8D,
    X86_REG_RAX,
    X86_REG_RCX,
    X86_REG_RIP,
    X86_REG_RSI,
    X86_REG_RSP,
)


IMAGE_BASE = 0x140000000
TARGET_BUILD = '16.16.805.0442'
EXPECTED_SHA256 = '0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55'

TARGET_NAMES = (
    'PKT_S2C_HeroStats_s',
    'PKT_S2C_StatFormulaOutputs_s',
    'PKT_NPC_BuffUpdateStatAdjustments_s',
    'PKT_CombatStateChanged_s',
    'PKT_SetAbilityResourceState_s',
    'PKT_S2C_ReplicateField_s',
    'PKT_S2C_ReplicateFields_s',
    'PKT_S2C_OnEnterTeamVisibility_s',
)

BASE_PACKET_VTABLE_RVA = 0x01A23AB0
BASE_PACKET_SERIALIZE_RVA = 0x0124C2E0
BASE_PACKET_DECODE_WRAPPER_RVA = 0x0122E820

# Independently supplied route migrations are re-derived from the factory and
# constructor bytes.  Only 0x010c is expected to intersect TARGET_NAMES.
STRUCTURAL_ROUTE_EXPECTATIONS = {
    0x010C: {
        'case_rva': 0x00EDD8E7,
        'constructor_rva': 0x00E8CF30,
        'vtable_rva': 0x01B11128,
        'deserialize_rva': 0x00F0A220,
        'legacy_shape_hint': 'old 0x003d fixed 1479-byte structural family',
    },
    0x0178: {
        'case_rva': 0x00EDEF67,
        'constructor_rva': 0x00E790F0,
        'vtable_rva': 0x01B0FE50,
        'deserialize_rva': 0x00EF4D80,
        'legacy_shape_hint': 'old 0x0439 65-79-byte structural family',
    },
    0x0302: {
        'case_rva': 0x00EE3E57,
        'constructor_rva': 0x00E932C0,
        'vtable_rva': 0x01B11940,
        'deserialize_rva': 0x00F69C20,
        'legacy_shape_hint': 'likely old 0x00e7 fixed two-byte generic family',
    },
    0x0405: {
        'case_rva': 0x00EE73B5,
        'constructor_rva': 0x00E9BF80,
        'vtable_rva': 0x01B13F38,
        'deserialize_rva': 0x0100DD30,
        'legacy_shape_hint': 'old 0x0298 7-9-byte structural family',
    },
    0x04CA: {
        'case_rva': 0x00EE9B99,
        'constructor_rva': 0x00E7A430,
        'vtable_rva': 0x01B172A8,
        'deserialize_rva': 0x0109BF40,
        'legacy_shape_hint': 'old 0x03da 17-34-byte structural family',
    },
    0x017F: {
        'constructor_rva': 0x00EAC750,
        'vtable_rva': 0x01B109B8,
        'deserialize_rva': 0x00F20F20,
        'legacy_shape_hint': 'independently recovered current-build Damage route',
    },
}


# Exact-build storage-layout evidence.  Field labels intentionally describe
# encoded storage shape, not gameplay semantics.  Every RVA is revalidated
# against the SHA-gated image before it is emitted.
STATIC_LAYOUT_EVIDENCE = {
    'PKT_S2C_HeroStats_s': {
        'expected_object_size': 0x28,
        'storage_fields': [
            {'offset': 0x10, 'size': 4, 'shape': 'encoded_u32'},
            {
                'offset': 0x18,
                'size': 0x10,
                'shape': 'byte_vector_header',
                'pointer_offset': 0x18,
                'count_offset': 0x20,
                'capacity_offset': 0x24,
                'element_stride': 1,
            },
        ],
        'required_helper_rvas': [0x0122E8C0, 0x00F32850, 0x00E53640, 0x002361D0],
        'packet_vtable_slot_3_rva': 0x00303DD0,
        'runtime_observation': (
            'Independent exact emulation recovered a 1476-byte +0x18 byte '
            'vector from fixed 1479-byte payloads; this route is a cumulative '
            'scoreboard/tail-stat carrier rather than proved live combat state.'
        ),
    },
    'PKT_S2C_StatFormulaOutputs_s': {
        'expected_object_size': 0x28,
        'storage_fields': [
            {'offset': 0x10, 'size': 4, 'shape': 'encoded_u32'},
            {
                'offset': 0x18,
                'size': 0x10,
                'shape': 'object_vector_header',
                'pointer_offset': 0x18,
                'count_offset': 0x20,
                'capacity_offset': 0x24,
                'element_stride': 0x20,
            },
        ],
        'required_helper_rvas': [
            0x0122E8C0, 0x00F32850, 0x00E63AF0, 0x00EBB270,
            0x00E55440, 0x00F48310,
        ],
        'packet_vtable_slot_3_rva': 0x003794A0,
        'nested_element': {
            'vtable_rva': 0x01B10DD8,
            'deserializer_rva': 0x00F2D210,
            'size_getter_rva': 0x00317210,
            'object_size': 0x20,
            'storage_fields': [
                {'offset': 0x08, 'size': 4, 'shape': 'encoded_u32'},
                {
                    'offset': 0x10,
                    'size': 0x10,
                    'shape': 'encoded_u32_vector_header',
                    'count_offset': 0x18,
                    'capacity_offset': 0x1C,
                    'element_stride': 4,
                },
            ],
            'required_helper_rvas': [0x00E627D0, 0x00347E40, 0x00E5C0D0],
        },
    },
    'PKT_NPC_BuffUpdateStatAdjustments_s': {
        'expected_object_size': 0x28,
        'storage_fields': [
            {'offset': 0x10, 'size': 1, 'shape': 'encoded_u8'},
            {
                'offset': 0x18,
                'size': 0x10,
                'shape': 'object_vector_header',
                'pointer_offset': 0x18,
                'count_offset': 0x20,
                'capacity_offset': 0x24,
                'element_stride': 0x1C,
            },
        ],
        'required_helper_rvas': [
            0x0122E8C0, 0x00F32850, 0x0106BF10, 0x00EBB3C0,
            0x01119810,
        ],
        'packet_vtable_slot_3_rva': 0x00EB6F50,
        'nested_element': {
            'vtable_rva': 0x01B16A60,
            'deserializer_rva': 0x010FCC10,
            'size_getter_rva': 0x002841B0,
            'object_size': 0x1C,
            'storage_fields': [
                {'offset': offset, 'size': 4, 'shape': 'encoded_dword'}
                for offset in (0x08, 0x0C, 0x10, 0x14, 0x18)
            ],
            'required_helper_rvas': [
                0x0106D9E0, 0x0106E950, 0x0106BF10,
                0x0106DFB0, 0x0106E220,
            ],
        },
    },
    'PKT_CombatStateChanged_s': {
        'expected_object_size': 0x18,
        'storage_fields': [
            {'offset': 0x10, 'size': 1, 'shape': 'encoded_u8'},
            {'offset': 0x14, 'size': 4, 'shape': 'encoded_u32'},
        ],
        'required_helper_rvas': [0x0122E8C0, 0x00F32850, 0x00E627D0, 0x00E634C0],
        'packet_vtable_slot_3_rva': 0x001E81B0,
        'inventory_boundary': 'No rows in the bounded latest-four Replay inventory.',
    },
    'PKT_SetAbilityResourceState_s': {
        'expected_object_size': 0x1C,
        'storage_fields': [
            {'offset': 0x10, 'size': 4, 'shape': 'encoded_u32'},
            {'offset': 0x14, 'size': 1, 'shape': 'encoded_u8'},
            {'offset': 0x18, 'size': 4, 'shape': 'encoded_u32'},
        ],
        'required_helper_rvas': [
            0x0122E8C0, 0x00F32850, 0x00F94BB0, 0x00F946C0, 0x00F94890,
        ],
        'packet_vtable_slot_3_rva': 0x0026B9F0,
        'inventory_boundary': 'No rows in the bounded latest-four Replay inventory.',
    },
    'PKT_S2C_ReplicateFields_s': {
        'expected_object_size': 0x38,
        'storage_fields': [
            {'offset': 0x10, 'size': 1, 'shape': 'encoded_u8'},
            {
                'offset': 0x18,
                'size': 0x10,
                'shape': 'byte_vector_header',
                'pointer_offset': 0x18,
                'count_offset': 0x20,
                'capacity_offset': 0x24,
                'element_stride': 1,
            },
            {
                'offset': 0x28,
                'size': 0x10,
                'shape': 'byte_vector_header',
                'pointer_offset': 0x28,
                'count_offset': 0x30,
                'capacity_offset': 0x34,
                'element_stride': 1,
            },
        ],
        'required_helper_rvas': [
            0x0122E8C0, 0x00F32850, 0x00E52610, 0x00EEB540, 0x002361D0,
        ],
        'packet_vtable_slot_3_rva': 0x00EB9200,
        'callback_read_evidence_rva': 0x0038E380,
        'runtime_observation': (
            'All 13163 bounded rows exact-emulated/full-consumed. Payload-3 '
            'rows decoded first vector 00; payload-7 rows decoded first vector '
            '0000000000; the second vector was empty in all rows.'
        ),
    },
    'PKT_S2C_ReplicateField_s': {
        'expected_object_size_minimum': 0x28,
        'storage_fields': [
            {'offset': 0x10, 'size': 2, 'shape': 'externally_populated_encoded_u16'},
            {
                'offset': 0x18,
                'size': 0x10,
                'shape': 'byte_vector_header',
                'pointer_offset': 0x18,
                'count_offset': 0x20,
                'capacity_offset': 0x24,
                'element_stride': 1,
            },
        ],
        'required_helper_rvas': [0x0122E8C0, 0x002361D0],
        'non_factory_decode_like_rva': 0x00F186B0,
        'callback_read_evidence_rva': 0x0038E2E0,
        'route_scope': (
            'Registration ID 0x04df is one above direct factory maximum 0x04de. '
            'No direct factory case/constructor/vtable is claimed.'
        ),
    },
    'PKT_S2C_OnEnterTeamVisibility_s': {
        'expected_object_size': 0x14,
        'storage_fields': [
            {'offset': 0x10, 'size': 1, 'shape': 'encoded_u8'},
        ],
        'required_helper_rvas': [0x0122E8C0, 0x00F32850, 0x00F51540],
        'packet_vtable_slot_3_rva': 0x002135E0,
        'callback_read_evidence_rva': 0x0038E260,
        'semantic_negative_control': (
            'RTTI proves OnEnterTeamVisibility; this high-frequency fixed-two-byte '
            'route is not a health/stat replication carrier.'
        ),
    },
}


def parse_int(value: str) -> int:
    return int(value, 0)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            'Trace exact 16.16 callback RTTI names through callback '
            'registration and the packet factory to constructors/vtables.'
        ),
    )
    parser.add_argument('--image', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--expected-sha256', default=EXPECTED_SHA256)
    parser.add_argument('--factory-rva', type=parse_int)
    parser.add_argument(
        '--enumerate-all-callbacks',
        action='store_true',
        help=(
            'Enumerate every MakeFunction callback TypeDescriptor carrying a '
            'PKT_*_s type and best-effort map it to registration/factory routes.'
        ),
    )
    parser.add_argument(
        '--inventory-json',
        help=(
            'Optional exact-build packet coverage inventory to intersect with '
            'the enumerated callback registration map.'
        ),
    )
    parser.add_argument(
        '--route-map-output',
        help='Optional compact observed packet_id-to-callback-name JSON output.',
    )
    return parser.parse_args()


def hx(value: int | None, width: int = 8) -> str | None:
    if value is None:
        return None
    return f'0x{value:0{width}x}'


def address_record(rva: int) -> dict:
    return {
        'rva': rva,
        'rva_hex': hx(rva),
        'va_hex': f'0x{IMAGE_BASE + rva:016x}',
    }


def instruction_record(insn) -> dict:
    return {
        **address_record(insn.address - IMAGE_BASE),
        'bytes': insn.bytes.hex(),
        'mnemonic': insn.mnemonic,
        'operands': insn.op_str,
    }


def executable_ranges(image: bytes, pe: pefile.PE) -> list[tuple[int, int]]:
    result = []
    for section in pe.sections:
        if not section.Characteristics & 0x20000000:
            continue
        start = section.VirtualAddress
        size = max(section.Misc_VirtualSize, section.SizeOfRawData)
        result.append((start, min(start + size, len(image))))
    return result


def is_executable(rva: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start <= rva < end for start, end in ranges)


def function_ranges(image: bytes, pe: pefile.PE) -> list[tuple[int, int, int]]:
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    result = []
    for offset in range(directory.VirtualAddress,
                        directory.VirtualAddress + directory.Size, 12):
        begin, end, unwind = struct.unpack_from('<III', image, offset)
        if begin < end <= len(image):
            result.append((begin, end, unwind))
    return result


def containing_function(
    ranges: list[tuple[int, int, int]],
    rva: int,
) -> tuple[int, int, int] | None:
    matches = [entry for entry in ranges if entry[0] <= rva < entry[1]]
    if not matches:
        return None
    return min(matches, key=lambda entry: entry[1] - entry[0])


def function_record(entry: tuple[int, int, int] | None) -> dict | None:
    if entry is None:
        return None
    return {
        'begin_rva': entry[0],
        'begin_rva_hex': hx(entry[0]),
        'end_rva': entry[1],
        'end_rva_hex': hx(entry[1]),
        'size': entry[1] - entry[0],
        'unwind_rva': entry[2],
        'unwind_rva_hex': hx(entry[2]),
    }


class StaticImage:
    def __init__(self, image: bytes, pe: pefile.PE):
        self.image = image
        self.pe = pe
        self.executable = executable_ranges(image, pe)
        self.pdata = function_ranges(image, pe)
        self.decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        self.decoder.detail = True
        self._function_cache: dict[tuple[int, int], list] = {}

    def disassemble(self, start: int, end: int) -> list:
        return list(self.decoder.disasm(
            self.image[start:end], IMAGE_BASE + start,
        ))

    def disassemble_function(self, entry: tuple[int, int, int]) -> list:
        key = (entry[0], entry[1])
        if key not in self._function_cache:
            self._function_cache[key] = self.disassemble(*key)
        return self._function_cache[key]

    def function_for(self, rva: int) -> tuple[int, int, int] | None:
        return containing_function(self.pdata, rva)

    def qword_rva(self, offset: int) -> int | None:
        if offset < 0 or offset + 8 > len(self.image):
            return None
        value = struct.unpack_from('<Q', self.image, offset)[0]
        rva = value - IMAGE_BASE
        if not 0 <= rva < len(self.image):
            return None
        return rva

    def lea_xrefs(self, target_rva: int) -> list:
        """Find and validate seven-byte REX.W LEA reg,[RIP+disp32] xrefs."""
        result = []
        for section_start, section_end in self.executable:
            cursor = section_start
            while True:
                opcode = self.image.find(b'\x8d', cursor, section_end)
                if opcode < 0 or opcode + 6 > section_end:
                    break
                cursor = opcode + 1
                start = opcode - 1
                if start < section_start:
                    continue
                rex = self.image[start]
                modrm = self.image[opcode + 1]
                if not 0x48 <= rex <= 0x4f or (modrm & 0xc7) != 0x05:
                    continue
                disp = struct.unpack_from('<i', self.image, opcode + 2)[0]
                destination = start + 7 + disp
                if destination != target_rva:
                    continue
                decoded = self.disassemble(start, start + 15)
                if not decoded:
                    continue
                insn = decoded[0]
                if insn.mnemonic != 'lea' or insn.size != 7:
                    continue
                if not any(
                    operand.type == X86_OP_MEM
                    and operand.mem.base == X86_REG_RIP
                    and insn.address + insn.size + operand.mem.disp
                    == IMAGE_BASE + target_rva
                    for operand in insn.operands
                ):
                    continue
                result.append(insn)
        return result

    def direct_call_xrefs(self, target_rva: int) -> list:
        result = []
        for section_start, section_end in self.executable:
            cursor = section_start
            while True:
                source = self.image.find(b'\xe8', cursor, section_end)
                if source < 0 or source + 5 > section_end:
                    break
                cursor = source + 1
                destination = source + 5 + struct.unpack_from(
                    '<i', self.image, source + 1,
                )[0]
                if destination != target_rva:
                    continue
                owner = self.function_for(source)
                if owner is None:
                    continue
                insn = next((candidate for candidate in self.disassemble_function(owner)
                             if candidate.address - IMAGE_BASE == source), None)
                if (insn is not None and insn.mnemonic == 'call'
                        and insn.operands
                        and insn.operands[0].type == X86_OP_IMM
                        and insn.operands[0].imm - IMAGE_BASE == target_rva):
                    result.append(insn)
        return result


def direct_call_target(insn) -> int | None:
    if (insn.mnemonic == 'call' and insn.operands
            and insn.operands[0].type == X86_OP_IMM):
        return insn.operands[0].imm - IMAGE_BASE
    return None


def read_c_string(image: bytes, start: int) -> str:
    end = image.find(b'\0', start)
    if end < 0:
        raise ValueError(f'unterminated C string at {start:#x}')
    return image[start:end].decode('ascii', errors='strict')


CALLBACK_PACKET_NAME_RE = re.compile(rb'PKT_[A-Za-z0-9_]+_s')


def discover_callback_descriptor_instances(image: bytes) -> list[dict]:
    """Discover MSVC MakeFunction TypeDescriptor strings without name guesses."""
    starts = set()
    cursor = 0
    needle = b'MakeFunction@'
    while True:
        occurrence = image.find(needle, cursor)
        if occurrence < 0:
            break
        cursor = occurrence + 1
        start = image.rfind(b'\0', max(0, occurrence - 0x2000), occurrence) + 1
        starts.add(start)

    result = []
    for start in sorted(starts):
        try:
            mangled = read_c_string(image, start)
        except (UnicodeDecodeError, ValueError):
            continue
        encoded = mangled.encode('ascii')
        names = sorted({
            match.decode('ascii')
            for match in CALLBACK_PACKET_NAME_RE.findall(encoded)
        })
        if not names:
            continue
        for name in names:
            result.append({
                'name': name,
                'string_start_rva': start,
                'string_start_rva_hex': hx(start),
                'name_occurrence_count_in_string': encoded.count(name.encode('ascii')),
            })
    return result


def locate_callback_descriptor(
    static: StaticImage,
    name: str,
    string_start_override: int | None = None,
) -> dict:
    needle = name.encode('ascii')
    if string_start_override is None:
        offsets = []
        cursor = 0
        while True:
            offset = static.image.find(needle, cursor)
            if offset < 0:
                break
            offsets.append(offset)
            cursor = offset + 1
        if not offsets:
            raise ValueError(f'{name}: string not present')

        string_starts = {
            static.image.rfind(b'\0', max(0, offset - 0x800), offset) + 1
            for offset in offsets
        }
        if len(string_starts) != 1:
            raise ValueError(f'{name}: expected one containing mangled C string')
        string_start = next(iter(string_starts))
    else:
        string_start = string_start_override
    mangled = read_c_string(static.image, string_start)
    offsets = []
    cursor = string_start
    string_end = string_start + len(mangled)
    while True:
        offset = static.image.find(needle, cursor, string_end)
        if offset < 0:
            break
        offsets.append(offset)
        cursor = offset + 1
    if not offsets:
        raise ValueError(
            f'{name}: not present in override mangled string {string_start:#x}',
        )
    if not all(string_start <= offset < string_start + len(mangled)
               for offset in offsets):
        raise ValueError(f'{name}: occurrences escape containing C string')
    descriptor_rva = string_start - 16
    type_info_vftable = struct.unpack_from('<Q', static.image, descriptor_rva)[0]
    spare = struct.unpack_from('<Q', static.image, descriptor_rva + 8)[0]
    if spare != 0 or not IMAGE_BASE <= type_info_vftable < IMAGE_BASE + len(static.image):
        raise ValueError(f'{name}: invalid MSVC TypeDescriptor header')

    accessor_candidates = []
    for insn in static.lea_xrefs(descriptor_rva):
        rva = insn.address - IMAGE_BASE
        trailing = static.image[rva + insn.size:rva + insn.size + 1]
        if (insn.operands[0].type == X86_OP_REG
                and insn.operands[0].reg == X86_REG_RAX
                and trailing == b'\xc3'):
            accessor_candidates.append(insn)
    if len(accessor_candidates) != 1:
        raise ValueError(
            f'{name}: expected one lea/ret type accessor, got '
            f'{len(accessor_candidates)}',
        )
    accessor = accessor_candidates[0]
    accessor_rva = accessor.address - IMAGE_BASE

    accessor_va = struct.pack('<Q', IMAGE_BASE + accessor_rva)
    table_candidates = []
    cursor = 0
    while True:
        reference = static.image.find(accessor_va, cursor)
        if reference < 0:
            break
        cursor = reference + 1
        table_rva = reference - 3 * 8
        entries = [static.qword_rva(table_rva + index * 8) for index in range(6)]
        if (entries[3] == accessor_rva
                and entries[0] == entries[1]
                and all(entry is not None and is_executable(entry, static.executable)
                        for entry in entries)):
            table_candidates.append((reference, table_rva, entries))
    if len(table_candidates) != 1:
        raise ValueError(
            f'{name}: expected one callback manager table, got '
            f'{len(table_candidates)}',
        )
    accessor_reference, manager_table_rva, manager_entries = table_candidates[0]

    manager_xrefs = static.lea_xrefs(manager_table_rva)
    non_manager_xrefs = [
        insn for insn in manager_xrefs
        if insn.address - IMAGE_BASE not in set(manager_entries[:2])
    ]
    # Some callback manager tables are also loaded by runtime type-erasure
    # comparison/dispatch code.  A real registration construction xref is
    # followed in the same function by a call to the manager entry and an r8d
    # packet-ID immediate.  This keeps those non-construction RTTI uses as
    # negative context instead of treating them as ambiguous registrations.
    construction_xrefs = list(non_manager_xrefs) if len(non_manager_xrefs) == 1 else []
    rejected_context_xrefs = []
    for candidate in ([] if len(non_manager_xrefs) == 1 else non_manager_xrefs):
        candidate_rva = candidate.address - IMAGE_BASE
        owner = static.function_for(candidate_rva)
        if owner is None:
            rejected_context_xrefs.append(candidate)
            continue
        insns = static.disassemble_function(owner)
        index = instruction_index(insns, candidate_rva)
        window = insns[index:index + 80]
        manager_call_seen = any(
            direct_call_target(insn) == manager_entries[0] for insn in window
        )
        id_write_seen = any(
            insn.mnemonic == 'mov'
            and len(insn.operands) == 2
            and insn.operands[0].type == X86_OP_REG
            and insn.operands[0].reg == X86_REG_R8D
            and insn.operands[1].type == X86_OP_IMM
            for insn in window
        )
        if manager_call_seen and id_write_seen:
            construction_xrefs.append(candidate)
        else:
            rejected_context_xrefs.append(candidate)
    if len(construction_xrefs) != 1:
        raise ValueError(
            f'{name}: expected one non-manager table construction xref, got '
            f'{len(construction_xrefs)}',
        )
    construction = construction_xrefs[0]

    construction_rva = construction.address - IMAGE_BASE
    construction_owner = static.function_for(construction_rva)
    callback_receive_candidates = []
    callback_receive_evidence = (
        'executable RVA loaded into the callback closure between the '
        'manager-table construction xref and manager copy call'
    )
    if construction_owner is not None:
        construction_insns = static.disassemble_function(construction_owner)
        construction_index = instruction_index(construction_insns, construction_rva)
        for insn in construction_insns[construction_index + 1:construction_index + 80]:
            if direct_call_target(insn) == manager_entries[0]:
                break
            if insn.mnemonic != 'lea' or len(insn.operands) != 2:
                continue
            destination, source = insn.operands
            if not (
                destination.type == X86_OP_REG
                and destination.reg == X86_REG_RAX
                and source.type == X86_OP_MEM
                and source.mem.base == X86_REG_RIP
            ):
                continue
            target = insn.address + insn.size + source.mem.disp - IMAGE_BASE
            if is_executable(target, static.executable):
                callback_receive_candidates.append((insn, target))

        # The common out-of-line MakeFunction builder does not materialize the
        # member-function pointer itself: the caller builds a two-qword MSVC
        # member-pointer value on its stack and passes its address in r8.  Only
        # accept a RIP-relative executable LEA when the same rsp displacement is
        # first written from rax and then passed via `lea r8,[rsp+disp]` before
        # the unique builder call.  This closes the receive target without
        # mistaking adjacent callback setup blocks for the current registration.
        if (not callback_receive_candidates
                and construction_owner[1] - construction_owner[0] <= 0x100):
            builder_callers = static.direct_call_xrefs(construction_owner[0])
            if len(builder_callers) == 1:
                builder_call = builder_callers[0]
                caller_owner = static.function_for(builder_call.address - IMAGE_BASE)
                if caller_owner is not None:
                    caller_insns = static.disassemble_function(caller_owner)
                    call_index = instruction_index(
                        caller_insns,
                        builder_call.address - IMAGE_BASE,
                    )
                    prelude = caller_insns[max(0, call_index - 24):call_index]
                    for pointer_index, pointer_load in enumerate(prelude):
                        if (pointer_load.mnemonic != 'lea'
                                or len(pointer_load.operands) != 2):
                            continue
                        pointer_destination, pointer_source = pointer_load.operands
                        if not (
                            pointer_destination.type == X86_OP_REG
                            and pointer_destination.reg == X86_REG_RAX
                            and pointer_source.type == X86_OP_MEM
                            and pointer_source.mem.base == X86_REG_RIP
                        ):
                            continue
                        target = (
                            pointer_load.address + pointer_load.size
                            + pointer_source.mem.disp - IMAGE_BASE
                        )
                        if not is_executable(target, static.executable):
                            continue

                        later_prelude = prelude[pointer_index + 1:]
                        if any(direct_call_target(later) is not None
                               for later in later_prelude):
                            continue
                        stack_writes = set()
                        stack_r8_arguments = set()
                        for later in later_prelude:
                            if (later.mnemonic == 'mov'
                                    and len(later.operands) == 2
                                    and later.operands[0].type == X86_OP_MEM
                                    and later.operands[0].mem.base == X86_REG_RSP
                                    and later.operands[1].type == X86_OP_REG
                                    and later.operands[1].reg == X86_REG_RAX):
                                stack_writes.add(later.operands[0].mem.disp)
                            if (later.mnemonic == 'lea'
                                    and len(later.operands) == 2
                                    and later.operands[0].type == X86_OP_REG
                                    and later.operands[0].reg == X86_REG_R8
                                    and later.operands[1].type == X86_OP_MEM
                                    and later.operands[1].mem.base == X86_REG_RSP):
                                stack_r8_arguments.add(later.operands[1].mem.disp)
                        if stack_writes & stack_r8_arguments:
                            callback_receive_candidates.append((pointer_load, target))
                    if callback_receive_candidates:
                        callback_receive_evidence = (
                            'executable member-function RVA loaded into the unique '
                            'out-of-line callback-builder caller, stored at an rsp '
                            'slot, and passed to the builder through r8'
                        )
    callback_receive = (
        callback_receive_candidates[0]
        if len(callback_receive_candidates) == 1
        else None
    )

    owner_match = re.search(r'MakeFunction@V([^@]+)@@', mangled)
    return {
        'name': name,
        'name_occurrence_count': len(offsets),
        'name_occurrence_rvas': offsets,
        'name_occurrence_rvas_hex': [hx(offset) for offset in offsets],
        'mangled_callback_type': mangled,
        'callback_owner_type': owner_match.group(1) if owner_match else None,
        'descriptor_scope': (
            'MSVC TypeDescriptor for the compiler-generated MakeFunction '
            'callback lambda; this is not the packet object vtable'
        ),
        'type_descriptor': {
            **address_record(descriptor_rva),
            'type_info_vftable_va_hex': f'0x{type_info_vftable:016x}',
            'spare_qword': spare,
        },
        'type_descriptor_accessor': instruction_record(accessor),
        'callback_manager_table': {
            **address_record(manager_table_rva),
            'type_accessor_qword_reference_rva': accessor_reference,
            'type_accessor_qword_reference_rva_hex': hx(accessor_reference),
            'entries_rva': manager_entries,
            'entries_rva_hex': [hx(entry) for entry in manager_entries],
            'manager_entry_rva': manager_entries[0],
            'manager_entry_rva_hex': hx(manager_entries[0]),
        },
        'manager_table_xrefs': [instruction_record(insn) for insn in manager_xrefs],
        'non_registration_manager_table_xrefs': [
            instruction_record(insn) for insn in rejected_context_xrefs
        ],
        'construction_xref': instruction_record(construction),
        'callback_receive_target': ({
            **address_record(callback_receive[1]),
            'function': function_record(static.function_for(callback_receive[1])),
            'function_pointer_load': instruction_record(callback_receive[0]),
            'evidence': callback_receive_evidence,
        } if callback_receive else None),
        'callback_receive_target_candidates': [
            {
                **address_record(target),
                'function_pointer_load': instruction_record(insn),
            }
            for insn, target in callback_receive_candidates
        ],
    }


def instruction_index(insns: list, rva: int) -> int:
    for index, insn in enumerate(insns):
        if insn.address - IMAGE_BASE == rva:
            return index
    raise ValueError(f'instruction {rva:#x} is not on a decoded boundary')


def find_r8_id_write(insns: list, start_index: int, limit: int = 80):
    for insn in insns[start_index:start_index + limit]:
        if insn.mnemonic != 'mov' or len(insn.operands) != 2:
            continue
        destination, source = insn.operands
        if (destination.type == X86_OP_REG and destination.reg == X86_REG_R8D
                and source.type == X86_OP_IMM):
            return insn, source.imm & 0xffffffff
    return None, None


def first_direct_call_after(insns: list, start_index: int, limit: int = 40):
    for insn in insns[start_index:start_index + limit]:
        if direct_call_target(insn) is not None:
            return insn
    return None


def locate_registration(static: StaticImage, descriptor: dict) -> dict:
    construction_rva = descriptor['construction_xref']['rva']
    construction_function = static.function_for(construction_rva)
    if construction_function is None:
        raise ValueError(f'no .pdata owner for construction xref {construction_rva:#x}')
    construction_insns = static.disassemble_function(construction_function)
    construction_index = instruction_index(construction_insns, construction_rva)

    if construction_function[1] - construction_function[0] <= 0x100:
        helper_rva = construction_function[0]
        callers = static.direct_call_xrefs(helper_rva)
        if len(callers) != 1:
            raise ValueError(
                f'callback builder {helper_rva:#x}: expected one caller, got '
                f'{len(callers)}',
            )
        builder_call = callers[0]
        caller_rva = builder_call.address - IMAGE_BASE
        caller_function = static.function_for(caller_rva)
        if caller_function is None:
            raise ValueError(f'no .pdata owner for builder caller {caller_rva:#x}')
        caller_insns = static.disassemble_function(caller_function)
        caller_index = instruction_index(caller_insns, caller_rva)
        thunk_call = first_direct_call_after(caller_insns, caller_index + 1, 16)
        if thunk_call is None:
            raise ValueError(f'no registration thunk after {caller_rva:#x}')
        thunk_rva = direct_call_target(thunk_call)
        thunk_function = static.function_for(thunk_rva)
        if thunk_function is None or thunk_function[0] != thunk_rva:
            raise ValueError(f'registration thunk {thunk_rva:#x} lacks exact .pdata entry')
        thunk_insns = static.disassemble_function(thunk_function)
        id_write, packet_id = find_r8_id_write(thunk_insns, 0)
        if id_write is None:
            raise ValueError(f'registration thunk {thunk_rva:#x} has no r8d ID write')
        id_index = instruction_index(thunk_insns, id_write.address - IMAGE_BASE)
        generic_call = first_direct_call_after(thunk_insns, id_index + 1, 16)
        if generic_call is None:
            raise ValueError(f'registration thunk {thunk_rva:#x} has no generic call')
        return {
            'path_kind': 'out_of_line_callback_builder_then_registration_thunk',
            'construction_function': function_record(construction_function),
            'callback_builder_call': instruction_record(builder_call),
            'registration_caller_function': function_record(caller_function),
            'registration_thunk_call': instruction_record(thunk_call),
            'registration_thunk_function': function_record(thunk_function),
            'packet_id_write': instruction_record(id_write),
            'packet_id': packet_id,
            'packet_id_hex': hx(packet_id, 4),
            'generic_registration_call': instruction_record(generic_call),
            'generic_registration_rva': direct_call_target(generic_call),
            'generic_registration_rva_hex': hx(direct_call_target(generic_call)),
        }

    id_write, packet_id = find_r8_id_write(
        construction_insns, construction_index + 1,
    )
    if id_write is None:
        raise ValueError(f'inline registration after {construction_rva:#x} has no ID')
    id_index = instruction_index(construction_insns, id_write.address - IMAGE_BASE)
    generic_call = first_direct_call_after(construction_insns, id_index + 1, 16)
    if generic_call is None:
        raise ValueError(f'inline registration after {construction_rva:#x} has no call')
    manager_rva = descriptor['callback_manager_table']['manager_entry_rva']
    manager_call = next((
        insn for insn in construction_insns[construction_index + 1:id_index]
        if direct_call_target(insn) == manager_rva
    ), None)
    return {
        'path_kind': 'inlined_callback_construction_and_registration',
        'construction_function': function_record(construction_function),
        'callback_manager_call': instruction_record(manager_call) if manager_call else None,
        'packet_id_write': instruction_record(id_write),
        'packet_id': packet_id,
        'packet_id_hex': hx(packet_id, 4),
        'generic_registration_call': instruction_record(generic_call),
        'generic_registration_rva': direct_call_target(generic_call),
        'generic_registration_rva_hex': hx(direct_call_target(generic_call)),
    }


def locate_factory(static: StaticImage, required_ids: set[int], forced_rva: int | None):
    candidates = []
    if forced_rva is not None:
        entry = static.function_for(forced_rva)
        if entry is None or entry[0] != forced_rva:
            raise ValueError(f'forced factory {forced_rva:#x} is not a .pdata start')
        search_positions = [
            insn.address - IMAGE_BASE
            for insn in static.disassemble(forced_rva, min(forced_rva + 0x80, entry[1]))
            if insn.mnemonic == 'cmp'
        ]
    else:
        search_positions = []
        for start, end in static.executable:
            cursor = start
            while True:
                position = static.image.find(b'\x81\xfe', cursor, end)
                if position < 0:
                    break
                cursor = position + 1
                search_positions.append(position)

    for position in search_positions:
        insns = static.disassemble(position, min(position + 0x40, len(static.image)))
        if not insns or insns[0].mnemonic != 'cmp' or len(insns[0].operands) != 2:
            continue
        left, right = insns[0].operands
        if not (left.type == X86_OP_REG and left.reg == X86_REG_ESI
                and right.type == X86_OP_IMM):
            continue
        maximum_id = right.imm & 0xffffffff
        if maximum_id < max(required_ids) or maximum_id > 0xffff:
            continue
        table_rva = None
        jump_seen = False
        for insn in insns[1:]:
            for operand in insn.operands:
                if (operand.type == X86_OP_MEM
                        and operand.mem.index == X86_REG_RSI
                        and operand.mem.scale == 4):
                    table_rva = operand.mem.disp & 0xffffffff
            if (insn.mnemonic == 'jmp' and insn.operands
                    and insn.operands[0].type == X86_OP_REG
                    and insn.operands[0].reg == X86_REG_R8):
                jump_seen = True
        if table_rva is None or not jump_seen:
            continue
        owner = static.function_for(position)
        if owner is None:
            continue
        case_rvas = {
            packet_id: struct.unpack_from('<I', static.image, table_rva + packet_id * 4)[0]
            for packet_id in required_ids
        }
        if not all(owner[0] <= case < owner[1] for case in case_rvas.values()):
            continue
        candidates.append((owner, position, maximum_id, table_rva, case_rvas, insns))

    unique = {(entry[0][0], entry[3]): entry for entry in candidates}
    if len(unique) != 1:
        raise ValueError(f'expected one packet factory, got {len(unique)}')
    owner, switch_rva, maximum_id, table_rva, case_rvas, insns = next(iter(unique.values()))
    return {
        'function': owner,
        'switch_rva': switch_rva,
        'maximum_id': maximum_id,
        'table_rva': table_rva,
        'case_rvas': case_rvas,
        'switch_window': insns,
    }


def simple_immediate_return(static: StaticImage, function_rva: int) -> int | None:
    insns = static.disassemble(function_rva, min(function_rva + 16, len(static.image)))
    if len(insns) < 2 or insns[1].mnemonic != 'ret':
        return None
    first = insns[0]
    if first.mnemonic != 'mov' or len(first.operands) != 2:
        return None
    destination, source = first.operands
    if (destination.type == X86_OP_REG and destination.reg == X86_REG_EAX
            and source.type == X86_OP_IMM):
        return source.imm & 0xffffffff
    return None


def analyze_constructor(
    static: StaticImage,
    constructor_rva: int,
    allocation_size: int,
) -> dict:
    owner = static.function_for(constructor_rva)
    if owner is not None and owner[0] == constructor_rva:
        insns = static.disassemble_function(owner)
        owner_record = function_record(owner)
        owner_record['boundary_source'] = 'pdata'
    else:
        # These compact packet constructors are leaf functions and therefore do
        # not need Windows unwind entries.  Decode from the factory-proven entry
        # through the first RET instead of inventing a .pdata range.
        decoded = static.disassemble(
            constructor_rva,
            min(constructor_rva + 0x1000, len(static.image)),
        )
        ret_index = next(
            (index for index, insn in enumerate(decoded) if insn.mnemonic == 'ret'),
            None,
        )
        if ret_index is None:
            raise ValueError(f'leaf constructor {constructor_rva:#x} has no RET')
        insns = decoded[:ret_index + 1]
        end_rva = insns[-1].address - IMAGE_BASE + insns[-1].size
        owner_record = {
            'begin_rva': constructor_rva,
            'begin_rva_hex': hx(constructor_rva),
            'end_rva': end_rva,
            'end_rva_hex': hx(end_rva),
            'size': end_rva - constructor_rva,
            'unwind_rva': None,
            'unwind_rva_hex': None,
            'boundary_source': 'factory_entry_to_first_ret_leaf',
        }
    id_writes = []
    for insn in insns:
        if insn.mnemonic != 'mov' or len(insn.operands) != 2:
            continue
        destination, source = insn.operands
        if (destination.type == X86_OP_MEM and destination.size == 2
                and destination.mem.base == X86_REG_RCX
                and destination.mem.disp == 8
                and source.type == X86_OP_IMM):
            id_writes.append((source.imm & 0xffff, insn))
    if len(id_writes) != 1:
        raise ValueError(
            f'constructor {constructor_rva:#x}: expected one packet ID write, '
            f'got {len(id_writes)}',
        )

    vtable_candidates = []
    for insn in insns:
        if insn.mnemonic != 'lea' or len(insn.operands) != 2:
            continue
        destination, source = insn.operands
        if not (destination.type == X86_OP_REG and destination.reg == X86_REG_RAX
                and source.type == X86_OP_MEM and source.mem.base == X86_REG_RIP):
            continue
        target = insn.address + insn.size + source.mem.disp - IMAGE_BASE
        entries = [static.qword_rva(target + index * 8) for index in range(6)]
        if not all(entry is not None and is_executable(entry, static.executable)
                   for entry in entries[:3]):
            continue
        object_size = simple_immediate_return(static, entries[2])
        if object_size is None:
            continue
        vtable_candidates.append((insn, target, entries, object_size))
    matching = [entry for entry in vtable_candidates if entry[3] == allocation_size]
    if len(matching) != 1:
        raise ValueError(
            f'constructor {constructor_rva:#x}: expected one vtable whose size '
            f'getter returns {allocation_size:#x}, got {len(matching)}',
        )
    vtable_write, vtable_rva, entries, object_size = matching[0]
    packet_id, id_write = id_writes[0]
    return {
        'constructor': {
            **address_record(constructor_rva),
            'function': owner_record,
            'packet_id_write': instruction_record(id_write),
            'packet_id': packet_id,
            'packet_id_hex': hx(packet_id, 4),
            'final_vtable_load': instruction_record(vtable_write),
        },
        'packet_object_vtable': {
            **address_record(vtable_rva),
            'entries_rva': entries,
            'entries_rva_hex': [hx(entry) for entry in entries],
            'slot_0_destructor_rva': entries[0],
            'slot_0_destructor_rva_hex': hx(entries[0]),
            'slot_1_deserializer_rva': entries[1],
            'slot_1_deserializer_rva_hex': hx(entries[1]),
            'slot_2_object_size_getter_rva': entries[2],
            'slot_2_object_size_getter_rva_hex': hx(entries[2]),
            'slot_2_returned_object_size': object_size,
        },
        'deserializer': {
            **address_record(entries[1]),
            'function': function_record(static.function_for(entries[1])),
            'evidence': 'direct absolute pointer at packet object vtable + 0x08',
        },
    }


def analyze_factory_case(static: StaticImage, factory: dict, packet_id: int) -> dict:
    case_rva = factory['case_rvas'][packet_id]
    insns = static.disassemble(case_rva, min(case_rva + 0x80, factory['function'][1]))
    direct_calls = [(insn, direct_call_target(insn)) for insn in insns
                    if direct_call_target(insn) is not None]
    if len(direct_calls) < 2:
        raise ValueError(f'factory case {case_rva:#x}: fewer than two direct calls')
    allocator_call, constructor_call = direct_calls[:2]
    allocation_size = None
    for insn in insns[:instruction_index(insns, allocator_call[0].address - IMAGE_BASE)]:
        if insn.mnemonic != 'mov' or len(insn.operands) != 2:
            continue
        destination, source = insn.operands
        if (destination.type == X86_OP_REG and destination.reg in (X86_REG_ECX, X86_REG_RCX)
                and source.type == X86_OP_IMM):
            allocation_size = source.imm & 0xffffffff
    if allocation_size is None:
        raise ValueError(f'factory case {case_rva:#x}: allocation size not found')
    constructor = analyze_constructor(static, constructor_call[1], allocation_size)
    if constructor['constructor']['packet_id'] != packet_id:
        raise ValueError(
            f'factory case {case_rva:#x}: constructor writes '
            f"{constructor['constructor']['packet_id']:#x}, expected {packet_id:#x}",
        )
    return {
        'packet_id': packet_id,
        'packet_id_hex': hx(packet_id, 4),
        'jump_table_entry_rva': factory['table_rva'] + packet_id * 4,
        'jump_table_entry_rva_hex': hx(factory['table_rva'] + packet_id * 4),
        'case': address_record(case_rva),
        'allocation_size': allocation_size,
        'allocator_call': instruction_record(allocator_call[0]),
        'allocator_rva': allocator_call[1],
        'allocator_rva_hex': hx(allocator_call[1]),
        'constructor_call': instruction_record(constructor_call[0]),
        **constructor,
    }


def expectation_checks(actual: dict, expected: dict) -> dict:
    checks = {
        'case_rva': actual['case']['rva'] == expected.get(
            'case_rva', actual['case']['rva'],
        ),
        'constructor_rva': actual['constructor']['rva'] == expected['constructor_rva'],
        'vtable_rva': actual['packet_object_vtable']['rva'] == expected['vtable_rva'],
        'deserialize_rva': actual['deserializer']['rva'] == expected['deserialize_rva'],
    }
    return {
        'all_match': all(checks.values()),
        'checks': checks,
        'expected': {
            key: hx(value) if key.endswith('_rva') else value
            for key, value in expected.items()
        },
    }


def compact_factory_case(factory_case: dict) -> dict:
    return {
        'case_rva': factory_case['case']['rva'],
        'case_rva_hex': factory_case['case']['rva_hex'],
        'allocation_size': factory_case['allocation_size'],
        'constructor_rva': factory_case['constructor']['rva'],
        'constructor_rva_hex': factory_case['constructor']['rva_hex'],
        'packet_object_vtable_rva': factory_case['packet_object_vtable']['rva'],
        'packet_object_vtable_rva_hex': (
            factory_case['packet_object_vtable']['rva_hex']
        ),
        'deserializer_rva': factory_case['deserializer']['rva'],
        'deserializer_rva_hex': factory_case['deserializer']['rva_hex'],
        'object_size': factory_case['packet_object_vtable'][
            'slot_2_returned_object_size'
        ],
    }


def audit_static_layout(
    static: StaticImage,
    name: str,
    factory_case: dict | None,
) -> dict | None:
    source = STATIC_LAYOUT_EVIDENCE.get(name)
    if source is None:
        return None
    evidence = json.loads(json.dumps(source))
    checks = {}

    expected_size = source.get('expected_object_size')
    if expected_size is not None:
        checks['storage_fields_fit_expected_object_size'] = all(
            field['offset'] + field['size'] <= expected_size
            for field in source.get('storage_fields', [])
        )
        checks['factory_object_size_matches_layout'] = (
            factory_case is not None
            and factory_case['allocation_size'] == expected_size
            and factory_case['packet_object_vtable'][
                'slot_2_returned_object_size'
            ] == expected_size
        )
    minimum_size = source.get('expected_object_size_minimum')
    if minimum_size is not None:
        checks['storage_fields_fit_minimum_object_size'] = all(
            field['offset'] + field['size'] <= minimum_size
            for field in source.get('storage_fields', [])
        )

    helper_rvas = list(source.get('required_helper_rvas', []))
    nested = source.get('nested_element')
    if nested:
        helper_rvas.extend(nested.get('required_helper_rvas', []))
    checks['all_required_helpers_are_executable'] = all(
        is_executable(rva, static.executable) for rva in helper_rvas
    )
    evidence['required_helper_rvas_hex'] = [hx(rva) for rva in helper_rvas]

    slot_3 = source.get('packet_vtable_slot_3_rva')
    if slot_3 is not None:
        checks['packet_vtable_slot_3_matches'] = (
            factory_case is not None
            and factory_case['packet_object_vtable']['entries_rva'][3] == slot_3
        )
        evidence['packet_vtable_slot_3_rva_hex'] = hx(slot_3)

    callback_read = source.get('callback_read_evidence_rva')
    if callback_read is not None:
        checks['callback_read_evidence_is_executable'] = is_executable(
            callback_read,
            static.executable,
        )
        evidence['callback_read_evidence_rva_hex'] = hx(callback_read)

    decode_like = source.get('non_factory_decode_like_rva')
    if decode_like is not None:
        checks['non_factory_decode_like_rva_is_executable'] = is_executable(
            decode_like,
            static.executable,
        )
        checks['non_factory_decode_like_writes_0x04df_id'] = (
            static.image.find(
                b'\x66\xc7\x41\x08\xdf\x04',
                decode_like,
                min(decode_like + 0x40, len(static.image)),
            ) >= 0
        )
        evidence['non_factory_decode_like_rva_hex'] = hx(decode_like)

    if nested:
        nested_vtable = nested['vtable_rva']
        nested_deserializer = nested['deserializer_rva']
        nested_size_getter = nested['size_getter_rva']
        checks['nested_vtable_plus_8_matches_deserializer'] = (
            static.qword_rva(nested_vtable + 8) == nested_deserializer
        )
        checks['nested_vtable_plus_0x10_matches_size_getter'] = (
            static.qword_rva(nested_vtable + 0x10) == nested_size_getter
        )
        checks['nested_size_getter_matches_object_size'] = (
            simple_immediate_return(static, nested_size_getter)
            == nested['object_size']
        )
        checks['nested_storage_fields_fit_object_size'] = all(
            field['offset'] + field['size'] <= nested['object_size']
            for field in nested.get('storage_fields', [])
        )
        evidence['nested_element']['vtable_rva_hex'] = hx(nested_vtable)
        evidence['nested_element']['deserializer_rva_hex'] = hx(
            nested_deserializer,
        )
        evidence['nested_element']['size_getter_rva_hex'] = hx(
            nested_size_getter,
        )

    return {
        'confidence': 'DIRECT_STATIC_STORAGE_LAYOUT_WITH_EXACT_BUILD_CHECKS',
        'semantic_boundary': (
            'Offsets and container shapes are proven storage/decoder evidence. '
            'Gameplay meanings such as current HP, max HP, armor, MR, or resource '
            'identity are not assigned unless separately stated as negative control.'
        ),
        'evidence': evidence,
        'checks': checks,
        'all_checks_pass': all(checks.values()),
    }


def enumerate_callback_registration_map(
    static: StaticImage,
    factory: dict,
    factory_case_cache: dict[int, dict],
) -> dict:
    instances = discover_callback_descriptor_instances(static.image)
    entries = []
    failures = []
    factory_failures: dict[int, str] = {}

    for instance in instances:
        try:
            descriptor = locate_callback_descriptor(
                static,
                instance['name'],
                instance['string_start_rva'],
            )
            registration = locate_registration(static, descriptor)
        except Exception as error:
            failures.append({
                **instance,
                'error': f'{type(error).__name__}: {error}',
            })
            continue

        packet_id = registration['packet_id']
        factory_status = None
        factory_record = None
        factory_error = None
        if packet_id > factory['maximum_id']:
            factory_status = 'REGISTRATION_ID_ABOVE_DIRECT_FACTORY_MAXIMUM'
        else:
            if packet_id not in factory_case_cache and packet_id not in factory_failures:
                factory['case_rvas'][packet_id] = struct.unpack_from(
                    '<I',
                    static.image,
                    factory['table_rva'] + packet_id * 4,
                )[0]
                try:
                    factory_case_cache[packet_id] = analyze_factory_case(
                        static,
                        factory,
                        packet_id,
                    )
                except Exception as error:
                    factory_failures[packet_id] = f'{type(error).__name__}: {error}'
            if packet_id in factory_case_cache:
                factory_status = 'VERIFIED_DIRECT_FACTORY_OBJECT'
                factory_record = compact_factory_case(factory_case_cache[packet_id])
            else:
                factory_status = 'DIRECT_FACTORY_CASE_ANALYSIS_FAILED'
                factory_error = factory_failures[packet_id]

        callback_receive = descriptor.get('callback_receive_target')
        entries.append({
            'name': descriptor['name'],
            'callback_owner_type': descriptor['callback_owner_type'],
            'type_descriptor_rva': descriptor['type_descriptor']['rva'],
            'type_descriptor_rva_hex': descriptor['type_descriptor']['rva_hex'],
            'callback_manager_table_rva': descriptor['callback_manager_table']['rva'],
            'callback_manager_table_rva_hex': (
                descriptor['callback_manager_table']['rva_hex']
            ),
            'callback_receive_target_rva': (
                callback_receive['rva'] if callback_receive else None
            ),
            'callback_receive_target_rva_hex': (
                callback_receive['rva_hex'] if callback_receive else None
            ),
            'callback_receive_target_evidence': (
                callback_receive['evidence'] if callback_receive else None
            ),
            'registration_path_kind': registration['path_kind'],
            'registration_id': packet_id,
            'registration_id_hex': registration['packet_id_hex'],
            'generic_registration_rva': registration['generic_registration_rva'],
            'generic_registration_rva_hex': registration[
                'generic_registration_rva_hex'
            ],
            'factory_status': factory_status,
            'factory_packet': factory_record,
            'factory_error': factory_error,
        })

    entries.sort(key=lambda entry: (
        entry['registration_id'],
        entry['name'],
        entry['type_descriptor_rva'],
    ))
    failures.sort(key=lambda entry: (
        entry['name'],
        entry['string_start_rva'],
    ))
    route_index: dict[str, list[dict]] = {}
    for entry in entries:
        route_index.setdefault(entry['registration_id_hex'], []).append({
            'name': entry['name'],
            'callback_owner_type': entry['callback_owner_type'],
            'type_descriptor_rva_hex': entry['type_descriptor_rva_hex'],
            'callback_receive_target_rva_hex': (
                entry['callback_receive_target_rva_hex']
            ),
            'callback_receive_target_evidence': (
                entry['callback_receive_target_evidence']
            ),
        })
    generic_registration_rvas = sorted({
        entry['generic_registration_rva'] for entry in entries
    })
    return {
        'scope': (
            'Best-effort enumeration of every exact-image MSVC MakeFunction '
            'TypeDescriptor string containing a PKT_*_s name. Verified entries '
            'have a closed descriptor/manager/construction/registration path; '
            'failures are retained rather than silently omitted.'
        ),
        'discovered_descriptor_instance_count': len(instances),
        'verified_registration_instance_count': len(entries),
        'failed_descriptor_or_registration_instance_count': len(failures),
        'unique_verified_registration_id_count': len({
            entry['registration_id'] for entry in entries
        }),
        'verified_callback_receive_target_count': sum(
            entry['callback_receive_target_rva'] is not None for entry in entries
        ),
        'unresolved_callback_receive_target_count': sum(
            entry['callback_receive_target_rva'] is None for entry in entries
        ),
        'generic_registration_rvas': generic_registration_rvas,
        'generic_registration_rvas_hex': [
            hx(rva) for rva in generic_registration_rvas
        ],
        'direct_factory_verified_count': sum(
            entry['factory_status'] == 'VERIFIED_DIRECT_FACTORY_OBJECT'
            for entry in entries
        ),
        'above_factory_maximum_count': sum(
            entry['factory_status']
            == 'REGISTRATION_ID_ABOVE_DIRECT_FACTORY_MAXIMUM'
            for entry in entries
        ),
        'direct_factory_analysis_failure_count': sum(
            entry['factory_status'] == 'DIRECT_FACTORY_CASE_ANALYSIS_FAILED'
            for entry in entries
        ),
        'entries': entries,
        'route_index': route_index,
        'failures': failures,
        'factory_case_failures_by_id': {
            hx(packet_id, 4): error
            for packet_id, error in sorted(factory_failures.items())
        },
    }


def build_observed_inventory_intersection(
    inventory_path: Path,
    callback_inventory: dict,
) -> dict:
    inventory_bytes = inventory_path.read_bytes()
    inventory = json.loads(inventory_bytes.decode('utf-8-sig'))
    packets = [
        packet for packet in inventory.get('packets', [])
        if packet.get('build') == TARGET_BUILD
    ]
    route_index = callback_inventory['route_index']
    callback_entries_by_id: dict[str, list[dict]] = {}
    for entry in callback_inventory['entries']:
        callback_entries_by_id.setdefault(entry['registration_id_hex'], []).append(entry)

    rows = []
    mapped_packet_count = 0
    status_counts: dict[str, int] = {}
    for packet in sorted(packets, key=lambda item: item['packet_id']):
        packet_id = packet['packet_id']
        packet_id_hex = hx(packet_id, 4)
        callbacks = route_index.get(packet_id_hex, [])
        unique_names = sorted({callback['name'] for callback in callbacks})
        if not callbacks:
            status = 'UNMAPPED_ON_MAKEFUNCTION_CALLBACK_REGISTRATION_SURFACE'
        elif len(unique_names) == 1:
            status = 'UNIQUE_CALLBACK_RTTI_NAME'
            mapped_packet_count += packet['count']
        else:
            status = 'AMBIGUOUS_MULTIPLE_CALLBACK_RTTI_NAMES'
            mapped_packet_count += packet['count']
        status_counts[status] = status_counts.get(status, 0) + 1

        factory_records = []
        for callback_entry in callback_entries_by_id.get(packet_id_hex, []):
            if callback_entry['factory_packet'] is not None:
                factory_records.append(callback_entry['factory_packet'])
        unique_factory_records = []
        seen_factory_keys = set()
        for record in factory_records:
            key = (
                record['case_rva'],
                record['constructor_rva'],
                record['packet_object_vtable_rva'],
                record['deserializer_rva'],
                record['object_size'],
            )
            if key not in seen_factory_keys:
                seen_factory_keys.add(key)
                unique_factory_records.append(record)

        rows.append({
            'packet_id': packet_id,
            'packet_id_hex': packet_id_hex,
            'observed_count': packet['count'],
            'payload_size_distribution': packet.get('payload_size_distribution', []),
            'existing_decode_status': packet.get('currently_decoded_as_status'),
            'callback_mapping_status': status,
            'callback_names': unique_names,
            'callbacks': callbacks,
            'factory_packets': unique_factory_records,
        })

    observed_packet_count = sum(row['observed_count'] for row in rows)
    return {
        'schema_version': 1,
        'analysis': 'observed_packet_to_callback_rtti_registration_intersection',
        'build': TARGET_BUILD,
        'inventory': {
            'path': str(inventory_path.resolve()),
            'sha256': hashlib.sha256(inventory_bytes).hexdigest(),
            'schema_version': inventory.get('schema_version'),
            'input_record_count': inventory.get('input_record_count'),
        },
        'mapping_surface': (
            'Exact-image MSVC MakeFunction callback registration surface. An '
            'unmapped row is not proof that the factory route has no class/name; '
            'it means no closed callback RTTI registration was recovered on this '
            'specific surface.'
        ),
        'observed_route_count': len(rows),
        'status_counts': dict(sorted(status_counts.items())),
        'mapped_observed_packet_count': mapped_packet_count,
        'total_observed_packet_count': observed_packet_count,
        'mapped_observed_packet_fraction': (
            mapped_packet_count / observed_packet_count
            if observed_packet_count else None
        ),
        'routes': rows,
    }
def analyze(
    image_path: Path,
    expected_sha256: str,
    forced_factory_rva: int | None,
    enumerate_all_callbacks: bool = False,
    inventory_path: Path | None = None,
) -> dict:
    image = image_path.read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    if digest.lower() != expected_sha256.lower():
        raise ValueError(
            f'image SHA-256 mismatch: got {digest}, expected {expected_sha256}',
        )
    pe = pefile.PE(data=image, fast_load=False)
    if pe.OPTIONAL_HEADER.ImageBase != IMAGE_BASE:
        raise ValueError(
            f'unexpected image base {pe.OPTIONAL_HEADER.ImageBase:#x}',
        )
    static = StaticImage(image, pe)

    descriptors = [locate_callback_descriptor(static, name) for name in TARGET_NAMES]
    registrations = {
        descriptor['name']: locate_registration(static, descriptor)
        for descriptor in descriptors
    }
    generic_registration_rvas = {
        registration['generic_registration_rva']
        for registration in registrations.values()
    }
    if len(generic_registration_rvas) != 1:
        raise ValueError(
            f'targets do not converge on one registration function: '
            f'{sorted(generic_registration_rvas)}',
        )

    target_ids = {
        registration['packet_id'] for registration in registrations.values()
    }
    # Locate the direct packet-object factory from independent in-range anchors
    # first.  Callback registries can also carry synthetic internal event IDs;
    # those may intentionally sit above the factory's maximum direct index.
    factory = locate_factory(
        static,
        set(STRUCTURAL_ROUTE_EXPECTATIONS),
        forced_factory_rva,
    )
    factory_target_ids = {
        packet_id for packet_id in target_ids
        if packet_id <= factory['maximum_id']
    }
    required_ids = factory_target_ids | set(STRUCTURAL_ROUTE_EXPECTATIONS)
    for packet_id in required_ids:
        factory['case_rvas'][packet_id] = struct.unpack_from(
            '<I',
            static.image,
            factory['table_rva'] + packet_id * 4,
        )[0]

    all_factory_cases = {
        packet_id: analyze_factory_case(static, factory, packet_id)
        for packet_id in sorted(required_ids)
    }

    chains = []
    for descriptor in descriptors:
        registration = registrations[descriptor['name']]
        packet_id = registration['packet_id']
        factory_case = all_factory_cases.get(packet_id)
        has_direct_factory_case = factory_case is not None
        chain = {
            'target_name': descriptor['name'],
            'status': (
                'VERIFIED_STATIC_REGISTRATION_TO_FACTORY_CHAIN'
                if has_direct_factory_case
                else 'VERIFIED_STATIC_REGISTRATION_WITHOUT_DIRECT_FACTORY_CASE'
            ),
            'confidence': 'DIRECT_STATIC_PROOF',
            'callback_descriptor': descriptor,
            'registration': registration,
            'factory_packet': factory_case,
            'static_layout_audit': audit_static_layout(
                static,
                descriptor['name'],
                factory_case,
            ),
            'chain_consistency': {
                'registration_id_is_within_factory_direct_range': (
                    registration['packet_id'] <= factory['maximum_id']
                ),
                'registration_id_equals_factory_index': (
                    registration['packet_id'] == factory_case['packet_id']
                    if has_direct_factory_case else None
                ),
                'constructor_id_equals_registration_id': (
                    factory_case['constructor']['packet_id']
                    == registration['packet_id']
                    if has_direct_factory_case else None
                ),
                'allocation_size_equals_vtable_size_getter': (
                    factory_case['allocation_size']
                    == factory_case['packet_object_vtable'][
                        'slot_2_returned_object_size'
                    ]
                    if has_direct_factory_case else None
                ),
                'deserializer_pointer_is_executable': (
                    is_executable(factory_case['deserializer']['rva'], static.executable)
                    if has_direct_factory_case else None
                ),
            },
            'id_scope': (
                (
                    'The same 16-bit value is written into the callback registry, '
                    'indexes the packet factory jump table, and is written by the '
                    'packet constructor. This proves the exact-build packet/factory '
                    'ID; no separate ECS component ID is established.'
                ) if has_direct_factory_case else (
                    'The callback registration ID is direct static evidence, but it '
                    'is above the direct packet-object factory maximum and therefore '
                    'does not establish an on-wire packet constructor or component ID.'
                )
            ),
        }
        if not has_direct_factory_case:
            chain['factory_negative_evidence'] = {
                'registration_id': packet_id,
                'registration_id_hex': hx(packet_id, 4),
                'factory_maximum_direct_index': factory['maximum_id'],
                'factory_maximum_direct_index_hex': hx(factory['maximum_id'], 4),
                'distance_above_factory_maximum': packet_id - factory['maximum_id'],
                'status': 'OUTSIDE_DIRECT_FACTORY_SWITCH_RANGE',
            }
        chains.append(chain)

    cross_checks = []
    for packet_id, expected in sorted(STRUCTURAL_ROUTE_EXPECTATIONS.items()):
        actual = all_factory_cases[packet_id]
        checks = expectation_checks(actual, expected)
        if not checks['all_match']:
            raise ValueError(
                f'structural route {packet_id:#x} disagrees with supplied '
                f'expectations: {checks}',
            )
        linked_names = [
            chain['target_name'] for chain in chains
            if chain['registration']['packet_id'] == packet_id
        ]
        cross_checks.append({
            'packet_id': packet_id,
            'packet_id_hex': hx(packet_id, 4),
            'factory_case': actual,
            'expectation_checks': checks,
            'linked_target_names': linked_names,
            'name_link_status': (
                'DIRECT_STATIC_NAME_LINK' if linked_names
                else 'NO_LINK_TO_THE_FIVE_REQUESTED_NAMES'
            ),
        })

    factory_summary = {
        'function': function_record(factory['function']),
        'switch_rva': factory['switch_rva'],
        'switch_rva_hex': hx(factory['switch_rva']),
        'maximum_direct_index': factory['maximum_id'],
        'jump_table_rva': factory['table_rva'],
        'jump_table_rva_hex': hx(factory['table_rva']),
        'switch_window': [instruction_record(insn) for insn in factory['switch_window']],
    }

    callback_registration_inventory = (
        enumerate_callback_registration_map(static, factory, all_factory_cases)
        if enumerate_all_callbacks else None
    )
    if inventory_path is not None and callback_registration_inventory is None:
        raise ValueError(
            '--inventory-json requires --enumerate-all-callbacks',
        )
    observed_inventory_intersection = (
        build_observed_inventory_intersection(
            inventory_path,
            callback_registration_inventory,
        ) if inventory_path is not None else None
    )

    return {
        'schema_version': 1,
        'analysis': 'hero_combat_state_runtime_static_registration_trace',
        'build': TARGET_BUILD,
        'image': {
            'path': str(image_path.resolve()),
            'sha256': digest,
            'size': len(image),
            'image_base': IMAGE_BASE,
            'image_base_hex': f'0x{IMAGE_BASE:x}',
        },
        'shared_runtime': {
            'generic_callback_registration_rva': next(iter(generic_registration_rvas)),
            'generic_callback_registration_rva_hex': hx(
                next(iter(generic_registration_rvas)),
            ),
            'packet_factory': factory_summary,
            'base_packet_vtable_rva': BASE_PACKET_VTABLE_RVA,
            'base_packet_vtable_rva_hex': hx(BASE_PACKET_VTABLE_RVA),
            'base_packet_serialize_rva': BASE_PACKET_SERIALIZE_RVA,
            'base_packet_serialize_rva_hex': hx(BASE_PACKET_SERIALIZE_RVA),
            'base_packet_decode_wrapper_rva': BASE_PACKET_DECODE_WRAPPER_RVA,
            'base_packet_decode_wrapper_rva_hex': hx(BASE_PACKET_DECODE_WRAPPER_RVA),
            'serializer_scope': (
                'The exact-build shared base serializer serializes the Replay '
                'packet header/wrapper. The packet object vtable exposes a '
                'packet-specific deserializer at +0x08 and an object-size getter '
                'at +0x10; no packet-specific serializer is claimed from that slot.'
            ),
        },
        'target_chains': chains,
        'independent_structural_route_cross_checks': cross_checks,
        'callback_registration_inventory': callback_registration_inventory,
        'observed_inventory_intersection': observed_inventory_intersection,
        'summary': {
            'target_count': len(chains),
            'closed_chain_count': sum(
                chain['status'] == 'VERIFIED_STATIC_REGISTRATION_TO_FACTORY_CHAIN'
                and all(
                    value for value in chain['chain_consistency'].values()
                    if value is not None
                )
                for chain in chains
            ),
            'registration_only_count': sum(
                chain['status']
                == 'VERIFIED_STATIC_REGISTRATION_WITHOUT_DIRECT_FACTORY_CASE'
                for chain in chains
            ),
            'target_packet_ids': {
                chain['target_name']: chain['registration']['packet_id_hex']
                for chain in chains
            },
            'hero_stats_structural_migration_intersection': (
                registrations['PKT_S2C_HeroStats_s']['packet_id'] == 0x010C
            ),
            'packet_specific_serializer_status': 'NOT_RECOVERED_OR_CLAIMED',
            'field_layout_status': (
                'STATIC_STORAGE_LAYOUTS_RECOVERED_AND_EXACT_BUILD_CHECKED; '
                'GAMEPLAY_FIELD_SEMANTICS_REMAIN_SEPARATE'
            ),
            'semantic_boundary': (
                'This report proves exact-build class-name callback registration '
                'and packet object construction/deserialization identity. It does '
                'not by itself assign HP, armor, MR, buff, resource, or combat '
                'field offsets or validate Replay payload semantics.'
            ),
        },
    }


def main() -> None:
    options = parse_args()
    result = analyze(
        Path(options.image).resolve(),
        options.expected_sha256,
        options.factory_rva,
        options.enumerate_all_callbacks,
        Path(options.inventory_json).resolve() if options.inventory_json else None,
    )
    output = Path(options.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, ensure_ascii=True) + '\n', encoding='ascii')
    route_map_output = None
    if options.route_map_output:
        if result['observed_inventory_intersection'] is None:
            raise ValueError(
                '--route-map-output requires --inventory-json and '
                '--enumerate-all-callbacks',
            )
        route_map_output = Path(options.route_map_output).resolve()
        route_map_output.parent.mkdir(parents=True, exist_ok=True)
        route_map_output.write_text(
            json.dumps(
                result['observed_inventory_intersection'],
                indent=2,
                ensure_ascii=True,
            ) + '\n',
            encoding='ascii',
        )
    print(json.dumps({
        'output': str(output),
        'build': result['build'],
        'closed_chain_count': result['summary']['closed_chain_count'],
        'target_packet_ids': result['summary']['target_packet_ids'],
        'factory_rva': result['shared_runtime']['packet_factory']['function']['begin_rva_hex'],
        'jump_table_rva': result['shared_runtime']['packet_factory']['jump_table_rva_hex'],
        'enumerated_callback_registration_count': (
            result['callback_registration_inventory'][
                'verified_registration_instance_count'
            ] if result['callback_registration_inventory'] else None
        ),
        'observed_route_map_output': (
            str(route_map_output) if route_map_output else None
        ),
    }, indent=2))


if __name__ == '__main__':
    main()

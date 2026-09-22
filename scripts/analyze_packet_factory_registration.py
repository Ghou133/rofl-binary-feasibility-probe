#!/usr/bin/env python3

"""Recover a packet class ID from a mapped League x86-64 PE image."""

import argparse
import hashlib
import json
import struct
from pathlib import Path

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import (
    X86_OP_IMM,
    X86_OP_MEM,
    X86_REG_R9,
    X86_REG_RBX,
    X86_REG_RCX,
    X86_REG_RIP,
)


IMAGE_BASE = 0x140000000


def integer(value):
    return int(value, 0)


def arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', required=True)
    parser.add_argument('--vtable', required=True, type=integer)
    parser.add_argument('--constructor', required=True, type=integer)
    parser.add_argument('--deserialize', required=True, type=integer)
    parser.add_argument('--constructor-callsite', required=True, type=integer)
    parser.add_argument('--output', required=True)
    return parser.parse_args()


def instruction_record(insn):
    return {
        'rva': insn.address - IMAGE_BASE,
        'bytes': insn.bytes.hex(),
        'mnemonic': insn.mnemonic,
        'operands': insn.op_str,
    }


def function_ranges(image, pe):
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    ranges = []
    for offset in range(directory.VirtualAddress,
                        directory.VirtualAddress + directory.Size, 12):
        begin, end, unwind = struct.unpack_from('<III', image, offset)
        if begin < end <= len(image):
            ranges.append((begin, end, unwind))
    return ranges


def containing_function(ranges, rva):
    matches = [entry for entry in ranges if entry[0] <= rva < entry[1]]
    if not matches:
        raise ValueError(f'no .pdata function contains RVA {rva:#x}')
    return min(matches, key=lambda entry: entry[1] - entry[0])


def direct_xrefs(image, target, executable_end):
    result = []
    for rva in range(0x1000, min(executable_end, len(image) - 4)):
        if image[rva] != 0xE8:
            continue
        destination = rva + 5 + struct.unpack_from('<i', image, rva + 1)[0]
        if destination == target:
            result.append(rva)
    return result


def analyze(options):
    image_path = Path(options.image).resolve()
    image = image_path.read_bytes()
    pe = pefile.PE(data=image, fast_load=False)
    if pe.OPTIONAL_HEADER.ImageBase != IMAGE_BASE:
        raise ValueError(f'unexpected image base {pe.OPTIONAL_HEADER.ImageBase:#x}')

    executable_end = max(
        section.VirtualAddress + section.Misc_VirtualSize
        for section in pe.sections
        if section.Characteristics & 0x20000000
    )
    ranges = function_ranges(image, pe)
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True

    ctor_range = containing_function(ranges, options.constructor)
    ctor_insns = list(decoder.disasm(
        image[ctor_range[0]:ctor_range[1]], IMAGE_BASE + ctor_range[0]))
    id_writes = []
    for insn in ctor_insns:
        if insn.mnemonic != 'mov' or len(insn.operands) != 2:
            continue
        destination, source = insn.operands
        if (destination.type == X86_OP_MEM and destination.size == 2
                and destination.mem.base == X86_REG_RCX
                and destination.mem.disp == 8
                and source.type == X86_OP_IMM):
            id_writes.append((source.imm & 0xffff, insn))
    if len(id_writes) != 1:
        raise ValueError(f'expected one constructor packet-ID write, got {len(id_writes)}')
    packet_id, id_write = id_writes[0]

    factory_range = containing_function(ranges, options.constructor_callsite)
    factory_insns = list(decoder.disasm(
        image[factory_range[0]:factory_range[1]], IMAGE_BASE + factory_range[0]))
    table_candidates = []
    max_id_candidates = []
    for insn in factory_insns[:40]:
        for operand in insn.operands:
            if (operand.type == X86_OP_MEM and operand.mem.index == X86_REG_RBX
                    and operand.mem.scale == 4):
                table_candidates.append(operand.mem.disp & 0xffffffff)
        if insn.mnemonic == 'cmp':
            for operand in insn.operands:
                if operand.type == X86_OP_IMM:
                    max_id_candidates.append(operand.imm)
    if len(table_candidates) != 1 or not max_id_candidates:
        raise ValueError('could not uniquely identify factory jump table')
    table_rva = table_candidates[0]
    maximum_id = max_id_candidates[0]
    if packet_id > maximum_id:
        raise ValueError('constructor ID is outside factory switch bounds')
    case_rva = struct.unpack_from('<I', image, table_rva + packet_id * 4)[0]
    if not case_rva <= options.constructor_callsite < case_rva + 0x100:
        raise ValueError('packet-ID jump-table case does not contain constructor callsite')

    callsite_insn = next(
        (insn for insn in factory_insns
         if insn.address - IMAGE_BASE == options.constructor_callsite), None)
    if (callsite_insn is None or callsite_insn.mnemonic != 'call'
            or callsite_insn.operands[0].imm - IMAGE_BASE != options.constructor):
        raise ValueError('declared callsite does not directly call constructor')

    vtable_deserialize = struct.unpack_from('<Q', image, options.vtable + 8)[0] - IMAGE_BASE
    if vtable_deserialize != options.deserialize:
        raise ValueError('vtable + 8 does not match declared deserializer')

    factory_xrefs = direct_xrefs(image, factory_range[0], executable_end)
    dispatcher_evidence = []
    callback_tree_headers = []
    callback_invoke_helpers = []
    for xref in factory_xrefs:
        owner = containing_function(ranges, xref)
        window = list(decoder.disasm(image[max(owner[0], xref - 24):min(owner[1], xref + 160)],
                                      IMAGE_BASE + max(owner[0], xref - 24)))
        has_indirect_deserialize = any(
            insn.mnemonic == 'call' and '[rax + 8]' in insn.op_str
            for insn in window)
        has_object_id_read = any(
            insn.mnemonic == 'movzx' and 'word ptr [rcx + 8]' in insn.op_str
            for insn in window)
        if has_indirect_deserialize and has_object_id_read:
            object_id_seen = False
            for insn in window:
                if insn.mnemonic == 'movzx' and 'word ptr [rcx + 8]' in insn.op_str:
                    object_id_seen = True
                if (insn.mnemonic == 'mov' and len(insn.operands) == 2
                        and insn.operands[0].reg == X86_REG_R9
                        and insn.operands[1].type == X86_OP_MEM
                        and insn.operands[1].mem.base == X86_REG_RIP):
                    target = (insn.address + insn.size
                              + insn.operands[1].mem.disp - IMAGE_BASE)
                    callback_tree_headers.append(target)
                if (object_id_seen and insn.mnemonic == 'call'
                        and insn.operands[0].type == X86_OP_IMM):
                    target = insn.operands[0].imm - IMAGE_BASE
                    callback_invoke_helpers.append(target)
            dispatcher_evidence.append({
                'function_begin_rva': owner[0],
                'function_end_rva': owner[1],
                'factory_call_rva': xref,
                'window': [instruction_record(insn) for insn in window],
            })

    return {
        'schema_version': 1,
        'analysis': 'static_packet_factory_registration',
        'image': {
            'path': str(image_path),
            'sha256': hashlib.sha256(image).hexdigest().upper(),
            'image_base': IMAGE_BASE,
        },
        'result': {
            'packet_id_decimal': packet_id,
            'packet_id_hex': f'0x{packet_id:04x}',
            'confidence': 'direct_static_proof',
        },
        'constructor': {
            'rva': options.constructor,
            'function_end_rva': ctor_range[1],
            'object_size': 0x90,
            'packet_id_write': instruction_record(id_write),
            'vtable_rva': options.vtable,
            'vtable_slot_1_deserialize_rva': vtable_deserialize,
        },
        'factory': {
            'function_begin_rva': factory_range[0],
            'function_end_rva': factory_range[1],
            'constructor_callsite_rva': options.constructor_callsite,
            'constructor_call': instruction_record(callsite_insn),
            'maximum_direct_index': maximum_id,
            'jump_table_rva': table_rva,
            'jump_table_entry_rva': table_rva + packet_id * 4,
            'case_rva': case_rva,
            'direct_callers': factory_xrefs,
        },
        'generic_replay_dispatch': dispatcher_evidence,
        'business_handler': {
            'status': 'not_recovered_from_module_image',
            'runtime_callback_tree_header_rvas': sorted(set(callback_tree_headers)),
            'runtime_callback_tree_pointer_values': [
                struct.unpack_from('<Q', image, rva)[0]
                for rva in sorted(set(callback_tree_headers))
            ],
            'generic_callback_invoke_candidate_rvas': sorted(set(callback_invoke_helpers)),
            'reason': (
                'The generic dispatcher performs a runtime tree lookup keyed by the '
                'decoded object ID. The dumped module contains the tree header/pointer '
                'but not heap-resident tree nodes, so a packet-specific callback address '
                'cannot be proven from this image alone.'
            ),
        },
    }


def main():
    options = arguments()
    result = analyze(options)
    output = Path(options.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n', encoding='ascii')
    print(json.dumps({
        'output': str(output.resolve()),
        'packet_id': result['result']['packet_id_decimal'],
        'case_rva': result['factory']['case_rva'],
    }))


if __name__ == '__main__':
    main()

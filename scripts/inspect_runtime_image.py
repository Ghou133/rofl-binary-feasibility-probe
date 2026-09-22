#!/usr/bin/env python3

import argparse
from collections import deque
import json
import os
import struct

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP


DEFAULT_IMAGE_BASE = 0x140000000


def parse_int(value):
    return int(value, 0)


def parse_args():
    parser = argparse.ArgumentParser(
        description='Inspect an unpacked x86-64 PE memory image by RVA.',
    )
    parser.add_argument('--image', required=True)
    parser.add_argument('--rva', action='append', default=[], type=parse_int)
    parser.add_argument('--xref', action='append', default=[], type=parse_int)
    parser.add_argument('--semantic-xref', action='append', default=[], type=parse_int)
    parser.add_argument('--indirect-call-disp', action='append', default=[], type=parse_int)
    parser.add_argument('--immediate-value', action='append', default=[], type=parse_int)
    parser.add_argument('--scan-start', type=parse_int)
    parser.add_argument('--scan-end', type=parse_int)
    parser.add_argument('--context-instructions', type=int, default=12)
    parser.add_argument('--before', type=parse_int, default=0)
    parser.add_argument('--size', type=parse_int, default=0x100)
    parser.add_argument('--output')
    return parser.parse_args()


def executable_ranges(image):
    pe = pefile.PE(data=image, fast_load=False)
    ranges = []
    for section in pe.sections:
        if not section.Characteristics & 0x20000000:
            continue
        start = section.VirtualAddress
        size = max(section.Misc_VirtualSize, section.SizeOfRawData)
        ranges.append({
            'name': section.Name.rstrip(b'\0').decode('ascii', errors='replace'),
            'start_rva': start,
            'end_rva': min(start + size, len(image)),
        })
    return pe.OPTIONAL_HEADER.ImageBase or DEFAULT_IMAGE_BASE, ranges


def disassemble(image, image_base, rva, before, size):
    start = max(0, rva - before)
    end = min(len(image), start + size)
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    instructions = []
    for instruction in decoder.disasm(image[start:end], image_base + start):
        instructions.append({
            'rva': instruction.address - image_base,
            'address': instruction.address,
            'bytes': instruction.bytes.hex(),
            'mnemonic': instruction.mnemonic,
            'operands': instruction.op_str,
        })
    return {
        'requested_rva': rva,
        'start_rva': start,
        'end_rva': end,
        'instructions': instructions,
    }


def direct_xrefs(image, ranges, targets):
    target_set = set(targets)
    references = {target: [] for target in targets}
    for section in ranges:
        start = section['start_rva']
        end = min(section['end_rva'], len(image) - 4)
        for rva in range(start, end):
            opcode = image[rva]
            if opcode not in (0xE8, 0xE9):
                continue
            destination = rva + 5 + struct.unpack_from('<i', image, rva + 1)[0]
            if destination not in target_set:
                continue
            references[destination].append({
                'source_rva': rva,
                'kind': 'call' if opcode == 0xE8 else 'jump',
                'section': section['name'],
            })
    return references


def semantic_xrefs(image, image_base, ranges, targets):
    if not targets:
        return {}
    absolute_targets = {image_base + target: target for target in targets}
    references = {target: [] for target in targets}
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    decoder.skipdata = True
    for section in ranges:
        start = section['start_rva']
        end = section['end_rva']
        for instruction in decoder.disasm(image[start:end], image_base + start):
            if instruction.id == 0:
                continue
            for operand_index, operand in enumerate(instruction.operands):
                destination = None
                kind = None
                if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                    destination = instruction.address + instruction.size + operand.mem.disp
                    kind = 'rip_relative_memory'
                elif operand.type == X86_OP_IMM:
                    destination = operand.imm & 0xffffffffffffffff
                    kind = 'immediate'
                target = absolute_targets.get(destination)
                if target is None:
                    continue
                references[target].append({
                    'source_rva': instruction.address - image_base,
                    'instruction_size': instruction.size,
                    'mnemonic': instruction.mnemonic,
                    'operands': instruction.op_str,
                    'operand_index': operand_index,
                    'kind': kind,
                    'section': section['name'],
                })
    return references


def indirect_calls(
    image,
    image_base,
    ranges,
    displacements,
    scan_start,
    scan_end,
    context_instructions,
):
    if not displacements:
        return []
    displacement_set = set(displacements)
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    decoder.skipdata = True
    matches = []
    for section in ranges:
        start = max(section['start_rva'], scan_start or 0)
        end = min(section['end_rva'], scan_end or len(image))
        if start >= end:
            continue
        context = deque(maxlen=max(0, context_instructions))
        for instruction in decoder.disasm(image[start:end], image_base + start):
            if instruction.id == 0:
                context.clear()
                continue
            matched_displacement = None
            if instruction.mnemonic == 'call':
                for operand in instruction.operands:
                    if operand.type != X86_OP_MEM:
                        continue
                    if operand.mem.disp in displacement_set:
                        matched_displacement = operand.mem.disp
                        break
            current = {
                'rva': instruction.address - image_base,
                'address': instruction.address,
                'bytes': instruction.bytes.hex(),
                'mnemonic': instruction.mnemonic,
                'operands': instruction.op_str,
            }
            if matched_displacement is not None:
                matches.append({
                    'section': section['name'],
                    'displacement': matched_displacement,
                    'instruction': current,
                    'context': list(context),
                })
            context.append(current)
    return matches


def immediate_references(
    image,
    image_base,
    ranges,
    values,
    scan_start,
    scan_end,
    context_instructions,
):
    if not values:
        return []
    value_set = set(values)
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    decoder.skipdata = True
    matches = []
    for section in ranges:
        start = max(section['start_rva'], scan_start or 0)
        end = min(section['end_rva'], scan_end or len(image))
        if start >= end:
            continue
        context = deque(maxlen=max(0, context_instructions))
        for instruction in decoder.disasm(image[start:end], image_base + start):
            if instruction.id == 0:
                context.clear()
                continue
            matched_value = None
            for operand in instruction.operands:
                if operand.type == X86_OP_IMM and operand.imm in value_set:
                    matched_value = operand.imm
                    break
            current = {
                'rva': instruction.address - image_base,
                'address': instruction.address,
                'bytes': instruction.bytes.hex(),
                'mnemonic': instruction.mnemonic,
                'operands': instruction.op_str,
            }
            if matched_value is not None:
                matches.append({
                    'section': section['name'],
                    'value': matched_value,
                    'instruction': current,
                    'context': list(context),
                })
            context.append(current)
    return matches


def main():
    options = parse_args()
    with open(options.image, 'rb') as stream:
        image = stream.read()
    image_base, ranges = executable_ranges(image)
    result = {
        'schema_version': 1,
        'image_path': os.path.abspath(options.image),
        'image_base': image_base,
        'executable_ranges': ranges,
        'disassembly': [
            disassemble(image, image_base, rva, options.before, options.size)
            for rva in options.rva
        ],
        'direct_xrefs': direct_xrefs(image, ranges, options.xref),
        'semantic_xrefs': semantic_xrefs(
            image,
            image_base,
            ranges,
            options.semantic_xref,
        ),
        'indirect_calls': indirect_calls(
            image,
            image_base,
            ranges,
            options.indirect_call_disp,
            options.scan_start,
            options.scan_end,
            options.context_instructions,
        ),
        'immediate_references': immediate_references(
            image,
            image_base,
            ranges,
            options.immediate_value,
            options.scan_start,
            options.scan_end,
            options.context_instructions,
        ),
    }
    rendered = json.dumps(result, ensure_ascii=True, indent=2)
    if options.output:
        output_path = os.path.abspath(options.output)
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(rendered)
            stream.write('\n')
    print(rendered)


if __name__ == '__main__':
    main()

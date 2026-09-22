#!/usr/bin/env python3

import argparse
import ctypes
import json
import os
import sys
from ctypes import wintypes
from datetime import datetime, timezone


PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x1000000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100
READABLE_PROTECTIONS = {
    0x02,
    0x04,
    0x08,
    0x20,
    0x40,
    0x80,
}


class MemoryBasicInformation(ctypes.Structure):
    _fields_ = [
        ('BaseAddress', wintypes.LPVOID),
        ('AllocationBase', wintypes.LPVOID),
        ('AllocationProtect', wintypes.DWORD),
        ('PartitionId', wintypes.WORD),
        ('RegionSize', ctypes.c_size_t),
        ('State', wintypes.DWORD),
        ('Protect', wintypes.DWORD),
        ('Type', wintypes.DWORD),
    ]


kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.VirtualQueryEx.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    ctypes.POINTER(MemoryBasicInformation),
    ctypes.c_size_t,
]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t
kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    wintypes.LPVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL


TYPE_NAMES = {
    MEM_PRIVATE: 'private',
    MEM_MAPPED: 'mapped',
    MEM_IMAGE: 'image',
}


def windows_error(operation):
    code = ctypes.get_last_error()
    return OSError(code, f'{operation} failed: {ctypes.FormatError(code).strip()}')


def parse_hex(value):
    normalized = ''.join(value.split())
    try:
        result = bytes.fromhex(normalized)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error
    if not result:
        raise argparse.ArgumentTypeError('pattern must not be empty')
    return result


def parse_args():
    parser = argparse.ArgumentParser(description='Scan readable Windows process memory without writing it.')
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--hex', action='append', default=[], type=parse_hex, dest='hex_patterns')
    parser.add_argument('--ascii', action='append', default=[])
    parser.add_argument('--memory-type', action='append', choices=('private', 'mapped', 'image'))
    parser.add_argument('--context', type=int, default=64)
    parser.add_argument('--chunk-size', type=int, default=4 * 1024 * 1024)
    parser.add_argument('--max-matches', type=int, default=100)
    parser.add_argument('--output')
    return parser.parse_args()


def readable_region(info, selected_types):
    if info.State != MEM_COMMIT:
        return False
    if info.Protect & (PAGE_NOACCESS | PAGE_GUARD):
        return False
    if info.Protect & 0xff not in READABLE_PROTECTIONS:
        return False
    type_name = TYPE_NAMES.get(info.Type, f'0x{info.Type:x}')
    return selected_types is None or type_name in selected_types


def iter_regions(process, selected_types):
    address = 0
    maximum_address = (1 << 47) - 1
    while address < maximum_address:
        info = MemoryBasicInformation()
        result = kernel32.VirtualQueryEx(
            process,
            ctypes.c_void_p(address),
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
        if result == 0:
            break
        base = ctypes.cast(info.BaseAddress, ctypes.c_void_p).value or 0
        size = int(info.RegionSize)
        if readable_region(info, selected_types):
            yield {
                'base': base,
                'size': size,
                'protect': int(info.Protect),
                'type': TYPE_NAMES.get(info.Type, f'0x{info.Type:x}'),
            }
        next_address = base + size
        if next_address <= address:
            break
        address = next_address


def read_memory(process, address, size):
    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t()
    if not kernel32.ReadProcessMemory(
        process,
        ctypes.c_void_p(address),
        buffer,
        size,
        ctypes.byref(bytes_read),
    ):
        return None
    return buffer.raw[:bytes_read.value]


def scan_region(process, region, patterns, chunk_size, context, remaining):
    overlap = max(len(pattern) for pattern in patterns) - 1
    matches = []
    cursor = 0
    tail = b''
    while cursor < region['size'] and len(matches) < remaining:
        length = min(chunk_size, region['size'] - cursor)
        value = read_memory(process, region['base'] + cursor, length)
        if value is None:
            tail = b''
            cursor += length
            continue
        combined = tail + value
        combined_address = region['base'] + cursor - len(tail)
        previous_end = region['base'] + cursor
        for pattern_index, pattern in enumerate(patterns):
            search_offset = 0
            while len(matches) < remaining:
                found = combined.find(pattern, search_offset)
                if found < 0:
                    break
                absolute_address = combined_address + found
                if absolute_address + len(pattern) > previous_end:
                    context_start = max(0, found - context)
                    context_end = min(len(combined), found + len(pattern) + context)
                    matches.append({
                        'pattern_index': pattern_index,
                        'address': f'0x{absolute_address:x}',
                        'region_offset': absolute_address - region['base'],
                        'context_address': f'0x{combined_address + context_start:x}',
                        'context_hex': combined[context_start:context_end].hex(),
                    })
                search_offset = found + 1
        tail = combined[-overlap:] if overlap else b''
        cursor += length
    return matches


def main():
    if os.name != 'nt':
        raise RuntimeError('this utility only supports Windows')
    options = parse_args()
    patterns = list(options.hex_patterns) + [value.encode('utf-8') for value in options.ascii]
    if not patterns:
        raise ValueError('at least one --hex or --ascii pattern is required')
    process = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        False,
        options.pid,
    )
    if not process:
        raise windows_error('OpenProcess')
    selected_types = set(options.memory_type) if options.memory_type else None
    result = {
        'schema_version': 1,
        'operation': 'READ_PROCESS_MEMORY_PATTERN_SCAN',
        'captured_at': datetime.now(timezone.utc).isoformat(),
        'process_id': options.pid,
        'patterns': [pattern.hex() for pattern in patterns],
        'selected_memory_types': sorted(selected_types) if selected_types else None,
        'scanned_region_count': 0,
        'scanned_bytes': 0,
        'unreadable_region_count': 0,
        'matches': [],
    }
    try:
        for region in iter_regions(process, selected_types):
            if len(result['matches']) >= options.max_matches:
                break
            region_matches = scan_region(
                process,
                region,
                patterns,
                options.chunk_size,
                options.context,
                options.max_matches - len(result['matches']),
            )
            result['scanned_region_count'] += 1
            result['scanned_bytes'] += region['size']
            for match in region_matches:
                result['matches'].append({
                    **match,
                    'region_base': f"0x{region['base']:x}",
                    'region_size': region['size'],
                    'region_type': region['type'],
                    'region_protect': f"0x{region['protect']:x}",
                })
    finally:
        kernel32.CloseHandle(process)
    rendered = json.dumps(result, ensure_ascii=True, indent=2)
    if options.output:
        output_path = os.path.abspath(options.output)
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(rendered)
            stream.write('\n')
    print(rendered)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'{type(error).__name__}: {error}', file=sys.stderr)
        sys.exit(1)

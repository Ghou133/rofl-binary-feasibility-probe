#!/usr/bin/env python3

import argparse
import ctypes
import hashlib
import json
import os
import sys
from ctypes import wintypes
from datetime import datetime, timezone


PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class ModuleEntry32W(ctypes.Structure):
    _fields_ = [
        ('dwSize', wintypes.DWORD),
        ('th32ModuleID', wintypes.DWORD),
        ('th32ProcessID', wintypes.DWORD),
        ('GlblcntUsage', wintypes.DWORD),
        ('ProccntUsage', wintypes.DWORD),
        ('modBaseAddr', ctypes.POINTER(wintypes.BYTE)),
        ('modBaseSize', wintypes.DWORD),
        ('hModule', wintypes.HMODULE),
        ('szModule', wintypes.WCHAR * 256),
        ('szExePath', wintypes.WCHAR * 260),
    ]


kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ModuleEntry32W)]
kernel32.Module32FirstW.restype = wintypes.BOOL
kernel32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ModuleEntry32W)]
kernel32.Module32NextW.restype = wintypes.BOOL
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
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


def windows_error(operation):
    code = ctypes.get_last_error()
    return OSError(code, f'{operation} failed: {ctypes.FormatError(code).strip()}')


def find_module(process_id, requested_name):
    snapshot = kernel32.CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
        process_id,
    )
    if snapshot == INVALID_HANDLE_VALUE:
        raise windows_error('CreateToolhelp32Snapshot')
    try:
        entry = ModuleEntry32W()
        entry.dwSize = ctypes.sizeof(entry)
        if not kernel32.Module32FirstW(snapshot, ctypes.byref(entry)):
            raise windows_error('Module32FirstW')
        requested = requested_name.casefold() if requested_name else None
        while True:
            if requested is None or entry.szModule.casefold() == requested:
                return {
                    'name': entry.szModule,
                    'path': entry.szExePath,
                    'base_address': ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value,
                    'size': int(entry.modBaseSize),
                }
            if not kernel32.Module32NextW(snapshot, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snapshot)
    raise RuntimeError(f'module not found in process {process_id}: {requested_name}')


def read_range(process, address, size):
    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t()
    ok = kernel32.ReadProcessMemory(
        process,
        ctypes.c_void_p(address),
        buffer,
        size,
        ctypes.byref(bytes_read),
    )
    if not ok or bytes_read.value != size:
        return None
    return buffer.raw


def dump_module(process_id, module, block_size=0x10000, page_size=0x1000):
    process = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        False,
        process_id,
    )
    if not process:
        raise windows_error('OpenProcess')
    try:
        image = bytearray(module['size'])
        readable_ranges = []
        unreadable_pages = []
        cursor = 0
        while cursor < module['size']:
            length = min(block_size, module['size'] - cursor)
            value = read_range(process, module['base_address'] + cursor, length)
            if value is not None:
                image[cursor:cursor + length] = value
                readable_ranges.append((cursor, length))
                cursor += length
                continue
            block_end = cursor + length
            page_cursor = cursor
            while page_cursor < block_end:
                page_length = min(page_size, block_end - page_cursor)
                value = read_range(
                    process,
                    module['base_address'] + page_cursor,
                    page_length,
                )
                if value is None:
                    unreadable_pages.append((page_cursor, page_length))
                else:
                    image[page_cursor:page_cursor + page_length] = value
                    readable_ranges.append((page_cursor, page_length))
                page_cursor += page_length
            cursor = block_end
        return bytes(image), readable_ranges, unreadable_pages
    finally:
        kernel32.CloseHandle(process)


def coalesce_ranges(ranges):
    result = []
    for offset, length in sorted(ranges):
        if result and result[-1][0] + result[-1][1] == offset:
            result[-1][1] += length
        else:
            result.append([offset, length])
    return result


def parse_args():
    parser = argparse.ArgumentParser(description='Read a Windows process module without injection.')
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--module', help='Module basename; defaults to the process main module.')
    parser.add_argument('--output', required=True)
    return parser.parse_args()


def main():
    if os.name != 'nt':
        raise RuntimeError('this utility only supports Windows')
    options = parse_args()
    module = find_module(options.pid, options.module)
    image, readable_ranges, unreadable_pages = dump_module(options.pid, module)
    output_path = os.path.abspath(options.output)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'wb') as stream:
        stream.write(image)
    metadata = {
        'schema_version': 1,
        'captured_at': datetime.now(timezone.utc).isoformat(),
        'operation': 'READ_PROCESS_MEMORY_ONLY',
        'process_id': options.pid,
        'module_name': module['name'],
        'module_path': module['path'],
        'base_address': f"0x{module['base_address']:x}",
        'module_size': module['size'],
        'readable_bytes': sum(length for _, length in readable_ranges),
        'unreadable_bytes': sum(length for _, length in unreadable_pages),
        'readable_ranges': [
            {'rva': f'0x{offset:x}', 'length': length}
            for offset, length in coalesce_ranges(readable_ranges)
        ],
        'unreadable_ranges': [
            {'rva': f'0x{offset:x}', 'length': length}
            for offset, length in coalesce_ranges(unreadable_pages)
        ],
        'output_path': output_path,
        'output_sha256': hashlib.sha256(image).hexdigest(),
    }
    metadata_path = output_path + '.json'
    with open(metadata_path, 'w', encoding='utf-8', newline='\n') as stream:
        json.dump(metadata, stream, ensure_ascii=True, indent=2)
        stream.write('\n')
    print(json.dumps(metadata, ensure_ascii=True, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'{type(error).__name__}: {error}', file=sys.stderr)
        sys.exit(1)

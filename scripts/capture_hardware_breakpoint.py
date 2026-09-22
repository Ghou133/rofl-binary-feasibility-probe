#!/usr/bin/env python3

import argparse
import ctypes
import json
import os
import struct
import sys
import time
from ctypes import wintypes
from datetime import datetime, timezone


TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPTHREAD = 0x00000004
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
THREAD_GET_CONTEXT = 0x0008
THREAD_SET_CONTEXT = 0x0010
THREAD_QUERY_INFORMATION = 0x0040

CONTEXT_AMD64 = 0x00100000
CONTEXT_CONTROL = CONTEXT_AMD64 | 0x00000001
CONTEXT_INTEGER = CONTEXT_AMD64 | 0x00000002
CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x00000010
CONTEXT_FLAGS = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS
CONTEXT_SIZE = 0x4D0

EXCEPTION_DEBUG_EVENT = 1
CREATE_THREAD_DEBUG_EVENT = 2
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_THREAD_DEBUG_EVENT = 4
EXIT_PROCESS_DEBUG_EVENT = 5
LOAD_DLL_DEBUG_EVENT = 6
UNLOAD_DLL_DEBUG_EVENT = 7
OUTPUT_DEBUG_STRING_EVENT = 8
RIP_EVENT = 9

EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001
ERROR_SEM_TIMEOUT = 121


class ProcessEntry32W(ctypes.Structure):
    _fields_ = [
        ('dwSize', wintypes.DWORD),
        ('cntUsage', wintypes.DWORD),
        ('th32ProcessID', wintypes.DWORD),
        ('th32DefaultHeapID', ctypes.c_size_t),
        ('th32ModuleID', wintypes.DWORD),
        ('cntThreads', wintypes.DWORD),
        ('th32ParentProcessID', wintypes.DWORD),
        ('pcPriClassBase', wintypes.LONG),
        ('dwFlags', wintypes.DWORD),
        ('szExeFile', wintypes.WCHAR * 260),
    ]


class ThreadEntry32(ctypes.Structure):
    _fields_ = [
        ('dwSize', wintypes.DWORD),
        ('cntUsage', wintypes.DWORD),
        ('th32ThreadID', wintypes.DWORD),
        ('th32OwnerProcessID', wintypes.DWORD),
        ('tpBasePri', wintypes.LONG),
        ('tpDeltaPri', wintypes.LONG),
        ('dwFlags', wintypes.DWORD),
    ]


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


ULONG_PTR = ctypes.c_size_t


class ExceptionRecord(ctypes.Structure):
    pass


ExceptionRecord._fields_ = [
    ('ExceptionCode', wintypes.DWORD),
    ('ExceptionFlags', wintypes.DWORD),
    ('ExceptionRecord', ctypes.POINTER(ExceptionRecord)),
    ('ExceptionAddress', wintypes.LPVOID),
    ('NumberParameters', wintypes.DWORD),
    ('ExceptionInformation', ULONG_PTR * 15),
]


class ExceptionDebugInfo(ctypes.Structure):
    _fields_ = [
        ('ExceptionRecord', ExceptionRecord),
        ('dwFirstChance', wintypes.DWORD),
    ]


class CreateThreadDebugInfo(ctypes.Structure):
    _fields_ = [
        ('hThread', wintypes.HANDLE),
        ('lpThreadLocalBase', wintypes.LPVOID),
        ('lpStartAddress', wintypes.LPVOID),
    ]


class CreateProcessDebugInfo(ctypes.Structure):
    _fields_ = [
        ('hFile', wintypes.HANDLE),
        ('hProcess', wintypes.HANDLE),
        ('hThread', wintypes.HANDLE),
        ('lpBaseOfImage', wintypes.LPVOID),
        ('dwDebugInfoFileOffset', wintypes.DWORD),
        ('nDebugInfoSize', wintypes.DWORD),
        ('lpThreadLocalBase', wintypes.LPVOID),
        ('lpStartAddress', wintypes.LPVOID),
        ('lpImageName', wintypes.LPVOID),
        ('fUnicode', wintypes.WORD),
    ]


class ExitThreadDebugInfo(ctypes.Structure):
    _fields_ = [('dwExitCode', wintypes.DWORD)]


class ExitProcessDebugInfo(ctypes.Structure):
    _fields_ = [('dwExitCode', wintypes.DWORD)]


class LoadDllDebugInfo(ctypes.Structure):
    _fields_ = [
        ('hFile', wintypes.HANDLE),
        ('lpBaseOfDll', wintypes.LPVOID),
        ('dwDebugInfoFileOffset', wintypes.DWORD),
        ('nDebugInfoSize', wintypes.DWORD),
        ('lpImageName', wintypes.LPVOID),
        ('fUnicode', wintypes.WORD),
    ]


class UnloadDllDebugInfo(ctypes.Structure):
    _fields_ = [('lpBaseOfDll', wintypes.LPVOID)]


class OutputDebugStringInfo(ctypes.Structure):
    _fields_ = [
        ('lpDebugStringData', wintypes.LPSTR),
        ('fUnicode', wintypes.WORD),
        ('nDebugStringLength', wintypes.WORD),
    ]


class RipInfo(ctypes.Structure):
    _fields_ = [('dwError', wintypes.DWORD), ('dwType', wintypes.DWORD)]


class DebugEventUnion(ctypes.Union):
    _fields_ = [
        ('Exception', ExceptionDebugInfo),
        ('CreateThread', CreateThreadDebugInfo),
        ('CreateProcessInfo', CreateProcessDebugInfo),
        ('ExitThread', ExitThreadDebugInfo),
        ('ExitProcess', ExitProcessDebugInfo),
        ('LoadDll', LoadDllDebugInfo),
        ('UnloadDll', UnloadDllDebugInfo),
        ('DebugString', OutputDebugStringInfo),
        ('RipInfo', RipInfo),
    ]


class DebugEvent(ctypes.Structure):
    _fields_ = [
        ('dwDebugEventCode', wintypes.DWORD),
        ('dwProcessId', wintypes.DWORD),
        ('dwThreadId', wintypes.DWORD),
        ('u', DebugEventUnion),
    ]


kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry32W)]
kernel32.Process32FirstW.restype = wintypes.BOOL
kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry32W)]
kernel32.Process32NextW.restype = wintypes.BOOL
kernel32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry32)]
kernel32.Thread32First.restype = wintypes.BOOL
kernel32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry32)]
kernel32.Thread32Next.restype = wintypes.BOOL
kernel32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ModuleEntry32W)]
kernel32.Module32FirstW.restype = wintypes.BOOL
kernel32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ModuleEntry32W)]
kernel32.Module32NextW.restype = wintypes.BOOL
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenThread.restype = wintypes.HANDLE
kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    wintypes.LPVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL
kernel32.GetThreadContext.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
kernel32.GetThreadContext.restype = wintypes.BOOL
kernel32.SetThreadContext.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
kernel32.SetThreadContext.restype = wintypes.BOOL
kernel32.DebugActiveProcess.argtypes = [wintypes.DWORD]
kernel32.DebugActiveProcess.restype = wintypes.BOOL
kernel32.DebugActiveProcessStop.argtypes = [wintypes.DWORD]
kernel32.DebugActiveProcessStop.restype = wintypes.BOOL
kernel32.DebugSetProcessKillOnExit.argtypes = [wintypes.BOOL]
kernel32.DebugSetProcessKillOnExit.restype = wintypes.BOOL
kernel32.WaitForDebugEvent.argtypes = [ctypes.POINTER(DebugEvent), wintypes.DWORD]
kernel32.WaitForDebugEvent.restype = wintypes.BOOL
kernel32.ContinueDebugEvent.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.DWORD]
kernel32.ContinueDebugEvent.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL


REGISTER_OFFSETS = {
    'dr0': 0x48,
    'dr1': 0x50,
    'dr2': 0x58,
    'dr3': 0x60,
    'dr6': 0x68,
    'dr7': 0x70,
    'rax': 0x78,
    'rcx': 0x80,
    'rdx': 0x88,
    'rbx': 0x90,
    'rsp': 0x98,
    'rbp': 0xA0,
    'rsi': 0xA8,
    'rdi': 0xB0,
    'r8': 0xB8,
    'r9': 0xC0,
    'r10': 0xC8,
    'r11': 0xD0,
    'r12': 0xD8,
    'r13': 0xE0,
    'r14': 0xE8,
    'r15': 0xF0,
    'rip': 0xF8,
}


def windows_error(operation):
    code = ctypes.get_last_error()
    return OSError(code, f'{operation} failed: {ctypes.FormatError(code).strip()}')


def snapshot(flags, process_id=0):
    handle = kernel32.CreateToolhelp32Snapshot(flags, process_id)
    if handle == INVALID_HANDLE_VALUE:
        raise windows_error('CreateToolhelp32Snapshot')
    return handle


def find_process(name):
    handle = snapshot(TH32CS_SNAPPROCESS)
    try:
        entry = ProcessEntry32W()
        entry.dwSize = ctypes.sizeof(entry)
        if not kernel32.Process32FirstW(handle, ctypes.byref(entry)):
            raise windows_error('Process32FirstW')
        requested = name.casefold()
        while True:
            if entry.szExeFile.casefold() == requested:
                return int(entry.th32ProcessID)
            if not kernel32.Process32NextW(handle, ctypes.byref(entry)):
                return None
    finally:
        kernel32.CloseHandle(handle)


def wait_for_process(name, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        process_id = find_process(name)
        if process_id is not None:
            return process_id
        time.sleep(0.1)
    raise TimeoutError(f'process did not appear within {timeout}s: {name}')


def find_module(process_id, name):
    handle = snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id)
    try:
        entry = ModuleEntry32W()
        entry.dwSize = ctypes.sizeof(entry)
        if not kernel32.Module32FirstW(handle, ctypes.byref(entry)):
            raise windows_error('Module32FirstW')
        requested = name.casefold()
        while True:
            if entry.szModule.casefold() == requested:
                return {
                    'name': entry.szModule,
                    'path': entry.szExePath,
                    'base_address': ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value,
                    'size': int(entry.modBaseSize),
                }
            if not kernel32.Module32NextW(handle, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(handle)
    raise RuntimeError(f'module not found in process {process_id}: {name}')


def enumerate_threads(process_id):
    handle = snapshot(TH32CS_SNAPTHREAD)
    result = []
    try:
        entry = ThreadEntry32()
        entry.dwSize = ctypes.sizeof(entry)
        if not kernel32.Thread32First(handle, ctypes.byref(entry)):
            raise windows_error('Thread32First')
        while True:
            if entry.th32OwnerProcessID == process_id:
                result.append(int(entry.th32ThreadID))
            if not kernel32.Thread32Next(handle, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(handle)
    return result


def aligned_context():
    storage = ctypes.create_string_buffer(CONTEXT_SIZE + 15)
    address = (ctypes.addressof(storage) + 15) & ~15
    ctypes.c_uint32.from_address(address + 0x30).value = CONTEXT_FLAGS
    return storage, address


def get_context(thread):
    storage, address = aligned_context()
    if not kernel32.GetThreadContext(thread, ctypes.c_void_p(address)):
        raise windows_error('GetThreadContext')
    registers = {
        name: ctypes.c_uint64.from_address(address + offset).value
        for name, offset in REGISTER_OFFSETS.items()
    }
    return storage, address, registers


def set_breakpoints(thread, addresses):
    storage, address, _ = get_context(thread)
    for index, breakpoint_address in enumerate(addresses):
        ctypes.c_uint64.from_address(address + REGISTER_OFFSETS[f'dr{index}']).value = breakpoint_address
    dr7 = 0
    for index in range(len(addresses)):
        dr7 |= 1 << (index * 2)
    ctypes.c_uint64.from_address(address + REGISTER_OFFSETS['dr6']).value = 0
    ctypes.c_uint64.from_address(address + REGISTER_OFFSETS['dr7']).value = dr7
    if not kernel32.SetThreadContext(thread, ctypes.c_void_p(address)):
        raise windows_error('SetThreadContext')
    return storage


def open_thread(thread_id):
    handle = kernel32.OpenThread(
        THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
        False,
        thread_id,
    )
    if not handle:
        raise windows_error(f'OpenThread({thread_id})')
    return handle


def read_memory(process, address, size):
    if not address:
        return None
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


def pointer_dump(process, address, size):
    value = read_memory(process, address, size)
    if value is None:
        return None
    return {'address': f'0x{address:x}', 'length': len(value), 'hex': value.hex()}


def capture_hit(process, thread_id, module, addresses, hit_index):
    thread = open_thread(thread_id)
    try:
        storage, address, registers = get_context(thread)
        dr6 = registers['dr6']
        slots = [index for index in range(len(addresses)) if dr6 & (1 << index)]
        stack = read_memory(process, registers['rsp'], 0x100)
        stack_module_rvas = []
        if stack is not None:
            for offset in range(0, len(stack) - 7, 8):
                value = struct.unpack_from('<Q', stack, offset)[0]
                if module['base_address'] <= value < module['base_address'] + module['size']:
                    stack_module_rvas.append({
                        'stack_offset': offset,
                        'address': f'0x{value:x}',
                        'rva': f"0x{value - module['base_address']:x}",
                    })
        result = {
            'schema_version': 1,
            'capture_index': hit_index,
            'captured_at': datetime.now(timezone.utc).isoformat(),
            'thread_id': thread_id,
            'breakpoint_slots': slots,
            'breakpoint_rvas': [f"0x{addresses[index] - module['base_address']:x}" for index in slots],
            'registers': {name: f'0x{value:x}' for name, value in registers.items()},
            'memory': {
                name: pointer_dump(process, registers[name], 0x100)
                for name in ('rcx', 'rdx', 'r8', 'r9', 'rsp')
            },
            'stack_module_rvas': stack_module_rvas,
        }
        ctypes.c_uint64.from_address(address + REGISTER_OFFSETS['dr6']).value = 0
        if not kernel32.SetThreadContext(thread, ctypes.c_void_p(address)):
            raise windows_error('SetThreadContext(clear Dr6)')
        return result
    finally:
        kernel32.CloseHandle(thread)


def apply_to_thread(thread_id, addresses):
    thread = open_thread(thread_id)
    try:
        set_breakpoints(thread, addresses)
    finally:
        kernel32.CloseHandle(thread)


def parse_int(value):
    return int(value, 0)


def parse_args():
    parser = argparse.ArgumentParser(
        description='Capture x86-64 packet state with hardware execution breakpoints.',
    )
    parser.add_argument('--pid', type=int)
    parser.add_argument('--process-name', default='League of Legends.exe')
    parser.add_argument('--module', default='League of Legends.exe')
    parser.add_argument('--rva', action='append', required=True, type=parse_int)
    parser.add_argument('--output', required=True)
    parser.add_argument('--wait-timeout', type=float, default=120.0)
    parser.add_argument('--capture-timeout', type=float, default=300.0)
    parser.add_argument('--max-hits', type=int, default=100)
    return parser.parse_args()


def main():
    if os.name != 'nt':
        raise RuntimeError('this utility only supports Windows')
    options = parse_args()
    if len(options.rva) > 4:
        raise ValueError('x86-64 exposes at most four hardware breakpoint slots')
    process_id = options.pid or wait_for_process(options.process_name, options.wait_timeout)
    module = find_module(process_id, options.module)
    addresses = [module['base_address'] + rva for rva in options.rva]
    process = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        False,
        process_id,
    )
    if not process:
        raise windows_error('OpenProcess')
    attached = False
    output_path = os.path.abspath(options.output)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    metadata = {
        'schema_version': 1,
        'operation': 'HARDWARE_EXECUTION_BREAKPOINT_READ_ONLY_CAPTURE',
        'process_id': process_id,
        'process_name': options.process_name,
        'module': module,
        'breakpoint_rvas': [f'0x{rva:x}' for rva in options.rva],
        'breakpoint_addresses': [f'0x{address:x}' for address in addresses],
        'started_at': datetime.now(timezone.utc).isoformat(),
    }
    print(json.dumps(metadata, ensure_ascii=True), flush=True)
    hit_count = 0
    deadline = time.monotonic() + options.capture_timeout
    try:
        if not kernel32.DebugActiveProcess(process_id):
            raise windows_error('DebugActiveProcess')
        attached = True
        if not kernel32.DebugSetProcessKillOnExit(False):
            raise windows_error('DebugSetProcessKillOnExit')
        with open(output_path, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(json.dumps({'type': 'metadata', **metadata}, ensure_ascii=True) + '\n')
            stream.flush()
            while time.monotonic() < deadline and hit_count < options.max_hits:
                event = DebugEvent()
                if not kernel32.WaitForDebugEvent(ctypes.byref(event), 100):
                    if ctypes.get_last_error() == ERROR_SEM_TIMEOUT:
                        continue
                    raise windows_error('WaitForDebugEvent')
                status = DBG_CONTINUE
                try:
                    if event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT:
                        info = event.u.CreateProcessInfo
                        if info.hFile:
                            kernel32.CloseHandle(info.hFile)
                        for thread_id in enumerate_threads(process_id):
                            try:
                                apply_to_thread(thread_id, addresses)
                            except OSError:
                                pass
                    elif event.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT:
                        try:
                            set_breakpoints(event.u.CreateThread.hThread, addresses)
                        except OSError:
                            pass
                    elif event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT:
                        if event.u.LoadDll.hFile:
                            kernel32.CloseHandle(event.u.LoadDll.hFile)
                    elif event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT:
                        break
                    elif event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
                        code = event.u.Exception.ExceptionRecord.ExceptionCode
                        if code == EXCEPTION_SINGLE_STEP:
                            hit_count += 1
                            hit = capture_hit(
                                process,
                                event.dwThreadId,
                                module,
                                addresses,
                                hit_count,
                            )
                            stream.write(json.dumps({'type': 'hit', **hit}, ensure_ascii=True) + '\n')
                            stream.flush()
                            print(
                                json.dumps({
                                    'capture_index': hit_count,
                                    'thread_id': event.dwThreadId,
                                    'breakpoint_rvas': hit['breakpoint_rvas'],
                                }, ensure_ascii=True),
                                flush=True,
                            )
                        elif code != EXCEPTION_BREAKPOINT:
                            status = DBG_EXCEPTION_NOT_HANDLED
                finally:
                    if not kernel32.ContinueDebugEvent(
                        event.dwProcessId,
                        event.dwThreadId,
                        status,
                    ):
                        raise windows_error('ContinueDebugEvent')
    finally:
        if attached:
            kernel32.DebugActiveProcessStop(process_id)
        kernel32.CloseHandle(process)
    result = {
        **metadata,
        'finished_at': datetime.now(timezone.utc).isoformat(),
        'capture_count': hit_count,
        'output_path': output_path,
    }
    print(json.dumps(result, ensure_ascii=True, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'{type(error).__name__}: {error}', file=sys.stderr)
        sys.exit(1)

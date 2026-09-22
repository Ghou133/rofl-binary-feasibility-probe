#!/usr/bin/env python3

import argparse
import ctypes
import json
import os
import sys
from datetime import datetime, timezone

from scan_process_memory import (
    PROCESS_QUERY_INFORMATION,
    PROCESS_VM_READ,
    kernel32,
    read_memory,
    windows_error,
)


def parse_int(value):
    return int(value, 0)


def parse_args():
    parser = argparse.ArgumentParser(description='Read an exact Windows process memory range.')
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--address', type=parse_int, required=True)
    parser.add_argument('--size', type=parse_int, required=True)
    parser.add_argument('--output')
    return parser.parse_args()


def main():
    if os.name != 'nt':
        raise RuntimeError('this utility only supports Windows')
    options = parse_args()
    process = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        False,
        options.pid,
    )
    if not process:
        raise windows_error('OpenProcess')
    try:
        value = read_memory(process, options.address, options.size)
    finally:
        kernel32.CloseHandle(process)
    if value is None or len(value) != options.size:
        raise RuntimeError(
            f'could not read complete range at 0x{options.address:x}: '
            f'expected {options.size}, got {0 if value is None else len(value)}'
        )
    result = {
        'schema_version': 1,
        'operation': 'READ_PROCESS_MEMORY_EXACT_RANGE',
        'captured_at': datetime.now(timezone.utc).isoformat(),
        'process_id': options.pid,
        'address': f'0x{options.address:x}',
        'size': options.size,
        'hex': value.hex(),
    }
    if options.output:
        output_path = os.path.abspath(options.output)
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8', newline='\n') as stream:
            json.dump(result, stream, ensure_ascii=True, indent=2)
            stream.write('\n')
    print(json.dumps(result, ensure_ascii=True, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'{type(error).__name__}: {error}', file=sys.stderr)
        sys.exit(1)

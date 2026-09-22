#!/usr/bin/env python3

import argparse
import ctypes
import hashlib
import json
import os
import struct
import sys
from datetime import datetime, timezone

from scan_process_memory import (
    PROCESS_QUERY_INFORMATION,
    PROCESS_VM_READ,
    kernel32,
    read_memory,
    windows_error,
)


RECORD_SIZE = 0x18


def parse_int(value):
    return int(value, 0)


def parse_args():
    parser = argparse.ArgumentParser(
        description='Capture a decoded packet history vector from a running client.',
    )
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--address', type=parse_int, required=True)
    parser.add_argument('--object-size', type=parse_int, required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--summary')
    parser.add_argument('--limit', type=int)
    return parser.parse_args()


def require_read(process, address, size):
    value = read_memory(process, address, size)
    if value is None or len(value) != size:
        raise RuntimeError(
            f'could not read complete range at 0x{address:x}: '
            f'expected {size}, got {0 if value is None else len(value)}'
        )
    return value


def main():
    if os.name != 'nt':
        raise RuntimeError('this utility only supports Windows')
    options = parse_args()
    if options.object_size < 1:
        raise ValueError('--object-size must be positive')
    if options.limit is not None and options.limit < 1:
        raise ValueError('--limit must be positive')

    process = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        False,
        options.pid,
    )
    if not process:
        raise windows_error('OpenProcess')
    captured_at = datetime.now(timezone.utc).isoformat()
    output_path = os.path.abspath(options.output)
    summary_path = os.path.abspath(options.summary or f'{options.output}.summary.json')
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    os.makedirs(os.path.dirname(summary_path), exist_ok=True)
    object_hash = hashlib.sha256()
    try:
        header = require_read(process, options.address, 0x20)
        opcode = struct.unpack_from('<I', header, 0)[0]
        begin, end, capacity = struct.unpack_from('<QQQ', header, 8)
        if end < begin or capacity < end:
            raise RuntimeError(
                f'invalid history bounds: 0x{begin:x} <= 0x{end:x} <= 0x{capacity:x}'
            )
        byte_length = end - begin
        if byte_length % RECORD_SIZE:
            raise RuntimeError(
                f'history byte length {byte_length} is not divisible by {RECORD_SIZE}'
            )
        record_count = byte_length // RECORD_SIZE
        capture_count = min(record_count, options.limit or record_count)
        records = require_read(process, begin, capture_count * RECORD_SIZE)
        unreadable_object_count = 0
        with open(output_path, 'w', encoding='utf-8', newline='\n') as destination:
            for index in range(capture_count):
                offset = index * RECORD_SIZE
                timestamp, object_address, control_address = struct.unpack_from(
                    '<f4xQQ',
                    records,
                    offset,
                )
                object_bytes = read_memory(
                    process,
                    object_address,
                    options.object_size,
                )
                if object_bytes is None or len(object_bytes) != options.object_size:
                    unreadable_object_count += 1
                    object_hex = None
                else:
                    object_hash.update(object_bytes)
                    object_hex = object_bytes.hex()
                row = {
                    'schema_version': 1,
                    'index': index,
                    'timestamp_seconds': timestamp,
                    'object_address': f'0x{object_address:x}',
                    'control_address': f'0x{control_address:x}',
                    'object_hex': object_hex,
                }
                destination.write(json.dumps(row, ensure_ascii=True, separators=(',', ':')))
                destination.write('\n')
    finally:
        kernel32.CloseHandle(process)

    summary = {
        'schema_version': 1,
        'operation': 'READ_PROCESS_MEMORY_PACKET_HISTORY',
        'captured_at': captured_at,
        'process_id': options.pid,
        'history_address': f'0x{options.address:x}',
        'opcode': opcode,
        'opcode_hex': f'0x{opcode:04x}',
        'record_size': RECORD_SIZE,
        'object_size': options.object_size,
        'begin_address': f'0x{begin:x}',
        'end_address': f'0x{end:x}',
        'capacity_address': f'0x{capacity:x}',
        'record_count': record_count,
        'captured_record_count': capture_count,
        'unreadable_object_count': unreadable_object_count,
        'concatenated_object_sha256': object_hash.hexdigest(),
        'output_path': output_path,
    }
    with open(summary_path, 'w', encoding='utf-8', newline='\n') as stream:
        json.dump(summary, stream, ensure_ascii=True, indent=2)
        stream.write('\n')
    print(json.dumps({**summary, 'summary_path': summary_path}, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'{type(error).__name__}: {error}', file=sys.stderr)
        sys.exit(1)

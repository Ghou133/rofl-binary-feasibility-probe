#!/usr/bin/env python3

import argparse
import collections
import hashlib
import json
import math
import os
import struct
import sys

from emulate_exact_packet_decoder import ExactPacketEmulator, PROFILES


def parse_args():
    parser = argparse.ArgumentParser(
        description='Compare offline packet emulation with captured client packet history.',
    )
    parser.add_argument('--image', required=True)
    parser.add_argument('--offline', required=True)
    parser.add_argument('--runtime', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--summary')
    parser.add_argument('--profile', choices=sorted(PROFILES), default='unit_apply_damage')
    parser.add_argument('--limit', type=int)
    parser.add_argument('--timestamp-tolerance-ms', type=float, default=1.1)
    return parser.parse_args()


def sha256_file(file_path):
    digest = hashlib.sha256()
    with open(file_path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def read_json_lines(stream):
    for line_number, line in enumerate(stream, start=1):
        if line.strip():
            yield line_number, json.loads(line)


def values_equal(left, right):
    if left is None or right is None:
        return left is right
    if isinstance(left, float) or isinstance(right, float):
        return math.isfinite(left) and math.isfinite(right) and left == right
    return left == right


def decode_runtime_object(emulator, profile, object_hex):
    object_bytes = bytes.fromhex(object_hex)
    if len(object_bytes) != profile['object_size']:
        raise ValueError(
            f"runtime object has {len(object_bytes)} bytes; "
            f"profile expects {profile['object_size']}"
        )
    state = emulator.prepare_profile(profile)
    fields = {
        field['name']: emulator.decode_field(object_bytes, field, state['byte_tables'])
        for field in profile['fields']
    }
    return {
        'opcode': struct.unpack_from('<H', object_bytes, 8)[0],
        'fields': fields,
    }


def main():
    options = parse_args()
    if options.limit is not None and options.limit < 1:
        raise ValueError('--limit must be a positive integer')
    if not math.isfinite(options.timestamp_tolerance_ms) or options.timestamp_tolerance_ms < 0:
        raise ValueError('--timestamp-tolerance-ms must be a finite non-negative number')

    with open(options.image, 'rb') as stream:
        image = stream.read()
    profile = PROFILES[options.profile]
    emulator = ExactPacketEmulator(image)
    output_path = os.path.abspath(options.output)
    summary_path = os.path.abspath(options.summary or f'{options.output}.summary.json')
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    os.makedirs(os.path.dirname(summary_path), exist_ok=True)

    counts = collections.Counter()
    field_match_counts = collections.Counter()
    first_mismatch = None
    max_timestamp_delta_ms = 0.0
    with open(options.offline, encoding='utf-8') as offline_stream, open(
        options.runtime,
        encoding='utf-8',
    ) as runtime_stream, open(
        output_path,
        'w',
        encoding='utf-8',
        newline='\n',
    ) as destination:
        offline_rows = read_json_lines(offline_stream)
        for runtime_line_number, runtime_row in read_json_lines(runtime_stream):
            if options.limit is not None and counts['compared_count'] >= options.limit:
                break
            try:
                offline_line_number, offline_row = next(offline_rows)
            except StopIteration as error:
                raise ValueError(
                    f'offline input ended before runtime line {runtime_line_number}'
                ) from error

            runtime_decoded = decode_runtime_object(
                emulator,
                profile,
                runtime_row['object_hex'],
            )
            offline_fields = offline_row.get('decoded_fields') or {}
            runtime_fields = runtime_decoded['fields']
            field_matches = {
                field['name']: values_equal(
                    offline_fields.get(field['name']),
                    runtime_fields.get(field['name']),
                )
                for field in profile['fields']
            }
            for field_name, matches in field_matches.items():
                field_match_counts[field_name] += int(matches)

            offline_timestamp_ms = offline_row.get('replay_time_ms')
            runtime_timestamp_ms = runtime_row.get('timestamp_seconds') * 1000
            timestamp_delta_ms = abs(runtime_timestamp_ms - offline_timestamp_ms)
            max_timestamp_delta_ms = max(max_timestamp_delta_ms, timestamp_delta_ms)
            timestamp_matches = timestamp_delta_ms <= options.timestamp_tolerance_ms
            opcode_matches = runtime_decoded['opcode'] == profile['client_opcode']
            index_matches = runtime_row.get('index') == counts['compared_count']
            all_fields_match = all(field_matches.values())
            full_match = timestamp_matches and opcode_matches and index_matches and all_fields_match

            counts['compared_count'] += 1
            counts['timestamp_match_count'] += int(timestamp_matches)
            counts['opcode_match_count'] += int(opcode_matches)
            counts['index_match_count'] += int(index_matches)
            counts['all_fields_match_count'] += int(all_fields_match)
            counts['full_match_count'] += int(full_match)
            if not full_match and first_mismatch is None:
                first_mismatch = {
                    'comparison_index': counts['compared_count'] - 1,
                    'offline_line_number': offline_line_number,
                    'runtime_line_number': runtime_line_number,
                    'timestamp_matches': timestamp_matches,
                    'opcode_matches': opcode_matches,
                    'index_matches': index_matches,
                    'field_matches': field_matches,
                }

            comparison = {
                'schema_version': 1,
                'comparison_index': counts['compared_count'] - 1,
                'offline_occurrence_index': offline_row.get('occurrence_index'),
                'runtime_index': runtime_row.get('index'),
                'offline_replay_time_ms': offline_timestamp_ms,
                'runtime_timestamp_ms': runtime_timestamp_ms,
                'timestamp_delta_ms': timestamp_delta_ms,
                'timestamp_matches': timestamp_matches,
                'runtime_opcode': runtime_decoded['opcode'],
                'runtime_opcode_hex': f"0x{runtime_decoded['opcode']:04x}",
                'opcode_matches': opcode_matches,
                'index_matches': index_matches,
                'offline_fields': offline_fields,
                'runtime_fields': runtime_fields,
                'field_matches': field_matches,
                'all_fields_match': all_fields_match,
                'full_match': full_match,
            }
            destination.write(json.dumps(comparison, ensure_ascii=True, separators=(',', ':')))
            destination.write('\n')

    compared_count = counts['compared_count']
    status = 'PASS' if compared_count > 0 and counts['full_match_count'] == compared_count else 'FAIL'
    summary = {
        'schema_version': 1,
        'status': status,
        'method': 'offline Unicorn decode versus read-only client runtime packet history',
        'profile': options.profile,
        'image_path': os.path.abspath(options.image),
        'image_sha256': hashlib.sha256(image).hexdigest(),
        'offline_path': os.path.abspath(options.offline),
        'offline_sha256': sha256_file(options.offline),
        'runtime_path': os.path.abspath(options.runtime),
        'runtime_sha256': sha256_file(options.runtime),
        'output_path': output_path,
        'timestamp_tolerance_ms': options.timestamp_tolerance_ms,
        'client_opcode': f"0x{profile['client_opcode']:04x}",
        'field_names': [field['name'] for field in profile['fields']],
        'compared_count': compared_count,
        'timestamp_match_count': counts['timestamp_match_count'],
        'opcode_match_count': counts['opcode_match_count'],
        'index_match_count': counts['index_match_count'],
        'all_fields_match_count': counts['all_fields_match_count'],
        'full_match_count': counts['full_match_count'],
        'per_field_match_count': dict(field_match_counts),
        'max_timestamp_delta_ms': max_timestamp_delta_ms,
        'first_mismatch': first_mismatch,
    }
    with open(summary_path, 'w', encoding='utf-8', newline='\n') as stream:
        json.dump(summary, stream, ensure_ascii=True, indent=2)
        stream.write('\n')
    print(json.dumps({**summary, 'summary_path': summary_path}, indent=2))
    if status != 'PASS':
        raise RuntimeError('runtime decoder validation failed')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'{type(error).__name__}: {error}', file=sys.stderr)
        sys.exit(1)

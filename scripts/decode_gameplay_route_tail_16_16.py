#!/usr/bin/env python3

"""Decode the six published 16.16 gameplay-tail routes in one runtime pass.

The input is an explicitly exported JSONL packet set.  Every input row must
belong to one of the supplied exact profile files; rows and failures are never
silently discarded.  The exact Tencent runtime image is loaded once and used
for all route profiles.
"""

import argparse
import collections
import hashlib
import json
import os
import sys

from emulate_exact_packet_decoder import ExactPacketEmulator, RUNTIME_PROFILES


EXACT_BUILD = '16.16.805.0442'
INTEGER_KEYS = ('client_opcode', 'constructor_rva', 'deserialize_rva', 'object_size')


def reject_protected_path(value):
    if 'holdout' in os.fspath(value).lower():
        raise ValueError(f'protected Holdout path is forbidden: {value}')


def parse_args():
    parser = argparse.ArgumentParser(
        description='Decode the published exact-build gameplay-tail route set.',
    )
    parser.add_argument('--image', required=True)
    parser.add_argument('--events', required=True)
    parser.add_argument('--profile-json', action='append', required=True)
    parser.add_argument('--runtime-profile', choices=sorted(RUNTIME_PROFILES), default=EXACT_BUILD)
    parser.add_argument('--output', required=True)
    parser.add_argument('--summary', required=True)
    parser.add_argument('--progress-every', type=int, default=0)
    return parser.parse_args()


def integer(value, name):
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise TypeError(f'{name} must be an integer or integer string')


def load_profiles(paths):
    profiles = {}
    for profile_path in paths:
        reject_protected_path(profile_path)
        with open(profile_path, 'rb') as stream:
            profile_bytes = stream.read()
        bundle = json.loads(profile_bytes.decode('utf-8-sig'))
        profile = dict(bundle.get('profile', bundle))
        for key in INTEGER_KEYS:
            if key not in profile:
                raise KeyError(f'{profile_path} is missing {key}')
            profile[key] = integer(profile[key], key)
        profile.setdefault('fields', [])
        opcode = profile['client_opcode']
        if opcode in profiles:
            raise ValueError(f'duplicate profile for 0x{opcode:04x}')
        profiles[opcode] = {
            'path': os.path.abspath(profile_path),
            'sha256': hashlib.sha256(profile_bytes).hexdigest(),
            'profile': profile,
            'bundle': bundle,
        }
    return profiles


def main():
    options = parse_args()
    for value in (
        options.image, options.events, options.output, options.summary,
        *options.profile_json,
    ):
        reject_protected_path(value)
    if options.runtime_profile != EXACT_BUILD:
        raise ValueError(f'exact runtime profile must be {EXACT_BUILD}')
    if options.progress_every < 0:
        raise ValueError('--progress-every cannot be negative')

    profiles = load_profiles(options.profile_json)
    if not profiles:
        raise ValueError('at least one exact profile is required')
    with open(options.image, 'rb') as stream:
        image = stream.read()
    image_sha256 = hashlib.sha256(image).hexdigest()
    emulator = ExactPacketEmulator(image, RUNTIME_PROFILES[options.runtime_profile])

    output_path = os.path.abspath(options.output)
    summary_path = os.path.abspath(options.summary)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    os.makedirs(os.path.dirname(summary_path), exist_ok=True)

    totals = collections.Counter()
    per_route = {opcode: collections.Counter() for opcode in profiles}
    payload_lengths = {opcode: collections.Counter() for opcode in profiles}
    errors = {opcode: collections.Counter() for opcode in profiles}
    replay_counts = collections.Counter()
    count_keys = (
        'input_event_count', 'deserialize_success_count', 'fully_consumed_count',
        'successful_full_consume_count', 'emulation_error_count',
    )
    for key in count_keys:
        totals[key] += 0
        for route_counts in per_route.values():
            route_counts[key] += 0

    with open(options.events, encoding='utf-8-sig') as source, open(
        output_path, 'w', encoding='utf-8', newline='\n',
    ) as destination:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            event = json.loads(line)
            if event.get('replay_version') != EXACT_BUILD:
                raise ValueError(f'line {line_number} has wrong exact build')
            opcode = event.get('packet_id')
            if opcode not in profiles:
                raise ValueError(f'line {line_number} has unprofiled route {opcode!r}')
            selected = profiles[opcode]
            totals['input_event_count'] += 1
            per_route[opcode]['input_event_count'] += 1
            try:
                decoded = emulator.decode(
                    bytes.fromhex(event['raw_payload_hex']),
                    selected['profile'],
                    packet_id=opcode,
                    raw_param=event.get('raw_param'),
                )
                success = decoded['deserialize_return_al'] != 0
                consumed = decoded['fully_consumed'] is True
                totals['deserialize_success_count'] += int(success)
                totals['fully_consumed_count'] += int(consumed)
                totals['successful_full_consume_count'] += int(success and consumed)
                per_route[opcode]['deserialize_success_count'] += int(success)
                per_route[opcode]['fully_consumed_count'] += int(consumed)
                per_route[opcode]['successful_full_consume_count'] += int(success and consumed)
                row = {
                    **event,
                    **decoded,
                    'decoder_profile': selected['profile'].get('id'),
                    'decoder_runtime_image_sha256': image_sha256,
                    'decoder_profile_sha256': selected['sha256'],
                }
            except Exception as error:  # Keep the original row and exact failure.
                message = f'{type(error).__name__}: {error}'
                totals['emulation_error_count'] += 1
                per_route[opcode]['emulation_error_count'] += 1
                errors[opcode][message] += 1
                row = {**event, 'emulation_error': message}
            destination.write(json.dumps(row, ensure_ascii=True, separators=(',', ':')))
            destination.write('\n')
            payload_lengths[opcode][event.get('payload_length', -1)] += 1
            replay_counts[event.get('replay_sha256', 'UNKNOWN')] += 1
            if options.progress_every and totals['input_event_count'] % options.progress_every == 0:
                print(f"decoded {totals['input_event_count']} events", file=sys.stderr)

    route_summary = {}
    for opcode, selected in sorted(profiles.items()):
        route_summary[f'0x{opcode:04x}'] = {
            'profile_path': selected['path'],
            'profile_sha256': selected['sha256'],
            'decoder_profile': selected['profile'].get('id'),
            **per_route[opcode],
            'payload_length_counts': dict(sorted(payload_lengths[opcode].items())),
            'emulation_errors': dict(errors[opcode].most_common()),
        }
    summary = {
        'schema': 'ROFL_GAMEPLAY_ROUTE_TAIL_MULTI_DECODE_V1',
        'schema_version': 1,
        'status': 'PASS' if (
            totals['input_event_count'] == totals['successful_full_consume_count']
            and totals['emulation_error_count'] == 0
        ) else 'PARTIAL',
        'exact_build': EXACT_BUILD,
        'exact_build_only': True,
        'nearest_build_fallback': 'FORBIDDEN',
        'runtime_profile': options.runtime_profile,
        'image_path': os.path.abspath(options.image),
        'image_sha256': image_sha256,
        'events_path': os.path.abspath(options.events),
        'output_path': output_path,
        **totals,
        'output_row_count': totals['input_event_count'],
        'input_conserved': totals['input_event_count'] == sum(
            row['input_event_count'] for row in route_summary.values()
        ),
        'replay_event_counts': dict(sorted(replay_counts.items())),
        'routes': route_summary,
        'protected_holdout': {
            'enumerated': False, 'read': False, 'hashed': False,
            'decoded': False, 'tested': False, 'consumed': False,
        },
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

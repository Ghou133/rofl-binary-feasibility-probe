#!/usr/bin/env python3

import argparse
import collections
import hashlib
import json
import os
import sys

from emulate_exact_packet_decoder import ExactPacketEmulator, RUNTIME_PROFILES


INTEGER_KEYS = (
    'client_opcode',
    'constructor_rva',
    'deserialize_rva',
    'object_size',
)


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            'Execute a packet constructor/deserializer profile from JSON against '
            'Replay packet JSONL using the exact unpacked client image.'
        ),
    )
    parser.add_argument('--image', required=True)
    parser.add_argument('--events', required=True)
    parser.add_argument('--profile-json', required=True)
    parser.add_argument('--runtime-profile', choices=sorted(RUNTIME_PROFILES), required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--summary')
    parser.add_argument('--limit', type=int)
    parser.add_argument('--progress-every', type=int, default=1000)
    return parser.parse_args()


def parse_integer(value, name):
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise TypeError(f'{name} must be an integer or integer string')


def load_profile(path):
    with open(path, encoding='utf-8-sig') as stream:
        bundle = json.load(stream)
    profile = dict(bundle.get('profile', bundle))
    for key in INTEGER_KEYS:
        if key not in profile:
            raise KeyError(f'packet profile is missing {key}')
        profile[key] = parse_integer(profile[key], key)
    profile.setdefault('fields', [])
    if not isinstance(profile['fields'], list):
        raise TypeError('packet profile fields must be a list')
    return profile, bundle


def main():
    options = parse_args()
    if options.limit is not None and options.limit < 1:
        raise ValueError('--limit must be a positive integer')
    if options.progress_every < 0:
        raise ValueError('--progress-every cannot be negative')

    with open(options.image, 'rb') as stream:
        image = stream.read()
    image_sha256 = hashlib.sha256(image).hexdigest()
    with open(options.profile_json, 'rb') as stream:
        profile_sha256 = hashlib.sha256(stream.read()).hexdigest()
    profile, profile_bundle = load_profile(options.profile_json)
    emulator = ExactPacketEmulator(image, RUNTIME_PROFILES[options.runtime_profile])
    output_path = os.path.abspath(options.output)
    summary_path = os.path.abspath(options.summary or f'{options.output}.summary.json')
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    os.makedirs(os.path.dirname(summary_path), exist_ok=True)

    counts = collections.Counter()
    payload_lengths = collections.Counter()
    streams = collections.Counter()
    replay_counts = collections.Counter()
    errors = collections.Counter()
    with open(options.events, encoding='utf-8-sig') as source, open(
        output_path,
        'w',
        encoding='utf-8',
        newline='\n',
    ) as destination:
        for line_number, line in enumerate(source, start=1):
            if options.limit is not None and counts['event_count'] >= options.limit:
                break
            if not line.strip():
                continue
            event = json.loads(line)
            if event.get('packet_id') != profile['client_opcode']:
                continue
            counts['event_count'] += 1
            try:
                decoded = emulator.decode(
                    bytes.fromhex(event['raw_payload_hex']),
                    profile,
                    packet_id=event.get('packet_id'),
                    raw_param=event.get('raw_param'),
                )
                counts['deserialize_success_count'] += int(
                    decoded['deserialize_return_al'] != 0
                )
                counts['fully_consumed_count'] += int(decoded['fully_consumed'])
                counts['successful_full_consume_count'] += int(
                    decoded['deserialize_return_al'] != 0 and decoded['fully_consumed']
                )
                row = {
                    **event,
                    **decoded,
                    'decoder_profile': profile.get('id'),
                    'decoder_runtime_image_sha256': image_sha256,
                    'decoder_profile_sha256': profile_sha256,
                }
            except Exception as error:  # Preserve evidence for every failing shape.
                error_text = f'{type(error).__name__}: {error}'
                errors[error_text] += 1
                counts['emulation_error_count'] += 1
                row = {**event, 'emulation_error': error_text}
            destination.write(json.dumps(row, ensure_ascii=True, separators=(',', ':')))
            destination.write('\n')
            payload_lengths[event['payload_length']] += 1
            streams[event.get('chunk_stream', 'unknown')] += 1
            replay_counts[event['replay_sha256']] += 1
            if options.progress_every and counts['event_count'] % options.progress_every == 0:
                print(f"decoded {counts['event_count']} events", file=sys.stderr)

    summary = {
        'schema_version': 1,
        'method': 'Unicorn x86-64 execution of exact unpacked Tencent image',
        'runtime_profile': options.runtime_profile,
        'runtime_profile_values': RUNTIME_PROFILES[options.runtime_profile],
        'image_path': os.path.abspath(options.image),
        'image_sha256': image_sha256,
        'events_path': os.path.abspath(options.events),
        'profile_path': os.path.abspath(options.profile_json),
        'profile_sha256': profile_sha256,
        'decoder_profile': profile.get('id'),
        'profile_source': profile_bundle,
        'output_path': output_path,
        'client_opcode': f"0x{profile['client_opcode']:04x}",
        'constructor_rva': f"0x{profile['constructor_rva']:08x}",
        'deserialize_rva': f"0x{profile['deserialize_rva']:08x}",
        'object_size': profile['object_size'],
        **counts,
        'payload_length_counts': dict(sorted(payload_lengths.items())),
        'stream_counts': dict(sorted(streams.items())),
        'replay_event_counts': dict(sorted(replay_counts.items())),
        'emulation_errors': dict(errors.most_common()),
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

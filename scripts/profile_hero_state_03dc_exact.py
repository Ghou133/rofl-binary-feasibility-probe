#!/usr/bin/env python3

"""Capture transient tagged-union discriminants for exact-build opcode 0x03dc.

The packet object intentionally retains only obfuscated union storage.  The
three wire discriminants are nevertheless available in AL immediately after
the exact client helper returns.  This profiler hooks those three points while
executing the original 16.16.805.0442 constructor/deserializer, preserving the
evidence needed to distinguish a stat-stone delta stream from a live hero
combat-state scalar stream.
"""

import argparse
import collections
import hashlib
import json
import os
import struct
import sys

from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_RAX

from emulate_exact_packet_decoder import ExactPacketEmulator, IMAGE_BASE, RUNTIME_PROFILES
from emulate_packet_profile_json import load_profile


TAG_CAPTURE_RVAS = {
    IMAGE_BASE + 0x00F73425: 'field_10_tag',
    IMAGE_BASE + 0x00F7361B: 'field_18_tag',
    IMAGE_BASE + 0x00F736CD: 'field_20_tag',
}


def parse_args():
    parser = argparse.ArgumentParser(
        description='Capture exact transient tags for PKT_S2C_UpdateStatStoneGameDelta_s.',
    )
    parser.add_argument('--image', required=True)
    parser.add_argument('--events', required=True)
    parser.add_argument('--profile-json', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--summary', required=True)
    parser.add_argument('--runtime-profile', default='16.16.805.0442')
    parser.add_argument('--progress-every', type=int, default=5000)
    return parser.parse_args()


def counter_dict(counter):
    return dict(sorted(counter.items(), key=lambda pair: str(pair[0])))


def main():
    options = parse_args()
    if options.runtime_profile not in RUNTIME_PROFILES:
        raise ValueError(f'unsupported runtime profile: {options.runtime_profile}')
    with open(options.image, 'rb') as stream:
        image = stream.read()
    with open(options.profile_json, 'rb') as stream:
        profile_bytes = stream.read()
    profile, profile_bundle = load_profile(options.profile_json)
    if profile['client_opcode'] != 0x03DC:
        raise ValueError('this profiler accepts only client opcode 0x03dc')

    emulator = ExactPacketEmulator(image, RUNTIME_PROFILES[options.runtime_profile])
    captured = []

    def capture_tag(runtime, address, _size, _user_data):
        captured.append((TAG_CAPTURE_RVAS[address], runtime.reg_read(UC_X86_REG_RAX) & 0xFF))

    for address in TAG_CAPTURE_RVAS:
        emulator.emulator.hook_add(
            UC_HOOK_CODE,
            capture_tag,
            begin=address,
            end=address,
        )

    counts = collections.Counter()
    payload_tag_counts = collections.Counter()
    stream_tag_counts = collections.Counter()
    raw_param_counts = collections.Counter()
    replay_counts = collections.Counter()
    keyframe_time_counts = collections.Counter()
    examples = {}
    output_path = os.path.abspath(options.output)
    summary_path = os.path.abspath(options.summary)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    os.makedirs(os.path.dirname(summary_path), exist_ok=True)

    with open(options.events, encoding='utf-8-sig') as source, open(
        output_path,
        'w',
        encoding='utf-8',
        newline='\n',
    ) as destination:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            event = json.loads(line)
            if event.get('packet_id') != 0x03DC:
                continue
            captured.clear()
            decoded = emulator.decode(
                bytes.fromhex(event['raw_payload_hex']),
                profile,
                packet_id=event.get('packet_id'),
                raw_param=event.get('raw_param'),
            )
            tags = dict(captured)
            expected_names = set(TAG_CAPTURE_RVAS.values())
            if set(tags) != expected_names or len(captured) != 3:
                raise RuntimeError(
                    f'line {line_number}: expected three unique tag captures, got {captured}'
                )
            tag_tuple = (
                tags['field_10_tag'],
                tags['field_18_tag'],
                tags['field_20_tag'],
            )
            storage = bytes.fromhex(decoded['object_hex'])
            row = {
                'schema_version': 1,
                'replay_sha256': event['replay_sha256'],
                'replay_label': event['replay_label'],
                'chunk_stream': event['chunk_stream'],
                'replay_time_ms': event['replay_time_ms'],
                'occurrence_index': event['occurrence_index'],
                'packet_id': event['packet_id'],
                'payload_length': event['payload_length'],
                'raw_param': event['raw_param'],
                'raw_param_hex': event['raw_param_hex'],
                **tags,
                'field_10_storage_hex': storage[0x10:0x14].hex(),
                'field_18_storage_hex': storage[0x18:0x20].hex(),
                'field_20_storage_hex': storage[0x20:0x21].hex(),
                'deserialize_return_al': decoded['deserialize_return_al'],
                'fully_consumed': decoded['fully_consumed'],
            }
            destination.write(json.dumps(row, ensure_ascii=True, separators=(',', ':')))
            destination.write('\n')

            counts['event_count'] += 1
            counts['deserialize_success_count'] += int(decoded['deserialize_return_al'] != 0)
            counts['fully_consumed_count'] += int(decoded['fully_consumed'])
            tag_key = f'{tag_tuple[0]}/{tag_tuple[1]}/{tag_tuple[2]}'
            payload_tag_counts[f'{event["payload_length"]}:{tag_key}'] += 1
            stream_tag_counts[f'{event["chunk_stream"]}:{tag_key}'] += 1
            raw_param_counts[event['raw_param_hex']] += 1
            replay_counts[event['replay_sha256']] += 1
            if event['chunk_stream'] == 'keyframe':
                keyframe_time_counts['time_zero'] += int(event['replay_time_ms'] == 0)
                keyframe_time_counts['time_nonzero'] += int(event['replay_time_ms'] != 0)
            examples.setdefault(tag_key, row)
            if options.progress_every and counts['event_count'] % options.progress_every == 0:
                print(f'profiled {counts["event_count"]} events', file=sys.stderr)

    summary = {
        'schema_version': 1,
        'status': 'EXACT_RUNTIME_TAG_CAPTURE_COMPLETE',
        'runtime_type_name': profile_bundle.get('runtime_type_name'),
        'client_opcode': '0x03dc',
        'runtime_profile': options.runtime_profile,
        'image_path': os.path.abspath(options.image),
        'image_sha256': hashlib.sha256(image).hexdigest(),
        'profile_path': os.path.abspath(options.profile_json),
        'profile_sha256': hashlib.sha256(profile_bytes).hexdigest(),
        'events_path': os.path.abspath(options.events),
        'output_path': output_path,
        'capture_rvas': {
            name: f'0x{address - IMAGE_BASE:08x}'
            for address, name in TAG_CAPTURE_RVAS.items()
        },
        **counts,
        'payload_length_and_tag_counts': counter_dict(payload_tag_counts),
        'stream_and_tag_counts': counter_dict(stream_tag_counts),
        'raw_param_counts': counter_dict(raw_param_counts),
        'distinct_raw_param_count': len(raw_param_counts),
        'replay_event_counts': counter_dict(replay_counts),
        'keyframe_time_counts': counter_dict(keyframe_time_counts),
        'tag_examples': examples,
        'semantic_interpretation': {
            'classification': 'HISTORICAL_STAT_STONE_DELTA_NOT_LIVE_COMBAT_STATE',
            'basis': [
                'The exact runtime RTTI names the packet UpdateStatStoneGameDelta.',
                'The packet is a three-field tagged union and not a current/max health pair.',
                'A large keyframe population replays accumulated stat-stone deltas.',
                'The same route spans many raw entity parameters and is not a ten-hero state snapshot.',
            ],
            'live_hp_max_hp_armor_mr_resource_carrier': False,
        },
    }
    with open(summary_path, 'w', encoding='utf-8', newline='\n') as stream:
        json.dump(summary, stream, ensure_ascii=True, indent=2)
        stream.write('\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'{type(error).__name__}: {error}', file=sys.stderr)
        sys.exit(1)

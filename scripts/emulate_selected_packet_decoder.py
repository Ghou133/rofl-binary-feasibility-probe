#!/usr/bin/env python3

import argparse
import collections
import hashlib
import json
import math
import os
import sys

from emulate_exact_packet_decoder import ExactPacketEmulator, PROFILES


DECODER_PROFILE_IDS = {
    'unit_apply_damage': 'rofl-16.15.801.3452-unit-apply-damage-unicorn-v1',
}


def parse_args():
    parser = argparse.ArgumentParser(
        description='Emulate an exact packet decoder for every event in a JSONL export.',
    )
    parser.add_argument('--image', required=True)
    parser.add_argument('--events', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--summary')
    parser.add_argument('--profile', choices=sorted(PROFILES), required=True)
    parser.add_argument('--limit', type=int)
    parser.add_argument('--progress-every', type=int, default=25000)
    parser.add_argument(
        '--output-scope',
        choices=['all', 'hero-pair', 'hero-pair-positive'],
        default='all',
    )
    return parser.parse_args()


def is_champion_network_id(value):
    return isinstance(value, int) and 0x400000AE <= value <= 0x400000B7


def participant_from_param(value):
    if not isinstance(value, int):
        return None
    participant = (value & 0xFF) - 0xAD
    return participant if 1 <= participant <= 10 else None


def main():
    options = parse_args()
    if options.limit is not None and options.limit < 1:
        raise ValueError('--limit must be a positive integer')
    if options.progress_every < 0:
        raise ValueError('--progress-every cannot be negative')

    with open(options.image, 'rb') as stream:
        image = stream.read()
    image_sha256 = hashlib.sha256(image).hexdigest()
    profile = PROFILES[options.profile]
    emulator = ExactPacketEmulator(image)
    output_path = os.path.abspath(options.output)
    summary_path = os.path.abspath(options.summary or f'{options.output}.summary.json')
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    os.makedirs(os.path.dirname(summary_path), exist_ok=True)

    counts = collections.Counter()
    payload_lengths = collections.Counter()
    replay_counts = collections.Counter()
    with open(options.events, encoding='utf-8') as source, open(
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
                raise ValueError(
                    f"line {line_number} has packet {event.get('packet_id')}; "
                    f"profile expects {profile['client_opcode']}"
                )
            decoded = emulator.decode(
                bytes.fromhex(event['raw_payload_hex']),
                profile,
                packet_id=event.get('packet_id'),
                raw_param=event.get('raw_param'),
            )
            counts['event_count'] += 1
            counts['deserialize_success_count'] += int(decoded['deserialize_return_al'] != 0)
            counts['fully_consumed_count'] += int(decoded['fully_consumed'])
            counts['successful_full_consume_count'] += int(
                decoded['deserialize_return_al'] != 0 and decoded['fully_consumed']
            )
            fields = decoded['decoded_fields']
            if options.profile == 'unit_apply_damage':
                source_is_champion = is_champion_network_id(fields.get('source_network_id'))
                target_is_champion = is_champion_network_id(fields.get('target_network_id'))
                amount = fields.get('amount')
                amount_is_positive = (
                    isinstance(amount, (int, float))
                    and math.isfinite(amount)
                    and amount > 0
                )
                counts['champion_source_count'] += int(source_is_champion)
                counts['champion_target_count'] += int(target_is_champion)
                counts['champion_pair_count'] += int(source_is_champion and target_is_champion)
                counts['positive_amount_count'] += int(amount_is_positive)
                counts['champion_pair_positive_amount_count'] += int(
                    source_is_champion and target_is_champion and amount_is_positive
                )
                selected = options.output_scope == 'all' or (
                    source_is_champion and target_is_champion and (
                        options.output_scope == 'hero-pair' or amount_is_positive
                    )
                )
            else:
                if options.output_scope != 'all':
                    raise ValueError(
                        f'--output-scope {options.output_scope} is only valid for unit_apply_damage'
                    )
                selected = True
            if options.profile == 'cast_spell':
                participant = participant_from_param(fields.get('raw_param'))
                counts['caster_participant_count'] += int(participant is not None)
                counts['raw_param_roundtrip_count'] += int(
                    fields.get('raw_param') == event.get('raw_param')
                )
            if selected:
                row = {
                    **event,
                    **decoded,
                    'decoder_profile': DECODER_PROFILE_IDS.get(options.profile),
                    'decoder_runtime_image_sha256': image_sha256,
                }
                destination.write(json.dumps(row, ensure_ascii=True, separators=(',', ':')))
                destination.write('\n')
                counts['output_event_count'] += 1
            payload_lengths[event['payload_length']] += 1
            replay_counts[event['replay_sha256']] += 1
            if options.progress_every and counts['event_count'] % options.progress_every == 0:
                print(f"decoded {counts['event_count']} events", file=sys.stderr)

    summary = {
        'schema_version': 1,
        'method': 'Unicorn x86-64 execution of exact unpacked Tencent image',
        'profile': options.profile,
        'image_path': os.path.abspath(options.image),
        'image_sha256': image_sha256,
        'events_path': os.path.abspath(options.events),
        'output_path': output_path,
        'output_scope': options.output_scope,
        'client_opcode': f"0x{profile['client_opcode']:04x}",
        'constructor_rva': f"0x{profile['constructor_rva']:08x}",
        'deserialize_rva': f"0x{profile['deserialize_rva']:08x}",
        **counts,
        'payload_length_counts': dict(sorted(payload_lengths.items())),
        'replay_event_counts': dict(sorted(replay_counts.items())),
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

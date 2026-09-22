#!/usr/bin/env python3

import argparse
import collections
import hashlib
import json
import os
import re
import sys

from emulate_exact_packet_decoder import ExactPacketEmulator


PROFILE_ID = 'rofl-16.15.801.3452-npc-level-up-unicorn-v1'
REPLAY_VERSION = '16.15.801.3452'
EXPECTED_IMAGE_SHA256 = (
    '7ee788155b9ba61d10603694cffb095e66ab3c641f933e4e7b181000c69f61bb'
)

PROFILE = {
    'client_opcode': 0x025A,
    'constructor_rva': 0x00E82060,
    'deserialize_rva': 0x00EFAA50,
    'object_size': 0x18,
    'fields': [
        {'name': 'field_10', 'offset': 0x10, 'type': 'u8'},
        {'name': 'field_11', 'offset': 0x11, 'type': 'u8'},
    ],
}

SHA256_PATTERN = re.compile(r'^[0-9a-f]{64}$')
PAYLOAD_HEX_PATTERN = re.compile(r'^(?:[0-9a-f]{2})*$')


def checked_nonnegative_int(event, field, line_number):
    value = event.get(field)
    if type(value) is not int or value < 0:
        raise ValueError(f'line {line_number} has invalid {field}')
    return value


def checked_metadata(event, line_number):
    replay_path = event.get('replay_path')
    replay_sha256 = event.get('replay_sha256')
    replay_label = event.get('replay_label')
    raw_param = event.get('raw_param')
    if event.get('schema_version') != 1:
        raise ValueError(f'line {line_number} has unsupported schema_version')
    if not isinstance(replay_path, str) or not replay_path:
        raise ValueError(f'line {line_number} has invalid replay_path')
    if not isinstance(replay_sha256, str) or not SHA256_PATTERN.fullmatch(replay_sha256):
        raise ValueError(f'line {line_number} has invalid replay_sha256')
    if event.get('replay_version') != REPLAY_VERSION:
        raise ValueError(f'line {line_number} has unsupported replay_version')
    if not isinstance(replay_label, str) or not replay_label:
        raise ValueError(f'line {line_number} has invalid replay_label')
    if event.get('chunk_stream') != 'game_chunk':
        raise ValueError(f'line {line_number} has invalid chunk_stream')
    if event.get('packet_type') != '0x025a':
        raise ValueError(f'line {line_number} has invalid packet_type')
    for field in (
        'chunk_index',
        'chunk_id',
        'chunk_file_offset',
        'compressed_body_offset',
        'decompressed_block_offset',
        'decompressed_payload_offset',
        'replay_time_ms',
        'occurrence_index',
    ):
        checked_nonnegative_int(event, field, line_number)
    if type(raw_param) is not int or not 0 <= raw_param <= 0xFFFFFFFF:
        raise ValueError(f'line {line_number} has invalid raw_param')
    expected_raw_param_hex = f'0x{raw_param:08x}'
    if event.get('raw_param_hex') != expected_raw_param_hex:
        raise ValueError(f'line {line_number} has inconsistent raw_param_hex')


def checked_payload(event, line_number):
    payload_hex = event.get('raw_payload_hex')
    payload_length = event.get('payload_length')
    payload_sha256 = event.get('raw_payload_sha256')
    if not isinstance(payload_hex, str) or not PAYLOAD_HEX_PATTERN.fullmatch(payload_hex):
        raise ValueError(f'line {line_number} has invalid raw_payload_hex')
    if not isinstance(payload_length, int) or payload_length < 0:
        raise ValueError(f'line {line_number} has invalid payload_length')
    if not isinstance(payload_sha256, str) or not SHA256_PATTERN.fullmatch(payload_sha256):
        raise ValueError(f'line {line_number} has invalid raw_payload_sha256')
    payload = bytes.fromhex(payload_hex)
    if len(payload) != payload_length:
        raise ValueError(
            f'line {line_number} payload length mismatch: '
            f'expected {payload_length}, got {len(payload)}'
        )
    actual_sha256 = hashlib.sha256(payload).hexdigest()
    if actual_sha256 != payload_sha256:
        raise ValueError(
            f'line {line_number} payload SHA-256 mismatch: '
            f'expected {payload_sha256}, got {actual_sha256}'
        )
    return payload


def raw_packet_ref(event):
    return {
        'source_path': event.get('replay_path'),
        'replay_sha256': event.get('replay_sha256'),
        'chunk_index': event.get('chunk_index'),
        'chunk_id': event.get('chunk_id'),
        'chunk_stream': event.get('chunk_stream'),
        'chunk_file_offset': event.get('chunk_file_offset'),
        'compressed_body_offset': event.get('compressed_body_offset'),
        'decompressed_block_offset': event.get('decompressed_block_offset'),
        'decompressed_payload_offset': event.get('decompressed_payload_offset'),
        'replay_time_ms': event.get('replay_time_ms'),
        'occurrence_index': event.get('occurrence_index'),
        'packet_id': event.get('packet_id'),
        'payload_length': event.get('payload_length'),
        'raw_param': event.get('raw_param'),
        'raw_param_hex': event.get('raw_param_hex'),
        'payload_sha256': event.get('raw_payload_sha256'),
    }


def parse_args():
    parser = argparse.ArgumentParser(
        description='Decode patch-pinned Replay 0x025A LevelUp packets.',
    )
    parser.add_argument('--image', required=True)
    parser.add_argument('--events', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--summary', required=True)
    parser.add_argument('--progress-every', type=int, default=0)
    return parser.parse_args()


def main():
    options = parse_args()
    with open(options.image, 'rb') as stream:
        image = stream.read()
    image_sha256 = hashlib.sha256(image).hexdigest()
    if image_sha256 != EXPECTED_IMAGE_SHA256:
        raise ValueError(
            f'decoder image SHA-256 mismatch: expected {EXPECTED_IMAGE_SHA256}, '
            f'got {image_sha256}'
        )
    with open(options.events, 'rb') as stream:
        events_sha256 = hashlib.sha256(stream.read()).hexdigest()
    with open(__file__, 'rb') as stream:
        decoder_script_sha256 = hashlib.sha256(stream.read()).hexdigest()
    emulator = ExactPacketEmulator(image)
    output_path = os.path.abspath(options.output)
    summary_path = os.path.abspath(options.summary)
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
            if not line.strip():
                continue
            event = json.loads(line)
            if event.get('packet_id') != PROFILE['client_opcode']:
                raise ValueError(
                    f"line {line_number} has packet {event.get('packet_id')}; "
                    f"profile expects {PROFILE['client_opcode']}"
                )
            checked_metadata(event, line_number)
            payload = checked_payload(event, line_number)
            decoded = emulator.decode(
                payload,
                PROFILE,
                packet_id=event.get('packet_id'),
                raw_param=event.get('raw_param'),
            )
            counts['event_count'] += 1
            counts['deserialize_success_count'] += int(
                decoded['deserialize_return_al'] != 0
            )
            counts['fully_consumed_count'] += int(decoded['fully_consumed'])
            counts['successful_full_consume_count'] += int(
                decoded['deserialize_return_al'] != 0 and decoded['fully_consumed']
            )
            destination.write(json.dumps(
                {
                    **event,
                    **decoded,
                    'decoder_profile': PROFILE_ID,
                    'decoder_runtime_image_sha256': image_sha256,
                    'decoder_constructor_rva': PROFILE['constructor_rva'],
                    'decoder_deserialize_rva': PROFILE['deserialize_rva'],
                    'decoder_object_size': PROFILE['object_size'],
                    'raw_packet_ref': raw_packet_ref(event),
                },
                ensure_ascii=True,
                separators=(',', ':'),
            ))
            destination.write('\n')
            counts['output_event_count'] += 1
            payload_lengths[event['payload_length']] += 1
            replay_counts[event['replay_sha256']] += 1
            if options.progress_every and counts['event_count'] % options.progress_every == 0:
                print(f"decoded {counts['event_count']} events", file=sys.stderr)

    with open(output_path, 'rb') as stream:
        output_sha256 = hashlib.sha256(stream.read()).hexdigest()

    summary = {
        'schema_version': 1,
        'method': 'Unicorn x86-64 execution of exact unpacked Tencent image',
        'profile': 'npc_level_up',
        'decoder_profile': PROFILE_ID,
        'image_path': os.path.abspath(options.image),
        'image_sha256': image_sha256,
        'events_path': os.path.abspath(options.events),
        'events_sha256': events_sha256,
        'output_path': output_path,
        'output_sha256': output_sha256,
        'decoder_script_sha256': decoder_script_sha256,
        'client_opcode': '0x025a',
        'constructor_rva': '0x00e82060',
        'deserialize_rva': '0x00efaa50',
        'object_size': PROFILE['object_size'],
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

#!/usr/bin/env python3

"""Link sampled hero positions to their exact 0x02d1 raw packet records."""

import argparse
import hashlib
import json
import os
import tempfile


PATH_PACKET_ID = 0x02D1
EXPECTED_POSITION_COUNT = 159765


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--raw-packets', required=True)
    parser.add_argument('--hero-events', required=True)
    parser.add_argument('--hero-positions', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--manifest', required=True)
    parser.add_argument(
        '--expected-position-count', type=int, default=EXPECTED_POSITION_COUNT
    )
    return parser.parse_args()


def file_evidence(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return {
        'path': os.path.abspath(path),
        'bytes': os.path.getsize(path),
        'sha256': digest.hexdigest(),
    }


def packet_ref(raw):
    return {
        'replay_sha256': raw['replay_sha256'],
        'chunk_index': raw['chunk_index'],
        'decompressed_block_offset': raw['decompressed_block_offset'],
        'packet_id': raw['packet_id'],
        'packet_type': raw.get('packet_type', f"0x{raw['packet_id']:04x}"),
        'payload_length': raw['payload_length'],
        'raw_param': raw['raw_param'],
        'raw_payload_sha256': raw['raw_payload_sha256'],
        'packet_timestamp_ms': raw['replay_time_ms'],
    }


def load_raw_packets(path):
    packets = {}
    count = 0
    with open(path, encoding='utf-8') as stream:
        for line_number, line in enumerate(stream, 1):
            raw = json.loads(line)
            count += 1
            if raw['packet_id'] != PATH_PACKET_ID:
                raise ValueError(
                    f'{path}:{line_number}: expected packet 0x02d1, '
                    f"found 0x{raw['packet_id']:04x}"
                )
            key = (raw['replay_sha256'], raw['occurrence_index'])
            if key in packets:
                raise ValueError(f'{path}:{line_number}: duplicate raw packet key {key}')
            packets[key] = packet_ref(raw)
    return packets, count


def load_event_links(path, packets):
    links = {}
    count = 0
    with open(path, encoding='utf-8') as stream:
        for line_number, line in enumerate(stream, 1):
            event = json.loads(line)
            count += 1
            packet_key = (
                event['replay_sha256'], event['raw_packet_occurrence_index']
            )
            raw_ref = packets.get(packet_key)
            if raw_ref is None:
                raise ValueError(
                    f'{path}:{line_number}: missing raw packet {packet_key}'
                )
            if raw_ref['packet_timestamp_ms'] != event['timestamp_ms']:
                raise ValueError(
                    f'{path}:{line_number}: event/raw timestamp mismatch for {packet_key}'
                )
            event_key = (
                event['replay_sha256'], event['entity_id'], event['timestamp_ms']
            )
            link = (
                event['raw_packet_occurrence_index'], event['record_index'], raw_ref
            )
            prior = links.get(event_key)
            if prior is not None and prior != link:
                raise ValueError(
                    f'{path}:{line_number}: ambiguous source event key {event_key}'
                )
            links[event_key] = link
    return links, count


def enrich_positions(path, output, links, expected_count):
    output = os.path.abspath(output)
    os.makedirs(os.path.dirname(output), exist_ok=True)
    output_directory = os.path.dirname(output)
    linked_count = 0
    fd, temporary = tempfile.mkstemp(
        prefix='.hero_positions_enriched.', suffix='.jsonl', dir=output_directory
    )
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as target, open(
            path, encoding='utf-8'
        ) as source:
            for line_number, line in enumerate(source, 1):
                row = json.loads(line)
                event_key = (
                    row['replay_sha256'],
                    row['entity_id'],
                    row['source_path_timestamp_ms'],
                )
                link = links.get(event_key)
                if link is None:
                    raise ValueError(
                        f'{path}:{line_number}: no source event for {event_key}'
                    )
                occurrence_index, record_index, raw_ref = link
                row['source_raw_packet_occurrence_index'] = occurrence_index
                row['source_record_index'] = record_index
                row['raw_packet_ref'] = raw_ref
                target.write(json.dumps(row, separators=(',', ':')) + '\n')
                linked_count += 1
        if linked_count != expected_count:
            raise ValueError(
                f'expected {expected_count} positions, found {linked_count}'
            )
        os.replace(temporary, output)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise
    return linked_count


def write_manifest(path, value):
    path = os.path.abspath(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix='.path_provenance_manifest.', suffix='.json',
        dir=os.path.dirname(path),
    )
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
            json.dump(value, stream, indent=2)
            stream.write('\n')
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def main():
    options = parse_args()
    inputs = {
        'raw_packets': file_evidence(options.raw_packets),
        'hero_events': file_evidence(options.hero_events),
        'hero_positions_1s': file_evidence(options.hero_positions),
    }
    packets, raw_packet_count = load_raw_packets(options.raw_packets)
    links, hero_event_count = load_event_links(options.hero_events, packets)
    linked_count = enrich_positions(
        options.hero_positions, options.output, links,
        options.expected_position_count,
    )
    output = file_evidence(options.output)
    manifest = {
        'schema_version': 1,
        'scope': 'Exact raw 0x02d1 packet provenance for one-second hero positions.',
        'inputs': inputs,
        'output': output,
        'counts': {
            'raw_packets': raw_packet_count,
            'hero_events': hero_event_count,
            'unique_hero_event_join_keys': len(links),
            'hero_positions_1s': linked_count,
            'linked_hero_positions_1s': linked_count,
        },
        'checks': {
            'all_raw_packets_are_0x02d1': True,
            'all_hero_events_link_to_raw_packets': True,
            'all_event_packet_timestamps_match': True,
            'all_hero_positions_linked': linked_count == options.expected_position_count,
            'linked_count_matches_expected': linked_count == options.expected_position_count,
        },
        'linkage': {
            'position_to_event_key': [
                'replay_sha256', 'entity_id', 'source_path_timestamp_ms'
            ],
            'event_to_packet_key': [
                'replay_sha256', 'raw_packet_occurrence_index'
            ],
            'packet_id': PATH_PACKET_ID,
            'packet_type': '0x02d1',
        },
        'generator': file_evidence(__file__),
    }
    write_manifest(options.manifest, manifest)
    print(json.dumps({
        'output': output,
        'manifest': file_evidence(options.manifest),
        'linked_count': linked_count,
    }, indent=2))


if __name__ == '__main__':
    main()
